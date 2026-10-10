//! Concurrency limiting and per-IP rate limiting used by the auth middleware.
//!
//! The concurrency limiter is a small waker-based async semaphore: waiters
//! register their [`Waker`] instead of busy-polling, and its permits are
//! `'static` (backed by an `Arc`) so they can be moved into a spawned task and
//! released only when validation truly completes. The failure limiter counts
//! failed attempts per client IP in a fixed window, with lazy pruning and a
//! hard cap on tracked IPs.

use ipnet::IpNet;
use ntex::http::HeaderMap;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Limits the number of concurrently in-flight validations.
///
/// Implemented as an async semaphore: when no permit is available the caller's
/// [`Waker`] is registered and the task parks (no polling loop); releasing a
/// permit wakes a single waiter. Waiters are served in registration order for
/// fairness.
pub(crate) struct ConcurrencyLimiter {
    inner: Mutex<SemState>,
    #[cfg(test)]
    max: usize,
}

struct SemState {
    /// Number of permits currently available.
    available: usize,
    /// Monotonic id used to order waiters (FIFO) and identify their wakers.
    next_id: u64,
    /// Parked waiters keyed by registration order.
    waiters: BTreeMap<u64, Waker>,
}

impl SemState {
    /// Wake the longest-waiting task (front of the queue) so it can claim a
    /// freed permit. Peeks without removing — the waiter removes itself when it
    /// actually takes the permit, which keeps servicing strictly FIFO.
    fn wake_front(&self) {
        if let Some((_, waker)) = self.waiters.iter().next() {
            waker.wake_by_ref();
        }
    }
}

impl ConcurrencyLimiter {
    /// Create a new limiter allowing up to `max` concurrent operations.
    pub(crate) fn new(max: usize) -> Self {
        Self {
            inner: Mutex::new(SemState {
                available: max,
                next_id: 0,
                waiters: BTreeMap::new(),
            }),
            #[cfg(test)]
            max,
        }
    }

    /// Acquire a permit, parking asynchronously (without busy polling) when the
    /// limit is reached.
    ///
    /// Takes `&Arc<Self>` so the returned permit can own an `Arc` and therefore
    /// be `'static` — allowing it to be held across a spawned task.
    pub(crate) fn acquire(self: &Arc<Self>) -> Acquire {
        Acquire {
            limiter: Arc::clone(self),
            id: None,
        }
    }

    /// Current number of in-flight operations.
    #[cfg(test)]
    fn current(&self) -> usize {
        let st = self.lock();
        self.max - st.available
    }

    fn lock(&self) -> MutexGuard<'_, SemState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn release(&self) {
        let mut st = self.lock();
        st.available += 1;
        st.wake_front();
    }
}

/// Future returned by [`ConcurrencyLimiter::acquire`].
pub(crate) struct Acquire {
    limiter: Arc<ConcurrencyLimiter>,
    id: Option<u64>,
}

impl Future for Acquire {
    type Output = ConcurrencyPermit;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut st = this.limiter.lock();

        // A permit may be claimed only when we are first in line: either nobody
        // is waiting, or we are the front (longest-waiting) waiter. This stops a
        // freshly-polled acquire from barging ahead of already-queued waiters.
        let is_front = match this.id {
            Some(id) => st.waiters.keys().next() == Some(&id),
            None => st.waiters.is_empty(),
        };
        if st.available > 0 && is_front {
            st.available -= 1;
            if let Some(id) = this.id.take() {
                st.waiters.remove(&id);
            }
            // If permits remain, hand the next waiter its turn so a freed permit
            // is not stranded.
            if st.available > 0 {
                st.wake_front();
            }
            return Poll::Ready(ConcurrencyPermit {
                limiter: Arc::clone(&this.limiter),
            });
        }

        // No permit for us yet: register (or refresh) our waker so a released
        // permit can wake us.
        let id = match this.id {
            Some(id) => id,
            None => {
                let id = st.next_id;
                st.next_id = st.next_id.wrapping_add(1);
                this.id = Some(id);
                id
            }
        };
        st.waiters.insert(id, cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for Acquire {
    fn drop(&mut self) {
        // If we parked but never received a permit, drop our waker. If we were
        // the front waiter (possibly just woken to claim a freed permit) and are
        // giving up, pass the turn on so that permit is not stranded.
        if let Some(id) = self.id.take() {
            let mut st = self.limiter.lock();
            let was_front = st.waiters.keys().next() == Some(&id);
            st.waiters.remove(&id);
            if was_front && st.available > 0 {
                st.wake_front();
            }
        }
    }
}

/// RAII permit returned by [`ConcurrencyLimiter::acquire`]. Releases a slot on drop.
pub(crate) struct ConcurrencyPermit {
    limiter: Arc<ConcurrencyLimiter>,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.limiter.release();
    }
}

/// Soft cap on tracked clients. Once reached, unseen clients share the overflow
/// entry, so rotating addresses can neither exhaust memory nor push existing
/// entries out.
const MAX_ENTRIES: usize = 65_536;

/// Normalized client IP, or `None` for the shared overflow entry (used for
/// unseen clients once the map is full and for requests without a client IP).
type Key = Option<IpAddr>;

/// Per-IP limiter of failed authentication attempts (fixed window).
///
/// Only failures are recorded, so legitimate traffic is never throttled. IPv6
/// clients are grouped by their /64 prefix, since a single host usually owns
/// the whole prefix.
pub(crate) struct FailureLimiter {
    max_failures: u32,
    window: Duration,
    state: Mutex<FailureState>,
}

struct FailureState {
    entries: HashMap<Key, FailureEntry>,
    last_prune: Instant,
}

struct FailureEntry {
    failures: u32,
    /// Attempts still being validated; they count against the budget so
    /// concurrent requests cannot exceed it before their failures are recorded
    pending: u32,
    window_start: Instant,
}

impl FailureLimiter {
    pub(crate) fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            state: Mutex::new(FailureState {
                entries: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    /// Reserve an attempt for `ip`, or return how long to wait.
    ///
    /// Fails once recorded failures plus attempts in flight reach the budget.
    /// The reservation is released when dropped (including on cancellation)
    /// unless it is turned into a failure with [`Reservation::fail`].
    pub(crate) fn reserve(&self, ip: Option<IpAddr>) -> Result<Reservation<'_>, Duration> {
        let now = Instant::now();
        let window = self.window;
        let mut state = self.lock();

        // Lazy pruning, at most once per window. Entries with attempts in
        // flight are kept, since their reservations still refer to them.
        if now.duration_since(state.last_prune) >= window {
            state
                .entries
                .retain(|_, e| e.pending > 0 || now.duration_since(e.window_start) < window);
            state.last_prune = now;
        }

        let key = state.key(ip);
        let entry = state.entries.entry(key).or_insert(FailureEntry {
            failures: 0,
            pending: 0,
            window_start: now,
        });
        let elapsed = now.duration_since(entry.window_start);
        if elapsed >= window {
            entry.failures = 0;
            entry.window_start = now;
        } else if entry.failures >= self.max_failures {
            return Err(window - elapsed);
        }
        if entry.failures.saturating_add(entry.pending) >= self.max_failures {
            // Budget held by attempts in flight, which resolve shortly.
            return Err(Duration::from_secs(1));
        }
        entry.pending += 1;
        Ok(Reservation {
            limiter: self,
            key,
            done: false,
        })
    }

    fn lock(&self) -> MutexGuard<'_, FailureState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Attempt reserved by [`FailureLimiter::reserve`].
pub(crate) struct Reservation<'a> {
    limiter: &'a FailureLimiter,
    key: Key,
    done: bool,
}

impl Reservation<'_> {
    /// Record the attempt as a failure.
    pub(crate) fn fail(mut self) {
        self.finish(true);
    }

    fn finish(&mut self, failed: bool) {
        self.done = true;
        let now = Instant::now();
        let mut state = self.limiter.lock();
        let Some(entry) = state.entries.get_mut(&self.key) else {
            return;
        };
        entry.pending = entry.pending.saturating_sub(1);
        if failed {
            if now.duration_since(entry.window_start) >= self.limiter.window {
                entry.failures = 0;
                entry.window_start = now;
            }
            entry.failures = entry.failures.saturating_add(1);
        } else if entry.failures == 0 && entry.pending == 0 {
            // Only failures need tracking.
            state.entries.remove(&self.key);
        }
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.finish(false);
        }
    }
}

impl FailureState {
    fn key(&self, ip: Option<IpAddr>) -> Key {
        let key = ip.map(normalize);
        if key.is_some() && self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&key) {
            None
        } else {
            key
        }
    }
}

/// Which peers may set the client IP through `X-Forwarded-For`.
#[derive(Default)]
pub(crate) struct ProxyTrust {
    /// Networks of trusted reverse proxies
    pub(crate) networks: Vec<IpNet>,
    /// Trust connections without a peer address (Unix sockets), which only
    /// local processes such as a reverse proxy can open
    pub(crate) peerless: bool,
}

impl ProxyTrust {
    /// Client IP from the peer address and, when the peer is trusted,
    /// `X-Forwarded-For`: the rightmost hop that is not itself a trusted proxy,
    /// so hops a client prepends are ignored. Falls back to the peer when the
    /// header is absent or that hop is malformed. `None` without a peer
    /// address unless such connections are trusted and the header is usable.
    pub(crate) fn client_ip(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let is_trusted = |ip: &IpAddr| self.networks.iter().any(|net| net.contains(ip));
        match peer.map(|ip| ip.to_canonical()) {
            Some(peer) if !is_trusted(&peer) => Some(peer),
            Some(peer) => Some(forwarded_for(headers, is_trusted).unwrap_or(peer)),
            None if self.peerless => forwarded_for(headers, is_trusted),
            None => None,
        }
    }
}

/// Rightmost untrusted `X-Forwarded-For` hop (or the leftmost one if all are
/// trusted) across all header lines; `None` if absent or malformed.
fn forwarded_for(headers: &HeaderMap, is_trusted: impl Fn(&IpAddr) -> bool) -> Option<IpAddr> {
    // `Some(None)` marks a malformed hop.
    let mut leftmost: Option<Option<IpAddr>> = None;
    let mut untrusted: Option<Option<IpAddr>> = None;
    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else {
            untrusted = Some(None);
            continue;
        };
        for hop in value.split(',') {
            let hop = parse_hop(hop.trim());
            leftmost.get_or_insert(hop);
            if !hop.is_some_and(|ip| is_trusted(&ip)) {
                untrusted = Some(hop);
            }
        }
    }
    untrusted.or(leftmost).flatten()
}

/// Parse a hop with an optional port (`1.2.3.4:80`, `[::1]:80`). The
/// unspecified address is never a valid client.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    let ip = hop
        .parse::<IpAddr>()
        .or_else(|_| hop.parse::<SocketAddr>().map(|addr| addr.ip()))
        .ok()?
        .to_canonical();
    (!ip.is_unspecified()).then_some(ip)
}

/// Map IPv4-mapped IPv6 addresses to IPv4 and other IPv6 addresses to their /64.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ntex::test]
    async fn test_concurrency_limiter_releases_on_drop() {
        let limiter = Arc::new(ConcurrencyLimiter::new(2));
        assert_eq!(limiter.current(), 0);

        let p1 = limiter.acquire().await;
        let _p2 = limiter.acquire().await;
        assert_eq!(limiter.current(), 2);

        drop(p1);
        assert_eq!(limiter.current(), 1);
    }

    #[ntex::test]
    async fn test_concurrency_limiter_parks_and_wakes_when_full() {
        // A third acquire on a limiter of 2 must not complete until a permit is
        // released — and it must complete promptly once one is (no busy poll).
        let limiter = Arc::new(ConcurrencyLimiter::new(2));
        let p1 = limiter.acquire().await;
        let _p2 = limiter.acquire().await;

        let mut fut = Box::pin(limiter.acquire());
        let waker = Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        assert_eq!(limiter.current(), 2);

        drop(p1);
        // With a permit free, the parked acquire resolves on the next poll.
        let p3 = match fut.as_mut().poll(&mut cx) {
            Poll::Ready(permit) => permit,
            Poll::Pending => panic!("acquire should resolve once a permit is freed"),
        };
        assert_eq!(limiter.current(), 2); // _p2 + p3 held
        drop(p3);
        assert_eq!(limiter.current(), 1); // only _p2 held
    }

    #[ntex::test]
    async fn test_concurrency_limiter_fifo_no_barging() {
        // A freshly-arriving acquire must not steal a permit ahead of a task
        // that is already queued.
        let limiter = Arc::new(ConcurrencyLimiter::new(1));
        let p1 = limiter.acquire().await; // available = 0

        let waker = Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);

        // `a` queues first and parks.
        let mut a = Box::pin(limiter.acquire());
        assert!(a.as_mut().poll(&mut cx).is_pending());

        // Free the permit; `a` is now the front waiter.
        drop(p1);

        // `b` arrives afterwards and polls: it must NOT barge ahead of `a`.
        let mut b = Box::pin(limiter.acquire());
        assert!(
            b.as_mut().poll(&mut cx).is_pending(),
            "b must not take the permit ahead of the queued front waiter a"
        );

        // The front waiter `a` gets the permit.
        assert!(
            a.as_mut().poll(&mut cx).is_ready(),
            "front waiter a should receive the freed permit"
        );
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    fn fail(limiter: &FailureLimiter, ip: Option<IpAddr>) {
        limiter.reserve(ip).unwrap().fail();
    }

    #[test]
    fn failure_limiter_blocks_after_budget() {
        let limiter = FailureLimiter::new(2, Duration::from_secs(60));
        fail(&limiter, ip("1.2.3.4"));
        drop(limiter.reserve(ip("1.2.3.4")).unwrap());
        fail(&limiter, ip("1.2.3.4"));
        let left = limiter.reserve(ip("1.2.3.4")).err().unwrap();
        assert!(left > Duration::from_secs(59) && left <= Duration::from_secs(60));
        assert!(limiter.reserve(ip("5.6.7.8")).is_ok());
        assert!(limiter.reserve(None).is_ok());
    }

    #[test]
    fn in_flight_attempts_count_against_budget() {
        let limiter = FailureLimiter::new(2, Duration::from_secs(60));
        let a = limiter.reserve(ip("1.2.3.4")).unwrap();
        let b = limiter.reserve(ip("1.2.3.4")).unwrap();
        assert_eq!(
            limiter.reserve(ip("1.2.3.4")).err(),
            Some(Duration::from_secs(1))
        );
        // Released (success or cancellation) frees the slot...
        drop(a);
        let c = limiter.reserve(ip("1.2.3.4")).unwrap();
        // ...while failures keep it.
        b.fail();
        c.fail();
        assert!(limiter.reserve(ip("1.2.3.4")).err().unwrap() > Duration::from_secs(1));
    }

    #[test]
    fn successes_leave_no_entry() {
        let limiter = FailureLimiter::new(2, Duration::from_secs(60));
        drop(limiter.reserve(ip("1.2.3.4")).unwrap());
        assert!(limiter.lock().entries.is_empty());
    }

    #[test]
    fn failure_limiter_window_resets() {
        let limiter = FailureLimiter::new(1, Duration::from_millis(10));
        fail(&limiter, ip("1.2.3.4"));
        assert!(limiter.reserve(ip("1.2.3.4")).is_err());
        std::thread::sleep(Duration::from_millis(20));
        fail(&limiter, ip("5.6.7.8"));
        assert_eq!(limiter.lock().entries.len(), 1, "stale entry pruned");
        assert!(limiter.reserve(ip("1.2.3.4")).is_ok());
    }

    #[test]
    fn ipv6_grouped_by_prefix() {
        let limiter = FailureLimiter::new(1, Duration::from_secs(60));
        fail(&limiter, ip("2001:db8::1"));
        assert!(limiter.reserve(ip("2001:db8::ffff")).is_err());
        assert!(limiter.reserve(ip("2001:db8:0:1::1")).is_ok());
        fail(&limiter, ip("::ffff:9.9.9.9"));
        assert!(limiter.reserve(ip("9.9.9.9")).is_err());
    }

    #[test]
    fn client_ip_resolution() {
        let mut trust = ProxyTrust {
            networks: vec!["10.0.0.0/8".parse().unwrap()],
            peerless: false,
        };
        let headers = |lines: &[&str]| {
            let mut map = HeaderMap::new();
            for line in lines {
                map.append("x-forwarded-for".try_into().unwrap(), line.parse().unwrap());
            }
            map
        };
        let resolve = |peer: &str, lines: &[&str]| trust.client_ip(ip(peer), &headers(lines));

        // Untrusted peer: header ignored.
        assert_eq!(resolve("1.1.1.1", &["9.9.9.9"]), ip("1.1.1.1"));
        // Trusted peer: rightmost untrusted hop, client-prepended hops ignored.
        assert_eq!(
            resolve("10.0.0.1", &["6.6.6.6, 9.9.9.9, 10.0.0.2"]),
            ip("9.9.9.9")
        );
        assert_eq!(
            resolve("10.0.0.1", &["6.6.6.6", "9.9.9.9:80"]),
            ip("9.9.9.9")
        );
        assert_eq!(resolve("10.0.0.1", &["[::ffff:9.9.9.9]:80"]), ip("9.9.9.9"));
        // All hops trusted: leftmost.
        assert_eq!(resolve("10.0.0.1", &["10.0.0.3, 10.0.0.2"]), ip("10.0.0.3"));
        // Absent or malformed: the proxy itself.
        assert_eq!(resolve("10.0.0.1", &[]), ip("10.0.0.1"));
        assert_eq!(resolve("10.0.0.1", &["9.9.9.9, junk"]), ip("10.0.0.1"));
        assert_eq!(resolve("10.0.0.1", &["0.0.0.0"]), ip("10.0.0.1"));
        // No peer (e.g. Unix socket): untrusted unless opted in.
        assert_eq!(trust.client_ip(None, &headers(&["9.9.9.9"])), None);
        trust.peerless = true;
        assert_eq!(
            trust.client_ip(None, &headers(&["6.6.6.6, 9.9.9.9, 10.0.0.2"])),
            ip("9.9.9.9")
        );
        assert_eq!(trust.client_ip(None, &headers(&[])), None);
        assert_eq!(trust.client_ip(None, &headers(&["junk"])), None);
    }

    #[test]
    fn full_map_routes_unseen_ips_to_overflow() {
        let limiter = FailureLimiter::new(1, Duration::from_secs(60));
        {
            let mut state = limiter.lock();
            let now = Instant::now();
            for i in 0..MAX_ENTRIES as u32 {
                let entry = FailureEntry {
                    failures: 1,
                    pending: 0,
                    window_start: now,
                };
                state
                    .entries
                    .insert(Some(IpAddr::from(i.to_be_bytes())), entry);
            }
        }
        // Rotating addresses all land in the overflow entry...
        fail(&limiter, ip("200.0.0.1"));
        assert!(limiter.reserve(ip("200.0.0.2")).is_err());
        assert!(limiter.reserve(None).is_err());
        // ...while tracked clients keep their own entry.
        assert!(limiter.reserve(ip("0.0.0.1")).is_err());
        assert!(limiter.lock().entries.contains_key(&ip("0.0.0.1")));
        assert_eq!(limiter.lock().entries.len(), MAX_ENTRIES + 1);
    }
}

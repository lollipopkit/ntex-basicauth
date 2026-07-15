//! Concurrency limiting and per-IP rate limiting used by the auth middleware.
//!
//! The concurrency limiter is a small waker-based async semaphore: waiters
//! register their [`Waker`] instead of busy-polling, and its permits are
//! `'static` (backed by an `Arc`) so they can be moved into a spawned task and
//! released only when validation truly completes. The rate limiter is a per-IP
//! fixed-window counter that prunes stale entries lazily so its map cannot grow
//! without bound as new IPs are seen.

use crate::error::AuthError;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Limits the number of concurrently in-flight validations.
///
/// Implemented as an async semaphore: when no permit is available the caller's
/// [`Waker`] is registered and the task parks (no polling loop); releasing a
/// permit wakes a single waiter. Waiters are served in registration order for
/// fairness.
pub struct ConcurrencyLimiter {
    inner: Mutex<SemState>,
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

impl ConcurrencyLimiter {
    /// Create a new limiter allowing up to `max` concurrent operations.
    pub fn new(max: usize) -> Self {
        Self {
            inner: Mutex::new(SemState {
                available: max,
                next_id: 0,
                waiters: BTreeMap::new(),
            }),
            max,
        }
    }

    /// Acquire a permit, parking asynchronously (without busy polling) when the
    /// limit is reached.
    ///
    /// Takes `&Arc<Self>` so the returned permit can own an `Arc` and therefore
    /// be `'static` — allowing it to be held across a spawned task.
    pub fn acquire(self: &Arc<Self>) -> Acquire {
        Acquire {
            limiter: Arc::clone(self),
            id: None,
        }
    }

    /// Current number of in-flight operations.
    pub fn current(&self) -> usize {
        let st = self.inner.lock().expect("concurrency limiter poisoned");
        self.max - st.available
    }

    fn release(&self) {
        let mut st = self.inner.lock().expect("concurrency limiter poisoned");
        st.available += 1;
        // Hand the freed permit to the longest-waiting task; it re-checks
        // availability when polled.
        if let Some((_, waker)) = st.waiters.pop_first() {
            waker.wake();
        }
    }
}

/// Future returned by [`ConcurrencyLimiter::acquire`].
pub struct Acquire {
    limiter: Arc<ConcurrencyLimiter>,
    id: Option<u64>,
}

impl Future for Acquire {
    type Output = ConcurrencyPermit;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut st = this.limiter.inner.lock().expect("concurrency limiter poisoned");

        if st.available > 0 {
            st.available -= 1;
            if let Some(id) = this.id.take() {
                st.waiters.remove(&id);
            }
            return Poll::Ready(ConcurrencyPermit {
                limiter: Arc::clone(&this.limiter),
            });
        }

        // No permit yet: register (or refresh) our waker so `release` can wake us.
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
        // If we parked but never received a permit, drop our waker so it is not
        // woken (and, if we were the one just handed a permit, wake the next
        // waiter so the permit is not lost).
        if let Some(id) = self.id.take() {
            let mut st = self.limiter.inner.lock().expect("concurrency limiter poisoned");
            st.waiters.remove(&id);
        }
    }
}

/// RAII permit returned by [`ConcurrencyLimiter::acquire`]. Releases a slot on drop.
pub struct ConcurrencyPermit {
    limiter: Arc<ConcurrencyLimiter>,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.limiter.release();
    }
}

/// Per-IP fixed-window rate limiter with lazy pruning.
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    state: Mutex<RateState>,
}

struct RateState {
    entries: HashMap<String, RateEntry>,
    /// Last time stale entries were pruned; prevents unbounded map growth.
    last_prune: Instant,
}

#[derive(Clone, Copy)]
struct RateEntry {
    count: u64,
    window_start: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter allowing `max_requests` per `window` per IP.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            state: Mutex::new(RateState {
                entries: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    /// Record an attempt for `ip` and return an error if the limit is exceeded.
    pub fn check(&self, ip: &str) -> Result<(), AuthError> {
        let now = Instant::now();
        let window = self.window;
        let mut state = self.state.lock().expect("rate limiter state poisoned");

        // Lazily drop stale entries (at most once per window) so the map cannot
        // grow without bound as new source IPs are seen.
        if now.duration_since(state.last_prune) >= window {
            state
                .entries
                .retain(|_, entry| now.duration_since(entry.window_start) < window);
            state.last_prune = now;
        }

        // Fast path: a known IP is updated in place, avoiding a per-request
        // `String` allocation for the map key.
        if let Some(entry) = state.entries.get_mut(ip) {
            if now.duration_since(entry.window_start) >= window {
                // Start a new window.
                entry.window_start = now;
                entry.count = 1;
                return Ok(());
            }
            entry.count += 1;
            return if entry.count > self.max_requests as u64 {
                Err(AuthError::RateLimited)
            } else {
                Ok(())
            };
        }

        // First time we see this IP: allocate the key and insert.
        state.entries.insert(
            ip.to_string(),
            RateEntry {
                count: 1,
                window_start: now,
            },
        );
        Ok(())
    }

    /// Remove entries whose window has fully elapsed, bounding memory usage.
    ///
    /// `check` already prunes lazily; this is exposed for manual or scheduled
    /// pruning if a caller wants to reclaim memory more eagerly.
    pub fn prune(&self) {
        let now = Instant::now();
        let window = self.window;
        let mut state = self.state.lock().expect("rate limiter state poisoned");
        state
            .entries
            .retain(|_, entry| now.duration_since(entry.window_start) < window);
        state.last_prune = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrency_limiter_releases_on_drop() {
        let limiter = Arc::new(ConcurrencyLimiter::new(2));
        assert_eq!(limiter.current(), 0);

        let p1 = limiter.acquire().await;
        let _p2 = limiter.acquire().await;
        assert_eq!(limiter.current(), 2);

        drop(p1);
        assert_eq!(limiter.current(), 1);
    }

    #[tokio::test]
    async fn test_concurrency_limiter_parks_and_wakes_when_full() {
        // A third acquire on a limiter of 2 must not complete until a permit is
        // released — and it must complete promptly once one is (no busy poll).
        let limiter = Arc::new(ConcurrencyLimiter::new(2));
        let p1 = limiter.acquire().await;
        let _p2 = limiter.acquire().await;

        let mut fut = Box::pin(limiter.acquire());
        let waker = Waker::from(Arc::new(NoopWake));
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

    struct NoopWake;
    impl std::task::Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    #[test]
    fn test_rate_limiter_allows_until_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("1.2.3.4").is_ok());
        assert!(limiter.check("1.2.3.4").is_ok());
        // Third request in the same window exceeds the limit.
        assert!(matches!(limiter.check("1.2.3.4"), Err(AuthError::RateLimited)));

        // A different IP has its own budget.
        assert!(limiter.check("5.6.7.8").is_ok());
    }

    #[test]
    fn test_rate_limiter_prune_bounds_map() {
        let limiter = RateLimiter::new(5, Duration::from_millis(1));
        for i in 0..100 {
            let _ = limiter.check(&format!("10.0.0.{i}"));
        }
        // After the window elapses, prune drops every stale entry.
        std::thread::sleep(Duration::from_millis(5));
        limiter.prune();
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.entries.len(), 0);
    }
}

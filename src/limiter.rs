//! Concurrency limiting and per-IP rate limiting used by the auth middleware.
//!
//! Both helpers are runtime-agnostic: the concurrency limiter uses an atomic
//! counter with `ntex::time::sleep` backoff (no dependency on a specific
//! runtime's semaphore), and the rate limiter uses a plain `Mutex<HashMap>`.

use crate::error::AuthError;
use ntex::time::sleep;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Limits the number of concurrently in-flight validations.
pub struct ConcurrencyLimiter {
    current: AtomicUsize,
    max: usize,
}

impl ConcurrencyLimiter {
    /// Create a new limiter allowing up to `max` concurrent operations.
    pub fn new(max: usize) -> Self {
        Self {
            current: AtomicUsize::new(0),
            max,
        }
    }

    /// Acquire a permit, waiting asynchronously when the limit is reached.
    pub async fn acquire(&self) -> ConcurrencyPermit<'_> {
        loop {
            let current = self.current.load(Ordering::Acquire);
            if current < self.max {
                if self
                    .current
                    .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return ConcurrencyPermit { limiter: self };
                }
            } else {
                // Back off briefly under contention instead of busy-waiting.
                sleep(Duration::from_millis(1)).await;
            }
        }
    }

    /// Current number of in-flight operations.
    pub fn current(&self) -> usize {
        self.current.load(Ordering::Acquire)
    }
}

/// RAII permit returned by [`ConcurrencyLimiter::acquire`]. Releases a slot on drop.
pub struct ConcurrencyPermit<'a> {
    limiter: &'a ConcurrencyLimiter,
}

impl Drop for ConcurrencyPermit<'_> {
    fn drop(&mut self) {
        self.limiter.current.fetch_sub(1, Ordering::Release);
    }
}

/// Per-IP fixed-window rate limiter.
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    state: Mutex<HashMap<String, RateEntry>>,
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
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt for `ip` and return an error if the limit is exceeded.
    pub fn check(&self, ip: &str) -> Result<(), AuthError> {
        let now = Instant::now();
        let mut state = self.state.lock().expect("rate limiter state poisoned");

        let entry = state.entry(ip.to_string()).or_insert(RateEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) >= self.window {
            // Start a new window.
            entry.window_start = now;
            entry.count = 1;
            Ok(())
        } else {
            entry.count += 1;
            if entry.count > self.max_requests as u64 {
                Err(AuthError::RateLimited)
            } else {
                Ok(())
            }
        }
    }

    /// Remove entries whose window has fully elapsed, bounding memory usage.
    pub fn prune(&self) {
        let now = Instant::now();
        let mut state = self.state.lock().expect("rate limiter state poisoned");
        state.retain(|_, entry| now.duration_since(entry.window_start) < self.window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrency_limiter_releases_on_drop() {
        let limiter = ConcurrencyLimiter::new(2);
        assert_eq!(limiter.current(), 0);

        let _p1 = limiter.acquire().await;
        let _p2 = limiter.acquire().await;
        assert_eq!(limiter.current(), 2);

        drop(_p1);
        assert_eq!(limiter.current(), 1);
    }

    #[test]
    fn test_rate_limiter_allows_until_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("1.2.3.4").is_ok());
        assert!(limiter.check("1.2.3.4").is_ok());
        // Third request in the same window exceeds the limit.
        assert!(matches!(
            limiter.check("1.2.3.4"),
            Err(AuthError::RateLimited)
        ));

        // A different IP has its own budget.
        assert!(limiter.check("5.6.7.8").is_ok());
    }
}

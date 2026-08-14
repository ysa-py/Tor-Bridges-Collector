//! Per-client rate limiting for the agent.
//!
//! A volunteer agent is a shared, quota-sensitive resource: unbounded probing
//! would both exhaust the volunteer and make the agent an amplification point.
//! [`RateLimiter`] enforces a token bucket per client (keyed by the peer's IP)
//! so a single caller can never exceed the configured burst and sustained
//! rate. [`TokenBucket`] refills against the wall clock and is deterministic
//! when the caller supplies `now`, which keeps the tests flake-free.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

/// A single refilling token bucket.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: u32,
    refill_rate: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a bucket full to `capacity`, refilling at
    /// `refill_per_second` tokens per second. Both values are clamped to at
    /// least one so a misconfigured limiter degrades to allow-one, never to a
    /// divide-by-zero or an always-open gate.
    pub fn new(capacity: u32, refill_per_second: u32, now: Instant) -> Self {
        let capacity = capacity.max(1);
        let refill_rate = f64::from(refill_per_second.max(1));
        Self {
            capacity,
            refill_rate,
            tokens: f64::from(capacity),
            last_refill: now,
        }
    }

    /// The number of tokens currently available (fractional values reflect a
    /// partially-completed refill interval).
    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    /// Try to spend one token at instant `now`, refilling first. Returns
    /// `false` (without spending) when the bucket is empty.
    pub fn try_acquire(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_rate).min(f64::from(self.capacity));
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A registry of per-client token buckets.
#[derive(Debug)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    capacity: u32,
    refill_per_second: u32,
}

impl RateLimiter {
    /// Build a limiter where each client gets its own bucket of `capacity`
    /// tokens refilling at `refill_per_second` per second.
    pub fn new(capacity: u32, refill_per_second: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
            refill_per_second: refill_per_second.max(1),
        }
    }

    /// Reserve one request for `key`, creating its bucket on first use.
    pub fn allow(&self, key: &str) -> bool {
        let mut buckets = self.lock();
        let now = Instant::now();
        let bucket = buckets
            .entry(key.to_owned())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_per_second, now));
        bucket.try_acquire(now)
    }

    /// The number of distinct clients currently tracked.
    pub fn entries(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, TokenBucket>> {
        self.buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_starts_full_and_drains() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(3, 1, now);
        assert!(bucket.try_acquire(now));
        assert!(bucket.try_acquire(now));
        assert!(bucket.try_acquire(now));
        assert!(!bucket.try_acquire(now));
    }

    #[test]
    fn bucket_refills_with_elapsed_time() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(1, 1, now);
        assert!(bucket.try_acquire(now));
        assert!(!bucket.try_acquire(now));
        // Two seconds later, two tokens (the refill plus the elapsed second
        // after the initial drain) are available.
        assert!(bucket.try_acquire(now + Duration::from_secs(2)));
    }

    #[test]
    fn bucket_caps_at_capacity() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(2, 1000, now);
        // Long elapsed time must not inflate the bucket beyond capacity.
        assert!(bucket.try_acquire(now + Duration::from_secs(60)));
        assert!(bucket.try_acquire(now + Duration::from_secs(60)));
        assert!(!bucket.try_acquire(now + Duration::from_secs(60)));
    }

    #[test]
    fn limiter_isolates_clients() {
        let limiter = RateLimiter::new(1, 1);
        assert!(limiter.allow("client-a"));
        assert!(!limiter.allow("client-a"));
        assert!(limiter.allow("client-b"));
        assert_eq!(limiter.entries(), 2);
    }
}

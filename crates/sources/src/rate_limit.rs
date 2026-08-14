//! Global token-bucket rate limiter.
//!
//! All sources share one budget so a burst of collectors cannot collectively
//! hammer a host. The bucket refills at a fixed rate and allows short bursts
//! up to a configured ceiling; over-use accrues as "debt" (a negative token
//! count) that spaces out subsequent acquisitions instead of failing them.
//!
//! Time comes from the injected [`tbc_core::Clock`], so accounting is
//! deterministic and unit-testable without sleeping. The async
//! [`TokenBucket::acquire`] wrapper performs the actual `tokio` sleep; the
//! pure [`TokenBucket::take`] method is the tested, deterministic core.

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::SourceError;
use tbc_core::Clock;

/// Mutable bucket state guarded by a mutex. The lock is recovered with
/// `unwrap_or_else(|poisoned| poisoned.into_inner())` so a panicked writer can
/// never turn a rate-limit check into a second panic.
#[derive(Debug)]
struct BucketState {
    /// Current token balance; may be negative (debt) after over-use.
    tokens: f64,
    /// Instant of the last refill.
    last_refill: DateTime<Utc>,
}

impl BucketState {
    fn refill(&mut self, now: DateTime<Utc>, rate_per_sec: f64, burst: f64) {
        let elapsed_ms = now
            .signed_duration_since(self.last_refill)
            .num_milliseconds();
        if elapsed_ms <= 0 {
            self.last_refill = now;
            return;
        }
        let gained = (elapsed_ms as f64 / 1000.0) * rate_per_sec;
        self.tokens = (self.tokens + gained).min(burst);
        self.last_refill = now;
    }
}

/// A token-bucket limiter shared across sources.
#[derive(Debug)]
pub struct TokenBucket {
    rate_per_sec: f64,
    burst: f64,
    clock: std::sync::Arc<dyn Clock>,
    state: Mutex<BucketState>,
}

impl TokenBucket {
    /// Create a bucket that refills `rate_per_sec` tokens per second and holds
    /// at most `burst` tokens.
    pub fn new(
        rate_per_sec: f64,
        burst: f64,
        clock: std::sync::Arc<dyn Clock>,
    ) -> Result<Self, SourceError> {
        if !rate_per_sec.is_finite() || rate_per_sec <= 0.0 {
            return Err(SourceError::RateLimit(format!(
                "rate must be a positive finite number, got {rate_per_sec}"
            )));
        }
        if !burst.is_finite() || burst < 1.0 {
            return Err(SourceError::RateLimit(format!(
                "burst must be >= 1 and finite, got {burst}"
            )));
        }
        let now = clock.now();
        Ok(Self {
            rate_per_sec,
            burst,
            clock,
            state: Mutex::new(BucketState {
                tokens: burst,
                last_refill: now,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, BucketState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Deterministically reserve one token at `now`, returning the duration
    /// the caller must wait before acting. Never fails once constructed.
    ///
    /// This is the tested core; [`Self::acquire`] wraps it with a real sleep.
    pub fn take(&self, now: DateTime<Utc>) -> Duration {
        let mut state = self.lock();
        state.refill(now, self.rate_per_sec, self.burst);
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            return Duration::ZERO;
        }
        // Not enough tokens: accrue one token of debt and report the wait the
        // deficit implies at the configured refill rate.
        let deficit = 1.0 - state.tokens;
        state.tokens -= 1.0;
        let wait_secs = deficit / self.rate_per_sec;
        // `wait_secs` is positive and finite here: deficit > 0 always (tokens
        // < 1.0), and rate is validated positive and finite at construction.
        Duration::from_secs_f64(wait_secs)
    }

    /// Acquire one token, sleeping if the bucket is temporarily empty.
    pub async fn acquire(&self) -> Result<(), SourceError> {
        let wait = self.take(self.clock.now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        Ok(())
    }

    /// Current token balance (including debt) at the injected clock's now.
    pub fn tokens(&self) -> f64 {
        let mut state = self.lock();
        state.refill(self.clock.now(), self.rate_per_sec, self.burst);
        state.tokens
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use std::sync::Arc as StdArc;
    use tbc_core::TestClock;

    /// A `TestClock` behind interior mutability so a test can advance time
    /// while the bucket holds an `Arc<dyn Clock>` to the same state.
    #[derive(Debug)]
    struct SharedTestClock {
        inner: Mutex<TestClock>,
    }

    impl SharedTestClock {
        fn new(now: DateTime<Utc>) -> Self {
            Self {
                inner: Mutex::new(TestClock::new(now)),
            }
        }

        fn advance(&self, delta: ChronoDuration) {
            self.inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .advance(delta);
        }
    }

    impl Clock for SharedTestClock {
        fn now(&self) -> DateTime<Utc> {
            self.inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .now()
        }
    }

    fn clock() -> (StdArc<SharedTestClock>, StdArc<dyn Clock>) {
        let start = DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let test = StdArc::new(SharedTestClock::new(start));
        let shared: StdArc<dyn Clock> = test.clone();
        (test, shared)
    }

    #[test]
    fn burst_consumed_without_delay() {
        let (_, clock) = clock();
        let bucket = TokenBucket::new(1.0, 2.0, clock).unwrap();
        assert_eq!(bucket.take(bucket.clock.now()), Duration::ZERO);
        assert_eq!(bucket.take(bucket.clock.now()), Duration::ZERO);
        // Third acquisition exceeds the burst and requires a wait.
        let wait = bucket.take(bucket.clock.now());
        assert!(wait > Duration::ZERO);
        assert!((wait.as_secs_f64() - 1.0).abs() < 0.001);
    }

    #[test]
    fn refill_over_time_restores_capacity() {
        let (test, clock) = clock();
        let bucket = TokenBucket::new(2.0, 2.0, clock).unwrap();
        assert_eq!(bucket.take(bucket.clock.now()), Duration::ZERO);
        assert_eq!(bucket.take(bucket.clock.now()), Duration::ZERO);
        // Empty. Advance 1 second at 2 tokens/sec -> 2 tokens restored.
        test.advance(ChronoDuration::seconds(1));
        assert_eq!(bucket.take(bucket.clock.now()), Duration::ZERO);
        assert_eq!(bucket.take(bucket.clock.now()), Duration::ZERO);
    }

    #[test]
    fn debt_spaces_out_sustained_over_use() {
        let (_, clock) = clock();
        let bucket = TokenBucket::new(1.0, 1.0, clock).unwrap();
        assert_eq!(bucket.take(bucket.clock.now()), Duration::ZERO);
        // Second immediate acquisition has no token: wait ~1s.
        let w1 = bucket.take(bucket.clock.now());
        assert!((w1.as_secs_f64() - 1.0).abs() < 0.001);
        // A third immediate acquisition accrues more debt: wait ~2s.
        let w2 = bucket.take(bucket.clock.now());
        assert!((w2.as_secs_f64() - 2.0).abs() < 0.001);
    }

    #[test]
    fn invalid_config_is_rejected() {
        let (_, clock) = clock();
        assert!(TokenBucket::new(0.0, 1.0, clock.clone()).is_err());
        assert!(TokenBucket::new(f64::NAN, 1.0, clock.clone()).is_err());
        assert!(TokenBucket::new(1.0, 0.0, clock.clone()).is_err());
    }
}

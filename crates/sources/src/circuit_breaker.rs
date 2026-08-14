//! Per-host circuit breaker.
//!
//! After `failure_threshold` consecutive failures the breaker opens and
//! refuses requests for `open_duration`, protecting an ailing host from a
//! retry storm. Once the cool-down elapses it moves to half-open and allows a
//! limited number of trial requests; `success_threshold` consecutive trial
//! successes close it again, and any trial failure re-opens it.
//!
//! Time comes from the injected [`tbc_core::Clock`] so state transitions are
//! deterministic in tests.

use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};

use crate::error::SourceError;
use tbc_core::Clock;

/// Circuit-breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

/// Configuration for a [`CircuitBreaker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures that trip the breaker from closed to open.
    pub failure_threshold: u32,
    /// Consecutive half-open successes that close the breaker again.
    pub success_threshold: u32,
    /// How long the breaker stays open before allowing a trial.
    pub open_duration: std::time::Duration,
    /// Maximum concurrent half-open trial requests before refusing again.
    pub half_open_max: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            open_duration: std::time::Duration::from_secs(30),
            half_open_max: 1,
        }
    }
}

#[derive(Debug)]
struct Inner {
    state: State,
    failures: u32,
    half_open_successes: u32,
    opened_at: Option<DateTime<Utc>>,
}

/// A per-host circuit breaker.
#[derive(Debug)]
pub struct CircuitBreaker {
    host: String,
    config: CircuitBreakerConfig,
    clock: Arc<dyn Clock>,
    state: Mutex<Inner>,
}

impl CircuitBreaker {
    /// Create a breaker for `host`.
    pub fn new(host: String, config: CircuitBreakerConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            host,
            config,
            clock,
            state: Mutex::new(Inner {
                state: State::Closed,
                failures: 0,
                half_open_successes: 0,
                opened_at: None,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Check whether a request may proceed.
    pub fn allow(&self) -> Result<(), SourceError> {
        let mut inner = self.lock();
        match inner.state {
            State::Closed => Ok(()),
            State::Open => {
                let now = self.clock.now();
                let elapsed_ms = inner
                    .opened_at
                    .map(|opened| now.signed_duration_since(opened).num_milliseconds())
                    .unwrap_or(i64::MAX);
                if elapsed_ms >= self.config.open_duration.as_millis() as i64 {
                    inner.state = State::HalfOpen;
                    inner.half_open_successes = 0;
                    Ok(())
                } else {
                    Err(SourceError::CircuitOpen {
                        host: self.host.clone(),
                    })
                }
            }
            State::HalfOpen => {
                if inner.half_open_successes >= self.config.half_open_max {
                    Err(SourceError::CircuitOpen {
                        host: self.host.clone(),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        let mut inner = self.lock();
        match inner.state {
            // A success resets the consecutive-failure counter so the breaker
            // trips on sustained failure, not on failures spread over a
            // healthy stretch.
            State::Closed => {
                inner.failures = 0;
            }
            State::HalfOpen => {
                inner.half_open_successes = inner.half_open_successes.saturating_add(1);
                if inner.half_open_successes >= self.config.success_threshold {
                    inner.state = State::Closed;
                    inner.failures = 0;
                    inner.opened_at = None;
                }
            }
            State::Open => {}
        }
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        let mut inner = self.lock();
        match inner.state {
            State::Closed => {
                inner.failures = inner.failures.saturating_add(1);
                if inner.failures >= self.config.failure_threshold {
                    inner.state = State::Open;
                    inner.opened_at = Some(self.clock.now());
                    inner.failures = 0;
                }
            }
            State::HalfOpen => {
                inner.state = State::Open;
                inner.opened_at = Some(self.clock.now());
                inner.half_open_successes = 0;
            }
            State::Open => {}
        }
    }

    /// The breaker's current state.
    pub fn state(&self) -> State {
        self.lock().state
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use std::sync::{Arc as StdArc, Mutex};
    use tbc_core::TestClock;

    /// A `TestClock` behind interior mutability so a test can advance time
    /// while the breaker holds an `Arc<dyn Clock>` to the same state.
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

    fn breaker(threshold: u32) -> (StdArc<SharedTestClock>, CircuitBreaker) {
        let start = DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let clock = StdArc::new(SharedTestClock::new(start));
        let config = CircuitBreakerConfig {
            failure_threshold: threshold,
            success_threshold: 2,
            open_duration: std::time::Duration::from_secs(10),
            half_open_max: 1,
        };
        let shared: Arc<dyn Clock> = clock.clone();
        (clock, CircuitBreaker::new("host".into(), config, shared))
    }

    #[test]
    fn trips_after_threshold_failures() {
        let (_, b) = breaker(3);
        assert_eq!(b.state(), State::Closed);
        b.record_failure();
        b.record_failure();
        assert_eq!(b.state(), State::Closed);
        b.record_failure();
        assert_eq!(b.state(), State::Open);
        assert!(matches!(b.allow(), Err(SourceError::CircuitOpen { .. })));
    }

    #[test]
    fn half_open_after_cool_down_then_closes_on_success() {
        let (clock, b) = breaker(1);
        b.record_failure();
        assert_eq!(b.state(), State::Open);
        assert!(b.allow().is_err());

        clock.advance(ChronoDuration::seconds(10));
        assert!(b.allow().is_ok());
        assert_eq!(b.state(), State::HalfOpen);

        // Half-open trial allowed; first success increments but stays half-open.
        b.record_success();
        assert_eq!(b.state(), State::HalfOpen);
        b.record_success();
        assert_eq!(b.state(), State::Closed);
    }

    #[test]
    fn half_open_failure_reopens() {
        let (clock, b) = breaker(1);
        b.record_failure();
        clock.advance(ChronoDuration::seconds(10));
        assert!(b.allow().is_ok());
        assert_eq!(b.state(), State::HalfOpen);
        b.record_failure();
        assert_eq!(b.state(), State::Open);
        assert!(b.allow().is_err());
    }

    #[test]
    fn success_resets_consecutive_failure_counter() {
        let (_, b) = breaker(3);
        b.record_failure();
        b.record_failure();
        b.record_success();
        b.record_failure();
        b.record_failure();
        assert_eq!(b.state(), State::Closed);
    }
}

//! Injectable clock abstraction.
//!
//! The master spec requires zero-flaky tests with an injected clock rather
//! than unbounded sleeps. Production code takes a `&dyn Clock` (or uses
//! [`SystemClock`]) and obtains "now" through it; tests substitute
//! [`TestClock`] and advance time deterministically.

use chrono::{DateTime, Duration, Utc};
use std::fmt;

/// A source of the current instant.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current instant in UTC.
    fn now(&self) -> DateTime<Utc>;
}

/// The real system clock, backed by [`Utc::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A manually advanced clock for deterministic tests and simulations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestClock {
    now: DateTime<Utc>,
}

impl TestClock {
    /// Create a clock fixed at `now`.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { now }
    }

    /// Override the current instant.
    pub fn set_now(&mut self, now: DateTime<Utc>) {
        self.now = now;
    }

    /// Advance the current instant by `delta`.
    pub fn advance(&mut self, delta: Duration) {
        self.now += delta;
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        self.now
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_advances_deterministically() {
        let start = DateTime::parse_from_rfc3339("2026-08-13T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut clock = TestClock::new(start);
        clock.advance(Duration::seconds(30));
        assert_eq!(clock.now().to_rfc3339(), "2026-08-13T00:00:30+00:00");
    }
}

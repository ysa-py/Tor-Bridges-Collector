//! Jittered exponential backoff.
//!
//! Retry delays grow geometrically and are randomized ("full-ish jitter" via a
//! symmetric ±`jitter` fraction) so many collectors retrying in lock-step do
//! not synchronize into thundering herds. [`Backoff::base_delay`] is the pure,
//! deterministic core used by tests; [`Backoff::next`] adds the random jitter
//! and advances the attempt counter.

use std::time::Duration;

use rand::Rng;

use crate::error::SourceError;

/// Jittered exponential backoff state.
#[derive(Debug, Clone)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    multiplier: f64,
    /// Jitter fraction in `0.0..=1.0`; the jittered delay lies in
    /// `[base * (1 - jitter), base * (1 + jitter)]`.
    jitter: f64,
    attempt: u32,
}

impl Backoff {
    /// Create a backoff policy. `multiplier` must be `>= 1.0`, `max` must be
    /// `>= initial`, and `jitter` must lie in `0.0..=1.0`.
    pub fn new(
        initial: Duration,
        max: Duration,
        multiplier: f64,
        jitter: f64,
    ) -> Result<Self, SourceError> {
        if initial.is_zero() {
            return Err(SourceError::Config(
                "backoff initial delay must be non-zero".into(),
            ));
        }
        if max < initial {
            return Err(SourceError::Config(format!(
                "backoff max ({max:?}) must be >= initial ({initial:?})"
            )));
        }
        if !multiplier.is_finite() || multiplier < 1.0 {
            return Err(SourceError::Config(format!(
                "backoff multiplier must be >= 1 and finite, got {multiplier}"
            )));
        }
        if !jitter.is_finite() || !(0.0..=1.0).contains(&jitter) {
            return Err(SourceError::Config(format!(
                "backoff jitter must be in 0.0..=1.0, got {jitter}"
            )));
        }
        Ok(Self {
            initial,
            max,
            multiplier,
            jitter,
            attempt: 0,
        })
    }

    /// The deterministic base delay for a given attempt index (0-based),
    /// capped at `max` and never overflowing.
    pub fn base_delay(&self, attempt: u32) -> Duration {
        // `powf` (f64 exponent) handles arbitrarily large attempt indices by
        // overflowing to infinity, which the finite/cap check below turns into
        // `max`. An `i32` cast would silently wrap and underflow the delay.
        let raw = self.initial.as_secs_f64() * self.multiplier.powf(attempt as f64);
        if !raw.is_finite() || raw > self.max.as_secs_f64() {
            return self.max;
        }
        Duration::from_secs_f64(raw)
    }

    /// The next jittered delay, advancing the internal attempt counter.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.base_delay(self.attempt);
        self.attempt = self.attempt.saturating_add(1);

        let jitter_factor = if self.jitter <= 0.0 {
            0.0
        } else {
            let sample: f64 = rand::thread_rng().gen_range(0.0..=1.0);
            (sample * 2.0 - 1.0) * self.jitter
        };
        // jitter_factor ∈ [-jitter, +jitter], so 1 + jitter_factor ∈ [0, 2].
        let factor = (1.0 + jitter_factor).clamp(0.0, 2.0);
        base.mul_f64(factor)
    }

    /// The number of `next_delay` calls issued so far.
    pub fn attempts(&self) -> u32 {
        self.attempt
    }
}

impl Default for Backoff {
    /// A conservative default: 500 ms base, 30 s ceiling, doubling, 25% jitter.
    fn default() -> Self {
        // Fixed, valid constants — construction cannot fail.
        Self {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: 0.25,
            attempt: 0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn base_delay_doubles_and_caps() {
        let b = Backoff::new(Duration::from_secs(1), Duration::from_secs(4), 2.0, 0.0).unwrap();
        assert_eq!(b.base_delay(0), Duration::from_secs(1));
        assert_eq!(b.base_delay(1), Duration::from_secs(2));
        assert_eq!(b.base_delay(2), Duration::from_secs(4));
        assert_eq!(b.base_delay(3), Duration::from_secs(4));
        // A huge attempt index saturates to max instead of overflowing.
        assert_eq!(b.base_delay(u32::MAX), Duration::from_secs(4));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let mut b =
            Backoff::new(Duration::from_secs(1), Duration::from_secs(60), 2.0, 0.5).unwrap();
        for _ in 0..100 {
            let attempt = b.attempts();
            let base = b.base_delay(attempt).as_secs_f64();
            let d = b.next_delay().as_secs_f64();
            assert!(d >= base * 0.5 - 1e-9, "delay {d} below lower bound");
            assert!(d <= base * 1.5 + 1e-9, "delay {d} above upper bound");
        }
    }

    #[test]
    fn invalid_config_is_rejected() {
        assert!(Backoff::new(Duration::ZERO, Duration::from_secs(1), 2.0, 0.0).is_err());
        assert!(Backoff::new(Duration::from_secs(5), Duration::from_secs(1), 2.0, 0.0).is_err());
        assert!(Backoff::new(Duration::from_secs(1), Duration::from_secs(10), 0.5, 0.0).is_err());
        assert!(Backoff::new(Duration::from_secs(1), Duration::from_secs(10), 2.0, 1.5).is_err());
    }
}

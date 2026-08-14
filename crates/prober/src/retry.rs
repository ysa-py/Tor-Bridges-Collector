//! Retry backoff computation.
//!
//! `backoff_delay` is the deterministic, overflow-safe exponential component;
//! `full_jitter` randomizes it in `[0, delay]` at the call site so retries
//! from concurrent runners do not synchronize. Both are pure functions of
//! their inputs and are unit-tested without sleeping.

use std::time::Duration;

/// The exponential backoff delay for `attempt` (0-based): `base * 2^attempt`,
/// capped at `max`. Overflow-safe for any `u32` attempt.
pub fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let shift = attempt.min(63);
    let factor = 1u128 << shift;
    let millis = base.as_millis().saturating_mul(factor);
    let millis = millis.min(max.as_millis());
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
}

/// Randomize a delay uniformly in `[0, delay]` (full jitter). Returns zero for
/// a zero delay.
pub fn full_jitter(delay: Duration) -> Duration {
    use rand::Rng;
    let millis = delay.as_millis();
    if millis == 0 {
        return Duration::ZERO;
    }
    let upper = u64::try_from(millis).unwrap_or(u64::MAX);
    let jittered = rand::thread_rng().gen_range(0..=upper);
    Duration::from_millis(jittered)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn backoff_delay_starts_at_base_and_grows() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(2);
        let d0 = backoff_delay(0, base, max);
        let d1 = backoff_delay(1, base, max);
        let d2 = backoff_delay(2, base, max);
        assert_eq!(d0, base);
        assert_eq!(d1, Duration::from_millis(200));
        assert_eq!(d2, Duration::from_millis(400));
        assert!(d2 > d1 && d1 > d0);
    }

    #[test]
    fn backoff_delay_caps_at_max() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(3);
        assert_eq!(backoff_delay(0, base, max), Duration::from_secs(1));
        assert_eq!(backoff_delay(1, base, max), Duration::from_secs(2));
        assert_eq!(backoff_delay(2, base, max), Duration::from_secs(3));
        assert_eq!(backoff_delay(63, base, max), Duration::from_secs(3));
    }

    #[test]
    fn backoff_delay_is_overflow_safe() {
        let base = Duration::from_secs(60);
        let max = Duration::from_secs(3600);
        // A huge attempt must still return a finite, capped delay.
        let delay = backoff_delay(u32::MAX, base, max);
        assert_eq!(delay, max);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let delay = Duration::from_millis(50);
        for _ in 0..100 {
            let jittered = full_jitter(delay);
            assert!(jittered <= delay);
        }
        assert_eq!(full_jitter(Duration::ZERO), Duration::ZERO);
    }
}

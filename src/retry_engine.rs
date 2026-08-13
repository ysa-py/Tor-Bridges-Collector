//! Parity port of `gateway/retry_engine.py`.
//!
//! Implements the same provider-aware retry strategy as the Python original:
//!   - HTTP 400: rotate model (never retry same slot)
//!   - HTTP 429: exponential backoff with jitter, then rotate slot
//!   - HTTP 5xx: retry up to N times with backoff, then rotate slot
//!   - HTTP 401/403: rotate slot immediately (auth failure)
//!   - Timeout (code 0): rotate immediately
//!   - Unknown: rotate slot
//!
//! The Python original wires side effects (logging, circuit breaker updates,
//! report generator events) inside `decide()`. The Rust port keeps the
//! decision logic pure and exposes the same fields via [`RetryDecision`] so
//! callers can apply the side effects in their own typed-error-safe paths.
//! Side-effect hooks are intentionally NOT in the parity contract — they are
//! cross-cutting concerns owned by the orchestrator.

use serde_json::{json, Value};

/// Mirror of Python's `RetryAction` enum. Order of variants matches the
/// string values used in JSON serialization so parity tests can compare
/// verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAction {
    RetrySame,
    RotateModel,
    RotateSlot,
    RotateProvider,
    Fail,
}

impl RetryAction {
    /// Return the snake_case string the Python `RetryAction` enum uses as
    /// its `.value` attribute.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RetrySame => "retry_same",
            Self::RotateModel => "rotate_model",
            Self::RotateSlot => "rotate_slot",
            Self::RotateProvider => "rotate_provider",
            Self::Fail => "fail",
        }
    }
}

/// Mirror of Python's `RetryDecision` dataclass.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryDecision {
    pub action: RetryAction,
    pub delay_secs: f64,
    pub reason: String,
    pub attempt_number: i64,
    pub max_attempts: i64,
}

impl RetryDecision {
    /// Serialize to JSON for parity-test comparison. Field names match the
    /// Python dataclass field names exactly.
    pub fn to_json(&self) -> Value {
        json!({
            "action": self.action.as_str(),
            "delay_secs": self.delay_secs,
            "reason": self.reason,
            "attempt_number": self.attempt_number,
            "max_attempts": self.max_attempts,
        })
    }
}

/// Tuning parameters for the retry engine. Mirrors the four env-var-driven
/// constants read at construction time in the Python original.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryConfig {
    pub backoff_cap_secs: f64,
    pub max_attempts_400: i64,
    pub max_attempts_429: i64,
    pub max_attempts_5xx: i64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            backoff_cap_secs: 60.0,
            max_attempts_400: 0,
            max_attempts_429: 5,
            max_attempts_5xx: 3,
        }
    }
}

/// Pure retry-decision engine. Mirrors `RetryEngine.decide()` from
/// `gateway/retry_engine.py` minus the side effects.
///
/// `compute_backoff` is injectable so tests can substitute a deterministic
/// function (the Python original uses `random.uniform(-0.5, 0.5)` which
/// is non-deterministic and therefore not parity-testable verbatim).
#[derive(Debug, Clone, PartialEq)]
pub struct RetryEngine<F: Fn(i64) -> f64> {
    config: RetryConfig,
    compute_backoff: F,
}

impl RetryEngine<fn(i64) -> f64> {
    /// Construct a retry engine whose default backoff curve is `2^attempt`
    /// capped at `config.backoff_cap_secs` (no jitter). Used in production
    /// when jitter is added by the caller, or in tests where determinism is
    /// required.
    ///
    /// The cap is read from the config instead of a hardcoded constant, so
    /// the previously-ignored `backoff_cap_secs` field now controls the
    /// curve. Engines built with [`RetryConfig::default()`] (cap 60.0)
    /// behave identically to the pre-change engine.
    #[must_use]
    pub fn new(config: RetryConfig) -> RetryEngine<impl Fn(i64) -> f64> {
        let cap = config.backoff_cap_secs;
        RetryEngine {
            config,
            compute_backoff: move |attempt| default_backoff_with_cap(attempt, cap),
        }
    }
}

impl<F: Fn(i64) -> f64> RetryEngine<F> {
    /// Construct a retry engine with a custom backoff function. The function
    /// receives the 0-indexed attempt number and returns the delay in
    /// seconds.
    pub fn with_backoff(config: RetryConfig, compute_backoff: F) -> Self {
        Self {
            config,
            compute_backoff,
        }
    }

    /// Decide what action to take after a failed request.
    ///
    /// Mirrors `RetryEngine.decide()` from `gateway/retry_engine.py`:
    /// - HTTP 400 → rotate model (never retry same slot)
    /// - HTTP 429 → exponential backoff until max attempts, then rotate slot
    /// - HTTP 5xx → retry with backoff up to max attempts, then rotate slot
    /// - HTTP 401/403 → rotate slot immediately
    /// - HTTP 0 (timeout) → rotate slot immediately
    /// - Anything else → rotate slot
    pub fn decide(
        &self,
        error_code: i64,
        attempt: i64,
        _provider: &str,
        slot: i64,
        model: &str,
    ) -> RetryDecision {
        // HTTP 400 — BAD REQUEST
        if error_code == 400 {
            return RetryDecision {
                action: RetryAction::RotateModel,
                delay_secs: 0.0,
                reason: "HTTP 400: bad request — rotate model, don't retry".to_string(),
                attempt_number: attempt,
                max_attempts: self.config.max_attempts_400,
            };
        }

        // HTTP 429 — RATE LIMITED
        if error_code == 429 {
            let delay = (self.compute_backoff)(attempt);
            if attempt < self.config.max_attempts_429 {
                return RetryDecision {
                    action: RetryAction::RetrySame,
                    delay_secs: delay,
                    reason: format!("HTTP 429: rate limited — backoff {:.1}s", delay),
                    attempt_number: attempt,
                    max_attempts: self.config.max_attempts_429,
                };
            }
            return RetryDecision {
                action: RetryAction::RotateSlot,
                delay_secs: 0.0,
                reason: "HTTP 429: max retries reached — rotate slot".to_string(),
                attempt_number: attempt,
                max_attempts: self.config.max_attempts_429,
            };
        }

        // HTTP 5xx — SERVER ERROR
        if error_code >= 500 {
            let delay = (self.compute_backoff)(attempt);
            if attempt < self.config.max_attempts_5xx {
                return RetryDecision {
                    action: RetryAction::RetrySame,
                    delay_secs: delay,
                    reason: format!("HTTP {}: server error — retry with backoff", error_code),
                    attempt_number: attempt,
                    max_attempts: self.config.max_attempts_5xx,
                };
            }
            return RetryDecision {
                action: RetryAction::RotateSlot,
                delay_secs: 0.0,
                reason: format!("HTTP {}: max retries — rotate slot", error_code),
                attempt_number: attempt,
                max_attempts: self.config.max_attempts_5xx,
            };
        }

        // HTTP 401/403 — AUTH FAILURE (mirrors Python's `error_code in (401, 403)`)
        if error_code == 401 || error_code == 403 {
            return RetryDecision {
                action: RetryAction::RotateSlot,
                delay_secs: 0.0,
                reason: format!("HTTP {}: auth failure — rotate slot", error_code),
                attempt_number: attempt,
                max_attempts: 0,
            };
        }

        // Timeout — code 0
        if error_code == 0 {
            return RetryDecision {
                action: RetryAction::RotateSlot,
                delay_secs: 0.0,
                reason: "Timeout — rotate immediately".to_string(),
                attempt_number: attempt,
                max_attempts: 0,
            };
        }

        // Unknown — try once more then fail
        let _ = (slot, model); // accepted for API parity; unused in decision
        RetryDecision {
            action: RetryAction::RotateSlot,
            delay_secs: 0.0,
            reason: format!("HTTP {}: unknown error — rotate slot", error_code),
            attempt_number: attempt,
            max_attempts: 1,
        }
    }
}

/// Default backoff curve: `2^attempt` capped at 60.0 seconds. No jitter.
///
/// Equivalent to [`default_backoff_with_cap`] at the historical 60.0 cap and
/// retained for callers that hardcode the historical curve. Engines built via
/// [`RetryEngine::new`] respect the configured `backoff_cap_secs` instead.
pub fn default_backoff(attempt: i64) -> f64 {
    default_backoff_with_cap(attempt, 60.0)
}

/// Exponential backoff curve `2^attempt` capped at `cap_secs`. No jitter.
/// Mirrors the Python original's `min(2 ** attempt, self._backoff_cap)`.
pub fn default_backoff_with_cap(attempt: i64, cap_secs: f64) -> f64 {
    let base = (2_i64).pow(attempt as u32) as f64;
    base.min(cap_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_engine() -> RetryEngine<impl Fn(i64) -> f64> {
        RetryEngine::new(RetryConfig::default())
    }

    #[test]
    fn http_400_rotates_model_without_retry() {
        let engine = default_engine();
        let decision = engine.decide(400, 0, "cloudflare", 1, "llama-3");
        assert_eq!(decision.action, RetryAction::RotateModel);
        assert_eq!(decision.delay_secs, 0.0);
        assert_eq!(decision.max_attempts, 0);
    }

    #[test]
    fn http_429_retries_with_backoff_until_max_then_rotates_slot() {
        let engine = default_engine();
        // attempt 0 → retry same with backoff 1.0
        let d0 = engine.decide(429, 0, "", 0, "");
        assert_eq!(d0.action, RetryAction::RetrySame);
        assert_eq!(d0.delay_secs, 1.0);
        // attempt 4 → still retry same (max=5, so attempt<5)
        let d4 = engine.decide(429, 4, "", 0, "");
        assert_eq!(d4.action, RetryAction::RetrySame);
        // attempt 5 → rotate slot
        let d5 = engine.decide(429, 5, "", 0, "");
        assert_eq!(d5.action, RetryAction::RotateSlot);
    }

    #[test]
    fn http_5xx_retries_then_rotates_slot() {
        let engine = default_engine();
        let d0 = engine.decide(503, 0, "", 0, "");
        assert_eq!(d0.action, RetryAction::RetrySame);
        let d3 = engine.decide(503, 3, "", 0, "");
        assert_eq!(d3.action, RetryAction::RotateSlot);
    }

    #[test]
    fn full_429_ladder_exact_delays_then_rotate_slot() {
        // Exponential backoff 2^attempt, no jitter: delays 1,2,4,8,16 for
        // attempts 0-4, then RotateSlot at attempt 5 (max_attempts_429 = 5).
        let engine = default_engine();
        let expected_delays = [1.0, 2.0, 4.0, 8.0, 16.0];
        for (attempt, &delay) in expected_delays.iter().enumerate() {
            let d = engine.decide(429, attempt as i64, "", 0, "");
            assert_eq!(d.action, RetryAction::RetrySame, "attempt {attempt}");
            assert_eq!(d.delay_secs, delay, "attempt {attempt} delay");
            assert_eq!(d.attempt_number, attempt as i64);
            assert_eq!(d.max_attempts, 5);
        }
        let d = engine.decide(429, 5, "", 0, "");
        assert_eq!(d.action, RetryAction::RotateSlot);
        assert_eq!(d.delay_secs, 0.0);
        assert_eq!(d.max_attempts, 5);
    }

    #[test]
    fn full_5xx_ladder_exact_delays_then_rotate_slot() {
        // 5xx retries at attempts 0-2 with delays 1,2,4, then RotateSlot at
        // attempt 3 (max_attempts_5xx = 3).
        let engine = default_engine();
        let expected_delays = [1.0, 2.0, 4.0];
        for (attempt, &delay) in expected_delays.iter().enumerate() {
            let d = engine.decide(500 + attempt as i64, attempt as i64, "", 0, "");
            assert_eq!(d.action, RetryAction::RetrySame, "attempt {attempt}");
            assert_eq!(d.delay_secs, delay, "attempt {attempt} delay");
            assert_eq!(d.attempt_number, attempt as i64);
            assert_eq!(d.max_attempts, 3);
        }
        let d = engine.decide(503, 3, "", 0, "");
        assert_eq!(d.action, RetryAction::RotateSlot);
        assert_eq!(d.delay_secs, 0.0);
        assert_eq!(d.max_attempts, 3);
    }

    #[test]
    fn http_401_and_403_rotate_slot_immediately() {
        let engine = default_engine();
        assert_eq!(
            engine.decide(401, 0, "", 0, "").action,
            RetryAction::RotateSlot
        );
        assert_eq!(
            engine.decide(403, 0, "", 0, "").action,
            RetryAction::RotateSlot
        );
    }

    #[test]
    fn timeout_rotates_immediately() {
        let engine = default_engine();
        let decision = engine.decide(0, 0, "", 0, "");
        assert_eq!(decision.action, RetryAction::RotateSlot);
        assert_eq!(decision.max_attempts, 0);
    }

    #[test]
    fn unknown_code_rotates_slot_with_one_attempt() {
        let engine = default_engine();
        let decision = engine.decide(418, 0, "", 0, "");
        assert_eq!(decision.action, RetryAction::RotateSlot);
        assert_eq!(decision.max_attempts, 1);
    }

    #[test]
    fn custom_backoff_function_is_used() {
        let engine = RetryEngine::with_backoff(RetryConfig::default(), |_| 42.0);
        let decision = engine.decide(429, 0, "", 0, "");
        assert_eq!(decision.delay_secs, 42.0);
    }

    #[test]
    fn default_backoff_caps_at_60_seconds() {
        assert_eq!(default_backoff(0), 1.0);
        assert_eq!(default_backoff(1), 2.0);
        assert_eq!(default_backoff(2), 4.0);
        assert_eq!(default_backoff(3), 8.0);
        assert_eq!(default_backoff(10), 60.0); // 2^10 = 1024 capped to 60
    }

    #[test]
    fn default_backoff_with_cap_mirrors_python_algorithm() {
        // Python: base = min(2 ** attempt, self._backoff_cap).
        assert_eq!(default_backoff_with_cap(0, 60.0), 1.0);
        assert_eq!(default_backoff_with_cap(3, 60.0), 8.0);
        assert_eq!(default_backoff_with_cap(6, 60.0), 60.0); // 64 capped to 60
        assert_eq!(default_backoff_with_cap(2, 3.0), 3.0); // 4 capped to 3
        assert_eq!(default_backoff_with_cap(5, 3.0), 3.0); // 32 capped to 3
                                                           // The standalone default is the 60.0-cap instance of the same curve.
        assert_eq!(default_backoff(4), default_backoff_with_cap(4, 60.0));
        assert_eq!(default_backoff(10), 60.0);
    }

    #[test]
    fn configured_cap_is_respected() {
        // Cap 3.0s: the 429 ladder becomes 1, 2, then 4 capped to 3 for the
        // remaining attempts, then rotate slot at attempt 5 (max 429).
        let config = RetryConfig {
            backoff_cap_secs: 3.0,
            ..RetryConfig::default()
        };
        let engine = RetryEngine::new(config);
        let expected_delays = [1.0, 2.0, 3.0, 3.0, 3.0];
        for (attempt, &delay) in expected_delays.iter().enumerate() {
            let d = engine.decide(429, attempt as i64, "", 0, "");
            assert_eq!(d.action, RetryAction::RetrySame, "attempt {attempt}");
            assert_eq!(d.delay_secs, delay, "attempt {attempt} delay");
        }
        let d = engine.decide(429, 5, "", 0, "");
        assert_eq!(d.action, RetryAction::RotateSlot);
        assert_eq!(d.delay_secs, 0.0);
    }

    #[test]
    fn default_config_keeps_previous_60s_behavior() {
        // Callers that do NOT set backoff_cap_secs get the exact historical
        // ladder — 1/2/4/8/16 then rotate slot — identical to the pre-change
        // engine, because RetryConfig::default() keeps cap 60.0.
        let engine = RetryEngine::new(RetryConfig::default());
        let expected_delays = [1.0, 2.0, 4.0, 8.0, 16.0];
        for (attempt, &delay) in expected_delays.iter().enumerate() {
            let d = engine.decide(429, attempt as i64, "", 0, "");
            assert_eq!(d.action, RetryAction::RetrySame, "attempt {attempt}");
            assert_eq!(d.delay_secs, delay, "attempt {attempt} delay");
            assert_eq!(d.max_attempts, 5);
        }
        let d = engine.decide(429, 5, "", 0, "");
        assert_eq!(d.action, RetryAction::RotateSlot);
        assert_eq!(d.delay_secs, 0.0);
    }
}

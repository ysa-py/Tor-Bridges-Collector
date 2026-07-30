//! Rust port of `torshield_ai_gateway/circuit_breaker.py`.
//!
//! Iran-aware self-healing circuit breaker. Understands Iran DPI/censorship
//! patterns: Iran-blocked providers (`cerebras`, `portkey`) open after 2
//! consecutive failures, standard providers after 5. Supports OPEN→HALF_OPEN
//! recovery gated on a threat-level-dependent timeout, and best-effort state
//! persistence to disk across runs.
//!
//! Behaviour is proven equivalent to the CPython original by
//! `tests/parity/gateway_circuit_breaker_parity.rs`, which replays an identical
//! scripted sequence of operations against both implementations (with a
//! controlled clock) and compares `can_attempt` results and the full
//! `get_status()` snapshot.
//!
//! ## Deviation (documented, see `MIGRATION_NOTES.md`)
//!   * Python reads the wall clock via `time.time()` internally; the Rust port
//!     takes the current time (`now`, Unix seconds as `f64`) as an explicit
//!     parameter on the time-dependent methods. This is the same OS clock —
//!     the parity test injects identical values into both — so it is not
//!     observable behaviour, only dependency-injected for testability.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;

use serde_json::{json, Map, Value};

/// Circuit breaker state machine (`CircuitState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitState {
    /// The Python enum `.value` string.
    pub fn value(self) -> &'static str {
        match self {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        }
    }
}

/// Per-provider statistics (`CircuitStats` dataclass).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CircuitStats {
    pub failures: i64,
    pub successes: i64,
    pub last_failure_time: f64,
    pub last_success_time: f64,
    pub consecutive_failures: i64,
    pub consecutive_successes: i64,
    pub iran_block_suspected: bool,
    pub total_latency_ms: f64,
    pub request_count: i64,
}

impl CircuitStats {
    /// Average latency across all tracked requests (`avg_latency_ms` property).
    /// NOTE: excluded from `get_status()` output, exactly like the Python
    /// `@property` which is absent from `vars(stats)`.
    pub fn avg_latency_ms(&self) -> f64 {
        if self.request_count > 0 {
            self.total_latency_ms / self.request_count as f64
        } else {
            0.0
        }
    }

    fn to_json(&self) -> Value {
        // Field types mirror the Python dataclass exactly (ints vs floats), so
        // the serialised snapshot compares equal to `vars(stats)`.
        json!({
            "failures": self.failures,
            "successes": self.successes,
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "iran_block_suspected": self.iran_block_suspected,
            "total_latency_ms": self.total_latency_ms,
            "request_count": self.request_count,
        })
    }
}

/// Iran-aware circuit breaker (`IranAwareCircuitBreaker`).
#[derive(Debug, Default)]
pub struct IranAwareCircuitBreaker {
    circuits: HashMap<String, CircuitState>,
    stats: HashMap<String, CircuitStats>,
    opened_at: HashMap<String, f64>,
    threat_level: String,
}

impl IranAwareCircuitBreaker {
    pub const IRAN_BLOCKED_THRESHOLD: i64 = 2;
    pub const STANDARD_THRESHOLD: i64 = 5;

    fn iran_blocked_providers() -> HashSet<&'static str> {
        ["cerebras", "portkey"].into_iter().collect()
    }

    fn recovery_timeout_for(level: &str) -> i64 {
        match level {
            "none" => 30,
            "low" => 60,
            "medium" => 120,
            "high" => 300,
            "critical" => 600,
            _ => 30,
        }
    }

    /// Construct a fresh breaker (threat level `"none"`). Unlike Python, this
    /// does NOT auto-load persisted state; call [`Self::load_state`] explicitly
    /// (the parity test does so where it matters) to keep construction pure.
    #[must_use]
    pub fn new() -> Self {
        Self {
            threat_level: "none".to_string(),
            ..Default::default()
        }
    }

    pub fn set_threat_level(&mut self, level: &str) {
        self.threat_level = level.to_string();
    }

    fn get_threshold(&self, provider: &str) -> i64 {
        if Self::iran_blocked_providers().contains(provider) {
            Self::IRAN_BLOCKED_THRESHOLD
        } else {
            Self::STANDARD_THRESHOLD
        }
    }

    fn get_recovery_timeout(&self) -> i64 {
        Self::recovery_timeout_for(&self.threat_level)
    }

    /// Whether a request can be attempted for `provider` at time `now`
    /// (Unix seconds). May transition OPEN→HALF_OPEN as a side effect.
    pub fn can_attempt(&mut self, provider: &str, now: f64) -> bool {
        let state = self
            .circuits
            .get(provider)
            .copied()
            .unwrap_or(CircuitState::Closed);
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let opened = self.opened_at.get(provider).copied().unwrap_or(0.0);
                if now - opened > self.get_recovery_timeout() as f64 {
                    self.circuits
                        .insert(provider.to_string(), CircuitState::HalfOpen);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request at `now`, possibly closing the circuit.
    pub fn record_success(&mut self, provider: &str, latency_ms: f64, now: f64) {
        let stats = self.stats.entry(provider.to_string()).or_default();
        stats.successes += 1;
        stats.consecutive_successes += 1;
        stats.consecutive_failures = 0;
        stats.last_success_time = now;
        stats.total_latency_ms += latency_ms;
        stats.request_count += 1;

        let state = self
            .circuits
            .get(provider)
            .copied()
            .unwrap_or(CircuitState::Closed);
        if state == CircuitState::HalfOpen {
            self.circuits
                .insert(provider.to_string(), CircuitState::Closed);
        }
    }

    /// Record a failed request at `now`, possibly opening the circuit.
    pub fn record_failure(
        &mut self,
        provider: &str,
        error: &str,
        http_status: Option<i64>,
        now: f64,
    ) {
        let iran_blocked = Self::iran_blocked_providers().contains(provider);
        let threshold = self.get_threshold(provider);
        let stats = self.stats.entry(provider.to_string()).or_default();
        stats.failures += 1;
        stats.consecutive_failures += 1;
        stats.consecutive_successes = 0;
        stats.last_failure_time = now;

        let el = error.to_lowercase();
        let iran_block_signals = matches!(http_status, Some(403) | Some(0))
            || el.contains("connection refused")
            || (el.contains("timed out") && iran_blocked)
            || el.contains("dns");
        if iran_block_signals {
            stats.iran_block_suspected = true;
        }

        let consecutive = stats.consecutive_failures;
        if consecutive >= threshold {
            let current = self
                .circuits
                .get(provider)
                .copied()
                .unwrap_or(CircuitState::Closed);
            if current != CircuitState::Open {
                self.circuits
                    .insert(provider.to_string(), CircuitState::Open);
                self.opened_at.insert(provider.to_string(), now);
            }
        }
    }

    /// Status snapshot for all tracked providers (`get_status`).
    pub fn get_status(&self) -> Value {
        let mut providers: Vec<String> = self
            .circuits
            .keys()
            .chain(self.stats.keys())
            .cloned()
            .collect();
        providers.sort();
        providers.dedup();
        let mut out = Map::new();
        for p in providers {
            let state = self
                .circuits
                .get(&p)
                .copied()
                .unwrap_or(CircuitState::Closed);
            let stats = self.stats.get(&p).cloned().unwrap_or_default();
            out.insert(p, json!({"state": state.value(), "stats": stats.to_json()}));
        }
        Value::Object(out)
    }

    /// Persist circuit state to `path` (best-effort; errors are swallowed).
    pub fn save_state(&self, path: &str) {
        let mut providers: Vec<String> = self
            .circuits
            .keys()
            .chain(self.stats.keys())
            .cloned()
            .collect();
        providers.sort();
        providers.dedup();
        let mut state: BTreeMap<String, Value> = BTreeMap::new();
        for p in providers {
            let circuit = self
                .circuits
                .get(&p)
                .copied()
                .unwrap_or(CircuitState::Closed);
            let stats = self.stats.get(&p).cloned().unwrap_or_default();
            let opened_at = self.opened_at.get(&p).copied().unwrap_or(0.0);
            state.insert(
                p,
                json!({
                    "circuit": circuit.value(),
                    "opened_at": opened_at,
                    "consecutive_failures": stats.consecutive_failures,
                    "iran_block_suspected": stats.iran_block_suspected,
                }),
            );
        }
        if let Ok(s) = serde_json::to_string(&state) {
            let _ = fs::write(path, s);
        }
    }

    /// Restore persisted state from `path`. Missing/corrupt files leave the
    /// breaker fresh. Only `consecutive_failures`/`iran_block_suspected` are
    /// restored; circuits always start CLOSED with `opened_at = 0`.
    pub fn load_state(&mut self, path: &str) {
        let contents = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };
        let parsed: Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => return,
        };
        if let Value::Object(map) = parsed {
            for (provider, data) in map {
                let stats = CircuitStats {
                    consecutive_failures: data
                        .get("consecutive_failures")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                    iran_block_suspected: data
                        .get("iran_block_suspected")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    ..Default::default()
                };
                self.stats.insert(provider.clone(), stats);
                self.circuits.insert(provider.clone(), CircuitState::Closed);
                self.opened_at.insert(provider, 0.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_after_threshold_iran_provider() {
        let mut b = IranAwareCircuitBreaker::new();
        b.record_failure("cerebras", "boom", None, 1.0);
        assert!(b.can_attempt("cerebras", 1.0));
        b.record_failure("cerebras", "boom", None, 2.0); // 2nd -> OPEN
        assert!(!b.can_attempt("cerebras", 2.0));
    }

    #[test]
    fn standard_provider_needs_five() {
        let mut b = IranAwareCircuitBreaker::new();
        for i in 0..4 {
            b.record_failure("openai", "boom", None, i as f64);
        }
        assert!(b.can_attempt("openai", 4.0));
        b.record_failure("openai", "boom", None, 5.0);
        assert!(!b.can_attempt("openai", 5.0));
    }

    #[test]
    fn recovery_half_open_then_closed() {
        let mut b = IranAwareCircuitBreaker::new();
        b.set_threat_level("none"); // 30s timeout
        b.record_failure("portkey", "x", None, 0.0);
        b.record_failure("portkey", "x", None, 0.0); // OPEN at t=0
        assert!(!b.can_attempt("portkey", 10.0));
        assert!(b.can_attempt("portkey", 31.0)); // -> HALF_OPEN
        b.record_success("portkey", 5.0, 32.0); // -> CLOSED
        assert!(b.can_attempt("portkey", 32.0));
    }
}

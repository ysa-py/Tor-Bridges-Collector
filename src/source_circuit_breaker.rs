//! Source Circuit Breaker (Phase 3 — Feature 5)
//!
//! Thread-safe circuit breaker pattern (`Closed`, `Open`, `HalfOpen`)
//! around HTTP/transport fetchers. Automatically trips breakers on
//! persistent upstream failures and routes traffic to healthy fallbacks.
//!
//! # Design
//!
//! Unlike `circuit_breaker_11slot.rs` (which manages AI provider slots)
//! and `slot_circuit_breaker.rs` (which manages CF gateway slots), this
//! module manages **bridge source** circuit breakers — one per upstream
//! bridge source URL.
//!
//! # States
//!
//! - **Closed**: Normal operation. Failures are counted.
//! - **Open**: Source is tripped. All requests fail fast. After cooldown,
//!   transitions to HalfOpen.
//! - **HalfOpen**: Probing. A limited number of requests are allowed
//!   through. Success → Closed, Failure → Open.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCircuitState {
    /// Normal operation.
    Closed,
    /// Tripped — fail fast.
    Open,
    /// Probing — limited requests allowed.
    HalfOpen,
}

impl SourceCircuitState {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// Per-source circuit breaker state.
#[derive(Debug, Clone)]
pub struct SourceCircuit {
    /// Source identifier (URL).
    pub source_id: String,
    /// Current state.
    pub state: SourceCircuitState,
    /// Consecutive failure count.
    pub failure_count: u32,
    /// Consecutive success count (used in HalfOpen to decide recovery).
    pub success_count: u32,
    /// Total requests attempted.
    pub total_requests: u64,
    /// Total successful requests.
    pub total_successes: u64,
    /// When the circuit was last tripped (Open).
    pub last_failure_time: Option<Instant>,
    /// When the circuit was last opened.
    pub opened_at: Option<Instant>,
    /// Failure threshold to trip the circuit.
    pub failure_threshold: u32,
    /// Cooldown duration before transitioning Open → HalfOpen.
    pub cooldown: Duration,
    /// Maximum probes allowed in HalfOpen state.
    pub half_open_max_probes: u32,
}

impl SourceCircuit {
    /// Create a new circuit breaker for a source.
    #[must_use]
    pub fn new(source_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            state: SourceCircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            total_requests: 0,
            total_successes: 0,
            last_failure_time: None,
            opened_at: None,
            failure_threshold: 3,
            cooldown: Duration::from_secs(60),
            half_open_max_probes: 2,
        }
    }

    /// Create with custom thresholds.
    #[must_use]
    pub fn with_thresholds(
        source_id: impl Into<String>,
        failure_threshold: u32,
        cooldown: Duration,
        half_open_max_probes: u32,
    ) -> Self {
        let mut circuit = Self::new(source_id);
        circuit.failure_threshold = failure_threshold;
        circuit.cooldown = cooldown;
        circuit.half_open_max_probes = half_open_max_probes;
        circuit
    }

    /// Check if a request is allowed through the circuit breaker.
    #[must_use]
    pub fn allow_request(&mut self) -> bool {
        self.total_requests += 1;
        match self.state {
            SourceCircuitState::Closed => true,
            SourceCircuitState::Open => {
                // Check if cooldown has elapsed → transition to HalfOpen
                if let Some(opened) = self.opened_at {
                    if opened.elapsed() >= self.cooldown {
                        self.state = SourceCircuitState::HalfOpen;
                        self.success_count = 0;
                        true // Allow one probe
                    } else {
                        false // Still in cooldown
                    }
                } else {
                    false
                }
            }
            SourceCircuitState::HalfOpen => {
                // Allow limited probes
                self.success_count < self.half_open_max_probes
            }
        }
    }

    /// Record a successful request.
    pub fn record_success(&mut self) {
        self.total_successes += 1;
        match self.state {
            SourceCircuitState::Closed => {
                self.failure_count = 0; // Reset on success
            }
            SourceCircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.half_open_max_probes {
                    // Enough successful probes → close circuit
                    self.state = SourceCircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            }
            SourceCircuitState::Open => {
                // Shouldn't happen (allow_request returns false)
            }
        }
    }

    /// Record a failed request.
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());
        match self.state {
            SourceCircuitState::Closed => {
                if self.failure_count >= self.failure_threshold {
                    // Trip the circuit
                    self.state = SourceCircuitState::Open;
                    self.opened_at = Some(Instant::now());
                }
            }
            SourceCircuitState::HalfOpen => {
                // Probe failed → re-open circuit
                self.state = SourceCircuitState::Open;
                self.opened_at = Some(Instant::now());
                self.success_count = 0;
            }
            SourceCircuitState::Open => {
                // Already open
            }
        }
    }

    /// Get success rate (0.0–1.0).
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            1.0
        } else {
            self.total_successes as f64 / self.total_requests as f64
        }
    }

    /// Convert to JSON.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "state": self.state.as_str(),
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "total_requests": self.total_requests,
            "total_successes": self.total_successes,
            "success_rate": (self.success_rate() * 1000.0).round() / 1000.0,
            "failure_threshold": self.failure_threshold,
            "cooldown_secs": self.cooldown.as_secs(),
            "half_open_max_probes": self.half_open_max_probes,
        })
    }
}

/// Thread-safe manager for source circuit breakers.
#[derive(Debug)]
pub struct SourceCircuitBreakerManager {
    circuits: BTreeMap<String, SourceCircuit>,
    /// Default failure threshold for new circuits.
    default_failure_threshold: u32,
    /// Default cooldown for new circuits.
    default_cooldown: Duration,
    /// Default half-open max probes.
    default_half_open_max: u32,
}

impl SourceCircuitBreakerManager {
    /// Create a new manager with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            circuits: BTreeMap::new(),
            default_failure_threshold: 3,
            default_cooldown: Duration::from_secs(60),
            default_half_open_max: 2,
        }
    }

    /// Create with custom defaults.
    #[must_use]
    pub fn with_defaults(failure_threshold: u32, cooldown_secs: u64, half_open_max: u32) -> Self {
        Self {
            circuits: BTreeMap::new(),
            default_failure_threshold: failure_threshold,
            default_cooldown: Duration::from_secs(cooldown_secs),
            default_half_open_max: half_open_max,
        }
    }

    /// Register a source. Idempotent.
    pub fn register(&mut self, source_id: impl Into<String>) {
        let id = source_id.into();
        self.circuits.entry(id.clone()).or_insert_with(|| {
            SourceCircuit::with_thresholds(
                id,
                self.default_failure_threshold,
                self.default_cooldown,
                self.default_half_open_max,
            )
        });
    }

    /// Check if a request to a source is allowed.
    pub fn allow_request(&mut self, source_id: &str) -> bool {
        if let Some(circuit) = self.circuits.get_mut(source_id) {
            circuit.allow_request()
        } else {
            // Unknown source: auto-register and allow
            self.register(source_id.to_string());
            true
        }
    }

    /// Record a successful request.
    pub fn record_success(&mut self, source_id: &str) {
        if let Some(circuit) = self.circuits.get_mut(source_id) {
            circuit.record_success();
        }
    }

    /// Record a failed request.
    pub fn record_failure(&mut self, source_id: &str) {
        if let Some(circuit) = self.circuits.get_mut(source_id) {
            circuit.record_failure();
        }
    }

    /// Get state of a source circuit.
    #[must_use]
    pub fn state(&self, source_id: &str) -> SourceCircuitState {
        self.circuits
            .get(source_id)
            .map(|c| c.state)
            .unwrap_or(SourceCircuitState::Closed)
    }

    /// Get all open (tripped) circuits.
    #[must_use]
    pub fn open_circuits(&self) -> Vec<&str> {
        self.circuits
            .values()
            .filter(|c| c.state == SourceCircuitState::Open)
            .map(|c| c.source_id.as_str())
            .collect()
    }

    /// Get all available (not open) sources.
    #[must_use]
    pub fn available_sources(&self) -> Vec<&str> {
        self.circuits
            .values()
            .filter(|c| c.state != SourceCircuitState::Open)
            .map(|c| c.source_id.as_str())
            .collect()
    }

    /// Get full status report as JSON.
    #[must_use]
    pub fn status_json(&self) -> Value {
        let circuits: Vec<Value> = self.circuits.values().map(|c| c.to_json()).collect();
        let open = self.open_circuits();
        json!({
            "total_sources": self.circuits.len(),
            "open_circuits": open.len(),
            "open_circuit_ids": open,
            "circuits": circuits,
        })
    }
}

impl Default for SourceCircuitBreakerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe shared circuit breaker manager.
pub type SharedSourceCircuitBreaker = Arc<Mutex<SourceCircuitBreakerManager>>;

/// Create a new shared circuit breaker manager.
#[must_use]
pub fn new_shared_circuit_breaker() -> SharedSourceCircuitBreaker {
    Arc::new(Mutex::new(SourceCircuitBreakerManager::new()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_circuit_is_closed() {
        let circuit = SourceCircuit::new("test");
        assert_eq!(circuit.state, SourceCircuitState::Closed);
        assert_eq!(circuit.failure_count, 0);
    }

    #[test]
    fn allow_request_when_closed() {
        let mut circuit = SourceCircuit::new("test");
        assert!(circuit.allow_request());
    }

    #[test]
    fn trips_after_threshold_failures() {
        let mut circuit = SourceCircuit::with_thresholds("test", 3, Duration::from_secs(60), 2);
        circuit.record_failure();
        circuit.record_failure();
        assert_eq!(circuit.state, SourceCircuitState::Closed);
        circuit.record_failure();
        assert_eq!(circuit.state, SourceCircuitState::Open);
    }

    #[test]
    fn open_circuit_blocks_requests() {
        let mut circuit = SourceCircuit::with_thresholds("test", 1, Duration::from_secs(300), 2);
        circuit.record_failure();
        assert_eq!(circuit.state, SourceCircuitState::Open);
        assert!(!circuit.allow_request());
    }

    #[test]
    fn success_resets_failure_count() {
        let mut circuit = SourceCircuit::with_thresholds("test", 3, Duration::from_secs(60), 2);
        circuit.record_failure();
        circuit.record_failure();
        circuit.record_success();
        assert_eq!(circuit.failure_count, 0);
    }

    #[test]
    fn half_open_allows_probes() {
        let mut circuit = SourceCircuit::with_thresholds("test", 1, Duration::from_millis(1), 2);
        circuit.record_failure();
        assert_eq!(circuit.state, SourceCircuitState::Open);

        // Wait for cooldown
        std::thread::sleep(Duration::from_millis(5));

        // Should transition to HalfOpen
        assert!(circuit.allow_request());
        assert_eq!(circuit.state, SourceCircuitState::HalfOpen);
    }

    #[test]
    fn half_open_closes_on_success() {
        let mut circuit = SourceCircuit::with_thresholds("test", 1, Duration::from_millis(1), 2);
        circuit.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        circuit.allow_request(); // → HalfOpen
        assert_eq!(circuit.state, SourceCircuitState::HalfOpen);

        circuit.record_success();
        circuit.record_success(); // 2 probes succeeded
        assert_eq!(circuit.state, SourceCircuitState::Closed);
    }

    #[test]
    fn half_open_reopens_on_failure() {
        let mut circuit = SourceCircuit::with_thresholds("test", 1, Duration::from_millis(1), 2);
        circuit.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        circuit.allow_request(); // → HalfOpen
        circuit.record_failure(); // Probe failed
        assert_eq!(circuit.state, SourceCircuitState::Open);
    }

    #[test]
    fn manager_auto_registers_unknown_sources() {
        let mut mgr = SourceCircuitBreakerManager::new();
        assert!(mgr.allow_request("new-source"));
        assert_eq!(mgr.state("new-source"), SourceCircuitState::Closed);
    }

    #[test]
    fn manager_tracks_open_circuits() {
        let mut mgr = SourceCircuitBreakerManager::with_defaults(1, 300, 2);
        mgr.register("s1");
        mgr.register("s2");
        mgr.record_failure("s1");
        let open = mgr.open_circuits();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0], "s1");
    }

    #[test]
    fn manager_available_sources() {
        let mut mgr = SourceCircuitBreakerManager::with_defaults(1, 300, 2);
        mgr.register("s1");
        mgr.register("s2");
        mgr.record_failure("s1");
        let available = mgr.available_sources();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0], "s2");
    }

    #[test]
    fn manager_status_json() {
        let mut mgr = SourceCircuitBreakerManager::new();
        mgr.register("s1");
        mgr.register("s2");
        let status = mgr.status_json();
        assert_eq!(status["total_sources"], 2);
        assert_eq!(status["open_circuits"], 0);
    }

    #[test]
    fn shared_manager_is_send_sync() {
        let mgr = new_shared_circuit_breaker();
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        assert_send_sync(&mgr);
    }

    #[test]
    fn success_rate_calculation() {
        let mut circuit = SourceCircuit::new("test");
        circuit.allow_request();
        circuit.record_success();
        circuit.allow_request();
        circuit.record_failure();
        assert!((circuit.success_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn circuit_to_json() {
        let circuit = SourceCircuit::new("test");
        let json = circuit.to_json();
        assert_eq!(json["source_id"], "test");
        assert_eq!(json["state"], "closed");
    }
}

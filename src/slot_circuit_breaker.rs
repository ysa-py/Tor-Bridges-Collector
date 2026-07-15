//! Parity port of `circuit_breaker/slot_circuit_breaker.py` — Enhanced Per-Slot
//! Circuit Breaker v1.0.
//!
//! Provides a per-slot state machine (CLOSED → OPEN → HALF_OPEN) that tracks
//! consecutive failures per Cloudflare account slot and blocks requests to
//! failing slots until a cooldown elapses, after which a limited probe is
//! allowed.
//!
//! Behavior traced to `circuit_breaker/slot_circuit_breaker.py`:
//! * [`SlotCircuitBreaker::new`] — parses env vars for failure threshold,
//!   cooldown, and half-open probe budget; initializes 11 slots with
//!   credential validation.
//! * [`SlotCircuitBreaker::allow_request`] — checks if a request is allowed,
//!   transitioning OPEN → HALF_OPEN when the cooldown elapses.
//! * [`SlotCircuitBreaker::record_success`] — resets failure counters,
//!   transitions any state → CLOSED.
//! * [`SlotCircuitBreaker::record_failure`] — increments failure counters,
//!   transitions CLOSED → OPEN at threshold or HALF_OPEN → OPEN on probe
//!   failure.
//! * [`SlotCircuitBreaker::get_available_slots`] /
//!   [`SlotCircuitBreaker::get_slot_for_rotation`] /
//!   [`SlotCircuitBreaker::get_status`] — query helpers matching the Python
//!   dict/list return shapes.
//!
//! The Python original uses `time.time()` for cooldown timing. This port uses
//! `chrono::Utc::now()` by default but accepts an injectable [`Clock`] for
//! deterministic testing.
//!
//! The Python original integrates with `monitoring.structured_logger` for
//! diagnostics logging. That integration is a no-op in this Rust port (the
//! module is not part of the Rust migration scope); state-machine behavior is
//! unaffected. See `MIGRATION_NOTES.md` for details.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::Utc;
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration constants (mirror `config/feature_flags.py` defaults)
// ─────────────────────────────────────────────────────────────────────────────

/// Default consecutive-failure count that opens a slot's circuit.
pub const DEFAULT_FAILURE_THRESHOLD: i64 = 3;

/// Default cooldown (seconds) before an OPEN slot transitions to HALF_OPEN.
pub const DEFAULT_COOLDOWN_SECS: f64 = 60.0;

/// Default number of probes allowed in HALF_OPEN state.
pub const DEFAULT_HALF_OPEN_MAX_PROBES: i64 = 1;

/// Number of Cloudflare account slots (1..=11).
pub const SLOT_COUNT: usize = 11;

/// Default `avg_latency_ms` for a fresh slot.
pub const DEFAULT_AVG_LATENCY_MS: f64 = 200.0;

/// EMA smoothing factor for `avg_latency_ms` updates in `record_success`.
pub const LATENCY_EMA_ALPHA: f64 = 0.25;

/// Multiplier applied to `health_score` when a slot is skipped or OPEN.
pub const DEGRADED_HEALTH_MULTIPLIER: f64 = 0.05;

// ─────────────────────────────────────────────────────────────────────────────
// Typed errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failures raised while parsing environment variables for the circuit breaker.
#[derive(Debug, thiserror::Error)]
pub enum SlotCircuitBreakerError {
    /// An integer env var could not be parsed.
    #[error("invalid integer for {name}: {value}")]
    InvalidInt { name: &'static str, value: String },

    /// A float env var could not be parsed.
    #[error("invalid float for {name}: {value}")]
    InvalidFloat { name: &'static str, value: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Environment map and clock
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python's `os.getenv` map — keys are uppercase env var names.
pub type EnvMap = BTreeMap<String, String>;

/// Injectable clock returning epoch seconds as `f64` (parity with `time.time()`).
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// Default clock using `chrono::Utc::now()`, returning epoch seconds as `f64`.
pub fn default_clock() -> Clock {
    Arc::new(|| {
        let now = Utc::now();
        now.timestamp() as f64 + now.timestamp_subsec_nanos() as f64 / 1_000_000_000.0
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// CircuitState
// ─────────────────────────────────────────────────────────────────────────────

/// Circuit breaker states. Mirror of Python's `CircuitState` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — requests flow through.
    Closed,
    /// Slot blocked after N consecutive failures.
    Open,
    /// Test probe after cooldown — limited requests allowed.
    HalfOpen,
}

impl CircuitState {
    /// Return the lowercase string value matching the Python enum.
    pub fn value(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.value())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SlotCircuitState
// ─────────────────────────────────────────────────────────────────────────────

/// Per-slot circuit breaker state. Mirror of Python's `SlotCircuitState` dataclass.
#[derive(Debug, Clone)]
pub struct SlotCircuitState {
    /// Slot index (1..=11).
    pub slot_index: i32,
    /// Cloudflare account ID (32-char hex).
    pub account_id: String,
    /// Cloudflare API token (>=40 chars).
    pub api_token: String,
    /// Cloudflare AI Gateway URL.
    pub gateway_url: String,

    /// Current circuit breaker state.
    pub state: CircuitState,
    /// Cumulative failure count (never reset).
    pub failure_count: i64,
    /// Consecutive failures since last success.
    pub consecutive_failures: i64,
    /// Epoch seconds of the last failure.
    pub last_failure_time: f64,
    /// Error type string of the last failure.
    pub last_failure_error: String,
    /// `last_failure_time + cooldown_secs`.
    pub recovery_time: f64,

    /// `true` if both account_id and api_token are non-empty.
    pub is_configured: bool,
    /// `true` if the slot failed validation.
    pub is_skipped: bool,
    /// Human-readable skip reason.
    pub skip_reason: String,

    /// Total requests recorded (successes + failures).
    pub total_requests: i64,
    /// Total successful requests.
    pub total_successes: i64,
    /// Total failed requests.
    pub total_failures: i64,
    /// Exponential moving average of latency in ms.
    pub avg_latency_ms: f64,

    /// Probes sent in HALF_OPEN (always 0 — see MIGRATION_NOTES).
    pub half_open_probes_sent: i64,
    /// Probes allowed in HALF_OPEN (hardcoded to 1 in Python dataclass).
    pub half_open_probes_allowed: i64,

    /// Failure counts keyed by error type.
    pub failure_by_type: BTreeMap<String, i64>,
}

impl SlotCircuitState {
    /// Construct a fresh CLOSED slot with default values.
    fn new(slot_index: i32, account_id: String, api_token: String, gateway_url: String) -> Self {
        let is_configured = !account_id.is_empty() && !api_token.is_empty();
        Self {
            slot_index,
            account_id,
            api_token,
            gateway_url,
            state: CircuitState::Closed,
            failure_count: 0,
            consecutive_failures: 0,
            last_failure_time: 0.0,
            last_failure_error: String::new(),
            recovery_time: 0.0,
            is_configured,
            is_skipped: false,
            skip_reason: String::new(),
            total_requests: 0,
            total_successes: 0,
            total_failures: 0,
            avg_latency_ms: DEFAULT_AVG_LATENCY_MS,
            half_open_probes_sent: 0,
            half_open_probes_allowed: 1,
            failure_by_type: BTreeMap::new(),
        }
    }

    /// Mirror of Python `success_rate` property. Returns 1.0 when no requests
    /// have been recorded.
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            1.0
        } else {
            self.total_successes as f64 / self.total_requests as f64
        }
    }

    /// Mirror of Python `health_score` property.
    pub fn health_score(&self) -> f64 {
        let latency_penalty = (self.avg_latency_ms / 10_000.0).min(0.5);
        let mut base = self.success_rate() * (1.0 - latency_penalty);
        if self.is_skipped || self.state == CircuitState::Open {
            base *= DEGRADED_HEALTH_MULTIPLIER;
        }
        base
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Env parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_int(
    env: &EnvMap,
    name: &'static str,
    default: i64,
) -> Result<i64, SlotCircuitBreakerError> {
    match env.get(name) {
        Some(value) => value
            .parse::<i64>()
            .map_err(|_| SlotCircuitBreakerError::InvalidInt {
                name,
                value: value.clone(),
            }),
        None => Ok(default),
    }
}

fn parse_float(
    env: &EnvMap,
    name: &'static str,
    default: f64,
) -> Result<f64, SlotCircuitBreakerError> {
    match env.get(name) {
        Some(value) => value
            .parse::<f64>()
            .map_err(|_| SlotCircuitBreakerError::InvalidFloat {
                name,
                value: value.clone(),
            }),
        None => Ok(default),
    }
}

/// Check if `account_id` matches the Python regex `^[0-9a-f]{32}$` (case-insensitive).
fn is_valid_account_id(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Mirror of Python `round(x, n)` for non-negative `n`. Uses
/// round-half-away-from-zero which matches Python's `round()` for all values
/// that do not fall on an exact 0.5 boundary at the nth decimal. The circuit
/// breaker's computed values (success_rate, health_score, avg_latency_ms) do
/// not produce such boundaries in practice.
fn round_to(x: f64, decimals: u32) -> f64 {
    let factor = 10f64.powi(decimals as i32);
    (x * factor).round() / factor
}

// ─────────────────────────────────────────────────────────────────────────────
// SlotCircuitBreaker
// ─────────────────────────────────────────────────────────────────────────────

/// Enhanced per-slot circuit breaker with CLOSED → OPEN → HALF_OPEN states.
///
/// Each of the 11 Cloudflare account slots has independent circuit breaker
/// state. Slots without valid credentials are marked SKIPPED at init and
/// excluded from request routing.
///
/// The Python original uses a class-level singleton with `threading.RLock`.
/// This port exposes [`get_slot_circuit_breaker`] which returns an
/// `Arc<Mutex<SlotCircuitBreaker>>`; callers lock the mutex to access the
/// breaker, matching the Python reentrant-lock semantics (each public method
/// takes `&mut self`, so the caller holds the lock for the duration of a call).
pub struct SlotCircuitBreaker {
    slots: BTreeMap<i32, SlotCircuitState>,
    failure_threshold: i64,
    cooldown_secs: f64,
    half_open_max_probes: i64,
    now: Clock,
}

impl std::fmt::Debug for SlotCircuitBreaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotCircuitBreaker")
            .field("slots", &self.slots)
            .field("failure_threshold", &self.failure_threshold)
            .field("cooldown_secs", &self.cooldown_secs)
            .field("half_open_max_probes", &self.half_open_max_probes)
            .field("now", &"<clock closure>")
            .finish()
    }
}

impl SlotCircuitBreaker {
    /// Construct a new breaker from the given env map and clock.
    ///
    /// Reads `CIRCUIT_BREAKER_FAILURE_THRESHOLD` (default 3),
    /// `CIRCUIT_BREAKER_COOLDOWN_SECS` (default 60.0),
    /// `CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES` (default 1), and
    /// `CF_ACCOUNT_ID_{i}` / `CF_API_TOKEN_{i}` / `CF_AI_GATEWAY_URL_{i}`
    /// for `i` in `1..=11`.
    pub fn new(env: &EnvMap, now: Clock) -> Result<Self, SlotCircuitBreakerError> {
        let failure_threshold = parse_int(
            env,
            "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
            DEFAULT_FAILURE_THRESHOLD,
        )?;
        let cooldown_secs =
            parse_float(env, "CIRCUIT_BREAKER_COOLDOWN_SECS", DEFAULT_COOLDOWN_SECS)?;
        let half_open_max_probes = parse_int(
            env,
            "CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES",
            DEFAULT_HALF_OPEN_MAX_PROBES,
        )?;
        let mut breaker = Self {
            slots: BTreeMap::new(),
            failure_threshold,
            cooldown_secs,
            half_open_max_probes,
            now,
        };
        breaker.init_slots(env);
        Ok(breaker)
    }

    /// Construct a breaker with default thresholds (no env parsing), used as a
    /// fallback for the singleton when env parsing fails. Slot credentials are
    /// still read from the env map.
    fn new_with_defaults(env: &EnvMap) -> Self {
        let mut breaker = Self {
            slots: BTreeMap::new(),
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
            half_open_max_probes: DEFAULT_HALF_OPEN_MAX_PROBES,
            now: default_clock(),
        };
        breaker.init_slots(env);
        breaker
    }

    /// Initialize all 11 CF slots with credential validation.
    ///
    /// Mirrors Python `_init_slots`: a slot is SKIPPED if credentials are
    /// missing, the account_id is not a 32-char hex string, or the API token
    /// is shorter than 40 characters.
    fn init_slots(&mut self, env: &EnvMap) {
        for i in 1..=(SLOT_COUNT as i32) {
            let account_id = env
                .get(&format!("CF_ACCOUNT_ID_{i}"))
                .cloned()
                .unwrap_or_default()
                .trim()
                .to_string();
            let api_token = env
                .get(&format!("CF_API_TOKEN_{i}"))
                .cloned()
                .unwrap_or_default()
                .trim()
                .to_string();
            let gateway_url = env
                .get(&format!("CF_AI_GATEWAY_URL_{i}"))
                .cloned()
                .unwrap_or_default()
                .trim()
                .to_string();

            let mut slot = SlotCircuitState::new(i, account_id, api_token, gateway_url);

            if slot.account_id.is_empty() || slot.api_token.is_empty() {
                slot.is_skipped = true;
                slot.skip_reason = "missing credentials".to_string();
            } else if !is_valid_account_id(&slot.account_id) {
                slot.is_skipped = true;
                slot.skip_reason =
                    format!("invalid account_id format (len={})", slot.account_id.len());
            } else if slot.api_token.len() < 40 {
                slot.is_skipped = true;
                slot.skip_reason = format!("token too short ({} chars)", slot.api_token.len());
            }

            self.slots.insert(i, slot);
        }
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Return the configured failure threshold.
    pub fn failure_threshold(&self) -> i64 {
        self.failure_threshold
    }

    /// Return the configured cooldown (seconds).
    pub fn cooldown_secs(&self) -> f64 {
        self.cooldown_secs
    }

    /// Return the configured half-open max probes.
    pub fn half_open_max_probes(&self) -> i64 {
        self.half_open_max_probes
    }

    /// Return a reference to the slot state for `slot_index`, if it exists.
    pub fn slot(&self, slot_index: i32) -> Option<&SlotCircuitState> {
        self.slots.get(&slot_index)
    }

    /// Return the current state string ("closed"/"open"/"half_open") for the
    /// given slot, or `None` if the slot does not exist.
    pub fn state(&self, slot_index: i32) -> Option<&str> {
        self.slots.get(&slot_index).map(|s| s.state.value())
    }

    // ── Core operations ──────────────────────────────────────────────────

    /// Check if a request is allowed for the given slot. Transitions
    /// OPEN → HALF_OPEN when the cooldown has elapsed.
    ///
    /// Returns `false` if the slot does not exist or is skipped. The Python
    /// original "fails open" (returns `true`) on internal exceptions; this port
    /// has no internal exception paths so the behavior is deterministic.
    pub fn allow_request(&mut self, slot_index: i32) -> bool {
        let now = (self.now)();
        let Some(slot) = self.slots.get_mut(&slot_index) else {
            return false;
        };
        if slot.is_skipped {
            return false;
        }
        match slot.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let elapsed = now - slot.last_failure_time;
                if elapsed >= self.cooldown_secs {
                    slot.state = CircuitState::HalfOpen;
                    slot.half_open_probes_sent = 0;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Parity note: the Python original checks
                // `half_open_probes_sent < half_open_max_probes` but never
                // increments `half_open_probes_sent`, so HALF_OPEN always
                // allows requests. This port replicates that behavior exactly.
                slot.half_open_probes_sent < self.half_open_max_probes
            }
        }
    }

    /// Alias for [`Self::allow_request`] — matches the parity contract name
    /// `can_proceed(slot)`.
    pub fn can_proceed(&mut self, slot_index: i32) -> bool {
        self.allow_request(slot_index)
    }

    /// Alias for [`Self::allow_request`] — matches the parity contract name
    /// `is_available(slot)`.
    pub fn is_available(&mut self, slot_index: i32) -> bool {
        self.allow_request(slot_index)
    }

    /// Record a successful request with the default latency (200.0 ms).
    /// Resets failure counters and transitions to CLOSED.
    pub fn record_success(&mut self, slot_index: i32) {
        self.record_success_with_latency(slot_index, DEFAULT_AVG_LATENCY_MS);
    }

    /// Record a successful request with an explicit latency. Resets failure
    /// counters, transitions to CLOSED, and updates `avg_latency_ms` via EMA
    /// (`alpha = 0.25`).
    pub fn record_success_with_latency(&mut self, slot_index: i32, latency_ms: f64) {
        let Some(slot) = self.slots.get_mut(&slot_index) else {
            return;
        };
        let prev_state = slot.state;
        slot.state = CircuitState::Closed;
        slot.failure_count = 0;
        slot.consecutive_failures = 0;
        slot.total_requests += 1;
        slot.total_successes += 1;
        slot.half_open_probes_sent = 0;
        let alpha = LATENCY_EMA_ALPHA;
        slot.avg_latency_ms = alpha * latency_ms + (1.0 - alpha) * slot.avg_latency_ms;
        // Python logs the transition when prev_state != Closed; that side effect
        // is a no-op in this Rust port (no structured logger integration).
        let _ = prev_state;
    }

    /// Record a failed request with default empty error type and detail.
    pub fn record_failure(&mut self, slot_index: i32) {
        self.record_failure_with_details(slot_index, "", "");
    }

    /// Record a failed request with an error type and optional detail.
    /// Increments failure counters and may transition CLOSED → OPEN (at
    /// threshold) or HALF_OPEN → OPEN (probe failure). Always updates
    /// `last_failure_time` and `recovery_time`, effectively resetting the
    /// cooldown timer.
    pub fn record_failure_with_details(
        &mut self,
        slot_index: i32,
        error_type: &str,
        _error_detail: &str,
    ) {
        let now = (self.now)();
        let Some(slot) = self.slots.get_mut(&slot_index) else {
            return;
        };
        slot.failure_count += 1;
        slot.consecutive_failures += 1;
        slot.total_requests += 1;
        slot.total_failures += 1;
        slot.last_failure_time = now;
        slot.last_failure_error = error_type.to_string();
        slot.recovery_time = now + self.cooldown_secs;
        *slot
            .failure_by_type
            .entry(error_type.to_string())
            .or_insert(0) += 1;

        match slot.state {
            CircuitState::HalfOpen => {
                slot.state = CircuitState::Open;
            }
            CircuitState::Closed => {
                if slot.consecutive_failures >= self.failure_threshold {
                    slot.state = CircuitState::Open;
                }
            }
            CircuitState::Open => {
                // Already open; no transition (cooldown timer reset via
                // last_failure_time above).
            }
        }
    }

    // ── Query helpers ────────────────────────────────────────────────────

    /// Get list of slot indices available for requests. A slot is available
    /// if it is configured, not skipped, and `allow_request` returns `true`.
    pub fn get_available_slots(&mut self) -> Vec<i32> {
        let indices: Vec<i32> = self.slots.keys().copied().collect();
        let mut result = Vec::new();
        for i in indices {
            let (is_configured, is_skipped) = match self.slots.get(&i) {
                Some(s) => (s.is_configured, s.is_skipped),
                None => continue,
            };
            if is_configured && !is_skipped && self.allow_request(i) {
                result.push(i);
            }
        }
        result
    }

    /// Get the next best slot for rotation, excluding specified slots.
    /// Prioritizes slots with the highest health score. Attempts aggressive
    /// recovery (OPEN → HALF_OPEN after `2 × cooldown`) if no slots are
    /// available.
    pub fn get_slot_for_rotation(&mut self, exclude_slots: Option<&BTreeSet<i32>>) -> Option<i32> {
        let exclude = exclude_slots.cloned().unwrap_or_default();
        let now = (self.now)();

        // Phase 1: collect available slots (calling allow_request which may
        // transition OPEN → HALF_OPEN).
        let mut available: Vec<i32> = Vec::new();
        let indices: Vec<i32> = self.slots.keys().copied().collect();
        for &i in &indices {
            if exclude.contains(&i) {
                continue;
            }
            let (is_configured, is_skipped) = match self.slots.get(&i) {
                Some(s) => (s.is_configured, s.is_skipped),
                None => continue,
            };
            if is_configured && !is_skipped && self.allow_request(i) {
                available.push(i);
            }
        }

        // Phase 2: aggressive recovery (elapsed > cooldown * 2).
        if available.is_empty() {
            for &i in &indices {
                let should_recover = match self.slots.get(&i) {
                    Some(s) => s.is_configured && !s.is_skipped && s.state == CircuitState::Open,
                    None => false,
                };
                if should_recover {
                    let last_failure_time = self
                        .slots
                        .get(&i)
                        .map(|s| s.last_failure_time)
                        .unwrap_or(0.0);
                    let elapsed = now - last_failure_time;
                    if elapsed > self.cooldown_secs * 2.0 {
                        if let Some(s) = self.slots.get_mut(&i) {
                            s.state = CircuitState::HalfOpen;
                            s.half_open_probes_sent = 0;
                            available.push(i);
                        }
                    }
                }
            }
            if available.is_empty() {
                return None;
            }
        }

        // Phase 3: sort by health score (best first), stable on ties.
        available.sort_by(|&a, &b| {
            let ha = self.slots.get(&a).map(|s| s.health_score()).unwrap_or(0.0);
            let hb = self.slots.get(&b).map(|s| s.health_score()).unwrap_or(0.0);
            hb.partial_cmp(&ha).unwrap_or(std::cmp::Ordering::Equal)
        });

        available.first().copied()
    }

    /// Get comprehensive circuit breaker status as a JSON value matching the
    /// Python `get_status()` dict shape. Calling this method may transition
    /// OPEN → HALF_OPEN slots (via `get_available_slots`), matching the Python
    /// side effect.
    pub fn get_status(&mut self) -> Value {
        let configured = self.slots.values().filter(|s| s.is_configured).count();
        let skipped = self.slots.values().filter(|s| s.is_skipped).count();
        let available = self.get_available_slots().len();

        let mut slots_map = serde_json::Map::new();
        for (i, s) in &self.slots {
            slots_map.insert(
                i.to_string(),
                json!({
                    "configured": s.is_configured,
                    "skipped": s.is_skipped,
                    "skip_reason": s.skip_reason,
                    "state": s.state.value(),
                    "consecutive_failures": s.consecutive_failures,
                    "total_failures": s.total_failures,
                    "total_successes": s.total_successes,
                    "success_rate": round_to(s.success_rate(), 3),
                    "health_score": round_to(s.health_score(), 3),
                    "avg_latency_ms": round_to(s.avg_latency_ms, 1),
                    "last_failure_error": s.last_failure_error,
                    "recovery_time": s.recovery_time,
                }),
            );
        }

        json!({
            "total_slots": SLOT_COUNT,
            "configured_slots": configured,
            "skipped_slots": skipped,
            "available_slots": available,
            "failure_threshold": self.failure_threshold,
            "cooldown_secs": self.cooldown_secs,
            "slots": Value::Object(slots_map),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton accessor
// ─────────────────────────────────────────────────────────────────────────────

static SINGLETON: OnceLock<Arc<Mutex<SlotCircuitBreaker>>> = OnceLock::new();

/// Get the singleton `SlotCircuitBreaker` instance, initialized from
/// `std::env::vars()`. If env parsing fails, falls back to default thresholds
/// (matching the Python "ZERO CRASH" docstring principle) and logs to stderr.
///
/// Returns an `Arc<Mutex<SlotCircuitBreaker>>` that callers lock to access the
/// breaker. Each public method on `SlotCircuitBreaker` takes `&mut self`, so
/// the caller holds the lock for the duration of a call (matching the Python
/// `RLock` semantics — no nested locking is required).
pub fn get_slot_circuit_breaker() -> Arc<Mutex<SlotCircuitBreaker>> {
    SINGLETON
        .get_or_init(|| {
            let env: EnvMap = std::env::vars().collect();
            let breaker = SlotCircuitBreaker::new(&env, default_clock()).unwrap_or_else(|err| {
                eprintln!("slot_circuit_breaker: singleton init failed, using defaults: {err}");
                SlotCircuitBreaker::new_with_defaults(&env)
            });
            Arc::new(Mutex::new(breaker))
        })
        .clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_env() -> EnvMap {
        let mut env = EnvMap::new();
        env.insert("CF_ACCOUNT_ID_1".to_string(), "a".repeat(32));
        env.insert("CF_API_TOKEN_1".to_string(), "t".repeat(40));
        env.insert("CF_ACCOUNT_ID_2".to_string(), "b".repeat(32));
        env.insert("CF_API_TOKEN_2".to_string(), "u".repeat(40));
        env
    }

    fn fixed_clock(t: f64) -> Clock {
        Arc::new(move || t)
    }

    /// Create an injectable clock backed by a shared mutable f64. Returns the
    /// clock and a handle that tests can advance via `*handle.lock().unwrap() = t`.
    fn test_clock(initial: f64) -> (Clock, Arc<Mutex<f64>>) {
        let state = Arc::new(Mutex::new(initial));
        let state_clone = Arc::clone(&state);
        let clock: Clock = Arc::new(move || *state_clone.lock().unwrap());
        (clock, state)
    }

    #[test]
    fn fresh_breaker_state_is_closed() {
        let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
        assert_eq!(b.state(1), Some("closed"));
        assert!(b.allow_request(1));
    }

    #[test]
    fn below_threshold_stays_closed() {
        let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
        b.record_failure_with_details(1, "HTTP_500", "");
        b.record_failure_with_details(1, "HTTP_500", "");
        assert_eq!(b.state(1), Some("closed"));
        assert_eq!(b.slot(1).unwrap().consecutive_failures, 2);
        assert!(b.allow_request(1));
    }

    #[test]
    fn at_threshold_opens() {
        let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
        for _ in 0..3 {
            b.record_failure_with_details(1, "HTTP_500", "");
        }
        assert_eq!(b.state(1), Some("open"));
        assert!(!b.allow_request(1));
    }

    #[test]
    fn cooldown_elapses_to_half_open() {
        let (clock, state) = test_clock(1000.0);
        let env = test_env();
        let mut b = SlotCircuitBreaker::new(&env, clock).unwrap();
        for _ in 0..3 {
            b.record_failure_with_details(1, "HTTP_500", "");
        }
        assert_eq!(b.state(1), Some("open"));
        *state.lock().unwrap() = 1000.0 + 61.0;
        assert!(b.allow_request(1));
        assert_eq!(b.state(1), Some("half_open"));
    }

    #[test]
    fn half_open_success_closes() {
        let (clock, state) = test_clock(1000.0);
        let env = test_env();
        let mut b = SlotCircuitBreaker::new(&env, clock).unwrap();
        for _ in 0..3 {
            b.record_failure_with_details(1, "HTTP_500", "");
        }
        *state.lock().unwrap() = 1000.0 + 61.0;
        b.allow_request(1); // OPEN → HALF_OPEN
        b.record_success_with_latency(1, 200.0);
        assert_eq!(b.state(1), Some("closed"));
        assert_eq!(b.slot(1).unwrap().consecutive_failures, 0);
        assert_eq!(b.slot(1).unwrap().total_successes, 1);
    }

    #[test]
    fn half_open_failure_reopens_with_reset_cooldown() {
        let (clock, state) = test_clock(1000.0);
        let env = test_env();
        let mut b = SlotCircuitBreaker::new(&env, clock).unwrap();
        for _ in 0..3 {
            b.record_failure_with_details(1, "HTTP_500", "");
        }
        let first_failure_time = b.slot(1).unwrap().last_failure_time;
        *state.lock().unwrap() = 1000.0 + 61.0;
        b.allow_request(1); // OPEN → HALF_OPEN
        *state.lock().unwrap() = 1000.0 + 62.0;
        b.record_failure_with_details(1, "HTTP_500", "");
        assert_eq!(b.state(1), Some("open"));
        let second_failure_time = b.slot(1).unwrap().last_failure_time;
        assert!(second_failure_time > first_failure_time);
        assert!(!b.allow_request(1));
    }

    #[test]
    fn multi_slot_isolation() {
        let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
        for _ in 0..3 {
            b.record_failure_with_details(1, "HTTP_500", "");
        }
        assert_eq!(b.state(1), Some("open"));
        assert_eq!(b.state(2), Some("closed"));
        assert!(!b.allow_request(1));
        assert!(b.allow_request(2));
    }

    #[test]
    fn skipped_slot_blocks_requests() {
        let env = EnvMap::new();
        let mut b = SlotCircuitBreaker::new(&env, fixed_clock(1000.0)).unwrap();
        for i in 1..=11 {
            assert!(!b.allow_request(i), "slot {i} should be blocked");
            assert_eq!(b.state(i), Some("closed"));
            assert!(b.slot(i).unwrap().is_skipped);
        }
    }

    #[test]
    fn get_status_shape() {
        let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
        let status = b.get_status();
        assert_eq!(status["total_slots"], json!(11));
        assert_eq!(status["configured_slots"], json!(2));
        assert_eq!(status["skipped_slots"], json!(9));
        assert_eq!(status["failure_threshold"], json!(3));
        assert_eq!(status["cooldown_secs"], json!(60.0));
        assert_eq!(status["slots"]["1"]["state"], json!("closed"));
        assert_eq!(status["slots"]["1"]["configured"], json!(true));
        assert_eq!(status["slots"]["1"]["skipped"], json!(false));
        assert_eq!(status["slots"]["1"]["success_rate"], json!(1.0));
        assert_eq!(status["slots"]["1"]["health_score"], json!(0.98));
        assert_eq!(status["slots"]["1"]["avg_latency_ms"], json!(200.0));
    }

    #[test]
    fn record_success_updates_latency_ema() {
        let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
        b.record_success_with_latency(1, 100.0);
        // EMA: 0.25 * 100 + 0.75 * 200 = 25 + 150 = 175
        assert_eq!(b.slot(1).unwrap().avg_latency_ms, 175.0);
    }

    #[test]
    fn invalid_env_returns_typed_error() {
        let mut env = test_env();
        env.insert(
            "CIRCUIT_BREAKER_FAILURE_THRESHOLD".to_string(),
            "abc".to_string(),
        );
        let err = SlotCircuitBreaker::new(&env, fixed_clock(1000.0)).unwrap_err();
        assert!(matches!(
            err,
            SlotCircuitBreakerError::InvalidInt { name, .. } if name == "CIRCUIT_BREAKER_FAILURE_THRESHOLD"
        ));
    }

    #[test]
    fn available_slots_excludes_skipped_and_open() {
        let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
        for _ in 0..3 {
            b.record_failure_with_details(1, "HTTP_500", "");
        }
        let avail = b.get_available_slots();
        assert_eq!(avail, vec![2]);
    }

    #[test]
    fn can_proceed_and_is_available_alias_allow_request() {
        let mut b = SlotCircuitBreaker::new(&test_env(), fixed_clock(1000.0)).unwrap();
        assert!(b.can_proceed(1));
        assert!(b.is_available(1));
        for _ in 0..3 {
            b.record_failure_with_details(1, "HTTP_500", "");
        }
        assert!(!b.can_proceed(1));
        assert!(!b.is_available(1));
    }
}

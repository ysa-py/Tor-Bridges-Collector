//! Parity port of `circuit_breaker_11slot.py` — 11-Slot Circuit Breaker with
//! Zero-Error Fallback v1.0.
//!
//! Production-grade circuit breaker for the 11 Cloudflare account slots.
//! Provides zero-error fallback, dynamic slot rotation, and automatic recovery.
//!
//! Behavior traced to `circuit_breaker_11slot.py`:
//! * [`SlotState`] — per-slot state dataclass with [`SlotState::success_rate`],
//!   [`SlotState::health_score`], and [`SlotState::is_available`] mirroring the
//!   Python `@property`/method behavior. `is_available` mutates slot state
//!   (clears expired blacklists/circuits) just like the Python original.
//! * [`CircuitBreaker11Slot::new`] — initializes 11 slots from the env map
//!   (CF_ACCOUNT_ID_{i}, CF_API_TOKEN_{i}, CF_AI_GATEWAY_URL_{i}).
//! * [`CircuitBreaker11Slot::get_next_slot`] — round-robin slot selection with
//!   health-gated availability; falls back to
//!   [`CircuitBreaker11Slot::aggressive_recovery`].
//! * [`CircuitBreaker11Slot::get_next_slot_with_gateway`] — prefers slots that
//!   have a gateway URL configured, sorted by health score.
//! * [`CircuitBreaker11Slot::get_next_model`] — zero-error fallback chain
//!   (Elite-Registry → ModelSelector → STATIC_BASELINE → ultimate fallback).
//! * [`CircuitBreaker11Slot::mark_slot_failed`] — increments failure counters,
//!   blacklists on critical errors, opens circuit at `MAX_CONSECUTIVE_FAILURES`.
//! * [`CircuitBreaker11Slot::mark_slot_success`] — increments success counters,
//!   resets consecutive failures, updates EMA latency.
//! * [`CircuitBreaker11Slot::mark_slot_request`] — increments total_requests.
//! * [`CircuitBreaker11Slot::get_status`] — comprehensive status dict matching
//!   the Python return shape.
//! * [`CircuitBreaker11Slot::get_available_slots`] /
//!   [`CircuitBreaker11Slot::get_blacklisted_slots`] /
//!   [`CircuitBreaker11Slot::reset_all_circuits`] /
//!   [`CircuitBreaker11Slot::reset_slot`] — query/recovery helpers.
//!
//! The Python original integrates with `telemetry_watcher`, `elite_registry`,
//! and `torshield_ai_gateway.model_selector`. Those integrations are exposed
//! as injectable traits ([`Telemetry`], [`EliteRegistry`], [`ModelSelector`]);
//! passing `None` for any of them mirrors the Python "ImportError → None" path.
//! See `MIGRATION_NOTES.md` for details.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use chrono::Utc;
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration constants (mirror `circuit_breaker_11slot.py`)
// ─────────────────────────────────────────────────────────────────────────────

/// Number of Cloudflare account slots (1..=11).
pub const NUM_SLOTS: i32 = 11;

/// Consecutive failure count that opens a slot's circuit.
pub const MAX_CONSECUTIVE_FAILURES: i64 = 3;

/// Seconds before an OPEN circuit auto-resets.
pub const CIRCUIT_RESET_SECONDS: f64 = 300.0;

/// Seconds during which a recently-failed slot is skipped.
pub const BACKOFF_WINDOW_SECONDS: f64 = 90.0;

/// Seconds a session-blacklisted slot stays blacklisted.
pub const SESSION_BLACKLIST_DURATION: f64 = 3600.0;

/// Default `avg_latency_ms` for a fresh slot.
pub const DEFAULT_AVG_LATENCY_MS: f64 = 200.0;

/// EMA smoothing factor for `avg_latency_ms` updates in `mark_slot_success`.
pub const LATENCY_EMA_ALPHA: f64 = 0.25;

/// Initial health multiplier applied to `health_score` for blacklisted slots.
pub const BLACKLIST_HEALTH_MULTIPLIER: f64 = 0.1;

/// Initial health multiplier applied to `health_score` for circuit-open slots.
pub const CIRCUIT_OPEN_HEALTH_MULTIPLIER: f64 = 0.05;

/// Latency penalty cap (`avg_latency_ms / 10_000`, max 0.5).
pub const LATENCY_PENALTY_CAP: f64 = 0.5;

/// Ultimate fallback model id when all dynamic/static sources are exhausted.
pub const ULTIMATE_FALLBACK_MODEL: &str = "@cf/meta/llama-3.1-8b-instruct";

/// Hardcoded mirror of `elite_registry.STATIC_BASELINE` model IDs. The Python
/// `STATIC_BASELINE` entries start with `is_available=True`; the Rust port
/// preserves that initial state. When an [`EliteRegistry`] is supplied, it can
/// override availability via [`EliteRegistry::is_model_available`].
pub const STATIC_BASELINE_MODELS: &[&str] = &[
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
    "@cf/meta/llama-3.3-70b-instruct",
    "@cf/meta/llama-4-scout-17b-16e-instruct",
    "@cf/mistralai/mistral-small-3.1-24b-instruct",
    "@cf/qwen/qwen3-32b",
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
    "@cf/google/gemma-3-27b-it",
    "@cf/meta/llama-3.1-8b-instruct",
    "@cf/mistralai/mistral-7b-instruct-v0.2-lora",
    "llama3.3-70b",
    "meta/llama-3.1-70b-instruct",
    "gpt-oss-120b",
];

/// Returns `true` if `error` contains any of the [`CRITICAL_ERRORS`] substrings.
///
/// Mirrors the Python `any(crit in error for crit in CRITICAL_ERRORS)`.
pub fn is_critical_error(error: &str) -> bool {
    CRITICAL_ERRORS.iter().any(|crit| error.contains(crit))
}

/// Error substrings that trigger immediate session blacklisting.
pub const CRITICAL_ERRORS: &[&str] = &["HTTP 403", "HTTP 401", "HTTP 1010", "Circuit Open"];

/// Error substrings that trigger circuit-breaker logic (but not immediate
/// blacklist). Listed for parity with the Python `CIRCUIT_ERRORS` set; the
/// Rust port does not branch on this set (the Python original also does not
/// branch on it beyond the docstring — `mark_slot_failed` only checks
/// `CRITICAL_ERRORS`).
pub const CIRCUIT_ERRORS: &[&str] = &[
    "HTTP 400",
    "HTTP 500",
    "HTTP 502",
    "HTTP 503",
    "HTTP 504",
    "Timeout",
    "ConnectionError",
    "SSLError",
];

// ─────────────────────────────────────────────────────────────────────────────
// Typed errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `circuit_breaker_11slot.py` parity port. The
/// Python original never raises (it logs and continues); this enum is reserved
/// for future strict-mode callers and is currently unused.
#[derive(Debug, thiserror::Error)]
pub enum CircuitBreaker11SlotError {
    /// A slot index was outside the valid range 1..=11.
    #[error("invalid slot index {index}: expected 1..={max}")]
    InvalidSlotIndex { index: i32, max: i32 },
}

// ─────────────────────────────────────────────────────────────────────────────
// Environment map and clock
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python's `os.environ` snapshot — keys are uppercase env var names.
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
// Injectable integration traits
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of the Python `telemetry_watcher.get_telemetry()` integration.
///
/// All methods are no-ops by default; implementations override them to emit
/// telemetry events. The Python original swallows all exceptions raised by
/// these calls; the Rust port preserves that "never raise" contract by
/// keeping the trait methods infallible.
pub trait Telemetry: Send + Sync {
    /// Mirror of `telemetry.log_slot_failure(slot_index, env_var, error_type, error_detail)`.
    fn log_slot_failure(
        &self,
        slot_index: i32,
        env_var: &str,
        error_type: &str,
        error_detail: &str,
    );

    /// Mirror of `telemetry.log_request(success)`.
    fn log_request(&self, success: bool);

    /// Mirror of `telemetry.log_self_heal(action, data, success, recovery_time_ms=...)`.
    /// `recovery_time_ms` is optional (Python defaults to 0.0).
    fn log_self_heal(
        &self,
        action: &str,
        data: Value,
        success: bool,
        recovery_time_ms: Option<f64>,
    );
}

/// Mirror of the Python `elite_registry.get_registry()` integration.
pub trait EliteRegistry: Send + Sync {
    /// Mirror of `registry.get_best_model(task)`. Returns `None` to fall
    /// through to the next fallback step.
    fn get_best_model(&self, task: &str) -> Option<String>;

    /// Mirror of `registry.mark_model_error(model_id)`.
    fn mark_model_error(&self, model_id: &str);

    /// Mirror of `registry.mark_model_success(model_id, latency_ms)`.
    fn mark_model_success(&self, model_id: &str, latency_ms: f64);

    /// Mirror of `entry.is_available` for the STATIC_BASELINE entry with the
    /// given model_id. The Python original reads `entry.is_available` from
    /// the registry's static list; the Rust port delegates to the registry
    /// implementation. Returns `true` by default (matching the initial
    /// `is_available=True` of all 12 STATIC_BASELINE entries).
    fn is_model_available(&self, _model_id: &str) -> bool {
        true
    }
}

/// Mirror of `torshield_ai_gateway.model_selector.best_cf_model()`.
pub trait ModelSelector: Send + Sync {
    /// Returns `Some(model_id)` if a model is available, `None` to fall
    /// through to the STATIC_BASELINE fallback.
    fn best_cf_model(&self) -> Option<String>;
}

// ─────────────────────────────────────────────────────────────────────────────
// SlotState
// ─────────────────────────────────────────────────────────────────────────────

/// Per-slot state. Mirror of Python's `SlotState` dataclass.
///
/// All fields are public to allow direct inspection by callers and tests,
/// matching the Python dataclass's public field access semantics. Mutations
/// happen via [`CircuitBreaker11Slot`] methods (which take `&mut self`) to
/// preserve the locking contract of the Python original.
#[derive(Debug, Clone)]
pub struct SlotState {
    /// Slot index (1..=11).
    pub index: i32,
    /// Cloudflare account ID.
    pub account_id: String,
    /// Cloudflare API token.
    pub api_token: String,
    /// Cloudflare AI Gateway URL.
    pub gateway_url: String,

    /// `true` if both `account_id` and `api_token` are non-empty.
    pub is_configured: bool,
    /// `true` when the circuit breaker is OPEN.
    pub circuit_open: bool,
    /// Epoch seconds when the circuit opened.
    pub circuit_open_ts: f64,
    /// `true` when the slot is session-blacklisted.
    pub session_blacklisted: bool,
    /// Epoch seconds when the slot was blacklisted.
    pub blacklist_ts: f64,

    /// Cumulative request count (successes + failures + pre-outcome tracking).
    pub total_requests: i64,
    /// Cumulative successful requests.
    pub total_successes: i64,
    /// Cumulative failed requests.
    pub total_failures: i64,
    /// Consecutive failures since the last success.
    pub consecutive_failures: i64,
    /// Epoch seconds of the last failure.
    pub last_failure_ts: f64,
    /// Error string of the last failure.
    pub last_failure_error: String,
    /// Epoch seconds of the last success.
    pub last_success_ts: f64,
    /// Exponential moving average of latency in ms.
    pub avg_latency_ms: f64,

    /// Model id currently associated with the slot.
    pub current_model: String,
    /// Per-model error counts.
    pub model_errors: BTreeMap<String, i64>,
}

impl SlotState {
    /// Construct a fresh slot with the given credentials. Mirror of the
    /// Python `SlotState(index=..., account_id=..., ...)` dataclass init.
    pub fn new(index: i32, account_id: String, api_token: String, gateway_url: String) -> Self {
        let is_configured = !account_id.is_empty() && !api_token.is_empty();
        Self {
            index,
            account_id,
            api_token,
            gateway_url,
            is_configured,
            circuit_open: false,
            circuit_open_ts: 0.0,
            session_blacklisted: false,
            blacklist_ts: 0.0,
            total_requests: 0,
            total_successes: 0,
            total_failures: 0,
            consecutive_failures: 0,
            last_failure_ts: 0.0,
            last_failure_error: String::new(),
            last_success_ts: 0.0,
            avg_latency_ms: DEFAULT_AVG_LATENCY_MS,
            current_model: String::new(),
            model_errors: BTreeMap::new(),
        }
    }

    /// Mirror of Python `success_rate` property. Returns 1.0 when no
    /// requests have been recorded.
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            1.0
        } else {
            self.total_successes as f64 / self.total_requests as f64
        }
    }

    /// Mirror of Python `health_score` property. Composite health score
    /// 0.0–1.0 (higher = better).
    pub fn health_score(&self) -> f64 {
        let latency_penalty = (self.avg_latency_ms / 10_000.0).min(LATENCY_PENALTY_CAP);
        let mut base = self.success_rate() * (1.0 - latency_penalty);
        if self.session_blacklisted {
            base *= BLACKLIST_HEALTH_MULTIPLIER;
        }
        if self.circuit_open {
            base *= CIRCUIT_OPEN_HEALTH_MULTIPLIER;
        }
        base
    }

    /// Mirror of Python `is_available()` method. Mutates state to clear
    /// expired blacklists/circuits (matching the Python side effect).
    ///
    /// The `now` parameter is the current epoch seconds (parity with
    /// `time.time()`); callers inject it via the breaker's clock.
    pub fn is_available(&mut self, now: f64) -> bool {
        if !self.is_configured {
            return false;
        }
        if self.session_blacklisted {
            // Check if blacklist has expired.
            if now - self.blacklist_ts > SESSION_BLACKLIST_DURATION {
                self.session_blacklisted = false;
                tracing::info!(
                    slot = self.index,
                    "[CircuitBreaker] Slot {}: blacklist expired",
                    self.index
                );
            } else {
                return false;
            }
        }
        if self.circuit_open {
            // Check if circuit should be reset.
            if now - self.circuit_open_ts > CIRCUIT_RESET_SECONDS {
                self.circuit_open = false;
                self.consecutive_failures = 0;
                tracing::info!(
                    slot = self.index,
                    "[CircuitBreaker] Slot {}: circuit reset",
                    self.index
                );
            } else {
                return false;
            }
        }
        // Skip recently failed slots.
        if self.consecutive_failures > 0
            && self.last_failure_ts > 0.0
            && now - self.last_failure_ts < BACKOFF_WINDOW_SECONDS
        {
            return false;
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Round to n decimals (parity with Python's round(x, n))
// ─────────────────────────────────────────────────────────────────────────────

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
// CircuitBreaker11Slot
// ─────────────────────────────────────────────────────────────────────────────

/// 11-Slot Circuit Breaker with Zero-Error Fallback.
///
/// Each of the 11 Cloudflare account slots has independent circuit breaker
/// state. Slots without credentials are marked unconfigured and excluded
/// from request routing.
///
/// The Python original uses a class-level singleton with `threading.Lock`.
/// This port exposes [`get_circuit_breaker_11slot`] which returns an
/// `Arc<Mutex<CircuitBreaker11Slot>>`; callers lock the mutex to access the
/// breaker, matching the Python lock semantics (each public method takes
/// `&mut self`, so the caller holds the lock for the duration of a call).
pub struct CircuitBreaker11Slot {
    slots: BTreeMap<i32, SlotState>,
    current_slot_index: i32,
    rotation_counter: i64,
    session_start: f64,
    fallback_mode: bool,
    now: Clock,
    telemetry: Option<Arc<dyn Telemetry>>,
    registry: Option<Arc<dyn EliteRegistry>>,
    model_selector: Option<Arc<dyn ModelSelector>>,
}

impl std::fmt::Debug for CircuitBreaker11Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitBreaker11Slot")
            .field("slots", &self.slots)
            .field("current_slot_index", &self.current_slot_index)
            .field("rotation_counter", &self.rotation_counter)
            .field("session_start", &self.session_start)
            .field("fallback_mode", &self.fallback_mode)
            .field("now", &"<clock closure>")
            .field("has_telemetry", &self.telemetry.is_some())
            .field("has_registry", &self.registry.is_some())
            .field("has_model_selector", &self.model_selector.is_some())
            .finish()
    }
}

impl CircuitBreaker11Slot {
    /// Construct a new breaker from the given env map, clock, and optional
    /// integrations. Mirrors the Python `__init__` (which reads `os.environ`
    /// at construction time).
    ///
    /// Passing `None` for `telemetry`/`registry`/`model_selector` mirrors the
    /// Python "ImportError → None" path; the corresponding integration calls
    /// are skipped.
    pub fn new(
        env: &EnvMap,
        now: Clock,
        telemetry: Option<Arc<dyn Telemetry>>,
        registry: Option<Arc<dyn EliteRegistry>>,
        model_selector: Option<Arc<dyn ModelSelector>>,
    ) -> Self {
        let mut breaker = Self {
            slots: BTreeMap::new(),
            current_slot_index: 0,
            rotation_counter: 0,
            session_start: now(),
            fallback_mode: false,
            now,
            telemetry,
            registry,
            model_selector,
        };
        breaker.init_slots(env);
        let configured = breaker.slots.values().filter(|s| s.is_configured).count();
        tracing::info!(
            configured,
            total = NUM_SLOTS,
            "[CircuitBreaker] Initialized: {}/{} slots configured",
            configured,
            NUM_SLOTS
        );
        breaker
    }

    /// Construct a breaker with no optional integrations (matching the
    /// Python `__init__` when both `telemetry_watcher` and `elite_registry`
    /// imports fail). Slot credentials are still read from the env map.
    pub fn new_without_integrations(env: &EnvMap, now: Clock) -> Self {
        Self::new(env, now, None, None, None)
    }

    /// Initialize all 11 CF slots from the env map. Mirror of Python `_init_slots`.
    fn init_slots(&mut self, env: &EnvMap) {
        for i in 1..=NUM_SLOTS {
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

            let slot = SlotState::new(i, account_id, api_token, gateway_url);
            self.slots.insert(i, slot);
        }
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Return a reference to the slot state for `slot_index`, if it exists.
    pub fn slot(&self, slot_index: i32) -> Option<&SlotState> {
        self.slots.get(&slot_index)
    }

    /// Return a mutable reference to the slot state for `slot_index`, if it
    /// exists. Exposed for tests that need to mutate slot state directly
    /// (matching the Python `cb._slots[i].<field> = ...` pattern).
    pub fn slot_mut(&mut self, slot_index: i32) -> Option<&mut SlotState> {
        self.slots.get_mut(&slot_index)
    }

    /// Return the current slot index (parity with `cb._current_slot_index`).
    pub fn current_slot_index(&self) -> i32 {
        self.current_slot_index
    }

    /// Return the rotation counter (parity with `cb._rotation_counter`).
    pub fn rotation_counter(&self) -> i64 {
        self.rotation_counter
    }

    /// Return whether the breaker is in fallback mode.
    pub fn fallback_mode(&self) -> bool {
        self.fallback_mode
    }

    /// Return the session start epoch seconds.
    pub fn session_start(&self) -> f64 {
        self.session_start
    }

    // ── Slot Selection ───────────────────────────────────────────────────

    /// Get the next available slot using round-robin with health scoring.
    /// Returns `Some(slot_index)` if a slot is available, `None` if all
    /// slots are unavailable (matching the Python `None` return).
    ///
    /// On `None`, callers should fall back to [`Self::get_next_model`] for
    /// zero-error behavior (the Python original returns `None` from this
    /// method and lets the caller decide).
    pub fn get_next_slot(&mut self) -> Option<i32> {
        let now = (self.now)();
        // Try all slots in round-robin order.
        for _ in 0..NUM_SLOTS {
            self.current_slot_index = (self.current_slot_index % NUM_SLOTS) + 1;
            if let Some(slot) = self.slots.get_mut(&self.current_slot_index) {
                if slot.is_available(now) {
                    self.rotation_counter += 1;
                    return Some(slot.index);
                }
            }
        }
        // No available slots — try aggressive recovery.
        self.aggressive_recovery()
    }

    /// Get the next available slot that has a gateway URL configured.
    /// Preferred during high-censorship hours for CDN caching benefits.
    /// Falls back to [`Self::get_next_slot`] when no gateway-enabled slot
    /// is available.
    pub fn get_next_slot_with_gateway(&mut self) -> Option<i32> {
        let now = (self.now)();
        // Filter to gateway-enabled slots. We clone the relevant slot data
        // (index + health_score) so we can sort without holding a borrow on
        // self.slots while mutating.
        let mut gateway_slots: Vec<(i32, f64)> = self
            .slots
            .values_mut()
            .filter_map(|s| {
                if s.is_available(now) && !s.gateway_url.is_empty() {
                    Some((s.index, s.health_score()))
                } else {
                    None
                }
            })
            .collect();
        if !gateway_slots.is_empty() {
            // Sort by health score (best first). Stable on ties (preserves
            // the BTreeMap insertion order which mirrors the Python dict
            // insertion order).
            gateway_slots
                .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            self.rotation_counter += 1;
            return Some(gateway_slots[0].0);
        }
        // Fallback to any available slot.
        self.get_next_slot()
    }

    /// Aggressive recovery when no slots are available. Resets blacklists
    /// and circuits, returns the best slot by health score. Mirrors the
    /// Python `_aggressive_recovery` method.
    pub fn aggressive_recovery(&mut self) -> Option<i32> {
        tracing::warn!("[CircuitBreaker] No available slots — aggressive recovery");
        // Reset all session blacklists.
        for slot in self.slots.values_mut() {
            slot.session_blacklisted = false;
            slot.circuit_open = false;
            slot.consecutive_failures = 0;
        }
        // Log telemetry.
        if let Some(telemetry) = &self.telemetry {
            telemetry.log_self_heal(
                "aggressive_slot_recovery",
                json!({"action": "reset_all_blacklists_and_circuits"}),
                true,
                None,
            );
        }
        // Return the slot with best historical performance among configured slots.
        let mut configured: Vec<(i32, f64)> = self
            .slots
            .values()
            .filter(|s| s.is_configured)
            .map(|s| (s.index, s.health_score()))
            .collect();
        if configured.is_empty() {
            return None;
        }
        configured.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Some(configured[0].0)
    }

    // ── Model Selection with Zero-Error Fallback ─────────────────────────

    /// Get the next best model with zero-error fallback chain:
    /// 1. Try Elite-Registry (dynamic ranking)
    /// 2. Try ModelSelector (`best_cf_model`)
    /// 3. Fallback to STATIC_BASELINE (first available entry)
    /// 4. Ultimate fallback: `@cf/meta/llama-3.1-8b-instruct`
    ///
    /// NEVER raises — always returns a valid model ID. Mirrors the Python
    /// `get_next_model` exactly, including the static-baseline iteration
    /// order.
    pub fn get_next_model(&self, task: &str) -> String {
        // Step 1: Try Elite-Registry.
        if let Some(registry) = &self.registry {
            if let Some(model_id) = registry.get_best_model(task) {
                if !model_id.is_empty() {
                    return model_id;
                }
            }
        }
        // Step 2: Try ModelSelector.
        if let Some(selector) = &self.model_selector {
            if let Some(model_id) = selector.best_cf_model() {
                if !model_id.is_empty() {
                    return model_id;
                }
            }
        }
        // Step 3: STATIC_BASELINE fallback.
        for model_id in STATIC_BASELINE_MODELS {
            let available = self
                .registry
                .as_ref()
                .map(|r| r.is_model_available(model_id))
                .unwrap_or(true);
            if available {
                return (*model_id).to_string();
            }
        }
        // Step 4: Ultimate fallback.
        ULTIMATE_FALLBACK_MODEL.to_string()
    }

    // ── Error Handling ───────────────────────────────────────────────────

    /// Mark a slot as failed. Implements zero-error fallback:
    /// a) Instantly log and blacklist the slot for current session (on critical errors)
    /// b) Open circuit breaker if needed (at MAX_CONSECUTIVE_FAILURES)
    /// c) Log to telemetry
    ///
    /// Mirrors the Python `mark_slot_failed` method exactly, including the
    /// `model_errors` tracking and the registry's `mark_model_error` call.
    pub fn mark_slot_failed(&mut self, slot_index: i32, error: &str, model_id: &str) {
        let now = (self.now)();
        let should_log_telemetry;
        {
            let Some(slot) = self.slots.get_mut(&slot_index) else {
                return;
            };
            slot.total_failures += 1;
            slot.consecutive_failures += 1;
            slot.last_failure_ts = now;
            slot.last_failure_error = error.to_string();

            // Track model-specific errors.
            if !model_id.is_empty() {
                *slot.model_errors.entry(model_id.to_string()).or_insert(0) += 1;
            }
            should_log_telemetry = !model_id.is_empty();

            // Immediate blacklist for critical errors.
            if is_critical_error(error) {
                slot.session_blacklisted = true;
                slot.blacklist_ts = now;
                tracing::warn!(
                    slot = slot_index,
                    error = error,
                    "[CircuitBreaker] Slot {}: SESSION BLACKLISTED ({})",
                    slot_index,
                    error
                );
            }

            // Open circuit for repeated failures.
            if slot.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                slot.circuit_open = true;
                slot.circuit_open_ts = now;
                tracing::warn!(
                    slot = slot_index,
                    consecutive_failures = slot.consecutive_failures,
                    "[CircuitBreaker] Slot {}: CIRCUIT OPEN (consecutive_failures={})",
                    slot_index,
                    slot.consecutive_failures
                );
            }
        }

        // Mark model error in elite registry (outside the slot lock scope
        // to avoid borrowing self.slots while calling the registry).
        if should_log_telemetry {
            if let Some(registry) = &self.registry {
                registry.mark_model_error(model_id);
            }
        }

        // Log to telemetry.
        if let Some(telemetry) = &self.telemetry {
            telemetry.log_slot_failure(
                slot_index,
                &format!("CF_SLOT_{slot_index}"),
                error,
                &format!("model={model_id}"),
            );
            // Log self-heal: automatic rotation to next slot.
            telemetry.log_self_heal(
                "slot_failover",
                json!({
                    "failed_slot": slot_index,
                    "error": error,
                    "action": "rotate_to_next_slot",
                }),
                true,
                Some(0.1), // Sub-second.
            );
        }
    }

    /// Mark a slot as having a successful response. Updates total_requests,
    /// total_successes, resets consecutive_failures, updates EMA latency
    /// (alpha=0.25), and tracks the current model.
    pub fn mark_slot_success(&mut self, slot_index: i32, latency_ms: f64, model_id: &str) {
        let now = (self.now)();
        let should_log_registry;
        {
            let Some(slot) = self.slots.get_mut(&slot_index) else {
                return;
            };
            slot.total_requests += 1;
            slot.total_successes += 1;
            slot.consecutive_failures = 0;
            slot.last_success_ts = now;

            // Update latency with EMA.
            let alpha = LATENCY_EMA_ALPHA;
            slot.avg_latency_ms = alpha * latency_ms + (1.0 - alpha) * slot.avg_latency_ms;

            // Track current model.
            if !model_id.is_empty() {
                slot.current_model = model_id.to_string();
                should_log_registry = true;
            } else {
                should_log_registry = false;
            }
        }

        // Mark model success in elite registry.
        if should_log_registry {
            if let Some(registry) = &self.registry {
                registry.mark_model_success(model_id, latency_ms);
            }
        }

        // Log to telemetry.
        if let Some(telemetry) = &self.telemetry {
            telemetry.log_request(true);
        }
    }

    /// Track that a request was made to a slot (before knowing outcome).
    /// Increments `total_requests` only.
    pub fn mark_slot_request(&mut self, slot_index: i32) {
        let Some(slot) = self.slots.get_mut(&slot_index) else {
            return;
        };
        slot.total_requests += 1;
    }

    // ── Status & Reporting ───────────────────────────────────────────────

    /// Get comprehensive circuit breaker status as a JSON value matching the
    /// Python `get_status()` dict shape. Calling this method may mutate slot
    /// state via `is_available` (matching the Python side effect of clearing
    /// expired blacklists/circuits).
    pub fn get_status(&mut self) -> Value {
        let now = (self.now)();
        let mut available_count = 0i64;
        let mut configured_count = 0i64;
        let mut blacklisted_count = 0i64;
        let mut circuit_open_count = 0i64;
        let mut slots_map = serde_json::Map::new();

        // We need to call is_available (which mutates) and also read fields.
        // Collect all slot data in one pass to avoid borrow conflicts.
        for (i, slot) in self.slots.iter_mut() {
            let available = slot.is_available(now);
            let configured = slot.is_configured;
            let circuit_open = slot.circuit_open;
            let blacklisted = slot.session_blacklisted;
            let health_score = slot.health_score();
            let success_rate = slot.success_rate();
            let avg_latency_ms = slot.avg_latency_ms;
            let consecutive_failures = slot.consecutive_failures;
            let has_gateway = !slot.gateway_url.is_empty();

            if available {
                available_count += 1;
            }
            if configured {
                configured_count += 1;
            }
            if blacklisted {
                blacklisted_count += 1;
            }
            if circuit_open {
                circuit_open_count += 1;
            }

            slots_map.insert(
                i.to_string(),
                json!({
                    "configured": configured,
                    "available": available,
                    "circuit_open": circuit_open,
                    "blacklisted": blacklisted,
                    "health_score": round_to(health_score, 3),
                    "success_rate": round_to(success_rate, 3),
                    "avg_latency_ms": round_to(avg_latency_ms, 1),
                    "consecutive_failures": consecutive_failures,
                    "has_gateway": has_gateway,
                }),
            );
        }

        let session_duration_minutes = ((now - self.session_start) / 60.0 * 10.0).round() / 10.0;

        json!({
            "total_slots": NUM_SLOTS,
            "configured_slots": configured_count,
            "available_slots": available_count,
            "blacklisted_slots": blacklisted_count,
            "circuit_open_slots": circuit_open_count,
            "rotation_counter": self.rotation_counter,
            "fallback_mode": self.fallback_mode,
            "session_duration_minutes": session_duration_minutes,
            "slots": Value::Object(slots_map),
        })
    }

    /// Get list of currently available slot indices. Mirrors the Python
    /// `get_available_slots` (which returns `list[SlotState]`; this port
    /// returns `Vec<i32>` of indices for caller convenience).
    pub fn get_available_slots(&mut self) -> Vec<i32> {
        let now = (self.now)();
        self.slots
            .values_mut()
            .filter_map(|s| {
                if s.is_available(now) {
                    Some(s.index)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get list of blacklisted slot indices. Mirrors the Python
    /// `get_blacklisted_slots` (which returns `list[int]`).
    pub fn get_blacklisted_slots(&self) -> Vec<i32> {
        self.slots
            .values()
            .filter_map(|s| {
                if s.session_blacklisted {
                    Some(s.index)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Reset all circuit breakers (emergency recovery). Mirrors the Python
    /// `reset_all_circuits` method.
    pub fn reset_all_circuits(&mut self) {
        for slot in self.slots.values_mut() {
            slot.circuit_open = false;
            slot.consecutive_failures = 0;
            slot.session_blacklisted = false;
        }
        tracing::info!("[CircuitBreaker] All circuits reset");
        if let Some(telemetry) = &self.telemetry {
            telemetry.log_self_heal(
                "reset_all_circuits",
                json!({"action": "emergency_recovery"}),
                true,
                None,
            );
        }
    }

    /// Reset a specific slot's circuit breaker. Returns `true` if the slot
    /// was found and reset, `false` otherwise. Mirrors the Python `reset_slot`.
    pub fn reset_slot(&mut self, slot_index: i32) -> bool {
        let Some(slot) = self.slots.get_mut(&slot_index) else {
            return false;
        };
        slot.circuit_open = false;
        slot.consecutive_failures = 0;
        slot.session_blacklisted = false;
        tracing::info!(
            slot = slot_index,
            "[CircuitBreaker] Slot {}: manually reset",
            slot_index
        );
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton accessor
// ─────────────────────────────────────────────────────────────────────────────

static SINGLETON: OnceLock<Arc<Mutex<CircuitBreaker11Slot>>> = OnceLock::new();

/// Get the singleton [`CircuitBreaker11Slot`] instance, initialized from
/// `std::env::vars()`. The singleton has no optional integrations attached
/// (matching the Python "import failed → None" path when the corresponding
/// modules are unavailable in the production environment).
///
/// Returns an `Arc<Mutex<CircuitBreaker11Slot>>` that callers lock to access
/// the breaker. Each public method on `CircuitBreaker11Slot` takes `&mut
/// self`, so the caller holds the lock for the duration of a call (matching
/// the Python `Lock` semantics).
pub fn get_circuit_breaker_11slot() -> Arc<Mutex<CircuitBreaker11Slot>> {
    SINGLETON
        .get_or_init(|| {
            let env: EnvMap = std::env::vars().collect();
            let breaker = CircuitBreaker11Slot::new_without_integrations(&env, default_clock());
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
        env.insert(
            "CF_AI_GATEWAY_URL_1".to_string(),
            "https://gw1.example".to_string(),
        );
        env.insert("CF_ACCOUNT_ID_2".to_string(), "b".repeat(32));
        env.insert("CF_API_TOKEN_2".to_string(), "u".repeat(40));
        env
    }

    fn fixed_clock(t: f64) -> Clock {
        Arc::new(move || t)
    }

    #[test]
    fn fresh_breaker_initializes_slots() {
        let env = test_env();
        let cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        assert_eq!(cb.slots.len(), NUM_SLOTS as usize);
        assert!(cb.slot(1).unwrap().is_configured);
        assert!(cb.slot(2).unwrap().is_configured);
        assert!(!cb.slot(3).unwrap().is_configured);
        assert_eq!(cb.slot(1).unwrap().gateway_url, "https://gw1.example");
    }

    #[test]
    fn health_score_default_is_0_98() {
        let env = test_env();
        let cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        // 1.0 * (1 - 200/10000) = 0.98
        assert_eq!(cb.slot(1).unwrap().health_score(), 0.98);
    }

    #[test]
    fn critical_error_blacklists_slot() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        cb.mark_slot_failed(1, "HTTP 403 Forbidden", "model-1");
        let s = cb.slot(1).unwrap();
        assert!(s.session_blacklisted);
        assert!(!s.circuit_open); // only 1 failure, below threshold
        assert_eq!(s.consecutive_failures, 1);
        assert_eq!(s.total_failures, 1);
        assert_eq!(s.model_errors.get("model-1"), Some(&1));
    }

    #[test]
    fn circuit_error_at_threshold_opens_circuit() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.mark_slot_failed(1, "HTTP 500 Internal", "model-1");
        }
        let s = cb.slot(1).unwrap();
        assert!(s.circuit_open);
        assert!(!s.session_blacklisted); // not a critical error
        assert_eq!(s.consecutive_failures, MAX_CONSECUTIVE_FAILURES);
    }

    #[test]
    fn mark_slot_success_resets_consecutive_failures_and_updates_ema() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        cb.mark_slot_failed(1, "HTTP 500", "m1");
        cb.mark_slot_failed(1, "HTTP 500", "m1");
        cb.mark_slot_success(1, 100.0, "m1");
        let s = cb.slot(1).unwrap();
        assert_eq!(s.consecutive_failures, 0);
        assert_eq!(s.total_successes, 1);
        // EMA: 0.25 * 100 + 0.75 * 200 = 175
        assert_eq!(s.avg_latency_ms, 175.0);
        assert_eq!(s.current_model, "m1");
    }

    #[test]
    fn mark_slot_request_increments_total_requests_only() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        cb.mark_slot_request(1);
        cb.mark_slot_request(1);
        let s = cb.slot(1).unwrap();
        assert_eq!(s.total_requests, 2);
        assert_eq!(s.total_successes, 0);
        assert_eq!(s.total_failures, 0);
    }

    #[test]
    fn is_available_respects_blacklist_expiry() {
        let env = test_env();
        let (clock, state) = test_clock(1000.0);
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, clock);
        cb.mark_slot_failed(1, "HTTP 403", "m1");
        assert!(cb.slot(1).unwrap().session_blacklisted);
        // Before expiry: not available.
        *state.lock().unwrap() = 1000.0 + SESSION_BLACKLIST_DURATION - 1.0;
        assert!(!cb.get_available_slots().contains(&1));
        // After expiry: blacklist cleared, available again.
        *state.lock().unwrap() = 1000.0 + SESSION_BLACKLIST_DURATION + 1.0;
        assert!(cb.get_available_slots().contains(&1));
        assert!(!cb.slot(1).unwrap().session_blacklisted);
    }

    #[test]
    fn is_available_respects_circuit_reset() {
        let env = test_env();
        let (clock, state) = test_clock(1000.0);
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, clock);
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.mark_slot_failed(1, "HTTP 500", "m1");
        }
        assert!(cb.slot(1).unwrap().circuit_open);
        // Before reset: not available.
        *state.lock().unwrap() = 1000.0 + CIRCUIT_RESET_SECONDS - 1.0;
        assert!(!cb.get_available_slots().contains(&1));
        // After reset: circuit cleared, available again.
        *state.lock().unwrap() = 1000.0 + CIRCUIT_RESET_SECONDS + 1.0;
        assert!(cb.get_available_slots().contains(&1));
        assert!(!cb.slot(1).unwrap().circuit_open);
    }

    #[test]
    fn is_available_respects_backoff_window() {
        let env = test_env();
        let (clock, state) = test_clock(1000.0);
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, clock);
        // 1 failure: below circuit threshold, but within backoff window.
        cb.mark_slot_failed(1, "HTTP 500", "m1");
        // Within backoff window: not available.
        *state.lock().unwrap() = 1000.0 + BACKOFF_WINDOW_SECONDS - 1.0;
        assert!(!cb.get_available_slots().contains(&1));
        // After backoff window: available.
        *state.lock().unwrap() = 1000.0 + BACKOFF_WINDOW_SECONDS + 1.0;
        assert!(cb.get_available_slots().contains(&1));
    }

    #[test]
    fn get_next_slot_round_robin() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        // First call: starts at 0, advances to 1, returns slot 1.
        let s1 = cb.get_next_slot().unwrap();
        assert_eq!(s1, 1);
        // Second call: advances to 2, returns slot 2.
        let s2 = cb.get_next_slot().unwrap();
        assert_eq!(s2, 2);
        // Third call: advances to 3..11 (all unconfigured), then wraps to 1.
        let s3 = cb.get_next_slot().unwrap();
        assert_eq!(s3, 1);
    }

    #[test]
    fn get_next_slot_with_gateway_prefers_gateway_slots() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        // Slot 1 has gateway; slot 2 does not. Should return slot 1.
        let s = cb.get_next_slot_with_gateway().unwrap();
        assert_eq!(s, 1);
    }

    #[test]
    fn aggressive_recovery_resets_and_returns_best() {
        let env = test_env();
        let (clock, state) = test_clock(1000.0);
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, clock);
        // Blacklist all configured slots.
        cb.mark_slot_failed(1, "HTTP 403", "m1");
        cb.mark_slot_failed(2, "HTTP 403", "m2");
        // Within blacklist window: no slots available. get_next_slot falls
        // back to aggressive_recovery which resets blacklists and returns
        // the best configured slot (slot 1 or 2).
        *state.lock().unwrap() = 1000.0 + 10.0;
        let recovered = cb.get_next_slot();
        assert!(
            recovered.is_some(),
            "aggressive_recovery should return a slot"
        );
        // aggressive_recovery should have cleared blacklists.
        assert!(!cb.slot(1).unwrap().session_blacklisted);
        assert!(!cb.slot(2).unwrap().session_blacklisted);
    }

    #[test]
    fn get_status_full_dict_shape() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        let status = cb.get_status();
        assert_eq!(status["total_slots"], json!(NUM_SLOTS));
        assert_eq!(status["configured_slots"], json!(2));
        assert_eq!(status["available_slots"], json!(2));
        assert_eq!(status["blacklisted_slots"], json!(0));
        assert_eq!(status["circuit_open_slots"], json!(0));
        assert_eq!(status["rotation_counter"], json!(0));
        assert_eq!(status["fallback_mode"], json!(false));
        assert_eq!(status["session_duration_minutes"], json!(0.0));
        assert_eq!(status["slots"]["1"]["configured"], json!(true));
        assert_eq!(status["slots"]["1"]["has_gateway"], json!(true));
        assert_eq!(status["slots"]["1"]["health_score"], json!(0.98));
        assert_eq!(status["slots"]["1"]["avg_latency_ms"], json!(200.0));
        assert_eq!(status["slots"]["2"]["has_gateway"], json!(false));
        assert_eq!(status["slots"]["3"]["configured"], json!(false));
    }

    #[test]
    fn get_blacklisted_slots_returns_indices() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        cb.mark_slot_failed(1, "HTTP 403", "m1");
        cb.mark_slot_failed(2, "HTTP 401", "m2");
        let mut bl = cb.get_blacklisted_slots();
        bl.sort();
        assert_eq!(bl, vec![1, 2]);
    }

    #[test]
    fn reset_all_circuits_clears_state() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        cb.mark_slot_failed(1, "HTTP 403", "m1");
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.mark_slot_failed(2, "HTTP 500", "m2");
        }
        cb.reset_all_circuits();
        for s in cb.slots.values() {
            assert!(!s.circuit_open);
            assert!(!s.session_blacklisted);
            assert_eq!(s.consecutive_failures, 0);
        }
    }

    #[test]
    fn reset_slot_returns_false_for_unknown() {
        let env = test_env();
        let mut cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        assert!(!cb.reset_slot(99));
        assert!(cb.reset_slot(1));
    }

    #[test]
    fn get_next_model_fallback_chain() {
        let env = test_env();
        let cb = CircuitBreaker11Slot::new_without_integrations(&env, fixed_clock(1000.0));
        // No registry, no model_selector: returns first STATIC_BASELINE entry.
        assert_eq!(
            cb.get_next_model("general"),
            "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
        );
    }

    #[test]
    fn get_next_model_ultimate_fallback_when_baseline_unavailable() {
        struct AllUnavailable;
        impl EliteRegistry for AllUnavailable {
            fn get_best_model(&self, _task: &str) -> Option<String> {
                None
            }
            fn mark_model_error(&self, _model_id: &str) {}
            fn mark_model_success(&self, _model_id: &str, _latency_ms: f64) {}
            fn is_model_available(&self, _model_id: &str) -> bool {
                false
            }
        }
        let env = test_env();
        let cb = CircuitBreaker11Slot::new(
            &env,
            fixed_clock(1000.0),
            None,
            Some(Arc::new(AllUnavailable)),
            None,
        );
        assert_eq!(cb.get_next_model("general"), ULTIMATE_FALLBACK_MODEL);
    }

    #[test]
    fn get_next_model_uses_registry_when_available() {
        struct StubRegistry;
        impl EliteRegistry for StubRegistry {
            fn get_best_model(&self, _task: &str) -> Option<String> {
                Some("custom-model".to_string())
            }
            fn mark_model_error(&self, _model_id: &str) {}
            fn mark_model_success(&self, _model_id: &str, _latency_ms: f64) {}
        }
        let env = test_env();
        let cb = CircuitBreaker11Slot::new(
            &env,
            fixed_clock(1000.0),
            None,
            Some(Arc::new(StubRegistry)),
            None,
        );
        assert_eq!(cb.get_next_model("general"), "custom-model");
    }

    #[test]
    fn get_next_model_uses_model_selector_when_no_registry() {
        struct StubSelector;
        impl ModelSelector for StubSelector {
            fn best_cf_model(&self) -> Option<String> {
                Some("selector-model".to_string())
            }
        }
        let env = test_env();
        let cb = CircuitBreaker11Slot::new(
            &env,
            fixed_clock(1000.0),
            None,
            None,
            Some(Arc::new(StubSelector)),
        );
        assert_eq!(cb.get_next_model("general"), "selector-model");
    }

    #[test]
    fn default_clock_returns_positive_epoch() {
        let clock = default_clock();
        let t = clock();
        assert!(
            t > 1_700_000_000.0,
            "default clock should return a recent epoch: {t}"
        );
    }

    /// Create an injectable clock backed by a shared mutable f64. Returns the
    /// clock and a handle that tests can advance via `*handle.lock().unwrap() = t`.
    fn test_clock(initial: f64) -> (Clock, Arc<Mutex<f64>>) {
        let state = Arc::new(Mutex::new(initial));
        let state_clone = Arc::clone(&state);
        let clock: Clock = Arc::new(move || *state_clone.lock().unwrap());
        (clock, state)
    }
}

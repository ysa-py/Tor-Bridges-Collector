//! Parity port of `telemetry_watcher.py` — Centralized Telemetry & Self-Healing
//! Monitor v1.0.
//!
//! Autonomous telemetry system for the TorShield-IR project. Provides
//! centralized logging, 24-hour aggregation, DPI event tracking, slot
//! poisoning detection, self-healing diagnostics, and auto-debug triggering.
//!
//! Behavior traced to `telemetry_watcher.py`:
//! * [`TelemetryWatcher::log_dpi_event`] / [`TelemetryWatcher::log_slot_failure`]
//!   / [`TelemetryWatcher::log_slot_recovery`] / [`TelemetryWatcher::log_self_heal`]
//!   — append-only event loggers that mutate the in-memory event lists and
//!   counters under a mutex, then attempt to write to `monitor.log` and
//!   persist state to `telemetry_state.json`. I/O failures are swallowed
//!   (matching Python's `try/except: pass` "ZERO CRASH" principle) but the
//!   in-memory state is always updated.
//! * [`TelemetryWatcher::log_model_resolution_failure`] — increments the
//!   consecutive failure counter and triggers [`TelemetryWatcher::trigger_auto_debug`]
//!   when the counter reaches `AUTO_DEBUG_TRIGGER_THRESHOLD` (= 2).
//! * [`TelemetryWatcher::get_24h_summary`] — pure decision logic that filters
//!   events to the last 24 hours, aggregates by category, and writes the
//!   daily report. The cutoff uses the injected clock.
//! * [`TelemetryWatcher::is_high_censorship_hours`] /
//!   [`TelemetryWatcher::get_censorship_intensity`] — pure IRST-hour
//!   classifiers; the `_with(now)` variants accept an explicit timestamp so
//!   tests can run deterministically.
//! * [`TelemetryWatcher::parse_ts`] — mirror of Python's `_parse_ts` static
//!   method. Returns a sentinel `DateTime<Utc>` (year 1) on parse failure
//!   (matching Python's `datetime.min.replace(tzinfo=UTC)`).
//!
//! The Python original integrates with `monitoring.structured_logger` for
//! silent-failure recording and with `auto_debug_system.AutoDebugSystem`,
//! `iran_smart_anti_filter.IranSmartAntiFilter`, and `urllib.request` for
//! side-effectful diagnostics. Those integrations are exposed as injectable
//! hooks in this Rust port; the default hooks are no-ops that match the
//! Python "module not available" / "no proxy configured" fallthrough paths.
//! See `MIGRATION_NOTES.md` for the full list of flagged side effects.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeDelta, TimeZone, Timelike, Utc};
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration constants (mirror `telemetry_watcher.py`)
// ─────────────────────────────────────────────────────────────────────────────

/// Consecutive model-resolution failures required to trigger auto-debug.
/// Mirrors `AUTO_DEBUG_TRIGGER_THRESHOLD = 2` in the Python original.
pub const AUTO_DEBUG_TRIGGER_THRESHOLD: i64 = 2;

/// IRST high-censorship window start hour (18:00 IRST).
pub const HIGH_CENSORSHIP_START: u32 = 18;

/// IRST high-censorship window end hour (01:00 IRST, exclusive).
pub const HIGH_CENSORSHIP_END: u32 = 1;

/// Monitor log rotation threshold (10 MB), mirroring the Python `10 * 1024 * 1024`.
pub const LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;

/// Number of recent events of each type retained in the persisted state file.
pub const STATE_EVENT_RETENTION: usize = 100;

/// Iran Standard Time offset (UTC+3:30).
pub fn irst_offset() -> TimeDelta {
    TimeDelta::hours(3) + TimeDelta::minutes(30)
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failures raised by the Rust `telemetry_watcher.py` parity port.
///
/// All public methods return `Result<T, TelemetryError>`; the Python
/// original swallows these via `try/except: pass`, which Rust callers can
/// replicate with `.ok()` or `let _ = ...`.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// `telemetry_state.json` exists but could not be read.
    #[error("failed to read telemetry state from {path}: {source}")]
    ReadState {
        path: PathBuf,
        source: std::io::Error,
    },
    /// `telemetry_state.json` exists but is not valid JSON.
    #[error("failed to parse telemetry state from {path}: {source}")]
    ParseState {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// Writing the state file failed.
    #[error("failed to save telemetry state to {path}: {source}")]
    SaveState {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Appending to `monitor.log` failed.
    #[error("failed to write monitor log at {path}: {source}")]
    WriteMonitorLog {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Writing the daily report failed.
    #[error("failed to save daily report to {path}: {source}")]
    SaveDailyReport {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Creating the parent directory for a state/log/report file failed.
    #[error("failed to create parent directory for {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A monitor-log rotation step failed.
    #[error("failed to rotate monitor log at {path}: {source}")]
    RotateLog {
        path: PathBuf,
        source: std::io::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Data classes (mirror `DPIEvent`, `SlotEvent`, `SelfHealEvent`, `DailyAggregation`)
// ─────────────────────────────────────────────────────────────────────────────

/// A single DPI detection/evasion event. Mirror of Python's `DPIEvent` dataclass.
#[derive(Debug, Clone, PartialEq)]
pub struct DPIEvent {
    /// ISO-8601 timestamp captured when the event was logged.
    pub timestamp: String,
    /// DPI system that produced the event (e.g. "sni_inspector").
    pub dpi_system: String,
    /// Action taken: "blocked", "detected", "evaded", or "camouflaged".
    pub action: String,
    /// Free-form event details (JSON object).
    pub details: Value,
    /// Evasion technique used (empty if none).
    pub evasion_used: String,
    /// Whether the evasion succeeded.
    pub success: bool,
}

impl DPIEvent {
    /// Construct a `DPIEvent` mirroring the Python dataclass defaults
    /// (`details=dict()`, `evasion_used=""`, `success=True`).
    pub fn new(
        timestamp: impl Into<String>,
        dpi_system: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: timestamp.into(),
            dpi_system: dpi_system.into(),
            action: action.into(),
            details: json!({}),
            evasion_used: String::new(),
            success: true,
        }
    }

    /// Serialize to a JSON object matching the Python `asdict(DPIEvent(...))` shape.
    pub fn to_json(&self) -> Value {
        json!({
            "timestamp": self.timestamp,
            "dpi_system": self.dpi_system,
            "action": self.action,
            "details": self.details.clone(),
            "evasion_used": self.evasion_used,
            "success": self.success,
        })
    }

    /// Parse from a JSON value (mirrors Python's `DPIEvent(**e_data)`).
    pub fn from_json(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        Some(Self {
            timestamp: obj.get("timestamp")?.as_str()?.to_string(),
            dpi_system: obj.get("dpi_system")?.as_str()?.to_string(),
            action: obj.get("action")?.as_str()?.to_string(),
            details: obj.get("details").cloned().unwrap_or(json!({})),
            evasion_used: obj
                .get("evasion_used")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            success: obj.get("success").and_then(Value::as_bool).unwrap_or(true),
        })
    }
}

/// A slot failure/recovery event. Mirror of Python's `SlotEvent` dataclass.
#[derive(Debug, Clone, PartialEq)]
pub struct SlotEvent {
    pub timestamp: String,
    pub slot_index: i32,
    pub env_var: String,
    pub error_type: String,
    pub error_detail: String,
    pub recovered: bool,
    pub recovery_method: String,
}

impl SlotEvent {
    /// Construct a `SlotEvent` mirroring the Python dataclass defaults
    /// (`error_detail=""`, `recovered=False`, `recovery_method=""`).
    pub fn new(
        timestamp: impl Into<String>,
        slot_index: i32,
        env_var: impl Into<String>,
        error_type: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: timestamp.into(),
            slot_index,
            env_var: env_var.into(),
            error_type: error_type.into(),
            error_detail: String::new(),
            recovered: false,
            recovery_method: String::new(),
        }
    }

    /// Serialize to a JSON object matching the Python `asdict(SlotEvent(...))` shape.
    pub fn to_json(&self) -> Value {
        json!({
            "timestamp": self.timestamp,
            "slot_index": self.slot_index,
            "env_var": self.env_var,
            "error_type": self.error_type,
            "error_detail": self.error_detail,
            "recovered": self.recovered,
            "recovery_method": self.recovery_method,
        })
    }

    /// Parse from a JSON value (mirrors Python's `SlotEvent(**e_data)`).
    pub fn from_json(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        Some(Self {
            timestamp: obj.get("timestamp")?.as_str()?.to_string(),
            slot_index: obj.get("slot_index")?.as_i64()? as i32,
            env_var: obj.get("env_var")?.as_str()?.to_string(),
            error_type: obj.get("error_type")?.as_str()?.to_string(),
            error_detail: obj
                .get("error_detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            recovered: obj
                .get("recovered")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            recovery_method: obj
                .get("recovery_method")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }
}

/// A self-healing event. Mirror of Python's `SelfHealEvent` dataclass.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfHealEvent {
    pub timestamp: String,
    pub action_type: String,
    pub details: Value,
    pub success: bool,
    pub recovery_time_ms: f64,
}

impl SelfHealEvent {
    /// Construct a `SelfHealEvent` mirroring the Python dataclass defaults
    /// (`details=dict()`, `success=True`, `recovery_time_ms=0.0`).
    pub fn new(timestamp: impl Into<String>, action_type: impl Into<String>) -> Self {
        Self {
            timestamp: timestamp.into(),
            action_type: action_type.into(),
            details: json!({}),
            success: true,
            recovery_time_ms: 0.0,
        }
    }

    /// Serialize to a JSON object matching the Python `asdict(SelfHealEvent(...))` shape.
    pub fn to_json(&self) -> Value {
        json!({
            "timestamp": self.timestamp,
            "action_type": self.action_type,
            "details": self.details.clone(),
            "success": self.success,
            "recovery_time_ms": self.recovery_time_ms,
        })
    }

    /// Parse from a JSON value (mirrors Python's `SelfHealEvent(**e_data)`).
    pub fn from_json(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        Some(Self {
            timestamp: obj.get("timestamp")?.as_str()?.to_string(),
            action_type: obj.get("action_type")?.as_str()?.to_string(),
            details: obj.get("details").cloned().unwrap_or(json!({})),
            success: obj.get("success").and_then(Value::as_bool).unwrap_or(true),
            recovery_time_ms: obj
                .get("recovery_time_ms")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
        })
    }
}

/// 24-hour aggregated telemetry report. Mirror of Python's `DailyAggregation` dataclass.
#[derive(Debug, Clone, PartialEq)]
pub struct DailyAggregation {
    pub date: String,
    pub total_dpi_events: i64,
    pub dpi_events_blocked: i64,
    pub dpi_events_evaded: i64,
    pub dpi_events_by_system: BTreeMap<String, i64>,
    pub total_slot_failures: i64,
    pub slots_poisoned: Vec<i32>,
    pub slots_recovered: Vec<i32>,
    pub total_self_heal_events: i64,
    pub self_heal_by_type: BTreeMap<String, i64>,
    pub failures_recovered: i64,
    pub model_resolution_failures: i64,
    pub auto_debug_triggered: i64,
    pub peak_censorship_hour_irst: String,
    pub evasion_success_rate: f64,
    pub uptime_percentage: f64,
}

impl DailyAggregation {
    /// Construct an empty aggregation with the given date string.
    /// Mirrors the Python `DailyAggregation(date=today_str)` default-constructed
    /// instance used as the fallback in `get_24h_summary`'s outer `except`.
    pub fn empty(date: impl Into<String>) -> Self {
        Self {
            date: date.into(),
            total_dpi_events: 0,
            dpi_events_blocked: 0,
            dpi_events_evaded: 0,
            dpi_events_by_system: BTreeMap::new(),
            total_slot_failures: 0,
            slots_poisoned: Vec::new(),
            slots_recovered: Vec::new(),
            total_self_heal_events: 0,
            self_heal_by_type: BTreeMap::new(),
            failures_recovered: 0,
            model_resolution_failures: 0,
            auto_debug_triggered: 0,
            peak_censorship_hour_irst: String::new(),
            evasion_success_rate: 0.0,
            uptime_percentage: 100.0,
        }
    }

    /// Serialize to a JSON object matching the Python `asdict(DailyAggregation(...))` shape.
    pub fn to_json(&self) -> Value {
        let dpi_by_system: Value = Value::Object(
            self.dpi_events_by_system
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(*v)))
                .collect(),
        );
        let heal_by_type: Value = Value::Object(
            self.self_heal_by_type
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(*v)))
                .collect(),
        );
        json!({
            "date": self.date,
            "total_dpi_events": self.total_dpi_events,
            "dpi_events_blocked": self.dpi_events_blocked,
            "dpi_events_evaded": self.dpi_events_evaded,
            "dpi_events_by_system": dpi_by_system,
            "total_slot_failures": self.total_slot_failures,
            "slots_poisoned": self.slots_poisoned,
            "slots_recovered": self.slots_recovered,
            "total_self_heal_events": self.total_self_heal_events,
            "self_heal_by_type": heal_by_type,
            "failures_recovered": self.failures_recovered,
            "model_resolution_failures": self.model_resolution_failures,
            "auto_debug_triggered": self.auto_debug_triggered,
            "peak_censorship_hour_irst": self.peak_censorship_hour_irst,
            "evasion_success_rate": self.evasion_success_rate,
            "uptime_percentage": self.uptime_percentage,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable hooks
// ─────────────────────────────────────────────────────────────────────────────

/// Injectable clock returning the current UTC time. Defaults to `chrono::Utc::now`.
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Environment-variable map (mirror of Python's `os.environ` lookup).
pub type EnvMap = BTreeMap<String, String>;

/// Default clock using `chrono::Utc::now()`.
pub fn default_clock() -> Clock {
    Arc::new(Utc::now)
}

/// Outcome returned by the auto-debug hook. Mirrors the fields the Python
/// `_trigger_auto_debug` extracts from `AutoDebugSystem.run_full_diagnosis()`
/// and `auto_fix_all()`.
///
/// * `errors` — `report["summary"]["errors"]`
/// * `warnings` — `report["summary"]["warnings"]`
/// * `fixes_dict_keys` — `len(fixed)` where `fixed = ads.auto_fix_all()`.
///   The Python `auto_fix_all()` always returns a 5-key dict, so this defaults
///   to 5 to match the Python `{"errors_fixed": len(fixed)}` self-heal event.
#[derive(Debug, Clone, Default)]
pub struct AutoDebugReport {
    pub errors: i64,
    pub warnings: i64,
    pub fixes_dict_keys: usize,
}

impl AutoDebugReport {
    /// Construct a report mirroring Python's `auto_fix_all()` return value
    /// (5 dict keys: `original_issues`, `fixes_applied`, `remaining_issues`,
    /// `fixes`, `verification`).
    pub fn from_auto_fix_all(errors: i64, warnings: i64) -> Self {
        Self {
            errors,
            warnings,
            fixes_dict_keys: 5,
        }
    }
}

/// Hook invoked by [`TelemetryWatcher::trigger_auto_debug`]. Returning `None`
/// mirrors the Python `ImportError` path ("auto_debug_system not available").
/// Returning `Some(report)` mirrors a successful diagnosis.
pub type AutoDebugHook = Arc<dyn Fn() -> Option<AutoDebugReport> + Send + Sync>;

/// Outcome returned by the proxy-health hook. `healthy=true` mirrors the
/// Python path where `opener.open(req, timeout=5)` succeeds; `healthy=false`
/// mirrors the `except Exception as e` path.
#[derive(Debug, Clone, Default)]
pub struct ProxyCheckOutcome {
    pub healthy: bool,
    pub error: String,
}

/// Hook invoked by [`TelemetryWatcher::check_proxy_health`] when proxy env
/// vars are set. The default hook returns `healthy=true` (the Rust port does
/// not make real HTTP requests; see `MIGRATION_NOTES.md`).
pub type ProxyCheckHook = Arc<dyn Fn(&str) -> ProxyCheckOutcome + Send + Sync>;

/// Outcome returned by the NIN/DPI check hook. Mirrors the fields the Python
/// `_check_nin_dpi_state` extracts from `IranSmartAntiFilter().get_status()`.
#[derive(Debug, Clone, Default)]
pub struct NinDpiOutcome {
    pub censorship_level: i64,
    pub nin_active: bool,
}

/// Hook invoked by [`TelemetryWatcher::check_nin_dpi_state`]. Returning `None`
/// mirrors the Python `ImportError` path ("Module not available").
pub type NinDpiCheckHook = Arc<dyn Fn() -> Option<NinDpiOutcome> + Send + Sync>;

fn default_auto_debug_hook() -> AutoDebugHook {
    // Mirrors Python's `ImportError` fallthrough: AutoDebugSystem not available.
    Arc::new(|| None)
}

fn default_proxy_check_hook() -> ProxyCheckHook {
    // The Rust port does not perform real HTTP requests. Default to "healthy"
    // to match the Python success path; callers needing the unhealthy path
    // should inject a custom hook. See MIGRATION_NOTES.md.
    Arc::new(|_proxy_url| ProxyCheckOutcome {
        healthy: true,
        error: String::new(),
    })
}

fn default_nin_dpi_check_hook() -> NinDpiCheckHook {
    // Mirrors Python's `ImportError` fallthrough: module not available.
    Arc::new(|| None)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────────────────

struct TelemetryState {
    dpi_events: Vec<DPIEvent>,
    slot_events: Vec<SlotEvent>,
    self_heal_events: Vec<SelfHealEvent>,
    consecutive_model_failures: i64,
    start_time: f64,
    #[allow(dead_code)]
    last_report_time: f64,
    total_requests: i64,
    successful_requests: i64,
    counters: BTreeMap<String, i64>,
}

impl TelemetryState {
    fn new(now_epoch: f64) -> Self {
        Self {
            dpi_events: Vec::new(),
            slot_events: Vec::new(),
            self_heal_events: Vec::new(),
            consecutive_model_failures: 0,
            start_time: now_epoch,
            last_report_time: now_epoch,
            total_requests: 0,
            successful_requests: 0,
            counters: BTreeMap::new(),
        }
    }

    fn counter(&self, key: &str) -> i64 {
        self.counters.get(key).copied().unwrap_or(0)
    }

    fn bump(&mut self, key: &str, delta: i64) {
        *self.counters.entry(key.to_string()).or_insert(0) += delta;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TelemetryWatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Centralized, fail-safe telemetry system. Mirror of Python's `TelemetryWatcher`.
///
/// All I/O is wrapped in `Result`; the Python original swallows errors via
/// `try/except: pass`. Rust callers can replicate the Python "ZERO CRASH"
/// behavior with `.ok()` or `let _ = ...`.
///
/// Shared state is protected by an internal `Mutex`. [`TelemetryWatcher`]
/// itself is cheaply clonable (it wraps an `Arc<Inner>`); all clones share
/// the same state. This mirrors the Python singleton's `threading.Lock`
/// semantics without requiring callers to hold an external lock.
#[derive(Clone)]
pub struct TelemetryWatcher {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<TelemetryState>,
    monitor_log_path: PathBuf,
    state_path: PathBuf,
    daily_report_path: PathBuf,
    clock: Clock,
    env: EnvMap,
    auto_debug_hook: AutoDebugHook,
    proxy_check_hook: ProxyCheckHook,
    nin_dpi_check_hook: NinDpiCheckHook,
}

impl std::fmt::Debug for TelemetryWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryWatcher")
            .field("monitor_log_path", &self.inner.monitor_log_path)
            .field("state_path", &self.inner.state_path)
            .field("daily_report_path", &self.inner.daily_report_path)
            .field("clock", &"<clock closure>")
            .field("env_keys", &self.inner.env.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl TelemetryWatcher {
    /// Strict constructor: returns [`TelemetryError`] if the state file
    /// exists but cannot be read or parsed. Returns an empty state if the
    /// file does not exist (mirrors Python's `Path.exists()` short-circuit).
    ///
    /// Uses the default clock (`chrono::Utc::now`), an empty env map, and
    /// the default no-op hooks. Use [`TelemetryWatcher::new_with`] for full
    /// injectability.
    pub fn new(
        monitor_log_path: &Path,
        state_path: &Path,
        daily_report_path: &Path,
    ) -> Result<Self, TelemetryError> {
        Self::new_with(
            monitor_log_path,
            state_path,
            daily_report_path,
            default_clock(),
            EnvMap::new(),
            default_auto_debug_hook(),
            default_proxy_check_hook(),
            default_nin_dpi_check_hook(),
        )
    }

    /// Full-construction constructor with injectable clock, env, and hooks.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with(
        monitor_log_path: &Path,
        state_path: &Path,
        daily_report_path: &Path,
        clock: Clock,
        env: EnvMap,
        auto_debug_hook: AutoDebugHook,
        proxy_check_hook: ProxyCheckHook,
        nin_dpi_check_hook: NinDpiCheckHook,
    ) -> Result<Self, TelemetryError> {
        let now_epoch = clock_to_epoch_secs(&clock);
        let mut state = TelemetryState::new(now_epoch);
        // Load persisted state (mirrors Python's `_load_state` called from `__init__`).
        Self::load_state_into(&mut state, state_path)?;
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(state),
                monitor_log_path: monitor_log_path.to_path_buf(),
                state_path: state_path.to_path_buf(),
                daily_report_path: daily_report_path.to_path_buf(),
                clock,
                env,
                auto_debug_hook,
                proxy_check_hook,
                nin_dpi_check_hook,
            }),
        })
    }

    /// Lenient constructor: matches Python's swallow-and-continue behavior on
    /// state load failures. Logs the error to stderr (replacing the Python
    /// `record_silent_failure` + `log.warning` calls) and starts with empty
    /// state.
    #[allow(clippy::too_many_arguments)]
    pub fn new_lenient(
        monitor_log_path: &Path,
        state_path: &Path,
        daily_report_path: &Path,
        clock: Clock,
        env: EnvMap,
        auto_debug_hook: AutoDebugHook,
        proxy_check_hook: ProxyCheckHook,
        nin_dpi_check_hook: NinDpiCheckHook,
    ) -> Self {
        // Clone the Arc-based hooks up-front so the error branch can reuse
        // them after `new_with` consumes its own clones.
        let clock_for_err = Arc::clone(&clock);
        let env_for_err = env.clone();
        let auto_debug_hook_for_err = Arc::clone(&auto_debug_hook);
        let proxy_check_hook_for_err = Arc::clone(&proxy_check_hook);
        let nin_dpi_check_hook_for_err = Arc::clone(&nin_dpi_check_hook);
        match Self::new_with(
            monitor_log_path,
            state_path,
            daily_report_path,
            clock,
            env,
            auto_debug_hook,
            proxy_check_hook,
            nin_dpi_check_hook,
        ) {
            Ok(watcher) => watcher,
            Err(error) => {
                eprintln!("telemetry_watcher: cannot load state: {error}");
                let now_epoch = clock_to_epoch_secs(&clock_for_err);
                Self {
                    inner: Arc::new(Inner {
                        state: Mutex::new(TelemetryState::new(now_epoch)),
                        monitor_log_path: monitor_log_path.to_path_buf(),
                        state_path: state_path.to_path_buf(),
                        daily_report_path: daily_report_path.to_path_buf(),
                        clock: clock_for_err,
                        env: env_for_err,
                        auto_debug_hook: auto_debug_hook_for_err,
                        proxy_check_hook: proxy_check_hook_for_err,
                        nin_dpi_check_hook: nin_dpi_check_hook_for_err,
                    }),
                }
            }
        }
    }

    // ── Core Logging Methods ───────────────────────────────────────────────

    /// Log a DPI detection/evasion event. Mirror of Python's `log_dpi_event`.
    ///
    /// Updates the in-memory event list and counters under the mutex, then
    /// attempts to write to `monitor.log` and persist state. I/O failures
    /// are returned via `Result` but the in-memory state is always updated
    /// (matching the Python "state mutation happens before I/O" ordering).
    pub fn log_dpi_event(
        &self,
        dpi_system: &str,
        action: &str,
        details: Option<&Value>,
        evasion_used: &str,
        success: bool,
    ) -> Result<(), TelemetryError> {
        let event = DPIEvent {
            timestamp: format_iso(&(self.inner.clock)()),
            dpi_system: dpi_system.to_string(),
            action: action.to_string(),
            details: details.cloned().unwrap_or(json!({})),
            evasion_used: evasion_used.to_string(),
            success,
        };

        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            state.dpi_events.push(event.clone());
            state.bump("dpi_total", 1);
            match action {
                "blocked" => state.bump("dpi_blocked", 1),
                "evaded" => state.bump("dpi_evaded", 1),
                "camouflaged" => state.bump("dpi_camouflaged", 1),
                _ => {}
            }
            let sys_key = format!("dpi_sys_{dpi_system}");
            state.bump(&sys_key, 1);
        }

        let _ = self.write_monitor_log(&format!(
            "DPI_EVENT | {dpi_system} | {action} | evasion={evasion_used} | success={success}"
        ));
        let _ = self.persist_state();
        Ok(())
    }

    /// Log a slot failure event. Mirror of Python's `log_slot_failure`.
    pub fn log_slot_failure(
        &self,
        slot_index: i32,
        env_var: &str,
        error_type: &str,
        error_detail: &str,
    ) -> Result<(), TelemetryError> {
        let event = SlotEvent {
            timestamp: format_iso(&(self.inner.clock)()),
            slot_index,
            env_var: env_var.to_string(),
            error_type: error_type.to_string(),
            error_detail: error_detail.to_string(),
            recovered: false,
            recovery_method: String::new(),
        };

        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            state.slot_events.push(event.clone());
            state.bump("slot_failures", 1);
            let slot_key = format!("slot_{slot_index}_failures");
            state.bump(&slot_key, 1);
        }

        let _ = self.write_monitor_log(&format!(
            "SLOT_FAILURE | Slot {slot_index} | {env_var} | {error_type} | {error_detail}"
        ));
        let _ = self.persist_state();
        Ok(())
    }

    /// Log a slot recovery event. Mirror of Python's `log_slot_recovery`.
    pub fn log_slot_recovery(
        &self,
        slot_index: i32,
        env_var: &str,
        recovery_method: &str,
    ) -> Result<(), TelemetryError> {
        let event = SlotEvent {
            timestamp: format_iso(&(self.inner.clock)()),
            slot_index,
            env_var: env_var.to_string(),
            error_type: "recovered".to_string(),
            error_detail: String::new(),
            recovered: true,
            recovery_method: recovery_method.to_string(),
        };

        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            state.slot_events.push(event.clone());
            state.bump("slot_recoveries", 1);
        }

        let _ = self.write_monitor_log(&format!(
            "SLOT_RECOVERY | Slot {slot_index} | {env_var} | method={recovery_method}"
        ));
        let _ = self.persist_state();
        Ok(())
    }

    /// Log a self-healing event. Mirror of Python's `log_self_heal`.
    pub fn log_self_heal(
        &self,
        action_type: &str,
        details: Option<&Value>,
        success: bool,
        recovery_time_ms: f64,
    ) -> Result<(), TelemetryError> {
        let event = SelfHealEvent {
            timestamp: format_iso(&(self.inner.clock)()),
            action_type: action_type.to_string(),
            details: details.cloned().unwrap_or(json!({})),
            success,
            recovery_time_ms,
        };

        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            state.self_heal_events.push(event.clone());
            state.bump("self_heal_total", 1);
            let heal_key = format!("self_heal_{action_type}");
            state.bump(&heal_key, 1);
            if success {
                state.bump("failures_recovered", 1);
            }
        }

        let _ = self.write_monitor_log(&format!(
            "SELF_HEAL | {action_type} | success={success} | recovery_time={:.1}ms",
            recovery_time_ms
        ));
        let _ = self.persist_state();
        Ok(())
    }

    /// Track a model resolution failure. Mirror of Python's `log_model_resolution_failure`.
    ///
    /// Increments the consecutive failure counter and triggers auto-debug
    /// when the counter reaches `AUTO_DEBUG_TRIGGER_THRESHOLD` (= 2).
    /// Returns `true` if auto-debug was triggered (matching the Python
    /// `if self._consecutive_model_failures >= AUTO_DEBUG_TRIGGER_THRESHOLD`
    /// branch).
    pub fn log_model_resolution_failure(&self) -> Result<bool, TelemetryError> {
        // Capture the consecutive count under the lock, then release the lock
        // before writing the monitor log. The Python original holds a single
        // `threading.Lock` for both state mutations and log writes, but
        // Python's lock is non-reentrant — the original Python code paths
        // that combine the two operations do NOT nest lock acquisition. The
        // Rust port uses `std::sync::Mutex` which is also non-reentrant, so
        // we must avoid taking the same lock twice. Releasing here before
        // `write_monitor_log` preserves the same observable ordering (counter
        // is incremented, then log line is written) without deadlocking.
        let (consec, triggered) = {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            state.consecutive_model_failures += 1;
            state.bump("model_resolution_failures", 1);
            let consec = state.consecutive_model_failures;
            (consec, consec >= AUTO_DEBUG_TRIGGER_THRESHOLD)
        };
        let _ = self.write_monitor_log(&format!("MODEL_FAILURE | consecutive={consec}"));
        if triggered {
            let _ = self.trigger_auto_debug();
        }
        Ok(triggered)
    }

    /// Reset the consecutive model failure counter on success. Mirror of
    /// Python's `log_model_resolution_success`.
    pub fn log_model_resolution_success(&self) -> Result<(), TelemetryError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        state.consecutive_model_failures = 0;
        Ok(())
    }

    /// Track overall request success/failure for uptime calculation. Mirror
    /// of Python's `log_request`.
    pub fn log_request(&self, success: bool) -> Result<(), TelemetryError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        state.total_requests += 1;
        if success {
            state.successful_requests += 1;
        }
        Ok(())
    }

    // ── 24-Hour Aggregation ─────────────────────────────────────────────────

    /// Generate a 24-hour aggregated telemetry report. Mirror of Python's
    /// `get_24h_summary`.
    ///
    /// Filters events to the last 24 hours based on the injected clock,
    /// aggregates by category, writes the daily report, and returns the
    /// aggregation. On error, returns an empty `DailyAggregation` (matching
    /// the Python outer `except` fallback).
    pub fn get_24h_summary(&self) -> Result<DailyAggregation, TelemetryError> {
        let now = (self.inner.clock)();
        let cutoff = now - TimeDelta::hours(24);
        let today_str = now.format("%Y-%m-%d").to_string();

        let (
            recent_dpi,
            recent_slots,
            recent_heals,
            model_failures,
            auto_debug_triggered,
            total_requests,
            successful_requests,
        ) = {
            let state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            let recent_dpi: Vec<DPIEvent> = state
                .dpi_events
                .iter()
                .filter(|e| parse_ts(&e.timestamp) > cutoff)
                .cloned()
                .collect();
            let recent_slots: Vec<SlotEvent> = state
                .slot_events
                .iter()
                .filter(|e| parse_ts(&e.timestamp) > cutoff)
                .cloned()
                .collect();
            let recent_heals: Vec<SelfHealEvent> = state
                .self_heal_events
                .iter()
                .filter(|e| parse_ts(&e.timestamp) > cutoff)
                .cloned()
                .collect();
            (
                recent_dpi,
                recent_slots,
                recent_heals,
                state.counter("model_resolution_failures"),
                state.counter("auto_debug_triggered"),
                state.total_requests,
                state.successful_requests,
            )
        };

        // DPI aggregation
        let dpi_blocked = recent_dpi.iter().filter(|e| e.action == "blocked").count() as i64;
        let dpi_evaded = recent_dpi
            .iter()
            .filter(|e| e.action == "evaded" || e.action == "camouflaged")
            .count() as i64;
        let mut dpi_by_system: BTreeMap<String, i64> = BTreeMap::new();
        for e in &recent_dpi {
            *dpi_by_system.entry(e.dpi_system.clone()).or_insert(0) += 1;
        }

        // Peak censorship hour (based on DPI event density by IRST hour).
        // Insertion-order-preserving accumulation so the "first wins on ties"
        // behavior matches Python's `max(hour_counts, key=hour_counts.get)`
        // over a `defaultdict(int)` (Python 3.7+ preserves insertion order).
        let mut hour_counts: Vec<(i32, i64)> = Vec::new();
        for e in &recent_dpi {
            let dt = parse_ts(&e.timestamp);
            let iran_hour = (dt + irst_offset()).hour() as i32;
            if let Some((_, count)) = hour_counts.iter_mut().find(|(h, _)| *h == iran_hour) {
                *count += 1;
            } else {
                hour_counts.push((iran_hour, 1));
            }
        }
        let peak_hour = max_by_value_first_wins(&hour_counts)
            .map(|h| format!("{h:02}:00 IRST"))
            .unwrap_or_default();

        // Slot aggregation
        let mut poisoned_set: BTreeSet<i32> = BTreeSet::new();
        let mut recovered_set: BTreeSet<i32> = BTreeSet::new();
        for e in &recent_slots {
            if !e.recovered {
                poisoned_set.insert(e.slot_index);
            } else {
                recovered_set.insert(e.slot_index);
            }
        }
        let poisoned_slots: Vec<i32> = poisoned_set.into_iter().collect();
        let recovered_slots: Vec<i32> = recovered_set.into_iter().collect();

        // Self-heal aggregation
        let mut heal_by_type: BTreeMap<String, i64> = BTreeMap::new();
        for e in &recent_heals {
            *heal_by_type.entry(e.action_type.clone()).or_insert(0) += 1;
        }
        let failures_recovered = recent_heals.iter().filter(|e| e.success).count() as i64;

        // Evasion success rate
        let total_evasion_attempts = dpi_blocked + dpi_evaded;
        let evasion_rate = if total_evasion_attempts > 0 {
            dpi_evaded as f64 / total_evasion_attempts as f64
        } else {
            1.0
        };

        // Uptime
        let uptime = if total_requests > 0 {
            successful_requests as f64 / total_requests as f64 * 100.0
        } else {
            100.0
        };

        let aggregation = DailyAggregation {
            date: today_str,
            total_dpi_events: recent_dpi.len() as i64,
            dpi_events_blocked: dpi_blocked,
            dpi_events_evaded: dpi_evaded,
            dpi_events_by_system: dpi_by_system,
            total_slot_failures: recent_slots.len() as i64,
            slots_poisoned: poisoned_slots,
            slots_recovered: recovered_slots,
            total_self_heal_events: recent_heals.len() as i64,
            self_heal_by_type: heal_by_type,
            failures_recovered,
            model_resolution_failures: model_failures,
            auto_debug_triggered,
            peak_censorship_hour_irst: peak_hour,
            evasion_success_rate: round_to(evasion_rate, 4),
            uptime_percentage: round_to(uptime, 2),
        };

        // Persist daily report (fail-safe: swallow write errors to match Python).
        let _ = self.save_daily_report(&aggregation);

        Ok(aggregation)
    }

    fn save_daily_report(&self, aggregation: &DailyAggregation) -> Result<(), TelemetryError> {
        let report_data = aggregation.to_json();
        let serialized = serde_json::to_string_pretty(&report_data).map_err(|_| {
            TelemetryError::SaveDailyReport {
                path: self.inner.daily_report_path.clone(),
                source: std::io::Error::other("serialize"),
            }
        })?;
        if let Some(parent) = self.inner.daily_report_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| TelemetryError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        fs::write(&self.inner.daily_report_path, serialized).map_err(|source| {
            TelemetryError::SaveDailyReport {
                path: self.inner.daily_report_path.clone(),
                source,
            }
        })?;
        Ok(())
    }

    // ── Auto-Debug Trigger ──────────────────────────────────────────────────

    /// Check if auto-debug should be triggered. Mirror of Python's `check_auto_debug`.
    ///
    /// Returns `true` if auto-debug was triggered (i.e. consecutive model
    /// failures >= threshold).
    pub fn check_auto_debug(&self) -> Result<bool, TelemetryError> {
        let consec = {
            let state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            state.consecutive_model_failures
        };
        if consec >= AUTO_DEBUG_TRIGGER_THRESHOLD {
            let _ = self.trigger_auto_debug();
            return Ok(true);
        }
        Ok(false)
    }

    /// Trigger deep self-diagnostic check. Mirror of Python's `_trigger_auto_debug`.
    ///
    /// Increments the `auto_debug_triggered` counter, writes a monitor-log
    /// marker, invokes the `auto_debug_hook` (default: no-op returning
    /// `None`, matching the Python `ImportError` path), then runs the
    /// env-var / proxy / NIN-DPI checks. Finally resets the consecutive
    /// failure counter.
    pub fn trigger_auto_debug(&self) -> Result<(), TelemetryError> {
        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            state.bump("auto_debug_triggered", 1);
        }
        let _ = self.write_monitor_log("AUTO_DEBUG_TRIGGERED | Starting deep self-diagnostic");

        // Run auto-debug system if available (default hook returns None).
        if let Some(report) = (self.inner.auto_debug_hook)() {
            if report.errors > 0 {
                let _ = self.write_monitor_log(&format!(
                    "AUTO_DEBUG_RESULT | errors={} | warnings={}",
                    report.errors, report.warnings
                ));
                // Attempt auto-fix (matches Python `if fixed:` — always true
                // because `auto_fix_all()` returns a 5-key dict).
                if report.fixes_dict_keys > 0 {
                    let details = json!({"errors_fixed": report.fixes_dict_keys});
                    let _ = self.log_self_heal("auto_debug_fix", Some(&details), true, 0.0);
                }
            } else {
                let _ = self.write_monitor_log("AUTO_DEBUG_RESULT | All checks passed");
            }
        } else {
            // Mirrors Python's `ImportError` fallthrough.
            let _ = self.write_monitor_log("AUTO_DEBUG_RESULT | auto_debug_system not available");
        }

        // Check environment variables (pure decision logic).
        let _ = self.check_env_vars();
        // Check proxy health (invokes injectable hook).
        let _ = self.check_proxy_health();
        // Check NIN/DPI state (invokes injectable hook).
        let _ = self.check_nin_dpi_state();

        // Reset counter after diagnostic (matches Python
        // `self._consecutive_model_failures = 0` at the end).
        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            state.consecutive_model_failures = 0;
        }
        Ok(())
    }

    /// Validate critical environment variables. Mirror of Python's `_check_env_vars`.
    ///
    /// Scans `CF_ACCOUNT_ID_i`, `CF_API_TOKEN_i`, `CF_AI_GATEWAY_URL_i`
    /// for `i` in `1..=11`. Writes monitor-log entries for the first 5
    /// missing or empty vars. Pure decision logic — no side effects beyond
    /// the monitor-log write.
    pub fn check_env_vars(&self) -> Result<(), TelemetryError> {
        let mut critical_vars: Vec<String> = Vec::new();
        for i in 1..=11 {
            critical_vars.push(format!("CF_ACCOUNT_ID_{i}"));
            critical_vars.push(format!("CF_API_TOKEN_{i}"));
            critical_vars.push(format!("CF_AI_GATEWAY_URL_{i}"));
        }

        let mut missing: Vec<String> = Vec::new();
        let mut empty: Vec<String> = Vec::new();
        for var in &critical_vars {
            match self.inner.env.get(var) {
                None => missing.push(var.clone()),
                Some(val) if val.trim().is_empty() => empty.push(var.clone()),
                _ => {}
            }
        }

        if !missing.is_empty() {
            let preview: Vec<String> = missing.iter().take(5).cloned().collect();
            let _ = self.write_monitor_log(&format!(
                "ENV_CHECK | Missing env vars: {}",
                preview.join(", ")
            ));
        }
        if !empty.is_empty() {
            let preview: Vec<String> = empty.iter().take(5).cloned().collect();
            let _ = self.write_monitor_log(&format!(
                "ENV_CHECK | Empty env vars: {} (total: {})",
                preview.join(", "),
                empty.len()
            ));
        }
        Ok(())
    }

    /// Check proxy connectivity if configured. Mirror of Python's `_check_proxy_health`.
    ///
    /// Reads `HTTP_PROXY` and `HTTPS_PROXY` from the injected env. If
    /// neither is set, the function is a no-op (matching Python). If at
    /// least one is set, invokes the `proxy_check_hook` (default: returns
    /// `healthy=true` since the Rust port does not make real HTTP requests).
    pub fn check_proxy_health(&self) -> Result<(), TelemetryError> {
        let http_proxy = self
            .inner
            .env
            .get("HTTP_PROXY")
            .cloned()
            .unwrap_or_default();
        let https_proxy = self
            .inner
            .env
            .get("HTTPS_PROXY")
            .cloned()
            .unwrap_or_default();
        if http_proxy.is_empty() && https_proxy.is_empty() {
            return Ok(());
        }
        let proxy_url = if !https_proxy.is_empty() {
            https_proxy
        } else {
            http_proxy
        };
        let outcome = (self.inner.proxy_check_hook)(&proxy_url);
        if outcome.healthy {
            let _ = self.write_monitor_log("PROXY_CHECK | Proxy healthy");
        } else {
            let _ = self
                .write_monitor_log(&format!("PROXY_CHECK | Proxy unhealthy: {}", outcome.error));
            let details = json!({"proxy": proxy_url, "error": outcome.error});
            let _ = self.log_self_heal("proxy_warning", Some(&details), false, 0.0);
        }
        Ok(())
    }

    /// Check current NIN/DPI state. Mirror of Python's `_check_nin_dpi_state`.
    ///
    /// Invokes the `nin_dpi_check_hook` (default: returns `None`, matching
    /// the Python `ImportError` path). When the hook returns `Some(outcome)`,
    /// writes a monitor-log entry and, if `nin_active` is true, logs a DPI
    /// event.
    pub fn check_nin_dpi_state(&self) -> Result<(), TelemetryError> {
        match (self.inner.nin_dpi_check_hook)() {
            None => {
                let _ = self.write_monitor_log("NIN_DPI_CHECK | Module not available");
            }
            Some(outcome) => {
                let _ = self.write_monitor_log(&format!(
                    "NIN_DPI_CHECK | Level={} | NIN={}",
                    outcome.censorship_level, outcome.nin_active
                ));
                if outcome.nin_active {
                    let details = json!({"censorship_level": outcome.censorship_level});
                    let _ = self.log_dpi_event(
                        "nin_internet_cut",
                        "detected",
                        Some(&details),
                        "",
                        true,
                    );
                }
            }
        }
        Ok(())
    }

    // ── IRST Time Utilities ─────────────────────────────────────────────────

    /// Get current Iran Standard Time (IRST). Mirror of Python's `get_iran_time`.
    pub fn get_iran_time(&self) -> DateTime<Utc> {
        (self.inner.clock)() + irst_offset()
    }

    /// Check if the given UTC time falls within IRST high-censorship hours
    /// (18:00 - 01:00). Pure variant of [`TelemetryWatcher::is_high_censorship_hours`]
    /// for deterministic testing.
    pub fn is_high_censorship_hours_with(now: DateTime<Utc>) -> bool {
        let iran_hour = (now + irst_offset()).hour();
        if (HIGH_CENSORSHIP_START..=23).contains(&iran_hour) {
            return true;
        }
        if iran_hour < HIGH_CENSORSHIP_END {
            return true;
        }
        false
    }

    /// Check if current IRST time is within high-censorship hours. Mirror
    /// of Python's `is_high_censorship_hours` static method.
    pub fn is_high_censorship_hours(&self) -> bool {
        Self::is_high_censorship_hours_with((self.inner.clock)())
    }

    /// Get current censorship intensity level for the given UTC time. Pure
    /// variant of [`TelemetryWatcher::get_censorship_intensity`] for
    /// deterministic testing.
    pub fn get_censorship_intensity_with(now: DateTime<Utc>) -> &'static str {
        let iran_hour = (now + irst_offset()).hour();
        // Peak hours: 20:00 - 23:00 IRST
        if (20..=23).contains(&iran_hour) {
            return "ultra_stealth";
        }
        // High censorship: 18:00 - 01:00 IRST
        if (18..=23).contains(&iran_hour) || iran_hour < 1 {
            return "high_stealth";
        }
        // Low censorship: 03:00 - 06:00 IRST
        if (3..=6).contains(&iran_hour) {
            return "relaxed";
        }
        "normal"
    }

    /// Get current censorship intensity level. Mirror of Python's
    /// `get_censorship_intensity` static method.
    pub fn get_censorship_intensity(&self) -> &'static str {
        Self::get_censorship_intensity_with((self.inner.clock)())
    }

    // ── Internal Helpers ────────────────────────────────────────────────────

    /// Write a message to `monitor.log`. Mirror of Python's `_write_monitor_log`.
    ///
    /// Appends a timestamped line to the monitor log. Rotates the log if
    /// it exceeds `LOG_ROTATE_BYTES` (10 MB). All errors are returned via
    /// `Result`; the Python original swallows them via `try/except: pass`.
    pub fn write_monitor_log(&self, message: &str) -> Result<(), TelemetryError> {
        let timestamp = (self.inner.clock)()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();
        let log_line = format!("[{timestamp}] {message}\n");

        // Append to the log file under the lock to match the Python
        // `with self._lock: with open(...) as f: f.write(...)` block.
        {
            let _state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            if let Some(parent) = self.inner.monitor_log_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|source| TelemetryError::CreateDir {
                        path: parent.to_path_buf(),
                        source,
                    })?;
                }
            }
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.inner.monitor_log_path)
                .map_err(|source| TelemetryError::WriteMonitorLog {
                    path: self.inner.monitor_log_path.clone(),
                    source,
                })?;
            file.write_all(log_line.as_bytes()).map_err(|source| {
                TelemetryError::WriteMonitorLog {
                    path: self.inner.monitor_log_path.clone(),
                    source,
                }
            })?;
        }

        // Rotate log if too large (> 10 MB). Matches the Python
        // `if MONITOR_LOG_PATH.stat().st_size > 10 * 1024 * 1024: self._rotate_log()`
        // check (swallowed in try/except).
        if let Ok(metadata) = fs::metadata(&self.inner.monitor_log_path) {
            if metadata.len() > LOG_ROTATE_BYTES {
                let _ = self.rotate_log();
            }
        }
        Ok(())
    }

    /// Rotate `monitor.log` when it exceeds the size limit. Mirror of
    /// Python's `_rotate_log`.
    pub fn rotate_log(&self) -> Result<(), TelemetryError> {
        let backup_path = self.inner.monitor_log_path.with_file_name("monitor.log.1");
        if backup_path.exists() {
            fs::remove_file(&backup_path).map_err(|source| TelemetryError::RotateLog {
                path: backup_path.clone(),
                source,
            })?;
        }
        fs::rename(&self.inner.monitor_log_path, &backup_path).map_err(|source| {
            TelemetryError::RotateLog {
                path: self.inner.monitor_log_path.clone(),
                source,
            }
        })?;
        let _ = self.write_monitor_log("LOG_ROTATION | monitor.log rotated");
        Ok(())
    }

    /// Persist telemetry state to disk for crash recovery. Mirror of Python's
    /// `_persist_state`.
    pub fn persist_state(&self) -> Result<(), TelemetryError> {
        let serialized = {
            let state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            let recent_dpi: Vec<Value> = state
                .dpi_events
                .iter()
                .rev()
                .take(STATE_EVENT_RETENTION)
                .map(|e| e.to_json())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let recent_slot: Vec<Value> = state
                .slot_events
                .iter()
                .rev()
                .take(STATE_EVENT_RETENTION)
                .map(|e| e.to_json())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let recent_heal: Vec<Value> = state
                .self_heal_events
                .iter()
                .rev()
                .take(STATE_EVENT_RETENTION)
                .map(|e| e.to_json())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let counters: Value = Value::Object(
                state
                    .counters
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::from(*v)))
                    .collect(),
            );
            json!({
                "last_updated": format_iso(&(self.inner.clock)()),
                "counters": counters,
                "consecutive_model_failures": state.consecutive_model_failures,
                "total_requests": state.total_requests,
                "successful_requests": state.successful_requests,
                "start_time": state.start_time,
                "recent_dpi_events": recent_dpi,
                "recent_slot_events": recent_slot,
                "recent_self_heal_events": recent_heal,
            })
        };
        let pretty =
            serde_json::to_string_pretty(&serialized).map_err(|_| TelemetryError::SaveState {
                path: self.inner.state_path.clone(),
                source: std::io::Error::other("serialize"),
            })?;
        if let Some(parent) = self.inner.state_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| TelemetryError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        fs::write(&self.inner.state_path, pretty).map_err(|source| TelemetryError::SaveState {
            path: self.inner.state_path.clone(),
            source,
        })?;
        Ok(())
    }

    fn load_state_into(
        state: &mut TelemetryState,
        state_path: &Path,
    ) -> Result<(), TelemetryError> {
        if !state_path.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(state_path).map_err(|source| TelemetryError::ReadState {
            path: state_path.to_path_buf(),
            source,
        })?;
        let value: Value =
            serde_json::from_str(&text).map_err(|source| TelemetryError::ParseState {
                path: state_path.to_path_buf(),
                source,
            })?;
        let obj = value
            .as_object()
            .ok_or_else(|| TelemetryError::ParseState {
                path: state_path.to_path_buf(),
                source: serde_json::from_str::<serde_json::Value>("0").unwrap_err(),
            })?;
        if let Some(counters) = obj.get("counters").and_then(Value::as_object) {
            for (k, v) in counters {
                if let Some(n) = v.as_i64() {
                    state.counters.insert(k.clone(), n);
                }
            }
        }
        state.consecutive_model_failures = obj
            .get("consecutive_model_failures")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        state.total_requests = obj
            .get("total_requests")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        state.successful_requests = obj
            .get("successful_requests")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if let Some(events) = obj.get("recent_dpi_events").and_then(Value::as_array) {
            for e in events {
                if let Some(parsed) = DPIEvent::from_json(e) {
                    state.dpi_events.push(parsed);
                }
            }
        }
        if let Some(events) = obj.get("recent_slot_events").and_then(Value::as_array) {
            for e in events {
                if let Some(parsed) = SlotEvent::from_json(e) {
                    state.slot_events.push(parsed);
                }
            }
        }
        if let Some(events) = obj.get("recent_self_heal_events").and_then(Value::as_array) {
            for e in events {
                if let Some(parsed) = SelfHealEvent::from_json(e) {
                    state.self_heal_events.push(parsed);
                }
            }
        }
        Ok(())
    }

    /// Get current telemetry status summary. Mirror of Python's `get_status`.
    pub fn get_status(&self) -> Result<Value, TelemetryError> {
        let (
            dpi_total,
            dpi_blocked,
            dpi_evaded,
            dpi_camouflaged,
            slot_failures,
            self_heal_total,
            failures_recovered,
            model_resolution_failures,
            consec,
            auto_debug_triggered,
            total_requests,
            successful_requests,
        ) = {
            let state = self
                .inner
                .state
                .lock()
                .expect("telemetry state mutex poisoned");
            (
                state.counter("dpi_total"),
                state.counter("dpi_blocked"),
                state.counter("dpi_evaded"),
                state.counter("dpi_camouflaged"),
                state.counter("slot_failures"),
                state.counter("self_heal_total"),
                state.counter("failures_recovered"),
                state.counter("model_resolution_failures"),
                state.consecutive_model_failures,
                state.counter("auto_debug_triggered"),
                state.total_requests,
                state.successful_requests,
            )
        };
        let iran_time_str = self.get_iran_time().format("%H:%M IRST").to_string();
        let is_high = self.is_high_censorship_hours();
        let intensity = self.get_censorship_intensity();
        let uptime = if total_requests > 0 {
            successful_requests as f64 / total_requests as f64 * 100.0
        } else {
            100.0
        };
        Ok(json!({
            "monitor_log_path": self.inner.monitor_log_path.to_string_lossy(),
            "total_dpi_events": dpi_total,
            "dpi_blocked": dpi_blocked,
            "dpi_evaded": dpi_evaded,
            "dpi_camouflaged": dpi_camouflaged,
            "total_slot_failures": slot_failures,
            "total_self_heal_events": self_heal_total,
            "failures_recovered": failures_recovered,
            "model_resolution_failures": model_resolution_failures,
            "consecutive_model_failures": consec,
            "auto_debug_triggered": auto_debug_triggered,
            "iran_time": iran_time_str,
            "is_high_censorship_hours": is_high,
            "censorship_intensity": intensity,
            "uptime_percentage": round_to(uptime, 2),
        }))
    }

    /// Get list of currently poisoned (failed) slot indices. Mirror of
    /// Python's `get_poisoned_slots`.
    pub fn get_poisoned_slots(&self) -> Result<Vec<i32>, TelemetryError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        // A slot is "poisoned" iff its most recent event is a failure (not a
        // recovery). Iterate events in order, tracking per-slot state; the
        // final state per slot determines membership in the poisoned set.
        // This matches the Python original's "currently failing" semantic.
        let mut latest_is_failure: BTreeMap<i32, bool> = BTreeMap::new();
        for e in &state.slot_events {
            latest_is_failure.insert(e.slot_index, !e.recovered);
        }
        let mut poisoned: BTreeSet<i32> = BTreeSet::new();
        for (slot, is_failure) in &latest_is_failure {
            if *is_failure {
                poisoned.insert(*slot);
            }
        }
        Ok(poisoned.into_iter().collect())
    }

    /// Get the current consecutive model failure counter. Used by parity tests
    /// and the CLI to mirror Python's `watcher._consecutive_model_failures` access.
    pub fn consecutive_model_failures(&self) -> i64 {
        let state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        state.consecutive_model_failures
    }

    /// Get the current value of a named counter, or 0 if absent. Used by
    /// parity tests to mirror Python's `watcher._counters.get(key, 0)`.
    pub fn counter(&self, key: &str) -> i64 {
        let state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        state.counter(key)
    }

    /// Get a snapshot of the current DPI events list. Used by parity tests
    /// to mirror Python's `watcher._dpi_events` direct access.
    pub fn dpi_events_snapshot(&self) -> Vec<DPIEvent> {
        let state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        state.dpi_events.clone()
    }

    /// Get a snapshot of the current slot events list. Used by parity tests
    /// to mirror Python's `watcher._slot_events` direct access.
    pub fn slot_events_snapshot(&self) -> Vec<SlotEvent> {
        let state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        state.slot_events.clone()
    }

    /// Get a snapshot of the current self-heal events list. Used by parity
    /// tests to mirror Python's `watcher._self_heal_events` direct access.
    pub fn self_heal_events_snapshot(&self) -> Vec<SelfHealEvent> {
        let state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        state.self_heal_events.clone()
    }

    /// Get a snapshot of the current counters map. Used by parity tests to
    /// mirror Python's `dict(watcher._counters)`.
    pub fn counters_snapshot(&self) -> BTreeMap<String, i64> {
        let state = self
            .inner
            .state
            .lock()
            .expect("telemetry state mutex poisoned");
        state.counters.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Module-level convenience functions (mirror `telemetry_watcher.py`)
// ─────────────────────────────────────────────────────────────────────────────

static SINGLETON: OnceLock<TelemetryWatcher> = OnceLock::new();

/// Get the singleton `TelemetryWatcher` instance. Mirror of Python's
/// `TelemetryWatcher.instance()` classmethod.
///
/// Uses default paths (`data/monitor.log`, `data/telemetry_state.json`,
/// `data/daily_telemetry_report.json`), the real clock, the real process
/// environment, and the default no-op hooks. Construction is fail-safe
/// (errors are logged to stderr and the singleton starts with empty state).
pub fn get_telemetry() -> TelemetryWatcher {
    SINGLETON
        .get_or_init(|| {
            let data_dir = PathBuf::from("data");
            TelemetryWatcher::new_lenient(
                &data_dir.join("monitor.log"),
                &data_dir.join("telemetry_state.json"),
                &data_dir.join("daily_telemetry_report.json"),
                default_clock(),
                std::env::vars().collect(),
                default_auto_debug_hook(),
                default_proxy_check_hook(),
                default_nin_dpi_check_hook(),
            )
        })
        .clone()
}

/// Module-level DPI event logging. Mirror of Python's `log_dpi_event` module function.
pub fn log_dpi_event(
    dpi_system: &str,
    action: &str,
    details: Option<&Value>,
    evasion_used: &str,
    success: bool,
) {
    let _ = get_telemetry().log_dpi_event(dpi_system, action, details, evasion_used, success);
}

/// Module-level slot failure logging. Mirror of Python's `log_slot_failure` module function.
pub fn log_slot_failure(slot_index: i32, env_var: &str, error_type: &str, error_detail: &str) {
    let _ = get_telemetry().log_slot_failure(slot_index, env_var, error_type, error_detail);
}

/// Module-level self-heal event logging. Mirror of Python's `log_self_heal` module function.
pub fn log_self_heal(
    action_type: &str,
    details: Option<&Value>,
    success: bool,
    recovery_time_ms: f64,
) {
    let _ = get_telemetry().log_self_heal(action_type, details, success, recovery_time_ms);
}

/// Generate and return the 24-hour telemetry report. Mirror of Python's
/// `generate_daily_report` module function.
pub fn generate_daily_report() -> DailyAggregation {
    match get_telemetry().get_24h_summary() {
        Ok(agg) => agg,
        Err(_) => DailyAggregation::empty(Utc::now().format("%Y-%m-%d").to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Format a `DateTime<Utc>` as an ISO-8601 string with microsecond precision
/// and a `+00:00` offset, matching Python's `datetime.now(UTC).isoformat()`.
fn format_iso(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string()
}

/// Convert a clock closure to epoch seconds as `f64` (parity with `time.time()`).
fn clock_to_epoch_secs(clock: &Clock) -> f64 {
    let now = clock();
    now.timestamp() as f64 + now.timestamp_subsec_nanos() as f64 / 1_000_000_000.0
}

/// Round an f64 to `decimals` decimal places, mirroring Python's `round(x, n)`
/// for finite floats. Uses round-half-away-from-zero which matches Python's
/// `round()` for the values produced by `get_24h_summary`.
fn round_to(x: f64, decimals: u32) -> f64 {
    let factor = 10f64.powi(decimals as i32);
    (x * factor).round() / factor
}

/// Return the first key with the maximum value, matching Python's
/// `max(d, key=d.get)` over an insertion-ordered dict (Python 3.7+).
/// Returns `None` for an empty slice.
fn max_by_value_first_wins(counts: &[(i32, i64)]) -> Option<i32> {
    let mut best: Option<(i32, i64)> = None;
    for &(hour, count) in counts {
        match best {
            None => best = Some((hour, count)),
            Some((_, bc)) if count > bc => best = Some((hour, count)),
            _ => {}
        }
    }
    best.map(|(h, _)| h)
}

/// Sentinel `DateTime<Utc>` representing Python's `datetime.min.replace(tzinfo=UTC)`
/// (= year 1, month 1, day 1, 00:00:00 UTC). Returned by [`parse_ts`] on
/// parse failure.
pub fn min_datetime_utc() -> DateTime<Utc> {
    let naive = NaiveDateTime::new(
        NaiveDate::from_ymd_opt(1, 1, 1).expect("year 1 is representable in chrono NaiveDate"),
        NaiveTime::from_hms_opt(0, 0, 0).expect("00:00:00 is representable"),
    );
    Utc.from_utc_datetime(&naive)
}

/// Replace a trailing `Z` with `+00:00` so chrono's strict ISO-8601 parser
/// accepts the same strings as Python's `datetime.fromisoformat`.
fn normalize_iso_z(input: &str) -> String {
    if let Some(stripped) = input.strip_suffix('Z') {
        let mut replacement = String::with_capacity(input.len() + 5);
        replacement.push_str(stripped);
        replacement.push_str("+00:00");
        replacement
    } else {
        input.to_string()
    }
}

/// Parse an ISO-8601 string into a UTC-aware datetime, returning the
/// [`min_datetime_utc`] sentinel on failure. Mirror of Python's `_parse_ts`.
///
/// - Naive timestamps are treated as UTC (Python: `parsed.replace(tzinfo=UTC)`).
/// - Aware timestamps are normalized to UTC (Python: `parsed.astimezone(UTC)`).
/// - Malformed input returns `min_datetime_utc()` (Python: `datetime.min.replace(tzinfo=UTC)`).
pub fn parse_ts(ts_str: &str) -> DateTime<Utc> {
    try_parse_ts(ts_str).unwrap_or_else(min_datetime_utc)
}

/// Parse an ISO-8601 string into a UTC-aware datetime, returning `None` on
/// failure. More idiomatic Rust variant of [`parse_ts`].
pub fn try_parse_ts(ts_str: &str) -> Option<DateTime<Utc>> {
    let normalized = normalize_iso_z(ts_str);
    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
        return Some(dt.with_timezone::<Utc>(&Utc));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&naive));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&naive));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixed_clock(iso: &str) -> Clock {
        let dt = DateTime::parse_from_rfc3339(iso)
            .expect("fixed_clock iso must parse")
            .with_timezone::<Utc>(&Utc);
        Arc::new(move || dt)
    }

    #[test]
    fn parse_ts_handles_naive_aware_and_invalid() {
        // Naive timestamp interpreted as UTC.
        let naive = parse_ts("2026-06-24T12:00:00");
        assert_eq!(naive.to_rfc3339(), "2026-06-24T12:00:00+00:00");
        // Aware with offset normalized to UTC.
        let aware = parse_ts("2026-06-24T15:30:00+03:30");
        assert_eq!(aware.to_rfc3339(), "2026-06-24T12:00:00+00:00");
        // Z suffix.
        let zed = parse_ts("2026-06-24T12:00:00Z");
        assert_eq!(zed.to_rfc3339(), "2026-06-24T12:00:00+00:00");
        // Invalid returns sentinel (year 1).
        let invalid = parse_ts("not-a-timestamp");
        assert_eq!(invalid, min_datetime_utc());
        // Empty returns sentinel.
        let empty = parse_ts("");
        assert_eq!(empty, min_datetime_utc());
    }

    #[test]
    fn is_high_censorship_hours_branches() {
        // 18:00-23:59 IRST → true
        for hour in 18..=23 {
            let utc = Utc.from_utc_datetime(
                &(NaiveDate::from_ymd_opt(2026, 6, 24)
                    .unwrap()
                    .and_hms_opt(hour, 0, 0)
                    .unwrap()
                    - irst_offset()),
            );
            assert!(
                TelemetryWatcher::is_high_censorship_hours_with(utc),
                "hour {hour} should be high-censorship"
            );
        }
        // 00:00 IRST → true (0 <= iran_hour < 1)
        let midnight_irst = Utc.from_utc_datetime(
            &(NaiveDate::from_ymd_opt(2026, 6, 24)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                - irst_offset()),
        );
        assert!(TelemetryWatcher::is_high_censorship_hours_with(
            midnight_irst
        ));
        // 01:00-17:00 IRST → false
        for hour in 1..=17 {
            let utc = Utc.from_utc_datetime(
                &(NaiveDate::from_ymd_opt(2026, 6, 24)
                    .unwrap()
                    .and_hms_opt(hour, 0, 0)
                    .unwrap()
                    - irst_offset()),
            );
            assert!(
                !TelemetryWatcher::is_high_censorship_hours_with(utc),
                "hour {hour} should NOT be high-censorship"
            );
        }
    }

    #[test]
    fn get_censorship_intensity_branches() {
        // 20-23 → ultra_stealth
        for hour in 20..=23 {
            let utc = Utc.from_utc_datetime(
                &(NaiveDate::from_ymd_opt(2026, 6, 24)
                    .unwrap()
                    .and_hms_opt(hour, 0, 0)
                    .unwrap()
                    - irst_offset()),
            );
            assert_eq!(
                TelemetryWatcher::get_censorship_intensity_with(utc),
                "ultra_stealth"
            );
        }
        // 18-19 → high_stealth (not ultra_stealth, not relaxed, not normal)
        for hour in 18..=19 {
            let utc = Utc.from_utc_datetime(
                &(NaiveDate::from_ymd_opt(2026, 6, 24)
                    .unwrap()
                    .and_hms_opt(hour, 0, 0)
                    .unwrap()
                    - irst_offset()),
            );
            assert_eq!(
                TelemetryWatcher::get_censorship_intensity_with(utc),
                "high_stealth"
            );
        }
        // 0 → high_stealth (0 < 1)
        let midnight = Utc.from_utc_datetime(
            &(NaiveDate::from_ymd_opt(2026, 6, 24)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                - irst_offset()),
        );
        assert_eq!(
            TelemetryWatcher::get_censorship_intensity_with(midnight),
            "high_stealth"
        );
        // 3-6 → relaxed
        for hour in 3..=6 {
            let utc = Utc.from_utc_datetime(
                &(NaiveDate::from_ymd_opt(2026, 6, 24)
                    .unwrap()
                    .and_hms_opt(hour, 0, 0)
                    .unwrap()
                    - irst_offset()),
            );
            assert_eq!(
                TelemetryWatcher::get_censorship_intensity_with(utc),
                "relaxed"
            );
        }
        // 2 → normal (not in any special range)
        let two_am = Utc.from_utc_datetime(
            &(NaiveDate::from_ymd_opt(2026, 6, 24)
                .unwrap()
                .and_hms_opt(2, 0, 0)
                .unwrap()
                - irst_offset()),
        );
        assert_eq!(
            TelemetryWatcher::get_censorship_intensity_with(two_am),
            "normal"
        );
        // 7-17 → normal
        for hour in 7..=17 {
            let utc = Utc.from_utc_datetime(
                &(NaiveDate::from_ymd_opt(2026, 6, 24)
                    .unwrap()
                    .and_hms_opt(hour, 0, 0)
                    .unwrap()
                    - irst_offset()),
            );
            assert_eq!(
                TelemetryWatcher::get_censorship_intensity_with(utc),
                "normal"
            );
        }
    }

    #[test]
    fn round_to_matches_python_round() {
        assert_eq!(round_to(0.5, 0), 1.0);
        assert_eq!(round_to(0.4, 0), 0.0);
        assert_eq!(round_to(1.23456, 4), 1.2346);
        assert_eq!(round_to(1.23454, 4), 1.2345);
        assert_eq!(round_to(100.0, 2), 100.0);
    }

    #[test]
    fn log_dpi_event_updates_counters() {
        let dir = std::env::temp_dir().join(format!(
            "telemetry_watcher_unit_log_dpi_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let watcher = TelemetryWatcher::new_with(
            &dir.join("monitor.log"),
            &dir.join("state.json"),
            &dir.join("report.json"),
            default_clock(),
            EnvMap::new(),
            default_auto_debug_hook(),
            default_proxy_check_hook(),
            default_nin_dpi_check_hook(),
        )
        .expect("construct watcher");
        watcher
            .log_dpi_event("sni_inspector", "blocked", None, "fragments", true)
            .unwrap();
        watcher
            .log_dpi_event("ja3", "evaded", None, "uTLS", true)
            .unwrap();
        watcher
            .log_dpi_event("http2", "camouflaged", None, "", true)
            .unwrap();
        watcher
            .log_dpi_event("sni_inspector", "detected", None, "", false)
            .unwrap();
        assert_eq!(watcher.counter("dpi_total"), 4);
        assert_eq!(watcher.counter("dpi_blocked"), 1);
        assert_eq!(watcher.counter("dpi_evaded"), 1);
        assert_eq!(watcher.counter("dpi_camouflaged"), 1);
        assert_eq!(watcher.counter("dpi_sys_sni_inspector"), 2);
        assert_eq!(watcher.counter("dpi_sys_ja3"), 1);
        assert_eq!(watcher.counter("dpi_sys_http2"), 1);
        assert_eq!(watcher.dpi_events_snapshot().len(), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_slot_failure_and_recovery_track_per_slot_counters() {
        let dir = std::env::temp_dir().join(format!(
            "telemetry_watcher_unit_slot_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let watcher = TelemetryWatcher::new_with(
            &dir.join("monitor.log"),
            &dir.join("state.json"),
            &dir.join("report.json"),
            default_clock(),
            EnvMap::new(),
            default_auto_debug_hook(),
            default_proxy_check_hook(),
            default_nin_dpi_check_hook(),
        )
        .unwrap();
        watcher
            .log_slot_failure(3, "CF_API_TOKEN_3", "HTTP 403", "forbidden")
            .unwrap();
        watcher
            .log_slot_failure(3, "CF_API_TOKEN_3", "HTTP 500", "")
            .unwrap();
        watcher
            .log_slot_recovery(3, "CF_API_TOKEN_3", "circuit_reset")
            .unwrap();
        assert_eq!(watcher.counter("slot_failures"), 2);
        assert_eq!(watcher.counter("slot_3_failures"), 2);
        assert_eq!(watcher.counter("slot_recoveries"), 1);
        assert_eq!(watcher.get_poisoned_slots().unwrap(), Vec::<i32>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_model_resolution_failure_triggers_auto_debug_at_threshold() {
        let dir = std::env::temp_dir().join(format!(
            "telemetry_watcher_unit_trigger_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let watcher = TelemetryWatcher::new_with(
            &dir.join("monitor.log"),
            &dir.join("state.json"),
            &dir.join("report.json"),
            default_clock(),
            EnvMap::new(),
            default_auto_debug_hook(),
            default_proxy_check_hook(),
            default_nin_dpi_check_hook(),
        )
        .unwrap();
        // First failure: counter = 1, no trigger.
        let triggered = watcher.log_model_resolution_failure().unwrap();
        assert!(!triggered);
        assert_eq!(watcher.consecutive_model_failures(), 1);
        // Second failure: counter = 2, triggers auto-debug which resets counter.
        let triggered = watcher.log_model_resolution_failure().unwrap();
        assert!(triggered);
        assert_eq!(watcher.consecutive_model_failures(), 0);
        assert_eq!(watcher.counter("auto_debug_triggered"), 1);
        assert_eq!(watcher.counter("model_resolution_failures"), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_auto_debug_no_trigger_below_threshold() {
        let dir = std::env::temp_dir().join(format!(
            "telemetry_watcher_unit_check_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let watcher = TelemetryWatcher::new_with(
            &dir.join("monitor.log"),
            &dir.join("state.json"),
            &dir.join("report.json"),
            default_clock(),
            EnvMap::new(),
            default_auto_debug_hook(),
            default_proxy_check_hook(),
            default_nin_dpi_check_hook(),
        )
        .unwrap();
        assert!(!watcher.check_auto_debug().unwrap());
        watcher.log_model_resolution_failure().unwrap();
        assert!(!watcher.check_auto_debug().unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_24h_summary_aggregates_events_with_fixed_clock() {
        let dir = std::env::temp_dir().join(format!(
            "telemetry_watcher_unit_summary_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let now = DateTime::parse_from_rfc3339("2026-06-24T12:00:00+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);
        let clock: Clock = Arc::new(move || now);
        let watcher = TelemetryWatcher::new_with(
            &dir.join("monitor.log"),
            &dir.join("state.json"),
            &dir.join("report.json"),
            clock,
            EnvMap::new(),
            default_auto_debug_hook(),
            default_proxy_check_hook(),
            default_nin_dpi_check_hook(),
        )
        .unwrap();
        // Recent DPI events (1 hour ago).
        let recent_ts = format_iso(&(now - TimeDelta::hours(1)));
        let old_ts = format_iso(&(now - TimeDelta::hours(48)));
        watcher
            .log_dpi_event_with_ts(&recent_ts, "sni", "blocked", None, "", true)
            .unwrap();
        watcher
            .log_dpi_event_with_ts(&recent_ts, "sni", "evaded", None, "", true)
            .unwrap();
        watcher
            .log_dpi_event_with_ts(&old_ts, "sni", "blocked", None, "", true)
            .unwrap();
        let summary = watcher.get_24h_summary().unwrap();
        assert_eq!(summary.total_dpi_events, 2);
        assert_eq!(summary.dpi_events_blocked, 1);
        assert_eq!(summary.dpi_events_evaded, 1);
        assert_eq!(summary.date, "2026-06-24");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_threaded_log_dpi_event_is_thread_safe() {
        let dir = std::env::temp_dir().join(format!(
            "telemetry_watcher_unit_mt_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let watcher = TelemetryWatcher::new_with(
            &dir.join("monitor.log"),
            &dir.join("state.json"),
            &dir.join("report.json"),
            default_clock(),
            EnvMap::new(),
            default_auto_debug_hook(),
            default_proxy_check_hook(),
            default_nin_dpi_check_hook(),
        )
        .unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let w = watcher.clone();
            let c = Arc::clone(&counter);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    w.log_dpi_event("sni", "blocked", None, "", true).unwrap();
                    c.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread");
        }
        assert_eq!(counter.load(Ordering::SeqCst), 800);
        assert_eq!(watcher.counter("dpi_total"), 800);
        assert_eq!(watcher.counter("dpi_blocked"), 800);
        assert_eq!(watcher.dpi_events_snapshot().len(), 800);
        let _ = fs::remove_dir_all(&dir);
    }

    // Internal test helper: log a DPI event with an explicit timestamp
    // (bypasses the clock) for deterministic 24h-summary tests.
    impl TelemetryWatcher {
        fn log_dpi_event_with_ts(
            &self,
            ts: &str,
            dpi_system: &str,
            action: &str,
            details: Option<&Value>,
            evasion_used: &str,
            success: bool,
        ) -> Result<(), TelemetryError> {
            let event = DPIEvent {
                timestamp: ts.to_string(),
                dpi_system: dpi_system.to_string(),
                action: action.to_string(),
                details: details.cloned().unwrap_or(json!({})),
                evasion_used: evasion_used.to_string(),
                success,
            };
            {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .expect("telemetry state mutex poisoned");
                state.dpi_events.push(event.clone());
                state.bump("dpi_total", 1);
                match action {
                    "blocked" => state.bump("dpi_blocked", 1),
                    "evaded" => state.bump("dpi_evaded", 1),
                    "camouflaged" => state.bump("dpi_camouflaged", 1),
                    _ => {}
                }
                let sys_key = format!("dpi_sys_{dpi_system}");
                state.bump(&sys_key, 1);
            }
            // Skip I/O for the test helper to keep tests fast and hermetic.
            let _ = action;
            let _ = evasion_used;
            let _ = success;
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn _silence_unused_warning() {
        let _ = fixed_clock;
    }
}

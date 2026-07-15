//! Parity port of `quarantine_manager.py` — FEATURE 5: Temporal Blocking
//! Pattern Anomaly Detection.
//!
//! Detects bridges that exhibit sudden spikes in blocking rate using a rolling
//! z-score (window = 7 days, threshold = 2σ). Flagged bridges enter a
//! quarantine tier and are excluded from recommended outputs until 3
//! consecutive clean measurement days are observed.
//!
//! All quarantine decisions are appended as structured JSON lines to the
//! configured quarantine log path for full auditability.
//!
//! Behavior traced to `quarantine_manager.py`:
//! * `rolling_zscore` — pure statistics helper; returns 0.0 when there is
//!   insufficient historical data or zero historical variance.
//! * `QuarantineManager` — owns the on-disk quarantine state file and the
//!   append-only JSONL audit log. File paths are injectable so parity tests
//!   can use a temp directory.
//!
//! The Python original calls `monitoring.structured_logger.record_silent_failure`
//! on load failures and logs via the stdlib `logging` module. The Rust port
//! routes those side effects through `eprintln!` (lenient constructor) and
//! typed `Result` errors (strict constructor) — no extra crates required.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{TimeDelta, Utc};
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration constants (mirror `quarantine_manager.py`)
// ─────────────────────────────────────────────────────────────────────────────

/// Days included in the "recent" window of the rolling z-score.
pub const ZSCORE_WINDOW: usize = 7;

/// Sigma threshold above which a bridge is quarantined.
pub const ZSCORE_THRESHOLD: f64 = 2.0;

/// Consecutive clean measurement days required to exit quarantine.
pub const CLEAN_DAYS_TO_RELEASE: i64 = 3;

// ─────────────────────────────────────────────────────────────────────────────
// Typed errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failures raised by the Rust `quarantine_manager.py` parity port.
#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    /// `quarantine_state.json` exists but could not be read.
    #[error("failed to read quarantine state from {path}: {source}")]
    ReadState {
        path: PathBuf,
        source: std::io::Error,
    },
    /// `quarantine_state.json` exists but is not valid JSON.
    #[error("failed to parse quarantine state from {path}: {source}")]
    ParseState {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// `quarantine_state.json` parsed but the root value is not a JSON object.
    #[error("invalid quarantine state structure at {path}: expected JSON object")]
    InvalidStateShape { path: PathBuf },
    /// A quarantine entry is missing a required field or has the wrong type.
    #[error("invalid quarantine entry for host {host}: missing or invalid {field}")]
    InvalidEntry { host: String, field: &'static str },
    /// A JSON serialization step (state file or log event) failed.
    #[error("failed to serialize quarantine JSON: {source}")]
    Serialize { source: serde_json::Error },
    /// Writing the state file failed.
    #[error("failed to save quarantine state to {path}: {source}")]
    SaveState {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Appending to the JSONL quarantine log failed.
    #[error("failed to append to quarantine log at {path}: {source}")]
    AppendLog {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Creating the parent directory for state or log file failed.
    #[error("failed to create parent directory for {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics helpers (pure functions, mirror `_mean` / `_std` / `rolling_zscore`)
// ─────────────────────────────────────────────────────────────────────────────

/// Kahan compensated summation over a slice of f64.
///
/// CPython 3.12+ uses Kahan summation inside the built-in `sum()` for
/// float sequences, so a naive left-to-right `iter().sum::<f64>()` can
/// diverge from Python by 1 ULP on inputs that accumulate rounding error.
/// This helper reproduces the CPython float-summation algorithm so that
/// `mean`, `std`, and `rolling_zscore` stay byte-identical to the Python
/// original.
fn kahan_sum(values: &[f64]) -> f64 {
    let mut sum = 0.0_f64;
    let mut compensation = 0.0_f64;
    for &value in values {
        let y = value - compensation;
        let t = sum + y;
        compensation = (t - sum) - y;
        sum = t;
    }
    sum
}

/// Mirror of Python's `_mean(values)`. Returns 0.0 for an empty slice.
pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    kahan_sum(values) / values.len() as f64
}

/// Mirror of Python's `_std(values)` (sample standard deviation, `n - 1`).
/// Returns 0.0 when fewer than 2 values are supplied.
pub fn std(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    let squared: Vec<f64> = values.iter().map(|x| (x - m).powi(2)).collect();
    let variance = kahan_sum(&squared) / (values.len() - 1) as f64;
    variance.sqrt()
}

/// Compute the z-score of the most recent `window` days vs. all prior days.
/// Returns 0.0 when insufficient historical data is available or when the
/// historical standard deviation is zero.
///
/// Direct port of `quarantine_manager.py::rolling_zscore`.
pub fn rolling_zscore(daily_rates: &[f64], window: usize) -> f64 {
    if daily_rates.len() < window + 1 {
        return 0.0;
    }
    let recent = &daily_rates[daily_rates.len() - window..];
    let historical = &daily_rates[..daily_rates.len() - window];
    let hist_mean = mean(historical);
    let hist_std = std(historical);
    if hist_std == 0.0 {
        return 0.0;
    }
    let recent_mean = mean(recent);
    (recent_mean - hist_mean) / hist_std
}

// ─────────────────────────────────────────────────────────────────────────────
// Quarantine entry model
// ─────────────────────────────────────────────────────────────────────────────

/// A single bridge's quarantine record. Field order matches the Python
/// `quarantine()` insertion order so JSON serialization is byte-compatible.
#[derive(Debug, Clone, PartialEq)]
pub struct QuarantineEntry {
    /// ISO-8601 timestamp captured when the bridge was quarantined.
    pub quarantined_at: String,
    /// Z-score that triggered the quarantine, rounded to 3 decimals.
    pub z_score: f64,
    /// Number of consecutive clean measurement days observed since quarantine.
    pub consecutive_clean: i64,
    /// Human-readable reason for the quarantine action.
    pub reason: String,
}

impl QuarantineEntry {
    /// Serialize the entry to a `serde_json::Value` for state-file writes.
    /// Field order matches the Python `quarantine()` method.
    pub fn to_json(&self) -> Value {
        json!({
            "quarantined_at": self.quarantined_at,
            "z_score": self.z_score,
            "consecutive_clean": self.consecutive_clean,
            "reason": self.reason,
        })
    }

    /// Parse an entry from a JSON value read from the state file.
    pub fn from_json(host: &str, value: &Value) -> Result<Self, QuarantineError> {
        let obj = value
            .as_object()
            .ok_or_else(|| QuarantineError::InvalidEntry {
                host: host.to_string(),
                field: "(root object)",
            })?;
        let quarantined_at = obj
            .get("quarantined_at")
            .and_then(Value::as_str)
            .ok_or_else(|| QuarantineError::InvalidEntry {
                host: host.to_string(),
                field: "quarantined_at",
            })?
            .to_string();
        let z_score = obj.get("z_score").and_then(Value::as_f64).ok_or_else(|| {
            QuarantineError::InvalidEntry {
                host: host.to_string(),
                field: "z_score",
            }
        })?;
        let consecutive_clean = obj
            .get("consecutive_clean")
            .and_then(Value::as_i64)
            .ok_or_else(|| QuarantineError::InvalidEntry {
                host: host.to_string(),
                field: "consecutive_clean",
            })?;
        let reason = obj
            .get("reason")
            .and_then(Value::as_str)
            .ok_or_else(|| QuarantineError::InvalidEntry {
                host: host.to_string(),
                field: "reason",
            })?
            .to_string();
        Ok(Self {
            quarantined_at,
            z_score,
            consecutive_clean,
            reason,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Update summary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary returned by `QuarantineManager::update_from_ooni_history`.
/// Field set matches the Python summary dict exactly.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateSummary {
    /// Number of bridges evaluated (i.e. `len(bridge_daily_history)`).
    pub evaluated: usize,
    /// Total bridges currently in quarantine after the update.
    pub currently_quarantined: usize,
    /// Bridges that were freshly quarantined by this update.
    pub newly_quarantined: usize,
    /// Bridges released from quarantine by this update.
    pub released: usize,
    /// Hosts currently quarantined (snapshot of state keys at return time).
    pub hosts_quarantined: Vec<String>,
}

impl UpdateSummary {
    /// Serialize the summary to a JSON value matching the Python dict shape.
    pub fn to_json(&self) -> Value {
        json!({
            "evaluated": self.evaluated,
            "currently_quarantined": self.currently_quarantined,
            "newly_quarantined": self.newly_quarantined,
            "released": self.released,
            "hosts_quarantined": self.hosts_quarantined,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QuarantineManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the bridge quarantine tier.
///
/// State file schema (`quarantine_state.json`):
/// ```json
/// {
///   "1.2.3.4": {
///     "quarantined_at": "ISO-8601",
///     "z_score": 3.142,
///     "consecutive_clean": 0,
///     "reason": "anomaly_spike"
///   }
/// }
/// ```
///
/// Paths are injectable so tests can point at a temp directory.
pub struct QuarantineManager {
    state: BTreeMap<String, QuarantineEntry>,
    state_path: PathBuf,
    log_path: PathBuf,
}

impl QuarantineManager {
    /// Strict constructor: returns [`QuarantineError`] if the state file
    /// exists but cannot be read or parsed. Returns an empty state if the
    /// file does not exist (mirrors Python's `Path.exists()` short-circuit).
    pub fn new(state_path: &Path, log_path: &Path) -> Result<Self, QuarantineError> {
        let state = Self::load_state(state_path)?;
        Ok(Self {
            state,
            state_path: state_path.to_path_buf(),
            log_path: log_path.to_path_buf(),
        })
    }

    /// Lenient constructor: matches Python's swallow-and-continue behavior on
    /// state load failures. Logs the error to stderr (replacing the Python
    /// `record_silent_failure` + `log.warning` calls) and starts with empty
    /// state. Use this in production; prefer [`QuarantineManager::new`] in
    /// tests where load failures should fail loudly.
    pub fn new_lenient(state_path: &Path, log_path: &Path) -> Self {
        match Self::new(state_path, log_path) {
            Ok(manager) => manager,
            Err(error) => {
                eprintln!("quarantine_manager: cannot load state: {error}");
                Self {
                    state: BTreeMap::new(),
                    state_path: state_path.to_path_buf(),
                    log_path: log_path.to_path_buf(),
                }
            }
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────

    fn load_state(path: &Path) -> Result<BTreeMap<String, QuarantineEntry>, QuarantineError> {
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let text = fs::read_to_string(path).map_err(|source| QuarantineError::ReadState {
            path: path.to_path_buf(),
            source,
        })?;
        let value: Value =
            serde_json::from_str(&text).map_err(|source| QuarantineError::ParseState {
                path: path.to_path_buf(),
                source,
            })?;
        let obj = value
            .as_object()
            .ok_or_else(|| QuarantineError::InvalidStateShape {
                path: path.to_path_buf(),
            })?;
        let mut state = BTreeMap::new();
        for (host, entry_value) in obj {
            let entry = QuarantineEntry::from_json(host, entry_value)?;
            state.insert(host.clone(), entry);
        }
        Ok(state)
    }

    fn save_state(&self) -> Result<(), QuarantineError> {
        let mut root = serde_json::Map::new();
        for (host, entry) in &self.state {
            root.insert(host.clone(), entry.to_json());
        }
        let serialized = serde_json::to_string_pretty(&Value::Object(root))
            .map_err(|source| QuarantineError::Serialize { source })?;
        if let Some(parent) = self.state_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| QuarantineError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        fs::write(&self.state_path, serialized).map_err(|source| QuarantineError::SaveState {
            path: self.state_path.clone(),
            source,
        })?;
        Ok(())
    }

    fn log_event(&self, mut event: Value) -> Result<(), QuarantineError> {
        if let Some(obj) = event.as_object_mut() {
            obj.insert("logged_at".to_string(), Value::String(iso_now()));
        }
        let line = serde_json::to_string(&event)
            .map_err(|source| QuarantineError::Serialize { source })?;
        if let Some(parent) = self.log_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| QuarantineError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|source| QuarantineError::AppendLog {
                path: self.log_path.clone(),
                source,
            })?;
        file.write_all(line.as_bytes())
            .map_err(|source| QuarantineError::AppendLog {
                path: self.log_path.clone(),
                source,
            })?;
        file.write_all(b"\n")
            .map_err(|source| QuarantineError::AppendLog {
                path: self.log_path.clone(),
                source,
            })?;
        Ok(())
    }

    // ── Core operations ───────────────────────────────────────────────────

    /// Quarantine a bridge host. Idempotent: if the host is already
    /// quarantined, the existing entry is left untouched and no log event
    /// is emitted.
    pub fn quarantine(
        &mut self,
        host: &str,
        z_score: f64,
        reason: &str,
    ) -> Result<(), QuarantineError> {
        if self.state.contains_key(host) {
            return Ok(());
        }
        let now = Utc::now();
        let ts = format_iso(&now);
        let rounded = round_to_3_decimals(z_score);
        let entry = QuarantineEntry {
            quarantined_at: ts,
            z_score: rounded,
            consecutive_clean: 0,
            reason: reason.to_string(),
        };
        self.state.insert(host.to_string(), entry);
        self.save_state()?;
        let quarantine_min_until = format_iso(&(now + TimeDelta::days(CLEAN_DAYS_TO_RELEASE)));
        self.log_event(json!({
            "action": "quarantined",
            "bridge_host": host,
            "z_score": rounded,
            "reason": reason,
            "quarantine_min_until": quarantine_min_until,
        }))?;
        Ok(())
    }

    /// Increment the consecutive clean counter. Returns `true` if the bridge
    /// was released from quarantine as a result of reaching the
    /// `CLEAN_DAYS_TO_RELEASE` threshold.
    pub fn record_clean_measurement(&mut self, host: &str) -> Result<bool, QuarantineError> {
        let should_release = match self.state.get_mut(host) {
            Some(entry) => {
                entry.consecutive_clean += 1;
                entry.consecutive_clean >= CLEAN_DAYS_TO_RELEASE
            }
            None => return Ok(false),
        };
        if should_release {
            self.release(host, "3_consecutive_clean_days")
        } else {
            self.save_state()?;
            Ok(false)
        }
    }

    /// Reset the consecutive clean counter when an anomaly is observed on an
    /// already-quarantined bridge. No-op if the host is not quarantined.
    pub fn record_anomaly_measurement(&mut self, host: &str) -> Result<(), QuarantineError> {
        if let Some(entry) = self.state.get_mut(host) {
            entry.consecutive_clean = 0;
            self.save_state()?;
        }
        Ok(())
    }

    /// Release a bridge from quarantine. Returns `false` if the host was not
    /// quarantined. Otherwise pops the entry, saves state, and logs a
    /// `released` audit event.
    pub fn release(&mut self, host: &str, reason: &str) -> Result<bool, QuarantineError> {
        let Some(entry) = self.state.remove(host) else {
            return Ok(false);
        };
        self.save_state()?;
        self.log_event(json!({
            "action": "released",
            "bridge_host": host,
            "reason": reason,
            "was_quarantined_at": entry.quarantined_at,
        }))?;
        Ok(true)
    }

    // ── Queries ───────────────────────────────────────────────────────────

    /// Return `true` if the host is currently quarantined.
    pub fn is_quarantined(&self, host: &str) -> bool {
        self.state.contains_key(host)
    }

    /// Return the set of currently quarantined hosts.
    pub fn quarantined_set(&self) -> BTreeSet<String> {
        self.state.keys().cloned().collect()
    }

    /// Return a shallow clone of the current quarantine state.
    pub fn state_snapshot(&self) -> BTreeMap<String, QuarantineEntry> {
        self.state.clone()
    }

    // ── Batch update from OONI measurement history ────────────────────────

    /// Evaluate all bridges against the rolling z-score anomaly detector.
    ///
    /// `bridge_daily_history` is a slice of `(host, daily)` pairs where
    /// `daily` is a slice of `(date_str, is_anomaly)` tuples sorted
    /// ascending by date. Using a slice (rather than a map) preserves the
    /// Python `dict.items()` iteration order, which is significant for the
    /// `hosts_quarantined` summary field.
    ///
    /// Returns a summary mirroring the Python `update_from_ooni_history`
    /// return dict.
    pub fn update_from_ooni_history(
        &mut self,
        bridge_daily_history: &[(String, Vec<(String, bool)>)],
    ) -> Result<UpdateSummary, QuarantineError> {
        let evaluated = bridge_daily_history.len();
        let mut newly_quarantined: usize = 0;
        let mut released: usize = 0;

        for (host, daily) in bridge_daily_history {
            if daily.is_empty() {
                continue;
            }
            let rates: Vec<f64> = daily
                .iter()
                .map(|(_, anomaly)| if *anomaly { 1.0 } else { 0.0 })
                .collect();
            let z = rolling_zscore(&rates, ZSCORE_WINDOW);
            let latest_is_anomaly = daily.last().map(|(_, a)| *a).unwrap_or(false);

            if z > ZSCORE_THRESHOLD && !self.is_quarantined(host) {
                self.quarantine(host, z, "anomaly_spike")?;
                newly_quarantined += 1;
            } else if self.is_quarantined(host) {
                if latest_is_anomaly {
                    self.record_anomaly_measurement(host)?;
                } else {
                    let released_now = self.record_clean_measurement(host)?;
                    if released_now {
                        released += 1;
                    }
                }
            }
        }

        Ok(UpdateSummary {
            evaluated,
            currently_quarantined: self.state.len(),
            newly_quarantined,
            released,
            hosts_quarantined: self.state.keys().cloned().collect(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Format a `DateTime<Utc>` as an ISO-8601 string with microsecond precision
/// and a `+00:00` offset, matching Python's `datetime.now(UTC).isoformat()`.
fn format_iso(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string()
}

/// Return the current UTC time formatted as ISO-8601 (Python `isoformat`
/// compatible).
fn iso_now() -> String {
    format_iso(&Utc::now())
}

/// Round an f64 to 3 decimal places, mirroring Python's `round(x, 3)` for
/// finite floats. Uses round-half-away-from-zero which matches Python's
/// `round()` for the irrational z-scores produced by `rolling_zscore`.
fn round_to_3_decimals(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_handles_empty_and_basic_cases() {
        assert_eq!(mean(&[]), 0.0);
        assert_eq!(mean(&[2.0]), 2.0);
        assert_eq!(mean(&[1.0, 2.0, 3.0]), 2.0);
    }

    #[test]
    fn std_handles_short_inputs_and_variance() {
        assert_eq!(std(&[]), 0.0);
        assert_eq!(std(&[1.0]), 0.0);
        // Sample std of [1.0, 2.0, 3.0]: mean=2, var = (1+0+1)/2 = 1.0, std=1.0
        assert_eq!(std(&[1.0, 2.0, 3.0]), 1.0);
    }

    #[test]
    fn rolling_zscore_returns_zero_for_insufficient_data() {
        assert_eq!(rolling_zscore(&[], ZSCORE_WINDOW), 0.0);
        assert_eq!(rolling_zscore(&[1.0, 2.0], ZSCORE_WINDOW), 0.0);
        // Exactly window+1 elements but historical has 1 element → std = 0
        let rates: Vec<f64> = vec![0.0; ZSCORE_WINDOW + 1];
        assert_eq!(rolling_zscore(&rates, ZSCORE_WINDOW), 0.0);
    }

    #[test]
    fn rolling_zscore_detects_spike() {
        // 7 historical (1 anomaly) + 7 recent (all anomalies)
        let rates: Vec<f64> = vec![
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
        ];
        let z = rolling_zscore(&rates, ZSCORE_WINDOW);
        assert!(
            z > ZSCORE_THRESHOLD,
            "expected z > {ZSCORE_THRESHOLD}, got {z}"
        );
    }

    #[test]
    fn round_to_3_decimals_matches_python_round() {
        assert_eq!(round_to_3_decimals(2.2677868380553634), 2.268);
        // Use values that are not near any mathematical constant to avoid
        // clippy::approx_constant.
        assert_eq!(round_to_3_decimals(4.56789), 4.568);
        assert_eq!(round_to_3_decimals(1.0), 1.0);
        assert_eq!(round_to_3_decimals(0.0), 0.0);
    }
}

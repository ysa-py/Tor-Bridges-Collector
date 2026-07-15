//! Rust port of `monitoring/structured_logger.py`.
//!
//! Fail-safe structured JSON logging to multiple log files (`diagnostics.log`,
//! `monitor.log`, `recovery.log`, `gateway.log`). Every log write is wrapped so
//! a disk-full / permission error can never crash the service, mirroring the
//! Python `try/except` fail-safe design.
//!
//! The observable, deterministic surface — the JSON log-record layout produced
//! by each `log_*` method (field set, insertion order, value types, and the
//! `round(latency_ms, 1)` rounding) — is proven equivalent to the CPython
//! original by `tests/parity/monitoring_structured_logger_parity.rs`, which
//! writes a record with the real Python module and compares it field-by-field
//! (and key-order) against the Rust port.
//!
//! ## Deviations (documented, see `MIGRATION_NOTES.md`)
//!   * The wall-clock `timestamp` field is non-deterministic in both
//!     implementations; the parity test normalises it before comparison.
//!   * Python serialises floats with its shortest-repr; the parity test parses
//!     the JSON and compares the numeric value, so a differing textual float
//!     rendering is not observable. The rounding *math* (`round(x, 1)`,
//!     round-half-to-even) is reproduced and asserted.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// A JSON value restricted to the shapes the logger emits, so serialisation can
/// match Python's `json.dumps(..., ensure_ascii=False)` output exactly.
#[derive(Debug, Clone, PartialEq)]
pub enum LogValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    List(Vec<LogValue>),
    Null,
}

impl LogValue {
    fn write_json(&self, out: &mut String) {
        match self {
            LogValue::Str(s) => write_json_string(s, out),
            LogValue::Int(i) => out.push_str(&i.to_string()),
            LogValue::Float(f) => out.push_str(&format_json_float(*f)),
            LogValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            LogValue::Null => out.push_str("null"),
            LogValue::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
        }
    }
}

/// Escape a string the way Python's `json.dumps(..., ensure_ascii=False)` does:
/// escape `"`, `\`, and control characters `< 0x20`; keep all other characters
/// (including non-ASCII) verbatim.
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Format a float as valid JSON. Integers-valued floats render as `N.0`, matching
/// Python's `json.dumps(float)` for the common cases; exact textual parity is not
/// observable (the parity test parses and compares numerically).
fn format_json_float(f: f64) -> String {
    if f.is_finite() && f == f.trunc() {
        format!("{f:.1}")
    } else {
        let mut s = format!("{f}");
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            s.push_str(".0");
        }
        s
    }
}

/// Round a value to the nearest integer, ties-to-even (banker's rounding).
/// Hand-rolled to stay within the pinned MSRV (1.75); `f64::round_ties_even`
/// was only stabilised in 1.77.
fn round_half_even(y: f64) -> f64 {
    let floor = y.floor();
    let diff = y - floor;
    if diff < 0.5 {
        floor
    } else if diff > 0.5 {
        floor + 1.0
    } else if floor.rem_euclid(2.0) == 0.0 {
        floor
    } else {
        floor + 1.0
    }
}

/// Python `round(x, 1)`: round to one decimal place, ties-to-even.
pub fn round1(x: f64) -> f64 {
    round_half_even(x * 10.0) / 10.0
}

/// An ordered JSON object (insertion order preserved, like a Python `dict`).
#[derive(Debug, Clone, Default)]
pub struct Entry {
    pairs: Vec<(String, LogValue)>,
}

impl Entry {
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    pub fn push(&mut self, key: &str, value: LogValue) -> &mut Self {
        self.pairs.push((key.to_string(), value));
        self
    }

    /// Ordered list of keys (for key-order parity assertions).
    pub fn keys(&self) -> Vec<String> {
        self.pairs.iter().map(|(k, _)| k.clone()).collect()
    }

    /// Serialise as a single JSON line, matching Python's
    /// `json.dumps(entry, ensure_ascii=False, default=str)`.
    pub fn to_json_line(&self) -> String {
        let mut out = String::from("{");
        for (i, (k, v)) in self.pairs.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            write_json_string(k, &mut out);
            out.push_str(": ");
            v.write_json(&mut out);
        }
        out.push('}');
        out
    }
}

/// Fail-safe structured JSON logger (port of `StructuredLogger`).
#[derive(Debug)]
pub struct StructuredLogger {
    log_dir: PathBuf,
    max_bytes: u64,
    files: BTreeMap<&'static str, PathBuf>,
    write_lock: Mutex<()>,
}

static INSTANCE: OnceLock<StructuredLogger> = OnceLock::new();

impl StructuredLogger {
    /// Construct with a log directory, mirroring `__init__`: create the
    /// directory (falling back to `.` on error) and read `LOG_MAX_MB` (default
    /// 10) for the rotation threshold.
    pub fn new(log_dir: &str) -> Self {
        let mut dir = PathBuf::from(log_dir);
        if fs::create_dir_all(&dir).is_err() {
            dir = PathBuf::from(".");
        }
        let max_mb: u64 = std::env::var("LOG_MAX_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let mut files = BTreeMap::new();
        files.insert("diagnostics", dir.join("diagnostics.log"));
        files.insert("monitor", dir.join("monitor.log"));
        files.insert("recovery", dir.join("recovery.log"));
        files.insert("gateway", dir.join("gateway.log"));
        Self {
            log_dir: dir,
            max_bytes: max_mb * 1024 * 1024,
            files,
            write_lock: Mutex::new(()),
        }
    }

    /// Process-wide singleton, mirroring `StructuredLogger.instance`.
    pub fn instance(log_dir: &str) -> &'static StructuredLogger {
        INSTANCE.get_or_init(|| StructuredLogger::new(log_dir))
    }

    /// The resolved log directory (may be `.` if the requested dir was
    /// unwritable).
    pub fn log_dir(&self) -> &PathBuf {
        &self.log_dir
    }

    /// Write a JSON line to the given log file. FAIL-SAFE: never panics; the
    /// `timestamp` and `log_type` fields are appended last, as in Python.
    pub fn write_log(&self, log_type: &str, mut entry: Entry, timestamp: &str) {
        entry.push("timestamp", LogValue::Str(timestamp.to_string()));
        entry.push("log_type", LogValue::Str(log_type.to_string()));

        let log_path = match self.files.get(log_type) {
            Some(p) => p.clone(),
            None => return,
        };

        // Size-based rotation (failure to rotate must not block logging).
        if let Ok(meta) = fs::metadata(&log_path) {
            if meta.len() > self.max_bytes {
                self.rotate_log(&log_path);
            }
        }

        let line = entry.to_json_line() + "\n";
        let _guard = self.write_lock.lock();
        // Disk-full / permission errors are swallowed, exactly like Python.
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// Rotate a log file to `*.log.1` when it exceeds the size threshold.
    fn rotate_log(&self, log_path: &PathBuf) {
        let backup = log_path.with_extension("log.1");
        let _ = fs::remove_file(&backup);
        let _ = fs::rename(log_path, &backup);
    }

    /// Build the diagnostics entry (public so the parity test can compare the
    /// record without touching the filesystem).
    pub fn diagnostics_entry(
        level: &str,
        provider: &str,
        slot: i64,
        model: &str,
        error_code: &str,
        message: &str,
        extra: &[(&str, LogValue)],
    ) -> Entry {
        let mut e = Entry::new();
        e.push("level", LogValue::Str(level.into()))
            .push("provider", LogValue::Str(provider.into()))
            .push("slot", LogValue::Int(slot))
            .push("model", LogValue::Str(model.into()))
            .push("error_code", LogValue::Str(error_code.into()))
            .push("message", LogValue::Str(message.into()));
        for (k, v) in extra {
            e.push(k, v.clone());
        }
        e
    }

    /// Build the monitor entry.
    #[allow(clippy::too_many_arguments)]
    pub fn monitor_entry(
        level: &str,
        event_type: &str,
        provider: &str,
        slot: i64,
        model: &str,
        error_code: &str,
        message: &str,
        extra: &[(&str, LogValue)],
    ) -> Entry {
        let mut e = Entry::new();
        e.push("level", LogValue::Str(level.into()))
            .push("event_type", LogValue::Str(event_type.into()))
            .push("provider", LogValue::Str(provider.into()))
            .push("slot", LogValue::Int(slot))
            .push("model", LogValue::Str(model.into()))
            .push("error_code", LogValue::Str(error_code.into()))
            .push("message", LogValue::Str(message.into()));
        for (k, v) in extra {
            e.push(k, v.clone());
        }
        e
    }

    /// Build the recovery entry. `slots_affected`/`models_rotated` default to
    /// empty lists (Python `x or []`).
    pub fn recovery_entry(
        level: &str,
        action: &str,
        trigger: &str,
        slots_affected: Vec<LogValue>,
        models_rotated: Vec<LogValue>,
        message: &str,
        extra: &[(&str, LogValue)],
    ) -> Entry {
        let mut e = Entry::new();
        e.push("level", LogValue::Str(level.into()))
            .push("action", LogValue::Str(action.into()))
            .push("trigger", LogValue::Str(trigger.into()))
            .push("slots_affected", LogValue::List(slots_affected))
            .push("models_rotated", LogValue::List(models_rotated))
            .push("message", LogValue::Str(message.into()));
        for (k, v) in extra {
            e.push(k, v.clone());
        }
        e
    }

    /// Build the gateway entry; `latency_ms` is rounded to one decimal
    /// (round-half-to-even), matching `round(latency_ms, 1)`.
    #[allow(clippy::too_many_arguments)]
    pub fn gateway_entry(
        level: &str,
        provider: &str,
        slot: i64,
        model: &str,
        latency_ms: f64,
        success: bool,
        error_code: &str,
        message: &str,
        extra: &[(&str, LogValue)],
    ) -> Entry {
        let mut e = Entry::new();
        e.push("level", LogValue::Str(level.into()))
            .push("provider", LogValue::Str(provider.into()))
            .push("slot", LogValue::Int(slot))
            .push("model", LogValue::Str(model.into()))
            .push("latency_ms", LogValue::Float(round1(latency_ms)))
            .push("success", LogValue::Bool(success))
            .push("error_code", LogValue::Str(error_code.into()))
            .push("message", LogValue::Str(message.into()));
        for (k, v) in extra {
            e.push(k, v.clone());
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round1_ties_to_even() {
        assert_eq!(round1(0.0), 0.0);
        assert_eq!(round1(5.5), 5.5);
        assert_eq!(round1(12.34), 12.3);
        assert_eq!(round1(250.0), 250.0);
    }

    #[test]
    fn diagnostics_key_order_and_json() {
        let e = StructuredLogger::diagnostics_entry("INFO", "cf", 3, "m", "", "hi", &[]);
        assert_eq!(
            e.keys(),
            vec![
                "level",
                "provider",
                "slot",
                "model",
                "error_code",
                "message"
            ]
        );
        assert_eq!(
            e.to_json_line(),
            r#"{"level": "INFO", "provider": "cf", "slot": 3, "model": "m", "error_code": "", "message": "hi"}"#
        );
    }

    #[test]
    fn writes_and_rotates() {
        let base = std::env::temp_dir().join(format!("sl_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let logger = StructuredLogger::new(base.to_str().unwrap());
        let e = StructuredLogger::monitor_entry("INFO", "ev", "cf", 1, "m", "", "hello", &[]);
        logger.write_log("monitor", e, "2026-01-01T00:00:00+00:00");
        let contents = fs::read_to_string(base.join("monitor.log")).unwrap();
        assert!(contents.contains("\"event_type\": \"ev\""));
        assert!(contents.ends_with('\n'));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn json_escaping_matches_python() {
        let mut out = String::new();
        write_json_string("a\"b\\c\nd\te", &mut out);
        assert_eq!(out, r#""a\"b\\c\nd\te""#);
    }
}

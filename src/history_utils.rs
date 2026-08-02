//! Parity port of `sources/history_utils.py`.
//!
//! Shared helpers for bridge history timestamp handling. The Python original
//! is a thin wrapper around `core/dt_utils.py` plus three dict-manipulation
//! helpers that normalize and prune entries in `bridge_history.json`.
//!
//! Behavior traced to `sources/history_utils.py`:
//! * `parse_history_dt` — wraps `coerce_utc_dt` with the default fallback.
//! * `normalize_history_timestamps` — mutates a JSON object in place so that
//!   legacy string entries and `first_seen`/`last_seen` fields on dict
//!   entries become UTC-aware ISO-8601 strings.
//! * `history_entry_timestamp` — returns the preferred timestamp value for
//!   an entry (string entries pass through; dict entries consult
//!   `last_seen` first by default, falling back to `first_seen`).
//! * `cleanup_history` — drops entries whose preferred timestamp parses to
//!   a UTC datetime older than `utc_now() - timedelta(days=retention_days)`.
//!
//! The Python `cleanup_history` uses `utc_now()` internally. The Rust port
//! exposes [`cleanup_history_with_now`] with an injectable `now` parameter
//! for deterministic testing, and [`cleanup_history`] as a thin production
//! wrapper that uses [`crate::dt_utils::utc_now`].
//!
//! All functions operate on [`serde_json::Value`] to mirror Python's
//! duck-typed dict handling. No I/O is performed; the only failure mode is
//! `HistoryError::NotAnObject` when a caller passes a non-object root.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value};
use thiserror::Error;

/// Fallback timestamp used by [`parse_history_dt`] when input is missing or
/// malformed. Mirrors the Python default `2000-01-01T00:00:00+00:00` from
/// `core/dt_utils.py` (re-exported here so callers do not need to depend on
/// the `dt_utils` module directly).
pub const FALLBACK: &str = crate::dt_utils::DEFAULT_FALLBACK;

/// Errors raised by the Rust `history_utils.py` parity port.
#[derive(Debug, Error)]
pub enum HistoryError {
    /// [`normalize_history_timestamps`] or [`cleanup_history_with_now`] was
    /// called on a JSON value that is not an object. The Python originals
    /// silently assume dict input; the Rust port surfaces this as a typed
    /// error so callers can decide whether to log or propagate.
    #[error("history root must be a JSON object, got {actual}")]
    NotAnObject { actual: &'static str },
}

/// Parse a history timestamp into a UTC-aware [`DateTime<Utc>`].
///
/// Mirrors `parse_history_dt(value)` from `sources/history_utils.py`, which
/// delegates to `coerce_utc_dt(value)` from `core/dt_utils.py`. Non-string
/// inputs collapse to `None` (matching Python's fallback path for
/// non-string, non-datetime values).
pub fn parse_history_dt(value: Option<&str>) -> DateTime<Utc> {
    crate::dt_utils::coerce_utc_dt(value, FALLBACK)
}

/// Normalize history timestamps to UTC-aware ISO strings in place.
///
/// Mirrors `normalize_history_timestamps(history)` from
/// `sources/history_utils.py`:
/// - Legacy string entries are timestamp values and are normalized directly.
/// - Dict entries retain all existing metadata and only normalize known
///   timestamp fields (`first_seen`, `last_seen`) when those fields are
///   strings.
///
/// Returns a `&mut Value` reference for chaining. Returns
/// `Err(HistoryError::NotAnObject)` when `history` is not a JSON object.
pub fn normalize_history_timestamps(history: &mut Value) -> Result<&mut Value, HistoryError> {
    let map = match history.as_object_mut() {
        Some(map) => map,
        None => {
            return Err(HistoryError::NotAnObject {
                actual: type_name_of_value(history),
            })
        }
    };
    for (_key, entry) in map.iter_mut() {
        match entry {
            Value::String(s) => {
                let normalized = parse_history_dt(Some(s)).to_rfc3339();
                *entry = Value::String(normalized);
            }
            Value::Object(entry_map) => {
                normalize_timestamp_field(entry_map, "first_seen");
                normalize_timestamp_field(entry_map, "last_seen");
            }
            _ => {}
        }
    }
    Ok(history)
}

/// Replace a single string-valued timestamp field with its UTC-normalized
/// ISO-8601 form. Non-string values are left untouched (matches Python's
/// `isinstance(value, str)` guard).
fn normalize_timestamp_field(map: &mut Map<String, Value>, field: &str) {
    if let Some(Value::String(s)) = map.get(field) {
        let normalized = parse_history_dt(Some(s)).to_rfc3339();
        map.insert(field.to_string(), Value::String(normalized));
    }
}

/// Return the preferred timestamp value for a bridge history entry.
///
/// Mirrors `history_entry_timestamp(entry, *, prefer_last_seen=True)` from
/// `sources/history_utils.py`:
/// - String entries are their own timestamp value (returned as-is, including
///   the empty string).
/// - Dict entries expire by `last_seen` first by default (falling back to
///   `first_seen`). With `prefer_last_seen=false`, the order is swapped.
///   The fallback mirrors Python's `entry.get(preferred) or
///   entry.get(fallback)` semantics: an empty/missing preferred value
///   falls through to the fallback, and an empty fallback string is
///   returned as `Some("")` (matching Python returning the right operand
///   of `or`).
/// - All other entry types return `None`.
pub fn history_entry_timestamp(entry: &Value, prefer_last_seen: bool) -> Option<String> {
    match entry {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => {
            let (preferred, fallback) = if prefer_last_seen {
                ("last_seen", "first_seen")
            } else {
                ("first_seen", "last_seen")
            };
            if let Some(value) = truthy_string_field(map, preferred) {
                return Some(value);
            }
            // Python: `entry.get(preferred) or entry.get(fallback)` returns
            // the fallback value verbatim (including "" when the field is
            // present but empty). Mirror that by returning any string
            // value, even an empty one.
            any_string_field(map, fallback)
        }
        _ => None,
    }
}

/// Return the field value only when it is a non-empty string (Python
/// truthy string).
fn truthy_string_field(map: &Map<String, Value>, field: &str) -> Option<String> {
    match map.get(field) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Return the field value when it is any string (including the empty
/// string), mirroring Python's `entry.get(field)` returning the value
/// verbatim once the `or` chain reaches it.
fn any_string_field(map: &Map<String, Value>, field: &str) -> Option<String> {
    match map.get(field) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Remove history entries older than `retention_days` using UTC comparisons.
///
/// Mirrors `cleanup_history(history, retention_days, prefer_last_seen=True)`
/// from `sources/history_utils.py`, with one extension: the `now` parameter
/// is injectable so parity tests can drive the cutoff deterministically
/// instead of monkey-patching `utc_now()`. The convenience wrapper
/// [`cleanup_history`] uses [`crate::dt_utils::utc_now`] to match the
/// Python behavior in production.
///
/// Returns a `&mut Value` reference for chaining. Returns
/// `Err(HistoryError::NotAnObject)` when `history` is not a JSON object.
pub fn cleanup_history_with_now(
    history: &mut Value,
    retention_days: i64,
    prefer_last_seen: bool,
    now: DateTime<Utc>,
) -> Result<&mut Value, HistoryError> {
    let cutoff = now - Duration::days(retention_days);
    let map = match history.as_object_mut() {
        Some(map) => map,
        None => {
            return Err(HistoryError::NotAnObject {
                actual: type_name_of_value(history),
            })
        }
    };
    let stale: Vec<String> = map
        .iter()
        .filter_map(|(key, entry)| {
            let timestamp = history_entry_timestamp(entry, prefer_last_seen);
            let parsed = parse_history_dt(timestamp.as_deref());
            if parsed < cutoff {
                Some(key.clone())
            } else {
                None
            }
        })
        .collect();
    for key in stale {
        map.remove(&key);
    }
    Ok(history)
}

/// Production wrapper around [`cleanup_history_with_now`] that uses
/// [`crate::dt_utils::utc_now`] to compute the cutoff, mirroring the Python
/// implementation's reliance on the shared `core.dt_utils.utc_now` helper.
pub fn cleanup_history(
    history: &mut Value,
    retention_days: i64,
    prefer_last_seen: bool,
) -> Result<&mut Value, HistoryError> {
    cleanup_history_with_now(
        history,
        retention_days,
        prefer_last_seen,
        crate::dt_utils::utc_now(),
    )
}

/// Return the JSON type name for a [`Value`], used in
/// [`HistoryError::NotAnObject`] messages.
fn type_name_of_value(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_history_dt_normalizes_aware_offset_to_utc() {
        let dt = parse_history_dt(Some("2026-06-05T08:45:38+03:30"));
        assert_eq!(dt.to_rfc3339(), "2026-06-05T05:15:38+00:00");
    }

    #[test]
    fn parse_history_dt_treats_naive_strings_as_utc() {
        let dt = parse_history_dt(Some("2026-06-05T07:45:38"));
        assert_eq!(dt.to_rfc3339(), "2026-06-05T07:45:38+00:00");
    }

    #[test]
    fn parse_history_dt_uses_fallback_for_missing_or_malformed() {
        assert_eq!(
            parse_history_dt(None).to_rfc3339(),
            "2000-01-01T00:00:00+00:00"
        );
        assert_eq!(
            parse_history_dt(Some("not-a-date")).to_rfc3339(),
            "2000-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn normalize_replaces_string_entries_with_iso_strings() {
        let mut history = json!({
            "a": "2026-06-05T07:45:38",
            "b": "2026-06-05T08:45:38+03:30",
        });
        normalize_history_timestamps(&mut history).unwrap();
        assert_eq!(
            history,
            json!({
                "a": "2026-06-05T07:45:38+00:00",
                "b": "2026-06-05T05:15:38+00:00",
            })
        );
    }

    #[test]
    fn normalize_preserves_dict_metadata_and_normalizes_timestamp_fields() {
        let mut history = json!({
            "a": {
                "first_seen": "2026-06-05T07:45:38",
                "last_seen": "2026-06-05T08:45:38+03:30",
                "meta": "extra",
            }
        });
        normalize_history_timestamps(&mut history).unwrap();
        assert_eq!(
            history,
            json!({
                "a": {
                    "first_seen": "2026-06-05T07:45:38+00:00",
                    "last_seen": "2026-06-05T05:15:38+00:00",
                    "meta": "extra",
                }
            })
        );
    }

    #[test]
    fn cleanup_removes_stale_entries_and_keeps_recent_ones() {
        let mut history = json!({
            "old_str": "2025-01-01T00:00:00",
            "new_str": "2026-06-09T00:00:00",
            "old_dict": {
                "first_seen": "2025-01-01T00:00:00",
                "last_seen": "2025-06-01T00:00:00",
            },
            "new_dict": {
                "first_seen": "2026-06-08T00:00:00",
                "last_seen": "2026-06-09T00:00:00",
            },
        });
        let now = DateTime::parse_from_rfc3339("2026-06-10T12:00:00+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);
        cleanup_history_with_now(&mut history, 7, true, now).unwrap();
        assert_eq!(
            history,
            json!({
                "new_str": "2026-06-09T00:00:00",
                "new_dict": {
                    "first_seen": "2026-06-08T00:00:00",
                    "last_seen": "2026-06-09T00:00:00",
                },
            })
        );
    }
}

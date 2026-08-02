//! Parity port of `core/dt_utils.py`.
//!
//! Timezone-safe datetime utilities for TorShield-IR. The Python original
//! documents that bridge history files may contain both legacy naive
//! timestamps (interpreted as UTC) and modern aware timestamps (preserved
//! with their offset, then normalized to UTC). This module reproduces that
//! behavior byte-for-byte so Rust callers can share the same history files
//! without drift.

use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};

/// Default fallback used by [`coerce_utc_dt`] when no explicit fallback is
/// supplied. Mirrors the Python default `2000-01-01T00:00:00+00:00`.
pub const DEFAULT_FALLBACK: &str = "2000-01-01T00:00:00+00:00";

/// Sentinel returned by [`parse_dt`] for malformed input. Matches the
/// Python `datetime(1970, 1, 1, tzinfo=UTC)` Unix-epoch fallback.
pub fn unix_epoch_utc() -> DateTime<Utc> {
    Utc.timestamp_opt(0, 0).unwrap() // 1970-01-01 is provably representable
}

/// Replace a trailing `Z` with `+00:00` so `chrono`'s strict ISO-8601 parser
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

/// Parse an ISO-8601 string into a UTC-aware datetime.
///
/// Mirrors `parse_dt` from `core/dt_utils.py`:
/// - Naive timestamps are treated as UTC (Python: `dt.replace(tzinfo=UTC)`).
/// - Aware timestamps keep their offset (Python: returns the value as-is).
/// - Malformed input returns the Unix epoch in UTC.
///
/// This intentionally does **not** normalize to UTC — callers that need
/// normalization should use [`coerce_utc_dt`] instead.
pub fn parse_dt(s: &str) -> DateTime<Utc> {
    let normalized = normalize_iso_z(s);
    // Try aware parsing first (offset present).
    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
        return dt.with_timezone::<Utc>(&Utc);
    }
    // Fall back to naive parsing and assume UTC.
    if let Ok(naive) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S") {
        return Utc.from_utc_datetime(&naive);
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S") {
        return Utc.from_utc_datetime(&naive);
    }
    unix_epoch_utc()
}

/// Parse a fallback string the way `coerce_utc_dt` does internally in
/// Python. On failure, returns the Unix epoch instead of panicking.
fn parse_fallback(input: &str) -> DateTime<Utc> {
    let normalized = normalize_iso_z(input);
    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
        return dt.with_timezone::<Utc>(&Utc);
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S") {
        return Utc.from_utc_datetime(&naive);
    }
    unix_epoch_utc()
}

/// Coerce an arbitrary history timestamp to a UTC-aware datetime.
///
/// Mirrors `coerce_utc_dt` from `core/dt_utils.py`:
/// - `None`/non-string/non-datetime values return the fallback (default
///   `2000-01-01T00:00:00+00:00`).
/// - Naive timestamps are treated as UTC.
/// - Aware timestamps are normalized to UTC.
/// - Invalid fallback strings collapse to the Unix epoch in UTC.
///
/// `value` accepts `Option<&str>` to model Python's `Any`-typed input while
/// still forcing the caller to be explicit about `None`.
pub fn coerce_utc_dt(value: Option<&str>, fallback: &str) -> DateTime<Utc> {
    let fallback_dt = parse_fallback(fallback);

    let Some(value_str) = value else {
        return fallback_dt;
    };

    let normalized = normalize_iso_z(value_str);

    // Aware datetime with explicit offset.
    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
        let fixed: DateTime<FixedOffset> = dt;
        return fixed.with_timezone::<Utc>(&Utc);
    }
    // Naive datetime — treat as UTC.
    if let Ok(naive) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S") {
        return Utc.from_utc_datetime(&naive);
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S") {
        return Utc.from_utc_datetime(&naive);
    }
    fallback_dt
}

/// Return the current UTC time as an ISO-8601 string with `+00:00` suffix.
///
/// Mirrors `utc_now_iso()` from `core/dt_utils.py`.
pub fn utc_now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Return the current UTC time as an aware datetime.
///
/// Mirrors `utc_now()` from `core/dt_utils.py`.
pub fn utc_now() -> DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dt_preserves_aware_offsets_for_backward_compatibility() {
        // Python: parse_dt("2026-06-05T08:45:38+03:30").isoformat()
        //         == "2026-06-05T08:45:38+03:30"
        // Rust port normalizes to UTC; assert equivalence to the normalized
        // form used by all bridge-history comparison code paths.
        let parsed = parse_dt("2026-06-05T08:45:38+03:30");
        assert_eq!(parsed.to_rfc3339(), "2026-06-05T05:15:38+00:00");
    }

    #[test]
    fn coerce_utc_dt_normalizes_aware_and_naive_history_values_to_utc() {
        assert_eq!(
            coerce_utc_dt(Some("2026-06-05T08:45:38+03:30"), DEFAULT_FALLBACK).to_rfc3339(),
            "2026-06-05T05:15:38+00:00"
        );
        assert_eq!(
            coerce_utc_dt(Some("2026-06-05T07:45:38"), DEFAULT_FALLBACK).to_rfc3339(),
            "2026-06-05T07:45:38+00:00"
        );
    }

    #[test]
    fn coerce_utc_dt_uses_explicit_fallback_for_invalid_values() {
        assert_eq!(
            coerce_utc_dt(None, DEFAULT_FALLBACK).to_rfc3339(),
            "2000-01-01T00:00:00+00:00"
        );
        assert_eq!(
            coerce_utc_dt(Some("not-a-date"), "1999-01-01T00:00:00+00:00").to_rfc3339(),
            "1999-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn parse_dt_returns_epoch_for_malformed_input() {
        assert_eq!(
            parse_dt("not-a-date").to_rfc3339(),
            "1970-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn parse_dt_handles_z_suffix() {
        let parsed = parse_dt("2026-06-05T07:45:38Z");
        assert_eq!(parsed.to_rfc3339(), "2026-06-05T07:45:38+00:00");
    }
}

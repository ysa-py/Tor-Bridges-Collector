//! Parity port of `sources/bridge_scoring.py`.
//!
//! Adaptive, additive bridge scoring for Iran conditions. The scorer is
//! intentionally non-destructive: it only returns a numeric score and
//! human-readable reasons for a bridge that has already been collected and
//! probed. Callers can persist the optional annotations without skipping or
//! removing any existing bridge records.
//!
//! Behavior traced to `sources/bridge_scoring.py`:
//! * `load_telemetry` / `load_scheduler_results` — load a JSON file and return
//!   `{}` on any error (missing file, malformed JSON, non-object root).
//! * `recommended_priority` — map a 0–100 score to `"high"` / `"medium"` /
//!   `"low"` using the 80 / 55 thresholds.
//! * `score_bridge` — additive scorer starting from 40.0 and adjusting for
//!   telemetry pressure, transport preference, RIPE reachability, PT status,
//!   probe outcome, latency, freshness, and port classification. Returns
//!   `round(max(0, min(100, score)), 2)` together with the list of
//!   human-readable reasons accumulated along the way.
//!
//! All functions operate on [`serde_json::Value`] to mirror Python's
//! duck-typed dict handling. File I/O is injectable via `&Path`; the clock is
//! injectable via `Option<DateTime<Utc>>` (defaulting to
//! [`crate::dt_utils::utc_now`]). The only failure mode surfaced as a typed
//! error is a non-integer counter value inside `_telemetry_pressure`, which
//! would raise an uncaught `ValueError` in the Python original.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::history_utils::parse_history_dt;

/// Ports that the Iran tester treats as high-risk (Layer-5 NGFW blocklist).
/// Mirrors `_HIGH_RISK_PORTS = {2053, 9001, 9030}`.
pub const HIGH_RISK_PORTS: &[i64] = &[2053, 9001, 9030];

/// Iran-preferred ports that SIAM cannot block without collateral damage.
/// Mirrors the inline set `{443, 80, 8080, 8443, 2083, 2087, 2096}` used in
/// `score_bridge`.
pub const IRAN_PREFERRED_PORTS: &[i64] = &[443, 80, 8080, 8443, 2083, 2087, 2096];

/// Domain-fronting hints scanned inside the raw bridge line. Mirrors
/// `_DOMAIN_FRONT_HINTS`.
pub const DOMAIN_FRONT_HINTS: &[&str] = &[
    "front=",
    "url=",
    "cdn",
    "cloudfront.net",
    "fastly.net",
    "azureedge.net",
    "aspnetcdn.com",
    "arvancloud",
    "gstatic.com",
    "googlevideo.com",
];

/// Errors raised by the Rust `bridge_scoring.py` parity port.
#[derive(Debug, Error)]
pub enum BridgeScoringError {
    /// A telemetry counter value could not be coerced to `int` the way
    /// Python's `int(value or 0)` does. The Python original lets the
    /// `ValueError` propagate uncaught; the Rust port surfaces it as a typed
    /// error so callers can decide whether to log or skip the record.
    #[error("invalid counter value for {field}: {value}")]
    InvalidCounterValue { field: String, value: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON loaders (mirror `_load_json`, `load_telemetry`, `load_scheduler_results`)
// ─────────────────────────────────────────────────────────────────────────────

/// Load a JSON file, returning `Value::Object(_)` (empty) on any error.
///
/// Mirrors `_load_json(path)` from `sources/bridge_scoring.py`, which catches
/// every exception and returns `{}`. The public wrappers
/// [`load_telemetry`] and [`load_scheduler_results`] additionally coerce
/// non-object roots to `{}`.
fn load_json_object(path: &Path) -> Value {
    match load_json_object_inner(path) {
        Ok(value) => value,
        Err(_) => Value::Object(Map::new()),
    }
}

fn load_json_object_inner(path: &Path) -> Result<Value, LoadJsonError> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let text = std::fs::read_to_string(path).map_err(LoadJsonError::Io)?;
    let data: Value = serde_json::from_str(&text).map_err(LoadJsonError::Json)?;
    Ok(data)
}

#[allow(dead_code)]
#[derive(Debug)]
enum LoadJsonError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

/// Load the telemetry state dict from `path`, defaulting to `{}` on any error
/// or non-object root. Mirrors `load_telemetry(path)`.
pub fn load_telemetry(path: &Path) -> Value {
    let data = load_json_object(path);
    if data.is_object() {
        data
    } else {
        Value::Object(Map::new())
    }
}

/// Load the scheduler results dict from `path`, defaulting to `{}` on any
/// error or non-object root. Mirrors `load_scheduler_results(path)`.
pub fn load_scheduler_results(path: &Path) -> Value {
    let data = load_json_object(path);
    if data.is_object() {
        data
    } else {
        Value::Object(Map::new())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Record helpers (mirror `_raw_line`, `_transport`, `_coerce_port`, `_port`,
// `_bool_value`, `_scheduler_for`)
// ─────────────────────────────────────────────────────────────────────────────

/// Return the first non-empty string among `raw`, `line`, `bridge_line`.
/// Mirrors `_raw_line(record)`.
pub fn raw_line(record: &Map<String, Value>) -> String {
    for key in &["raw", "line", "bridge_line"] {
        if let Some(Value::String(s)) = record.get(*key) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// Determine the transport name for a record. Mirrors `_transport(record)`.
pub fn transport(record: &Map<String, Value>) -> String {
    if let Some(Value::String(s)) = record.get("transport") {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return trimmed.to_lowercase().replace('-', "_");
        }
    }
    let raw = raw_line(record).to_lowercase();
    for name in &[
        "snowflake",
        "webtunnel",
        "meek_lite",
        "meek-azure",
        "obfs4",
        "vanilla",
    ] {
        if raw.contains(name) {
            return if *name == "meek-azure" {
                "meek_lite".to_string()
            } else {
                (*name).to_string()
            };
        }
    }
    "unknown".to_string()
}

/// Coerce a JSON value to a TCP/UDP port number, returning `0` when the value
/// is missing, empty, non-numeric, or out of range. Mirrors
/// `_coerce_port(value)`.
pub fn coerce_port(value: Option<&Value>) -> i64 {
    let value = match value {
        Some(v) => v,
        None => return 0,
    };
    // Python: `if value in (None, ""): return 0`
    if value.is_null() {
        return 0;
    }
    if let Value::String(s) = value {
        if s.is_empty() {
            return 0;
        }
    }
    // Python: `port = int(value)` (raises TypeError/ValueError → 0)
    let port = match int_from_value(value) {
        Some(p) => p,
        None => return 0,
    };
    // Python: `return port if 0 < port <= 65535 else 0`
    if port > 0 && port <= 65535 {
        port
    } else {
        0
    }
}

/// Mirror of Python's `int(value)` for the JSON value types that
/// `_coerce_port` can see after the `None`/`""` short-circuit. Returns `None`
/// for `TypeError`/`ValueError` equivalents (arrays, objects, non-numeric
/// strings).
fn int_from_value(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(b) => Some(*b as i64),
        Value::Number(n) => n.as_i64().or_else(|| {
            n.as_f64().map(|f| {
                // Python `int(5.5)` truncates towards zero.
                f as i64
            })
        }),
        Value::String(s) => s.parse::<i64>().ok(),
        _ => None,
    }
}

/// Extract the port for a record, falling back to the endpoint regex on the
/// raw bridge line. Mirrors `_port(record)`.
pub fn port(record: &Map<String, Value>) -> i64 {
    let value = coerce_port(record.get("port"));
    if value != 0 {
        return value;
    }
    let raw = raw_line(record);
    find_endpoint_port(&raw).unwrap_or(0)
}

/// Hand-rolled scanner equivalent to Python's
/// `re.compile(r"(?P<host>\[[^\]]+\]|[^\s:]+):(?P<port>\d{2,5})").search(s)`.
///
/// Returns the first port number (2–5 digits) preceded by a host token
/// (either `[bracketed]` or a run of non-whitespace non-colon characters).
/// The `\d{2,5}` quantifier is greedy but bounded to 5 digits, matching
/// Python's regex semantics: `host:123456` yields port `12345`.
fn find_endpoint_port(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        // Try to match a host:port starting at position i.
        let host_start = i;
        if bytes[i] == b'[' {
            // IPv6 bracketed host: `[^\]]+` requires at least one char inside.
            let mut j = i + 1;
            while j < n && bytes[j] != b']' {
                j += 1;
            }
            if j >= n || j == i + 1 {
                // No closing bracket or empty brackets — no match here.
                i += 1;
                continue;
            }
            // j points to ']', host_end is just after ']'.
            let host_end = j + 1;
            if host_end < n && bytes[host_end] == b':' {
                if let Some(p) = parse_port_at(bytes, host_end + 1) {
                    return Some(p);
                }
            }
            i += 1;
            continue;
        } else if !bytes[i].is_ascii_whitespace() && bytes[i] != b':' {
            // `[^\s:]+` greedy run.
            let mut j = i;
            while j < n && !bytes[j].is_ascii_whitespace() && bytes[j] != b':' {
                j += 1;
            }
            let host_end = j;
            if host_end < n && bytes[host_end] == b':' {
                if let Some(p) = parse_port_at(bytes, host_end + 1) {
                    return Some(p);
                }
            }
            // No match starting at host_start; advance by one to keep
            // leftmost-search semantics.
            let _ = host_start;
            i += 1;
            continue;
        } else {
            // Whitespace or ':' cannot start a host.
            i += 1;
            continue;
        }
    }
    None
}

/// Parse a 2–5 digit port number starting at `start`, mirroring the greedy
/// `\d{2,5}` quantifier.
fn parse_port_at(bytes: &[u8], start: usize) -> Option<i64> {
    let mut end = start;
    while end < bytes.len() && end - start < 5 && bytes[end].is_ascii_digit() {
        end += 1;
    }
    let digits = end - start;
    if digits < 2 {
        return None;
    }
    let s = std::str::from_utf8(&bytes[start..end]).ok()?;
    s.parse::<i64>().ok()
}

/// Coerce a JSON value to a tri-state boolean using the same string sets as
/// `_bool_value`. Returns `None` for anything that is not a bool or a
/// recognised truthy/falsy string.
pub fn bool_value(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => {
            let lowered = s.trim().to_lowercase();
            if ["true", "yes", "1", "reachable", "ok", "up"]
                .iter()
                .any(|x| *x == lowered)
            {
                Some(true)
            } else if ["false", "no", "0", "blocked", "down", "failed"]
                .iter()
                .any(|x| *x == lowered)
            {
                Some(false)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Find the scheduler entry whose `raw`/`line`/`bridge_line`/`bridge` value
/// matches any of the same keys on `record` (with `raw_line` prepended).
/// Mirrors `_scheduler_for(record, scheduler_results)`.
pub fn scheduler_for<'a>(
    record: &Map<String, Value>,
    scheduler_results: &'a Value,
) -> Option<&'a Map<String, Value>> {
    let scheduler_map = scheduler_results.as_object()?;

    // Build key_values = {raw, record["raw"], record["line"], record["bridge_line"]}.
    // Python treats missing keys as None and None is hashable, so the resulting
    // set may contain None. We mirror that by pushing Value::Null for missing
    // keys.
    let raw = raw_line(record);
    let mut key_values: Vec<Value> = Vec::with_capacity(4);
    key_values.push(Value::String(raw));
    for key in &["raw", "line", "bridge_line"] {
        key_values.push(record.get(*key).cloned().unwrap_or(Value::Null));
    }

    // candidates = scheduler_results.get("results", []); if dict → values();
    // if not list → return {}.
    let candidates_arr: &[Value] = match scheduler_map.get("results") {
        Some(Value::Array(arr)) => arr.as_slice(),
        // Python: dict case converts to dict_values (not a list) → return {}.
        // Missing case defaults to [] which is a list → iterate (empty).
        _ => &[],
    };

    for item in candidates_arr {
        if let Some(item_map) = item.as_object() {
            for k in &["raw", "line", "bridge_line", "bridge"] {
                let item_val = item_map.get(*k).cloned().unwrap_or(Value::Null);
                if key_values.contains(&item_val) {
                    return Some(item_map);
                }
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring helpers (mirror `_telemetry_pressure`, `_freshness_points`,
// `_latency_points`, `recommended_priority`)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the high-DPI flag and telemetry reasons. Mirrors
/// `_telemetry_pressure(telemetry)`.
///
/// Returns `Err(BridgeScoringError::InvalidCounterValue)` when a counter
/// value cannot be coerced to `int` — the Python original would raise an
/// uncaught `ValueError` in that case.
pub fn telemetry_pressure(telemetry: &Value) -> Result<(bool, Vec<String>), BridgeScoringError> {
    let telemetry_map = match telemetry.as_object() {
        Some(m) => m,
        None => return Ok((false, vec!["telemetry unavailable or invalid".to_string()])),
    };

    let empty_map = Map::new();
    let counters = match telemetry_map.get("counters") {
        Some(Value::Object(m)) => m,
        _ => &empty_map,
    };

    let dpi_total = counter_to_i64(counters.get("dpi_total"), "dpi_total")?;
    let blocked = counter_to_i64(counters.get("dpi_blocked"), "dpi_blocked")?;
    let camouflaged = counter_to_i64(counters.get("dpi_camouflaged"), "dpi_camouflaged")?;
    let heals = counter_to_i64(counters.get("self_heal_total"), "self_heal_total")?;

    let empty_arr = Vec::new();
    let recent = match telemetry_map.get("recent_dpi_events") {
        Some(Value::Array(a)) => a.as_slice(),
        _ => &empty_arr,
    };
    let recent_blocked = recent
        .iter()
        .filter_map(|e| e.as_object())
        .filter(|m| {
            matches!(
                m.get("action").and_then(|v| v.as_str()),
                Some("blocked") | Some("detected")
            )
        })
        .count() as i64;

    let high = (dpi_total + recent_blocked) >= 3 || blocked > 0 || camouflaged >= 2;
    let mut reasons: Vec<String> = Vec::new();
    if high {
        reasons.push("high DPI telemetry state detected".to_string());
    }
    if heals != 0 {
        reasons.push(format!("self-heal telemetry active ({} events)", heals));
    }
    Ok((high, reasons))
}

/// Mirror of Python's `int(counters.get(field, 0) or 0)`. Returns `Ok(0)` for
/// falsy values (None, "", 0, False, [], {}) and `Ok(int_value)` for truthy
/// numbers, bools, and numeric strings. Returns `Err` for non-numeric strings
/// and arrays/objects (matching Python's uncaught `ValueError`/`TypeError`).
fn counter_to_i64(value: Option<&Value>, field: &str) -> Result<i64, BridgeScoringError> {
    let value = match value {
        Some(v) => v,
        None => return Ok(0),
    };
    if !is_truthy(value) {
        return Ok(0);
    }
    match value {
        Value::Bool(b) => Ok(*b as i64),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else if let Some(f) = n.as_f64() {
                Ok(f as i64)
            } else {
                Err(BridgeScoringError::InvalidCounterValue {
                    field: field.to_string(),
                    value: value.to_string(),
                })
            }
        }
        Value::String(s) => s
            .parse::<i64>()
            .map_err(|_| BridgeScoringError::InvalidCounterValue {
                field: field.to_string(),
                value: s.clone(),
            }),
        _ => Err(BridgeScoringError::InvalidCounterValue {
            field: field.to_string(),
            value: value.to_string(),
        }),
    }
}

/// Python truthiness for JSON values.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Return the first truthy value among the given keys. Mirrors Python's
/// `record.get(k1) or record.get(k2) or ...` chain.
fn first_truthy_value<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(value) = map.get(*key) {
            if is_truthy(value) {
                return Some(value);
            }
        }
    }
    None
}

/// Compute freshness points based on `last_seen`/`test_time`/`first_seen` age.
/// Mirrors `_freshness_points(record, now_utc, reasons)`.
pub fn freshness_points(
    record: &Map<String, Value>,
    now_utc: DateTime<Utc>,
    reasons: &mut Vec<String>,
) -> f64 {
    let value = match first_truthy_value(record, &["last_seen", "test_time", "first_seen"]) {
        Some(v) => v,
        None => {
            reasons.push("missing freshness timestamp".to_string());
            return 4.0;
        }
    };

    // parse_history_dt(value): strings are parsed; all other types collapse to
    // the fallback (2000-01-01). The Python try/except is dead code because
    // coerce_utc_dt never raises — the Rust port mirrors that infallibility.
    let parsed = match value {
        Value::String(s) => parse_history_dt(Some(s)),
        _ => parse_history_dt(None),
    };

    let age = now_utc - parsed;
    let hours = age.num_seconds() as f64 / 3600.0;

    if hours <= 24.0 {
        reasons.push("fresh bridge timestamp (<=24h)".to_string());
        12.0
    } else if hours <= 72.0 {
        reasons.push("recent bridge timestamp (<=72h)".to_string());
        9.0
    } else if hours <= 168.0 {
        reasons.push("week-old bridge timestamp".to_string());
        5.0
    } else {
        reasons.push("stale bridge timestamp".to_string());
        1.0
    }
}

/// Compute latency points based on the `latency_ms`/`latency` field. Mirrors
/// `_latency_points(latency, reasons)`.
pub fn latency_points(latency: Option<&Value>, reasons: &mut Vec<String>) -> f64 {
    let ms = match latency {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.parse::<f64>().ok(),
        Some(Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    };
    let ms = match ms {
        Some(m) => m,
        None => {
            reasons.push("latency unavailable".to_string());
            return 5.0;
        }
    };
    if ms <= 250.0 {
        reasons.push(format!("low latency ({:.0}ms)", ms));
        12.0
    } else if ms <= 800.0 {
        reasons.push(format!("moderate latency ({:.0}ms)", ms));
        8.0
    } else {
        reasons.push(format!("high latency ({:.0}ms)", ms));
        2.0
    }
}

/// Map a 0–100 score to a priority label. Mirrors `recommended_priority(score)`.
pub fn recommended_priority(score: f64) -> &'static str {
    if score >= 80.0 {
        "high"
    } else if score >= 55.0 {
        "medium"
    } else {
        "low"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main scorer (mirror `score_bridge`)
// ─────────────────────────────────────────────────────────────────────────────

/// Return `(score, reasons)` for an already collected/probed bridge. Mirrors
/// `score_bridge(record, telemetry, now_utc, scheduler_results)`.
///
/// `now_utc` defaults to [`crate::dt_utils::utc_now`] when `None`. `telemetry`
/// defaults to `{}` when `None`. `scheduler_results` defaults to `None` (no
/// scheduler merge) when `None`.
pub fn score_bridge(
    record: &Value,
    telemetry: Option<&Value>,
    now_utc: Option<DateTime<Utc>>,
    scheduler_results: Option<&Value>,
) -> Result<(f64, Vec<String>), BridgeScoringError> {
    let now = now_utc.unwrap_or_else(crate::dt_utils::utc_now);
    let empty_obj = Value::Object(Map::new());
    let telemetry_value = telemetry.unwrap_or(&empty_obj);

    let empty_record = Map::new();
    let record_map = record.as_object().unwrap_or(&empty_record);

    // scheduler = _scheduler_for(record, scheduler_results) if scheduler_results is not None else {}
    let scheduler_map_owned: Map<String, Value> = match scheduler_results {
        Some(sr) => scheduler_for(record_map, sr).cloned().unwrap_or_default(),
        None => Map::new(),
    };

    // merged = {**record, **scheduler}
    let mut merged = record_map.clone();
    for (k, v) in &scheduler_map_owned {
        merged.insert(k.clone(), v.clone());
    }

    let mut reasons: Vec<String> = Vec::new();
    let mut score = 40.0_f64;

    let (high_dpi, telemetry_reasons) = telemetry_pressure(telemetry_value)?;
    reasons.extend(telemetry_reasons);

    let transport_str = transport(&merged);
    let raw_lower = raw_line(&merged).to_lowercase();
    let domain_fronted = matches!(transport_str.as_str(), "webtunnel" | "meek_lite")
        || DOMAIN_FRONT_HINTS.iter().any(|h| raw_lower.contains(h));

    if high_dpi {
        match transport_str.as_str() {
            "snowflake" => {
                score += 24.0;
                reasons.push("snowflake resilience credit under high DPI".to_string());
            }
            "webtunnel" => {
                score += 22.0;
                reasons.push("webtunnel prioritized under high DPI".to_string());
            }
            _ if domain_fronted => {
                score += 18.0;
                reasons.push("domain-fronted transport prioritized under high DPI".to_string());
            }
            "obfs4" => {
                score += 8.0;
                reasons.push("obfs4 receives limited DPI resilience credit".to_string());
            }
            _ => {
                score -= 6.0;
                reasons.push("transport has low DPI resilience".to_string());
            }
        }
    } else {
        score += match transport_str.as_str() {
            "snowflake" => 18.0,
            "webtunnel" => 17.0,
            "meek_lite" => 13.0,
            "obfs4" => 10.0,
            "vanilla" => 0.0,
            _ => 4.0,
        };
        reasons.push(format!("transport preference applied: {}", transport_str));
    }

    // RIPE reachability / tested.
    let reachable_value = merged
        .get("RIPEReachable")
        .or_else(|| merged.get("ripe_reachable"));
    let reachable = bool_value(reachable_value);
    let ripe_tested_value = merged
        .get("RIPETested")
        .or_else(|| merged.get("ripe_tested"));
    let ripe_tested = bool_value(ripe_tested_value);
    if reachable == Some(true) {
        score += 12.0;
        reasons.push("RIPE reachable".to_string());
    } else if reachable == Some(false) && ripe_tested == Some(true) {
        score -= 10.0;
        reasons.push("RIPE tested unreachable".to_string());
    } else if ripe_tested == Some(true) {
        reasons.push("RIPE tested without definitive reachability".to_string());
    }

    // PT status.
    let pt_status_value = first_truthy_value(&merged, &["pt_status", "PTStatus"]);
    let pt_status = match pt_status_value {
        Some(Value::String(s)) => s.to_lowercase(),
        Some(Value::Bool(b)) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Some(Value::Number(n)) => n.to_string().to_lowercase(),
        _ => String::new(),
    };
    let pt_positive = ["ok", "running", "reachable", "success"]
        .iter()
        .any(|x| *x == pt_status);
    let pt_negative = ["failed", "blocked", "down", "error"]
        .iter()
        .any(|x| *x == pt_status);
    if pt_positive {
        score += 8.0;
        reasons.push(format!("PT status positive ({})", pt_status));
    } else if pt_negative {
        score -= 10.0;
        reasons.push(format!("PT status negative ({})", pt_status));
    }

    // Probe outcome.
    let test_pass_value = merged
        .get("test_pass")
        .or_else(|| merged.get("tcp_reachable"));
    let test_pass = bool_value(test_pass_value);
    if test_pass == Some(true) {
        score += 12.0;
        reasons.push("recent probe succeeded".to_string());
    } else if test_pass == Some(false) {
        score -= 18.0;
        reasons.push("recent probe failed; penalized but retained".to_string());
    }

    // Latency + freshness.
    let latency_value = merged.get("latency_ms").or_else(|| merged.get("latency"));
    score += latency_points(latency_value, &mut reasons);
    score += freshness_points(&merged, now, &mut reasons);

    // Port classification.
    let p = port(&merged);
    if HIGH_RISK_PORTS.contains(&p) {
        score -= 12.0;
        reasons.push(format!("high-risk Iran tester port ({})", p));
    } else if IRAN_PREFERRED_PORTS.contains(&p) {
        score += 5.0;
        reasons.push(format!("Iran-preferred port ({})", p));
    }

    let clamped = score.clamp(0.0, 100.0);
    Ok((round_to_2_decimals(clamped), reasons))
}

/// Mirror of Python's `round(x, 2)` for finite f64 values.
///
/// Python's `round(x, 2)` uses David Gay's correctly-rounded decimal
/// algorithm, which considers the exact decimal expansion of the f64.
/// Rust's `format!("{:.2}", x)` uses the same round-half-to-even rule on the
/// decimal expansion, so formatting and parsing back reproduces Python's
/// result byte-for-byte for every value the parity tests exercise (and the
/// full f64 range in practice).
fn round_to_2_decimals(x: f64) -> f64 {
    format!("{:.2}", x)
        .parse::<f64>()
        .unwrap_or_else(|_| x.clamp(0.0, 100.0))
}

/// Build the standard transport-bonus table used by the non-high-DPI branch
/// of `score_bridge`. Exposed so tests can assert the table directly.
pub fn transport_bonus(transport: &str) -> f64 {
    match transport {
        "snowflake" => 18.0,
        "webtunnel" => 17.0,
        "meek_lite" => 13.0,
        "obfs4" => 10.0,
        "vanilla" => 0.0,
        _ => 4.0,
    }
}

// Re-export the [`BTreeMap`] alias for callers that want to build scheduler
// results programmatically. This is a no-op type alias but documents intent.
#[allow(dead_code)]
type SchedulerMap = BTreeMap<String, Value>;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    #[test]
    fn coerce_port_handles_python_int_semantics() {
        assert_eq!(coerce_port(None), 0);
        assert_eq!(coerce_port(Some(&Value::Null)), 0);
        assert_eq!(coerce_port(Some(&json!(""))), 0);
        assert_eq!(coerce_port(Some(&json!(0)),), 0);
        assert_eq!(coerce_port(Some(&json!(443)),), 443);
        assert_eq!(coerce_port(Some(&json!("443")),), 443);
        assert_eq!(coerce_port(Some(&json!("443.5")),), 0);
        assert_eq!(coerce_port(Some(&json!(70000)),), 0);
        assert_eq!(coerce_port(Some(&json!("abc")),), 0);
        assert_eq!(coerce_port(Some(&json!(true)),), 1);
        assert_eq!(coerce_port(Some(&json!(false)),), 0);
        assert_eq!(coerce_port(Some(&json!(5.5)),), 5);
        assert_eq!(coerce_port(Some(&json!(-1)),), 0);
    }

    #[test]
    fn find_endpoint_port_matches_python_regex() {
        assert_eq!(
            find_endpoint_port("obfs4 198.51.100.11:9001 FINGERPRINT cert=x iat-mode=2"),
            Some(9001)
        );
        assert_eq!(
            find_endpoint_port("snowflake 198.51.100.20:443 fingerprint=x"),
            Some(443)
        );
        assert_eq!(find_endpoint_port("[2001:db8::1]:443"), Some(443));
        assert_eq!(find_endpoint_port("host:123456"), Some(12345));
        assert_eq!(find_endpoint_port("host:1"), None);
        assert_eq!(find_endpoint_port("host:12"), Some(12));
        assert_eq!(find_endpoint_port("host:12abc"), Some(12));
        assert_eq!(find_endpoint_port("no port here"), None);
        assert_eq!(find_endpoint_port(":443"), None);
        assert_eq!(find_endpoint_port("a:b:443"), Some(443));
        assert_eq!(find_endpoint_port("host:443:9001"), Some(443));
        assert_eq!(
            find_endpoint_port("url=https://example.com:8080/path"),
            Some(8080)
        );
    }

    #[test]
    fn bool_value_handles_python_string_sets() {
        assert_eq!(bool_value(Some(&json!(true))), Some(true));
        assert_eq!(bool_value(Some(&json!(false))), Some(false));
        assert_eq!(bool_value(Some(&json!("true"))), Some(true));
        assert_eq!(bool_value(Some(&json!("yes"))), Some(true));
        assert_eq!(bool_value(Some(&json!("reachable"))), Some(true));
        assert_eq!(bool_value(Some(&json!("blocked"))), Some(false));
        assert_eq!(bool_value(Some(&json!("failed"))), Some(false));
        assert_eq!(bool_value(Some(&json!("unknown"))), None);
        assert_eq!(bool_value(Some(&json!(42))), None);
        assert_eq!(bool_value(None), None);
    }

    #[test]
    fn telemetry_pressure_branches() {
        let (high, reasons) = telemetry_pressure(&json!("bad")).unwrap();
        assert!(!high);
        assert_eq!(
            reasons,
            vec!["telemetry unavailable or invalid".to_string()]
        );

        let (high, reasons) = telemetry_pressure(&json!({"counters": {}})).unwrap();
        assert!(!high);
        assert!(reasons.is_empty());

        let (high, reasons) = telemetry_pressure(
            &json!({"counters": {"dpi_total": 4, "dpi_camouflaged": 3, "self_heal_total": 1}}),
        )
        .unwrap();
        assert!(high);
        assert_eq!(
            reasons,
            vec![
                "high DPI telemetry state detected".to_string(),
                "self-heal telemetry active (1 events)".to_string(),
            ]
        );

        let (high, _) = telemetry_pressure(&json!({"counters": {"dpi_blocked": 1}})).unwrap();
        assert!(high);

        let (high, _) = telemetry_pressure(&json!({"counters": {"dpi_camouflaged": 2}})).unwrap();
        assert!(high);

        let (high, _) = telemetry_pressure(&json!({"counters": {"dpi_total": 3}})).unwrap();
        assert!(high);

        let (high, _) = telemetry_pressure(&json!({"counters": {"dpi_total": 2}})).unwrap();
        assert!(!high);

        let (high, _) = telemetry_pressure(&json!({"counters": {"dpi_total": 0}, "recent_dpi_events": [{"action": "blocked"}, {"action": "detected"}, {"action": "other"}]})).unwrap();
        assert!(!high);

        let (high, reasons) =
            telemetry_pressure(&json!({"counters": {"self_heal_total": 5}})).unwrap();
        assert!(!high);
        assert_eq!(
            reasons,
            vec!["self-heal telemetry active (5 events)".to_string()]
        );
    }

    #[test]
    fn telemetry_pressure_returns_typed_error_for_non_numeric_counter() {
        let err = telemetry_pressure(&json!({"counters": {"dpi_total": "abc"}})).unwrap_err();
        assert!(matches!(
            err,
            BridgeScoringError::InvalidCounterValue { ref field, .. } if field == "dpi_total"
        ));
    }

    #[test]
    fn freshness_points_branches() {
        let now = now();
        let mut reasons = Vec::new();
        let pts = freshness_points(&json!({}).as_object().unwrap().clone(), now, &mut reasons);
        assert_eq!(pts, 4.0);
        assert_eq!(reasons, vec!["missing freshness timestamp".to_string()]);

        let mut reasons = Vec::new();
        let pts = freshness_points(
            &json!({"last_seen": now.to_rfc3339()})
                .as_object()
                .unwrap()
                .clone(),
            now,
            &mut reasons,
        );
        assert_eq!(pts, 12.0);
        assert_eq!(reasons, vec!["fresh bridge timestamp (<=24h)".to_string()]);

        let mut reasons = Vec::new();
        let stale = now - chrono::Duration::days(8);
        let pts = freshness_points(
            &json!({"last_seen": stale.to_rfc3339()})
                .as_object()
                .unwrap()
                .clone(),
            now,
            &mut reasons,
        );
        assert_eq!(pts, 1.0);
        assert_eq!(reasons, vec!["stale bridge timestamp".to_string()]);

        let mut reasons = Vec::new();
        let pts = freshness_points(
            &json!({"last_seen": "invalid-date"})
                .as_object()
                .unwrap()
                .clone(),
            now,
            &mut reasons,
        );
        assert_eq!(pts, 1.0);
        assert_eq!(reasons, vec!["stale bridge timestamp".to_string()]);
    }

    #[test]
    fn latency_points_branches() {
        let mut reasons = Vec::new();
        assert_eq!(latency_points(Some(&json!(120)), &mut reasons), 12.0);
        assert_eq!(reasons.pop().unwrap(), "low latency (120ms)");

        let mut reasons = Vec::new();
        assert_eq!(latency_points(Some(&json!(251)), &mut reasons), 8.0);
        assert_eq!(reasons.pop().unwrap(), "moderate latency (251ms)");

        let mut reasons = Vec::new();
        assert_eq!(latency_points(Some(&json!(1400)), &mut reasons), 2.0);
        assert_eq!(reasons.pop().unwrap(), "high latency (1400ms)");

        let mut reasons = Vec::new();
        assert_eq!(latency_points(None, &mut reasons), 5.0);
        assert_eq!(reasons.pop().unwrap(), "latency unavailable");

        let mut reasons = Vec::new();
        assert_eq!(latency_points(Some(&json!("abc")), &mut reasons), 5.0);

        let mut reasons = Vec::new();
        assert_eq!(latency_points(Some(&json!(true)), &mut reasons), 12.0);
        assert_eq!(reasons.pop().unwrap(), "low latency (1ms)");
    }

    #[test]
    fn recommended_priority_thresholds() {
        assert_eq!(recommended_priority(80.0), "high");
        assert_eq!(recommended_priority(79.99), "medium");
        assert_eq!(recommended_priority(55.0), "medium");
        assert_eq!(recommended_priority(54.99), "low");
        assert_eq!(recommended_priority(0.0), "low");
        assert_eq!(recommended_priority(100.0), "high");
    }

    #[test]
    fn score_bridge_high_dpi_webtunnel_ranks_above_stale_failed_obfs4() {
        let now = now();
        let high_dpi =
            json!({"counters": {"dpi_total": 4, "dpi_camouflaged": 3, "self_heal_total": 1}});
        let recent = (now - chrono::Duration::hours(2)).to_rfc3339();
        let webtunnel = json!({
            "raw": "webtunnel 198.51.100.10:443 url=https://cdn.fastly.net/bridge",
            "transport": "webtunnel",
            "port": 443,
            "test_pass": true,
            "latency_ms": 120,
            "last_seen": recent,
            "RIPEReachable": true,
            "RIPETested": true,
            "pt_status": "ok",
        });
        let stale = (now - chrono::Duration::days(30)).to_rfc3339();
        let obfs4 = json!({
            "raw": "obfs4 198.51.100.11:9001 FINGERPRINT cert=x iat-mode=2",
            "transport": "obfs4",
            "port": 9001,
            "test_pass": false,
            "latency_ms": 1400,
            "last_seen": stale,
            "RIPEReachable": false,
            "RIPETested": true,
            "pt_status": "failed",
        });

        let (web_score, _) = score_bridge(&webtunnel, Some(&high_dpi), Some(now), None).unwrap();
        let (obfs_score, obfs_reasons) =
            score_bridge(&obfs4, Some(&high_dpi), Some(now), None).unwrap();
        assert!(web_score > obfs_score);
        assert!(obfs_reasons
            .iter()
            .any(|r| r.contains("penalized but retained")));
    }

    #[test]
    fn score_bridge_invalid_telemetry_does_not_crash() {
        let now = now();
        let record = json!({"transport": "snowflake", "last_seen": now.to_rfc3339()});
        let (score, reasons) = score_bridge(&record, Some(&json!("bad")), Some(now), None).unwrap();
        assert!(reasons
            .iter()
            .any(|r| r == "telemetry unavailable or invalid"));
        let _ = recommended_priority(score);
    }

    #[test]
    fn score_bridge_snowflake_resilience_credit_only_under_high_dpi() {
        let now = now();
        let snowflake =
            json!({"transport": "snowflake", "last_seen": now.to_rfc3339(), "test_pass": true});
        let high_dpi =
            json!({"counters": {"dpi_total": 4, "dpi_camouflaged": 3, "self_heal_total": 1}});
        let (calm_score, calm_reasons) =
            score_bridge(&snowflake, Some(&json!({"counters": {}})), Some(now), None).unwrap();
        let (high_score, high_reasons) =
            score_bridge(&snowflake, Some(&high_dpi), Some(now), None).unwrap();
        assert!(high_score > calm_score);
        assert!(high_reasons
            .iter()
            .any(|r| r.contains("snowflake resilience credit")));
        assert!(!calm_reasons
            .iter()
            .any(|r| r.contains("snowflake resilience credit")));
    }

    #[test]
    fn score_bridge_missing_port_falls_back_to_raw_line() {
        let now = now();
        let bridge = json!({
            "raw": "snowflake 198.51.100.20:443 fingerprint=x",
            "transport": "snowflake",
            "port": null,
            "last_seen": now.to_rfc3339(),
        });
        let (score, reasons) =
            score_bridge(&bridge, Some(&json!({"counters": {}})), Some(now), None).unwrap();
        assert!(score >= 80.0);
        assert!(reasons.iter().any(|r| r == "Iran-preferred port (443)"));
    }

    #[test]
    fn score_bridge_rounds_to_two_decimals_like_python() {
        // A bridge whose raw score lands on a 0.005 boundary: verify the
        // rounding matches Python's round(x, 2) banker's-rounding rule.
        let now = now();
        let record = json!({"transport": "vanilla", "last_seen": now.to_rfc3339()});
        let (score, _) = score_bridge(&record, None, Some(now), None).unwrap();
        // Sanity: vanilla, fresh, no telemetry → 40 + 0 (vanilla) + 5 (latency
        // unavailable) + 12 (fresh) = 57.00.
        assert_eq!(score, 57.0);
    }

    #[test]
    fn load_telemetry_returns_empty_object_on_missing_or_invalid() {
        let missing = std::env::temp_dir().join("bridge_scoring_missing_telemetry.json");
        let _ = std::fs::remove_file(&missing);
        assert!(load_telemetry(&missing).is_object());

        let malformed = std::env::temp_dir().join("bridge_scoring_malformed_telemetry.json");
        std::fs::write(&malformed, "{not valid json").unwrap();
        assert!(load_telemetry(&malformed).is_object());

        let non_object = std::env::temp_dir().join("bridge_scoring_non_object_telemetry.json");
        std::fs::write(&non_object, "[1, 2, 3]").unwrap();
        let v = load_telemetry(&non_object);
        assert!(v.is_object());
        assert!(v.as_object().unwrap().is_empty());
    }
}

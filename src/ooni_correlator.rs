//! Parity port of `ooni_correlator.py` — Phase 3 classification.
//!
//! OONI measurement cross-referencer for TorShield-IR. Queries the OONI API
//! for Tor bridge measurements from Iranian probes over the last 7 days,
//! cross-references the results with the Go `probe_scheduler`'s merged output,
//! computes a composite reachability score per bridge, writes a human-readable
//! Markdown report and a machine-readable JSON summary, and signals failure
//! when fewer than 30 % of tested bridges achieve a composite score above 0.5.
//!
//! Composite scoring formula:
//! ```text
//! composite = 0.35 * tcp_reachable
//!           + 0.40 * ooni_factor     (1.0 clean | 0.5 unknown | 0.0 anomaly)
//!           + 0.25 * ripe_factor     (1.0 reachable | 0.5 untested | 0.0 unreachable)
//! ```
//!
//! # Behavior traced to `ooni_correlator.py`
//!
//! * [`ooni_factor`] — pure helper. Empty list → 0.5; any anomaly/confirmed
//!   truthy → 0.0; all clean → 1.0; otherwise 0.5 (unreachable branch in
//!   practice but preserved for parity).
//! * [`ripe_factor`] — pure helper. `!ripe_tested` → 0.5; else `1.0` if
//!   `ripe_reachable` is truthy else `0.0`.
//! * [`compute_composite`] — pure helper, returns `round(x, 4)` matching
//!   Python's banker's-rounding `round()`.
//! * [`build_daily_history`] — pure helper mirroring `_build_daily_history`.
//! * [`load_iran_results`] / [`load_scheduler_results`] — file loaders with
//!   injectable `&Path`. Use [`crate::generated_json_loader::load_generated_json`]
//!   for the defensive fallback semantics.
//! * [`ooni_query`] / [`fetch_iran_measurements`] — OONI API queries with an
//!   injectable [`OoniHttpFetch`] client. Production [`ReqwestOoniHttpFetch`]
//!   is gated behind the `network` Cargo feature.
//! * [`correlate_enriched`] — pure decision-logic core of `correlate()`.
//!   Takes the loaded data + quarantined set and returns the enriched list.
//! * [`correlate`] — full I/O-bound orchestrator that loads files, fetches
//!   OONI, updates the [`QuarantineManager`], and delegates to
//!   [`correlate_enriched`].
//! * [`write_latest_results`] / [`write_markdown_report`] — file writers with
//!   injectable `&Path` and `DateTime<Utc>` for deterministic testing.
//! * [`quality_gate`] / [`run_pipeline`] — quality-gate decision and the
//!   full pipeline entry point matching `main()`.
//!
//! # Side effects not ported 1:1
//!
//! * `time.sleep(OONI_RATE_SLEEP)` is moved into the production
//!   `ReqwestOoniHttpFetch` (gated behind `network`). The mock client used in
//!   tests does not sleep. See `MIGRATION_NOTES.md` for details.
//! * `monitoring.structured_logger.record_silent_failure` calls are replaced
//!   with `tracing::warn!` (no-op by default unless a subscriber is installed).
//! * `sys.exit(0)` / `sys.exit(1)` from `main()` become a typed
//!   [`PipelineOutcome`] returned by [`run_pipeline`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{json, Value};
use thiserror::Error;

use crate::generated_json_loader::load_generated_json;
use crate::quarantine_manager::QuarantineManager;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration constants (mirror `ooni_correlator.py`)
// ─────────────────────────────────────────────────────────────────────────────

/// OONI measurements API base URL. Mirrors `OONI_BASE`.
pub const OONI_BASE: &str = "https://api.ooni.io/api/v1/measurements";

/// Per-request timeout in seconds. Mirrors `OONI_TIMEOUT`.
pub const OONI_TIMEOUT_SECS: u64 = 30;

/// Sleep between OONI requests in seconds (5 req/s → 200 ms). Mirrors
/// `OONI_RATE_SLEEP`. The production `ReqwestOoniHttpFetch` sleeps this long
/// before each request; the mock test client does not.
pub const OONI_RATE_SLEEP_SECS: f64 = 0.2;

/// Pass-rate threshold (exit 1 if fewer than 30 % of bridges score above 0.5).
/// Mirrors `PASS_THRESHOLD`.
pub const PASS_THRESHOLD: f64 = 0.30;

// ─────────────────────────────────────────────────────────────────────────────
// Typed errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failures raised by the Rust `ooni_correlator.py` parity port.
#[derive(Debug, Error)]
pub enum OoniError {
    /// File I/O failure on a loader or writer path.
    #[error("ooni I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    /// JSON (de)serialization failure.
    #[error("ooni JSON error: {source}")]
    Json {
        #[from]
        source: serde_json::Error,
    },

    /// Underlying HTTP client error (production `reqwest` path only).
    #[error("ooni HTTP error for {url}: {message}")]
    Http { url: String, message: String },

    /// Underlying `QuarantineManager` error (propagated from
    /// `update_from_ooni_history`).
    #[error("ooni quarantine error: {0}")]
    Quarantine(#[from] crate::quarantine_manager::QuarantineError),
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable HTTP client
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal HTTP response shape used by [`OoniHttpFetch`].
#[derive(Debug, Clone)]
pub struct OoniHttpResponse {
    /// HTTP status code (e.g. 200, 404).
    pub status: u16,
    /// Response body decoded as UTF-8 text.
    pub body: String,
}

/// Injectable HTTP client used by [`ooni_query`] and [`fetch_iran_measurements`].
///
/// Production code uses [`ReqwestOoniHttpFetch`] (gated behind the `network`
/// Cargo feature); tests substitute a mock implementation that returns canned
/// responses without making real network calls.
///
/// The production implementation also sleeps [`OONI_RATE_SLEEP_SECS`] before
/// each request, mirroring the Python `time.sleep(OONI_RATE_SLEEP)` call
/// inside `_ooni_query`. Mock implementations do not sleep, keeping tests fast.
pub trait OoniHttpFetch {
    /// Issue a GET request with the given query parameters and return the
    /// response. The `params` slice is a list of `(name, value)` pairs that
    /// the implementation should URL-encode and append to `url`.
    fn get(&self, url: &str, params: &[(&str, String)]) -> Result<OoniHttpResponse, OoniError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers — Python truthiness
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate Python truthiness for a JSON value, matching the semantics of
/// `if value:` in Python:
/// * `null` → false
/// * `bool(b)` → b
/// * `number(n)` → n != 0
/// * `string(s)` → !s.is_empty()
/// * `array(a)` → !a.is_empty()
/// * `object(o)` → !o.is_empty()
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => match n.as_f64() {
            Some(f) => f != 0.0,
            None => true, // non-finite fallback — should not occur in valid JSON
        },
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Extract a `bool` from a JSON value using Python truthiness.
fn as_truthy_bool(v: Option<&Value>) -> bool {
    v.is_some_and(truthy)
}

/// Extract an `Option<bool>` that mirrors Python's `bool | None` semantics for
/// the `ripe_reachable` field. Python's `sched_rec.get("ripe_reachable")`
/// returns None if the key is missing or value is null, False if the value
/// is False (or falsy like 0 or empty string), True if the value is True
/// (or truthy). The Rust port preserves that distinction so that the JSON
/// output matches Python byte-for-byte.
fn as_python_bool_or_none(v: Option<&Value>) -> Option<Value> {
    match v {
        None => None,
        Some(Value::Null) => None,
        Some(val) => Some(val.clone()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers — composite scoring
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_ooni_factor(measurements)`.
///
/// Returns:
/// * `0.5` when `measurements` is empty (no data → neutral).
/// * `0.0` when any measurement has `anomaly` or `confirmed` truthy.
/// * `1.0` when every measurement has both `anomaly` and `confirmed` falsy.
/// * `0.5` otherwise (unreachable in practice — see parity notes).
pub fn ooni_factor(measurements: &[Value]) -> f64 {
    if measurements.is_empty() {
        return 0.5;
    }
    let any_anomaly = measurements
        .iter()
        .any(|m| as_truthy_bool(m.get("anomaly")) || as_truthy_bool(m.get("confirmed")));
    let all_clean = measurements
        .iter()
        .all(|m| !as_truthy_bool(m.get("anomaly")) && !as_truthy_bool(m.get("confirmed")));
    if any_anomaly {
        0.0
    } else if all_clean {
        1.0
    } else {
        0.5
    }
}

/// Mirror of `_ripe_factor(ripe_reachable, ripe_tested)`.
///
/// Returns `0.5` when `ripe_tested` is false; otherwise `1.0` if
/// `ripe_reachable` is `Some(true)` else `0.0`.
pub fn ripe_factor(ripe_reachable: Option<bool>, ripe_tested: bool) -> f64 {
    if !ripe_tested {
        return 0.5;
    }
    match ripe_reachable {
        Some(true) => 1.0,
        _ => 0.0,
    }
}

/// Mirror of `compute_composite(tcp_reachable, ooni_measurements, ripe_reachable, ripe_tested)`.
///
/// Computes `0.35 * tcp + 0.40 * ooni_factor + 0.25 * ripe_factor` and rounds
/// to 4 decimal places using Python's `round(x, 4)` semantics (banker's
/// rounding on the decimal expansion of the underlying IEEE-754 value).
pub fn compute_composite(
    tcp_reachable: bool,
    ooni_measurements: &[Value],
    ripe_reachable: Option<bool>,
    ripe_tested: bool,
) -> f64 {
    let tcp_f = if tcp_reachable { 1.0 } else { 0.0 };
    let ooni_f = ooni_factor(ooni_measurements);
    let ripe_f = ripe_factor(ripe_reachable, ripe_tested);
    round_to_4_decimals(0.35 * tcp_f + 0.40 * ooni_f + 0.25 * ripe_f)
}

/// Round an f64 to 4 decimal places, mirroring Python's `round(x, 4)` for
/// finite floats.
///
/// Python's `round()` operates on the actual decimal expansion of the IEEE-754
/// value and uses banker's rounding (round half to even) at the requested
/// precision. Rust's `f64::round()` rounds half away from zero and operates
/// on the multiplied f64, which diverges for values that land exactly on a
/// half-way point at the 4th decimal (e.g. `0.00035` → Python `0.0003` vs
/// naive Rust `0.0004`).
///
/// This helper uses `format!("{:.4}", x).parse()` which delegates to Rust's
/// `{:.4}` formatter — that formatter rounds half to even on the decimal
/// expansion of the underlying f64, matching Python's `round(x, 4)` byte-for-
/// byte for all tested values.
fn round_to_4_decimals(x: f64) -> f64 {
    format!("{:.4}", x).parse::<f64>().unwrap_or(x)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers — daily history
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_build_daily_history(ooni_by_ip)`.
///
/// Builds per-bridge daily anomaly histories for the quarantine rolling
/// z-score engine. Returns `Vec<(host, Vec<(date_str, is_anomaly)>)>` sorted
/// ascending by `date_str` within each host, with hosts in the same order as
/// the input slice (mirrors Python `dict` insertion-order preservation).
///
/// For each measurement:
/// * skip if `test_start_time` is missing, null, empty, or not a string;
/// * take the first 10 characters as `date_str` (`YYYY-MM-DD`);
/// * compute `is_anom = bool(anomaly or confirmed)` using Python truthiness;
/// * OR with any existing entry for the same `(host, date_str)` (conservative
///   merge — multiple measurements on the same day OR together).
pub fn build_daily_history(
    ooni_by_ip: &[(String, Vec<Value>)],
) -> Vec<(String, Vec<(String, bool)>)> {
    let mut out: Vec<(String, Vec<(String, bool)>)> = Vec::with_capacity(ooni_by_ip.len());
    for (host, measurements) in ooni_by_ip {
        // BTreeMap automatically sorts by date_str ascending.
        let mut day_map: BTreeMap<String, bool> = BTreeMap::new();
        for m in measurements {
            let ts_raw = match m.get("test_start_time") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                _ => continue,
            };
            let date_str: String = ts_raw.chars().take(10).collect();
            let is_anom = as_truthy_bool(m.get("anomaly")) || as_truthy_bool(m.get("confirmed"));
            let merged = day_map.get(&date_str).copied().unwrap_or(false) || is_anom;
            day_map.insert(date_str, merged);
        }
        // Mirror Python's `defaultdict(dict)` behavior: only emit a host
        // entry when at least one measurement was successfully processed
        // (i.e. `day_map` is non-empty). Hosts with empty measurements or
        // all-invalid `test_start_time` values are excluded from the
        // returned map.
        if day_map.is_empty() {
            continue;
        }
        let daily: Vec<(String, bool)> = day_map.into_iter().collect();
        out.push((host.clone(), daily));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// File loaders
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_load_iran_results()`.
///
/// Loads `bridge/iran_results.json` written by the Go `iran_tester`. Returns
/// the defensive fallback `{"bridges": [], "summary": {}}` when the file is
/// missing, empty, invalid JSON, or has a top-level type mismatch (delegated
/// to [`load_generated_json`]).
///
/// Emits a `tracing::warn!` when the file is missing, mirroring the Python
/// `log.warning(...)` call.
pub fn load_iran_results(path: &Path) -> Value {
    let fallback = json!({"bridges": [], "summary": {}});
    if !path.exists() {
        tracing::warn!("{} not found — OONI-only mode.", path.display());
    }
    load_generated_json(path, fallback)
}

/// Mirror of `_load_scheduler_results()`.
///
/// Loads `data/scheduler_results.json` and indexes by `bridge_line`. Returns
/// an empty map when the file is missing/invalid or when `results` is not a
/// list. Entries with non-string or empty `bridge_line` are skipped, matching
/// the Python `isinstance(bridge_line, str) and bridge_line` check.
pub fn load_scheduler_results(path: &Path) -> BTreeMap<String, Value> {
    let fallback = json!({"results": []});
    let data = load_generated_json(path, fallback);
    let Some(results) = data.get("results") else {
        return BTreeMap::new();
    };
    let Some(results_arr) = results.as_array() else {
        return BTreeMap::new();
    };
    let mut index: BTreeMap<String, Value> = BTreeMap::new();
    for r in results_arr {
        if !r.is_object() {
            continue;
        }
        if let Some(bridge_line) = r.get("bridge_line").and_then(Value::as_str) {
            if !bridge_line.is_empty() {
                index.insert(bridge_line.to_string(), r.clone());
            }
        }
    }
    index
}

// ─────────────────────────────────────────────────────────────────────────────
// OONI API queries
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `_ooni_query(test_name, since, until, limit=100)`.
///
/// Issues a GET request to [`OONI_BASE`] with the standard OONI query
/// parameters (`probe_cc=IR`, `test_name`, `since`, `until`, `limit`,
/// `order_by=measurement_start_time`). Returns the `results` list from the
/// JSON body on HTTP 200; returns an empty list on non-200 status, on HTTP
/// client error, or on JSON parse failure — mirroring the Python `try/except`
/// swallow-and-return-empty-list behavior.
pub fn ooni_query(
    client: &dyn OoniHttpFetch,
    test_name: &str,
    since: &str,
    until: &str,
    limit: i64,
) -> Vec<Value> {
    let params: Vec<(&str, String)> = vec![
        ("probe_cc", "IR".to_string()),
        ("test_name", test_name.to_string()),
        ("since", since.to_string()),
        ("until", until.to_string()),
        ("limit", limit.to_string()),
        ("order_by", "measurement_start_time".to_string()),
    ];
    // The production client sleeps OONI_RATE_SLEEP before the request and
    // enforces OONI_TIMEOUT_SECS as its per-request timeout; the mock client
    // ignores both. The OONI_TIMEOUT_SECS constant is honored by the
    // `ReqwestOoniHttpFetch` implementation (gated behind `network`).
    let response = match client.get(OONI_BASE, &params) {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!("OONI [{}] error: {}", test_name, err);
            return Vec::new();
        }
    };
    if response.status != 200 {
        tracing::warn!("OONI [{}] HTTP {}", test_name, response.status);
        return Vec::new();
    }
    let parsed: Value = match serde_json::from_str(&response.body) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!("OONI [{}] error: {}", test_name, err);
            return Vec::new();
        }
    };
    match parsed.get("results") {
        Some(Value::Array(arr)) => arr.clone(),
        _ => Vec::new(),
    }
}

/// Mirror of `fetch_iran_measurements(days=7)`.
///
/// Fetches Tor-related measurements (`torsf` + `tor`) from Iranian probes over
/// the last `days` days (computed from `now`). Returns a `Vec<(host,
/// measurements)>` in first-appearance order of the `input` field, mirroring
/// Python's `dict` insertion-order preservation. Measurements with a falsy
/// `input` field are indexed under the key `"global"`.
pub fn fetch_iran_measurements(
    client: &dyn OoniHttpFetch,
    now: DateTime<Utc>,
    days: i64,
) -> Vec<(String, Vec<Value>)> {
    let since = (now - ChronoDuration::days(days))
        .format("%Y-%m-%d")
        .to_string();
    let until = now.format("%Y-%m-%d").to_string();

    tracing::info!(
        "Querying OONI measurements from Iran ({} → {})…",
        since,
        until
    );

    let sf_results = ooni_query(client, "torsf", &since, &until, 100);
    let tor_results = ooni_query(client, "tor", &since, &until, 100);

    let sf_count = sf_results.len();
    let tor_count = tor_results.len();

    let mut all_results: Vec<Value> = Vec::with_capacity(sf_count + tor_count);
    all_results.extend(sf_results);
    all_results.extend(tor_results);

    tracing::info!(
        "OONI: {} measurements retrieved (torsf={}, tor={})",
        all_results.len(),
        sf_count,
        tor_count
    );

    // Index by `input` field (usually bridge IP or bridge line). Measurements
    // with a falsy `input` go under "global". Preserves first-appearance order.
    let mut indexed: Vec<(String, Vec<Value>)> = Vec::new();
    for m in &all_results {
        let key = m
            .get("input")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("global")
            .to_string();
        match indexed.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1.push(m.clone()),
            None => indexed.push((key, vec![m.clone()])),
        }
    }
    indexed
}

// ─────────────────────────────────────────────────────────────────────────────
// Correlation
// ─────────────────────────────────────────────────────────────────────────────

/// Pure decision-logic core of `correlate()`.
///
/// Takes the loaded `iran_data` (the JSON object from `bridge/iran_results.json`),
/// the scheduler index `sched_by_line` (built by [`load_scheduler_results`]),
/// the OONI index `ooni_by_ip` (built by [`fetch_iran_measurements`]), and the
/// `quarantined` set (built by [`QuarantineManager::quarantined_set`]), and
/// returns the enriched bridge records sorted by `composite_score` descending.
///
/// For each bridge record in `iran_data["bridges"]`:
/// * If `host` is non-empty and present in `quarantined`: append a copy of the
///   original record with `quarantined = true` and `composite_score = 0.0`
///   (overriding any pre-existing `composite_score`). No OONI/RIPE enrichment
///   fields are added.
/// * Otherwise: append a new record that spreads all original fields plus
///   `quarantined = false`, `ooni_measurements_ir`, `ooni_factor`,
///   `ripe_tested`, `ripe_reachable`, and `composite_score`.
///
/// The OONI lookup is `ooni_by_ip.get(host) or ooni_by_ip.get(line)`: if the
/// host's measurement list is non-empty, use it; otherwise fall back to the
/// line's list (which may be empty).
pub fn correlate_enriched(
    iran_data: &Value,
    sched_by_line: &BTreeMap<String, Value>,
    ooni_by_ip: &[(String, Vec<Value>)],
    quarantined: &BTreeSet<String>,
) -> Vec<Value> {
    let mut enriched: Vec<Value> = Vec::new();
    let bridges = iran_data.get("bridges").and_then(Value::as_array);
    let empty: Vec<Value> = Vec::new();
    let bridges = bridges.unwrap_or(&empty);

    for bridge_rec in bridges {
        let host = bridge_rec.get("host").and_then(Value::as_str).unwrap_or("");
        let line = bridge_rec.get("line").and_then(Value::as_str).unwrap_or("");
        let tcp_ok = as_truthy_bool(bridge_rec.get("tcp_reachable"));

        // FEATURE 5: hard-exclude quarantined bridges from enriched list.
        if !host.is_empty() && quarantined.contains(host) {
            let mut rec = bridge_rec.clone();
            if let Some(obj) = rec.as_object_mut() {
                obj.insert("quarantined".to_string(), Value::Bool(true));
                obj.insert(
                    "composite_score".to_string(),
                    serde_json::Number::from_f64(0.0)
                        .map(Value::Number)
                        .unwrap_or(Value::Null),
                );
            }
            enriched.push(rec);
            continue;
        }

        // OONI: look up by host IP or full bridge line.
        let ooni_meas: Vec<Value> = match ooni_by_ip.iter().find(|(k, _)| k == host) {
            Some((_, list)) if !list.is_empty() => list.clone(),
            _ => match ooni_by_ip.iter().find(|(k, _)| k == line) {
                Some((_, list)) => list.clone(),
                None => Vec::new(),
            },
        };

        // RIPE Atlas: look up from scheduler merged results.
        let sched_rec = sched_by_line.get(line).cloned().unwrap_or(Value::Null);
        let ripe_tested = as_truthy_bool(sched_rec.get("ripe_tested"));
        // Mirror Python's `sched_rec.get("ripe_reachable") if ripe_tested else None`:
        //   - If `ripe_tested` is False → None (Python returns None unconditionally)
        //   - If `ripe_tested` is True → the actual value (None, False, True, or other truthy)
        let ripe_reachable_raw: Option<Value> = if ripe_tested {
            as_python_bool_or_none(sched_rec.get("ripe_reachable"))
        } else {
            None
        };
        // For the score computation, only truthiness matters: Some(true) if
        // the raw value is truthy, else None. This matches `_ripe_factor`'s
        // `if ripe_reachable else 0.0` branch.
        let ripe_reachable_for_score: Option<bool> = ripe_reachable_raw.as_ref().map(truthy);

        let score = compute_composite(tcp_ok, &ooni_meas, ripe_reachable_for_score, ripe_tested);
        let ooni_f = ooni_factor(&ooni_meas);

        // Build the enriched record: spread all original fields, then add the
        // new fields. `serde_json::Map` (BTreeMap-backed without
        // `preserve_order`) iterates in alphabetical key order on
        // serialization, but the JSON content is semantically equivalent.
        let mut rec = bridge_rec.clone();
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("quarantined".to_string(), Value::Bool(false));
            obj.insert(
                "ooni_measurements_ir".to_string(),
                Value::Number(serde_json::Number::from(ooni_meas.len() as u64)),
            );
            obj.insert(
                "ooni_factor".to_string(),
                serde_json::Number::from_f64(ooni_f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
            );
            obj.insert("ripe_tested".to_string(), Value::Bool(ripe_tested));
            obj.insert(
                "ripe_reachable".to_string(),
                ripe_reachable_raw.unwrap_or(Value::Null),
            );
            obj.insert(
                "composite_score".to_string(),
                serde_json::Number::from_f64(score)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
            );
        }
        enriched.push(rec);
    }

    // Sort by composite_score descending. Records without composite_score
    // default to 0.0.
    enriched.sort_by(|a, b| {
        let sa = a
            .get("composite_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let sb = b
            .get("composite_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });
    enriched
}

/// Full I/O-bound orchestrator mirroring `correlate()`.
///
/// Loads `iran_path` and `scheduler_path`, fetches OONI measurements via
/// `client` for the `days`-day window ending at `now`, builds the daily
/// anomaly history, updates the [`QuarantineManager`] (if provided), and
/// delegates to [`correlate_enriched`].
///
/// If `quarantine_mgr` is `Some`, the manager is updated in place and its
/// `quarantined_set()` is used for exclusion. If `quarantine_mgr` is `None`,
/// an empty quarantined set is used (mirrors the Python `except Exception`
/// fallback when `QuarantineManager()` fails to construct).
///
/// Returns the enriched records sorted by `composite_score` descending.
pub fn correlate(
    iran_path: &Path,
    scheduler_path: &Path,
    client: &dyn OoniHttpFetch,
    now: DateTime<Utc>,
    days: i64,
    quarantine_mgr: Option<&mut QuarantineManager>,
) -> Result<Vec<Value>, OoniError> {
    let iran_data = load_iran_results(iran_path);
    let sched_by_line = load_scheduler_results(scheduler_path);
    let ooni_by_ip = fetch_iran_measurements(client, now, days);

    let daily_hist = build_daily_history(&ooni_by_ip);

    let quarantined: BTreeSet<String> = match quarantine_mgr {
        Some(mgr) => {
            let summary = mgr.update_from_ooni_history(&daily_hist)?;
            tracing::info!(
                "Quarantine: {} bridges quarantined, {} new this run.",
                summary.currently_quarantined,
                summary.newly_quarantined
            );
            mgr.quarantined_set()
        }
        None => {
            tracing::warn!(
                "QuarantineManager not provided — running without quarantine exclusions."
            );
            BTreeSet::new()
        }
    };

    Ok(correlate_enriched(
        &iran_data,
        &sched_by_line,
        &ooni_by_ip,
        &quarantined,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Output writers
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `write_latest_results(records)`.
///
/// Writes a JSON summary to `path` with the schema:
/// ```json
/// {
///   "schema": "1.0",
///   "generated_at": "<iso>",
///   "total_bridges": <n>,
///   "above_0_5": <n>,
///   "pass_rate": <float, 4 decimals>,
///   "bridges": [ ...records ]
/// }
/// ```
///
/// `generated_at` is formatted as `now.isoformat()` (Python parity: omits
/// microseconds when zero, includes 6 digits otherwise).
pub fn write_latest_results(
    records: &[Value],
    path: &Path,
    now: DateTime<Utc>,
) -> Result<(), OoniError> {
    let above_threshold = records
        .iter()
        .filter(|r| {
            r.get("composite_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                > 0.5
        })
        .count();
    let pass_rate = if records.is_empty() {
        0.0
    } else {
        round_to_4_decimals(above_threshold as f64 / records.len() as f64)
    };

    let payload = json!({
        "schema": "1.0",
        "generated_at": isoformat(&now),
        "total_bridges": records.len(),
        "above_0_5": above_threshold,
        "pass_rate": pass_rate,
        "bridges": records,
    });

    let serialized = serde_json::to_string_pretty(&payload)?;
    write_file(path, serialized.as_bytes())?;
    tracing::info!(
        "data/latest-results.json: {} records written.",
        records.len()
    );
    Ok(())
}

/// Mirror of `write_markdown_report(records)`.
///
/// Writes a Markdown report to `path`. The report includes:
/// * a status header (`✅` if pass_rate >= [`PASS_THRESHOLD`] else `🚨`);
/// * a summary table (total, above-0.5, OONI clean/anomaly/no-data counts,
///   quality gate);
/// * a static "Iran DPI Intelligence" section;
/// * a top-N (max 20) working-bridges table filtered by `composite_score > 0.5`;
/// * static "Classification Definitions" and "DPI Risk Flags" sections.
///
/// `now` is used for the `Generated:` timestamp formatted as
/// `%Y-%m-%d %H:%M UTC`.
pub fn write_markdown_report(
    records: &[Value],
    path: &Path,
    now: DateTime<Utc>,
) -> Result<(), OoniError> {
    let ts = now.format("%Y-%m-%d %H:%M UTC").to_string();
    let total = records.len();
    let above = records
        .iter()
        .filter(|r| {
            r.get("composite_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                > 0.5
        })
        .count();
    let pass_rate = if total == 0 {
        0.0
    } else {
        above as f64 / total as f64
    };

    let ooni_clean = records
        .iter()
        .filter(|r| r.get("ooni_factor").and_then(Value::as_f64).unwrap_or(0.5) == 1.0)
        .count();
    let ooni_anomaly = records
        .iter()
        .filter(|r| r.get("ooni_factor").and_then(Value::as_f64).unwrap_or(0.5) == 0.0)
        .count();
    let ooni_unknown = total - ooni_clean - ooni_anomaly;

    // Top-20 working bridges table (composite_score > 0.5).
    let top20: Vec<&Value> = records
        .iter()
        .filter(|r| {
            r.get("composite_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                > 0.5
        })
        .take(20)
        .collect();

    let mut rows: Vec<String> = Vec::with_capacity(top20.len());
    for r in &top20 {
        let host_raw = r.get("host").and_then(Value::as_str).unwrap_or("");
        let host: String = host_raw.chars().take(20).collect();
        let port = r.get("port").and_then(Value::as_i64).unwrap_or(0);
        let t_icon = transport_badge(r.get("transport").and_then(Value::as_str).unwrap_or(""));
        let score_val = r
            .get("composite_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let score = format!("{:.2}", score_val);
        let ooni_factor_val = r.get("ooni_factor").and_then(Value::as_f64).unwrap_or(0.5);
        let ooni = if ooni_factor_val == 1.0 {
            "✅"
        } else if ooni_factor_val == 0.0 {
            "❌"
        } else {
            "❓"
        };
        let tcp = if as_truthy_bool(r.get("tcp_reachable")) {
            "✅"
        } else {
            "❌"
        };
        rows.push(format!(
            "| `{host}:{port}` | {t_icon} | {tcp} | {ooni} | `{score}` |"
        ));
    }
    let table_body = if rows.is_empty() {
        "| — | — | — | — | — |".to_string()
    } else {
        rows.join("\n")
    };

    let status_emoji = if pass_rate >= PASS_THRESHOLD {
        "✅"
    } else {
        "🚨"
    };
    let pass_rate_pct = format!("{:.0}%", pass_rate * 100.0);
    let gate_text = if pass_rate >= PASS_THRESHOLD {
        "PASS ✅"
    } else {
        "FAIL 🚨"
    };

    let report = format!(
        "# {status_emoji} TorShield-IR — Iran Bridge Status Report\n\
\n\
**Generated:** `{ts}`<br>\n\
**Pipeline:** Python scraper → Go iran_tester → Rust bridge-probe → OONI correlator\n\
\n\
---\n\
\n\
## Summary\n\
\n\
| Metric | Value |\n\
| :--- | :--- |\n\
| Total bridges analysed | `{total}` |\n\
| Composite score > 0.5 | `{above}` ({pass_rate_pct}) |\n\
| OONI clean (Iran) | `{ooni_clean}` |\n\
| OONI anomaly/blocked | `{ooni_anomaly}` |\n\
| OONI no data | `{ooni_unknown}` |\n\
| Quality gate (≥ 30 %) | `{gate_text}` |\n\
\n\
---\n\
\n\
## Iran DPI Intelligence\n\
\n\
Iran's censorship infrastructure (SIAM) uses:\n\
- **TLS fingerprinting** — JA3 hash matching for known Tor patterns (`e7d705a3286e19ea42f587b344ee6865`)\n\
- **Port-based blocking** — Ports 9001, 9030, 9050 are consistently blocked\n\
- **IP-based blocking** — Known Tor relay/bridge IPs are blocklisted within 24–48 h of first use\n\
- **Traffic volume anomaly detection** — Unusual traffic shapes are flagged\n\
\n\
### Recommended Transport Priority for Iran\n\
\n\
```\n\
Snowflake → WebTunnel (CDN-fronted) → obfs4 (port 443) → meek-lite → vanilla\n\
```\n\
\n\
---\n\
\n\
## Top {top20_count} Working Bridges (composite score > 0.5)\n\
\n\
| Host:Port | Transport | TCP | OONI-IR | Score |\n\
| :--- | :---: | :---: | :---: | :---: |\n\
{table_body}\n\
\n\
---\n\
\n\
## Classification Definitions\n\
\n\
| Status | Meaning |\n\
| :--- | :--- |\n\
| `iran_likely_working` | OONI shows clean results from Iranian probes in last 7 days |\n\
| `iran_likely_blocked` | OONI shows anomaly/confirmed block from Iranian probes |\n\
| `iran_frequently_blocked` | Recurrence rate > 2 blocks per 30-day period |\n\
| `iran_unknown` | No OONI data from Iranian probes; TCP reachable from GitHub Actions |\n\
| `tcp_unreachable` | TCP connection failed from GitHub Actions runner (likely globally down) |\n\
| `iran_asn_blocked` | Bridge IP resolves to an Iranian ISP ASN — excluded from all packs |\n\
\n\
---\n\
\n\
## DPI Risk Flags\n\
\n\
| Flag | Description |\n\
| :--- | :--- |\n\
| `iran_dpi_high_risk` | Bridge uses a JA3 fingerprint or port known to Iran's DPI blocklist |\n\
| `iran_port_high_risk` | Bridge is on port 9001, 9030, or 9050 |\n\
| `domain_front_degraded` | WebTunnel front domain resolves to a non-CDN IP |\n\
| `domain_front_cdn_ok` | WebTunnel front domain resolves to a known CDN (Cloudflare, Azure, Fastly) |\n\
\n\
---\n\
\n\
*This report is generated automatically by [TorShield-IR](https://github.com/user/torshield-ir).*\n",
        status_emoji = status_emoji,
        ts = ts,
        total = total,
        above = above,
        pass_rate_pct = pass_rate_pct,
        ooni_clean = ooni_clean,
        ooni_anomaly = ooni_anomaly,
        ooni_unknown = ooni_unknown,
        gate_text = gate_text,
        top20_count = top20.len(),
        table_body = table_body,
    );

    write_file(path, report.as_bytes())?;
    tracing::info!(
        "docs/iran-bridge-status.md written ({} bridge records).",
        records.len()
    );
    Ok(())
}

/// Mirror of the inline `transport_badge(t)` closure in
/// `write_markdown_report`.
fn transport_badge(t: &str) -> &'static str {
    match t {
        "snowflake" => "🌨️",
        "webtunnel" => "🌐",
        "obfs4" => "🔐",
        "meek_lite" => "☁️",
        "vanilla" => "🟡",
        _ => "❓",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Quality gate and pipeline entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of [`run_pipeline`]. Mirrors the side effects of Python `main()`
/// without calling `sys.exit()` — callers inspect `passed` to decide the
/// process exit code.
#[derive(Debug, Clone, PartialEq)]
pub struct PipelineOutcome {
    /// Enriched bridge records (sorted by `composite_score` descending).
    pub records: Vec<Value>,
    /// Total number of records (`len(records)`).
    pub total: usize,
    /// Number of records with `composite_score > 0.5`.
    pub above_threshold: usize,
    /// `above_threshold / total` (or 0.0 when `total == 0`).
    pub pass_rate: f64,
    /// `true` when `pass_rate >= PASS_THRESHOLD`.
    pub passed: bool,
}

/// Compute the quality-gate decision for a list of records.
///
/// Returns `(total, above_threshold, pass_rate, passed)` where:
/// * `total = records.len()`
/// * `above_threshold` = count of records with `composite_score > 0.5`
/// * `pass_rate = above_threshold / total` (or `0.0` when `total == 0`)
/// * `passed = pass_rate >= PASS_THRESHOLD`
pub fn quality_gate(records: &[Value]) -> (usize, usize, f64, bool) {
    let total = records.len();
    let above_threshold = records
        .iter()
        .filter(|r| {
            r.get("composite_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                > 0.5
        })
        .count();
    let pass_rate = if total == 0 {
        0.0
    } else {
        above_threshold as f64 / total as f64
    };
    let passed = pass_rate >= PASS_THRESHOLD;
    (total, above_threshold, pass_rate, passed)
}

/// Full pipeline entry point mirroring `main()` in `ooni_correlator.py`.
///
/// Loads inputs, fetches OONI measurements, updates the [`QuarantineManager`]
/// (if provided), enriches the bridge records, writes the latest-results JSON
/// and the Markdown report, and returns a [`PipelineOutcome`] describing the
/// quality-gate decision.
///
/// Unlike Python `main()`, this function does NOT call `sys.exit()`. Callers
/// inspect `outcome.passed` and translate `false` to a non-zero process exit
/// code if desired.
///
/// When `records` is empty (no bridges in `iran_results.json`), the function
/// writes empty reports and returns a passing outcome (mirrors Python
/// `sys.exit(0)` on the empty-records branch).
#[allow(clippy::too_many_arguments)]
pub fn run_pipeline(
    iran_path: &Path,
    scheduler_path: &Path,
    latest_path: &Path,
    report_path: &Path,
    client: &dyn OoniHttpFetch,
    now: DateTime<Utc>,
    days: i64,
    quarantine_mgr: Option<&mut QuarantineManager>,
) -> Result<PipelineOutcome, OoniError> {
    tracing::info!("═══ OONI Correlator ═════════════════════════════════════════");

    let records = correlate(iran_path, scheduler_path, client, now, days, quarantine_mgr)?;

    if records.is_empty() {
        tracing::warn!("No bridge records to process — writing empty report.");
        write_latest_results(&records, latest_path, now)?;
        write_markdown_report(&records, report_path, now)?;
        return Ok(PipelineOutcome {
            records,
            total: 0,
            above_threshold: 0,
            pass_rate: 0.0,
            passed: true,
        });
    }

    write_latest_results(&records, latest_path, now)?;
    write_markdown_report(&records, report_path, now)?;

    let (total, above, pass_rate, passed) = quality_gate(&records);
    tracing::info!(
        "Quality gate: {}/{} bridges score > 0.5 ({:.0}%)",
        above,
        total,
        pass_rate * 100.0
    );

    if !passed {
        tracing::error!(
            "QUALITY GATE FAILED: Only {:.0}% of bridges exceed composite score 0.5 \
             (threshold: {:.0}%). This may indicate widespread blocking or a pipeline failure.",
            pass_rate * 100.0,
            PASS_THRESHOLD * 100.0
        );
    } else {
        tracing::info!("Quality gate PASSED. ✅");
        tracing::info!("═══ Correlator done ═════════════════════════════════════════");
    }

    Ok(PipelineOutcome {
        records,
        total,
        above_threshold: above,
        pass_rate,
        passed,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Format a `DateTime<Utc>` as an ISO-8601 string matching Python's
/// `datetime.now(UTC).isoformat()`:
/// * omits microseconds when zero (`YYYY-MM-DDTHH:MM:SS+00:00`);
/// * includes 6 digits of microseconds when non-zero
///   (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`).
fn isoformat(dt: &DateTime<Utc>) -> String {
    if dt.timestamp_subsec_nanos() == 0 {
        dt.format("%Y-%m-%dT%H:%M:%S%:z").to_string()
    } else {
        dt.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string()
    }
}

/// Write `bytes` to `path`, creating parent directories as needed. Mirrors
/// Python's `Path.write_text(...)` plus the module-level
/// `REPORT_PATH.parent.mkdir(...)` and `LATEST_RESULTS_PATH.parent.mkdir(...)`
/// calls.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), OoniError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| OoniError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    fs::write(path, bytes).map_err(|source| OoniError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Production HTTP client (network feature)
// ─────────────────────────────────────────────────────────────────────────────

/// Production [`OoniHttpFetch`] implementation backed by `reqwest::blocking`.
///
/// Only available when the `network` Cargo feature is enabled. Sleeps
/// [`OONI_RATE_SLEEP_SECS`] before each request, mirroring the Python
/// `time.sleep(OONI_RATE_SLEEP)` call inside `_ooni_query`. Uses a shared
/// `reqwest::blocking::Client` with the `scraper.py` User-Agent / Accept
/// headers and explicit per-request timeouts.
#[cfg(feature = "network")]
#[derive(Debug, Clone)]
pub struct ReqwestOoniHttpFetch {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "network")]
impl Default for ReqwestOoniHttpFetch {
    fn default() -> Self {
        Self::new(std::time::Duration::from_secs(OONI_TIMEOUT_SECS))
    }
}

#[cfg(feature = "network")]
impl ReqwestOoniHttpFetch {
    /// Construct a new client with the given default request timeout and the
    /// `ooni_correlator.py` User-Agent / Accept headers.
    pub fn new(timeout: std::time::Duration) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .user_agent("TorShield-IR/1.0")
            .default_headers(reqwest::header::HeaderMap::from_iter([(
                reqwest::header::ACCEPT,
                "application/json".parse().expect("static header value"),
            )]))
            .build()
            .expect("reqwest client builds with valid defaults");
        Self { client }
    }
}

#[cfg(feature = "network")]
impl OoniHttpFetch for ReqwestOoniHttpFetch {
    fn get(&self, url: &str, params: &[(&str, String)]) -> Result<OoniHttpResponse, OoniError> {
        // Mirror Python `time.sleep(OONI_RATE_SLEEP)` before each request.
        std::thread::sleep(std::time::Duration::from_secs_f64(OONI_RATE_SLEEP_SECS));
        let mut req = self
            .client
            .get(url)
            .timeout(std::time::Duration::from_secs(OONI_TIMEOUT_SECS));
        for (name, value) in params {
            req = req.query(&[(name.to_string(), value.clone())]);
        }
        let resp = req.send().map_err(|err| OoniError::Http {
            url: url.to_string(),
            message: err.to_string(),
        })?;
        let status = resp.status().as_u16();
        let body = resp.text().map_err(|err| OoniError::Http {
            url: url.to_string(),
            message: err.to_string(),
        })?;
        Ok(OoniHttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ooni_factor_empty_returns_neutral() {
        assert_eq!(ooni_factor(&[]), 0.5);
    }

    #[test]
    fn ooni_factor_all_clean_returns_one() {
        let measurements = vec![
            json!({"anomaly": false, "confirmed": false}),
            json!({"anomaly": null, "confirmed": null}),
            json!({}),
        ];
        assert_eq!(ooni_factor(&measurements), 1.0);
    }

    #[test]
    fn ooni_factor_any_anomaly_returns_zero() {
        let measurements = vec![
            json!({"anomaly": false, "confirmed": false}),
            json!({"anomaly": true}),
        ];
        assert_eq!(ooni_factor(&measurements), 0.0);

        let measurements = vec![json!({"confirmed": true})];
        assert_eq!(ooni_factor(&measurements), 0.0);
    }

    #[test]
    fn ripe_factor_branches() {
        assert_eq!(ripe_factor(Some(true), false), 0.5);
        assert_eq!(ripe_factor(Some(false), false), 0.5);
        assert_eq!(ripe_factor(None, false), 0.5);
        assert_eq!(ripe_factor(Some(true), true), 1.0);
        assert_eq!(ripe_factor(Some(false), true), 0.0);
        assert_eq!(ripe_factor(None, true), 0.0);
    }

    #[test]
    fn compute_composite_known_values() {
        // tcp + ooni-clean + ripe-reachable = 1.0
        assert_eq!(
            compute_composite(true, &[json!({"anomaly": false})], Some(true), true),
            1.0
        );
        // notcp + nooni + notripe = 0.325
        assert_eq!(compute_composite(false, &[], None, false), 0.325);
        // tcp + ooni-clean + notripe = 0.875
        assert_eq!(
            compute_composite(true, &[json!({"anomaly": false})], None, false),
            0.875
        );
    }

    #[test]
    fn round_to_4_decimals_matches_python_round() {
        // Python's round(0.00035, 4) == 0.0003 (banker's on decimal expansion).
        assert_eq!(round_to_4_decimals(0.00035), 0.0003);
        assert_eq!(round_to_4_decimals(0.00065), 0.0006);
        assert_eq!(round_to_4_decimals(0.00085), 0.0008);
        assert_eq!(round_to_4_decimals(0.00105), 0.001);
        assert_eq!(round_to_4_decimals(0.5), 0.5);
        assert_eq!(round_to_4_decimals(0.0), 0.0);
    }

    #[test]
    fn isoformat_matches_python_isoformat() {
        // Microsecond zero → omit.
        let dt = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 6, 28, 7, 55, 0).unwrap();
        assert_eq!(isoformat(&dt), "2026-06-28T07:55:00+00:00");
        // Non-zero microsecond → include 6 digits.
        let dt = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 6, 28, 7, 55, 0).unwrap()
            + ChronoDuration::microseconds(123456);
        assert_eq!(isoformat(&dt), "2026-06-28T07:55:00.123456+00:00");
    }

    #[test]
    fn build_daily_history_preserves_input_order_and_sorts_days() {
        let ooni_by_ip: Vec<(String, Vec<Value>)> = vec![
            (
                "1.2.3.4".to_string(),
                vec![
                    json!({"input": "1.2.3.4", "test_start_time": "2026-06-02T10:00:00Z", "anomaly": false, "confirmed": false}),
                    json!({"input": "1.2.3.4", "test_start_time": "2026-06-01T10:00:00Z", "anomaly": true, "confirmed": false}),
                    json!({"input": "1.2.3.4", "test_start_time": "2026-06-01T11:00:00Z", "anomaly": false, "confirmed": false}),
                    json!({"input": "1.2.3.4", "test_start_time": "", "anomaly": true}),
                ],
            ),
            (
                "5.6.7.8".to_string(),
                vec![json!({"test_start_time": "2026-06-03T10:00:00Z", "confirmed": true})],
            ),
            // Empty-measurements host is excluded from the output, mirroring
            // Python's `defaultdict(dict)` behavior (the inner loop never
            // runs, so `daily[host]` is never created).
            ("9.10.11.12".to_string(), vec![]),
        ];
        let out = build_daily_history(&ooni_by_ip);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, "1.2.3.4");
        assert_eq!(
            out[0].1,
            vec![
                ("2026-06-01".to_string(), true),
                ("2026-06-02".to_string(), false),
            ]
        );
        assert_eq!(out[1].0, "5.6.7.8");
        assert_eq!(out[1].1, vec![("2026-06-03".to_string(), true)]);
    }

    #[test]
    fn quality_gate_threshold_boundary() {
        // 0 of 1 → pass_rate 0.0 → fail.
        let recs = vec![json!({"composite_score": 0.4})];
        let (total, above, rate, passed) = quality_gate(&recs);
        assert_eq!((total, above), (1, 0));
        assert_eq!(rate, 0.0);
        assert!(!passed);

        // 3 of 10 → pass_rate 0.3 → pass (>= threshold).
        let recs: Vec<Value> = (0..10)
            .map(|i| {
                if i < 3 {
                    json!({"composite_score": 0.6})
                } else {
                    json!({"composite_score": 0.4})
                }
            })
            .collect();
        let (_, above, rate, passed) = quality_gate(&recs);
        assert_eq!(above, 3);
        assert_eq!(rate, 0.3);
        assert!(passed);

        // 2 of 10 → pass_rate 0.2 → fail.
        let recs: Vec<Value> = (0..10)
            .map(|i| {
                if i < 2 {
                    json!({"composite_score": 0.6})
                } else {
                    json!({"composite_score": 0.4})
                }
            })
            .collect();
        let (_, _, _, passed) = quality_gate(&recs);
        assert!(!passed);

        // Empty → pass_rate 0.0 → quality_gate decision is FAIL
        // (0.0 < PASS_THRESHOLD). The `run_pipeline` orchestrator
        // short-circuits empty records before reaching quality_gate,
        // returning `passed = true` to mirror Python `sys.exit(0)` on
        // the empty-records branch. The pure `quality_gate` helper does
        // not have that special-case override.
        let (total, above, rate, passed) = quality_gate(&[]);
        assert_eq!((total, above), (0, 0));
        assert_eq!(rate, 0.0);
        assert!(!passed);
    }
}

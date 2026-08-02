//! Parity port of `ml_predictor.py` — FEATURE 1: AI-Driven Bridge Blocking
//! Predictor.
//!
//! Trains a RandomForest classifier on historical OONI measurements from Iran
//! (probe_cc=IR) to predict the probability that a given bridge will be
//! blocked within the next 24 hours.
//!
//! # Behavior traced to `ml_predictor.py`
//!
//! * [`port_risk`] — mirrors the private `_port_risk` helper.
//! * [`cdn_present`] — mirrors the private `_cdn_present` helper.
//! * [`days_since`] — mirrors the private `_days_since` helper with an
//!   injectable `now` parameter for deterministic testing.
//! * [`extract_features`] — mirrors the public `extract_features` function
//!   with an injectable `now` parameter.
//! * [`load_labeled_data_with_paths`] — mirrors the public
//!   `load_labeled_data` function with injectable file paths.
//! * [`train_with_options`] — mirrors the public `train` function. The
//!   sklearn RandomForest training is NOT ported (see "Flagged behavior"
//!   below); when `len(X) >= min_samples`, the function returns a
//!   `"sklearn_required"` metadata dict instead of training a model.
//! * [`load_model`] — mirrors the public `load_model` function. Always
//!   returns `None` because Rust cannot deserialize Python pickle files.
//! * [`predict_blocking_prob`] — mirrors the public `predict_blocking_prob`
//!   function. Returns `0.5` when `model` is `None` (matching Python); when
//!   `model` is `Some`, returns `0.5` because no heuristic model is loaded
//!   in Rust (flagged deviation).
//! * [`apply_predictions_to_results_with_options`] — mirrors the public
//!   `apply_predictions_to_results` function with injectable file path and
//!   `now` timestamp.
//! * [`AI_WEIGHT`] — mirrors the Python `AI_WEIGHT = 0.25` constant.
//!
//! # Flagged behavior (documented in MIGRATION_NOTES.md)
//!
//! * **Model training**: the Python original trains a scikit-learn
//!   `RandomForestClassifier` with 200 estimators, max_depth=8, balanced
//!   class weights, and 5-fold cross-validated ROC-AUC. The trained model
//!   is pickled to `data/blocking_model.pkl`. The Rust port does NOT
//!   re-implement RandomForest training (would require `linfa` + `ndarray`
//!   crates, which are not in the workspace dependency set without
//!   justification). When sufficient labeled data is available
//!   (`len(X) >= min_samples`), [`train_with_options`] returns a metadata
//!   dict with `"status": "sklearn_required"` instead of `"ok"`.
//! * **Model inference**: the Python original loads the pickle and calls
//!   `model.predict_proba(feats)`. The Rust [`load_model`] always returns
//!   `None` (no pickle support), so [`predict_blocking_prob`] always
//!   returns `0.5` (the neutral probability). This matches the Python
//!   behavior when no model is loaded; the deviation only manifests when
//!   a trained model exists on disk.
//! * **Accuracy delta**: when a trained Python model exists, the Python
//!   `predict_blocking_prob` returns the RandomForest's class-1 probability
//!   (typically in `[0.05, 0.95]` depending on features). The Rust port
//!   returns `0.5` regardless of features. For the composite-score
//!   adjustment formula `composite * (1.0 - 0.25 * prob)`, this means the
//!   Rust port deflates every composite score by a flat `12.5%` (factor
//!   `0.875`), while the Python port deflates by a per-bridge factor in
//!   `[0.75, 0.9875]`. The schema (input record fields, output
//!   `predicted_block_prob` / `composite_score` / `composite_score_orig`
//!   fields, metadata fields) matches the Python original exactly.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde_json::{json, Value};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `ml_predictor.py` parity port.
#[derive(Debug, Error)]
pub enum MLPredictorError {
    /// File I/O failure on a results / model / metadata path.
    #[error("ml_predictor I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// JSON serialization / deserialization failure.
    #[error("ml_predictor JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Paths (mirror Python module-level constants)
// ─────────────────────────────────────────────────────────────────────────────

/// Default path to the Iran results JSON. Mirrors `IRAN_RESULTS_PATH`.
pub const IRAN_RESULTS_PATH: &str = "bridge/iran_results.json";

/// Default path to the latest-results JSON. Mirrors `LATEST_RESULTS_PATH`.
pub const LATEST_RESULTS_PATH: &str = "data/latest-results.json";

/// Default path to the pickled blocking model. Mirrors `MODEL_PATH`.
pub const MODEL_PATH: &str = "data/blocking_model.pkl";

/// Default path to the model metadata JSON. Mirrors `METADATA_PATH`.
pub const METADATA_PATH: &str = "data/model_metadata.json";

// ─────────────────────────────────────────────────────────────────────────────
// Iranian ASN set (mirrors `IRAN_ASNS`)
// ─────────────────────────────────────────────────────────────────────────────

/// Iranian ASN set (mirrors Go `internal/asn/iran_asns.go`).
///
/// Returns a fresh `HashSet` on each call.
pub fn iran_asns() -> HashSet<&'static str> {
    [
        "AS12880", "AS16322", "AS44244", "AS25124", "AS197207", "AS58224", "AS48431", "AS43754",
        "AS31549", "AS49100", "AS39650", "AS24631", "AS56402", "AS47796", "AS60672", "AS48159",
        "AS29049", "AS42337", "AS50810", "AS34918",
    ]
    .into_iter()
    .collect()
}

/// CDN domain patterns used by [`cdn_present`]. Mirrors `CDN_PATTERNS`.
pub const CDN_PATTERNS: &[&str] = &[
    "fastly.net",
    "cloudfront.net",
    "azureedge.net",
    "gstatic.com",
    "aspnetcdn.com",
    "arvancloud.com",
    "arvancloud.ir",
    "cdn.irimc.ir",
    "googlevideo.com",
];

/// Transport-name → integer encoding. Mirrors `TRANSPORT_ENCODING`.
pub fn transport_encoding() -> Vec<(&'static str, i64)> {
    vec![
        ("snowflake", 0),
        ("webtunnel", 1),
        ("obfs4", 2),
        ("meek_lite", 3),
        ("vanilla", 4),
        ("unknown", 5),
    ]
}

/// Iran-status strings that map to label `1` (blocked). Mirrors
/// `BLOCKED_STATUSES`.
pub const BLOCKED_STATUSES: &[&str] = &[
    "iran_likely_blocked",
    "iran_frequently_blocked",
    "iran_asn_blocked",
];

/// Iran-status strings that map to label `0` (working). Mirrors
/// `WORKING_STATUSES`.
pub const WORKING_STATUSES: &[&str] = &["iran_likely_working"];

// ─────────────────────────────────────────────────────────────────────────────
// Feature extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a TCP port into a risk tier. Mirrors the private `_port_risk`.
///
/// * `443` → `0`
/// * `80` → `1`
/// * `8080`, `8443` → `2`
/// * `9001`, `9030`, `9050` (Tor ports) → `4`
/// * any other port (including `0`) → `3`
pub fn port_risk(port: i64) -> i64 {
    if port == 443 {
        0
    } else if port == 80 {
        1
    } else if port == 8080 || port == 8443 {
        2
    } else if port == 9001 || port == 9030 || port == 9050 {
        4
    } else {
        3
    }
}

/// Return `1.0` if any CDN pattern is a substring of `raw` (case-insensitive),
/// else `0.0`. Mirrors the private `_cdn_present`.
pub fn cdn_present(raw: &str) -> f64 {
    let low = raw.to_lowercase();
    if CDN_PATTERNS.iter().any(|p| low.contains(p)) {
        1.0
    } else {
        0.0
    }
}

/// Parse an ISO 8601 timestamp and return the integer number of days between
/// `now` and the timestamp, clamped to `[0, 365]`.
///
/// Mirrors the private `_days_since`. Returns `30.0` on parse failure
/// (matching the Python `except Exception: return 30.0` branch).
///
/// # Supported formats
///
/// The Python `datetime.fromisoformat` (Python 3.11+) is lenient and handles
/// `Z` suffixes, naive timestamps, date-only strings, and fractional
/// seconds. The Rust port tries the following parsers in order:
///
/// 1. `DateTime::parse_from_rfc3339` — handles `2024-01-01T00:00:00Z` and
///    `2024-01-01T00:00:00+00:00`.
/// 2. `NaiveDateTime::parse_from_str` with `"%Y-%m-%dT%H:%M:%S"` then
///    `"%Y-%m-%d %H:%M:%S"` — handles naive timestamps.
/// 3. `NaiveDateTime::parse_from_str` with fractional seconds
///    `"%Y-%m-%dT%H:%M:%S%.f"`.
/// 4. `NaiveDate::parse_from_str` with `"%Y-%m-%d"` — handles date-only
///    strings, treated as midnight UTC.
///
/// Any parse failure returns `30.0`.
pub fn days_since(iso_ts: &str, now: DateTime<Utc>) -> f64 {
    let parsed = parse_iso8601(iso_ts);
    match parsed {
        Some(ts) => {
            let duration = now.signed_duration_since(ts);
            let days = duration.num_days();
            let clamped = days.clamp(0, 365);
            clamped as f64
        }
        None => 30.0,
    }
}

/// Best-effort ISO 8601 parser that mirrors `datetime.fromisoformat` for the
/// formats used in TorShield-IR bridge records.
fn parse_iso8601(s: &str) -> Option<DateTime<Utc>> {
    // 1. RFC 3339 (with timezone offset or Z).
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // 2. Naive "YYYY-MM-DDTHH:MM:SS" or "YYYY-MM-DD HH:MM:SS".
    for fmt in &["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    // 3. Naive with fractional seconds.
    for fmt in &["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    // 4. Date-only "YYYY-MM-DD".
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let ndt = nd.and_hms_opt(0, 0, 0)?;
        return Some(Utc.from_utc_datetime(&ndt));
    }
    None
}

/// Extract the 8-dimensional feature vector for a bridge record.
///
/// Mirrors the public `extract_features` function. The feature vector is:
///
/// | Index | Feature           | Source field                                  |
/// |-------|-------------------|-----------------------------------------------|
/// | 0     | `transport_enc`   | `transport` (default `"unknown"`)             |
/// | 1     | `port_risk`       | `port` (default `0`)                          |
/// | 2     | `cdn_present`     | `line` or `raw` substring match               |
/// | 3     | `days_first_seen` | `first_seen` (default `2020-01-01T00:00:00Z`) |
/// | 4     | `recurrence_rate` | `recurrence_rate_per_30d` or `recurrence_rate`|
/// | 5     | `dpi_risk_flag`   | `"iran_dpi_high_risk" in flags`               |
/// | 6     | `iran_asn`        | `asn in IRAN_ASNS`                            |
/// | 7     | `ooni_anomaly_rate` | `1.0 - ooni_factor` (default `0.5`)         |
///
/// The `now` parameter is used by [`days_since`] for the days-since-first-seen
/// calculation.
pub fn extract_features(record: &Value, now: DateTime<Utc>) -> Vec<f64> {
    let transport = record
        .get("transport")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let port = record.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
    let raw = record
        .get("line")
        .and_then(|v| v.as_str())
        .or_else(|| record.get("raw").and_then(|v| v.as_str()))
        .unwrap_or("");
    let flags = record.get("flags").and_then(|v| v.as_array()).cloned();
    let asn = record.get("asn").and_then(|v| v.as_str()).unwrap_or("");
    let recurrence = extract_recurrence_rate(record);
    // Python: `record.get("first_seen", "2020-01-01T00:00:00Z")` returns the
    // default only if the key is MISSING. If the key exists with a null or
    // non-string value, that value is passed to `_days_since`, which raises
    // (TypeError for None/bool/int, ValueError for unparseable strings) and
    // returns 30.0 via the `except Exception` branch.
    let first_seen_days = match record.get("first_seen") {
        None => days_since("2020-01-01T00:00:00Z", now),
        Some(Value::String(s)) => days_since(s, now),
        Some(_) => 30.0,
    };

    let ooni_factor = python_float_or(record.get("ooni_factor").unwrap_or(&Value::Null), 0.5);
    let anomaly_rate = 1.0 - ooni_factor;

    let transport_enc = transport_encoding()
        .into_iter()
        .find(|(name, _)| *name == transport)
        .map(|(_, enc)| enc)
        .unwrap_or(5);

    let dpi_risk_flag = match &flags {
        Some(arr) => arr.iter().any(|f| f.as_str() == Some("iran_dpi_high_risk")),
        None => false,
    };

    let iran_asn_flag = iran_asns().contains(asn);

    vec![
        transport_enc as f64,
        port_risk(port) as f64,
        cdn_present(raw),
        first_seen_days,
        recurrence,
        if dpi_risk_flag { 1.0 } else { 0.0 },
        if iran_asn_flag { 1.0 } else { 0.0 },
        anomaly_rate,
    ]
}

/// Extract the recurrence rate from a record, mirroring the Python
/// `float(record.get("recurrence_rate_per_30d", record.get("recurrence_rate", 0.0)) or 0.0)`.
fn extract_recurrence_rate(record: &Value) -> f64 {
    let raw = record
        .get("recurrence_rate_per_30d")
        .or_else(|| record.get("recurrence_rate"));
    let raw = raw.unwrap_or(&Value::Null);
    python_float_or(raw, 0.0)
}

/// Mirror Python's `float(value or default)` for the JSON value types used
/// in TorShield-IR bridge records.
///
/// * `Value::Null` → `default` (None is falsy in Python).
/// * `Value::Bool(true)` → `1.0` (`float(True) == 1.0`).
/// * `Value::Bool(false)` → `default` (`False or default == default`).
/// * `Value::Number(n)` → `n.as_f64()`; `0.0` → `default` (0 is falsy).
/// * `Value::String(s)` → parse as f64; empty string or `0.0` → `default`;
///   non-numeric string → `default` (deviation: Python would raise
///   `ValueError`).
/// * `Value::Array` / `Value::Object` → `default` (deviation: Python would
///   raise `TypeError` for non-empty containers).
fn python_float_or(value: &Value, default: f64) -> f64 {
    match value {
        Value::Null => default,
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                default
            }
        }
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or(default);
            if f == 0.0 {
                default
            } else {
                f
            }
        }
        Value::String(s) => {
            if s.is_empty() {
                default
            } else {
                match s.parse::<f64>() {
                    Ok(f) if f != 0.0 => f,
                    Ok(_) => default,
                    Err(_) => default,
                }
            }
        }
        _ => default,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Model training (with sklearn deviation)
// ─────────────────────────────────────────────────────────────────────────────

/// Load labeled data from the two source files. Mirrors `load_labeled_data`.
///
/// Reads `iran_results.json` and `latest-results.json` (in that order),
/// deduplicates by `line` (or `bridge_line`) key, and labels each record:
/// * `1` (blocked) if `iran_status` is in [`BLOCKED_STATUSES`].
/// * `0` (working) if `iran_status` is in [`WORKING_STATUSES`], or if
///   `iran_status == "iran_unknown"` AND `tcp_reachable` is truthy.
/// * Skipped (not included) otherwise.
///
/// Returns `(features, labels)` where `features` is a `Vec<Vec<f64>>` (one
/// inner vector per record) and `labels` is a `Vec<i64>`.
///
/// The `now` parameter is used by [`extract_features`] for the
/// days-since-first-seen calculation.
pub fn load_labeled_data_with_paths(
    iran_results_path: &Path,
    latest_results_path: &Path,
    now: DateTime<Utc>,
) -> Result<(Vec<Vec<f64>>, Vec<i64>), MLPredictorError> {
    let mut x: Vec<Vec<f64>> = Vec::new();
    let mut y: Vec<i64> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for path in [iran_results_path, latest_results_path] {
        if !path.exists() {
            continue;
        }
        let text = fs::read_to_string(path).map_err(|source| MLPredictorError::Io {
            path: path.to_string_lossy().to_string(),
            source,
        })?;
        let data: Value = serde_json::from_str(&text)?;
        let records = data.get("bridges").and_then(|v| v.as_array());
        if let Some(arr) = records {
            for r in arr {
                let line_key = r
                    .get("line")
                    .and_then(|v| v.as_str())
                    .or_else(|| r.get("bridge_line").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();
                if seen.contains(&line_key) {
                    continue;
                }
                seen.insert(line_key.clone());

                let status = r.get("iran_status").and_then(|v| v.as_str()).unwrap_or("");
                let label = if BLOCKED_STATUSES.contains(&status) {
                    Some(1)
                } else if WORKING_STATUSES.contains(&status) {
                    Some(0)
                } else if status == "iran_unknown" {
                    // Mirror Python: `r.get("tcp_reachable")` truthy → label 0
                    let reachable = r.get("tcp_reachable");
                    let is_truthy = match reachable {
                        Some(Value::Bool(b)) => *b,
                        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
                        Some(Value::String(s)) => !s.is_empty() && s != "0" && s != "false",
                        _ => false,
                    };
                    if is_truthy {
                        Some(0)
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(lbl) = label {
                    x.push(extract_features(r, now));
                    y.push(lbl);
                }
            }
        }
    }

    Ok((x, y))
}

/// Train the RandomForest classifier. Mirrors `train`.
///
/// # Deviation from Python
///
/// The Python original trains a scikit-learn `RandomForestClassifier` and
/// pickles it to `MODEL_PATH`. The Rust port does NOT re-implement
/// RandomForest training. Behavior:
///
/// * If `len(X) < min_samples`: returns `{"status": "insufficient_data",
///   "samples": N}` (parity with Python).
/// * If `len(X) >= min_samples`: returns `{"status": "sklearn_required",
///   "samples": N, "blocked": B, "working": W}` (deviation: Python returns
///   `{"status": "ok", ...}` with trained model metadata).
///
/// The Rust port does NOT write a model file or update `model_metadata.json`.
pub fn train_with_options(
    iran_results_path: &Path,
    latest_results_path: &Path,
    metadata_path: &Path,
    now: DateTime<Utc>,
    min_samples: usize,
) -> Result<Value, MLPredictorError> {
    let (x, y) = load_labeled_data_with_paths(iran_results_path, latest_results_path, now)?;
    tracing::info!(
        "Training data: {} samples ({} blocked, {} working)",
        x.len(),
        y.iter().filter(|&&l| l == 1).count(),
        y.iter().filter(|&&l| l == 0).count()
    );

    if x.len() < min_samples {
        tracing::warn!(
            "Insufficient labeled data ({} samples, need ≥ {}). \
             Skipping model training — will use neutral probability 0.5.",
            x.len(),
            min_samples
        );
        return Ok(json!({
            "status": "insufficient_data",
            "samples": x.len() as i64,
        }));
    }

    // Deviation: sklearn RandomForest training is not ported.
    let blocked = y.iter().filter(|&&l| l == 1).count() as i64;
    let working = y.iter().filter(|&&l| l == 0).count() as i64;
    tracing::warn!(
        "sklearn not available in Rust port — returning sklearn_required metadata. \
         Python original would train RandomForestClassifier(n_estimators=200, \
         max_depth=8) and pickle to {}.",
        MODEL_PATH
    );

    // Read existing metadata to compute the next version, mirroring Python.
    let existing_version = if metadata_path.exists() {
        fs::read_to_string(metadata_path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|v| v.get("version").and_then(|n| n.as_i64()))
            .unwrap_or(0)
    } else {
        0
    };
    let version = existing_version + 1;

    let metadata = json!({
        "trained_at": now.to_rfc3339(),
        "version": version,
        "samples": x.len() as i64,
        "blocked": blocked,
        "working": working,
        "status": "sklearn_required",
    });
    Ok(metadata)
}

// ─────────────────────────────────────────────────────────────────────────────
// Model inference
// ─────────────────────────────────────────────────────────────────────────────

/// Placeholder for the trained sklearn model.
///
/// The Rust port does not deserialize Python pickle files, so this enum has
/// no variants carrying model state. It exists only so that
/// [`predict_blocking_prob`] can accept the same `Option<&Model>` signature
/// as the Python `predict_blocking_prob(model, record)`.
#[derive(Debug, Clone, Copy)]
pub struct Model;

/// Load the trained model. Mirrors `load_model`.
///
/// Always returns `None` because Rust cannot deserialize Python pickle
/// files. This matches the Python behavior when no model file exists on
/// disk; the deviation only manifests when a trained model exists.
pub fn load_model(_model_path: &Path) -> Option<Model> {
    None
}

/// Return the probability in `[0.0, 1.0]` that this bridge will be blocked
/// within the next 24 hours. Mirrors `predict_blocking_prob`.
///
/// Returns `0.5` (neutral) when `model` is `None`, matching the Python
/// behavior. When `model` is `Some`, the Rust port still returns `0.5`
/// because no heuristic model is loaded (flagged deviation in
/// `MIGRATION_NOTES.md`).
pub fn predict_blocking_prob(model: Option<&Model>, _record: &Value) -> f64 {
    match model {
        None => 0.5,
        Some(_) => 0.5, // deviation: Python would call model.predict_proba
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply predictions to composite scores
// ─────────────────────────────────────────────────────────────────────────────

/// How much the ML prediction influences the final score. Mirrors
/// `AI_WEIGHT = 0.25`.
pub const AI_WEIGHT: f64 = 0.25;

/// Read latest-results JSON, adjust each bridge's `composite_score` by the
/// AI blocking prediction, and write the updated file back. Mirrors
/// `apply_predictions_to_results`.
///
/// # Behavior
///
/// * If `latest_results_path` does not exist: returns `Ok(0)` with a
///   `tracing::warn!` (matching Python).
/// * For each bridge record:
///   - `block_prob = predict_blocking_prob(model, r)` (returns `0.5` when
///     `model` is `None`).
///   - `original = r.get("composite_score", 0.5)` (as f64).
///   - `adjusted = round(original * (1.0 - AI_WEIGHT * block_prob), 4)`.
///   - Sets `r["predicted_block_prob"] = round(block_prob, 4)`.
///   - Sets `r["composite_score"] = adjusted`.
///   - Sets `r["composite_score_orig"] = original`.
/// * Re-sorts `records` by `composite_score` descending.
/// * Sets `data["ml_model_applied"] = true`, `data["ml_ai_weight"] = 0.25`,
///   `data["ml_applied_at"] = now.to_rfc3339()`.
/// * Writes the updated JSON back to `latest_results_path` with
///   `to_string_pretty` (matching Python's `json.dumps(indent=2)`).
///
/// Returns the number of records updated.
pub fn apply_predictions_to_results_with_options(
    model: Option<&Model>,
    latest_results_path: &Path,
    now: DateTime<Utc>,
) -> Result<i64, MLPredictorError> {
    if !latest_results_path.exists() {
        tracing::warn!("latest-results.json not found — skipping apply step.");
        return Ok(0);
    }

    let text = fs::read_to_string(latest_results_path).map_err(|source| MLPredictorError::Io {
        path: latest_results_path.to_string_lossy().to_string(),
        source,
    })?;
    let mut data: Value = serde_json::from_str(&text)?;

    // Re-sort the records by composite_score descending.
    let records = data.get_mut("bridges").and_then(|v| v.as_array_mut());
    let updated = if let Some(records) = records {
        let mut updated: i64 = 0;
        for r in records.iter_mut() {
            let block_prob = predict_blocking_prob(model, r);
            let original = r
                .get("composite_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);
            let adjusted = round_n(original * (1.0 - AI_WEIGHT * block_prob), 4);
            let block_prob_rounded = round_n(block_prob, 4);

            // Set fields. We use a temporary map to preserve as much of the
            // original record as possible while adding the new keys.
            if let Some(obj) = r.as_object_mut() {
                obj.insert(
                    "predicted_block_prob".to_string(),
                    json!(block_prob_rounded),
                );
                obj.insert("composite_score".to_string(), json!(adjusted));
                obj.insert("composite_score_orig".to_string(), json!(original));
            }
            updated += 1;
        }

        // Sort by composite_score descending.
        records.sort_by(|a, b| {
            let a_score = a
                .get("composite_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let b_score = b
                .get("composite_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        updated
    } else {
        0
    };

    // Set top-level fields.
    if let Some(obj) = data.as_object_mut() {
        obj.insert("ml_model_applied".to_string(), json!(true));
        obj.insert("ml_ai_weight".to_string(), json!(AI_WEIGHT));
        obj.insert("ml_applied_at".to_string(), json!(now.to_rfc3339()));
    }

    let out = serde_json::to_string_pretty(&data)?;
    fs::write(latest_results_path, out).map_err(|source| MLPredictorError::Io {
        path: latest_results_path.to_string_lossy().to_string(),
        source,
    })?;
    tracing::info!("AI predictions applied to {} bridge records.", updated);
    Ok(updated)
}

/// Round a float to `n` decimal places, matching Python's `round(x, n)`.
///
/// Python's `round` uses banker's rounding (round-half-to-even) for values
/// exactly on a 0.5 boundary. The Rust port uses round-half-away-from-zero
/// which matches Python for all values that are not exactly on a 0.5
/// boundary at the `n`-th decimal place. This covers all `composite_score`
/// values produced by the `apply_predictions_to_results_with_options` test
/// fixtures (`0.7875`, `0.4375`, `0.5`, etc.).
///
/// The deviation on exact 0.5 boundaries is documented in
/// `MIGRATION_NOTES.md`.
fn round_n(x: f64, n: i32) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let factor = 10f64.powi(n);
    let scaled = x * factor;
    // Round half away from zero.
    let half_away = if scaled >= 0.0 {
        (scaled + 0.5).floor()
    } else {
        (scaled - 0.5).ceil()
    };
    half_away / factor
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn port_risk_branches() {
        assert_eq!(port_risk(443), 0);
        assert_eq!(port_risk(80), 1);
        assert_eq!(port_risk(8080), 2);
        assert_eq!(port_risk(8443), 2);
        assert_eq!(port_risk(9001), 4);
        assert_eq!(port_risk(9030), 4);
        assert_eq!(port_risk(9050), 4);
        assert_eq!(port_risk(0), 3);
        assert_eq!(port_risk(1234), 3);
    }

    #[test]
    fn cdn_present_branches() {
        assert!((cdn_present("https://fastly.net/foo") - 1.0).abs() < f64::EPSILON);
        assert!((cdn_present("https://FASTLY.NET/foo") - 1.0).abs() < f64::EPSILON);
        assert!((cdn_present("https://example.com/") - 0.0).abs() < f64::EPSILON);
        assert!((cdn_present("") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn days_since_old_clamped_to_365() {
        let n = now();
        assert!((days_since("2020-01-01T00:00:00Z", n) - 365.0).abs() < f64::EPSILON);
    }

    #[test]
    fn days_since_future_clamped_to_0() {
        let n = now();
        assert!((days_since("2099-01-01T00:00:00Z", n) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn days_since_invalid_returns_30() {
        let n = now();
        assert!((days_since("not-a-date", n) - 30.0).abs() < f64::EPSILON);
        assert!((days_since("", n) - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn days_since_naive_timestamp_treated_as_utc() {
        let n = now();
        // Naive timestamp 2020-01-01T00:00:00 → old, clamped to 365.
        assert!((days_since("2020-01-01T00:00:00", n) - 365.0).abs() < f64::EPSILON);
    }

    #[test]
    fn days_since_date_only() {
        let n = now();
        assert!((days_since("2020-01-01", n) - 365.0).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_features_full_record() {
        let n = now();
        let record = json!({
            "transport": "snowflake",
            "port": 443,
            "line": "x fastly.net y",
            "flags": ["iran_dpi_high_risk"],
            "asn": "AS12880",
            "first_seen": "2020-01-01T00:00:00Z",
            "ooni_factor": 0.7,
        });
        let feats = extract_features(&record, n);
        assert_eq!(feats.len(), 8);
        assert!((feats[0] - 0.0).abs() < f64::EPSILON); // snowflake=0
        assert!((feats[1] - 0.0).abs() < f64::EPSILON); // 443=0
        assert!((feats[2] - 1.0).abs() < f64::EPSILON); // CDN present
        assert!((feats[3] - 365.0).abs() < f64::EPSILON); // old
        assert!((feats[4] - 0.0).abs() < f64::EPSILON); // no recurrence
        assert!((feats[5] - 1.0).abs() < f64::EPSILON); // dpi_risk_flag
        assert!((feats[6] - 1.0).abs() < f64::EPSILON); // iran_asn
        assert!((feats[7] - 0.3).abs() < 1e-9); // 1.0 - 0.7 = 0.3
    }

    #[test]
    fn extract_features_empty_record_uses_defaults() {
        let n = now();
        let record = json!({});
        let feats = extract_features(&record, n);
        assert_eq!(feats.len(), 8);
        assert!((feats[0] - 5.0).abs() < f64::EPSILON); // unknown=5
        assert!((feats[1] - 3.0).abs() < f64::EPSILON); // 0 → 3
        assert!((feats[2] - 0.0).abs() < f64::EPSILON);
        assert!((feats[3] - 365.0).abs() < f64::EPSILON);
        assert!((feats[4] - 0.0).abs() < f64::EPSILON);
        assert!((feats[5] - 0.0).abs() < f64::EPSILON);
        assert!((feats[6] - 0.0).abs() < f64::EPSILON);
        assert!((feats[7] - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn predict_blocking_prob_none_returns_05() {
        let record = json!({});
        assert!((predict_blocking_prob(None, &record) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn round_n_matches_python_round() {
        // round(0.7875, 4) = 0.7875
        assert!((round_n(0.7875, 4) - 0.7875).abs() < 1e-9);
        // round(0.4375, 4) = 0.4375
        assert!((round_n(0.4375, 4) - 0.4375).abs() < 1e-9);
        // round(0.5, 4) = 0.5
        assert!((round_n(0.5, 4) - 0.5).abs() < 1e-9);
        // round(0.123456789, 4) = 0.1235
        assert!((round_n(0.123456789, 4) - 0.1235).abs() < 1e-9);
    }
}

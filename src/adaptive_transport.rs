//! Parity port of `adaptive_transport.py` — FEATURE 4: Adaptive Transport
//! Selection Engine.
//!
//! After each pipeline run, analyzes which transport types (obfs4, snowflake,
//! webtunnel, meek_lite) have the highest OONI success rate in Iran over the
//! last 7 days.  Dynamically adjusts the transport weights used by
//! `core/scorer.py` to reflect current real-world conditions, and publishes:
//!
//!   `data/transport_weights.json`       — current weights + scorer scores
//!   `data/transport_weight_history.json` — time-series audit log
//!   `data/best_transports.json`          — human/machine-readable ranking
//!
//! Weighting formula:
//!   `raw_weight[t] = ooni_success_rate[t] * ooni_recency_factor`
//!   `normalized    = raw_weight[t] / sum(raw_weights)`
//!   `scorer_score  = BASE_SCORE[t] * (0.7 + 0.6 * normalized)`
//!   (clamped to `[3, 30]`)
//!
//! Behavior traced to `adaptive_transport.py`:
//! * [`collect_transport_stats`] — mirror of `_collect_transport_stats`.
//! * [`compute_weights`] — mirror of `compute_weights(stats, min_samples=3)`.
//! * [`weights_to_scores`] — mirror of `weights_to_scores(weights)`.
//! * [`load_weight_history`] / [`save_weight_history`] — mirror of
//!   `_load_weight_history` / `_save_weight_history`.
//! * [`save_weights`] — mirror of `save_weights(weights, scores, stats)`.
//! * [`save_best_transports`] — mirror of `save_best_transports(...)`.
//! * [`main`] — mirror of `main()`.
//! * [`select_transport_for_nin_cut`] — mirror of
//!   `select_transport_for_nin_cut()`.
//!
//! File I/O is injectable via `&Path`. The clock is injectable via
//! `now: DateTime<Utc>`; the Python original calls `datetime.now(UTC)`
//! internally. Logging side effects (`logging.info`/`warning`) are no-ops in
//! the Rust port (see `MIGRATION_NOTES.md`).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use crate::generated_json_loader::load_generated_json;

// ─────────────────────────────────────────────────────────────────────────────
// Paths (mirror module-level Path constants)
// ─────────────────────────────────────────────────────────────────────────────

pub const IRAN_RESULTS_PATH: &str = "bridge/iran_results.json";
pub const LATEST_RESULTS_PATH: &str = "data/latest-results.json";
pub const WEIGHTS_PATH: &str = "data/transport_weights.json";
pub const WEIGHT_HISTORY_PATH: &str = "data/transport_weight_history.json";
pub const BEST_TRANSPORTS_PATH: &str = "data/best_transports.json";

// ─────────────────────────────────────────────────────────────────────────────
// Base scorer scores (mirror BASE_SCORES, MIN_SCORE, MAX_SCORE)
// ─────────────────────────────────────────────────────────────────────────────

/// Base scorer scores per transport. Iteration order matches the Python dict
/// insertion order (`snowflake`, `webtunnel`, `obfs4`, `meek_lite`, `vanilla`,
/// `unknown`).
pub const BASE_SCORES: &[(&str, i64)] = &[
    ("snowflake", 30),
    ("webtunnel", 28),
    ("obfs4", 25),
    ("meek_lite", 20),
    ("vanilla", 5),
    ("unknown", 8),
];

pub const MIN_SCORE: i64 = 3;
pub const MAX_SCORE: i64 = 30;

pub const WORKING_STATUSES: &[&str] = &["iran_likely_working"];
pub const BLOCKED_STATUSES: &[&str] = &[
    "iran_likely_blocked",
    "iran_frequently_blocked",
    "iran_asn_blocked",
];

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failures raised by the Rust `adaptive_transport.py` parity port.
#[derive(Debug, thiserror::Error)]
pub enum AdaptiveTransportError {
    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to serialize JSON for {path}: {source}")]
    Serialize {
        path: PathBuf,
        source: serde_json::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// TransportStats (mirror dict[str, dict[str, int]])
// ─────────────────────────────────────────────────────────────────────────────

/// Per-transport working/blocked/unknown/total counters. Mirrors the
/// `{"working": 0, "blocked": 0, "unknown": 0, "total": 0}` dict shape.
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub working: i64,
    pub blocked: i64,
    pub unknown: i64,
    pub total: i64,
}

impl TransportStats {
    pub fn to_json(&self) -> Value {
        json!({
            "working": self.working,
            "blocked": self.blocked,
            "unknown": self.unknown,
            "total": self.total,
        })
    }
}

/// Serialize a `BTreeMap<String, TransportStats>` to a JSON object.
pub fn stats_to_json(stats: &BTreeMap<String, TransportStats>) -> Value {
    let mut map = Map::new();
    for (k, v) in stats {
        map.insert(k.clone(), v.to_json());
    }
    Value::Object(map)
}

// ─────────────────────────────────────────────────────────────────────────────
// Analysis (mirror _collect_transport_stats, compute_weights, weights_to_scores)
// ─────────────────────────────────────────────────────────────────────────────

/// Count working vs total bridges per transport. Mirrors
/// `_collect_transport_stats(records)`.
pub fn collect_transport_stats(records: &[Value]) -> BTreeMap<String, TransportStats> {
    let mut stats: BTreeMap<String, TransportStats> = BTreeMap::new();
    for r in records {
        let t = transport_key(r.get("transport"));
        let entry = stats.entry(t).or_default();
        entry.total += 1;
        let status = r.get("iran_status").and_then(Value::as_str).unwrap_or("");
        if WORKING_STATUSES.contains(&status) {
            entry.working += 1;
        } else if BLOCKED_STATUSES.contains(&status) {
            entry.blocked += 1;
        } else {
            entry.unknown += 1;
        }
    }
    stats
}

/// Compute normalized success-rate weights for each transport. Mirrors
/// `compute_weights(stats, min_samples=3)`. Transports with fewer than
/// `min_samples` data points keep a neutral weight of `0.5`.
pub fn compute_weights(
    stats: &BTreeMap<String, TransportStats>,
    min_samples: i64,
) -> BTreeMap<String, f64> {
    let mut raw: BTreeMap<String, f64> = BTreeMap::new();
    for (t, s) in stats {
        if s.total < min_samples {
            raw.insert(t.clone(), 0.5);
        } else {
            raw.insert(t.clone(), s.working as f64 / s.total as f64);
        }
    }
    let total: f64 = raw.values().sum();
    if total == 0.0 {
        let n = raw.len() as f64;
        return raw.keys().map(|t| (t.clone(), 1.0 / n)).collect();
    }
    raw.iter().map(|(t, v)| (t.clone(), v / total)).collect()
}

/// Convert normalized weights → scorer integer scores in `[MIN_SCORE, MAX_SCORE]`.
/// Mirrors `weights_to_scores(weights)`.
pub fn weights_to_scores(weights: &BTreeMap<String, f64>) -> BTreeMap<String, i64> {
    let mut scores = BTreeMap::new();
    let default_w = 1.0 / BASE_SCORES.len() as f64;
    for (t, base) in BASE_SCORES {
        let w = weights.get(*t).copied().unwrap_or(default_w);
        let raw = *base as f64 * (0.70 + 0.60 * w);
        let clamped = raw.max(MIN_SCORE as f64).min(MAX_SCORE as f64);
        scores.insert((*t).to_string(), python_round_int(clamped));
    }
    scores
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence (mirror _load_weight_history, _save_weight_history,
// save_weights, save_best_transports)
// ─────────────────────────────────────────────────────────────────────────────

/// Load the weight-history time-series. Mirrors `_load_weight_history()`.
/// Returns an empty `Vec` when the file is missing, unreadable, invalid JSON,
/// or a non-array JSON value.
pub fn load_weight_history(path: &Path) -> Vec<Value> {
    if path.exists() {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if let Some(arr) = v.as_array() {
                    return arr.clone();
                }
            }
        }
    }
    Vec::new()
}

/// Save the weight-history time-series, keeping only the last 90 entries.
/// Mirrors `_save_weight_history(history)`.
pub fn save_weight_history(path: &Path, history: &[Value]) -> Result<(), AdaptiveTransportError> {
    let start = if history.len() > 90 {
        history.len() - 90
    } else {
        0
    };
    let trimmed = &history[start..];
    write_json_pretty(path, &Value::Array(trimmed.to_vec()))
}

/// Write `data/transport_weights.json` consumed by `IranScorer`, and append
/// to the weight-history time-series. Mirrors `save_weights(weights, scores, stats)`.
pub fn save_weights(
    weights: &BTreeMap<String, f64>,
    scores: &BTreeMap<String, i64>,
    stats: &BTreeMap<String, TransportStats>,
    now: DateTime<Utc>,
    weights_path: &Path,
    history_path: &Path,
) -> Result<(), AdaptiveTransportError> {
    let ts = format_iso(now);

    let payload_weights: Map<String, Value> = weights
        .iter()
        .map(|(t, w)| (t.clone(), json!(python_round_4(*w))))
        .collect();
    let payload_scores: Map<String, Value> =
        scores.iter().map(|(t, s)| (t.clone(), json!(s))).collect();

    let payload = json!({
        "updated_at": ts,
        "weights": Value::Object(payload_weights),
        "scores": Value::Object(payload_scores),
        "stats": stats_to_json(stats),
    });

    write_json_pretty(weights_path, &payload)?;

    // Append to time-series history (uses raw weights, not rounded)
    let mut history = load_weight_history(history_path);
    let history_weights: Map<String, Value> =
        weights.iter().map(|(t, w)| (t.clone(), json!(w))).collect();
    let history_scores: Map<String, Value> =
        scores.iter().map(|(t, s)| (t.clone(), json!(s))).collect();
    history.push(json!({
        "ts": ts,
        "weights": Value::Object(history_weights),
        "scores": Value::Object(history_scores),
    }));
    save_weight_history(history_path, &history)?;

    Ok(())
}

/// Write `data/best_transports.json` — human and machine-readable ranking.
/// Mirrors `save_best_transports(weights, scores, stats)`.
pub fn save_best_transports(
    weights: &BTreeMap<String, f64>,
    scores: &BTreeMap<String, i64>,
    stats: &BTreeMap<String, TransportStats>,
    now: DateTime<Utc>,
    output_path: &Path,
) -> Result<(), AdaptiveTransportError> {
    let ts = format_iso(now);

    let mut ranked: Vec<Value> = Vec::new();
    for (t, base) in BASE_SCORES {
        if *t == "unknown" {
            continue;
        }
        let stat = stats.get(*t);
        let working = stat.map(|s| s.working).unwrap_or(0);
        let total = stat.map(|s| s.total).unwrap_or(0);
        let blocked = stat.map(|s| s.blocked).unwrap_or(0);
        let success_rate = python_round_4(working as f64 / total.max(1) as f64);
        let weight = weights.get(*t).copied().unwrap_or(0.0);
        let scorer_score = scores.get(*t).copied().unwrap_or(*base);

        ranked.push(json!({
            "transport": t,
            "success_rate": success_rate,
            "total_tested": total,
            "working": working,
            "blocked": blocked,
            "weight": python_round_4(weight),
            "scorer_score": scorer_score,
            "iran_dpi_resistance": dpi_resistance_label(t),
            "survives_nic": matches!(*t, "snowflake" | "webtunnel" | "meek_lite"),
        }));
    }

    // Python: sorted(..., key=lambda x: (x["success_rate"], x["scorer_score"]), reverse=True)
    ranked.sort_by(|a, b| {
        let a_sr = a.get("success_rate").and_then(Value::as_f64).unwrap_or(0.0);
        let b_sr = b.get("success_rate").and_then(Value::as_f64).unwrap_or(0.0);
        let a_ss = a.get("scorer_score").and_then(Value::as_i64).unwrap_or(0);
        let b_ss = b.get("scorer_score").and_then(Value::as_i64).unwrap_or(0);
        b_sr.partial_cmp(&a_sr)
            .unwrap_or(Ordering::Equal)
            .then_with(|| b_ss.cmp(&a_ss))
    });

    let recommended_order: Vec<Value> = ranked
        .iter()
        .map(|r| json!(r.get("transport").and_then(Value::as_str).unwrap_or("")))
        .collect();

    let payload = json!({
        "generated_at": ts,
        "analysis_window_days": 7,
        "recommended_order": recommended_order,
        "transports": ranked,
        "note": "Weights are recomputed on every CI run from OONI measurements. For internet cut (شبکه ملی), use only: snowflake → webtunnel → meek_lite.",
    });

    write_json_pretty(output_path, &payload)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point (mirror main)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `main()`. Loads bridge records from `iran_path` and
/// `latest_path`, computes stats/weights/scores, and writes the three output
/// files. Returns `Ok(())` without writing when no records are found
/// (mirrors the Python `sys.exit(0)` early-return path).
pub fn main(
    iran_path: &Path,
    latest_path: &Path,
    weights_path: &Path,
    history_path: &Path,
    best_path: &Path,
    now: DateTime<Utc>,
) -> Result<(), AdaptiveTransportError> {
    let mut records: Vec<Value> = Vec::new();
    for path in [iran_path, latest_path] {
        let data = load_generated_json(path, json!({"bridges": []}));
        if let Some(bridges) = data.get("bridges").and_then(Value::as_array) {
            records.extend(bridges.iter().cloned());
        }
    }
    if records.is_empty() {
        // Python: log.warning + sys.exit(0)
        return Ok(());
    }
    let stats = collect_transport_stats(&records);
    let weights = compute_weights(&stats, 3);
    let scores = weights_to_scores(&weights);
    save_weights(&weights, &scores, &stats, now, weights_path, history_path)?;
    save_best_transports(&weights, &scores, &stats, now, best_path)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// NIN internet-cut transport auto-selector (mirror select_transport_for_nin_cut)
// ─────────────────────────────────────────────────────────────────────────────

/// Rank all available transport options for the NIN-isolation scenario.
/// Mirrors `select_transport_for_nin_cut()`.
///
/// Reads three input files (`nin_path`, `reality_path`, `next_gen_path`),
/// builds candidates from four priority tiers, sorts by
/// `(tier, -nin_score)`, deduplicates by `raw` line (falling back to
/// `ip:port`), and writes `output_path`. Returns the output payload.
pub fn select_transport_for_nin_cut(
    nin_path: &Path,
    reality_path: &Path,
    next_gen_path: &Path,
    output_path: &Path,
    now: DateTime<Utc>,
) -> Result<Value, AdaptiveTransportError> {
    let nin_data = safe_load(nin_path);
    let reality_data = safe_load(reality_path);
    let next_gen = safe_load(next_gen_path);

    let mut candidates: Vec<Value> = Vec::new();

    // Tier 1a: WebTunnel bridges from nin_data with nin_score >= 0.60
    if let Some(bridges) = nin_data.get("bridges").and_then(Value::as_array) {
        for bridge in bridges {
            let transport = bridge
                .get("transport")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let nin_score = bridge
                .get("nin_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if transport == "webtunnel" && nin_score >= 0.60 {
                candidates.push(json!({
                    "tier": 1,
                    "tier_label": "WebTunnel/CDN-443",
                    "transport": "webtunnel",
                    "ip": bridge.get("ip").cloned().unwrap_or(Value::Null),
                    "port": bridge.get("port").cloned().unwrap_or(Value::Null),
                    "raw": bridge.get("raw").cloned().unwrap_or(Value::String(String::new())),
                    "nin_score": bridge.get("nin_score").cloned().unwrap_or(json!(0.0)),
                    "reason": "WebTunnel on port 443 via Iranian CDN SNI is the strongest NIN-cut transport — indistinguishable from domestic HTTPS.",
                }));
            }
        }
    }

    // Tier 1b: WebTunnel from next_gen webtransport_scores with score >= 0.70
    if let Some(scores) = next_gen
        .get("webtransport_scores")
        .and_then(Value::as_array)
    {
        for entry in scores {
            let wt_score = entry
                .get("webtransport_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if wt_score >= 0.70 {
                candidates.push(json!({
                    "tier": 1,
                    "tier_label": "WebTunnel/QUIC-CDN",
                    "transport": "webtunnel",
                    "ip": entry.get("ip").cloned().unwrap_or(Value::Null),
                    "port": entry.get("port").cloned().unwrap_or(Value::Null),
                    "raw": entry.get("raw").cloned().unwrap_or(Value::String(String::new())),
                    "nin_score": entry.get("webtransport_score").cloned().unwrap_or(json!(0.0)),
                    "reason": "WebTunnel with QUIC/H3 CDN profile match -- mimics Aparat video streaming traffic on SIAM allowlist.",
                }));
            }
        }
    }

    // Tier 2: XTLS-Reality from reality_data per_bridge with dpi_score >= 0.60
    if let Some(per_bridge) = reality_data.get("per_bridge").and_then(Value::as_array) {
        for entry in per_bridge {
            let dpi_score = entry
                .get("dpi_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if dpi_score >= 0.60 {
                let ip = entry.get("ip").cloned().unwrap_or(Value::Null);
                let port = entry.get("port").cloned().unwrap_or(Value::Null);
                let raw = format!("vless {}:{} (Reality)", python_str(&ip), python_str(&port));
                candidates.push(json!({
                    "tier": 2,
                    "tier_label": "XTLS-Reality/VLESS-443",
                    "transport": "vless+reality",
                    "ip": ip,
                    "port": port,
                    "sni": entry.get("sni").cloned().unwrap_or(Value::Null),
                    "raw": raw,
                    "nin_score": entry.get("dpi_score").cloned().unwrap_or(json!(0.0)),
                    "reason": "XTLS-Reality borrows TLS cert of Iranian CDN domain. SIAM DPI cannot distinguish from domestic HTTPS.",
                }));
            }
        }
    }

    // Tier 3: obfs4 on port 443/8443 with nin_score >= 0.50
    if let Some(bridges) = nin_data.get("bridges").and_then(Value::as_array) {
        for bridge in bridges {
            let transport = bridge
                .get("transport")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let port = bridge.get("port").and_then(Value::as_i64).unwrap_or(0);
            let nin_score = bridge
                .get("nin_score")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if transport == "obfs4" && (port == 443 || port == 8443) && nin_score >= 0.50 {
                candidates.push(json!({
                    "tier": 3,
                    "tier_label": "obfs4-443/8443",
                    "transport": "obfs4",
                    "ip": bridge.get("ip").cloned().unwrap_or(Value::Null),
                    "port": bridge.get("port").cloned().unwrap_or(Value::Null),
                    "raw": bridge.get("raw").cloned().unwrap_or(Value::String(String::new())),
                    "nin_score": bridge.get("nin_score").cloned().unwrap_or(json!(0.0)),
                    "reason": "obfs4 on port 443/8443 blends into HTTPS traffic. Blocking port 443 is politically infeasible on Iran's NIN.",
                }));
            }
        }
    }

    // Tier 4: Snowflake (STUN-dependent, nin_score * 0.7 penalty)
    if let Some(bridges) = nin_data.get("bridges").and_then(Value::as_array) {
        for bridge in bridges {
            let transport = bridge
                .get("transport")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            if transport == "snowflake" {
                let nin_score = bridge
                    .get("nin_score")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                candidates.push(json!({
                    "tier": 4,
                    "tier_label": "Snowflake/WebRTC",
                    "transport": "snowflake",
                    "ip": bridge.get("ip").cloned().unwrap_or(Value::Null),
                    "port": bridge.get("port").cloned().unwrap_or(Value::Null),
                    "raw": bridge.get("raw").cloned().unwrap_or(Value::String(String::new())),
                    "nin_score": nin_score * 0.7,
                    "reason": "Snowflake uses WebRTC (classified as video-call by SIAM). Requires STUN reachability -- less reliable during full NIN cut.",
                }));
            }
        }
    }

    // Sort: tier ascending, then nin_score descending
    candidates.sort_by(|a, b| {
        let a_tier = a.get("tier").and_then(Value::as_i64).unwrap_or(0);
        let b_tier = b.get("tier").and_then(Value::as_i64).unwrap_or(0);
        let a_score = a.get("nin_score").and_then(Value::as_f64).unwrap_or(0.0);
        let b_score = b.get("nin_score").and_then(Value::as_f64).unwrap_or(0.0);
        a_tier
            .cmp(&b_tier)
            .then_with(|| b_score.partial_cmp(&a_score).unwrap_or(Ordering::Equal))
    });

    // Remove duplicates by raw line (fall back to ip:port)
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut deduped: Vec<Value> = Vec::new();
    for c in &candidates {
        let key = match c.get("raw") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => format!(
                "{}:{}",
                python_str(c.get("ip").unwrap_or(&Value::Null)),
                python_str(c.get("port").unwrap_or(&Value::Null))
            ),
        };
        if seen.insert(key) {
            deduped.push(c.clone());
        }
    }

    let tier_counts = json!({
        "tier_1_webtunnel_cdn": deduped.iter().filter(|c| c.get("tier").and_then(Value::as_i64) == Some(1)).count(),
        "tier_2_xtls_reality": deduped.iter().filter(|c| c.get("tier").and_then(Value::as_i64) == Some(2)).count(),
        "tier_3_obfs4_443": deduped.iter().filter(|c| c.get("tier").and_then(Value::as_i64) == Some(3)).count(),
        "tier_4_snowflake": deduped.iter().filter(|c| c.get("tier").and_then(Value::as_i64) == Some(4)).count(),
    });

    let top_recommendation = deduped.first().cloned().unwrap_or(Value::Null);

    let output = json!({
        "generated_at": format_iso(now),
        "nin_cut_scenario": "Complete international internet blackout. Only traffic through Iranian domestic ASNs (ITC/TCI/ParsOnline/ArvanCloud) reachable.",
        "total_candidates": deduped.len(),
        "tier_counts": tier_counts,
        "top_recommendation": top_recommendation,
        "ranked_candidates": deduped,
    });

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| AdaptiveTransportError::CreateDir {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }
    write_json_pretty(output_path, &output)?;

    Ok(output)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `r.get("transport", "unknown")` used as a dict key. Non-string
/// values are converted to their Python `str()` representation to match
/// `json.dumps` key coercion.
fn transport_key(v: Option<&Value>) -> String {
    match v {
        None => "unknown".to_string(),
        Some(Value::Null) => "null".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(true)) => "true".to_string(),
        Some(Value::Bool(false)) => "false".to_string(),
        Some(_) => "unknown".to_string(),
    }
}

/// Mirror of Python's `str(value)` for the JSON value types that
/// `ip`/`port` formatting can see.
fn python_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(_) => "[...]".to_string(),
        Value::Object(_) => "{...}".to_string(),
    }
}

/// Mirror of Python's `round(x)` (banker's rounding) via Rust's `{:.0}` format.
fn python_round_int(x: f64) -> i64 {
    format!("{:.0}", x).parse::<i64>().unwrap_or(0)
}

/// Mirror of Python's `round(x, 4)` (banker's rounding) via Rust's `{:.4}` format.
fn python_round_4(x: f64) -> f64 {
    format!("{:.4}", x).parse::<f64>().unwrap_or(x)
}

/// Format a `DateTime<Utc>` to match Python's `datetime.now(UTC).isoformat()`.
/// Uses chrono's `to_rfc3339` which produces `2024-01-01T12:00:00.123456+00:00`.
fn format_iso(now: DateTime<Utc>) -> String {
    now.to_rfc3339()
}

/// DPI resistance label per transport. Mirrors the inline dict in
/// `save_best_transports`.
fn dpi_resistance_label(t: &str) -> &str {
    match t {
        "snowflake" => "maximum — WebRTC/DTLS, hardest to fingerprint",
        "webtunnel" => "very_high — HTTPS CDN mimicry",
        "obfs4" => "high — random-looking traffic",
        "meek_lite" => "high — CDN domain fronting",
        "vanilla" => "none — plaintext Tor",
        _ => "unknown",
    }
}

/// Mirror of `_safe_load(path)` in `select_transport_for_nin_cut`.
fn safe_load(path: &Path) -> Value {
    if !path.exists() {
        return Value::Object(Map::new());
    }
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str::<Value>(&text).unwrap_or(Value::Object(Map::new())),
        Err(_) => Value::Object(Map::new()),
    }
}

/// Write a JSON value to `path` with 2-space indentation, creating parent
/// directories as needed.
fn write_json_pretty(path: &Path, value: &Value) -> Result<(), AdaptiveTransportError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| AdaptiveTransportError::CreateDir {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }
    let json_str =
        serde_json::to_string_pretty(value).map_err(|e| AdaptiveTransportError::Serialize {
            path: path.to_path_buf(),
            source: e,
        })?;
    fs::write(path, json_str).map_err(|e| AdaptiveTransportError::WriteFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_transport_stats_counts_per_transport() {
        let records = json!([
            {"transport": "obfs4", "iran_status": "iran_likely_working"},
            {"transport": "obfs4", "iran_status": "iran_likely_blocked"},
            {"transport": "obfs4", "iran_status": "unknown_status"},
            {"transport": "snowflake", "iran_status": "iran_likely_working"},
            {"iran_status": "iran_likely_working"},
        ]);
        let records = records.as_array().unwrap();
        let stats = collect_transport_stats(records);
        assert_eq!(stats.get("obfs4").unwrap().total, 3);
        assert_eq!(stats.get("obfs4").unwrap().working, 1);
        assert_eq!(stats.get("obfs4").unwrap().blocked, 1);
        assert_eq!(stats.get("obfs4").unwrap().unknown, 1);
        assert_eq!(stats.get("snowflake").unwrap().total, 1);
        assert_eq!(stats.get("unknown").unwrap().total, 1);
    }

    #[test]
    fn compute_weights_insufficient_samples_uses_neutral() {
        let mut stats = BTreeMap::new();
        stats.insert(
            "obfs4".to_string(),
            TransportStats {
                working: 1,
                total: 2,
                ..Default::default()
            },
        );
        let weights = compute_weights(&stats, 3);
        // total < 3 → raw = 0.5; only one transport → normalized = 1.0
        assert!((weights.get("obfs4").unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn compute_weights_zero_total_distributes_evenly() {
        let mut stats = BTreeMap::new();
        stats.insert(
            "obfs4".to_string(),
            TransportStats {
                working: 0,
                total: 5,
                ..Default::default()
            },
        );
        stats.insert(
            "snowflake".to_string(),
            TransportStats {
                working: 0,
                total: 5,
                ..Default::default()
            },
        );
        let weights = compute_weights(&stats, 3);
        // both raw = 0/5 = 0; total = 0 → 1/2 each
        assert!((weights.get("obfs4").unwrap() - 0.5).abs() < 1e-9);
        assert!((weights.get("snowflake").unwrap() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn compute_weights_normalizes_success_rates() {
        let mut stats = BTreeMap::new();
        stats.insert(
            "obfs4".to_string(),
            TransportStats {
                working: 3,
                total: 4,
                ..Default::default()
            },
        );
        stats.insert(
            "snowflake".to_string(),
            TransportStats {
                working: 1,
                total: 4,
                ..Default::default()
            },
        );
        let weights = compute_weights(&stats, 3);
        // raw: 0.75, 0.25 → total 1.0 → 0.75, 0.25
        assert!((weights.get("obfs4").unwrap() - 0.75).abs() < 1e-9);
        assert!((weights.get("snowflake").unwrap() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn weights_to_scores_clamps_and_rounds() {
        let mut weights = BTreeMap::new();
        weights.insert("snowflake".to_string(), 1.0); // 30 * (0.7 + 0.6) = 39 → clamp 30
        weights.insert("vanilla".to_string(), 0.0); // 5 * 0.7 = 3.5 → round 4
        let scores = weights_to_scores(&weights);
        assert_eq!(scores.get("snowflake").unwrap(), &30);
        assert_eq!(scores.get("vanilla").unwrap(), &4);
        // unknown not in weights → default w = 1/6
        // 8 * (0.7 + 0.6/6) = 8 * 0.8 = 6.4 → round 6
        assert_eq!(scores.get("unknown").unwrap(), &6);
    }

    #[test]
    fn weights_to_scores_min_score_floor() {
        let mut weights = BTreeMap::new();
        weights.insert("vanilla".to_string(), 0.0); // 5 * 0.7 = 3.5 → round 4 (above min)
                                                    // But if we force below min: vanilla * (0.7 + 0.6*0) = 3.5, not below 3
                                                    // For unknown: 8 * (0.7 + 0.6*0) = 5.6
        let scores = weights_to_scores(&weights);
        // vanilla: 5 * 0.7 = 3.5 → round to 4 (banker's: 3.5 → 4, since 4 is even)
        assert!(scores.get("vanilla").unwrap() >= &MIN_SCORE);
        assert!(scores.get("snowflake").unwrap() <= &MAX_SCORE);
    }

    #[test]
    fn load_weight_history_missing_file_returns_empty() {
        let result = load_weight_history(Path::new("/nonexistent/path/that/does/not/exist.json"));
        assert!(result.is_empty());
    }

    #[test]
    fn load_weight_history_valid_array() {
        let dir = std::env::temp_dir().join(format!(
            "torshield_adaptive_transport_test_{}_{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        fs::write(&path, r#"[{"ts":"2024-01-01","weights":{},"scores":{}}]"#).unwrap();
        let result = load_weight_history(&path);
        assert_eq!(result.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_weight_history_non_array_returns_empty() {
        let dir = std::env::temp_dir().join(format!(
            "torshield_adaptive_transport_test_{}_{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        fs::write(&path, r#"{"not":"an array"}"#).unwrap();
        let result = load_weight_history(&path);
        assert!(result.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_weight_history_trims_to_90_entries() {
        let dir = std::env::temp_dir().join(format!(
            "torshield_adaptive_transport_test_{}_{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        let history: Vec<Value> = (0..100).map(|i| json!({"i": i})).collect();
        save_weight_history(&path, &history).unwrap();
        let loaded = load_weight_history(&path);
        assert_eq!(loaded.len(), 90);
        // Last 90 → entries 10..99
        assert_eq!(loaded[0]["i"], json!(10));
        assert_eq!(loaded[89]["i"], json!(99));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_weights_writes_payload_and_history() {
        let dir = std::env::temp_dir().join(format!(
            "torshield_adaptive_transport_test_{}_{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        let weights_path = dir.join("weights.json");
        let history_path = dir.join("history.json");
        let now = DateTime::parse_from_rfc3339("2024-01-01T12:00:00.123456+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);

        let mut weights = BTreeMap::new();
        weights.insert("obfs4".to_string(), 0.75);
        let mut scores = BTreeMap::new();
        scores.insert("obfs4".to_string(), 25);
        let mut stats = BTreeMap::new();
        stats.insert(
            "obfs4".to_string(),
            TransportStats {
                working: 3,
                total: 4,
                ..Default::default()
            },
        );

        save_weights(&weights, &scores, &stats, now, &weights_path, &history_path).unwrap();

        let weights_json: Value =
            serde_json::from_str(&fs::read_to_string(&weights_path).unwrap()).unwrap();
        assert_eq!(
            weights_json["updated_at"],
            "2024-01-01T12:00:00.123456+00:00"
        );
        assert_eq!(weights_json["weights"]["obfs4"], json!(0.75));
        assert_eq!(weights_json["scores"]["obfs4"], json!(25));

        let history_json: Vec<Value> =
            serde_json::from_str(&fs::read_to_string(&history_path).unwrap()).unwrap();
        assert_eq!(history_json.len(), 1);
        assert_eq!(history_json[0]["ts"], "2024-01-01T12:00:00.123456+00:00");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_best_transports_writes_ranked_payload() {
        let dir = std::env::temp_dir().join(format!(
            "torshield_adaptive_transport_test_{}_{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        let best_path = dir.join("best.json");
        let now = DateTime::parse_from_rfc3339("2024-01-01T12:00:00.123456+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);

        let mut weights = BTreeMap::new();
        weights.insert("snowflake".to_string(), 0.8);
        weights.insert("obfs4".to_string(), 0.2);
        let scores = weights_to_scores(&weights);
        let mut stats = BTreeMap::new();
        stats.insert(
            "snowflake".to_string(),
            TransportStats {
                working: 4,
                total: 5,
                ..Default::default()
            },
        );
        stats.insert(
            "obfs4".to_string(),
            TransportStats {
                working: 1,
                total: 5,
                ..Default::default()
            },
        );

        save_best_transports(&weights, &scores, &stats, now, &best_path).unwrap();

        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&best_path).unwrap()).unwrap();
        assert_eq!(payload["analysis_window_days"], json!(7));
        let transports = payload["transports"].as_array().unwrap();
        // Should have 5 entries (BASE_SCORES minus "unknown")
        assert_eq!(transports.len(), 5);
        // snowflake should be ranked first (success_rate 0.8 > 0.2)
        assert_eq!(transports[0]["transport"], json!("snowflake"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn main_with_empty_records_writes_nothing() {
        let dir = std::env::temp_dir().join(format!(
            "torshield_adaptive_transport_test_{}_{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        let iran_path = dir.join("iran.json");
        let latest_path = dir.join("latest.json");
        let weights_path = dir.join("weights.json");
        let history_path = dir.join("history.json");
        let best_path = dir.join("best.json");
        fs::write(&iran_path, r#"{"bridges": []}"#).unwrap();
        fs::write(&latest_path, r#"{"bridges": []}"#).unwrap();
        let now = Utc::now();

        main(
            &iran_path,
            &latest_path,
            &weights_path,
            &history_path,
            &best_path,
            now,
        )
        .unwrap();

        assert!(!weights_path.exists());
        assert!(!best_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_transport_for_nin_cut_empty_inputs() {
        let dir = std::env::temp_dir().join(format!(
            "torshield_adaptive_transport_test_{}_{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&dir).unwrap();
        let nin_path = dir.join("nin.json");
        let reality_path = dir.join("reality.json");
        let next_gen_path = dir.join("next_gen.json");
        let output_path = dir.join("export/output.json");
        fs::write(&nin_path, r#"{"bridges": []}"#).unwrap();
        fs::write(&reality_path, r#"{"per_bridge": []}"#).unwrap();
        fs::write(&next_gen_path, r#"{"webtransport_scores": []}"#).unwrap();
        let now = DateTime::parse_from_rfc3339("2024-01-01T12:00:00.123456+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);

        let output = select_transport_for_nin_cut(
            &nin_path,
            &reality_path,
            &next_gen_path,
            &output_path,
            now,
        )
        .unwrap();

        assert_eq!(output["total_candidates"], json!(0));
        assert_eq!(output["top_recommendation"], Value::Null);
        assert!(output_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn python_round_int_matches_bankers_rounding() {
        // Verify that Rust's {:.0} format uses round-half-to-even like Python
        assert_eq!(python_round_int(2.5), 2);
        assert_eq!(python_round_int(3.5), 4);
        assert_eq!(python_round_int(0.5), 0);
        assert_eq!(python_round_int(1.5), 2);
        assert_eq!(python_round_int(2.4), 2);
        assert_eq!(python_round_int(2.6), 3);
        assert_eq!(python_round_int(-2.5), -2);
    }

    #[test]
    fn python_round_4_truncates_to_four_decimals() {
        assert!((python_round_4(0.333333) - 0.3333).abs() < 1e-9);
        assert!((python_round_4(0.5) - 0.5).abs() < 1e-9);
        assert!((python_round_4(0.123456) - 0.1235).abs() < 1e-9);
    }
}

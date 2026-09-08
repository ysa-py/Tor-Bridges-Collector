//! Stage 8u — Drift & survivability advisories (ADDITIVE, NON-BLOCKING).
//!
//! This binary produces three ADVISORY artifacts. It never gates CI, never
//! edits any of the 55 contracted `bridge/` files, and never changes a score,
//! a membership decision, or a ranking. Its entire output is new files under
//! `data/` plus `::notice` annotations in the run log.
//!
//! Sections (each grounded in this repo's REAL data; see the honest-capability
//! notes inline — where the historical signal does not exist yet, the report
//! says so instead of inventing one):
//!
//! 1. Per-bridge drift report (`data/bridge_drift_report.json`)
//!    The live collector already maintains drift-aware health per bridge —
//!    `src/tor_collector/storage.rs::record_probe` keeps an exponentially
//!    weighted health score (`new = 0.8*old + 0.2*outcome`) plus lifetime
//!    `probe_successes` / `probe_failures` counters — but nothing in the
//!    publication/scoring path consumes them (verified: `bridge_publication.rs`
//!    reads only `probe_successes > 0` for its `tested` projection). This
//!    report surfaces the "stale positive" cohort: bridges with historical
//!    successes that are CURRENTLY unreachable, whose lifetime counter alone
//!    would present them as tested. Fronted transports (meek/conjure/
//!    webtunnel/snowflake) are exempt from the label: they have no raw TCP
//!    endpoint, so `tcp_reachable == false` is not evidence of death.
//!
//! 2. Transport success-rate history (`data/transport_success_history.json`)
//!    + run-over-run anomaly flags (advisory only).
//!    Nothing in this repo accumulates a per-transport success-rate time
//!    series (verified 2026-09-08: `bridge_history.json` has zero populated
//!    `probes` logs; `transport_weight_history.json` scores are integer-flat;
//!    `collector_yield_history.json` tracks supply, not success). This binary
//!    APPENDS this run's per-transport working/total snapshot so the series
//!    starts accumulating now, and compares the current rates against the
//!    trailing baseline once enough entries exist. An "anomaly" is an
//!    externally-observable reachability-rate drop — it is NOT a claim about
//!    Iran's DPI mechanism (this repo has no visibility into filtering rules).
//!
//! 3. Per-transport step-change scan over the accumulated series.
//!    Same file, `step_changes` section: the largest mean-shift per transport
//!    (candidate changepoint scan with a minimum segment length), annotated
//!    with the timestamp of the first entry of the later segment. Explicitly
//!    framed as an observable-effect proxy for "reachability rate changed
//!    around date Y", never as "a DPI signature was deployed on date Y".
//!
//! 4. Front-domain survivability (`data/front_domain_survivability.json`)
//!    For domain-fronted transports the same front domain is reused across
//!    multiple bridge candidates. This aggregates per front domain: how many
//!    candidates use it, how many are currently reachable, and the mean
//!    collector health of its candidates — so a front failing across many
//!    otherwise-unrelated candidates is visible as a FRONT problem rather
//!    than N independent bridge problems.
//!
//! Determinism: all computations are pure functions over injected values;
//! `Utc::now()` is only used to stamp the report. Unit tests embed real
//! records from the committed `bridge/bridge_history.json` dataset.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Paths (env-overridable so tests and local runs never touch production files)
// ─────────────────────────────────────────────────────────────────────────────

fn path_or_env(default: &str, env_key: &str) -> PathBuf {
    std::env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}

/// Transports that dial a front domain instead of a raw TCP endpoint.
/// `tcp_reachable == false` for these is not evidence of death.
const FRONTED_TRANSPORTS: &[&str] = &[
    "meek_lite",
    "meek-azure",
    "conjure",
    "webtunnel",
    "snowflake",
];

/// Minimum trailing history entries before run-over-run anomaly flags are
/// emitted (below this the report states the series is too short).
const MIN_ANOMALY_BASELINE: usize = 5;

/// Minimum total entries before the step-change scan reports anything.
const MIN_STEP_SERIES: usize = 20;

/// Minimum segment length on both sides of a candidate step-change split.
const MIN_STEP_SEGMENT: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Section 1: per-bridge drift (consumes the collector's existing EWMA health)
// ─────────────────────────────────────────────────────────────────────────────

/// A bridge's drift classification from its history record.
#[derive(Debug, Clone, PartialEq)]
pub enum DriftClass {
    /// Historical successes exist and the bridge is currently reachable.
    Healthy,
    /// Historical successes exist, the bridge is CURRENTLY unreachable, and
    /// the transport has a raw TCP endpoint — the stale-positive cohort.
    StalePositive,
    /// Historical successes exist, currently unreachable, but the transport
    /// is fronted (no raw TCP endpoint) — unclassifiable by this signal.
    FrontedUnreachable,
    /// No recorded successes (or no probe evidence at all).
    NoHistory,
}

/// Classify one bridge history record. `record` is a single entry of
/// `bridge_history.json` (the collector's field set: `transport`,
/// `probe_successes`, `probe_failures`, `tcp_reachable`, `health_score`).
pub fn classify_drift(record: &Map<String, Value>) -> DriftClass {
    let transport = record
        .get("transport")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let successes = record
        .get("probe_successes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let reachable = record.get("tcp_reachable").and_then(Value::as_bool);
    if successes == 0 {
        return DriftClass::NoHistory;
    }
    match reachable {
        Some(true) => DriftClass::Healthy,
        Some(false) => {
            if FRONTED_TRANSPORTS.contains(&transport.as_str()) {
                DriftClass::FrontedUnreachable
            } else {
                DriftClass::StalePositive
            }
        }
        None => DriftClass::NoHistory,
    }
}

/// The fallback drift factor when `health_score` is absent or invalid:
/// the lifetime success ratio `successes / (successes + failures)`.
pub fn lifetime_success_ratio(record: &Map<String, Value>) -> Option<f64> {
    let successes = record
        .get("probe_successes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let failures = record
        .get("probe_failures")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total = successes + failures;
    if total == 0 {
        None
    } else {
        Some(successes as f64 / total as f64)
    }
}

/// The bridge's current drift evidence, preferring the collector's EWMA
/// `health_score` (recent probes weighted more) over the lifetime ratio.
pub fn drift_evidence(record: &Map<String, Value>) -> Option<f64> {
    if let Some(health) = record.get("health_score").and_then(Value::as_f64) {
        if health.is_finite() && (0.0..=1.0).contains(&health) {
            return Some(health);
        }
    }
    lifetime_success_ratio(record)
}

/// Build the per-bridge drift report section from a `bridge_history.json`
/// document. Returns `(summary_json, stale_positive_entries_json)`.
pub fn bridge_drift_report(
    history: &Value,
    now: &DateTime<Utc>,
) -> (Value, Vec<Value>) {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut health_by_class: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    let mut stale_entries: Vec<Value> = Vec::new();
    let records = history_records(history);
    for record in records {
        let class = classify_drift(record);
        let label = class.label();
        *counts.entry(label).or_default() += 1;
        if let Some(evidence) = drift_evidence(record) {
            health_by_class.entry(label).or_default().push(evidence);
        }
        if class == DriftClass::StalePositive {
            let raw = record
                .get("raw")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            stale_entries.push(json!({
                "raw": raw,
                "transport": record.get("transport").cloned().unwrap_or(Value::Null),
                "probe_successes": record.get("probe_successes").cloned().unwrap_or(Value::Null),
                "probe_failures": record.get("probe_failures").cloned().unwrap_or(Value::Null),
                "health_score": record.get("health_score").cloned().unwrap_or(Value::Null),
                "lifetime_success_ratio": lifetime_success_ratio(record),
                "last_probe": record.get("last_probe").cloned().unwrap_or(Value::Null),
                "days_since_last_probe": record
                    .get("last_probe")
                    .and_then(Value::as_str)
                    .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                    .map(|t| (*now - t.with_timezone(&Utc)).num_days()),
            }));
        }
    }
    let mut medians: BTreeMap<&str, f64> = BTreeMap::new();
    for (label, values) in &health_by_class {
        let mut sorted = values.clone();
        sorted.sort_by(|a, b| a.total_cmp(b));
        if !sorted.is_empty() {
            medians.insert(*label, sorted[sorted.len() / 2]);
        }
    }
    let summary = json!({
        "total_records": records.len(),
        "counts": counts,
        "median_drift_evidence_by_class": medians,
        "note": "drift evidence = collector EWMA health_score (0.8*old + 0.2*outcome, src/tor_collector/storage.rs::record_probe) with lifetime success-ratio fallback; stale_positive = historical successes + currently unreachable + non-fronted transport",
    });
    (summary, stale_entries)
}

impl DriftClass {
    pub fn label(&self) -> &'static str {
        match self {
            DriftClass::Healthy => "healthy",
            DriftClass::StalePositive => "stale_positive",
            DriftClass::FrontedUnreachable => "fronted_unreachable",
            DriftClass::NoHistory => "no_history",
        }
    }
}

fn history_records(history: &Value) -> Vec<&Map<String, Value>> {
    match history {
        Value::Object(map) => {
            // Production shape: { "<key>": {record}, ... }
            map.values().filter_map(Value::as_object).collect()
        }
        Value::Array(items) => items.iter().filter_map(Value::as_object).collect(),
        _ => Vec::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sections 2+3: transport success-rate history, anomaly flags, step changes
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical transport classification by bridge-line prefix — the same rule
/// `scripts/build_nin_recommended_transport.sh` applies (never the possibly
/// malformed `transport` field of iran_results.json, which holds host:port
/// for vanilla "Bridge " lines in the committed data).
pub fn classify_line(line: &str) -> &'static str {
    let trimmed = line.trim_start();
    if trimmed.starts_with("snowflake") {
        "snowflake"
    } else if trimmed.starts_with("webtunnel") {
        "webtunnel"
    } else if trimmed.starts_with("meek") {
        "meek_lite"
    } else if trimmed.starts_with("conjure") {
        "conjure"
    } else if trimmed.starts_with("obfs4") {
        "obfs4"
    } else if trimmed.starts_with("Bridge ") {
        "vanilla"
    } else {
        "unknown"
    }
}

/// This run's per-transport working/total snapshot from iran_results.json.
/// "Working" mirrors `bridge_publication.rs::is_likely_working`: status is
/// not blocked AND (tcp_reachable || transport_capable).
pub fn current_transport_rates(iran_results: &Value) -> BTreeMap<String, (usize, usize)> {
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut working: BTreeMap<String, usize> = BTreeMap::new();
    let empty = Vec::new();
    let bridges = iran_results
        .get("bridges")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for bridge in bridges {
        let line = bridge.get("line").and_then(Value::as_str).unwrap_or("");
        if line.trim().is_empty() {
            continue;
        }
        let transport = classify_line(line).to_string();
        *totals.entry(transport.clone()).or_default() += 1;
        let status = bridge.get("iran_status").and_then(Value::as_str).unwrap_or("");
        let not_blocked = !matches!(
            status,
            "iran_likely_blocked" | "iran_frequently_blocked" | "iran_asn_blocked"
        );
        let reachable = bridge
            .get("tcp_reachable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || bridge
                .get("transport_capable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        if not_blocked && reachable {
            *working.entry(transport).or_default() += 1;
        }
    }
    totals
        .into_iter()
        .map(|(transport, total)| {
            let work = working.get(&transport).copied().unwrap_or(0);
            (transport, (work, total))
        })
        .collect()
}

/// One appended history entry: `{"ts": ..., "rates": {transport: [working, total]}}`.
pub fn history_entry(now: &DateTime<Utc>, rates: &BTreeMap<String, (usize, usize)>) -> Value {
    let rates_json: BTreeMap<String, Value> = rates
        .iter()
        .map(|(transport, (working, total))| {
            (transport.clone(), json!([working, total]))
        })
        .collect();
    json!({
        "ts": now.to_rfc3339(),
        "rates": rates_json,
    })
}

/// Load the accumulated success-history file (empty vector when missing).
pub fn load_success_history(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| {
            value
                .get("entries")
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
}

/// Advisory run-over-run anomaly detection. For each transport present in the
/// current snapshot AND with at least [`MIN_ANOMALY_BASELINE`] prior rate
/// observations, flag when the current success rate drops at least 10
/// percentage points below the trailing mean with a z-score <= -2.
/// Returns per-transport advisory rows (empty when history is too short —
/// the caller reports that state honestly instead).
pub fn anomaly_rows(
    current: &BTreeMap<String, (usize, usize)>,
    prior_entries: &[Value],
) -> Vec<Value> {
    let mut rows = Vec::new();
    for (transport, (working, total)) in current {
        if *total == 0 {
            continue;
        }
        let prior_rates: Vec<f64> = prior_entries
            .iter()
            .filter_map(|entry| {
                entry
                    .get("rates")?
                    .get(transport)?
                    .as_array()
                    .and_then(|pair| {
                        let w = pair.first()?.as_u64()? as f64;
                        let t = pair.get(1)?.as_u64()? as f64;
                        if t > 0.0 {
                            Some(w / t)
                        } else {
                            None
                        }
                    })
            })
            .collect();
        if prior_rates.len() < MIN_ANOMALY_BASELINE {
            rows.push(json!({
                "transport": transport,
                "status": "insufficient_history",
                "prior_observations": prior_rates.len(),
                "required": MIN_ANOMALY_BASELINE,
            }));
            continue;
        }
        let mean = prior_rates.iter().sum::<f64>() / prior_rates.len() as f64;
        let variance = prior_rates
            .iter()
            .map(|r| (r - mean) * (r - mean))
            .sum::<f64>()
            / prior_rates.len() as f64;
        let sd = variance.sqrt();
        let current_rate = *working as f64 / *total as f64;
        let drop = mean - current_rate;
        let z = if sd > 1e-9 {
            (current_rate - mean) / sd
        } else if drop > 0.0 {
            f64::NEG_INFINITY
        } else {
            0.0
        };
        let flagged = drop >= 0.10 && z <= -2.0;
        let status = if flagged { "anomaly_drop" } else { "within_baseline" };
        let z_json = if z.is_finite() {
            json!((z * 100.0).round() / 100.0)
        } else {
            Value::Null
        };
        rows.push(json!({
            "transport": transport,
            "status": status,
            "current_working": working,
            "current_total": total,
            "current_rate": (current_rate * 1000.0).round() / 1000.0,
            "trailing_mean": (mean * 1000.0).round() / 1000.0,
            "trailing_sd": (sd * 1000.0).round() / 1000.0,
            "z": z_json,
            "drop_pp": (drop * 1000.0).round() / 10.0,
            "advisory_only": true,
        }));
    }
    rows.sort_by(|a, b| a["transport"].as_str().cmp(&b["transport"].as_str()));
    rows
}

/// One detected step-change in a transport's rate series.
#[derive(Debug, Clone, PartialEq)]
pub struct StepChange {
    pub transport: String,
    pub split_ts: String,
    pub mean_before: f64,
    pub mean_after: f64,
    pub n_before: usize,
    pub n_after: usize,
}

/// Candidate-changepoint scan: over a `(timestamp, rate)` series, find the
/// split maximizing `|mean(before) - mean(after)|` with at least
/// [`MIN_STEP_SEGMENT`] observations on each side. Returns the best split
/// per transport (the scan is exhaustive over valid split points, so it is
/// deterministic; with fewer than [`MIN_STEP_SERIES`] points it returns None).
pub fn detect_step_change(
    transport: &str,
    series: &[(String, f64)],
) -> Option<StepChange> {
    if series.len() < MIN_STEP_SERIES {
        return None;
    }
    let mut best: Option<StepChange> = None;
    let mut best_gap = 0.0_f64;
    for split in MIN_STEP_SEGMENT..=(series.len() - MIN_STEP_SEGMENT) {
        let before = &series[..split];
        let after = &series[split..];
        let mean_before = before.iter().map(|(_, r)| r).sum::<f64>() / before.len() as f64;
        let mean_after = after.iter().map(|(_, r)| r).sum::<f64>() / after.len() as f64;
        let gap = (mean_after - mean_before).abs();
        if gap > best_gap {
            best_gap = gap;
            best = Some(StepChange {
                transport: transport.to_string(),
                split_ts: after[0].0.clone(),
                mean_before,
                mean_after,
                n_before: before.len(),
                n_after: after.len(),
            });
        }
    }
    best
}

/// Scan every transport that appears often enough in the accumulated series.
pub fn step_changes(prior_entries: &[Value]) -> Vec<StepChange> {
    let mut by_transport: BTreeMap<String, Vec<(String, f64)>> = BTreeMap::new();
    for entry in prior_entries {
        let Some(ts) = entry.get("ts").and_then(Value::as_str) else {
            continue;
        };
        let Some(rates) = entry.get("rates").and_then(Value::as_object) else {
            continue;
        };
        for (transport, pair) in rates {
            let Some(pair) = pair.as_array() else { continue };
            let (Some(w), Some(t)) = (
                pair.first().and_then(Value::as_u64),
                pair.get(1).and_then(Value::as_u64),
            ) else {
                continue;
            };
            if t > 0 {
                by_transport
                    .entry(transport.clone())
                    .or_default()
                    .push((ts.to_string(), w as f64 / t as f64));
            }
        }
    }
    let mut found = Vec::new();
    for (transport, series) in by_transport {
        if let Some(change) = detect_step_change(&transport, &series) {
            found.push(change);
        }
    }
    found
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4: front-domain survivability
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the front domains a bridge line dials, from `front=` (single) and
/// `fronts=` (comma list) parameters.
pub fn front_domains(line: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for token in line.split_whitespace() {
        if let Some(value) = token
            .strip_prefix("fronts=")
            .or_else(|| token.strip_prefix("front="))
        {
            for domain in value.split(',') {
                let domain = domain.trim();
                if !domain.is_empty() {
                    domains.push(domain.to_string());
                }
            }
        }
    }
    domains
}

/// Aggregate per-front-domain survivability across all history records that
/// reference a front. Returns a JSON object keyed by front domain.
pub fn front_survivability(history: &Value) -> Value {
    let mut fronts: BTreeMap<String, Vec<&Map<String, Value>>> = BTreeMap::new();
    for record in history_records(history) {
        let raw = record.get("raw").and_then(Value::as_str).unwrap_or("");
        for domain in front_domains(raw) {
            fronts.entry(domain).or_default().push(record);
        }
    }
    let mut out = Map::new();
    for (domain, records) in fronts {
        let candidates: Vec<Value> = records
            .iter()
            .map(|record| {
                json!({
                    "raw": record.get("raw").cloned().unwrap_or(Value::Null),
                    "transport": record.get("transport").cloned().unwrap_or(Value::Null),
                    "tcp_reachable": record.get("tcp_reachable").cloned().unwrap_or(Value::Null),
                    "health_score": record.get("health_score").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
        let reachable = records
            .iter()
            .filter(|record| {
                record
                    .get("tcp_reachable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .count();
        let health: Vec<f64> = records
            .iter()
            .filter_map(|record| {
                record
                    .get("health_score")
                    .and_then(Value::as_f64)
                    .filter(|h| h.is_finite())
            })
            .collect();
        let mean_health = if health.is_empty() {
            Value::Null
        } else {
            json!((health.iter().sum::<f64>() / health.len() as f64 * 1000.0).round() / 1000.0)
        };
        let concentrated_failure = !records.is_empty() && reachable == 0;
        let advisory = if concentrated_failure {
            format!(
                "front domain unreachable for all {n} candidate(s) using it — treat as a front-level fault, not N independent bridge failures",
                n = records.len()
            )
        } else {
            String::new()
        };
        out.insert(
            domain,
            json!({
                "candidates": candidates.len(),
                "currently_reachable": reachable,
                "mean_candidate_health": mean_health,
                "concentrated_failure": concentrated_failure,
                "advisory": advisory,
                "candidate_details": candidates,
            }),
        );
    }
    Value::Object(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let now = Utc::now();
    let history_path = path_or_env("bridge/bridge_history.json", "DRIFT_HISTORY");
    let iran_path = path_or_env("bridge/iran_results.json", "DRIFT_IRAN");
    let series_path = path_or_env("data/transport_success_history.json", "DRIFT_TS_HISTORY");
    let drift_out = path_or_env("data/bridge_drift_report.json", "DRIFT_OUT");
    let front_out = path_or_env("data/front_domain_survivability.json", "DRIFT_FRONT_OUT");

    let read_json = |path: &Path| -> Option<Value> {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
    };

    println!(
        "═══ Stage 8u — Drift & survivability advisories (additive, non-blocking) ═══"
    );
    // Section 1: per-bridge drift.
    if let Some(history) = read_json(&history_path) {
        let (summary, stale) = bridge_drift_report(&history, &now);
        let stale_count = stale.len();
        println!(
            "  bridge drift: {} records — {}",
            summary["total_records"],
            serde_json::to_string(&summary["counts"]).unwrap_or_default()
        );
        if stale_count > 0 {
            println!(
                "::notice::bridge drift: {stale_count} stale-positive bridge(s) — historical successes but currently unreachable (advisory; see data/bridge_drift_report.json)"
            );
        }
        let report = json!({
            "generated_at": now.to_rfc3339(),
            "summary": summary,
            "stale_positives": stale,
            "advisory_only": true,
        });
        write_json_file(&drift_out, &report);
        println!("  wrote {}", drift_out.display());

        // Section 4: front-domain survivability (same history input).
        let fronts = front_survivability(&history);
        let concentrated: Vec<String> = fronts
            .as_object()
            .map(|map| {
                map.iter()
                    .filter(|(_, value)| {
                        value["concentrated_failure"].as_bool().unwrap_or(false)
                    })
                    .map(|(domain, _)| domain.clone())
                    .collect()
            })
            .unwrap_or_default();
        if let Some(map) = fronts.as_object() {
            println!(
                "  front domains: {} aggregated ({})",
                map.len(),
                map.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        for domain in &concentrated {
            println!(
                "::notice::front domain {domain} is unreachable for every candidate using it (advisory; see data/front_domain_survivability.json)"
            );
        }
        let report = json!({
            "generated_at": now.to_rfc3339(),
            "fronts": fronts,
            "advisory_only": true,
        });
        write_json_file(&front_out, &report);
        println!("  wrote {}", front_out.display());
    } else {
        println!(
            "::notice::bridge history {} unreadable — drift and front sections skipped",
            history_path.display()
        );
    }

    // Sections 2+3: transport success-rate history + anomaly + step changes.
    let mut prior = load_success_history(&series_path);
    if let Some(iran) = read_json(&iran_path) {
        let rates = current_transport_rates(&iran);
        let rates_display: Vec<String> = rates
            .iter()
            .map(|(transport, (working, total))| format!("{transport}:{working}/{total}"))
            .collect();
        println!("  this run per-transport working/total: {}", rates_display.join(" "));
        let entry = history_entry(&now, &rates);
        prior.push(entry);

        let anomalies = anomaly_rows(&rates, &prior);
        for row in &anomalies {
            if row["status"].as_str() == Some("anomaly_drop") {
                println!(
                    "::notice::transport anomaly (advisory): {} — see data/transport_success_history.json",
                    serde_json::to_string(row).unwrap_or_default()
                );
            }
        }
        let flagged = anomalies
            .iter()
            .filter(|row| row["status"].as_str() == Some("anomaly_drop"))
            .count();
        let insufficient = anomalies
            .iter()
            .filter(|row| row["status"].as_str() == Some("insufficient_history"))
            .count();
        println!(
            "  transport anomalies: {flagged} flagged, {insufficient} transport(s) with insufficient history (need {MIN_ANOMALY_BASELINE} prior runs)"

        );
        let steps = step_changes(&prior);
        if steps.is_empty() {
            println!(
                "  step-change scan: no transport has >= {MIN_STEP_SERIES} history entries yet — nothing to scan (the series starts accumulating with this run)"
            );
        } else {
            for step in &steps {
                println!(
                    "::notice::transport step-change (advisory): {} around {} — mean {:.3} -> {:.3} (externally-observable reachability proxy; NOT a claim about the DPI mechanism)",
                    step.transport, step.split_ts, step.mean_before, step.mean_after
                );
            }
        }
        let prior_len = prior.len();
        let series_doc = json!({
            "note": "per-transport working/total per pipeline run, appended by drift_advisory (Stage 8u); working mirrors bridge_publication.rs::is_likely_working",
            "entries": prior,
            "anomalies": anomalies,
            "step_changes": steps,
            "step_change_disclaimer": "a step-change is an externally-observable reachability-rate shift; this repo has no visibility into Iran's actual filtering rules and makes no claim about DPI mechanisms",
        });
        write_json_file(&series_path, &series_doc);
        println!("  wrote {} ({prior_len} entries)", series_path.display());
    } else {
        println!(
            "::notice::iran results {} unreadable — transport-rate section skipped",
            iran_path.display()
        );
    }
    println!("  advisory-only: no CI gate, no bridge/ file, no score was changed");
}

fn write_json_file(path: &Path, value: &Value) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string_pretty(value) {
        if let Err(error) = fs::write(path, format!("{text}\n")) {
            println!(
                "::warning::drift_advisory could not write {}: {error}",
                path.display()
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (fixtures embed REAL records from the committed bridge_history.json)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn record(fields: &[(&str, Value)]) -> Map<String, Value> {
        fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    // Real record (committed bridge_history.json): 47 successes, 31 failures,
    // EWMA health 0.09, currently unreachable — the canonical stale-positive.
    #[test]
    fn classify_drift_flags_real_stale_positive() {
        let rec = record(&[
            ("raw", json!("121.110.203.115:443 ADE62…")),
            ("transport", json!("vanilla")),
            ("probe_successes", json!(47)),
            ("probe_failures", json!(31)),
            ("tcp_reachable", json!(false)),
            ("health_score", json!(0.09)),
        ]);
        assert_eq!(classify_drift(&rec), DriftClass::StalePositive);
        assert_eq!(drift_evidence(&rec), Some(0.09));
        assert_eq!(lifetime_success_ratio(&rec), Some(47.0 / 78.0));
    }

    // Real record: 78 successes, 0 failures, reachable (healthy cohort,
    // median EWMA health 1.0 in the committed dataset).
    #[test]
    fn classify_drift_healthy_and_no_history() {
        let healthy = record(&[
            ("transport", json!("vanilla")),
            ("probe_successes", json!(78)),
            ("probe_failures", json!(0)),
            ("tcp_reachable", json!(true)),
            ("health_score", json!(1.0)),
        ]);
        assert_eq!(classify_drift(&healthy), DriftClass::Healthy);
        let no_history = record(&[
            ("transport", json!("vanilla")),
            ("probe_successes", json!(0)),
            ("tcp_reachable", json!(false)),
        ]);
        assert_eq!(classify_drift(&no_history), DriftClass::NoHistory);
        assert_eq!(lifetime_success_ratio(&no_history), None);
    }

    // Real conjure line: probe_successes>0, tcp_reachable=false, but conjure
    // dials a front domain — must NOT be labelled stale-positive.
    #[test]
    fn classify_drift_exempts_fronted_transports() {
        let rec = record(&[
            (
                "raw",
                json!("conjure 2B28… url=https://registration.refraction.network/api fronts=cdn.sstatic.net,assets.cloud.censys.io"),
            ),
            ("transport", json!("conjure")),
            ("probe_successes", json!(3)),
            ("probe_failures", json!(0)),
            ("tcp_reachable", json!(false)),
        ]);
        assert_eq!(classify_drift(&rec), DriftClass::FrontedUnreachable);
    }

    #[test]
    fn drift_evidence_falls_back_to_lifetime_ratio_without_ewma() {
        let rec = record(&[
            ("probe_successes", json!(2)),
            ("probe_failures", json!(2)),
        ]);
        assert_eq!(drift_evidence(&rec), Some(0.5));
    }

    #[test]
    fn classify_line_matches_the_nin_script_rule() {
        assert_eq!(classify_line("Bridge 1.2.3.4:443 fp"), "vanilla");
        assert_eq!(classify_line("obfs4 1.2.3.4:9001 fp"), "obfs4");
        assert_eq!(classify_line("meek_lite fp url=… front=ajax.aspnetcdn.com"), "meek_lite");
        assert_eq!(classify_line("conjure fp url=…"), "conjure");
        assert_eq!(classify_line("webtunnel fp url=…"), "webtunnel");
        assert_eq!(classify_line("snowflake fp url=…"), "snowflake");
        assert_eq!(classify_line("mystery 1.2.3.4:1"), "unknown");
    }

    #[test]
    fn current_transport_rates_mirrors_is_likely_working_semantics() {
        let doc = json!({
            "bridges": [
                {"line": "obfs4 1.1.1.1:1 f", "iran_status": "iran_unknown", "tcp_reachable": true},
                {"line": "obfs4 2.2.2.2:2 f", "iran_status": "iran_likely_blocked", "tcp_reachable": true},
                {"line": "obfs4 3.3.3.3:3 f", "iran_status": "iran_unknown", "tcp_reachable": false},
                {"line": "webtunnel w url=https://x", "iran_status": "iran_unknown", "tcp_reachable": false, "transport_capable": true},
                {"line": "Bridge 4.4.4.4:443 f", "iran_status": "iran_unknown", "tcp_reachable": false},
            ]
        });
        let rates = current_transport_rates(&doc);
        assert_eq!(rates["obfs4"], (1, 3));
        assert_eq!(rates["webtunnel"], (1, 1));
        assert_eq!(rates["vanilla"], (0, 1));
    }

    #[test]
    fn anomaly_requires_drop_and_zscore_and_baseline() {
        let mut current = BTreeMap::new();
        current.insert("obfs4".to_string(), (10usize, 100usize));
        // Trailing baseline: stable ~50% rate over 6 runs.
        let prior: Vec<Value> = (0..6)
            .map(|_| {
                json!({"ts": "2026-09-01T00:00:00Z", "rates": {"obfs4": [50, 100]}})
            })
            .collect();
        let rows = anomaly_rows(&current, &prior);
        let row = rows.iter().find(|r| r["transport"] == "obfs4").unwrap();
        assert_eq!(row["status"], "anomaly_drop");
        assert_eq!(row["drop_pp"], 40.0);

        // A 4pp drop stays within baseline: the absolute-drop gate (10pp)
        // dominates even when the trailing sd is 0 (z = -inf).
        let mut mild = BTreeMap::new();
        mild.insert("obfs4".to_string(), (46usize, 100usize));
        let rows = anomaly_rows(&mild, &prior);
        let row = rows.iter().find(|r| r["transport"] == "obfs4").unwrap();
        assert_eq!(row["status"], "within_baseline");

        // Too little history: reported as insufficient, never flagged.
        let short: Vec<Value> = (0..2)
            .map(|_| json!({"ts": "t", "rates": {"obfs4": [50, 100]}}))
            .collect();
        let rows = anomaly_rows(&current, &short);
        let row = rows.iter().find(|r| r["transport"] == "obfs4").unwrap();
        assert_eq!(row["status"], "insufficient_history");
    }

    #[test]
    fn step_change_finds_the_largest_shift_and_its_date() {
        // 10 entries at 0.5, then 12 entries at 0.1 → split at index 10.
        let mut series: Vec<(String, f64)> = Vec::new();
        for i in 0..10 {
            series.push((format!("2026-08-{:02}T00:00:00Z", i + 1), 0.5));
        }
        for i in 0..12 {
            series.push((format!("2026-09-{:02}T00:00:00Z", i + 1), 0.1));
        }
        let step = detect_step_change("obfs4", &series).expect("step expected");
        assert_eq!(step.split_ts, "2026-09-01T00:00:00Z");
        assert!((step.mean_before - 0.5).abs() < 1e-9);
        assert!((step.mean_after - 0.1).abs() < 1e-9);
        assert_eq!(step.n_before, 10);
        assert_eq!(step.n_after, 12);

        // Short series: no claim.
        assert!(detect_step_change("obfs4", &series[..19]).is_none());
    }

    #[test]
    fn front_domains_parses_real_line_shapes() {
        // Real meek_lite line (committed bridge/meek_lite.txt):
        assert_eq!(
            front_domains("meek_lite fp url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"),
            vec!["ajax.aspnetcdn.com"]
        );
        // Real conjure line (comma list):
        let conjure_line = concat!(
            "conjure fp url=https://registration.refraction.network/api ",
            "fronts=cdn.sstatic.net,assets.cloud.censys.io transport=min"
        );
        assert_eq!(
            front_domains(conjure_line),
            vec!["cdn.sstatic.net", "assets.cloud.censys.io"]
        );
        // Real snowflake lines carry two fronts each:
        let snowflake_line = concat!(
            "snowflake fp url=https://1098762253.rsc.cdn77.org/ ",
            "fronts=www.cdn77.com,www.phpmyadmin.net ice=…"
        );
        assert_eq!(
            front_domains(snowflake_line),
            vec!["www.cdn77.com", "www.phpmyadmin.net"]
        );
        assert!(front_domains("obfs4 1.2.3.4:9001 fp").is_empty());
    }

    #[test]
    fn front_survivability_flags_concentrated_real_failure() {
        // Real committed dataset shape: both meek_lite candidates share the
        // ajax.aspnetcdn.com front and both are currently unreachable.
        let history = json!({
            "k1": {"raw": "meek_lite f1 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com", "transport": "meek_lite", "tcp_reachable": false, "health_score": 0.0},
            "k2": {"raw": "meek_lite f2 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com", "transport": "meek_lite", "tcp_reachable": false, "health_score": 0.0},
            "k3": {"raw": "snowflake s1 url=https://x/ fronts=www.cdn77.com,www.phpmyadmin.net", "transport": "snowflake", "tcp_reachable": true, "health_score": 1.0},
            "k4": {"raw": "snowflake s2 url=https://x/ fronts=www.cdn77.com,www.phpmyadmin.net", "transport": "snowflake", "tcp_reachable": true, "health_score": 0.9},
            "k5": {"raw": "obfs4 1.2.3.4:9001 f", "transport": "obfs4", "tcp_reachable": true, "health_score": 1.0},
        });
        let fronts = front_survivability(&history);
        let aspnet = fronts.get("ajax.aspnetcdn.com").unwrap();
        assert_eq!(aspnet["candidates"], 2);
        assert_eq!(aspnet["currently_reachable"], 0);
        assert_eq!(aspnet["concentrated_failure"], true);
        let cdn77 = fronts.get("www.cdn77.com").unwrap();
        assert_eq!(cdn77["candidates"], 2);
        assert_eq!(cdn77["currently_reachable"], 2);
        assert_eq!(cdn77["concentrated_failure"], false);
        // Non-fronted bridges never appear.
        assert!(fronts.get("obfs4 1.2.3.4:9001 f").is_none());
    }

    #[test]
    fn history_entry_shape_is_stable() {
        let now = DateTime::parse_from_rfc3339("2026-09-08T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut rates = BTreeMap::new();
        rates.insert("obfs4".to_string(), (158usize, 1144usize));
        let entry = history_entry(&now, &rates);
        assert_eq!(entry["ts"], "2026-09-08T12:00:00+00:00");
        assert_eq!(entry["rates"]["obfs4"], json!([158, 1144]));
    }
}

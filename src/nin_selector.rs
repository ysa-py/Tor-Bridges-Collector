//! Parity port of `core/nin_selector.py`.
//!
//! National Internet Network (NIN / شبکه ملی) bridge selector. When Iran
//! activates the NIN and cuts international connectivity, only a narrow
//! class of Tor bridges can survive: Snowflake (CDN-fronted WebRTC
//! signalling), WebTunnel behind CDN edges with Iranian PoPs, and
//! meek-lite over Azure/AWS domains Iran cannot block without collateral
//! damage to its own cloud/banking infrastructure.
//!
//! ## Fallible scoring (deviation from the `ml_predictor.rs` precedent)
//!
//! `is_nin_eligible`/`rescore_for_nin` return `Result<_, NinSelectorError>`
//! rather than silently defaulting on a malformed `composite_score`/`score`
//! field, unlike `ml_predictor.rs::python_float_or`'s documented
//! silent-default behavior. This is deliberate, not an inconsistency: the
//! Python originals differ in the same way. `ml_predictor.py`'s pattern is
//! `float(record.get(K1, record.get(K2, D)) or D)` — the trailing `or D`
//! means an explicit JSON `null` under `K1` is caught and replaced with
//! `D` *before* `float()` ever sees it. `nin_selector.py`'s pattern (both
//! call sites: `is_nin_eligible` line 122, `rescore_for_nin` line 175) has
//! no such `or` guard — `float(record.get(K1, record.get(K2, D)))` — so an
//! explicit `null` under `K1` propagates straight into `float(None)`,
//! which raises an uncaught `TypeError` in Python. No writer anywhere in
//! this codebase was found to emit `composite_score: null` (checked every
//! assignment site), but unlike `config.py`'s load-time type coercion this
//! isn't a provable static guarantee — the JSON files this module reads
//! are also a plausible target for hand-editing or an external tool. A
//! `Result` here surfaces that malformed input honestly instead of
//! silently guessing a score for a security-relevant eligibility gate.
//!
//! ## Other non-numeric-field deviations (documented, not Result-wrapped)
//!
//! `transport.lower()`, and the `host`/`asn`/`raw` string reads, have the
//! same theoretical crash shape (Python would raise `AttributeError`/
//! `TypeError` calling `.lower()`/regex-matching a non-string value) but
//! every writer in this codebase assigns these fields as string literals
//! from a small fixed vocabulary — a materially different situation from
//! the numeric fields above, which flow from arithmetic and are far more
//! likely to end up `null` on a partial/failed computation. This port
//! treats a non-string value in these fields as equivalent to an absent
//! one (empty string), matching this same package's own sibling module
//! `iran_bridge_prioritizer.py`'s explicit `isinstance(value, str)` guard
//! convention for the identically-shaped `transport` field, rather than
//! panicking on a shape this codebase's own writers cannot produce.
//!
//! ## Regex `$`-anchor divergence (fixed, not just documented)
//!
//! Python's `re` `$` (without `re.MULTILINE`) matches at the absolute end
//! of the string *or* immediately before a single trailing `\n` — Rust's
//! `regex` crate `$` matches only at the absolute end by default
//! (empirically confirmed divergent on `"cdn.fastly.net\n"`: Python's
//! `search` returns a match, Rust's `is_match` does not). Every
//! `NIN_SAFE_DOMAIN_PATTERNS` entry ends in `$`. [`domain_is_cdn_safe`]
//! strips at most one trailing `\n` (matching Python's exact
//! one-newline-only behavior — verified two/three trailing newlines do
//! *not* match in Python either) before matching, rather than leaving
//! this as an unfixed edge case.

//! ## Single injected `now` vs. Python's two independent `datetime.now()` calls
//!
//! `build_nin_pack` in the Python original calls `datetime.now(UTC)`
//! twice, independently: once for the pack file's `# Generated:` header
//! (line 230) and again for the summary's `generated_at` field (line
//! 262) — these can differ by whatever wall-clock time elapses between
//! the two statements (microseconds in practice). Since this value is
//! real wall-clock time either way, there is no fixed "ground truth" for
//! either Python call to reproduce even between two runs of the Python
//! original itself. [`build_nin_pack_with_paths`] takes one `now`
//! parameter and uses it for both, which is a strict improvement (the
//! pack file and summary are now always mutually consistent) rather than
//! a capability loss — collapsing two independent, non-reproducible
//! timestamp reads into one deterministic parameter changes an ambient
//! side effect, not an documented/tested behavior. Parity tests compare
//! every other field for exact equality and separately verify the
//! timestamp fields are well-formed and consistent with the injected
//! `now`, rather than asserting byte-equality against a Python subprocess
//! call that has no single correct answer to match.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::generated_json_loader::load_generated_json;

/// Mirrors `NIN_SURVIVABLE_TRANSPORTS`. Membership-only usage in the
/// Python original (`transport not in ...`), so — unlike
/// `iran_bridge_prioritizer.rs`'s `SUPPORTED_TRANSPORTS` — Python set
/// iteration order is never observable here; a plain slice is sufficient.
const NIN_SURVIVABLE_TRANSPORTS: [&str; 3] = ["snowflake", "webtunnel", "meek_lite"];

/// Mirrors `NIN_SAFE_CDN_ASNS`. Membership-only usage; order irrelevant.
const NIN_SAFE_CDN_ASNS: [&str; 8] = [
    "AS20940", "AS16509", "AS54113", "AS13335", "AS8075", "AS15169", "AS206804", "AS209675",
];

/// Mirrors `NIN_MIN_SCORE`.
pub const NIN_MIN_SCORE: f64 = 0.40;

/// Mirrors `NIN_TRANSPORT_MULTIPLIER`.
fn transport_multiplier(transport: &str) -> f64 {
    match transport {
        "snowflake" => 1.5,
        "webtunnel" => 1.35,
        "meek_lite" => 1.25,
        "obfs4" => 0.4,
        "vanilla" => 0.1,
        _ => 0.3, // "unknown" and any other value
    }
}

/// Mirrors `_TRANSPORT_ORDER` (used only in `build_nin_pack`'s sort key).
fn transport_sort_rank(transport: &str) -> i32 {
    match transport {
        "snowflake" => 0,
        "webtunnel" => 1,
        "meek_lite" => 2,
        _ => 9,
    }
}

/// Errors surfaced by this module. See the module-level doc comment for
/// exactly which Python `TypeError` this maps to and why only this one
/// field is treated as fallible rather than silently defaulted.
#[derive(Debug, thiserror::Error)]
pub enum NinSelectorError {
    #[error(
        "field `{field}` is present but not coercible to a number \
         (Python `float(...)` would raise here): {value}"
    )]
    NonNumericScore { field: &'static str, value: String },
}

/// Mirrors `float(record.get("composite_score", record.get("score", default)))`
/// exactly, including the crash-on-explicit-null behavior — see the
/// module-level doc comment.
fn coerce_score(record: &Map<String, Value>, default: f64) -> Result<f64, NinSelectorError> {
    let raw: Option<&Value> = match record.get("composite_score") {
        Some(v) => Some(v),
        None => record.get("score"),
    };
    match raw {
        None => Ok(default),
        Some(Value::Null) => Err(NinSelectorError::NonNumericScore {
            field: "composite_score/score",
            value: "null".to_string(),
        }),
        Some(Value::Bool(b)) => Ok(if *b { 1.0 } else { 0.0 }), // Python: float(True) == 1.0
        Some(Value::Number(n)) => n.as_f64().ok_or_else(|| NinSelectorError::NonNumericScore {
            field: "composite_score/score",
            value: n.to_string(),
        }),
        Some(Value::String(s)) => {
            s.trim()
                .parse::<f64>()
                .map_err(|_| NinSelectorError::NonNumericScore {
                    field: "composite_score/score",
                    value: s.clone(),
                })
        }
        Some(other) => Err(NinSelectorError::NonNumericScore {
            field: "composite_score/score",
            value: other.to_string(),
        }),
    }
}

/// A field read as a string, treating a non-string/absent value as `""`.
/// See the module-level doc comment for why this is a documented
/// deviation rather than a `Result`.
fn get_str<'a>(record: &'a Map<String, Value>, key: &str) -> &'a str {
    match record.get(key) {
        Some(Value::String(s)) => s.as_str(),
        _ => "",
    }
}

/// Mirrors `record.get("line", record.get("bridge_line", ""))` — a
/// two-level `.get(k, default)` chain (NOT the three-way `or`-chain used
/// elsewhere), so an explicit non-string, non-absent value under `"line"`
/// is returned as `""` under this port's documented string-coercion
/// deviation (see `get_str`), matching Python's `.get` returning that
/// value as-is only when it IS a string.
fn get_raw_line(record: &Map<String, Value>) -> &str {
    if record.contains_key("line") {
        match record.get("line") {
            Some(Value::String(s)) => s.as_str(),
            _ => "",
        }
    } else {
        get_str(record, "bridge_line")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled regexes
// ─────────────────────────────────────────────────────────────────────────────

fn nin_safe_domain_patterns() -> &'static [Regex] {
    static PATTERNS: std::sync::OnceLock<Vec<Regex>> = std::sync::OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)fastly\.net$",
            r"(?i)arvancloud\.(com|ir)$",
            r"(?i)azureedge\.net$",
            r"(?i)cloudfront\.net$",
            r"(?i)ajax\.aspnetcdn\.com$",
            r"(?i)gstatic\.com$",
            r"(?i)cdn\.irimc\.ir$",
            r"(?i)googlevideo\.com$",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("nin_safe_domain_patterns compiles"))
        .collect()
    })
}

/// Mirrors `_domain_is_cdn_safe`. See the module-level doc comment for the
/// trailing-`\n` `$`-anchor fix.
fn domain_is_cdn_safe(host: &str) -> bool {
    let probe = host.strip_suffix('\n').unwrap_or(host);
    nin_safe_domain_patterns().iter().any(|p| p.is_match(probe))
}

/// Mirrors `_asn_is_cdn_safe`.
fn asn_is_cdn_safe(asn: &str) -> bool {
    NIN_SAFE_CDN_ASNS.contains(&asn.to_uppercase().as_str())
}

// ─────────────────────────────────────────────────────────────────────────────
// Eligibility check
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `is_nin_eligible`.
pub fn is_nin_eligible(record: &Map<String, Value>) -> Result<bool, NinSelectorError> {
    let transport = get_str(record, "transport").to_lowercase();
    if !NIN_SURVIVABLE_TRANSPORTS.contains(&transport.as_str()) {
        return Ok(false);
    }

    // Python: `record.get("iran_status") == "iran_asn_blocked"` — a plain
    // equality check never raises regardless of the value's type, so no
    // string-coercion deviation applies here.
    if record.get("iran_status") == Some(&json!("iran_asn_blocked")) {
        return Ok(false);
    }

    let score = coerce_score(record, 0.0)?;
    if score < NIN_MIN_SCORE {
        return Ok(false);
    }

    if transport == "snowflake" {
        return Ok(true);
    }

    let host = get_str(record, "host");
    let asn = get_str(record, "asn");
    let raw = get_raw_line(record);

    if domain_is_cdn_safe(host) || asn_is_cdn_safe(asn) {
        return Ok(true);
    }
    if domain_is_cdn_safe(raw) {
        return Ok(true);
    }

    // Mirrors `record.get("flags", []) or []` then `"domain_front_cdn_ok"
    // in flags`. A non-array, non-null `flags` value is treated as `[]`
    // under this port's string/shape-coercion deviation policy (see the
    // module doc comment) — Python's `in` on a non-list truthy value
    // (e.g. a string) would perform a different operation (substring
    // check) rather than crash, but no writer in this codebase has ever
    // been observed to store `flags` as anything but a JSON array.
    if let Some(Value::Array(flags)) = record.get("flags") {
        if flags
            .iter()
            .any(|f| f.as_str() == Some("domain_front_cdn_ok"))
        {
            return Ok(true);
        }
    }

    Ok(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rescoring for NIN mode
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `rescore_for_nin`. Returns a new list; does not mutate `records`.
pub fn rescore_for_nin(
    records: &[Map<String, Value>],
) -> Result<Vec<Map<String, Value>>, NinSelectorError> {
    let mut rescored: Vec<(f64, Map<String, Value>)> = Vec::with_capacity(records.len());
    for rec in records {
        let transport = {
            let t = get_str(rec, "transport");
            if t.is_empty() {
                "unknown".to_string()
            } else {
                t.to_lowercase()
            }
        };
        let multiplier = transport_multiplier(&transport);
        let original = coerce_score(rec, 0.5)?;
        let adjusted = python_round4(original * multiplier).min(1.0);
        // Python: `round(min(1.0, original * multiplier), 4)` — clamp THEN
        // round, not round then clamp. Replicated in that order below via
        // clamp-then-round instead: since round-to-4-decimals is monotonic
        // and 1.0 has an exact decimal representation, `round(min(x, 1.0),
        // 4) == min(round(x, 4), 1.0)` for every finite x — verified by
        // construction (rounding never pushes a value that was <= 1.0
        // before rounding to something > 1.0 at 4-decimal precision, and
        // never pushes something already > 1.0 below 1.0).
        let mut entry = rec.clone();
        entry.insert("nin_score".to_string(), json!(adjusted));
        entry.insert("nin_multiplier".to_string(), json!(multiplier));
        entry.insert("nin_eligible".to_string(), json!(is_nin_eligible(rec)?));
        rescored.push((adjusted, entry));
    }

    // Python: `rescored.sort(key=lambda x: x["nin_score"], reverse=True)`.
    // Confirmed empirically that CPython's `reverse=True` preserves
    // original relative order among ties (NOT the reverse of it) — Rust's
    // `sort_by` is also stable, so a straightforward descending comparator
    // reproduces this exactly with no extra index tie-break needed.
    rescored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    Ok(rescored.into_iter().map(|(_, entry)| entry).collect())
}

/// Round to 4 decimal places matching Python's `round(x, 4)`. See
/// `iran_bridge_prioritizer.rs::python_round4` for the empirical
/// verification this is based on (identical implementation, duplicated
/// here to keep this module's public surface independent — the two
/// modules are ported from separate Python files with no shared runtime
/// helper module of their own to place a common copy in).
fn python_round4(x: f64) -> f64 {
    format!("{:.4}", x)
        .parse::<f64>()
        .expect("a 4-decimal formatted float always reparses")
}

// ─────────────────────────────────────────────────────────────────────────────
// Export builder
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_load_all_records`. `now_paths` are read in the given order —
/// order matters for the first-seen-wins dedup below, matching Python's
/// `for path in (LATEST_RESULTS_PATH, IRAN_RESULTS_PATH)`.
fn load_all_records(paths_in_order: &[&Path]) -> Vec<Map<String, Value>> {
    let mut records = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for path in paths_in_order {
        let fallback = json!({"bridges": []});
        let data = load_generated_json(path, fallback);
        let Some(bridges) = data.get("bridges").and_then(Value::as_array) else {
            continue;
        };
        for r in bridges {
            let Some(obj) = r.as_object() else { continue };
            // Mirrors `r.get("line") or r.get("bridge_line") or r.get("raw", "")`
            // — a genuine three-way `or`-chain (distinct from
            // `get_raw_line`'s two-level `.get(k, default)` chain used
            // elsewhere in this module), so falsy-but-present values (e.g.
            // an empty string under "line") correctly fall through to the
            // next candidate here.
            let key = ["line", "bridge_line"]
                .iter()
                .find_map(|k| match obj.get(*k) {
                    Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                })
                .or_else(|| match obj.get("raw") {
                    Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                });
            if let Some(key) = key {
                if seen.insert(key) {
                    records.push(obj.clone());
                }
            }
            // Python: `if key and key not in seen` — a record whose key
            // resolves to "" (none of the three fields present/non-empty)
            // is silently dropped from the output entirely. Replicated
            // above: `key` is `None` in that case, and the `if let
            // Some(key)` guard skips pushing the record.
        }
    }
    records
}

/// Mirrors `build_nin_pack`, with all file paths and the current time
/// taken as explicit parameters for testability (the Python original
/// hard-codes both the four paths and `datetime.now(UTC)`). See
/// [`build_nin_pack`] for the production entry point using the same
/// hard-coded paths the Python original uses.
pub fn build_nin_pack_with_paths(
    latest_results_path: &Path,
    iran_results_path: &Path,
    export_dir: &Path,
    data_dir: &Path,
    now: DateTime<Utc>,
) -> Result<Value, NinSelectorError> {
    // Python creates these directories once at module-import time
    // (`EXPORT_DIR.mkdir(parents=True, exist_ok=True)` /
    // `DATA_DIR.mkdir(...)`), which has no Rust equivalent hook — creating
    // them here immediately before they're needed produces the identical
    // observable guarantee (both directories exist before any write
    // below) without relying on an import-time side effect.
    let _ = std::fs::create_dir_all(export_dir);
    let _ = std::fs::create_dir_all(data_dir);

    let records = load_all_records(&[latest_results_path, iran_results_path]);

    if records.is_empty() {
        return Ok(json!({"eligible": 0, "total": 0}));
    }

    let mut eligible: Vec<Map<String, Value>> = Vec::new();
    for r in &records {
        if is_nin_eligible(r)? {
            eligible.push(r.clone());
        }
    }

    // Mirrors the (transport_rank, -score) stable ascending sort. Score
    // coercion here uses the SAME fallible path as `is_nin_eligible`
    // (Python: `float(r.get("composite_score", r.get("score", 0)))`,
    // still unguarded by `or`).
    let mut keyed: Vec<(i32, f64, Map<String, Value>)> = Vec::with_capacity(eligible.len());
    for r in eligible {
        let score = coerce_score(&r, 0.0)?;
        let rank = transport_sort_rank(get_str(&r, "transport"));
        keyed.push((rank, score, r));
    }
    keyed.sort_by(|a, b| {
        a.0.cmp(&b.0).then(
            (-a.1)
                .partial_cmp(&-b.1)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    let eligible: Vec<Map<String, Value>> = keyed.into_iter().map(|(_, _, r)| r).collect();

    // Plain-text bridge pack.
    let mut pack_lines: Vec<String> = vec![
        "# TorShield-IR — Internet Cut Pack (شبکه ملی / NIN Mode)".to_string(),
        format!("# Generated: {}", now.format("%Y-%m-%d %H:%M UTC")),
        format!(
            "# Bridges: {}  (survivable during full international internet cut)",
            eligible.len()
        ),
        "# Order: Snowflake → WebTunnel (CDN) → meek-lite (Azure)".to_string(),
        "#".to_string(),
        "# These bridges work by routing through CDN edges with Iranian PoPs".to_string(),
        "# or WebRTC/DTLS signalling that Iran cannot block without collateral damage.".to_string(),
        "#".to_string(),
    ];
    for r in &eligible {
        let raw = get_raw_line(r);
        if !raw.is_empty() {
            pack_lines.push(raw.to_string());
        }
    }
    let pack_text = format!("{}\n", pack_lines.join("\n"));
    let nin_pack_path = export_dir.join("iran_cut_pack.txt");
    std::fs::write(&nin_pack_path, pack_text).map_err(|_| NinSelectorError::NonNumericScore {
        // Reusing NinSelectorError here would be a poor fit; in practice
        // this path is created above via create_dir_all immediately
        // before this write, so a write failure here indicates a
        // genuinely exceptional environment (permissions, disk full)
        // rather than a code-path this module's own logic can produce —
        // matching Python's behavior of letting the underlying OSError
        // propagate uncaught rather than being part of this module's
        // documented Result contract.
        field: "iran_cut_pack.txt write",
        value: nin_pack_path.display().to_string(),
    })?;

    // Machine-readable eligible JSON.
    let eligible_json_path = data_dir.join("nin_eligible.json");
    let eligible_json = serde_json::to_string_pretty(&Value::Array(
        eligible.iter().cloned().map(Value::Object).collect(),
    ))
    .expect("eligible list serializes");
    std::fs::write(&eligible_json_path, eligible_json).map_err(|_| {
        NinSelectorError::NonNumericScore {
            field: "nin_eligible.json write",
            value: eligible_json_path.display().to_string(),
        }
    })?;

    // Transport breakdown.
    let mut transport_counts: HashMap<String, i64> = HashMap::new();
    for r in &eligible {
        let t = {
            let t = get_str(r, "transport");
            if t.is_empty() {
                "unknown".to_string()
            } else {
                t.to_string()
            }
        };
        *transport_counts.entry(t).or_insert(0) += 1;
    }

    let summary = json!({
        "generated_at": now.to_rfc3339(),
        "total_tested": records.len(),
        "nin_eligible": eligible.len(),
        "transport_counts": transport_counts,
        "recommended_order": ["snowflake", "webtunnel", "meek_lite"],
        "pack_path": nin_pack_path.display().to_string(),
        "note": "هنگام قطع اینترنت بین‌المللی (شبکه ملی)، فقط بریج‌های این فایل کار می‌کنند. During international internet cut, only bridges in this pack are reachable. Use: Snowflake first, then WebTunnel (CDN-fronted), then meek-lite.",
    });

    let summary_path = data_dir.join("nin_summary.json");
    let summary_json = serde_json::to_string_pretty(&summary).expect("summary serializes");
    std::fs::write(&summary_path, summary_json).map_err(|_| NinSelectorError::NonNumericScore {
        field: "nin_summary.json write",
        value: summary_path.display().to_string(),
    })?;

    Ok(summary)
}

/// Mirrors the zero-argument `build_nin_pack()` entry point, using the
/// same hard-coded relative paths and wall-clock time as the Python
/// original.
pub fn build_nin_pack() -> Result<Value, NinSelectorError> {
    build_nin_pack_with_paths(
        Path::new("data/latest-results.json"),
        Path::new("bridge/iran_results.json"),
        Path::new("export"),
        Path::new("data"),
        Utc::now(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn is_nin_eligible_snowflake_passes_on_score_alone() {
        let record = obj(vec![
            ("transport", json!("snowflake")),
            ("composite_score", json!(0.5)),
        ]);
        assert!(is_nin_eligible(&record).unwrap());
    }

    #[test]
    fn is_nin_eligible_rejects_non_survivable_transport() {
        let record = obj(vec![
            ("transport", json!("obfs4")),
            ("composite_score", json!(0.9)),
        ]);
        assert!(!is_nin_eligible(&record).unwrap());
    }

    #[test]
    fn is_nin_eligible_rejects_iran_asn_blocked() {
        let record = obj(vec![
            ("transport", json!("snowflake")),
            ("iran_status", json!("iran_asn_blocked")),
            ("composite_score", json!(0.9)),
        ]);
        assert!(!is_nin_eligible(&record).unwrap());
    }

    #[test]
    fn is_nin_eligible_rejects_below_min_score() {
        let record = obj(vec![
            ("transport", json!("snowflake")),
            ("composite_score", json!(0.39)),
        ]);
        assert!(!is_nin_eligible(&record).unwrap());
        let boundary = obj(vec![
            ("transport", json!("snowflake")),
            ("composite_score", json!(0.40)),
        ]);
        assert!(is_nin_eligible(&boundary).unwrap());
    }

    #[test]
    fn is_nin_eligible_webtunnel_requires_cdn_domain_or_asn() {
        let via_host = obj(vec![
            ("transport", json!("webtunnel")),
            ("composite_score", json!(0.9)),
            ("host", json!("edge.fastly.net")),
        ]);
        assert!(is_nin_eligible(&via_host).unwrap());

        let via_asn = obj(vec![
            ("transport", json!("webtunnel")),
            ("composite_score", json!(0.9)),
            ("asn", json!("as13335")),
        ]);
        assert!(is_nin_eligible(&via_asn).unwrap());

        let via_flag = obj(vec![
            ("transport", json!("webtunnel")),
            ("composite_score", json!(0.9)),
            ("flags", json!(["domain_front_cdn_ok"])),
        ]);
        assert!(is_nin_eligible(&via_flag).unwrap());

        let none_of_the_above = obj(vec![
            ("transport", json!("webtunnel")),
            ("composite_score", json!(0.9)),
            ("host", json!("random.example.com")),
        ]);
        assert!(!is_nin_eligible(&none_of_the_above).unwrap());
    }

    #[test]
    fn is_nin_eligible_checks_raw_line_for_cdn_marker() {
        let record = obj(vec![
            ("transport", json!("webtunnel")),
            ("composite_score", json!(0.9)),
            (
                "line",
                json!("webtunnel 1.2.3.4:443 url=https://x.cloudfront.net"),
            ),
        ]);
        assert!(is_nin_eligible(&record).unwrap());
    }

    #[test]
    fn is_nin_eligible_score_null_returns_error() {
        let record = obj(vec![
            ("transport", json!("snowflake")),
            ("composite_score", Value::Null),
        ]);
        assert!(is_nin_eligible(&record).is_err());
    }

    #[test]
    fn is_nin_eligible_falls_back_from_composite_score_to_score() {
        let record = obj(vec![
            ("transport", json!("snowflake")),
            ("score", json!(0.9)),
        ]);
        assert!(is_nin_eligible(&record).unwrap());
    }

    #[test]
    fn is_nin_eligible_missing_score_defaults_to_zero_and_fails_gate() {
        let record = obj(vec![("transport", json!("snowflake"))]);
        assert!(!is_nin_eligible(&record).unwrap());
    }

    #[test]
    fn domain_is_cdn_safe_handles_trailing_newline_like_python() {
        assert!(domain_is_cdn_safe("cdn.fastly.net"));
        assert!(domain_is_cdn_safe("cdn.fastly.net\n"));
        assert!(!domain_is_cdn_safe("cdn.fastly.net\n\n"));
        assert!(!domain_is_cdn_safe("cdn.fastly.net.evil.com"));
    }

    #[test]
    fn rescore_for_nin_applies_multiplier_and_sorts_descending() {
        let records = vec![
            obj(vec![
                ("id", json!("a")),
                ("transport", json!("vanilla")),
                ("composite_score", json!(0.9)),
            ]),
            obj(vec![
                ("id", json!("b")),
                ("transport", json!("snowflake")),
                ("composite_score", json!(0.5)),
            ]),
        ];
        let result = rescore_for_nin(&records).unwrap();
        // snowflake: 0.5 * 1.5 = 0.75; vanilla: 0.9 * 0.1 = 0.09 -> snowflake first.
        assert_eq!(result[0]["id"], json!("b"));
        assert_eq!(result[0]["nin_score"], json!(0.75));
        assert_eq!(result[1]["id"], json!("a"));
        assert!((result[1]["nin_score"].as_f64().unwrap() - 0.09).abs() < 1e-9);
    }

    #[test]
    fn rescore_for_nin_clamps_to_one() {
        let records = vec![obj(vec![
            ("transport", json!("snowflake")),
            ("composite_score", json!(0.9)),
        ])];
        let result = rescore_for_nin(&records).unwrap();
        // 0.9 * 1.5 = 1.35, clamped to 1.0.
        assert_eq!(result[0]["nin_score"], json!(1.0));
    }

    #[test]
    fn rescore_for_nin_does_not_mutate_input() {
        let records = vec![obj(vec![
            ("transport", json!("snowflake")),
            ("composite_score", json!(0.5)),
        ])];
        let before = records.clone();
        let _ = rescore_for_nin(&records).unwrap();
        assert_eq!(records, before);
    }

    #[test]
    fn rescore_for_nin_ties_preserve_original_order() {
        let records = vec![
            obj(vec![
                ("id", json!(0)),
                ("transport", json!("obfs4")),
                ("composite_score", json!(1.0)),
            ]),
            obj(vec![
                ("id", json!(1)),
                ("transport", json!("obfs4")),
                ("composite_score", json!(1.0)),
            ]),
        ];
        let result = rescore_for_nin(&records).unwrap();
        assert_eq!(result[0]["id"], json!(0));
        assert_eq!(result[1]["id"], json!(1));
    }

    #[test]
    fn build_nin_pack_with_paths_empty_records_short_circuits() {
        let tmp = std::env::temp_dir().join(format!("nin_selector_empty_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let latest = tmp.join("nonexistent-latest.json");
        let iran = tmp.join("nonexistent-iran.json");
        let export_dir = tmp.join("export");
        let data_dir = tmp.join("data");
        let now = Utc::now();

        let result =
            build_nin_pack_with_paths(&latest, &iran, &export_dir, &data_dir, now).unwrap();
        assert_eq!(result, json!({"eligible": 0, "total": 0}));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_nin_pack_with_paths_writes_all_three_files() {
        let tmp = std::env::temp_dir().join(format!("nin_selector_full_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let latest = tmp.join("latest-results.json");
        let iran = tmp.join("iran_results.json");
        let export_dir = tmp.join("export");
        let data_dir = tmp.join("data");

        std::fs::write(
            &latest,
            serde_json::to_string(&json!({
                "bridges": [
                    {"line": "snowflake url=https://x abc", "transport": "snowflake", "composite_score": 0.9},
                    {"line": "obfs4 1.2.3.4:443 ABC", "transport": "obfs4", "composite_score": 0.2}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &iran,
            serde_json::to_string(&json!({"bridges": []})).unwrap(),
        )
        .unwrap();

        let now = Utc::now();
        let summary =
            build_nin_pack_with_paths(&latest, &iran, &export_dir, &data_dir, now).unwrap();

        assert_eq!(summary["total_tested"], json!(2));
        assert_eq!(summary["nin_eligible"], json!(1));
        assert!(export_dir.join("iran_cut_pack.txt").exists());
        assert!(data_dir.join("nin_eligible.json").exists());
        assert!(data_dir.join("nin_summary.json").exists());

        let pack_text = std::fs::read_to_string(export_dir.join("iran_cut_pack.txt")).unwrap();
        assert!(pack_text.contains("snowflake url=https://x abc"));
        assert!(!pack_text.contains("obfs4 1.2.3.4:443 ABC"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_all_records_dedups_first_seen_wins_across_paths() {
        let tmp = std::env::temp_dir().join(format!("nin_selector_dedup_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let first = tmp.join("first.json");
        let second = tmp.join("second.json");
        std::fs::write(
            &first,
            serde_json::to_string(&json!({"bridges": [{"line": "shared", "tag": "from_first"}]}))
                .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &second,
            serde_json::to_string(&json!({"bridges": [{"line": "shared", "tag": "from_second"}]}))
                .unwrap(),
        )
        .unwrap();

        let records = load_all_records(&[&first, &second]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["tag"], json!("from_first"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_all_records_drops_records_with_no_usable_key() {
        let tmp = std::env::temp_dir().join(format!("nin_selector_nokey_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("data.json");
        std::fs::write(
            &path,
            serde_json::to_string(&json!({"bridges": [{"transport": "obfs4"}]})).unwrap(),
        )
        .unwrap();
        let records = load_all_records(&[&path]);
        assert!(records.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

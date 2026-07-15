//! Parity port of `anti_ai_dpi.py`.
//!
//! Anti-AI Deep Packet Inspection Evasion for Iran. Scores bridges for
//! ML-classifier evasion under Iran's SIAM/NGFW ML-based DPI, which has
//! been integrated since 2022 (confirmed by Censored Planet / OONI reports).
//!
//! # Iran DPI ML pipeline (observed behaviour, 2022-2026)
//!
//! * Traffic volume/timing analysis via temporal clustering
//! * JA3 fingerprint matching against Tor relay database
//! * Protocol length distribution analysis (defeats vanilla Tor easily)
//! * SNI blocklist + wildcard matching
//! * Certificate fingerprint DB matching
//!
//! # Countermeasures scored (mirrors Python `TRANSPORT_DPI_SCORES`)
//!
//! | Transport  | Score | Rationale                                              |
//! |------------|-------|--------------------------------------------------------|
//! | snowflake  | 0.92  | DTLS/WebRTC — Iran classifies as video call            |
//! | webtunnel  | 0.88  | Pure HTTPS — indistinguishable from normal web traffic |
//! | meek_lite  | 0.80  | CDN-fronted HTTPS                                      |
//! | obfs4      | 0.72  | Random padding defeats traffic classifiers             |
//! | vanilla    | 0.05  | Fully identifiable — no evasion                        |
//!
//! # Behavior traced to `anti_ai_dpi.py`
//!
//! * [`IRAN_BLOCKED_JA3`] — known-blocked JA3 fingerprints.
//! * [`TRANSPORT_DPI_SCORES`] — transport → score table.
//! * [`SAFE_PORTS`] — ports NOT in Iran DPI Tor-port blocklist.
//! * [`detect_transport`] — `_detect_transport(line)`.
//! * [`extract_port`] — `_extract_port(line)`.
//! * [`score_anti_ai_dpi`] — `score_anti_ai_dpi(line)`.
//! * [`run_pipeline`] — orchestrates load → score → sort → write report.
//!
//! # Side effects not ported
//!
//! * `main()` orchestration reads `bridge/bridge_list_for_testing.json` and
//!   writes `data/anti_ai_dpi_report.json` + `export/anti_ai_dpi_bridges.txt`.
//!   Both behaviors are exposed as [`run_pipeline`] taking injectable paths.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use regex::Regex;
use serde_json::{json, Map, Value};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (mirrors module-level constants in anti_ai_dpi.py)
// ─────────────────────────────────────────────────────────────────────────────

/// Iran DPI known-blocked JA3 fingerprints (Python `IRAN_BLOCKED_JA3` set).
pub const IRAN_BLOCKED_JA3: &[&str] = &[
    "e7d705a3286e19ea42f587b344ee6865", // Default Tor Browser JA3
    "6734f37431670b3ab4292b8f60f29984", // Legacy Tor PT handshake
    "51523dc8c3d26b21defdcbe4ab87c9e0", // obfs4 misconfigured
];

/// Transport anti-AI-DPI scores (Python `TRANSPORT_DPI_SCORES` dict).
pub fn transport_dpi_score(transport: &str) -> f64 {
    match transport {
        "snowflake" => 0.92,
        "webtunnel" => 0.88,
        "meek_lite" => 0.80,
        "obfs4" => 0.72,
        _ => 0.05, // vanilla + unknown
    }
}

/// Ports NOT in Iran DPI Tor-port blocklist (Python `SAFE_PORTS` set).
pub const SAFE_PORTS: &[u16] = &[443, 80, 8080, 8443, 2053, 2083, 2087, 2096, 1194, 51820];

/// Tor-known ports that Iran explicitly blocks (Python inline set).
pub const TOR_KNOWN_PORTS: &[u16] = &[9001, 9030, 9050];

/// CDN keyword hints used by the bonus logic (Python inline set).
pub const CDN_HINT_KEYWORDS: &[&str] = &["cloudflare", "fastly", "akamai", "cloudfront", "arvan"];

/// Returns true if `port` is in [`SAFE_PORTS`].
pub fn is_safe_port(port: u16) -> bool {
    SAFE_PORTS.contains(&port)
}

/// Returns true if `port` is in [`TOR_KNOWN_PORTS`].
pub fn is_tor_known_port(port: u16) -> bool {
    TOR_KNOWN_PORTS.contains(&port)
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `anti_ai_dpi.py` parity port.
#[derive(Debug, Error)]
pub enum AntiAiDpiError {
    /// File I/O failure on the input bridge JSON or output report path.
    #[error("anti_ai_dpi I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Input bridge JSON was not a JSON array of strings.
    #[error("anti_ai_dpi: bridge list is not a JSON array of strings (got {0})")]
    InvalidBridgeList(String),

    /// Bridge list JSON could not be parsed.
    #[error("anti_ai_dpi: bridge list JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge-line parsing helpers (mirror Python regex and detection)
// ─────────────────────────────────────────────────────────────────────────────

/// Detect transport from a bridge line. Mirrors Python `_detect_transport`:
/// * `"snowflake" in l` → snowflake
/// * `"webtunnel" in l or "url=https" in l` → webtunnel
/// * `"obfs4" in l` → obfs4
/// * `"meek" in l` → meek_lite
/// * else → vanilla
pub fn detect_transport(line: &str) -> &'static str {
    let l = line.to_lowercase();
    if l.contains("snowflake") {
        "snowflake"
    } else if l.contains("webtunnel") || l.contains("url=https") {
        "webtunnel"
    } else if l.contains("obfs4") {
        "obfs4"
    } else if l.contains("meek") {
        "meek_lite"
    } else {
        "vanilla"
    }
}

/// Extract port from a bridge line. Mirrors Python `_extract_port`:
/// 1. Try HTTPS regex: `https?://([^/:\s]+)(?::(\d+))?` — if group 2 present,
///    parse it; otherwise default to 443.
/// 2. Fall back to IPv4 regex: `(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})`.
/// 3. Return None if neither matches.
pub fn extract_port(line: &str) -> Option<u16> {
    let https_re = Regex::new(r"(?i)https?://([^/\s:]+)(?::(\d+))?").ok()?;
    if let Some(caps) = https_re.captures(line) {
        if let Some(p) = caps.get(2) {
            return p.as_str().parse::<u16>().ok();
        }
        return Some(443);
    }
    let ip4_re = Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})").ok()?;
    let caps = ip4_re.captures(line)?;
    caps[2].parse::<u16>().ok()
}

/// Score a single bridge line for anti-AI-DPI effectiveness. Mirrors Python
/// `score_anti_ai_dpi(line)` exactly, including:
/// * transport base score (with default 0.05 for unknown)
/// * port safety bonus (+0.05 safe_port, +0.03 ephemeral_port, -0.10 tor_known_port)
/// * iat-mode=2 bonus (+0.08 obfs4_iat_timing_randomised)
/// * CDN hint bonus (+0.05 cdn_hinted)
/// * `min(base + bonus, 1.0)` clamp + `round(..., 3)` precision
/// * `iran_ml_dpi_risk` classification thresholds
/// * `flags` vector accumulation order
pub fn score_anti_ai_dpi(line: &str) -> Value {
    let trimmed = line.trim();
    let transport = detect_transport(trimmed);
    let port = extract_port(trimmed);

    let base_score = transport_dpi_score(transport);
    let mut flags: Vec<&str> = Vec::new();
    let mut bonus: f64 = 0.0;

    match port {
        Some(p) if is_safe_port(p) => {
            bonus += 0.05;
            flags.push("safe_port");
        }
        Some(p) if p > 49152 => {
            bonus += 0.03;
            flags.push("ephemeral_port");
        }
        Some(p) if is_tor_known_port(p) => {
            bonus -= 0.10;
            flags.push("tor_known_port");
        }
        _ => {}
    }

    // Python: `if "iat-mode=2" in line or "iat-mode=2" in line:` — duplicated
    // condition (always the same check). We mirror the single effective check.
    if trimmed.contains("iat-mode=2") {
        bonus += 0.08;
        flags.push("obfs4_iat_timing_randomised");
    }

    // CDN hint in line (case-insensitive)
    let lower = trimmed.to_lowercase();
    if CDN_HINT_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        bonus += 0.05;
        flags.push("cdn_hinted");
    }

    let final_score = ((base_score + bonus).min(1.0) * 1000.0).round() / 1000.0;

    let risk = if final_score >= 0.80 {
        "VERY_LOW"
    } else if final_score >= 0.60 {
        "LOW"
    } else if final_score >= 0.40 {
        "MEDIUM"
    } else if final_score >= 0.20 {
        "HIGH"
    } else {
        "CRITICAL"
    };

    let mut out = Map::new();
    out.insert("bridge_line".to_string(), json!(trimmed));
    out.insert("transport".to_string(), json!(transport));
    out.insert(
        "port".to_string(),
        match port {
            Some(p) => json!(p),
            None => Value::Null,
        },
    );
    out.insert("anti_ai_dpi_score".to_string(), json!(final_score));
    out.insert("iran_ml_dpi_risk".to_string(), json!(risk));
    out.insert(
        "flags".to_string(),
        json!(flags.into_iter().collect::<Vec<_>>()),
    );
    Value::Object(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline orchestration (mirrors Python `main()`)
// ─────────────────────────────────────────────────────────────────────────────

/// Run the full anti-AI-DPI scoring pipeline:
/// 1. Read `bridge/bridge_list_for_testing.json` (JSON array of strings).
/// 2. Score each bridge via [`score_anti_ai_dpi`].
/// 3. Sort by `anti_ai_dpi_score` descending.
/// 4. Write `{"anti_ai_dpi_results": [...]}` to `data/anti_ai_dpi_report.json`.
/// 5. Write bridges whose `iran_ml_dpi_risk` is `VERY_LOW` or `LOW` to
///    `export/anti_ai_dpi_bridges.txt`, one per line, with trailing newline.
pub fn run_pipeline(
    bridge_json_path: &Path,
    report_path: &Path,
    export_path: &Path,
) -> Result<(), AntiAiDpiError> {
    let raw = fs::read_to_string(bridge_json_path).map_err(|source| AntiAiDpiError::Io {
        path: bridge_json_path.display().to_string(),
        source,
    })?;
    let bridges: Vec<String> = serde_json::from_str(&raw)
        .map_err(AntiAiDpiError::Json)
        .and_then(|v: Value| match v {
            Value::Array(arr) => arr
                .into_iter()
                .map(|x| match x {
                    Value::String(s) => Ok(s),
                    other => Err(AntiAiDpiError::InvalidBridgeList(format!(
                        "element is not a string: {other}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>(),
            other => Err(AntiAiDpiError::InvalidBridgeList(format!(
                "expected array, got {other}"
            ))),
        })?;

    let mut results: Vec<Value> = bridges.iter().map(|b| score_anti_ai_dpi(b)).collect();

    results.sort_by(|a, b| {
        let sa = a
            .get("anti_ai_dpi_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let sb = b
            .get("anti_ai_dpi_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    let report = json!({ "anti_ai_dpi_results": results });
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).map_err(|source| AntiAiDpiError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let report_bytes = serde_json::to_string_pretty(&report).unwrap_or_default() + "\n";
    fs::write(report_path, report_bytes).map_err(|source| AntiAiDpiError::Io {
        path: report_path.display().to_string(),
        source,
    })?;

    let top: Vec<&str> = results
        .iter()
        .filter_map(|r| {
            let risk = r.get("iran_ml_dpi_risk").and_then(Value::as_str);
            if matches!(risk, Some("VERY_LOW") | Some("LOW")) {
                r.get("bridge_line").and_then(Value::as_str)
            } else {
                None
            }
        })
        .collect();
    if !top.is_empty() {
        if let Some(parent) = export_path.parent() {
            fs::create_dir_all(parent).map_err(|source| AntiAiDpiError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let mut out = top.join("\n");
        out.push('\n');
        fs::write(export_path, out).map_err(|source| AntiAiDpiError::Io {
            path: export_path.display().to_string(),
            source,
        })?;
    }

    // Track the set of unique transports observed (mirrors Python
    // `probe_status_counts` Counter style — we compute but don't print
    // to keep behaviour parity without a logging side effect).
    let _transports_seen: BTreeSet<String> = results
        .iter()
        .filter_map(|r| r.get("transport").and_then(Value::as_str).map(String::from))
        .collect();

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_dpi_scores_match_python_dict() {
        assert_eq!(transport_dpi_score("snowflake"), 0.92);
        assert_eq!(transport_dpi_score("webtunnel"), 0.88);
        assert_eq!(transport_dpi_score("meek_lite"), 0.80);
        assert_eq!(transport_dpi_score("obfs4"), 0.72);
        assert_eq!(transport_dpi_score("vanilla"), 0.05);
        assert_eq!(transport_dpi_score("unknown"), 0.05);
    }

    #[test]
    fn detect_transport_priority_matches_python() {
        // snowflake > (webtunnel | url=https) > obfs4 > meek > vanilla
        assert_eq!(detect_transport("snowflake 1.2.3.4:443"), "snowflake");
        assert_eq!(detect_transport("webtunnel url=https://x"), "webtunnel");
        assert_eq!(detect_transport("url=https://x"), "webtunnel");
        assert_eq!(detect_transport("obfs4 1.2.3.4:443"), "obfs4");
        assert_eq!(detect_transport("meek 1.2.3.4:443"), "meek_lite");
        assert_eq!(detect_transport("vanilla 1.2.3.4:443"), "vanilla");
    }

    #[test]
    fn extract_port_https_with_explicit_port() {
        assert_eq!(extract_port("https://example.com:8443/path"), Some(8443));
    }

    #[test]
    fn extract_port_https_default_443() {
        assert_eq!(extract_port("https://example.com/path"), Some(443));
    }

    #[test]
    fn extract_port_http_default_443() {
        // Python regex matches http:// too — and group 2 absent → 443
        assert_eq!(extract_port("http://example.com/path"), Some(443));
    }

    #[test]
    fn extract_port_ipv4_fallback() {
        assert_eq!(extract_port("obfs4 1.2.3.4:443 cert=abc"), Some(443));
    }

    #[test]
    fn extract_port_no_match_returns_none() {
        assert!(extract_port("vanilla line without port").is_none());
    }

    #[test]
    fn score_vanilla_no_port_minimal() {
        let r = score_anti_ai_dpi("vanilla-line");
        assert_eq!(r["transport"], "vanilla");
        assert!(r["port"].is_null());
        // 0.05 base, no port bonus, no flags
        assert_eq!(r["anti_ai_dpi_score"], 0.05);
        assert_eq!(r["iran_ml_dpi_risk"], "CRITICAL");
    }

    #[test]
    fn score_vanilla_safe_port_443() {
        let r = score_anti_ai_dpi("vanilla 1.2.3.4:443");
        // 0.05 + 0.05 (safe_port) = 0.10 → CRITICAL
        assert_eq!(r["anti_ai_dpi_score"], 0.10);
        assert_eq!(r["iran_ml_dpi_risk"], "CRITICAL");
        assert_eq!(r["flags"][0], "safe_port");
    }

    #[test]
    fn score_vanilla_tor_known_port_9001() {
        let r = score_anti_ai_dpi("vanilla 1.2.3.4:9001");
        // 0.05 - 0.10 = -0.05 → clamp via min(1.0) but NOT max(0.0)?
        // Python: `min(base_score + bonus, 1.0)` — only clamps upper bound.
        // -0.05 → -0.05 (round to 3 decimals = -0.05)
        // But this can't happen because Python: `0.05 + (-0.10) = -0.05` and
        // `min(-0.05, 1.0) = -0.05`. So score = -0.05.
        // risk = CRITICAL (since -0.05 < 0.20)
        assert_eq!(r["anti_ai_dpi_score"], -0.05);
        assert_eq!(r["iran_ml_dpi_risk"], "CRITICAL");
        assert_eq!(r["flags"][0], "tor_known_port");
    }

    #[test]
    fn score_snowflake_safe_port_high_score() {
        let r = score_anti_ai_dpi("snowflake 1.2.3.4:443");
        // 0.92 + 0.05 = 0.97 → round 0.97 → VERY_LOW
        assert_eq!(r["anti_ai_dpi_score"], 0.97);
        assert_eq!(r["iran_ml_dpi_risk"], "VERY_LOW");
    }

    #[test]
    fn score_webtunnel_https_default_443() {
        let r = score_anti_ai_dpi("webtunnel url=https://example.com/path");
        // 0.88 + 0.05 (443 safe) = 0.93 → VERY_LOW
        assert_eq!(r["anti_ai_dpi_score"], 0.93);
        assert_eq!(r["iran_ml_dpi_risk"], "VERY_LOW");
    }

    #[test]
    fn score_obfs4_iat_mode_2_adds_bonus() {
        let r = score_anti_ai_dpi("obfs4 1.2.3.4:443 iat-mode=2");
        // 0.72 + 0.05 (safe) + 0.08 (iat) = 0.85 → VERY_LOW
        assert_eq!(r["anti_ai_dpi_score"], 0.85);
        assert_eq!(r["iran_ml_dpi_risk"], "VERY_LOW");
        let flags: Vec<&str> = r["flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(flags.contains(&"safe_port"));
        assert!(flags.contains(&"obfs4_iat_timing_randomised"));
    }

    #[test]
    fn score_cdn_hint_adds_bonus() {
        let r = score_anti_ai_dpi("obfs4 1.2.3.4:443 cloudflare");
        // 0.72 + 0.05 (safe) + 0.05 (cdn) = 0.82 → VERY_LOW
        assert_eq!(r["anti_ai_dpi_score"], 0.82);
        assert_eq!(r["iran_ml_dpi_risk"], "VERY_LOW");
    }

    #[test]
    fn score_ephemeral_port_bonus() {
        let r = score_anti_ai_dpi("vanilla 1.2.3.4:50000");
        // 0.05 + 0.03 = 0.08 → CRITICAL
        assert_eq!(r["anti_ai_dpi_score"], 0.08);
        assert_eq!(r["iran_ml_dpi_risk"], "CRITICAL");
        assert_eq!(r["flags"][0], "ephemeral_port");
    }

    #[test]
    fn score_clamps_at_1_0() {
        // snowflake (0.92) + safe (0.05) + iat (0.08) = 1.05 → 1.0
        let r = score_anti_ai_dpi("snowflake 1.2.3.4:443 iat-mode=2 cloudflare");
        // 0.92 + 0.05 + 0.08 + 0.05 = 1.10 → 1.0
        assert_eq!(r["anti_ai_dpi_score"], 1.0);
    }

    #[test]
    fn risk_threshold_boundaries() {
        // VERY_LOW boundary: 0.80
        // Construct: obfs4 (0.72) + safe (0.05) + iat (0.08) = 0.85
        // For exactly 0.80: meek_lite (0.80) + nothing = 0.80 → VERY_LOW
        let r = score_anti_ai_dpi("meek 1.2.3.4:9999"); // 9999 not in any list, no bonus
                                                        // meek_lite = 0.80 + no bonus = 0.80 → VERY_LOW (>= 0.80)
        assert_eq!(r["anti_ai_dpi_score"], 0.80);
        assert_eq!(r["iran_ml_dpi_risk"], "VERY_LOW");

        // LOW boundary: 0.60
        // obfs4 = 0.72 → LOW? No, 0.72 >= 0.60 → LOW. Wait: 0.72 >= 0.60 → LOW
        // Actually 0.72 >= 0.80? No. 0.72 >= 0.60 → LOW.
        let r = score_anti_ai_dpi("obfs4 1.2.3.4:9999"); // no port bonus
                                                         // 0.72 → LOW (>= 0.60)
        assert_eq!(r["anti_ai_dpi_score"], 0.72);
        assert_eq!(r["iran_ml_dpi_risk"], "LOW");
    }

    #[test]
    fn run_pipeline_writes_report_and_export() {
        let tmp = tempfile_dir();
        let bridge_json = tmp.join("bridge_list_for_testing.json");
        let report = tmp.join("anti_ai_dpi_report.json");
        let export = tmp.join("anti_ai_dpi_bridges.txt");
        let bridges = vec![
            "snowflake 1.2.3.4:443".to_string(),   // 0.97 VERY_LOW
            "vanilla 5.6.7.8:9001".to_string(),    // -0.05 CRITICAL
            "obfs4 9.10.11.12:443".to_string(),    // 0.77 LOW
            "webtunnel url=https://x".to_string(), // 0.93 VERY_LOW
        ];
        std::fs::write(&bridge_json, serde_json::to_string(&bridges).unwrap()).unwrap();

        run_pipeline(&bridge_json, &report, &export).unwrap();

        let rep: Value = serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
        let arr = rep["anti_ai_dpi_results"].as_array().unwrap();
        assert_eq!(arr.len(), 4);
        // Sorted descending: snowflake(0.97), webtunnel(0.93), obfs4(0.77), vanilla(-0.05)
        assert_eq!(arr[0]["transport"], "snowflake");
        assert_eq!(arr[1]["transport"], "webtunnel");
        assert_eq!(arr[2]["transport"], "obfs4");
        assert_eq!(arr[3]["transport"], "vanilla");

        // Top export: snowflake + webtunnel (both VERY_LOW). obfs4 is LOW → also included.
        let export_text = std::fs::read_to_string(&export).unwrap();
        assert!(export_text.contains("snowflake"));
        assert!(export_text.contains("webtunnel"));
        assert!(export_text.contains("obfs4"));
        assert!(!export_text.contains("vanilla 5.6.7.8:9001"));
        assert!(export_text.ends_with('\n'));
    }

    #[test]
    fn run_pipeline_missing_input_returns_io_error() {
        let tmp = tempfile_dir();
        let err = run_pipeline(
            &tmp.join("missing.json"),
            &tmp.join("report.json"),
            &tmp.join("export.txt"),
        )
        .unwrap_err();
        match err {
            AntiAiDpiError::Io { .. } => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn run_pipeline_invalid_json_returns_json_error() {
        let tmp = tempfile_dir();
        let bridge_json = tmp.join("bridge_list_for_testing.json");
        std::fs::write(&bridge_json, "not json {{{").unwrap();
        let err = run_pipeline(
            &bridge_json,
            &tmp.join("report.json"),
            &tmp.join("export.txt"),
        )
        .unwrap_err();
        match err {
            AntiAiDpiError::Json(_) => {}
            other => panic!("expected Json, got {other:?}"),
        }
    }

    #[test]
    fn run_pipeline_non_array_returns_invalid_bridge_list() {
        let tmp = tempfile_dir();
        let bridge_json = tmp.join("bridge_list_for_testing.json");
        std::fs::write(&bridge_json, "{\"key\": \"value\"}").unwrap();
        let err = run_pipeline(
            &bridge_json,
            &tmp.join("report.json"),
            &tmp.join("export.txt"),
        )
        .unwrap_err();
        match err {
            AntiAiDpiError::InvalidBridgeList(_) => {}
            other => panic!("expected InvalidBridgeList, got {other:?}"),
        }
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let base = std::env::temp_dir();
        let dir = base.join(format!(
            "anti_ai_dpi_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}

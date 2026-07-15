// Parity tests for `src/iran_dpi_shaper.rs` vs `core/iran_dpi_shaper.py`.
//
// Everything in this module is a pure function over a bridge-line string
// (no network I/O, unlike `iran_detector.rs`/`censorship_monitor.rs`), so
// every test here is a straightforward differential comparison against the
// real Python via subprocess — no local listeners needed.

use std::process::Command;

use serde_json::{json, Value};

use torshield_ir_ultra::iran_dpi_shaper::{
    get_phantom_stealth, score_all, score_siam_evasion, IranDpiShaper,
};

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        return Box::leak(path.into_boxed_str());
    }
    "python3"
}

struct PythonResult {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_python_script(script: &str, payload: &Value) -> PythonResult {
    let payload_json = serde_json::to_string(payload).expect("payload must serialize");
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(script)
        .arg(&payload_json)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    PythonResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn run_python_json(script: &str, payload: &Value) -> Value {
    let result = run_python_script(script, payload);
    assert!(result.success, "python helper failed: {}", result.stderr);
    serde_json::from_str(result.stdout.trim())
        .unwrap_or_else(|err| panic!("python helper must emit JSON: {err}; stdout={}", result.stdout))
}

const SCORE_SCRIPT: &str = r##"
import json, sys
from core.iran_dpi_shaper import score_siam_evasion

p = json.loads(sys.argv[1])
result = score_siam_evasion(p["line"], ja3_hash=p.get("ja3_hash"))
print(json.dumps(result.to_dict()))
"##;

fn assert_score_matches_python(line: &str, ja3_hash: Option<&str>) -> Value {
    let payload = json!({ "line": line, "ja3_hash": ja3_hash });
    let py = run_python_json(SCORE_SCRIPT, &payload);
    let rs = score_siam_evasion(line, ja3_hash).to_value();

    assert_eq!(py["bridge_line"], rs["bridge_line"], "line: {line}");
    assert_eq!(py["transport"], rs["transport"], "line: {line}");
    assert_eq!(py["port"], rs["port"], "line: {line}");
    assert_eq!(
        py["iran_siam_score"], rs["iran_siam_score"],
        "line: {line}"
    );
    assert_eq!(py["bypass_tier"], rs["bypass_tier"], "line: {line}");
    assert_eq!(
        py["layers_bypassed"], rs["layers_bypassed"],
        "line: {line}"
    );
    assert_eq!(py["evasion_flags"], rs["evasion_flags"], "line: {line}");
    assert_eq!(py["layer_scores"], rs["layer_scores"], "line: {line}");
    assert_eq!(
        py["recommendation"], rs["recommendation"],
        "line: {line}"
    );
    rs
}

// ─────────────────────────────────────────────────────────────────────────────
// score_siam_evasion — one test per transport / condition combination
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn snowflake_is_phantom_tier() {
    let rs = assert_score_matches_python(
        "snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72 \
         url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
         fronts=ftls.googlevideo.com",
        None,
    );
    assert_eq!(rs["bypass_tier"], json!("PHANTOM"));
}

#[test]
fn webtunnel_with_cdn_sni_match() {
    assert_score_matches_python(
        "webtunnel 1.2.3.4:443 FINGERPRINT url=https://x.cloudfront.net/path",
        None,
    );
}

#[test]
fn webtunnel_without_cdn_sni_match() {
    assert_score_matches_python(
        "webtunnel 1.2.3.4:443 FINGERPRINT url=https://example-not-a-cdn.test/path",
        None,
    );
}

#[test]
fn meek_lite_scores() {
    assert_score_matches_python("meek_lite cert=abc123 front=ajax.aspnetcdn.com", None);
}

#[test]
fn obfs4_iat_mode_2_is_best_obfs4_case() {
    let rs = assert_score_matches_python("obfs4 1.2.3.4:443 FINGERPRINT iat-mode=2", None);
    assert_eq!(rs["transport"], json!("obfs4"));
}

#[test]
fn obfs4_iat_mode_1() {
    assert_score_matches_python("obfs4 5.6.7.8:9001 FINGERPRINT iat-mode=1", None);
}

#[test]
fn obfs4_iat_mode_absent_defaults_to_zero() {
    assert_score_matches_python("obfs4 5.6.7.8:9001 FINGERPRINT", None);
}

#[test]
fn obfs4_on_ngfw_blocked_port_gets_penalized() {
    let rs =
        assert_score_matches_python("obfs4 5.6.7.8:9001 FINGERPRINT iat-mode=2", None);
    assert_eq!(rs["port"], json!(9001));
    let flags = rs["evasion_flags"].as_array().unwrap();
    assert!(flags.iter().any(|f| f == "ngfw_blocked_port"));
}

#[test]
fn obfs4_on_siam_safe_port_gets_bonus() {
    let rs =
        assert_score_matches_python("obfs4 5.6.7.8:8443 FINGERPRINT iat-mode=2", None);
    let flags = rs["evasion_flags"].as_array().unwrap();
    assert!(flags.iter().any(|f| f == "siam_safe_port"));
}

#[test]
fn vanilla_tor_is_detected_tier() {
    let rs = assert_score_matches_python("192.168.0.1:9001 ABC123FINGERPRINT", None);
    assert_eq!(rs["bypass_tier"], json!("DETECTED"));
}

#[test]
fn ja3_hash_in_blocklist() {
    let rs = assert_score_matches_python(
        "obfs4 1.2.3.4:443 FP iat-mode=2",
        Some("e7d705a3286e19ea42f587b344ee6865"),
    );
    let flags = rs["evasion_flags"].as_array().unwrap();
    assert!(flags.iter().any(|f| f == "ja3_in_iran_siam_blocklist"));
}

#[test]
fn ja3_hash_not_in_blocklist() {
    let rs = assert_score_matches_python(
        "obfs4 1.2.3.4:443 FP iat-mode=2",
        Some("0000000000000000000000000000000"),
    );
    let flags = rs["evasion_flags"].as_array().unwrap();
    assert!(flags.iter().any(|f| f == "ja3_not_in_siam_blocklist"));
}

#[test]
fn ja3_hash_absent_is_treated_as_moderate_not_blocked() {
    let rs = assert_score_matches_python("obfs4 1.2.3.4:443 FP iat-mode=2", None);
    let flags = rs["evasion_flags"].as_array().unwrap();
    assert!(flags.is_empty() || !flags.iter().any(|f| f == "ja3_in_iran_siam_blocklist"));
    assert_eq!(rs["layer_scores"]["L4_ja3_tls"], json!(0.75));
}

#[test]
fn empty_and_whitespace_lines_are_trimmed_like_python() {
    assert_score_matches_python("   obfs4 1.2.3.4:443 FP iat-mode=2   ", None);
}

// ─────────────────────────────────────────────────────────────────────────────
// score_all — batch scoring + sort order
// ─────────────────────────────────────────────────────────────────────────────

const SCORE_ALL_SCRIPT: &str = r##"
import json, sys
from core.iran_dpi_shaper import score_all

p = json.loads(sys.argv[1])
ja3_map = {k: v for k, v in p.get("ja3_map", [])}
results = score_all(p["lines"], ja3_map=ja3_map)
print(json.dumps([r.to_dict() for r in results]))
"##;

#[test]
fn score_all_sorts_descending_and_skips_blank_lines() {
    let lines = vec![
        "192.168.0.1:9001 ABC123FINGERPRINT", // vanilla, low score
        "",
        "snowflake 192.0.2.3:1 FP url=https://x.fastly.net/",
        "  ",
        "obfs4 1.2.3.4:443 FP iat-mode=2",
    ];
    let payload = json!({ "lines": lines, "ja3_map": [] });
    let py = run_python_json(SCORE_ALL_SCRIPT, &payload);

    let rs_results = score_all(&lines, &[]);
    let rs: Value = json!(rs_results.iter().map(|r| r.to_value()).collect::<Vec<_>>());

    let py_arr = py.as_array().unwrap();
    let rs_arr = rs.as_array().unwrap();
    assert_eq!(py_arr.len(), rs_arr.len());
    assert_eq!(py_arr.len(), 3, "blank/whitespace-only lines must be skipped");
    for (p, r) in py_arr.iter().zip(rs_arr.iter()) {
        assert_eq!(p["bridge_line"], r["bridge_line"]);
        assert_eq!(p["iran_siam_score"], r["iran_siam_score"]);
    }
    // Descending order: snowflake (highest) should come before vanilla (lowest).
    let scores: Vec<f64> = rs_arr
        .iter()
        .map(|r| r["iran_siam_score"].as_f64().unwrap())
        .collect();
    let mut sorted_desc = scores.clone();
    sorted_desc.sort_by(|a, b| b.partial_cmp(a).unwrap());
    assert_eq!(scores, sorted_desc);
}

#[test]
fn score_all_uses_ja3_map_keyed_by_trimmed_line() {
    let lines = vec!["obfs4 1.2.3.4:443 FP iat-mode=2"];
    let ja3_map = vec![(
        "obfs4 1.2.3.4:443 FP iat-mode=2",
        "e7d705a3286e19ea42f587b344ee6865",
    )];
    let payload = json!({ "lines": lines, "ja3_map": ja3_map });
    let py = run_python_json(SCORE_ALL_SCRIPT, &payload);

    let rs_results = score_all(&lines, &ja3_map);
    let rs: Value = json!(rs_results.iter().map(|r| r.to_value()).collect::<Vec<_>>());

    assert_eq!(py[0]["evasion_flags"], rs[0]["evasion_flags"]);
    let flags = rs[0]["evasion_flags"].as_array().unwrap();
    assert!(flags.iter().any(|f| f == "ja3_in_iran_siam_blocklist"));
}

// ─────────────────────────────────────────────────────────────────────────────
// get_phantom_stealth
// ─────────────────────────────────────────────────────────────────────────────

const PHANTOM_STEALTH_SCRIPT: &str = r##"
import json, sys
from core.iran_dpi_shaper import score_all, get_phantom_stealth

p = json.loads(sys.argv[1])
results = score_all(p["lines"])
print(json.dumps(get_phantom_stealth(results)))
"##;

#[test]
fn get_phantom_stealth_matches_python() {
    let lines = vec![
        "snowflake 192.0.2.3:1 FP url=https://x.fastly.net/",
        "192.168.0.1:9001 ABC123FINGERPRINT",
        "obfs4 1.2.3.4:443 FP iat-mode=2",
    ];
    let payload = json!({ "lines": lines });
    let py = run_python_json(PHANTOM_STEALTH_SCRIPT, &payload);

    let scored = score_all(&lines, &[]);
    let rs = get_phantom_stealth(&scored);

    assert_eq!(py, json!(rs));
    assert!(!rs.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// IranDPIShaper — backward-compatible object API mirrors the free functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn iran_dpi_shaper_struct_matches_free_functions() {
    let shaper = IranDpiShaper;
    let line = "obfs4 1.2.3.4:443 FP iat-mode=2";
    let via_struct = shaper.score_bridge(line, None).to_value();
    let via_function = score_siam_evasion(line, None).to_value();
    assert_eq!(via_struct, via_function);

    let lines = vec![line];
    let via_struct_batch: Value = json!(shaper
        .score_bridges(&lines, &[])
        .iter()
        .map(|r| r.to_value())
        .collect::<Vec<_>>());
    let via_function_batch: Value = json!(score_all(&lines, &[])
        .iter()
        .map(|r| r.to_value())
        .collect::<Vec<_>>());
    assert_eq!(via_struct_batch, via_function_batch);
}

// Parity test: `anti_ai_dpi.py` vs `anti_ai_dpi.rs`.
//
// Runs both the Python original and the Rust port on the same fixed input
// set and asserts identical output for every branch logged in the Phase 0
// contract.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::anti_ai_dpi as rs;

fn python_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_python_score(line: &str) -> Value {
    let script = format!(
        r#"
import json, sys
sys.path.insert(0, {root:?})
import anti_ai_dpi as m
print(json.dumps(m.score_anti_ai_dpi({line:?})))
"#,
        root = python_root().display().to_string(),
        line = line,
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("python3 must be installed");
    if !out.status.success() {
        panic!(
            "python score_anti_ai_dpi failed: {}\n--- stderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    serde_json::from_str(&s).expect("python output must be valid JSON")
}

fn assert_json_eq(a: Value, b: Value, ctx: &str) {
    if a != b {
        panic!("{ctx}: JSON mismatch\n--- Python:\n{a:#}\n--- Rust:\n{b:#}");
    }
}

#[test]
fn parity_score_vanilla_no_port() {
    let py = run_python_score("vanilla-line");
    let rs_v = rs::score_anti_ai_dpi("vanilla-line");
    assert_json_eq(py, rs_v, "vanilla no port");
}

#[test]
fn parity_score_vanilla_safe_port_443() {
    let py = run_python_score("vanilla 1.2.3.4:443");
    let rs_v = rs::score_anti_ai_dpi("vanilla 1.2.3.4:443");
    assert_json_eq(py, rs_v, "vanilla 443");
}

#[test]
fn parity_score_vanilla_tor_known_port_9001() {
    let py = run_python_score("vanilla 1.2.3.4:9001");
    let rs_v = rs::score_anti_ai_dpi("vanilla 1.2.3.4:9001");
    assert_json_eq(py, rs_v, "vanilla 9001");
}

#[test]
fn parity_score_snowflake_safe_port() {
    let py = run_python_score("snowflake 1.2.3.4:443");
    let rs_v = rs::score_anti_ai_dpi("snowflake 1.2.3.4:443");
    assert_json_eq(py, rs_v, "snowflake 443");
}

#[test]
fn parity_score_webtunnel_https_default_443() {
    let py = run_python_score("webtunnel url=https://example.com/path");
    let rs_v = rs::score_anti_ai_dpi("webtunnel url=https://example.com/path");
    assert_json_eq(py, rs_v, "webtunnel https default");
}

#[test]
fn parity_score_webtunnel_https_explicit_port() {
    let py = run_python_score("webtunnel url=https://example.com:8443/path");
    let rs_v = rs::score_anti_ai_dpi("webtunnel url=https://example.com:8443/path");
    assert_json_eq(py, rs_v, "webtunnel https explicit port");
}

#[test]
fn parity_score_obfs4_iat_mode_2() {
    let py = run_python_score("obfs4 1.2.3.4:443 iat-mode=2");
    let rs_v = rs::score_anti_ai_dpi("obfs4 1.2.3.4:443 iat-mode=2");
    assert_json_eq(py, rs_v, "obfs4 iat-mode=2");
}

#[test]
fn parity_score_cdn_hint_cloudflare() {
    let py = run_python_score("obfs4 1.2.3.4:443 cloudflare");
    let rs_v = rs::score_anti_ai_dpi("obfs4 1.2.3.4:443 cloudflare");
    assert_json_eq(py, rs_v, "obfs4 cdn=cloudflare");
}

#[test]
fn parity_score_ephemeral_port() {
    let py = run_python_score("vanilla 1.2.3.4:50000");
    let rs_v = rs::score_anti_ai_dpi("vanilla 1.2.3.4:50000");
    assert_json_eq(py, rs_v, "vanilla ephemeral port");
}

#[test]
fn parity_score_clamped_at_one() {
    let py = run_python_score("snowflake 1.2.3.4:443 iat-mode=2 cloudflare");
    let rs_v = rs::score_anti_ai_dpi("snowflake 1.2.3.4:443 iat-mode=2 cloudflare");
    assert_json_eq(py, rs_v, "snowflake clamped at 1.0");
}

#[test]
fn parity_score_meek_no_port_bonus() {
    let py = run_python_score("meek 1.2.3.4:9999");
    let rs_v = rs::score_anti_ai_dpi("meek 1.2.3.4:9999");
    assert_json_eq(py, rs_v, "meek no port bonus");
}

#[test]
fn parity_score_negative_score_clamp_behavior() {
    // Python: min(base + bonus, 1.0) — only clamps upper bound.
    // vanilla(0.05) + tor_known_port(-0.10) = -0.05
    let py = run_python_score("vanilla 1.2.3.4:9050");
    let rs_v = rs::score_anti_ai_dpi("vanilla 1.2.3.4:9050");
    assert_json_eq(py, rs_v, "vanilla 9050 negative score");
}

#[test]
fn parity_run_pipeline_byte_identical_report() {
    let tmp = std::env::temp_dir().join(format!(
        "anti_ai_dpi_parity_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    // Python `main()` reads from `bridge/bridge_list_for_testing.json`
    // (relative path). The Rust `run_pipeline` takes an injectable path;
    // we point it at the same file so both sides see identical inputs.
    let bridge_dir = tmp.join("bridge");
    std::fs::create_dir_all(&bridge_dir).unwrap();
    let bridge_json = bridge_dir.join("bridge_list_for_testing.json");
    let bridges = json!(vec![
        "snowflake 1.2.3.4:443",
        "vanilla 5.6.7.8:9001",
        "obfs4 9.10.11.12:443 iat-mode=2",
        "webtunnel url=https://x.example.com:8443",
        "meek 1.2.3.4:9999",
    ]);
    std::fs::write(&bridge_json, bridges.to_string()).unwrap();

    // Rust pipeline
    let rs_report = tmp.join("rs_report.json");
    let rs_export = tmp.join("rs_export.txt");
    rs::run_pipeline(&bridge_json, &rs_report, &rs_export).unwrap();

    // Python main()
    let script = format!(
        r#"
import json, sys, os
sys.path.insert(0, {root:?})
import anti_ai_dpi as m
os.chdir({tmp:?})
m.main()
"#,
        root = python_root().display().to_string(),
        tmp = tmp.display().to_string(),
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("python3 must be installed");
    if !out.status.success() {
        panic!(
            "python main() failed: {}\n--- stderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let py_report = tmp.join("data").join("anti_ai_dpi_report.json");
    let py_export = tmp.join("export").join("anti_ai_dpi_bridges.txt");

    let py_text = std::fs::read_to_string(py_report).unwrap();
    let rs_text = std::fs::read_to_string(&rs_report).unwrap();

    let py_json: Value = serde_json::from_str(&py_text).unwrap();
    let rs_json: Value = serde_json::from_str(&rs_text).unwrap();
    assert_json_eq(py_json, rs_json, "run_pipeline byte-identical report");

    let py_export_text = std::fs::read_to_string(py_export).unwrap_or_default();
    let rs_export_text = std::fs::read_to_string(&rs_export).unwrap_or_default();
    assert_eq!(py_export_text, rs_export_text, "export file mismatch");
}

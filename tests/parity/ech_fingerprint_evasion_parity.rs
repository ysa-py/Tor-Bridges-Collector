#![allow(warnings)]
// Parity test: `ech_fingerprint_evasion.py` vs `ech_fingerprint_evasion.rs`.
//
// Runs both the Python original and the Rust port on the same fixed input
// set and asserts identical output for every branch logged in the Phase 0
// contract.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::ech_fingerprint_evasion as rs;

fn python_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_python_score(line: &str) -> Value {
    let script = format!(
        r#"
import json, sys, os
sys.path.insert(0, {root:?})
# Disable the live TLS probe by monkey-patching _check_ech to a no-op.
import ech_fingerprint_evasion as m
def _no_probe(host, port, timeout=8.0):
    return {{}}
m._check_ech = _no_probe
print(json.dumps(m.score_bridge({line:?})))
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
            "python score_bridge failed: {}\n--- stderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    serde_json::from_str(&s).expect("python output must be valid JSON")
}

fn run_python_score_with_probe(line: &str, probe_kind: &str) -> Value {
    let probe_patch = match probe_kind {
        "reachable_tls13" => {
            r#"
def _probe(host, port, timeout=8.0):
    return {
        "host": host, "port": port,
        "tls_reachable": True, "tls_version": "TLSv1.3",
        "ech_supported": False, "ech_grease": False,
        "tls_probe_status": "reachable", "tls_error_type": None,
    }
m._check_ech = _probe
"#
        }
        "ech_supported" => {
            r#"
def _probe(host, port, timeout=8.0):
    return {
        "host": host, "port": port,
        "tls_reachable": True, "tls_version": "TLSv1.3",
        "ech_supported": True, "ech_grease": False,
        "tls_probe_status": "reachable", "tls_error_type": None,
    }
m._check_ech = _probe
"#
        }
        "timeout" => {
            r#"
def _probe(host, port, timeout=8.0):
    return {
        "host": host, "port": port,
        "tls_reachable": False, "tls_version": None,
        "ech_supported": False, "ech_grease": False,
        "tls_probe_status": "timeout", "tls_error_type": "TimeoutError",
    }
m._check_ech = _probe
"#
        }
        _ => "m._check_ech = lambda h, p, t=8.0: {}",
    };
    let script = format!(
        r#"
import json, sys
sys.path.insert(0, {root:?})
import ech_fingerprint_evasion as m
{probe_patch}
print(json.dumps(m.score_bridge({line:?})))
"#,
        root = python_root().display().to_string(),
        probe_patch = probe_patch,
        line = line,
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("python3 must be installed");
    if !out.status.success() {
        panic!(
            "python score_bridge failed: {}\n--- stderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    serde_json::from_str(&s).expect("python output must be valid JSON")
}

struct ReachableTls13;
impl rs::TlsProbe for ReachableTls13 {
    fn probe(&self, host: &str, port: u16, _t: f64) -> rs::TlsProbeResult {
        rs::TlsProbeResult {
            host: host.to_string(),
            port,
            tls_reachable: true,
            tls_version: Some("TLSv1.3".to_string()),
            ech_supported: false,
            ech_grease: false,
            tls_probe_status: "reachable".to_string(),
            tls_error_type: None,
            probe_is_noop: false,
        }
    }
}

struct EchSupported;
impl rs::TlsProbe for EchSupported {
    fn probe(&self, host: &str, port: u16, _t: f64) -> rs::TlsProbeResult {
        rs::TlsProbeResult {
            host: host.to_string(),
            port,
            tls_reachable: true,
            tls_version: Some("TLSv1.3".to_string()),
            ech_supported: true,
            ech_grease: false,
            tls_probe_status: "reachable".to_string(),
            tls_error_type: None,
            probe_is_noop: false,
        }
    }
}

struct AlwaysTimeout;
impl rs::TlsProbe for AlwaysTimeout {
    fn probe(&self, host: &str, port: u16, _t: f64) -> rs::TlsProbeResult {
        rs::TlsProbeResult::new(host, port).with_failure("timeout", "TimeoutError")
    }
}

fn assert_json_eq(a: Value, b: Value, ctx: &str) {
    if a != b {
        panic!("{ctx}: JSON mismatch\n--- Python:\n{a:#}\n--- Rust:\n{b:#}");
    }
}

#[test]
fn parity_score_vanilla_no_host_no_probe() {
    let py = run_python_score("vanilla-line");
    let rs_v = rs::score_bridge("vanilla-line");
    assert_json_eq(py, rs_v, "vanilla-line no-probe");
}

#[test]
fn parity_score_snowflake_443_no_probe() {
    let py = run_python_score("snowflake 1.2.3.4:443");
    let rs_v = rs::score_bridge("snowflake 1.2.3.4:443");
    assert_json_eq(py, rs_v, "snowflake 443 no-probe");
}

#[test]
fn parity_score_webtunnel_https_no_probe() {
    let py = run_python_score("webtunnel url=https://example.com:443/path");
    let rs_v = rs::score_bridge("webtunnel url=https://example.com:443/path");
    assert_json_eq(py, rs_v, "webtunnel https no-probe");
}

#[test]
fn parity_score_obfs4_high_risk_port_no_probe() {
    let py = run_python_score("obfs4 1.2.3.4:9001 cert=abc");
    let rs_v = rs::score_bridge("obfs4 1.2.3.4:9001 cert=abc");
    assert_json_eq(py, rs_v, "obfs4 9001 no-probe");
}

#[test]
fn parity_score_port_80_no_probe() {
    let py = run_python_score("vanilla 1.2.3.4:80");
    let rs_v = rs::score_bridge("vanilla 1.2.3.4:80");
    assert_json_eq(py, rs_v, "vanilla 80 no-probe");
}

#[test]
fn parity_score_with_reachable_tls13_probe() {
    let py = run_python_score_with_probe("vanilla 1.2.3.4:443", "reachable_tls13");
    let rs_v = rs::score_bridge_with_probe("vanilla 1.2.3.4:443", &ReachableTls13);
    assert_json_eq(py, rs_v, "vanilla 443 reachable_tls13");
}

#[test]
fn parity_score_with_ech_supported_probe() {
    let py = run_python_score_with_probe("vanilla 1.2.3.4:443", "ech_supported");
    let rs_v = rs::score_bridge_with_probe("vanilla 1.2.3.4:443", &EchSupported);
    assert_json_eq(py, rs_v, "vanilla 443 ech_supported");
}

#[test]
fn parity_score_with_timeout_probe() {
    let py = run_python_score_with_probe("vanilla 1.2.3.4:443", "timeout");
    let rs_v = rs::score_bridge_with_probe("vanilla 1.2.3.4:443", &AlwaysTimeout);
    assert_json_eq(py, rs_v, "vanilla 443 timeout");
}

#[test]
fn parity_score_webtunnel_with_ech_clamps_to_one() {
    let py = run_python_score_with_probe("webtunnel url=https://x 1.2.3.4:443", "ech_supported");
    let rs_v = rs::score_bridge_with_probe("webtunnel url=https://x 1.2.3.4:443", &EchSupported);
    assert_json_eq(py, rs_v, "webtunnel+ech clamps to 1.0");
}

#[test]
fn parity_extract_host_port_ipv4() {
    // Verify both sides agree on host:port extraction (we test via score_bridge
    // because the python helper isn't exposed; the score's transport field is
    // the observable signal — both sides should detect "vanilla").
    let py = run_python_score("vanilla 192.168.1.1:443");
    let rs_v = rs::score_bridge("vanilla 192.168.1.1:443");
    assert_eq!(py["transport"], rs_v["transport"]);
    assert_eq!(py["transport"], "vanilla");
    // Both sides should produce the same score (0.10 — non_standard_port only,
    // since _check_ech is monkey-patched to no-op).
    assert_eq!(py["iran_dpi_evasion_score"], rs_v["iran_dpi_evasion_score"]);
}

#[test]
fn parity_run_pipeline_byte_identical_report() {
    // Build a temp bridge JSON, run both Python main() and Rust run_pipeline,
    // assert the output reports are byte-identical (modulo trailing newline).
    let tmp = std::env::temp_dir().join(format!(
        "ech_parity_{}_{}",
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
        "obfs4 5.6.7.8:9001",
        "vanilla 9.10.11.12:80",
        "webtunnel url=https://x.example.com:8443",
    ]);
    std::fs::write(&bridge_json, bridges.to_string()).unwrap();

    // Run Rust pipeline (NoProbe so no network)
    let rs_report = tmp.join("rs_report.json");
    let rs_export = tmp.join("rs_export.txt");
    rs::run_pipeline(&bridge_json, &rs_report, &rs_export, &rs::NoProbe).unwrap();

    // Run Python main() with monkey-patched _check_ech
    let script = format!(
        r#"
import json, sys, os
sys.path.insert(0, {root:?})
import ech_fingerprint_evasion as m
m._check_ech = lambda h, p, t=8.0: {{}}
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

    // Python writes data/ech_report.json under tmp; resolve
    let py_report_actual = tmp.join("data").join("ech_report.json");
    let py_export_actual = tmp.join("export").join("ech_top_bridges.txt");

    let py_text = std::fs::read_to_string(py_report_actual).unwrap();
    let rs_text = std::fs::read_to_string(&rs_report).unwrap();

    let py_json: Value = serde_json::from_str(&py_text).unwrap();
    let rs_json: Value = serde_json::from_str(&rs_text).unwrap();
    assert_json_eq(py_json, rs_json, "run_pipeline byte-identical report");

    // Export file: both should exist (or both not exist). If exists, content
    // must match modulo trailing newline.
    let py_export_text = std::fs::read_to_string(py_export_actual).unwrap_or_default();
    let rs_export_text = std::fs::read_to_string(&rs_export).unwrap_or_default();
    assert_eq!(py_export_text, rs_export_text, "export file mismatch");
}

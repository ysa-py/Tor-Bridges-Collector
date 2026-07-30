#![allow(warnings)]
// Parity tests for `src/bridge_scoring.rs` vs `sources/bridge_scoring.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `sources.bridge_scoring` and calls the matching function on the same
// input. The Rust port is invoked on the identical input and the JSON
// outputs are compared for equality (parsed [`Value`] comparison so object
// key ordering is irrelevant).
//
// Coverage:
// * `score_bridge` over the high-DPI / calm-DPI branches, every transport
//   bonus, RIPE reachability/tested combinations, PT-status positive and
//   negative, probe pass/fail, latency bands, freshness bands, high-risk
//   and Iran-preferred ports, scheduler-result merging, and the invalid
//   telemetry short-circuit.
// * `recommended_priority` over the 80/55 threshold boundaries.
// * `load_telemetry` / `load_scheduler_results` over happy path, missing
//   file, malformed JSON, and non-object root.
// * `coerce_port` / `find_endpoint_port` (via `score_bridge` port branches)
//   over the documented edge cases.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use torshield_ir_ultra::bridge_scoring::{
    load_scheduler_results, load_telemetry, recommended_priority, score_bridge, BridgeScoringError,
};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    for candidate in [
        "/root/.pyenv/shims/python",
        "/usr/local/bin/python",
        "/usr/bin/python3",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("python")
}

/// Dispatch a single JSON command to the Python `sources.bridge_scoring`
/// module and return the parsed JSON output. Supported operations:
/// * `score_bridge` — call `score_bridge(record, telemetry, now_utc,
///   scheduler_results)` and return `{"score": float, "reasons": [str]}`.
/// * `recommended_priority` — call `recommended_priority(score)`.
/// * `load_telemetry` / `load_scheduler_results` — read a file from a temp
///   path and return the parsed dict (or `{}` on error).
fn python_bridge_scoring(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("bridge_scoring parity cmd must serialize: {err}"));
    let script = r#"
import json, sys
from datetime import datetime, timezone
from sources.bridge_scoring import score_bridge, recommended_priority, load_telemetry, load_scheduler_results

cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'score_bridge':
    record = cmd['record']
    telemetry = cmd.get('telemetry')
    now_utc = datetime.fromisoformat(cmd['now_utc']) if cmd.get('now_utc') else None
    scheduler_results = cmd.get('scheduler_results')
    score, reasons = score_bridge(record, telemetry, now_utc, scheduler_results)
    print(json.dumps({'score': score, 'reasons': reasons}, sort_keys=True, separators=(',', ':')))
elif op == 'recommended_priority':
    print(json.dumps({'priority': recommended_priority(cmd['score'])}, sort_keys=True, separators=(',', ':')))
elif op == 'load_telemetry':
    print(json.dumps(load_telemetry(cmd['path']), sort_keys=True, separators=(',', ':')))
elif op == 'load_scheduler_results':
    print(json.dumps(load_scheduler_results(cmd['path']), sort_keys=True, separators=(',', ':')))
else:
    raise SystemExit('unknown op: ' + op)
"#;
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .arg(&cmd_json)
        .output()
        .unwrap_or_else(|err| panic!("python bridge_scoring helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python bridge_scoring helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python bridge_scoring helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn parse_utc(iso: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(iso)
        .unwrap_or_else(|err| panic!("test fixture iso must parse: {err}"))
        .with_timezone::<Utc>(&Utc)
}

const NOW_ISO: &str = "2026-06-25T12:00:00+00:00";

fn rust_score_bridge(
    record: &Value,
    telemetry: Option<&Value>,
    scheduler_results: Option<&Value>,
) -> Value {
    let (score, reasons) = score_bridge(
        record,
        telemetry,
        Some(parse_utc(NOW_ISO)),
        scheduler_results,
    )
    .expect("rust score_bridge succeeds");
    json!({"score": score, "reasons": reasons})
}

// ─────────────────────────────────────────────────────────────────────────────
// score_bridge parity (Python subprocess on every case)
// ─────────────────────────────────────────────────────────────────────────────

fn assert_score_bridge_parity(
    label: &str,
    record: Value,
    telemetry: Value,
    scheduler: Option<Value>,
) {
    let py_cmd = json!({
        "op": "score_bridge",
        "record": record,
        "telemetry": telemetry,
        "now_utc": NOW_ISO,
        "scheduler_results": scheduler,
    });
    let py = python_bridge_scoring(&py_cmd);
    let rs = rust_score_bridge(&record, Some(&telemetry), scheduler.as_ref());
    assert_eq!(py, rs, "score_bridge parity failed for {label}");
}

#[test]
fn parity_score_bridge_high_dpi_webtunnel_full_record() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(2)).to_rfc3339();
    let record = json!({
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
    let telemetry =
        json!({"counters": {"dpi_total": 4, "dpi_camouflaged": 3, "self_heal_total": 1}});
    assert_score_bridge_parity("high_dpi_webtunnel", record, telemetry, None);
}

#[test]
fn parity_score_bridge_high_dpi_obfs4_failed_probe() {
    let now = parse_utc(NOW_ISO);
    let stale = (now - chrono::Duration::days(30)).to_rfc3339();
    let record = json!({
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
    let telemetry =
        json!({"counters": {"dpi_total": 4, "dpi_camouflaged": 3, "self_heal_total": 1}});
    assert_score_bridge_parity("high_dpi_obfs4_failed", record, telemetry, None);
}

#[test]
fn parity_score_bridge_calm_dpi_snowflake_fresh() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(1)).to_rfc3339();
    let record = json!({
        "transport": "snowflake",
        "last_seen": recent,
        "test_pass": true,
    });
    let telemetry = json!({"counters": {}});
    assert_score_bridge_parity("calm_dpi_snowflake", record, telemetry, None);
}

#[test]
fn parity_score_bridge_invalid_telemetry_string() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(1)).to_rfc3339();
    let record = json!({
        "transport": "snowflake",
        "last_seen": recent,
    });
    let telemetry = json!("bad");
    assert_score_bridge_parity("invalid_telemetry", record, telemetry, None);
}

#[test]
fn parity_score_bridge_missing_port_falls_back_to_endpoint_regex() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(1)).to_rfc3339();
    let record = json!({
        "raw": "snowflake 198.51.100.20:443 fingerprint=x",
        "transport": "snowflake",
        "port": null,
        "last_seen": recent,
    });
    let telemetry = json!({"counters": {}});
    assert_score_bridge_parity("missing_port_regex_fallback", record, telemetry, None);
}

#[test]
fn parity_score_bridge_scheduler_merge_overrides_record_fields() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(1)).to_rfc3339();
    let record = json!({
        "raw": "obfs4 1.2.3.4:443 cert=x iat-mode=2",
        "transport": "obfs4",
        "port": 9001,
    });
    let scheduler = json!({
        "results": [
            {"raw": "different", "latency_ms": 100, "pt_status": "ok"},
            {"raw": "obfs4 1.2.3.4:443 cert=x iat-mode=2", "latency_ms": 50, "test_pass": true, "last_seen": recent},
        ]
    });
    let telemetry = json!({"counters": {}});
    assert_score_bridge_parity("scheduler_merge", record, telemetry, Some(scheduler));
}

#[test]
fn parity_score_bridge_domain_fronted_meek_under_high_dpi() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(3)).to_rfc3339();
    let record = json!({
        "raw": "meek_lite 198.51.100.30:443 url=https://arvancloud.example/ front=arvancloud",
        "transport": "meek_lite",
        "port": 443,
        "last_seen": recent,
        "test_pass": true,
        "latency_ms": 200,
    });
    let telemetry = json!({"counters": {"dpi_total": 5}});
    assert_score_bridge_parity("domain_fronted_meek", record, telemetry, None);
}

#[test]
fn parity_score_bridge_vanilla_low_dpi_resilience_penalty() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(5)).to_rfc3339();
    let record = json!({
        "raw": "vanilla 1.2.3.4:443",
        "transport": "vanilla",
        "port": 443,
        "last_seen": recent,
        "test_pass": false,
        "latency_ms": 500,
    });
    let telemetry = json!({"counters": {"dpi_total": 5}});
    assert_score_bridge_parity("vanilla_high_dpi_penalty", record, telemetry, None);
}

#[test]
fn parity_score_bridge_empty_record_calm_dpi() {
    let record = json!({});
    let telemetry = json!({"counters": {}});
    assert_score_bridge_parity("empty_record_calm", record, telemetry, None);
}

#[test]
fn parity_score_bridge_empty_record_high_dpi_unknown_transport() {
    let record = json!({});
    let telemetry = json!({"counters": {"dpi_total": 5}});
    assert_score_bridge_parity("empty_record_high_dpi", record, telemetry, None);
}

#[test]
fn parity_score_bridge_ripe_tested_unreachable_branch() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(10)).to_rfc3339();
    let record = json!({
        "raw": "obfs4 1.2.3.4:443 cert=x iat-mode=2",
        "transport": "obfs4",
        "port": 443,
        "last_seen": recent,
        "RIPEReachable": false,
        "RIPETested": true,
        "latency_ms": 300,
    });
    let telemetry = json!({"counters": {}});
    assert_score_bridge_parity("ripe_tested_unreachable", record, telemetry, None);
}

#[test]
fn parity_score_bridge_pt_status_negative_branch() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(10)).to_rfc3339();
    let record = json!({
        "transport": "obfs4",
        "port": 443,
        "last_seen": recent,
        "pt_status": "blocked",
        "latency_ms": 300,
    });
    let telemetry = json!({"counters": {}});
    assert_score_bridge_parity("pt_status_negative", record, telemetry, None);
}

#[test]
fn parity_score_bridge_stale_timestamp_branch() {
    let now = parse_utc(NOW_ISO);
    let stale = (now - chrono::Duration::days(10)).to_rfc3339();
    let record = json!({
        "transport": "obfs4",
        "port": 443,
        "last_seen": stale,
        "latency_ms": 300,
    });
    let telemetry = json!({"counters": {}});
    assert_score_bridge_parity("stale_timestamp", record, telemetry, None);
}

#[test]
fn parity_score_bridge_high_risk_port_2053_branch() {
    let now = parse_utc(NOW_ISO);
    let recent = (now - chrono::Duration::hours(1)).to_rfc3339();
    let record = json!({
        "transport": "obfs4",
        "port": 2053,
        "last_seen": recent,
        "latency_ms": 100,
    });
    let telemetry = json!({"counters": {}});
    assert_score_bridge_parity("high_risk_port_2053", record, telemetry, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// recommended_priority parity (Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_recommended_priority_threshold_boundaries() {
    for score in [0.0_f64, 1.0, 54.99, 55.0, 79.99, 80.0, 100.0] {
        let py = python_bridge_scoring(&json!({"op": "recommended_priority", "score": score}));
        let rs = recommended_priority(score);
        assert_eq!(
            py["priority"].as_str().unwrap(),
            rs,
            "priority mismatch at {score}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// load_telemetry / load_scheduler_results parity (Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

fn case_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield_bridge_scoring_parity_{}_{}",
        name,
        std::process::id()
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean stale parity tempdir");
    }
    fs::create_dir_all(&dir).expect("create parity tempdir");
    dir
}

fn assert_load_parity(op: &str, name: &str, file_content: Option<&str>) {
    let py_dir = case_dir(&format!("{op}_{name}_py"));
    let rust_dir = case_dir(&format!("{op}_{name}_rust"));
    let target_name = "state.json";
    if let Some(content) = file_content {
        fs::write(py_dir.join(target_name), content).expect("write python input");
        fs::write(rust_dir.join(target_name), content).expect("write rust input");
    }
    let py_path = py_dir.join(target_name);
    let rust_path = rust_dir.join(target_name);

    let py = python_bridge_scoring(&json!({"op": op, "path": py_path}));
    let rs = match op {
        "load_telemetry" => load_telemetry(&rust_path),
        "load_scheduler_results" => load_scheduler_results(&rust_path),
        _ => unreachable!("unknown op {op}"),
    };
    assert_eq!(py, rs, "load parity failed for {op}/{name}");

    let _ = fs::remove_dir_all(&py_dir);
    let _ = fs::remove_dir_all(&rust_dir);
}

#[test]
fn parity_load_telemetry_happy_path() {
    assert_load_parity(
        "load_telemetry",
        "happy",
        Some(r#"{"counters":{"dpi_total":3},"recent_dpi_events":[{"action":"blocked"}]}"#),
    );
}

#[test]
fn parity_load_telemetry_missing_file_returns_empty_object() {
    assert_load_parity("load_telemetry", "missing", None);
}

#[test]
fn parity_load_telemetry_malformed_json_returns_empty_object() {
    assert_load_parity("load_telemetry", "malformed", Some("{not valid json"));
}

#[test]
fn parity_load_telemetry_non_object_root_returns_empty_object() {
    assert_load_parity("load_telemetry", "non_object", Some("[1, 2, 3]"));
}

#[test]
fn parity_load_scheduler_results_happy_path() {
    assert_load_parity(
        "load_scheduler_results",
        "happy",
        Some(r#"{"results":[{"raw":"b1","latency_ms":50}]}"#),
    );
}

#[test]
fn parity_load_scheduler_results_missing_file_returns_empty_object() {
    assert_load_parity("load_scheduler_results", "missing", None);
}

#[test]
fn parity_load_scheduler_results_malformed_json_returns_empty_object() {
    assert_load_parity("load_scheduler_results", "malformed", Some("{bad json"));
}

#[test]
fn parity_load_scheduler_results_non_object_root_returns_empty_object() {
    assert_load_parity(
        "load_scheduler_results",
        "non_object",
        Some("\"just a string\""),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust-only typed-error path (no Python subprocess needed)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_score_bridge_invalid_counter_returns_typed_error() {
    let record = json!({"transport": "snowflake", "last_seen": NOW_ISO});
    let telemetry = json!({"counters": {"dpi_total": "abc"}});
    let err = score_bridge(&record, Some(&telemetry), Some(parse_utc(NOW_ISO)), None)
        .expect_err("non-numeric counter must surface typed error");
    assert!(matches!(
        err,
        BridgeScoringError::InvalidCounterValue { ref field, .. } if field == "dpi_total"
    ));
}

#[test]
fn rust_recommended_priority_default_thresholds_match_python_constants() {
    // Mirrors Python's `recommended_priority` constants; no Python subprocess
    // needed since the parity test above already exercises the boundaries.
    assert_eq!(recommended_priority(80.0), "high");
    assert_eq!(recommended_priority(55.0), "medium");
    assert_eq!(recommended_priority(0.0), "low");
}

#[test]
fn rust_score_bridge_now_defaults_to_utc_now_when_none() {
    // Smoke test: passing `None` for `now_utc` must not panic and must
    // produce a finite score for a fresh bridge.
    let recent = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let record = json!({"transport": "snowflake", "last_seen": recent, "test_pass": true});
    let (score, _) = score_bridge(&record, Some(&json!({"counters": {}})), None, None)
        .expect("rust score_bridge with default clock succeeds");
    assert!(score.is_finite());
    assert!((0.0..=100.0).contains(&score));
}

// ─────────────────────────────────────────────────────────────────────────────
// Env-map smoke test (kept for parity with the existing config_parity pattern)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_score_bridge_parity_smoke_multiple_records() {
    // Run several records through both implementations in a single test to
    // exercise transport-preference table coverage in one shot.
    let cases: BTreeMap<&str, Value> = BTreeMap::from([
        (
            "snowflake_calm",
            json!({"transport": "snowflake", "port": 443, "last_seen": NOW_ISO, "test_pass": true, "latency_ms": 80}),
        ),
        (
            "webtunnel_calm",
            json!({"transport": "webtunnel", "port": 443, "last_seen": NOW_ISO, "test_pass": true, "latency_ms": 80}),
        ),
        (
            "meek_lite_calm",
            json!({"transport": "meek_lite", "port": 443, "last_seen": NOW_ISO, "test_pass": true, "latency_ms": 80}),
        ),
        (
            "obfs4_calm",
            json!({"transport": "obfs4", "port": 443, "last_seen": NOW_ISO, "test_pass": true, "latency_ms": 80}),
        ),
        (
            "vanilla_calm",
            json!({"transport": "vanilla", "port": 443, "last_seen": NOW_ISO, "test_pass": true, "latency_ms": 80}),
        ),
        (
            "unknown_transport_calm",
            json!({"transport": "lyrebird", "port": 443, "last_seen": NOW_ISO, "test_pass": true, "latency_ms": 80}),
        ),
    ]);
    for (label, record) in cases {
        assert_score_bridge_parity(label, record, json!({"counters": {}}), None);
    }
}

#![allow(warnings)]
// Parity tests for `src/adaptive_transport.rs` vs `adaptive_transport.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `adaptive_transport` and calls the matching function on the same input.
// The Rust port is invoked on the identical input and the JSON outputs are
// compared for equality (parsed [`Value`] comparison so object key ordering
// is irrelevant). Timestamp fields (`updated_at`, `generated_at`, `ts`) are
// stripped from both sides before comparison because the Python original
// calls `datetime.now(UTC)` internally and cannot be injected.
//
// Coverage:
// * `collect_transport_stats` over working/blocked/unknown/missing-transport
//   branches.
// * `compute_weights` over insufficient-samples, zero-total, and
//   normal-normalization branches.
// * `weights_to_scores` over clamp-to-max, clamp-to-min, default-weight, and
//   banker's-rounding branches.
// * `save_weights` writes the payload + history file (timestamp-stripped
//   parity).
// * `save_best_transports` writes the ranked payload (timestamp-stripped
//   parity).
// * `main` end-to-end with bridge records and with empty records.
// * `select_transport_for_nin_cut` over all 4 tiers, sort, and dedup
//   (timestamp-stripped parity, run from a temp CWD).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use torshield_ir_ultra::adaptive_transport::{
    collect_transport_stats, compute_weights, main as transport_main, save_best_transports,
    save_weights, select_transport_for_nin_cut, weights_to_scores, TransportStats,
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

const FIXED_NOW_ISO: &str = "2024-01-01T12:00:00.123456+00:00";

fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(FIXED_NOW_ISO)
        .unwrap()
        .with_timezone::<Utc>(&Utc)
}

/// Strip timestamp fields (`updated_at`, `generated_at`, `ts`) from a JSON
/// value recursively. Used to compare Python and Rust outputs that embed
/// `datetime.now(UTC)` internally.
fn strip_timestamps(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.remove("updated_at");
            map.remove("generated_at");
            map.remove("ts");
            for (_, child) in map.iter_mut() {
                strip_timestamps(child);
            }
        }
        Value::Array(arr) => {
            for child in arr.iter_mut() {
                strip_timestamps(child);
            }
        }
        _ => {}
    }
}

/// Dispatch a JSON command to the Python `adaptive_transport` module.
fn python_adaptive_transport(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("adaptive_transport parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os
from pathlib import Path
from datetime import datetime, timezone
import adaptive_transport

cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'collect_transport_stats':
    stats = adaptive_transport._collect_transport_stats(cmd['records'])
    print(json.dumps(stats, sort_keys=True, separators=(',', ':')))
elif op == 'compute_weights':
    weights = adaptive_transport.compute_weights(cmd['stats'], cmd.get('min_samples', 3))
    print(json.dumps(weights, sort_keys=True, separators=(',', ':')))
elif op == 'weights_to_scores':
    scores = adaptive_transport.weights_to_scores(cmd['weights'])
    print(json.dumps(scores, sort_keys=True, separators=(',', ':')))
elif op == 'save_weights':
    adaptive_transport.WEIGHTS_PATH = Path(cmd['weights_path'])
    adaptive_transport.WEIGHT_HISTORY_PATH = Path(cmd['history_path'])
    adaptive_transport.save_weights(cmd['weights'], cmd['scores'], cmd['stats'])
    weights_out = json.loads(adaptive_transport.WEIGHTS_PATH.read_text(encoding='utf-8'))
    history_out = json.loads(adaptive_transport.WEIGHT_HISTORY_PATH.read_text(encoding='utf-8'))
    print(json.dumps({'weights': weights_out, 'history': history_out}, sort_keys=True, separators=(',', ':')))
elif op == 'save_best_transports':
    adaptive_transport.BEST_TRANSPORTS_PATH = Path(cmd['best_path'])
    adaptive_transport.save_best_transports(cmd['weights'], cmd['scores'], cmd['stats'])
    best_out = json.loads(adaptive_transport.BEST_TRANSPORTS_PATH.read_text(encoding='utf-8'))
    print(json.dumps(best_out, sort_keys=True, separators=(',', ':')))
elif op == 'main':
    adaptive_transport.IRAN_RESULTS_PATH = Path(cmd['iran_path'])
    adaptive_transport.LATEST_RESULTS_PATH = Path(cmd['latest_path'])
    adaptive_transport.WEIGHTS_PATH = Path(cmd['weights_path'])
    adaptive_transport.WEIGHT_HISTORY_PATH = Path(cmd['history_path'])
    adaptive_transport.BEST_TRANSPORTS_PATH = Path(cmd['best_path'])
    try:
        adaptive_transport.main()
    except SystemExit:
        pass
    result = {}
    if adaptive_transport.WEIGHTS_PATH.exists():
        result['weights'] = json.loads(adaptive_transport.WEIGHTS_PATH.read_text(encoding='utf-8'))
    if adaptive_transport.BEST_TRANSPORTS_PATH.exists():
        result['best'] = json.loads(adaptive_transport.BEST_TRANSPORTS_PATH.read_text(encoding='utf-8'))
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
elif op == 'nin_cut':
    output = adaptive_transport.select_transport_for_nin_cut()
    print(json.dumps(output, sort_keys=True, separators=(',', ':')))
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
        .unwrap_or_else(|err| panic!("python adaptive_transport helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python adaptive_transport helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python adaptive_transport helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// Run `select_transport_for_nin_cut` via Python from `cwd` (the function
/// uses local path constants relative to CWD).
fn python_nin_cut(cwd: &Path) -> Value {
    let script = r#"
import json
import adaptive_transport
output = adaptive_transport.select_transport_for_nin_cut()
print(json.dumps(output, sort_keys=True, separators=(',', ':')))
"#;
    let output = Command::new(python_executable())
        .current_dir(cwd)
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python nin_cut helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python nin_cut helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python nin_cut helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Temp-dir helper
// ─────────────────────────────────────────────────────────────────────────────

fn case_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield_adaptive_transport_parity_{}_{}_{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean stale parity tempdir");
    }
    fs::create_dir_all(&dir).expect("create parity tempdir");
    dir
}

fn stats_to_json_value(stats: &BTreeMap<String, TransportStats>) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in stats {
        map.insert(
            k.clone(),
            json!({
                "working": v.working,
                "blocked": v.blocked,
                "unknown": v.unknown,
                "total": v.total,
            }),
        );
    }
    Value::Object(map)
}

fn stats_from_json_value(v: &Value) -> BTreeMap<String, TransportStats> {
    let mut map = BTreeMap::new();
    if let Some(obj) = v.as_object() {
        for (k, child) in obj {
            map.insert(
                k.clone(),
                TransportStats {
                    working: child.get("working").and_then(Value::as_i64).unwrap_or(0),
                    blocked: child.get("blocked").and_then(Value::as_i64).unwrap_or(0),
                    unknown: child.get("unknown").and_then(Value::as_i64).unwrap_or(0),
                    total: child.get("total").and_then(Value::as_i64).unwrap_or(0),
                },
            );
        }
    }
    map
}

fn weights_to_json_value(weights: &BTreeMap<String, f64>) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in weights {
        map.insert(k.clone(), json!(v));
    }
    Value::Object(map)
}

fn weights_from_json_value(v: &Value) -> BTreeMap<String, f64> {
    let mut map = BTreeMap::new();
    if let Some(obj) = v.as_object() {
        for (k, child) in obj {
            map.insert(k.clone(), child.as_f64().unwrap_or(0.0));
        }
    }
    map
}

fn scores_to_json_value(scores: &BTreeMap<String, i64>) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in scores {
        map.insert(k.clone(), json!(v));
    }
    Value::Object(map)
}

fn scores_from_json_value(v: &Value) -> BTreeMap<String, i64> {
    let mut map = BTreeMap::new();
    if let Some(obj) = v.as_object() {
        for (k, child) in obj {
            map.insert(k.clone(), child.as_i64().unwrap_or(0));
        }
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// collect_transport_stats parity (Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_collect_transport_stats_mixed_records() {
    let records = json!([
        {"transport": "obfs4", "iran_status": "iran_likely_working"},
        {"transport": "obfs4", "iran_status": "iran_likely_blocked"},
        {"transport": "obfs4", "iran_status": "iran_frequently_blocked"},
        {"transport": "obfs4", "iran_status": "iran_asn_blocked"},
        {"transport": "obfs4", "iran_status": "unknown_status"},
        {"transport": "snowflake", "iran_status": "iran_likely_working"},
        {"iran_status": "iran_likely_working"},
        {"transport": "webtunnel"}
    ]);
    let records_arr = records.as_array().unwrap().clone();
    let py = python_adaptive_transport(&json!({
        "op": "collect_transport_stats",
        "records": records,
    }));
    let rs_stats = collect_transport_stats(&records_arr);
    let rs = stats_to_json_value(&rs_stats);
    assert_eq!(py, rs, "collect_transport_stats parity failed");
}

#[test]
fn parity_collect_transport_stats_empty_records() {
    let py = python_adaptive_transport(&json!({
        "op": "collect_transport_stats",
        "records": [],
    }));
    let rs_stats = collect_transport_stats(&[]);
    let rs = stats_to_json_value(&rs_stats);
    assert_eq!(py, rs, "collect_transport_stats empty parity failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// compute_weights parity (Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_compute_weights_normal_normalization() {
    let stats_json = json!({
        "obfs4": {"working": 3, "blocked": 1, "unknown": 0, "total": 4},
        "snowflake": {"working": 1, "blocked": 3, "unknown": 0, "total": 4}
    });
    let py = python_adaptive_transport(&json!({
        "op": "compute_weights",
        "stats": stats_json,
        "min_samples": 3,
    }));
    let stats = stats_from_json_value(&stats_json);
    let rs_weights = compute_weights(&stats, 3);
    let rs = weights_to_json_value(&rs_weights);
    assert_eq!(py, rs, "compute_weights normal parity failed");
}

#[test]
fn parity_compute_weights_insufficient_samples_neutral() {
    let stats_json = json!({
        "obfs4": {"working": 1, "blocked": 0, "unknown": 0, "total": 2}
    });
    let py = python_adaptive_transport(&json!({
        "op": "compute_weights",
        "stats": stats_json,
        "min_samples": 3,
    }));
    let stats = stats_from_json_value(&stats_json);
    let rs_weights = compute_weights(&stats, 3);
    let rs = weights_to_json_value(&rs_weights);
    assert_eq!(py, rs, "compute_weights insufficient parity failed");
}

#[test]
fn parity_compute_weights_zero_total_even_split() {
    let stats_json = json!({
        "obfs4": {"working": 0, "blocked": 5, "unknown": 0, "total": 5},
        "snowflake": {"working": 0, "blocked": 5, "unknown": 0, "total": 5},
        "webtunnel": {"working": 0, "blocked": 5, "unknown": 0, "total": 5}
    });
    let py = python_adaptive_transport(&json!({
        "op": "compute_weights",
        "stats": stats_json,
        "min_samples": 3,
    }));
    let stats = stats_from_json_value(&stats_json);
    let rs_weights = compute_weights(&stats, 3);
    let rs = weights_to_json_value(&rs_weights);
    assert_eq!(py, rs, "compute_weights zero-total parity failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// weights_to_scores parity (Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_weights_to_scores_full_weights() {
    let weights_json = json!({
        "snowflake": 1.0,
        "webtunnel": 0.8,
        "obfs4": 0.5,
        "meek_lite": 0.3,
        "vanilla": 0.0,
        "unknown": 0.1
    });
    let py = python_adaptive_transport(&json!({
        "op": "weights_to_scores",
        "weights": weights_json,
    }));
    let weights = weights_from_json_value(&weights_json);
    let rs_scores = weights_to_scores(&weights);
    let rs = scores_to_json_value(&rs_scores);
    assert_eq!(py, rs, "weights_to_scores full parity failed");
}

#[test]
fn parity_weights_to_scores_empty_weights_uses_defaults() {
    let weights_json = json!({});
    let py = python_adaptive_transport(&json!({
        "op": "weights_to_scores",
        "weights": weights_json,
    }));
    let weights = weights_from_json_value(&weights_json);
    let rs_scores = weights_to_scores(&weights);
    let rs = scores_to_json_value(&rs_scores);
    assert_eq!(py, rs, "weights_to_scores empty parity failed");
}

#[test]
fn parity_weights_to_scores_clamp_boundaries() {
    // snowflake with w=1.0 → 30*(0.7+0.6) = 39 → clamp 30
    // vanilla with w=0.0 → 5*0.7 = 3.5 → round 4 (banker's: 4 is even)
    let weights_json = json!({
        "snowflake": 1.0,
        "vanilla": 0.0
    });
    let py = python_adaptive_transport(&json!({
        "op": "weights_to_scores",
        "weights": weights_json,
    }));
    let weights = weights_from_json_value(&weights_json);
    let rs_scores = weights_to_scores(&weights);
    let rs = scores_to_json_value(&rs_scores);
    assert_eq!(py, rs, "weights_to_scores clamp parity failed");
    // Verify the clamp explicitly
    assert_eq!(rs_scores.get("snowflake"), Some(&30));
}

// ─────────────────────────────────────────────────────────────────────────────
// save_weights parity (Python subprocess, timestamp-stripped)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_save_weights_writes_payload_and_history() {
    let dir = case_dir("save_weights");
    let py_weights_path = dir.join("py_weights.json");
    let py_history_path = dir.join("py_history.json");
    let rs_weights_path = dir.join("rs_weights.json");
    let rs_history_path = dir.join("rs_history.json");

    let weights_json = json!({"obfs4": 0.75, "snowflake": 0.25});
    let scores_json = json!({"obfs4": 25, "snowflake": 30});
    let stats_json = json!({
        "obfs4": {"working": 3, "blocked": 1, "unknown": 0, "total": 4},
        "snowflake": {"working": 1, "blocked": 3, "unknown": 0, "total": 4}
    });

    let py = python_adaptive_transport(&json!({
        "op": "save_weights",
        "weights_path": py_weights_path,
        "history_path": py_history_path,
        "weights": weights_json,
        "scores": scores_json,
        "stats": stats_json,
    }));

    let weights = weights_from_json_value(&weights_json);
    let scores = scores_from_json_value(&scores_json);
    let stats = stats_from_json_value(&stats_json);
    save_weights(
        &weights,
        &scores,
        &stats,
        fixed_now(),
        &rs_weights_path,
        &rs_history_path,
    )
    .expect("rust save_weights succeeds");

    let rust_weights: Value =
        serde_json::from_str(&fs::read_to_string(&rs_weights_path).unwrap()).unwrap();
    let rust_history: Value =
        serde_json::from_str(&fs::read_to_string(&rs_history_path).unwrap()).unwrap();
    let rs = json!({"weights": rust_weights, "history": rust_history});

    let mut py = py;
    let mut rs = rs;
    strip_timestamps(&mut py);
    strip_timestamps(&mut rs);
    assert_eq!(py, rs, "save_weights parity failed");

    let _ = fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// save_best_transports parity (Python subprocess, timestamp-stripped)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_save_best_transports_writes_ranked_payload() {
    let dir = case_dir("save_best_transports");
    let best_path = dir.join("best.json");

    let weights_json = json!({"snowflake": 0.8, "obfs4": 0.2, "webtunnel": 0.5});
    let scores_json = json!({"snowflake": 30, "obfs4": 22, "webtunnel": 27});
    let stats_json = json!({
        "snowflake": {"working": 4, "blocked": 1, "unknown": 0, "total": 5},
        "obfs4": {"working": 1, "blocked": 4, "unknown": 0, "total": 5},
        "webtunnel": {"working": 2, "blocked": 3, "unknown": 0, "total": 5}
    });

    let py = python_adaptive_transport(&json!({
        "op": "save_best_transports",
        "best_path": best_path,
        "weights": weights_json,
        "scores": scores_json,
        "stats": stats_json,
    }));

    let weights = weights_from_json_value(&weights_json);
    let scores = scores_from_json_value(&scores_json);
    let stats = stats_from_json_value(&stats_json);
    save_best_transports(&weights, &scores, &stats, fixed_now(), &best_path)
        .expect("rust save_best_transports succeeds");

    let rs: Value = serde_json::from_str(&fs::read_to_string(&best_path).unwrap()).unwrap();

    let mut py = py;
    let mut rs = rs;
    strip_timestamps(&mut py);
    strip_timestamps(&mut rs);
    assert_eq!(py, rs, "save_best_transports parity failed");

    let _ = fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// main parity (Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_main_with_bridge_records() {
    let dir = case_dir("main_with_records");
    let iran_path = dir.join("iran.json");
    let latest_path = dir.join("latest.json");
    let weights_path = dir.join("weights.json");
    let history_path = dir.join("history.json");
    let best_path = dir.join("best.json");

    let iran_data = json!({
        "bridges": [
            {"transport": "snowflake", "iran_status": "iran_likely_working"},
            {"transport": "snowflake", "iran_status": "iran_likely_working"},
            {"transport": "snowflake", "iran_status": "iran_likely_working"},
            {"transport": "obfs4", "iran_status": "iran_likely_blocked"},
            {"transport": "obfs4", "iran_status": "iran_likely_blocked"},
            {"transport": "obfs4", "iran_status": "iran_likely_blocked"},
        ]
    });
    fs::write(&iran_path, serde_json::to_string(&iran_data).unwrap()).unwrap();
    fs::write(&latest_path, r#"{"bridges": []}"#).unwrap();

    let py = python_adaptive_transport(&json!({
        "op": "main",
        "iran_path": iran_path,
        "latest_path": latest_path,
        "weights_path": weights_path,
        "history_path": history_path,
        "best_path": best_path,
    }));

    // Rust: use the same iran/latest files but separate output paths to avoid
    // collision with the Python run.
    let rs_weights_path = dir.join("rust_weights.json");
    let rs_history_path = dir.join("rust_history.json");
    let rs_best_path = dir.join("rust_best.json");
    transport_main(
        &iran_path,
        &latest_path,
        &rs_weights_path,
        &rs_history_path,
        &rs_best_path,
        fixed_now(),
    )
    .expect("rust main succeeds");

    let mut rs_result = serde_json::Map::new();
    if rs_weights_path.exists() {
        rs_result.insert(
            "weights".to_string(),
            serde_json::from_str(&fs::read_to_string(&rs_weights_path).unwrap()).unwrap(),
        );
    }
    if rs_best_path.exists() {
        rs_result.insert(
            "best".to_string(),
            serde_json::from_str(&fs::read_to_string(&rs_best_path).unwrap()).unwrap(),
        );
    }
    let rs = Value::Object(rs_result);

    let mut py = py;
    let mut rs = rs;
    strip_timestamps(&mut py);
    strip_timestamps(&mut rs);
    assert_eq!(py, rs, "main with records parity failed");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn parity_main_with_empty_records_writes_nothing() {
    let dir = case_dir("main_empty");
    let iran_path = dir.join("iran.json");
    let latest_path = dir.join("latest.json");
    let weights_path = dir.join("weights.json");
    let history_path = dir.join("history.json");
    let best_path = dir.join("best.json");

    fs::write(&iran_path, r#"{"bridges": []}"#).unwrap();
    fs::write(&latest_path, r#"{"bridges": []}"#).unwrap();

    let py = python_adaptive_transport(&json!({
        "op": "main",
        "iran_path": iran_path,
        "latest_path": latest_path,
        "weights_path": weights_path,
        "history_path": history_path,
        "best_path": best_path,
    }));

    // Python main() calls sys.exit(0) on empty → helper catches SystemExit
    // and returns empty result.
    let rs_weights_path = dir.join("rust_weights.json");
    let rs_history_path = dir.join("rust_history.json");
    let rs_best_path = dir.join("rust_best.json");
    transport_main(
        &iran_path,
        &latest_path,
        &rs_weights_path,
        &rs_history_path,
        &rs_best_path,
        fixed_now(),
    )
    .expect("rust main empty succeeds");

    // Both sides should produce no output files
    assert_eq!(py, json!({}), "python main empty should return empty");
    assert!(!rs_weights_path.exists(), "rust should not write weights");
    assert!(!rs_best_path.exists(), "rust should not write best");

    let _ = fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// select_transport_for_nin_cut parity (Python subprocess from temp CWD)
// ─────────────────────────────────────────────────────────────────────────────

fn write_nin_cut_fixtures(dir: &Path, nin_data: &Value, reality_data: &Value, next_gen: &Value) {
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::create_dir_all(dir.join("export")).unwrap();
    fs::write(
        dir.join("data/nin_cut_report.json"),
        serde_json::to_string_pretty(nin_data).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("data/reality_report.json"),
        serde_json::to_string_pretty(reality_data).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("data/next_gen_bridges.json"),
        serde_json::to_string_pretty(next_gen).unwrap(),
    )
    .unwrap();
}

#[test]
fn parity_select_transport_for_nin_cut_all_tiers() {
    let dir = case_dir("nin_cut_all_tiers");

    let nin_data = json!({
        "bridges": [
            {"transport": "webtunnel", "ip": "1.1.1.1", "port": 443, "raw": "wt-line-1", "nin_score": 0.8},
            {"transport": "webtunnel", "ip": "1.1.1.2", "port": 443, "raw": "wt-line-2", "nin_score": 0.5},
            {"transport": "obfs4", "ip": "2.2.2.2", "port": 443, "raw": "obfs4-443", "nin_score": 0.6},
            {"transport": "obfs4", "ip": "2.2.2.3", "port": 9001, "raw": "obfs4-9001", "nin_score": 0.9},
            {"transport": "snowflake", "ip": "3.3.3.3", "port": 443, "raw": "sf-line", "nin_score": 0.7}
        ]
    });
    let reality_data = json!({
        "per_bridge": [
            {"ip": "4.4.4.4", "port": 443, "sni": "cdn.example.com", "dpi_score": 0.75},
            {"ip": "4.4.4.5", "port": 8443, "sni": "cdn2.example.com", "dpi_score": 0.4}
        ]
    });
    let next_gen = json!({
        "webtransport_scores": [
            {"ip": "5.5.5.5", "port": 443, "raw": "wt-quic-1", "webtransport_score": 0.85},
            {"ip": "5.5.5.6", "port": 443, "raw": "wt-quic-2", "webtransport_score": 0.6}
        ]
    });

    write_nin_cut_fixtures(&dir, &nin_data, &reality_data, &next_gen);

    let py = python_nin_cut(&dir);

    let output_path = dir.join("export/rust_output.json");
    let rs = select_transport_for_nin_cut(
        &dir.join("data/nin_cut_report.json"),
        &dir.join("data/reality_report.json"),
        &dir.join("data/next_gen_bridges.json"),
        &output_path,
        fixed_now(),
    )
    .expect("rust nin_cut succeeds");

    let mut py = py;
    let mut rs = rs;
    strip_timestamps(&mut py);
    strip_timestamps(&mut rs);
    assert_eq!(
        py, rs,
        "select_transport_for_nin_cut all-tiers parity failed"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn parity_select_transport_for_nin_cut_empty_inputs() {
    let dir = case_dir("nin_cut_empty");

    let nin_data = json!({"bridges": []});
    let reality_data = json!({"per_bridge": []});
    let next_gen = json!({"webtransport_scores": []});

    write_nin_cut_fixtures(&dir, &nin_data, &reality_data, &next_gen);

    let py = python_nin_cut(&dir);

    let output_path = dir.join("export/rust_output.json");
    let rs = select_transport_for_nin_cut(
        &dir.join("data/nin_cut_report.json"),
        &dir.join("data/reality_report.json"),
        &dir.join("data/next_gen_bridges.json"),
        &output_path,
        fixed_now(),
    )
    .expect("rust nin_cut empty succeeds");

    let mut py = py;
    let mut rs = rs;
    strip_timestamps(&mut py);
    strip_timestamps(&mut rs);
    assert_eq!(py, rs, "select_transport_for_nin_cut empty parity failed");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn parity_select_transport_for_nin_cut_dedup_by_raw() {
    let dir = case_dir("nin_cut_dedup");

    // Two webtunnel bridges with the same raw line → one should be deduped
    let nin_data = json!({
        "bridges": [
            {"transport": "webtunnel", "ip": "1.1.1.1", "port": 443, "raw": "duplicate-line", "nin_score": 0.9},
            {"transport": "webtunnel", "ip": "1.1.1.2", "port": 443, "raw": "duplicate-line", "nin_score": 0.7}
        ]
    });
    let reality_data = json!({"per_bridge": []});
    let next_gen = json!({"webtransport_scores": []});

    write_nin_cut_fixtures(&dir, &nin_data, &reality_data, &next_gen);

    let py = python_nin_cut(&dir);

    let output_path = dir.join("export/rust_output.json");
    let rs = select_transport_for_nin_cut(
        &dir.join("data/nin_cut_report.json"),
        &dir.join("data/reality_report.json"),
        &dir.join("data/next_gen_bridges.json"),
        &output_path,
        fixed_now(),
    )
    .expect("rust nin_cut dedup succeeds");

    let mut py = py;
    let mut rs = rs;
    strip_timestamps(&mut py);
    strip_timestamps(&mut rs);
    assert_eq!(py, rs, "select_transport_for_nin_cut dedup parity failed");

    let _ = fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust-only edge-case tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_collect_transport_stats_missing_transport_uses_unknown_key() {
    let records = json!([
        {"iran_status": "iran_likely_working"},
        {"transport": null, "iran_status": "iran_likely_blocked"}
    ]);
    let records_arr = records.as_array().unwrap().clone();
    let stats = collect_transport_stats(&records_arr);
    // Missing transport → "unknown" key (Python r.get("transport", "unknown"))
    assert_eq!(stats.get("unknown").unwrap().total, 1);
    assert_eq!(stats.get("unknown").unwrap().working, 1);
    // null transport → "null" key (Python None key → json "null")
    assert_eq!(stats.get("null").unwrap().total, 1);
    assert_eq!(stats.get("null").unwrap().blocked, 1);
}

#[test]
fn rust_compute_weights_single_transport_insufficient() {
    let mut stats = BTreeMap::new();
    stats.insert(
        "obfs4".to_string(),
        TransportStats {
            working: 0,
            total: 1,
            ..Default::default()
        },
    );
    let weights = compute_weights(&stats, 3);
    // raw = 0.5, total = 0.5 → normalized = 1.0
    assert!((weights.get("obfs4").unwrap() - 1.0).abs() < 1e-9);
}

#[test]
fn rust_weights_to_scores_default_weight_for_missing_transport() {
    let weights: BTreeMap<String, f64> = BTreeMap::new();
    let scores = weights_to_scores(&weights);
    // All transports use default weight = 1/6
    // snowflake: 30 * (0.7 + 0.6/6) = 30 * 0.8 = 24
    assert_eq!(scores.get("snowflake").unwrap(), &24);
    // unknown: 8 * 0.8 = 6.4 → round 6
    assert_eq!(scores.get("unknown").unwrap(), &6);
}

#[test]
fn rust_save_weights_appends_to_existing_history() {
    let dir = case_dir("save_weights_append");
    let weights_path = dir.join("weights.json");
    let history_path = dir.join("history.json");

    // Pre-populate history with one entry
    let existing_history =
        json!([{"ts": "2023-01-01T00:00:00+00:00", "weights": {}, "scores": {}}]);
    fs::write(
        &history_path,
        serde_json::to_string_pretty(&existing_history).unwrap(),
    )
    .unwrap();

    let weights: BTreeMap<String, f64> = BTreeMap::from([("obfs4".to_string(), 0.5)]);
    let scores: BTreeMap<String, i64> = BTreeMap::from([("obfs4".to_string(), 20)]);
    let stats: BTreeMap<String, TransportStats> = BTreeMap::new();

    save_weights(
        &weights,
        &scores,
        &stats,
        fixed_now(),
        &weights_path,
        &history_path,
    )
    .expect("rust save_weights append succeeds");

    let history: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(&history_path).unwrap()).unwrap();
    assert_eq!(
        history.len(),
        2,
        "history should have 2 entries after append"
    );

    let _ = fs::remove_dir_all(&dir);
}

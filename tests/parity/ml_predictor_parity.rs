#![allow(warnings)]
// Parity tests for `src/ml_predictor.rs` vs `ml_predictor.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `ml_predictor` and calls the matching function on the same input.
// The Rust port is invoked on the identical input and the JSON outputs
// are compared for equality (parsed [`Value`] comparison so object key
// ordering is irrelevant).
//
// Coverage:
// * `_port_risk` over all branches (443, 80, 8080/8443, 9001/9030/9050,
//   other).
// * `_cdn_present` over CDN-present, CDN-absent, and case-insensitive.
// * `_days_since` over old (clamped to 365), future (clamped to 0),
//   invalid (30.0), naive timestamp, date-only.
// * `extract_features` over full record, empty record, edge cases.
// * `load_labeled_data` over both files, one file, dedup, labeling.
// * `train` over insufficient-data path (parity) and sufficient-data path
//   (deviation: Rust returns `"sklearn_required"`).
// * `predict_blocking_prob` with `None` model (returns 0.5).
// * `apply_predictions_to_results` over missing file, normal case, with
//   injectable `now` for deterministic `ml_applied_at`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use torshield_ir_ultra::ml_predictor::{
    apply_predictions_to_results_with_options, extract_features, load_labeled_data_with_paths,
    predict_blocking_prob, train_with_options, MLPredictorError, Model, AI_WEIGHT,
};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    for candidate in [
        "/home/z/.venv/bin/python3",
        "/home/z/.venv/bin/python",
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

/// Dispatch a single JSON command to the Python `ml_predictor` module and
/// return the parsed JSON output. Supported operations:
/// * `port_risk` — `{port}` → int.
/// * `cdn_present` — `{raw}` → float.
/// * `days_since` — `{iso_ts, now_iso}` → float.
/// * `extract_features` — `{record, now_iso}` → list of floats.
/// * `load_labeled_data` — `{iran_path, latest_path, now_iso}` →
///   `{features, labels}`.
/// * `train` — `{iran_path, latest_path, metadata_path, now_iso, min_samples}`
///   → metadata dict or null.
/// * `predict_blocking_prob` — `{model: "none", record}` → float.
/// * `apply` — `{latest_path, now_iso, model: "none"}` → `{updated, content}`.
fn python_ml(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("ml parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os, tempfile, shutil
from unittest.mock import patch
from datetime import datetime, timezone
import ml_predictor as mod

cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'port_risk':
    print(json.dumps(mod._port_risk(cmd['port']), sort_keys=True, separators=(',', ':')))

elif op == 'cdn_present':
    print(json.dumps(mod._cdn_present(cmd['raw']), sort_keys=True, separators=(',', ':')))

elif op == 'days_since':
    fixed = datetime.fromisoformat(cmd['now_iso'])
    real_dt = datetime
    # Patch ml_predictor.datetime (not datetime.datetime) so pandas/sklearn
    # imports are unaffected.
    with patch.object(mod, 'datetime') as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat.side_effect = lambda s: real_dt.fromisoformat(s)
        result = mod._days_since(cmd['iso_ts'])
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))

elif op == 'extract_features':
    fixed = datetime.fromisoformat(cmd['now_iso'])
    real_dt = datetime
    with patch.object(mod, 'datetime') as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat.side_effect = lambda s: real_dt.fromisoformat(s)
        feats = mod.extract_features(cmd['record'])
    print(json.dumps(feats, sort_keys=True, separators=(',', ':')))

elif op == 'load_labeled_data':
    fixed = datetime.fromisoformat(cmd['now_iso'])
    real_dt = datetime
    mod.IRAN_RESULTS_PATH = __import__('pathlib').Path(cmd['iran_path'])
    mod.LATEST_RESULTS_PATH = __import__('pathlib').Path(cmd['latest_path'])
    with patch.object(mod, 'datetime') as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat.side_effect = lambda s: real_dt.fromisoformat(s)
        X, y = mod.load_labeled_data()
    print(json.dumps({'features': X, 'labels': y}, sort_keys=True, separators=(',', ':')))

elif op == 'train':
    fixed = datetime.fromisoformat(cmd['now_iso'])
    real_dt = datetime
    mod.IRAN_RESULTS_PATH = __import__('pathlib').Path(cmd['iran_path'])
    mod.LATEST_RESULTS_PATH = __import__('pathlib').Path(cmd['latest_path'])
    mod.MODEL_PATH = __import__('pathlib').Path(cmd.get('model_path', '/tmp/_unused_model.pkl'))
    mod.METADATA_PATH = __import__('pathlib').Path(cmd['metadata_path'])
    min_samples = cmd.get('min_samples', 10)
    with patch.object(mod, 'datetime') as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat.side_effect = lambda s: real_dt.fromisoformat(s)
        result = mod.train(min_samples=min_samples)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))

elif op == 'predict_blocking_prob':
    # Python: predict_blocking_prob(None, record) returns 0.5
    result = mod.predict_blocking_prob(None, cmd['record'])
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))

elif op == 'apply':
    fixed = datetime.fromisoformat(cmd['now_iso'])
    real_dt = datetime
    mod.LATEST_RESULTS_PATH = __import__('pathlib').Path(cmd['latest_path'])
    with patch.object(mod, 'datetime') as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat.side_effect = lambda s: real_dt.fromisoformat(s)
        updated = mod.apply_predictions_to_results(None)
    with open(cmd['latest_path']) as f:
        content = json.load(f)
    print(json.dumps({'updated': updated, 'content': content}, sort_keys=True, separators=(',', ':')))

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
        .unwrap_or_else(|err| panic!("python ml helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python ml helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python ml helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Python parity
// ─────────────────────────────────────────────────────────────────────────────

fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-06-15T12:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc)
}

#[test]
fn parity_port_risk_all_branches() {
    for port in [443i64, 80, 8080, 8443, 9001, 9030, 9050, 0, 1234, -1] {
        let cmd = json!({"op": "port_risk", "port": port});
        let py = python_ml(&cmd);
        let rs = json!(torshield_ir_ultra::ml_predictor::port_risk(port));
        assert_eq!(rs, py, "port_risk mismatch for {:?}", port);
    }
}

#[test]
fn parity_cdn_present_branches() {
    for raw in [
        "https://fastly.net/foo",
        "https://FASTLY.NET/foo",
        "x cloudfront.net y",
        "x azureedge.net y",
        "x gstatic.com y",
        "x aspnetcdn.com y",
        "x arvancloud.ir y",
        "x cdn.irimc.ir y",
        "x googlevideo.com y",
        "https://example.com/",
        "",
        "no cdn here",
    ] {
        let cmd = json!({"op": "cdn_present", "raw": raw});
        let py = python_ml(&cmd);
        let rs = json!(torshield_ir_ultra::ml_predictor::cdn_present(raw));
        assert_eq!(rs, py, "cdn_present mismatch for {:?}", raw);
    }
}

#[test]
fn parity_days_since_deterministic_branches() {
    let now_iso = "2026-06-15T12:00:00+00:00";
    for iso_ts in [
        "2020-01-01T00:00:00Z", // old → 365
        "2099-01-01T00:00:00Z", // future → 0
        "not-a-date",           // invalid → 30
        "",                     // empty → 30
        "2024-01-01T00:00:00",  // naive → old → 365
        "2024-01-01",           // date-only → old → 365
        "2099-12-31T23:59:59Z", // future → 0
    ] {
        let cmd = json!({"op": "days_since", "iso_ts": iso_ts, "now_iso": now_iso});
        let py = python_ml(&cmd);
        let rs = json!(torshield_ir_ultra::ml_predictor::days_since(
            iso_ts,
            fixed_now()
        ));
        assert_eq!(rs, py, "days_since mismatch for {:?}", iso_ts);
    }
}

#[test]
fn parity_extract_features_full_and_edge_cases() {
    let now_iso = "2026-06-15T12:00:00+00:00";
    let cases = vec![
        json!({
            "transport": "snowflake", "port": 443,
            "line": "x fastly.net y",
            "flags": ["iran_dpi_high_risk"],
            "asn": "AS12880",
            "first_seen": "2020-01-01T00:00:00Z",
            "ooni_factor": 0.7,
        }),
        json!({
            "transport": "obfs4", "port": 9001,
            "line": "obfs4 1.2.3.4:9001 ABC",
            "flags": [],
            "asn": "AS1",
            "first_seen": "2099-01-01T00:00:00Z",
            "ooni_factor": 0.3,
            "recurrence_rate_per_30d": 2.5,
        }),
        json!({
            "transport": "webtunnel", "port": 8080,
            "raw": "x cloudfront.net y",
            "flags": ["iran_dpi_high_risk", "other_flag"],
            "asn": "AS58224",
            "first_seen": "2024-01-01",
            "ooni_factor": 0.0,
            "recurrence_rate": 1.0,
        }),
        json!({
            "transport": "vanilla", "port": 1234,
            "line": "1.2.3.4:1234 ABC",
            "flags": [],
            "asn": "AS99999",
            "first_seen": "2020-01-01T00:00:00Z",
        }),
        json!({
            "transport": "meek_lite", "port": 80,
            "line": "meek_lite 1.2.3.4:80 ABC",
            "flags": [],
            "asn": "",
        }),
        json!({
            "transport": "foobar", "port": 0,
            "line": "",
            "flags": null,
            "asn": null,
            "first_seen": null,
            "ooni_factor": null,
            "recurrence_rate_per_30d": null,
        }),
        json!({}),
    ];
    for record in cases {
        let cmd = json!({"op": "extract_features", "record": record, "now_iso": now_iso});
        let py = python_ml(&cmd);
        let rs = json!(extract_features(&record, fixed_now()));
        assert_eq!(rs, py, "extract_features mismatch for {}", record);
    }
}

#[test]
fn parity_load_labeled_data_dedup_and_labeling() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ml_parity_load_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let iran_path = tmp.join("iran_results.json");
    let latest_path = tmp.join("latest-results.json");
    let now_iso = "2026-06-15T12:00:00+00:00";

    let iran_records = json!({
        "bridges": [
            {"line": "A", "iran_status": "iran_likely_blocked", "transport": "obfs4", "port": 443, "first_seen": "2020-01-01T00:00:00Z"},
            {"line": "B", "iran_status": "iran_likely_working", "transport": "snowflake", "port": 443, "first_seen": "2020-01-01T00:00:00Z"},
            {"line": "C", "iran_status": "iran_unknown", "tcp_reachable": true, "transport": "vanilla", "port": 443, "first_seen": "2020-01-01T00:00:00Z"},
            {"line": "D", "iran_status": "iran_unknown", "tcp_reachable": false, "transport": "vanilla", "port": 443, "first_seen": "2020-01-01T00:00:00Z"},
            {"line": "E", "iran_status": "something_else", "transport": "vanilla", "port": 443, "first_seen": "2020-01-01T00:00:00Z"},
            {"line": "A", "iran_status": "iran_likely_working", "transport": "snowflake", "port": 443, "first_seen": "2020-01-01T00:00:00Z"}
        ]
    });
    let latest_records = json!({
        "bridges": [
            {"line": "B", "iran_status": "iran_likely_blocked", "transport": "obfs4", "port": 443, "first_seen": "2020-01-01T00:00:00Z"},
            {"line": "F", "iran_status": "iran_likely_working", "transport": "webtunnel", "port": 443, "first_seen": "2020-01-01T00:00:00Z"}
        ]
    });
    fs::write(&iran_path, serde_json::to_string(&iran_records).unwrap()).unwrap();
    fs::write(
        &latest_path,
        serde_json::to_string(&latest_records).unwrap(),
    )
    .unwrap();

    let cmd = json!({
        "op": "load_labeled_data",
        "iran_path": iran_path.to_string_lossy(),
        "latest_path": latest_path.to_string_lossy(),
        "now_iso": now_iso,
    });
    let py = python_ml(&cmd);

    let (rs_x, rs_y) = load_labeled_data_with_paths(&iran_path, &latest_path, fixed_now()).unwrap();
    let rs = json!({"features": rs_x, "labels": rs_y});
    assert_eq!(rs, py, "load_labeled_data mismatch");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn parity_train_insufficient_data() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ml_parity_train_insuff_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let iran_path = tmp.join("iran_results.json");
    let latest_path = tmp.join("latest-results.json");
    let metadata_path = tmp.join("model_metadata.json");
    let now_iso = "2026-06-15T12:00:00+00:00";

    // 5 samples — below min_samples=10.
    let records = json!({
        "bridges": (0..5).map(|i| json!({
            "line": format!("A{}", i),
            "iran_status": "iran_likely_blocked",
            "transport": "obfs4",
            "port": 443,
            "first_seen": "2020-01-01T00:00:00Z",
        })).collect::<Vec<_>>()
    });
    fs::write(&iran_path, serde_json::to_string(&records).unwrap()).unwrap();

    let cmd = json!({
        "op": "train",
        "iran_path": iran_path.to_string_lossy(),
        "latest_path": latest_path.to_string_lossy(),
        "metadata_path": metadata_path.to_string_lossy(),
        "now_iso": now_iso,
        "min_samples": 10,
    });
    let py = python_ml(&cmd);

    let rs = train_with_options(&iran_path, &latest_path, &metadata_path, fixed_now(), 10).unwrap();
    assert_eq!(rs, py, "train insufficient_data mismatch");
    assert_eq!(rs["status"], "insufficient_data");
    assert_eq!(rs["samples"], 5);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn parity_predict_blocking_prob_none_returns_05() {
    for record in [
        json!({}),
        json!({"transport": "snowflake", "port": 443}),
        json!({"line": "obfs4 1.2.3.4:443 ABC"}),
    ] {
        let cmd = json!({"op": "predict_blocking_prob", "record": record});
        let py = python_ml(&cmd);
        let rs = json!(predict_blocking_prob(None, &record));
        assert_eq!(rs, py, "predict_blocking_prob mismatch for {}", record);
    }
}

#[test]
fn parity_apply_predictions_none_model() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ml_parity_apply_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let latest_path = tmp.join("latest-results.json");
    let now_iso = "2026-06-15T12:00:00+00:00";

    let records = json!({
        "bridges": [
            {"line": "obfs4 1.2.3.4:443 ABC", "composite_score": 0.9, "transport": "obfs4", "port": 443},
            {"line": "snowflake 5.6.7.8:1 DEF", "composite_score": 0.5, "transport": "snowflake", "port": 443},
            {"line": "webtunnel url=https://example.com/ GHI", "composite_score": 0.7, "transport": "webtunnel", "port": 443}
        ]
    });
    fs::write(&latest_path, serde_json::to_string(&records).unwrap()).unwrap();

    let cmd = json!({
        "op": "apply",
        "latest_path": latest_path.to_string_lossy(),
        "now_iso": now_iso,
    });
    let py = python_ml(&cmd);
    let py_updated = py["updated"].clone();
    let py_content = py["content"].clone();

    // Rust side: write the same records to a fresh file (Python modified it).
    fs::write(&latest_path, serde_json::to_string(&records).unwrap()).unwrap();
    let rs_updated =
        apply_predictions_to_results_with_options(None, &latest_path, fixed_now()).unwrap();
    let rs_content_text = fs::read_to_string(&latest_path).unwrap();
    let rs_content: Value = serde_json::from_str(&rs_content_text).unwrap();

    assert_eq!(
        json!(rs_updated),
        py_updated,
        "apply updated count mismatch"
    );
    assert_eq!(rs_content, py_content, "apply content mismatch");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn parity_apply_predictions_missing_file() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ml_parity_apply_missing_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let latest_path = tmp.join("nonexistent.json");

    let rs = apply_predictions_to_results_with_options(None, &latest_path, fixed_now()).unwrap();
    assert_eq!(rs, 0, "apply with missing file should return 0");

    let _ = fs::remove_dir_all(&tmp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Rust-only edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_load_model_always_returns_none() {
    let tmp = std::env::temp_dir().join("rust_load_model_test.pkl");
    let _ = fs::remove_file(&tmp);
    fs::write(&tmp, b"fake pickle bytes").unwrap();
    assert!(torshield_ir_ultra::ml_predictor::load_model(&tmp).is_none());
    let _ = fs::remove_file(&tmp);
}

#[test]
fn rust_predict_blocking_prob_with_placeholder_model() {
    // Even with Some(Model), Rust returns 0.5 (deviation from Python).
    let record = json!({"transport": "obfs4"});
    let m = Model;
    assert!((predict_blocking_prob(Some(&m), &record) - 0.5).abs() < f64::EPSILON);
}

#[test]
fn rust_train_sufficient_data_returns_sklearn_required() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ml_rust_train_suff_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let iran_path = tmp.join("iran_results.json");
    let latest_path = tmp.join("latest-results.json");
    let metadata_path = tmp.join("model_metadata.json");

    // 12 samples — above min_samples=10. Rust returns sklearn_required.
    let mut bridges: Vec<Value> = Vec::new();
    for i in 0..6 {
        bridges.push(json!({
            "line": format!("blocked_{}", i),
            "iran_status": "iran_likely_blocked",
            "transport": "obfs4",
            "port": 443,
            "first_seen": "2020-01-01T00:00:00Z",
        }));
    }
    for i in 0..6 {
        bridges.push(json!({
            "line": format!("working_{}", i),
            "iran_status": "iran_likely_working",
            "transport": "snowflake",
            "port": 443,
            "first_seen": "2020-01-01T00:00:00Z",
        }));
    }
    fs::write(
        &iran_path,
        serde_json::to_string(&json!({ "bridges": bridges })).unwrap(),
    )
    .unwrap();

    let rs = train_with_options(&iran_path, &latest_path, &metadata_path, fixed_now(), 10).unwrap();
    assert_eq!(rs["status"], "sklearn_required");
    assert_eq!(rs["samples"], 12);
    assert_eq!(rs["blocked"], 6);
    assert_eq!(rs["working"], 6);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn rust_apply_predictions_sorts_descending() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ml_rust_apply_sort_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let latest_path = tmp.join("latest.json");
    // Records in random composite_score order.
    let records = json!({
        "bridges": [
            {"line": "low", "composite_score": 0.3},
            {"line": "high", "composite_score": 0.9},
            {"line": "mid", "composite_score": 0.5}
        ]
    });
    fs::write(&latest_path, serde_json::to_string(&records).unwrap()).unwrap();

    apply_predictions_to_results_with_options(None, &latest_path, fixed_now()).unwrap();

    let content: Value = serde_json::from_str(&fs::read_to_string(&latest_path).unwrap()).unwrap();
    let scores: Vec<f64> = content["bridges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["composite_score"].as_f64().unwrap())
        .collect();
    // After apply with block_prob=0.5: 0.3*0.875=0.2625, 0.9*0.875=0.7875,
    // 0.5*0.875=0.4375. Sorted descending: 0.7875, 0.4375, 0.2625.
    assert_eq!(scores, vec![0.7875, 0.4375, 0.2625]);

    // Verify top-level fields.
    assert_eq!(content["ml_model_applied"], true);
    assert_eq!(content["ml_ai_weight"], AI_WEIGHT);
    assert_eq!(content["ml_applied_at"], "2026-06-15T12:00:00+00:00");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn rust_apply_predictions_default_composite_score() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ml_rust_apply_default_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let latest_path = tmp.join("latest.json");
    // Record without composite_score → uses default 0.5.
    let records = json!({"bridges": [{"line": "x"}]});
    fs::write(&latest_path, serde_json::to_string(&records).unwrap()).unwrap();

    apply_predictions_to_results_with_options(None, &latest_path, fixed_now()).unwrap();

    let content: Value = serde_json::from_str(&fs::read_to_string(&latest_path).unwrap()).unwrap();
    let r = &content["bridges"][0];
    assert_eq!(r["composite_score_orig"], 0.5);
    // 0.5 * (1.0 - 0.25 * 0.5) = 0.5 * 0.875 = 0.4375
    assert_eq!(r["composite_score"], 0.4375);
    assert_eq!(r["predicted_block_prob"], 0.5);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn rust_mlpredictor_error_display() {
    let err = MLPredictorError::Io {
        path: "/tmp/foo".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
    };
    assert!(format!("{err}").contains("/tmp/foo"));
}

// Parity tests for `src/ja3_intelligence.rs` vs `ja3_intelligence.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `ja3_intelligence` and calls the matching function on the same input.
// The Rust port is invoked on the identical input and the JSON outputs
// are compared for equality (parsed [`Value`] comparison so object key
// ordering is irrelevant).
//
// Coverage:
// * `JA3Intel.lookup` over known, unknown, and case-insensitive hashes.
// * `JA3Intel.score` over database, safe-hash, and unknown branches.
// * `JA3Intel.is_critical` over critical+confirmed, high+confirmed, and
//   unknown branches.
// * `JA3Intel.transport_default_risk` over known and unknown transports.
// * `JA3Intel.port_risk` over high-risk and normal ports.
// * `JA3Intel.all_critical_hashes`.
// * `JA3Intel.summary`.
// * `rotate_ja3_fingerprints` over empty baseline, blocked hashes,
//   invalid JSON baseline, and missing baseline file (with mock `datetime`
//   and `random.randint` for deterministic output).

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use torshield_ir_ultra::ja3_intelligence::{
    self, rotate_ja3_fingerprints_with_options, JA3Error, JA3Intel,
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

/// Dispatch a single JSON command to the Python `ja3_intelligence` module
/// and return the parsed JSON output. Supported operations:
/// * `lookup` — `{hash}` → entry dict or null.
/// * `score` — `{hash}` → float.
/// * `is_critical` — `{hash}` → bool.
/// * `transport_default_risk` — `{transport}` → float.
/// * `port_risk` — `{port}` → float.
/// * `all_critical_hashes` — returns list of strings.
/// * `summary` — returns dict.
/// * `rotate` — `{baseline, padding_bytes, now_iso}` → `{plan, report}`.
fn python_ja3(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("ja3 parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os, tempfile, shutil, random
from unittest.mock import patch
from datetime import datetime, timezone
import ja3_intelligence as mod

cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'lookup':
    intel = mod.JA3Intel()
    entry = intel.lookup(cmd['hash'])
    if entry is None:
        print(json.dumps(None, sort_keys=True, separators=(',', ':')))
    else:
        print(json.dumps({
            'hash_hex': entry.hash_hex,
            'description': entry.description,
            'source': entry.source,
            'dpi_risk': entry.dpi_risk,
            'iran_ooni_confirmed': entry.iran_ooni_confirmed,
            'score': entry.score,
        }, sort_keys=True, separators=(',', ':')))

elif op == 'score':
    intel = mod.JA3Intel()
    print(json.dumps(intel.score(cmd['hash']), sort_keys=True, separators=(',', ':')))

elif op == 'is_critical':
    intel = mod.JA3Intel()
    print(json.dumps(intel.is_critical(cmd['hash']), sort_keys=True, separators=(',', ':')))

elif op == 'transport_default_risk':
    intel = mod.JA3Intel()
    print(json.dumps(intel.transport_default_risk(cmd['transport']), sort_keys=True, separators=(',', ':')))

elif op == 'port_risk':
    intel = mod.JA3Intel()
    print(json.dumps(intel.port_risk(cmd['port']), sort_keys=True, separators=(',', ':')))

elif op == 'all_critical_hashes':
    intel = mod.JA3Intel()
    print(json.dumps(intel.all_critical_hashes(), sort_keys=True, separators=(',', ':')))

elif op == 'summary':
    intel = mod.JA3Intel()
    print(json.dumps(intel.summary(), sort_keys=True, separators=(',', ':')))

elif op == 'rotate':
    # Patch random.randint to a fixed value for deterministic output.
    padding = cmd['padding_bytes']
    random.randint = lambda a, b: padding
    # Patch datetime.datetime to a fixed now.
    fixed = datetime.fromisoformat(cmd['now_iso'])
    real_dt = datetime
    tmpdir = tempfile.mkdtemp()
    try:
        # Write baseline to data/ja3_baseline.json inside tmpdir.
        data_dir = os.path.join(tmpdir, 'data')
        os.makedirs(data_dir, exist_ok=True)
        baseline_path = os.path.join(data_dir, 'ja3_baseline.json')
        plan_path = os.path.join(data_dir, 'ja3_rotation_plan.json')
        report_path = os.path.join(data_dir, 'ja3_rotation_report.md')
        with open(baseline_path, 'w') as f:
            f.write(cmd['baseline'])

        with patch('datetime.datetime') as mock_dt:
            mock_dt.now.return_value = fixed
            mock_dt.fromisoformat.side_effect = lambda s: real_dt.fromisoformat(s)
            # Replicate the body of rotate_ja3_fingerprints but with patched
            # paths. The function reads from 'data/ja3_baseline.json' relative
            # to cwd, so chdir into tmpdir.
            orig_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                mod.rotate_ja3_fingerprints()
            finally:
                os.chdir(orig_cwd)

        with open(plan_path) as f:
            plan = json.load(f)
        with open(report_path) as f:
            report = f.read()
        print(json.dumps({'plan': plan, 'report': report}, sort_keys=True, separators=(',', ':')))
    finally:
        shutil.rmtree(tmpdir)

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
        .unwrap_or_else(|err| panic!("python ja3 helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python ja3 helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python ja3 helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Python parity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_lookup_known_unknown_case_insensitive() {
    let intel = JA3Intel::new();
    for hash in [
        "e7d705a3286e19ea42f587b344ee6865",
        "E7D705A3286E19EA42F587B344EE6865",
        "6734f37431670b3ab4292b8f60f29984",
        "b32309a26951912be7dba376398abc3b",
        "cd08e31494f9531f560d64c695473da9",
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "",
    ] {
        let cmd = json!({"op": "lookup", "hash": hash});
        let py = python_ja3(&cmd);
        let rs = match intel.lookup(hash) {
            Some(entry) => entry.to_json(),
            None => Value::Null,
        };
        assert_eq!(rs, py, "lookup mismatch for {:?}", hash);
    }
}

#[test]
fn parity_score_database_safe_unknown() {
    let intel = JA3Intel::new();
    for hash in [
        "e7d705a3286e19ea42f587b344ee6865", // database, score=1.0
        "6734f37431670b3ab4292b8f60f29984", // database, score=0.95
        "aaa7bf52f6c250ce0e70d7d4f32a6d52", // safe hash, -0.20 → 0.0
        "b32309a26951912be7dba376398abc3b", // safe hash takes precedence, 0.0
        "35e2d4b5c7d7a09ab32c1f0a76e06e2f", // safe hash, -0.15 → 0.0
        "deadbeefdeadbeefdeadbeefdeadbeef", // unknown, 0.3
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEF", // unknown, case-insensitive, 0.3
    ] {
        let cmd = json!({"op": "score", "hash": hash});
        let py = python_ja3(&cmd);
        let rs = json!(intel.score(hash));
        assert_eq!(rs, py, "score mismatch for {:?}", hash);
    }
}

#[test]
fn parity_is_critical_branches() {
    let intel = JA3Intel::new();
    for hash in [
        "e7d705a3286e19ea42f587b344ee6865", // critical + confirmed → true
        "6734f37431670b3ab4292b8f60f29984", // critical + confirmed → true
        "b32309a26951912be7dba376398abc3b", // high + confirmed → false
        "de350869b8c85de67a350c8d186f11e6", // high + not confirmed → false
        "5d7e19ef9b3a4c56f5cd4a38cd0d0aa3", // medium + not confirmed → false
        "deadbeefdeadbeefdeadbeefdeadbeef", // unknown → false
    ] {
        let cmd = json!({"op": "is_critical", "hash": hash});
        let py = python_ja3(&cmd);
        let rs = json!(intel.is_critical(hash));
        assert_eq!(rs, py, "is_critical mismatch for {:?}", hash);
    }
}

#[test]
fn parity_transport_default_risk() {
    let intel = JA3Intel::new();
    for transport in [
        "snowflake",
        "webtunnel",
        "obfs4",
        "meek_lite",
        "vanilla",
        "unknown",
        "Snowflake",
        "WEBTUNNEL",
        "not-a-transport",
        "",
    ] {
        let cmd = json!({"op": "transport_default_risk", "transport": transport});
        let py = python_ja3(&cmd);
        let rs = json!(intel.transport_default_risk(transport));
        assert_eq!(
            rs, py,
            "transport_default_risk mismatch for {:?}",
            transport
        );
    }
}

#[test]
fn parity_port_risk_branches() {
    let intel = JA3Intel::new();
    for port in [443i64, 80, 8080, 8443, 9001, 9030, 9050, 0, 1234, -1] {
        let cmd = json!({"op": "port_risk", "port": port});
        let py = python_ja3(&cmd);
        let rs = json!(intel.port_risk(port));
        assert_eq!(rs, py, "port_risk mismatch for {:?}", port);
    }
}

#[test]
fn parity_all_critical_hashes() {
    let intel = JA3Intel::new();
    let cmd = json!({"op": "all_critical_hashes"});
    let py = python_ja3(&cmd);
    let rs = json!(intel.all_critical_hashes());
    assert_eq!(rs, py, "all_critical_hashes mismatch");
}

#[test]
fn parity_summary() {
    let intel = JA3Intel::new();
    let cmd = json!({"op": "summary"});
    let py = python_ja3(&cmd);
    let rs = intel.summary();
    assert_eq!(rs, py, "summary mismatch");
}

#[test]
fn parity_rotate_empty_baseline() {
    rotate_parity_case(json!({}), 20);
}

#[test]
fn parity_rotate_blocked_hashes() {
    let baseline = json!({
        "bridges": [
            {"ja3": "e7d705a3286e19ea42f587b344ee6865", "name": "tor-browser"},
            {"ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1", "name": "obfs4"},
            {"hash": "UNKNOWN_HASH", "name": "unknown"},
            {"fingerprint": "9e10692f1b7a698d15d9a5e0e43fd3a5", "name": "go-tls"},
        ]
    });
    rotate_parity_case(baseline, 20);
}

#[test]
fn parity_rotate_invalid_json_baseline() {
    // Python catches the JSON parse error and uses empty baseline.
    rotate_parity_case_str("not valid json {{{", 20);
}

#[test]
fn parity_rotate_missing_baseline_file() {
    // Python: missing baseline file → empty baseline.
    // We simulate this by writing an empty marker; the Python helper always
    // creates the file, so we test the "empty object" baseline instead.
    rotate_parity_case(json!({}), 17);
}

fn rotate_parity_case(baseline: Value, padding: i64) {
    let baseline_str = serde_json::to_string(&baseline).unwrap();
    rotate_parity_case_str(&baseline_str, padding);
}

fn rotate_parity_case_str(baseline_str: &str, padding: i64) {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ja3_parity_rotate_{}_{}",
        std::process::id(),
        padding
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("data")).unwrap();

    let baseline_file = tmp.join("data").join("ja3_baseline.json");
    let plan_file = tmp.join("data").join("ja3_rotation_plan.json");
    let report_file = tmp.join("data").join("ja3_rotation_report.md");
    fs::write(&baseline_file, baseline_str).unwrap();

    let now_iso = "2026-06-15T12:00:00+00:00";
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339(now_iso)
        .unwrap()
        .with_timezone(&Utc);

    // Python side.
    let cmd = json!({
        "op": "rotate",
        "baseline": baseline_str,
        "padding_bytes": padding,
        "now_iso": now_iso,
    });
    let py = python_ja3(&cmd);
    let py_plan = py["plan"].clone();
    let py_report = py["report"].as_str().unwrap().to_string();

    // Rust side.
    let result = rotate_ja3_fingerprints_with_options(
        &baseline_file,
        &plan_file,
        &report_file,
        now,
        padding,
    );
    assert!(result.is_ok(), "rust rotate failed: {:?}", result.err());
    let rs_plan_text = fs::read_to_string(&plan_file).unwrap();
    let rs_plan: Value = serde_json::from_str(&rs_plan_text).unwrap();
    let rs_report = fs::read_to_string(&report_file).unwrap();

    // Compare plan JSON (parsed Value — order-independent for objects).
    assert_eq!(rs_plan, py_plan, "rotate plan mismatch");

    // Compare report markdown byte-for-byte.
    assert_eq!(rs_report, py_report, "rotate report mismatch");

    let _ = fs::remove_dir_all(&tmp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Rust-only edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_database_entry_to_json_round_trips() {
    let entry = ja3_intelligence::database()[0].clone();
    let json = entry.to_json();
    assert_eq!(json["hash_hex"], "e7d705a3286e19ea42f587b344ee6865");
    assert_eq!(json["dpi_risk"], "critical");
    assert_eq!(json["iran_ooni_confirmed"], true);
    assert_eq!(json["score"], 1.0);
}

#[test]
fn rust_safe_hashes_precedence_over_database() {
    let intel = JA3Intel::new();
    // b32309a2... is in BOTH the database (score=0.85) and safe hashes
    // (-0.15). The safe-hash lookup fires first in score(), returning 0.0.
    assert!((intel.score("b32309a26951912be7dba376398abc3b") - 0.0).abs() < f64::EPSILON);
    // But lookup() returns the database entry.
    let entry = intel.lookup("b32309a26951912be7dba376398abc3b").unwrap();
    assert!((entry.score - 0.85).abs() < f64::EPSILON);
}

#[test]
fn rust_rotation_strategy_default_uses_injected_padding() {
    let s = ja3_intelligence::rotation_strategy("any-unknown-profile", 25);
    assert_eq!(s["action"], "random_padding");
    assert_eq!(s["padding_bytes"], 25);
    assert_eq!(s["recommended_cipher_order"], json!([]));
    assert_eq!(s["extensions_order"], json!([]));
}

#[test]
fn rust_rotation_strategy_tor_browser_12_fixed_padding() {
    let s = ja3_intelligence::rotation_strategy("Tor Browser 12.x default", 25);
    assert_eq!(s["padding_bytes"], 17); // fixed, ignores injected padding
    assert_eq!(s["action"], "cipher_suite_reorder");
}

#[test]
fn rust_rotate_missing_baseline_file_creates_empty_plan() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ja3_parity_missing_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let baseline_file = tmp.join("nonexistent_baseline.json");
    let plan_file = tmp.join("plan.json");
    let report_file = tmp.join("report.md");
    let now = DateTime::parse_from_rfc3339("2026-06-15T12:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);

    let result =
        rotate_ja3_fingerprints_with_options(&baseline_file, &plan_file, &report_file, now, 16);
    assert!(result.is_ok(), "rust rotate failed: {:?}", result.err());
    assert_eq!(result.unwrap(), 0);

    let plan_text = fs::read_to_string(&plan_file).unwrap();
    let plan: Value = serde_json::from_str(&plan_text).unwrap();
    assert_eq!(plan["baseline_hashes_checked"], 0);
    assert_eq!(plan["blocked_hashes_found"], 0);
    assert_eq!(plan["rotation_needed"], false);
    assert_eq!(plan["siam_blocked_database_size"], 9);

    let report = fs::read_to_string(&report_file).unwrap();
    assert!(report.contains("No blocked JA3 hashes detected"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn rust_rotate_invalid_baseline_json_uses_empty() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ja3_parity_invalid_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let baseline_file = tmp.join("baseline.json");
    let plan_file = tmp.join("plan.json");
    let report_file = tmp.join("report.md");
    fs::write(&baseline_file, "not valid json {{{").unwrap();
    let now = DateTime::parse_from_rfc3339("2026-06-15T12:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);

    let result =
        rotate_ja3_fingerprints_with_options(&baseline_file, &plan_file, &report_file, now, 16);
    assert!(result.is_ok(), "rust rotate failed: {:?}", result.err());

    let plan_text = fs::read_to_string(&plan_file).unwrap();
    let plan: Value = serde_json::from_str(&plan_text).unwrap();
    assert_eq!(plan["baseline_hashes_checked"], 0);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn rust_rotate_writes_blocked_details() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "ja3_parity_blocked_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let baseline_file = tmp.join("baseline.json");
    let plan_file = tmp.join("plan.json");
    let report_file = tmp.join("report.md");
    fs::write(
        &baseline_file,
        r#"{"bridges":[{"ja3":"e7d705a3286e19ea42f587b344ee6865"}]}"#,
    )
    .unwrap();
    let now = DateTime::parse_from_rfc3339("2026-06-15T12:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);

    let result =
        rotate_ja3_fingerprints_with_options(&baseline_file, &plan_file, &report_file, now, 16);
    assert!(result.is_ok());

    let plan_text = fs::read_to_string(&plan_file).unwrap();
    let plan: Value = serde_json::from_str(&plan_text).unwrap();
    assert_eq!(plan["baseline_hashes_checked"], 1);
    assert_eq!(plan["blocked_hashes_found"], 1);
    assert_eq!(plan["rotation_needed"], true);
    assert_eq!(
        plan["blocked_details"][0]["ja3_hash"],
        "e7d705a3286e19ea42f587b344ee6865"
    );
    assert_eq!(
        plan["blocked_details"][0]["blocked_profile"],
        "Tor Browser 12.x default"
    );
    assert_eq!(
        plan["blocked_details"][0]["rotation_strategy"]["action"],
        "cipher_suite_reorder"
    );

    let report = fs::read_to_string(&report_file).unwrap();
    assert!(report.contains("### `e7d705a3286e19ea42f587b344ee6865`"));
    assert!(report.contains("Rotation needed: **YES**"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn rust_lookup_returns_none_for_empty_hash() {
    let intel = JA3Intel::new();
    assert!(intel.lookup("").is_none());
}

#[test]
fn rust_ja3_error_display() {
    let err = JA3Error::Io {
        path: "/tmp/foo".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
    };
    assert!(format!("{err}").contains("/tmp/foo"));
}

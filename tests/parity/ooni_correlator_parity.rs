// Parity tests for `src/ooni_correlator.rs` vs `ooni_correlator.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `ooni_correlator` and calls the matching function on the same input. The
// Rust port is invoked on the identical input and the JSON outputs are
// compared for equality (parsed [`Value`] comparison so object key ordering
// is irrelevant; markdown output is compared byte-for-byte after stripping
// the timestamp).
//
// Coverage:
// * `ooni_factor` over empty, all-clean, any-anomaly, any-confirmed, mixed
//   branches.
// * `ripe_factor` over not-tested/tested × reachable/unreachable/null
//   branches.
// * `compute_composite` over all 18 (tcp × ooni × ripe) combinations.
// * `build_daily_history` over multi-host, multi-day, duplicate-day, and
//   empty-`test_start_time` branches.
// * `load_iran_results` over missing-file and valid-file branches.
// * `load_scheduler_results` over missing, empty-results, non-list-results,
//   and valid-entries branches.
// * `write_latest_results` over empty and populated records with a fixed
//   `now` (compares parsed JSON minus `generated_at`).
// * `write_markdown_report` over empty and populated records with a fixed
//   `now` (compares raw markdown text byte-for-byte).
// * `correlate` end-to-end with mocked `_ooni_query` and a temp
//   `QuarantineManager` (compares enriched records as parsed JSON).
// * `run_pipeline` quality-gate decision (pass/fail boundary cases).
// * Rust-only edge cases for `ooni_query` HTTP error / non-200 / invalid
//   JSON branches and `fetch_iran_measurements` with a mock HTTP client.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::TimeZone;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{json, Value};

use torshield_ir_ultra::ooni_correlator::{
    self, build_daily_history, compute_composite, correlate, correlate_enriched,
    fetch_iran_measurements, load_iran_results, load_scheduler_results, ooni_factor, ooni_query,
    ripe_factor, run_pipeline, write_latest_results, write_markdown_report, OoniError,
    OoniHttpFetch, OoniHttpResponse, PASS_THRESHOLD,
};
use torshield_ir_ultra::quarantine_manager::QuarantineManager;

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    // Prefer a venv python that has `requests` installed (needed by
    // ooni_correlator.py's `import requests`); fall back to the system
    // interpreter.
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

/// Dispatch a single JSON command to the Python `ooni_correlator` module and
/// return the parsed JSON output. Supported operations:
/// * `ooni_factor` — `{measurements: [...]}` → float
/// * `ripe_factor` — `{ripe_reachable, ripe_tested}` → float
/// * `compute_composite` — `{tcp_reachable, ooni_measurements, ripe_reachable, ripe_tested}` → float
/// * `build_daily_history` — `{ooni_by_ip: {host: [measurements]}}` → `{host: [[date_str, bool]]}`
/// * `load_iran_results` — `{path}` → dict (writes warning to stderr if missing)
/// * `load_scheduler_results` — `{path}` → dict
/// * `write_latest_results` — `{records, path, now_iso}` → `{content: <string>}`
/// * `write_markdown_report` — `{records, path, now_iso}` → `{content: <string>}`
/// * `correlate` — `{iran_data, sched_data, ooni_torsf, ooni_tor, now_iso, days,
///   quarantine_state_path, quarantine_log_path}` → enriched records list
fn python_ooni(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("ooni parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os, pathlib
import ooni_correlator as oc
import quarantine_manager as qm

cmd = json.loads(sys.argv[1])
op = cmd['op']

# Patch datetime inside ooni_correlator (and quarantine_manager) to a fixed
# `now` so date math, isoformat(), and strftime() are deterministic.
if 'now_iso' in cmd:
    from datetime import datetime, timezone
    fixed_now = datetime.fromisoformat(cmd['now_iso'])
    class _PatchedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is None else fixed_now.astimezone(tz)
    oc.datetime = _PatchedDatetime
    qm.datetime = _PatchedDatetime

if op == 'ooni_factor':
    print(json.dumps(oc._ooni_factor(cmd['measurements']), sort_keys=True, separators=(',', ':')))
elif op == 'ripe_factor':
    rr = cmd['ripe_reachable']
    rt = cmd['ripe_tested']
    print(json.dumps(oc._ripe_factor(rr, rt), sort_keys=True, separators=(',', ':')))
elif op == 'compute_composite':
    tcp = cmd['tcp_reachable']
    ooni = cmd['ooni_measurements']
    rr = cmd['ripe_reachable']
    rt = cmd['ripe_tested']
    print(json.dumps(oc.compute_composite(tcp, ooni, rr, rt), sort_keys=True, separators=(',', ':')))
elif op == 'build_daily_history':
    # Convert dict-of-lists to dict-of-lists (already in that shape).
    out = oc._build_daily_history(cmd['ooni_by_ip'])
    # Convert tuples to lists for JSON.
    out_serializable = {k: [[d, v] for d, v in v_list] for k, v_list in out.items()}
    print(json.dumps(out_serializable, sort_keys=True, separators=(',', ':')))
elif op == 'load_iran_results':
    oc.IRAN_RESULTS_PATH = pathlib.Path(cmd['path'])
    print(json.dumps(oc._load_iran_results(), sort_keys=True, separators=(',', ':')))
elif op == 'load_scheduler_results':
    oc.SCHEDULER_RESULTS_PATH = pathlib.Path(cmd['path'])
    print(json.dumps(oc._load_scheduler_results(), sort_keys=True, separators=(',', ':')))
elif op == 'write_latest_results':
    oc.LATEST_RESULTS_PATH = pathlib.Path(cmd['path'])
    oc.write_latest_results(cmd['records'])
    with open(cmd['path'], 'r', encoding='utf-8') as fh:
        content = fh.read()
    print(json.dumps({'content': content}, sort_keys=True, separators=(',', ':')))
elif op == 'write_markdown_report':
    oc.REPORT_PATH = pathlib.Path(cmd['path'])
    oc.write_markdown_report(cmd['records'])
    with open(cmd['path'], 'r', encoding='utf-8') as fh:
        content = fh.read()
    print(json.dumps({'content': content}, sort_keys=True, separators=(',', ':')))
elif op == 'correlate':
    # Write iran_data and sched_data to temp files.
    iran_path = pathlib.Path(cmd['iran_path'])
    sched_path = pathlib.Path(cmd['sched_path'])
    iran_path.write_text(json.dumps(cmd['iran_data']))
    sched_path.write_text(json.dumps(cmd['sched_data']))
    oc.IRAN_RESULTS_PATH = iran_path
    oc.SCHEDULER_RESULTS_PATH = sched_path
    # Mock _ooni_query to return the canned torsf/tor results.
    torsf_results = cmd.get('ooni_torsf', [])
    tor_results = cmd.get('ooni_tor', [])
    def mock_query(test_name, since, until, limit=100):
        if test_name == 'torsf':
            return torsf_results
        elif test_name == 'tor':
            return tor_results
        return []
    oc._ooni_query = mock_query
    # Override quarantine_manager paths.
    qm.QUARANTINE_STATE_PATH = pathlib.Path(cmd['quarantine_state_path'])
    qm.QUARANTINE_LOG_PATH = pathlib.Path(cmd['quarantine_log_path'])
    for p in [qm.QUARANTINE_STATE_PATH, qm.QUARANTINE_LOG_PATH]:
        if p.exists():
            p.unlink()
    records = oc.correlate()
    print(json.dumps(records, sort_keys=True, separators=(',', ':')))
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
        .unwrap_or_else(|err| panic!("python ooni helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python ooni helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python ooni helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Temp directory helper
// ─────────────────────────────────────────────────────────────────────────────

/// Create a unique temp directory for a test case. The directory name
/// includes the test name, process id, and a monotonic counter to avoid
/// collisions between parallel test executions.
fn case_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "torshield_ooni_correlator_parity_{}_{}_{}",
        name,
        std::process::id(),
        n,
    ));
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
    }
    fs::create_dir_all(&dir).expect("create parity tempdir");
    dir
}

/// Fixed `now` for deterministic timestamp parity. Uses a non-zero
/// microsecond to exercise the `%.6f` formatter branch in [`ooni_correlator`].
fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 28, 7, 55, 0).unwrap() + ChronoDuration::microseconds(123456)
}

/// Fixed `now` with zero microseconds to exercise the no-microsecond branch
/// in [`ooni_correlator::isoformat`].
fn fixed_now_zero_us() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 28, 7, 55, 0).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock HTTP client
// ─────────────────────────────────────────────────────────────────────────────

/// Mock [`OoniHttpFetch`] implementation that returns canned responses based
/// on the `test_name` query parameter. Tests construct this with the exact
/// JSON bodies the production fetcher would receive from the OONI API.
#[derive(Default, Clone)]
struct MockOoniHttp {
    /// Map from `test_name` query parameter value to canned JSON body.
    responses: BTreeMap<String, String>,
    /// Optional override for the HTTP status code (defaults to 200).
    status: u16,
    /// If set, return this error instead of a response.
    error: Option<String>,
}

impl MockOoniHttp {
    fn with_torsf(body: &str) -> Self {
        let mut m = Self::default();
        m.status = 200;
        m.responses.insert("torsf".to_string(), body.to_string());
        m
    }

    fn with_torsf_and_tor(torsf: &str, tor: &str) -> Self {
        let mut m = Self::default();
        m.status = 200;
        m.responses.insert("torsf".to_string(), torsf.to_string());
        m.responses.insert("tor".to_string(), tor.to_string());
        m
    }

    fn with_status(status: u16) -> Self {
        Self {
            status,
            ..Default::default()
        }
    }

    fn with_error(message: &str) -> Self {
        Self {
            error: Some(message.to_string()),
            ..Default::default()
        }
    }
}

impl OoniHttpFetch for MockOoniHttp {
    fn get(&self, url: &str, params: &[(&str, String)]) -> Result<OoniHttpResponse, OoniError> {
        if let Some(msg) = &self.error {
            return Err(OoniError::Http {
                url: url.to_string(),
                message: msg.clone(),
            });
        }
        // Find the test_name query parameter.
        let test_name = params
            .iter()
            .find(|(k, _)| *k == "test_name")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let body = self
            .responses
            .get(&test_name)
            .cloned()
            .unwrap_or_else(|| json!({"results": []}).to_string());
        Ok(OoniHttpResponse {
            status: self.status,
            body,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Python parity (>=4 scenarios invoking Python)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_ooni_factor_branches() {
    let cases: Vec<(Vec<Value>, f64)> = vec![
        (vec![], 0.5),
        (vec![json!({"anomaly": false, "confirmed": false})], 1.0),
        (vec![json!({})], 1.0), // missing keys → falsy
        (vec![json!({"anomaly": null, "confirmed": null})], 1.0),
        (vec![json!({"anomaly": true})], 0.0),
        (vec![json!({"confirmed": true})], 0.0),
        (
            vec![json!({"anomaly": false}), json!({"anomaly": true})],
            0.0,
        ),
        (
            vec![
                json!({"anomaly": 1}), // truthy non-bool
                json!({"anomaly": false}),
            ],
            0.0,
        ),
        (vec![json!({"anomaly": ""})], 1.0), // empty string is falsy
    ];
    for (measurements, expected) in cases {
        let cmd = json!({"op": "ooni_factor", "measurements": measurements});
        let py = python_ooni(&cmd);
        let rs = json!(ooni_factor(&measurements));
        assert_eq!(rs, py, "ooni_factor mismatch for {:?}", measurements);
        assert_eq!(rs.as_f64().unwrap(), expected);
    }
}

#[test]
fn parity_ripe_factor_branches() {
    let cases: Vec<(Option<bool>, bool, f64)> = vec![
        (Some(true), false, 0.5),
        (Some(false), false, 0.5),
        (None, false, 0.5),
        (Some(true), true, 1.0),
        (Some(false), true, 0.0),
        (None, true, 0.0),
    ];
    for (ripe_reachable, ripe_tested, expected) in cases {
        let rr_json = match ripe_reachable {
            Some(true) => json!(true),
            Some(false) => json!(false),
            None => json!(null),
        };
        let cmd = json!({
            "op": "ripe_factor",
            "ripe_reachable": rr_json,
            "ripe_tested": ripe_tested,
        });
        let py = python_ooni(&cmd);
        let rs = json!(ripe_factor(ripe_reachable, ripe_tested));
        assert_eq!(
            rs,
            py,
            "ripe_factor mismatch for {:?}",
            (ripe_reachable, ripe_tested)
        );
        assert_eq!(rs.as_f64().unwrap(), expected);
    }
}

#[test]
fn parity_compute_composite_all_combinations() {
    // All 18 (tcp × ooni × ripe) combinations.
    let tcp_vals = [false, true];
    let ooni_measurements_options: Vec<Vec<Value>> = vec![
        vec![],                                              // ooni_factor 0.5
        vec![json!({"anomaly": false, "confirmed": false})], // ooni_factor 1.0
        vec![json!({"anomaly": true})],                      // ooni_factor 0.0
    ];
    let ripe_options: Vec<(Option<bool>, bool)> = vec![
        (None, false),       // ripe_factor 0.5
        (Some(true), true),  // ripe_factor 1.0
        (Some(false), true), // ripe_factor 0.0
    ];
    for &tcp in &tcp_vals {
        for ooni_meas in &ooni_measurements_options {
            for (ripe_reachable, ripe_tested) in &ripe_options {
                let rr_json = match ripe_reachable {
                    Some(true) => json!(true),
                    Some(false) => json!(false),
                    None => json!(null),
                };
                let cmd = json!({
                    "op": "compute_composite",
                    "tcp_reachable": tcp,
                    "ooni_measurements": ooni_meas,
                    "ripe_reachable": rr_json,
                    "ripe_tested": ripe_tested,
                });
                let py = python_ooni(&cmd);
                let rs = json!(compute_composite(
                    tcp,
                    ooni_meas,
                    *ripe_reachable,
                    *ripe_tested
                ));
                assert_eq!(
                    rs,
                    py,
                    "compute_composite mismatch for {:?}",
                    (tcp, ooni_meas, ripe_reachable, ripe_tested)
                );
            }
        }
    }
}

#[test]
fn parity_build_daily_history_branches() {
    let ooni_by_ip = json!({
        "1.2.3.4": [
            {"input": "1.2.3.4", "test_start_time": "2026-06-02T10:00:00Z", "anomaly": false, "confirmed": false},
            {"input": "1.2.3.4", "test_start_time": "2026-06-01T10:00:00Z", "anomaly": true, "confirmed": false},
            {"input": "1.2.3.4", "test_start_time": "2026-06-01T11:00:00Z", "anomaly": false, "confirmed": false},
            {"input": "1.2.3.4", "test_start_time": "", "anomaly": true},
            {"input": "1.2.3.4"}, // missing test_start_time → skip
            {"input": "1.2.3.4", "test_start_time": null, "anomaly": true}
        ],
        "5.6.7.8": [
            {"test_start_time": "2026-06-03T10:00:00Z", "confirmed": true}
        ],
        "9.10.11.12": []
    });
    let cmd = json!({"op": "build_daily_history", "ooni_by_ip": ooni_by_ip.clone()});
    let py = python_ooni(&cmd);

    // Convert Rust output to the same JSON shape as Python output.
    let rust_input: Vec<(String, Vec<Value>)> = ooni_by_ip
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_array().unwrap().clone()))
        .collect();
    let rust_out = build_daily_history(&rust_input);
    let rust_serializable: BTreeMap<String, Vec<Vec<Value>>> = rust_out
        .into_iter()
        .map(|(k, v_list)| {
            let pairs: Vec<Vec<Value>> = v_list
                .into_iter()
                .map(|(d, b)| vec![json!(d), json!(b)])
                .collect();
            (k, pairs)
        })
        .collect();
    let rs = json!(rust_serializable);
    assert_eq!(rs, py, "build_daily_history mismatch");
}

#[test]
fn parity_load_iran_results_missing_and_valid() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let dir = case_dir("load_iran_results");
    let missing_path = dir.join("missing_iran.json");
    let valid_path = dir.join("valid_iran.json");
    let valid_data = json!({
        "bridges": [{"host": "1.2.3.4", "line": "a:1", "port": 1, "tcp_reachable": true}],
        "summary": {"total_tested": 1}
    });
    fs::write(
        &valid_path,
        serde_json::to_string_pretty(&valid_data).unwrap(),
    )
    .unwrap();

    // Missing file → fallback {"bridges": [], "summary": {}}.
    let cmd = json!({"op": "load_iran_results", "path": missing_path.to_string_lossy()});
    let py = python_ooni(&cmd);
    let rs = json!(load_iran_results(&missing_path));
    assert_eq!(rs, py, "missing-file load_iran_results mismatch");
    assert_eq!(rs, json!({"bridges": [], "summary": {}}));

    // Valid file → returned as-is.
    let cmd = json!({"op": "load_iran_results", "path": valid_path.to_string_lossy()});
    let py = python_ooni(&cmd);
    let rs = json!(load_iran_results(&valid_path));
    assert_eq!(rs, py, "valid-file load_iran_results mismatch");
    assert_eq!(rs, valid_data);
}

#[test]
fn parity_load_scheduler_results_branches() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let dir = case_dir("load_scheduler_results");
    let cases: Vec<(String, Value)> = vec![
        ("missing".to_string(), json!({})),
        ("empty_results".to_string(), json!({"results": []})),
        ("no_results_field".to_string(), json!({"foo": 1})),
        ("results_is_dict".to_string(), json!({"results": {"a": 1}})),
        (
            "valid_entries".to_string(),
            json!({
                "results": [
                    {"bridge_line": "a:1", "ripe_tested": true, "ripe_reachable": true},
                    {"bridge_line": "", "ripe_tested": false},
                    {"bridge_line": null, "ripe_tested": false},
                    "not a dict",
                    {"ripe_tested": false}
                ]
            }),
        ),
    ];

    let mut expected_valid: BTreeMap<String, Value> = BTreeMap::new();
    expected_valid.insert(
        "a:1".to_string(),
        json!({"bridge_line": "a:1", "ripe_tested": true, "ripe_reachable": true}),
    );

    for (name, data) in &cases {
        let path = dir.join(format!("{}.json", name));
        if name == "missing" {
            // Don't write the file.
        } else {
            fs::write(&path, serde_json::to_string(data).unwrap()).unwrap();
        }
        let cmd = json!({"op": "load_scheduler_results", "path": path.to_string_lossy()});
        let py = python_ooni(&cmd);
        let rs_map = load_scheduler_results(&path);
        let rs: Value = json!(rs_map);
        assert_eq!(rs, py, "load_scheduler_results mismatch for case {}", name);

        if name == "valid_entries" {
            assert_eq!(rs_map, expected_valid);
        } else {
            assert!(rs_map.is_empty(), "expected empty map for case {}", name);
        }
    }
}

#[test]
fn parity_write_latest_results_empty_and_populated() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let dir = case_dir("write_latest_results");
    let now_iso = "2026-06-28T07:55:00.123456+00:00".to_string();
    let now = fixed_now();

    // Empty records.
    let py_path = dir.join("py_empty.json");
    let cmd = json!({
        "op": "write_latest_results",
        "records": [],
        "path": py_path.to_string_lossy(),
        "now_iso": now_iso,
    });
    let py = python_ooni(&cmd);
    let py_content = py["content"].as_str().unwrap();
    let py_parsed: Value = serde_json::from_str(py_content).unwrap();
    let py_parsed = strip_generated_at(py_parsed);

    let rs_path = dir.join("rs_empty.json");
    write_latest_results(&[], &rs_path, now).unwrap();
    let rs_content = fs::read_to_string(&rs_path).unwrap();
    let rs_parsed: Value = serde_json::from_str(&rs_content).unwrap();
    let rs_parsed = strip_generated_at(rs_parsed);

    assert_eq!(rs_parsed, py_parsed, "empty write_latest_results mismatch");
    assert_eq!(
        rs_parsed,
        json!({
            "schema": "1.0",
            "total_bridges": 0,
            "above_0_5": 0,
            "pass_rate": 0.0,
            "bridges": []
        })
    );

    // Populated records.
    let records = vec![
        json!({"composite_score": 0.6, "host": "a", "port": 1}),
        json!({"composite_score": 0.4, "host": "b", "port": 2}),
        json!({"composite_score": 1.0, "host": "c", "port": 3}),
    ];
    let py_path = dir.join("py_full.json");
    let cmd = json!({
        "op": "write_latest_results",
        "records": records,
        "path": py_path.to_string_lossy(),
        "now_iso": now_iso,
    });
    let py = python_ooni(&cmd);
    let py_parsed: Value = serde_json::from_str(py["content"].as_str().unwrap()).unwrap();
    let py_parsed = strip_generated_at(py_parsed);

    let rs_path = dir.join("rs_full.json");
    write_latest_results(&records, &rs_path, now).unwrap();
    let rs_parsed: Value = serde_json::from_str(&fs::read_to_string(&rs_path).unwrap()).unwrap();
    let rs_parsed = strip_generated_at(rs_parsed);

    assert_eq!(
        rs_parsed, py_parsed,
        "populated write_latest_results mismatch"
    );
    assert_eq!(rs_parsed["above_0_5"], json!(2));
    assert_eq!(rs_parsed["pass_rate"], json!(0.6667));
}

#[test]
fn parity_write_markdown_report_empty_and_populated() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let dir = case_dir("write_markdown_report");
    let now_iso = "2026-06-28T07:55:00.123456+00:00".to_string();
    let now = fixed_now();

    // Empty records — should produce FAIL 🚨 (pass_rate 0.0 < threshold).
    let py_path = dir.join("py_empty.md");
    let cmd = json!({
        "op": "write_markdown_report",
        "records": [],
        "path": py_path.to_string_lossy(),
        "now_iso": now_iso,
    });
    let py = python_ooni(&cmd);
    let py_content = py["content"].as_str().unwrap().to_string();

    let rs_path = dir.join("rs_empty.md");
    write_markdown_report(&[], &rs_path, now).unwrap();
    let rs_content = fs::read_to_string(&rs_path).unwrap();

    assert_eq!(
        rs_content, py_content,
        "empty write_markdown_report mismatch (byte-for-byte)"
    );

    // Populated records — mix of scores above and below 0.5.
    let records = vec![
        json!({
            "composite_score": 0.6,
            "host": "a.example.com",
            "port": 443,
            "transport": "snowflake",
            "ooni_factor": 1.0,
            "tcp_reachable": true
        }),
        json!({
            "composite_score": 0.4,
            "host": "b.example.com",
            "port": 443,
            "transport": "obfs4",
            "ooni_factor": 0.0,
            "tcp_reachable": false
        }),
        json!({
            "composite_score": 1.0,
            "host": "c.example.com",
            "port": 443,
            "transport": "webtunnel",
            "ooni_factor": 0.5,
            "tcp_reachable": true
        }),
    ];
    let py_path = dir.join("py_full.md");
    let cmd = json!({
        "op": "write_markdown_report",
        "records": records.clone(),
        "path": py_path.to_string_lossy(),
        "now_iso": now_iso,
    });
    let py = python_ooni(&cmd);
    let py_content = py["content"].as_str().unwrap().to_string();

    let rs_path = dir.join("rs_full.md");
    write_markdown_report(&records, &rs_path, now).unwrap();
    let rs_content = fs::read_to_string(&rs_path).unwrap();

    assert_eq!(
        rs_content, py_content,
        "populated write_markdown_report mismatch (byte-for-byte)"
    );
}

#[test]
fn parity_correlate_end_to_end_with_mocked_ooni() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let dir = case_dir("correlate");
    let now_iso = "2026-06-28T07:55:00.000000+00:00".to_string();
    let now = fixed_now_zero_us();

    let iran_data = json!({
        "bridges": [
            {"host": "1.2.3.4", "line": "a:1", "port": 1, "transport": "obfs4", "tcp_reachable": true, "existing_field": "hello"},
            {"host": "5.6.7.8", "line": "b:2", "port": 2, "transport": "snowflake", "tcp_reachable": false, "composite_score": 0.99},
            {"host": "", "line": "c:3", "port": 3, "transport": "vanilla", "tcp_reachable": true},
            {"host": "9.10.11.12", "line": "d:4", "port": 4, "transport": "webtunnel", "tcp_reachable": true}
        ]
    });
    let sched_data = json!({
        "results": [
            {"bridge_line": "a:1", "ripe_tested": true, "ripe_reachable": true},
            {"bridge_line": "b:2", "ripe_tested": false, "ripe_reachable": true},
            {"bridge_line": "d:4", "ripe_tested": true, "ripe_reachable": false}
        ]
    });
    let ooni_torsf = json!([
        {"input": "1.2.3.4", "test_start_time": "2026-06-01T10:00:00Z", "anomaly": false, "confirmed": false},
        {"input": "1.2.3.4", "test_start_time": "2026-06-02T10:00:00Z", "anomaly": true, "confirmed": false},
        {"input": "", "test_start_time": "2026-06-03T10:00:00Z", "anomaly": false}
    ]);
    let ooni_tor = json!([
        {"input": "9.10.11.12", "test_start_time": "2026-06-04T10:00:00Z", "confirmed": true},
        {"input": "1.2.3.4", "test_start_time": "2026-06-05T10:00:00Z", "anomaly": false}
    ]);

    // Python side.
    let py_iran_path = dir.join("py_iran.json");
    let py_sched_path = dir.join("py_sched.json");
    let py_qm_state = dir.join("py_qm_state.json");
    let py_qm_log = dir.join("py_qm_log.jsonl");
    let cmd = json!({
        "op": "correlate",
        "iran_path": py_iran_path.to_string_lossy(),
        "sched_path": py_sched_path.to_string_lossy(),
        "iran_data": iran_data,
        "sched_data": sched_data,
        "ooni_torsf": ooni_torsf,
        "ooni_tor": ooni_tor,
        "now_iso": now_iso,
        "days": 7,
        "quarantine_state_path": py_qm_state.to_string_lossy(),
        "quarantine_log_path": py_qm_log.to_string_lossy(),
    });
    let py_records = python_ooni(&cmd);

    // Rust side.
    let rs_iran_path = dir.join("rs_iran.json");
    let rs_sched_path = dir.join("rs_sched.json");
    let rs_qm_state = dir.join("rs_qm_state.json");
    let rs_qm_log = dir.join("rs_qm_log.jsonl");
    fs::write(&rs_iran_path, serde_json::to_string(&iran_data).unwrap()).unwrap();
    fs::write(&rs_sched_path, serde_json::to_string(&sched_data).unwrap()).unwrap();

    let torsf_body = json!({ "results": ooni_torsf }).to_string();
    let tor_body = json!({ "results": ooni_tor }).to_string();
    let client = MockOoniHttp::with_torsf_and_tor(&torsf_body, &tor_body);

    let mut qm = QuarantineManager::new(&rs_qm_state, &rs_qm_log).unwrap();
    let rs_records = correlate(
        &rs_iran_path,
        &rs_sched_path,
        &client,
        now,
        7,
        Some(&mut qm),
    )
    .unwrap();
    let rs = json!(rs_records);

    assert_eq!(rs, py_records, "correlate end-to-end mismatch");

    // Spot-check expected ordering and enrichment.
    assert_eq!(rs.as_array().unwrap().len(), 4);
    // Sorted by composite_score descending: c (0.675) > a (0.6) > d (0.35) > b (0.325).
    assert_eq!(rs[0]["host"], json!(""));
    assert_eq!(rs[0]["composite_score"], json!(0.675));
    assert_eq!(rs[1]["host"], json!("1.2.3.4"));
    assert_eq!(rs[1]["composite_score"], json!(0.6));
    assert_eq!(rs[1]["existing_field"], json!("hello"));
    assert_eq!(rs[1]["ooni_measurements_ir"], json!(3));
    assert_eq!(rs[1]["ooni_factor"], json!(0.0));
    assert_eq!(rs[1]["ripe_tested"], json!(true));
    assert_eq!(rs[1]["ripe_reachable"], json!(true));
    assert_eq!(rs[1]["quarantined"], json!(false));
    assert_eq!(rs[2]["host"], json!("9.10.11.12"));
    assert_eq!(rs[2]["composite_score"], json!(0.35));
    assert_eq!(rs[2]["ooni_factor"], json!(0.0));
    assert_eq!(rs[2]["ripe_reachable"], json!(false));
    assert_eq!(rs[3]["host"], json!("5.6.7.8"));
    assert_eq!(rs[3]["composite_score"], json!(0.325));
    // The original composite_score (0.99) is overridden by compute_composite.
    assert_eq!(rs[3]["ooni_factor"], json!(0.5));
    assert_eq!(rs[3]["ripe_tested"], json!(false));
    assert_eq!(rs[3]["ripe_reachable"], json!(null));
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — Rust-only edge cases (no Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_ooni_query_http_error_returns_empty() {
    let client = MockOoniHttp::with_error("connection refused");
    let results = ooni_query(&client, "torsf", "2026-06-21", "2026-06-28", 100);
    assert!(results.is_empty(), "HTTP error should yield empty list");
}

#[test]
fn rust_ooni_query_non_200_returns_empty() {
    let client = MockOoniHttp::with_status(500);
    let results = ooni_query(&client, "torsf", "2026-06-21", "2026-06-28", 100);
    assert!(results.is_empty(), "non-200 status should yield empty list");
}

#[test]
fn rust_ooni_query_invalid_json_returns_empty() {
    // Build a mock client that returns invalid JSON with status 200.
    let mut client = MockOoniHttp::default();
    client.status = 200;
    client
        .responses
        .insert("torsf".to_string(), "this is not valid JSON".to_string());
    let results = ooni_query(&client, "torsf", "2026-06-21", "2026-06-28", 100);
    assert!(results.is_empty(), "invalid JSON should yield empty list");
}

#[test]
fn rust_ooni_query_valid_response_returns_results() {
    let body = json!({
        "results": [
            {"input": "1.2.3.4", "anomaly": false},
            {"input": "5.6.7.8", "anomaly": true}
        ]
    })
    .to_string();
    let client = MockOoniHttp::with_torsf(&body);
    let results = ooni_query(&client, "torsf", "2026-06-21", "2026-06-28", 100);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["input"], json!("1.2.3.4"));
    assert_eq!(results[1]["input"], json!("5.6.7.8"));
}

#[test]
fn rust_fetch_iran_measurements_with_mock_client() {
    let torsf_body = json!({
        "results": [
            {"input": "1.2.3.4", "test_start_time": "2026-06-01T10:00:00Z", "anomaly": false},
            {"input": "", "test_start_time": "2026-06-02T10:00:00Z", "anomaly": true}
        ]
    })
    .to_string();
    let tor_body = json!({
        "results": [
            {"input": "1.2.3.4", "test_start_time": "2026-06-03T10:00:00Z", "anomaly": false},
            {"input": "5.6.7.8", "test_start_time": "2026-06-04T10:00:00Z", "confirmed": true}
        ]
    })
    .to_string();
    let client = MockOoniHttp::with_torsf_and_tor(&torsf_body, &tor_body);
    let now = fixed_now();
    let indexed = fetch_iran_measurements(&client, now, 7);

    // 3 distinct keys: "1.2.3.4", "global" (from input=""), "5.6.7.8".
    assert_eq!(indexed.len(), 3);
    let one_two_three_four = indexed.iter().find(|(k, _)| k == "1.2.3.4").unwrap();
    assert_eq!(one_two_three_four.1.len(), 2); // 1 torsf + 1 tor
    let global = indexed.iter().find(|(k, _)| k == "global").unwrap();
    assert_eq!(global.1.len(), 1);
    let five_six_seven_eight = indexed.iter().find(|(k, _)| k == "5.6.7.8").unwrap();
    assert_eq!(five_six_seven_eight.1.len(), 1);

    // since/until window: 7 days before 2026-06-28 = 2026-06-21 → 2026-06-28.
    // (Verified by the mock returning canned data; the actual since/until
    // strings are not asserted here because the mock ignores them.)
}

#[test]
fn rust_correlate_with_quarantine_manager_excludes_quarantined_bridges() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let dir = case_dir("rust_correlate_quarantine");
    let now = fixed_now_zero_us();

    // Set up iran_data with two bridges.
    let iran_data = json!({
        "bridges": [
            {"host": "1.2.3.4", "line": "a:1", "port": 1, "transport": "obfs4", "tcp_reachable": true},
            {"host": "5.6.7.8", "line": "b:2", "port": 2, "transport": "snowflake", "tcp_reachable": true}
        ]
    });
    let sched_data = json!({"results": []});
    let iran_path = dir.join("iran.json");
    let sched_path = dir.join("sched.json");
    fs::write(&iran_path, serde_json::to_string(&iran_data).unwrap()).unwrap();
    fs::write(&sched_path, serde_json::to_string(&sched_data).unwrap()).unwrap();

    // Pre-populate quarantine state with one of the bridges.
    let qm_state = dir.join("qm_state.json");
    let qm_log = dir.join("qm_log.jsonl");
    let initial_state = json!({
        "1.2.3.4": {
            "quarantined_at": "2026-06-20T00:00:00+00:00",
            "z_score": 3.0,
            "consecutive_clean": 0,
            "reason": "pre-existing"
        }
    });
    fs::write(
        &qm_state,
        serde_json::to_string_pretty(&initial_state).unwrap(),
    )
    .unwrap();

    // OONI mock returns no measurements, so the daily history is empty and
    // update_from_ooni_history won't release any quarantined bridges.
    let client = MockOoniHttp::with_torsf_and_tor(
        &json!({"results": []}).to_string(),
        &json!({"results": []}).to_string(),
    );

    let mut qm = QuarantineManager::new(&qm_state, &qm_log).unwrap();
    let records = correlate(&iran_path, &sched_path, &client, now, 7, Some(&mut qm)).unwrap();

    // 1.2.3.4 is quarantined → composite_score 0.0, no enrichment fields.
    let quarantined_rec = records
        .iter()
        .find(|r| r["host"] == json!("1.2.3.4"))
        .unwrap();
    assert_eq!(quarantined_rec["quarantined"], json!(true));
    assert_eq!(quarantined_rec["composite_score"], json!(0.0));
    assert!(quarantined_rec.get("ooni_factor").is_none());
    assert!(quarantined_rec.get("ripe_tested").is_none());

    // 5.6.7.8 is not quarantined → enriched normally.
    let clean_rec = records
        .iter()
        .find(|r| r["host"] == json!("5.6.7.8"))
        .unwrap();
    assert_eq!(clean_rec["quarantined"], json!(false));
    assert_eq!(clean_rec["ooni_factor"], json!(0.5));
    assert_eq!(clean_rec["composite_score"], json!(0.675));
    assert_eq!(clean_rec["ooni_measurements_ir"], json!(0));
}

#[test]
fn rust_run_pipeline_quality_gate_decision() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let dir = case_dir("rust_run_pipeline");
    let now = fixed_now_zero_us();

    // Set up iran_data with 10 bridges: 3 with score 0.6 (pass) and 7 with score 0.4 (fail).
    // pass_rate = 3/10 = 0.3 → exactly at threshold → PASS.
    let mut bridges = Vec::new();
    for i in 0..10 {
        let score = if i < 3 { 0.6 } else { 0.4 };
        bridges.push(json!({
            "host": format!("{}.{}.{}.{}", 10 + i, 0, 0, 1),
            "line": format!("bridge_{}", i),
            "port": 9001,
            "transport": "vanilla",
            "tcp_reachable": score > 0.5,
            "composite_score": score
        }));
    }
    let iran_data = json!({ "bridges": bridges });
    let sched_data = json!({"results": []});
    let iran_path = dir.join("iran.json");
    let sched_path = dir.join("sched.json");
    fs::write(&iran_path, serde_json::to_string(&iran_data).unwrap()).unwrap();
    fs::write(&sched_path, serde_json::to_string(&sched_data).unwrap()).unwrap();

    let latest_path = dir.join("latest.json");
    let report_path = dir.join("report.md");
    let qm_state = dir.join("qm_state.json");
    let qm_log = dir.join("qm_log.jsonl");

    let client = MockOoniHttp::with_torsf_and_tor(
        &json!({"results": []}).to_string(),
        &json!({"results": []}).to_string(),
    );

    let mut qm = QuarantineManager::new(&qm_state, &qm_log).unwrap();
    let outcome = run_pipeline(
        &iran_path,
        &sched_path,
        &latest_path,
        &report_path,
        &client,
        now,
        7,
        Some(&mut qm),
    )
    .unwrap();

    // The records get re-scored by compute_composite:
    // - tcp_reachable=true, no OONI, no RIPE → 0.35*1 + 0.40*0.5 + 0.25*0.5 = 0.675
    // - tcp_reachable=false, no OONI, no RIPE → 0.35*0 + 0.40*0.5 + 0.25*0.5 = 0.325
    // So 3 bridges score 0.675 (>0.5) and 7 score 0.325 (<0.5).
    // pass_rate = 3/10 = 0.3 → exactly at threshold → PASS.
    assert_eq!(outcome.total, 10);
    assert_eq!(outcome.above_threshold, 3);
    assert_eq!(outcome.pass_rate, 0.3);
    assert!(
        outcome.passed,
        "pass_rate 0.3 should pass (>= threshold 0.30)"
    );

    // Verify the latest.json and report.md were written.
    assert!(latest_path.exists(), "latest.json should be written");
    assert!(report_path.exists(), "report.md should be written");

    // Spot-check the markdown content for PASS ✅.
    let md = fs::read_to_string(&report_path).unwrap();
    assert!(md.contains("PASS ✅"), "markdown should contain PASS ✅");
    // The "Quality gate PASSED" message is emitted via Python's log.info,
    // NOT in the markdown report. Verify the markdown contains the quality
    // gate row instead.
    assert!(
        md.contains("Quality gate"),
        "markdown should contain Quality gate row"
    );
}

#[test]
fn rust_run_pipeline_empty_records_passes_with_empty_outputs() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let dir = case_dir("rust_run_pipeline_empty");
    let now = fixed_now_zero_us();

    // Empty iran_data.
    let iran_data = json!({"bridges": []});
    let sched_data = json!({"results": []});
    let iran_path = dir.join("iran.json");
    let sched_path = dir.join("sched.json");
    fs::write(&iran_path, serde_json::to_string(&iran_data).unwrap()).unwrap();
    fs::write(&sched_path, serde_json::to_string(&sched_data).unwrap()).unwrap();

    let latest_path = dir.join("latest.json");
    let report_path = dir.join("report.md");
    let qm_state = dir.join("qm_state.json");
    let qm_log = dir.join("qm_log.jsonl");

    let client = MockOoniHttp::with_torsf_and_tor(
        &json!({"results": []}).to_string(),
        &json!({"results": []}).to_string(),
    );

    let mut qm = QuarantineManager::new(&qm_state, &qm_log).unwrap();
    let outcome = run_pipeline(
        &iran_path,
        &sched_path,
        &latest_path,
        &report_path,
        &client,
        now,
        7,
        Some(&mut qm),
    )
    .unwrap();

    // Empty records → run_pipeline short-circuits with passed=true (mirrors
    // Python sys.exit(0) on the empty-records branch in main()).
    assert_eq!(outcome.total, 0);
    assert_eq!(outcome.above_threshold, 0);
    assert_eq!(outcome.pass_rate, 0.0);
    assert!(
        outcome.passed,
        "empty records should pass (mirror Python sys.exit(0))"
    );

    // Verify the latest.json contains 0 records and FAIL 🚨 in the report
    // (because pass_rate 0.0 < threshold, the markdown shows FAIL).
    let latest: Value = serde_json::from_str(&fs::read_to_string(&latest_path).unwrap()).unwrap();
    assert_eq!(latest["total_bridges"], json!(0));
    assert_eq!(latest["above_0_5"], json!(0));

    let md = fs::read_to_string(&report_path).unwrap();
    assert!(
        md.contains("FAIL 🚨"),
        "empty markdown should contain FAIL 🚨"
    );
    assert!(md.contains("| — | — | — | — | — |"));
}

#[test]
fn rust_correlate_enriched_quarantined_overrides_existing_composite_score() {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    // Verify that a quarantined bridge with a pre-existing composite_score
    // field has it overridden to 0.0 (matching Python's `bridge_rec["composite_score"] = 0.0`).
    let iran_data = json!({
        "bridges": [
            {"host": "1.2.3.4", "line": "a:1", "port": 1, "composite_score": 0.99}
        ]
    });
    let mut quarantined = std::collections::BTreeSet::new();
    quarantined.insert("1.2.3.4".to_string());
    let records = correlate_enriched(&iran_data, &BTreeMap::new(), &[], &quarantined);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["quarantined"], json!(true));
    assert_eq!(records[0]["composite_score"], json!(0.0));
    // The original 0.99 is overridden; no enrichment fields are added.
    assert!(records[0].get("ooni_factor").is_none());
}

#[test]
fn rust_correlate_enriched_ooni_lookup_falls_back_to_line() {
    // Verify the `ooni_by_ip.get(host, []) or ooni_by_ip.get(line, [])` fallback:
    // when the host key is missing or has an empty list, fall back to line key.
    let iran_data = json!({
        "bridges": [
            {
                "host": "1.2.3.4",
                "line": "obfs4 1.2.3.4:443 abc",
                "port": 443,
                "transport": "obfs4",
                "tcp_reachable": true
            }
        ]
    });
    // OONI index has the line key but not the host key.
    let ooni_by_ip: Vec<(String, Vec<Value>)> = vec![
        (
            "obfs4 1.2.3.4:443 abc".to_string(),
            vec![json!({"anomaly": false, "confirmed": false})],
        ),
        // Empty list for host "1.2.3.4" → should fall back to line.
        ("1.2.3.4".to_string(), vec![]),
    ];
    let records = correlate_enriched(
        &iran_data,
        &BTreeMap::new(),
        &ooni_by_ip,
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["ooni_measurements_ir"], json!(1));
    assert_eq!(records[0]["ooni_factor"], json!(1.0));
    // tcp + ooni-clean + not-tested-ripe = 0.35 + 0.40 + 0.125 = 0.875.
    assert_eq!(records[0]["composite_score"], json!(0.875));
}

#[test]
fn rust_constants_match_python_module_constants() {
    // Verify the Rust constants match the Python module-level constants
    // (probed via a one-shot Python call).
    let script = r#"
import json
import ooni_correlator as oc
out = {
    "OONI_BASE": oc.OONI_BASE,
    "OONI_TIMEOUT": oc.OONI_TIMEOUT,
    "OONI_RATE_SLEEP": oc.OONI_RATE_SLEEP,
    "PASS_THRESHOLD": oc.PASS_THRESHOLD
}
print(json.dumps(out, sort_keys=True, separators=(',', ':')))
"#;
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python constants probe must execute: {err}"));
    assert!(
        output.status.success(),
        "python constants probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let py: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python constants probe must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(py["OONI_BASE"], json!(ooni_correlator::OONI_BASE));
    assert_eq!(
        py["OONI_TIMEOUT"],
        json!(ooni_correlator::OONI_TIMEOUT_SECS)
    );
    assert_eq!(
        py["OONI_RATE_SLEEP"],
        json!(ooni_correlator::OONI_RATE_SLEEP_SECS)
    );
    assert_eq!(py["PASS_THRESHOLD"], json!(ooni_correlator::PASS_THRESHOLD));
    // Re-export the constant for the assertion above.
    let _: f64 = PASS_THRESHOLD;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Strip the `generated_at` field from a parsed JSON payload so two
/// `write_latest_results` outputs can be compared without the timestamp
/// differing (the timestamp is injected on both sides via fixed `now`).
fn strip_generated_at(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("generated_at");
    }
    value
}

// Re-export the constant for the `rust_constants_match_python_module_constants`
// test (avoids an unused-import warning).
#[allow(dead_code)]
fn _ensure_pass_threshold_used() -> f64 {
    PASS_THRESHOLD
}

#![allow(warnings)]
// Parity tests for `src/iran_anti_siam.rs` vs `iran_anti_siam.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `iran_anti_siam` (and `core.iran_dpi_shaper` for the mocked `score_all`)
// and returns the same JSON output the Rust port produces.
//
// Coverage:
// * `load_bridges_json` over array-of-strings, dict-with-bridges, missing,
//   malformed, and non-object-root inputs.
// * `load_bridges_txt` over multi-file dirs with comments, dedup, and
//   `iran_blocked*` skipping.
// * `load_ja3_map` over present, missing-key, missing-file, and malformed
//   inputs.
// * `load_bridges` over the test-json → iran-results → txt fallback chain.
// * `build_md_report` over empty, single-tier, and multi-transport inputs.
// * `run_pipeline` (mocked `score_all`) over empty bridges and a full
//   multi-tier bridge set, comparing every output file byte-for-byte.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};
use torshield_ir_ultra::iran_anti_siam::{
    build_md_report, load_bridges, load_bridges_json, load_bridges_txt, load_ja3_map, run_pipeline,
    SiamResult,
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

/// Dispatch a JSON command to the Python `iran_anti_siam` module and return
/// the parsed JSON output. Supported operations:
/// * `load_bridges_json` — call `_load_bridges_json(path)`.
/// * `load_bridges_txt` — call `_load_bridges_txt(dir)` (passed via argv).
/// * `load_ja3_map` — chdir into a temp dir, write `data/ja3_rotation_plan.json`,
///   call `_load_ja3_map()`.
/// * `load_bridges` — chdir into a temp dir containing `bridge/`, call
///   `load_bridges()`.
/// * `build_md_report` — build mock results and call `_build_md_report`.
/// * `main` — chdir into a temp dir, patch `core.iran_dpi_shaper.score_all`
///   to return the fixed results, call `main()`, and return every output
///   file's contents.
fn python_iran_anti_siam(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("iran_anti_siam parity cmd must serialize: {err}"));
    let script = r#"
import json, sys, os, shutil, tempfile, types
from dataclasses import dataclass, asdict

@dataclass
class MockResult:
    bridge_line: str
    transport: str
    port: int
    iran_siam_score: float
    bypass_tier: str
    layers_bypassed: int
    evasion_flags: list
    layer_scores: dict
    recommendation: str

    def to_dict(self):
        return asdict(self)


def make_result(d):
    return MockResult(**d)


cmd = json.loads(sys.argv[1])
op = cmd['op']

if op == 'load_bridges_json':
    import iran_anti_siam as m
    print(json.dumps({'lines': m._load_bridges_json(__import__('pathlib').Path(cmd['path']))}, sort_keys=True, separators=(',', ':')))

elif op == 'load_bridges_txt':
    import iran_anti_siam as m
    print(json.dumps({'lines': m._load_bridges_txt(__import__('pathlib').Path(cmd['dir']))}, sort_keys=True, separators=(',', ':')))

elif op == 'load_ja3_map':
    tmp = tempfile.mkdtemp()
    try:
        cwd = os.getcwd()
        os.chdir(tmp)
        import iran_anti_siam as m
        if cmd.get('content') is not None:
            os.makedirs('data', exist_ok=True)
            with open('data/ja3_rotation_plan.json', 'w') as f:
                f.write(cmd['content'])
        result = m._load_ja3_map()
        print(json.dumps({'ja3_map': result}, sort_keys=True, separators=(',', ':')))
        os.chdir(cwd)
    finally:
        shutil.rmtree(tmp)

elif op == 'load_bridges':
    tmp = tempfile.mkdtemp()
    try:
        cwd = os.getcwd()
        os.chdir(tmp)
        os.makedirs('bridge', exist_ok=True)
        for entry in cmd.get('files', []):
            full = os.path.join('bridge', entry['name'])
            os.makedirs(os.path.dirname(full) or '.', exist_ok=True)
            with open(full, 'w') as f:
                f.write(entry['content'])
        import iran_anti_siam as m
        lines = m.load_bridges()
        print(json.dumps({'lines': lines}, sort_keys=True, separators=(',', ':')))
        os.chdir(cwd)
    finally:
        shutil.rmtree(tmp)

elif op == 'build_md_report':
    import iran_anti_siam as m
    results = [make_result(d) for d in cmd['results']]
    tier_counts = {k: int(v) for k, v in cmd['tier_counts'].items()}
    transport_counts = {k: int(v) for k, v in cmd['transport_counts'].items()}
    ts = cmd['ts']
    md = m._build_md_report(results, tier_counts, transport_counts, ts)
    print(json.dumps({'md': md}, sort_keys=True, separators=(',', ':')))

elif op == 'main':
    tmp = tempfile.mkdtemp()
    try:
        cwd = os.getcwd()
        os.chdir(tmp)
        os.makedirs('bridge', exist_ok=True)
        for entry in cmd.get('bridge_files', []):
            full = os.path.join('bridge', entry['name'])
            os.makedirs(os.path.dirname(full) or '.', exist_ok=True)
            with open(full, 'w') as f:
                f.write(entry['content'])
        if cmd.get('ja3_content') is not None:
            os.makedirs('data', exist_ok=True)
            with open('data/ja3_rotation_plan.json', 'w') as f:
                f.write(cmd['ja3_content'])
        # Patch core.iran_dpi_shaper.score_all before main() imports it.
        import core.iran_dpi_shaper
        fixed_results = [make_result(d) for d in cmd['results']]
        core.iran_dpi_shaper.score_all = lambda lines, ja3_map=None: list(fixed_results)
        import iran_anti_siam as m
        # Patch datetime so generated_at is deterministic and matches the
        # Rust port's `now` parameter. The `main()` body uses
        # `datetime.now(tz=UTC)` and `datetime.now(UTC)`.
        from datetime import datetime as real_datetime
        fixed_dt = real_datetime.fromisoformat(cmd['now'])
        class FakeDatetime(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_dt
        m.datetime = FakeDatetime
        # Avoid log output polluting stdout.
        import logging
        logging.disable(logging.CRITICAL)
        m.main()
        out = {}
        for path in ['data/iran_siam_report.json',
                     'export/iran_phantom_bridges.txt',
                     'export/iran_stealth_bridges.txt',
                     'export/iran_siam_best_bridges.txt',
                     'docs/iran-siam-analysis.md']:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    out[path] = f.read()
        print(json.dumps({'outputs': out}, sort_keys=True, separators=(',', ':')))
        os.chdir(cwd)
    finally:
        shutil.rmtree(tmp)

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
        .unwrap_or_else(|err| panic!("python iran_anti_siam helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python iran_anti_siam helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python iran_anti_siam helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Test scaffolding
// ─────────────────────────────────────────────────────────────────────────────

fn case_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield_iran_anti_siam_parity_{}_{}",
        name,
        std::process::id()
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean stale parity tempdir");
    }
    fs::create_dir_all(&dir).expect("create parity tempdir");
    dir
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    fs::write(path, content).expect("write file");
}

fn parse_utc(iso: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(iso)
        .unwrap_or_else(|err| panic!("test fixture iso must parse: {err}"))
        .with_timezone::<Utc>(&Utc)
}

const NOW_ISO: &str = "2026-06-25T12:00:00.123456+00:00";

// ─────────────────────────────────────────────────────────────────────────────
// load_bridges_json parity (Python subprocess on every case)
// ─────────────────────────────────────────────────────────────────────────────

fn assert_load_bridges_json_parity(name: &str, content: Option<&str>) {
    let py_dir = case_dir(&format!("lbj_{name}_py"));
    let rust_dir = case_dir(&format!("lbj_{name}_rust"));
    let target = "input.json";
    if let Some(c) = content {
        write_file(&py_dir.join(target), c);
        write_file(&rust_dir.join(target), c);
    }
    let py_path = py_dir.join(target);
    let rust_path = rust_dir.join(target);

    let py = python_iran_anti_siam(&json!({"op": "load_bridges_json", "path": py_path}));
    let rs = load_bridges_json(&rust_path);
    assert_eq!(
        py["lines"],
        json!(rs),
        "load_bridges_json parity failed for {name}"
    );

    let _ = fs::remove_dir_all(&py_dir);
    let _ = fs::remove_dir_all(&rust_dir);
}

#[test]
fn parity_load_bridges_json_array_of_strings() {
    assert_load_bridges_json_parity(
        "array",
        Some(r#"["bridge1", "bridge2", "", null, "bridge3"]"#),
    );
}

#[test]
fn parity_load_bridges_json_dict_with_bridges() {
    assert_load_bridges_json_parity(
        "dict",
        Some(r#"{"bridges":[{"line":"b1"},{"line":"b2"},{"other":"no line"},{"line":""}]}"#),
    );
}

#[test]
fn parity_load_bridges_json_missing_file_returns_empty() {
    assert_load_bridges_json_parity("missing", None);
}

#[test]
fn parity_load_bridges_json_malformed_returns_empty() {
    assert_load_bridges_json_parity("malformed", Some("{not valid json"));
}

#[test]
fn parity_load_bridges_json_non_object_root_returns_empty() {
    assert_load_bridges_json_parity("non_object", Some("42"));
}

// ─────────────────────────────────────────────────────────────────────────────
// load_bridges_txt parity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_load_bridges_txt_skips_blocked_comments_and_dedupes() {
    let py_dir = case_dir("lbtxt_py");
    let rust_dir = case_dir("lbtxt_rust");
    for dir in [&py_dir, &rust_dir] {
        write_file(
            &dir.join("a.txt"),
            "# comment\nbridge1\n\nbridge2\n  bridge3  \n# another\nbridge1\n",
        );
        write_file(&dir.join("iran_blocked.txt"), "should be skipped\n");
        write_file(&dir.join("b.txt"), "bridge4\n");
    }
    let py = python_iran_anti_siam(&json!({"op": "load_bridges_txt", "dir": py_dir}));
    let rs = load_bridges_txt(&rust_dir);
    // Order may differ between Python's pathlib.glob and Rust's read_dir;
    // compare as sorted sets to make the test filesystem-order-independent.
    let mut py_sorted: Vec<String> = py["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    py_sorted.sort();
    let mut rs_sorted = rs.clone();
    rs_sorted.sort();
    assert_eq!(
        py_sorted, rs_sorted,
        "load_bridges_txt parity failed (set comparison)"
    );

    let _ = fs::remove_dir_all(&py_dir);
    let _ = fs::remove_dir_all(&rust_dir);
}

#[test]
fn parity_load_bridges_txt_empty_dir_returns_empty() {
    let py_dir = case_dir("lbtxt_empty_py");
    let rust_dir = case_dir("lbtxt_empty_rust");
    let py = python_iran_anti_siam(&json!({"op": "load_bridges_txt", "dir": py_dir}));
    let rs = load_bridges_txt(&rust_dir);
    assert_eq!(py["lines"], json!([]));
    assert!(rs.is_empty());
    let _ = fs::remove_dir_all(&py_dir);
    let _ = fs::remove_dir_all(&rust_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// load_ja3_map parity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_load_ja3_map_present() {
    let content = r#"{"bridge_ja3_map":{"b1":"hash1","b2":"hash2"}}"#;
    let py = python_iran_anti_siam(&json!({"op": "load_ja3_map", "content": content}));
    let rust_dir = case_dir("ja3_present_rust");
    let rust_path = rust_dir.join("ja3_rotation_plan.json");
    write_file(&rust_path, content);
    let rs = load_ja3_map(&rust_path);
    assert_eq!(py["ja3_map"], rs, "load_ja3_map parity failed for present");
    let _ = fs::remove_dir_all(&rust_dir);
}

#[test]
fn parity_load_ja3_map_missing_file_returns_empty() {
    let py = python_iran_anti_siam(&json!({"op": "load_ja3_map", "content": null}));
    let rust_dir = case_dir("ja3_missing_rust");
    let rust_path = rust_dir.join("ja3_rotation_plan.json");
    let rs = load_ja3_map(&rust_path);
    assert_eq!(py["ja3_map"], rs);
    assert!(rs.is_object());
    assert!(rs.as_object().unwrap().is_empty());
    let _ = fs::remove_dir_all(&rust_dir);
}

#[test]
fn parity_load_ja3_map_malformed_returns_empty() {
    let content = "{bad json";
    let py = python_iran_anti_siam(&json!({"op": "load_ja3_map", "content": content}));
    let rust_dir = case_dir("ja3_malformed_rust");
    let rust_path = rust_dir.join("ja3_rotation_plan.json");
    write_file(&rust_path, content);
    let rs = load_ja3_map(&rust_path);
    assert_eq!(py["ja3_map"], rs);
    let _ = fs::remove_dir_all(&rust_dir);
}

#[test]
fn parity_load_ja3_map_no_bridge_ja3_map_key_returns_empty() {
    let content = r#"{"other":"value"}"#;
    let py = python_iran_anti_siam(&json!({"op": "load_ja3_map", "content": content}));
    let rust_dir = case_dir("ja3_no_key_rust");
    let rust_path = rust_dir.join("ja3_rotation_plan.json");
    write_file(&rust_path, content);
    let rs = load_ja3_map(&rust_path);
    assert_eq!(py["ja3_map"], rs);
    let _ = fs::remove_dir_all(&rust_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// load_bridges parity (fallback chain)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_load_bridges_fallback_chain_txt_only() {
    let files = vec![json!({"name": "vanilla.txt", "content": "vanilla_bridge\n"})];
    let py = python_iran_anti_siam(&json!({"op": "load_bridges", "files": files}));
    let rust_dir = case_dir("lb_txt_only_rust");
    let bridge_dir = rust_dir.join("bridge");
    fs::create_dir_all(&bridge_dir).unwrap();
    write_file(&bridge_dir.join("vanilla.txt"), "vanilla_bridge\n");
    let rs = load_bridges(&bridge_dir);
    assert_eq!(py["lines"], json!(rs));
    let _ = fs::remove_dir_all(&rust_dir);
}

#[test]
fn parity_load_bridges_fallback_chain_test_json_wins() {
    let files = vec![
        json!({"name": "vanilla.txt", "content": "vanilla_bridge\n"}),
        json!({"name": "iran_results.json", "content": r#"{"bridges":[{"line":"iran_bridge"}]}"#}),
        json!({"name": "bridge_list_for_testing.json", "content": r#"["test_bridge"]"#}),
    ];
    let py = python_iran_anti_siam(&json!({"op": "load_bridges", "files": files}));
    let rust_dir = case_dir("lb_test_json_wins_rust");
    let bridge_dir = rust_dir.join("bridge");
    fs::create_dir_all(&bridge_dir).unwrap();
    write_file(&bridge_dir.join("vanilla.txt"), "vanilla_bridge\n");
    write_file(
        &bridge_dir.join("iran_results.json"),
        r#"{"bridges":[{"line":"iran_bridge"}]}"#,
    );
    write_file(
        &bridge_dir.join("bridge_list_for_testing.json"),
        r#"["test_bridge"]"#,
    );
    let rs = load_bridges(&bridge_dir);
    assert_eq!(py["lines"], json!(rs));
    assert_eq!(rs, vec!["test_bridge"]);
    let _ = fs::remove_dir_all(&rust_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// build_md_report parity
// ─────────────────────────────────────────────────────────────────────────────

fn mock_result(score: f64, tier: &str, transport: &str, bridge_line: &str) -> SiamResult {
    SiamResult {
        bridge_line: bridge_line.to_string(),
        transport: transport.to_string(),
        port: Some(443),
        iran_siam_score: score,
        bypass_tier: tier.to_string(),
        layers_bypassed: 8,
        evasion_flags: vec![],
        layer_scores: std::collections::BTreeMap::new(),
        recommendation: "rec".to_string(),
    }
}

fn mock_result_json(score: f64, tier: &str, transport: &str, bridge_line: &str) -> Value {
    json!({
        "bridge_line": bridge_line,
        "transport": transport,
        "port": 443,
        "iran_siam_score": score,
        "bypass_tier": tier,
        "layers_bypassed": 8,
        "evasion_flags": [],
        "layer_scores": {},
        "recommendation": "rec"
    })
}

#[test]
fn parity_build_md_report_empty_results() {
    let py = python_iran_anti_siam(&json!({
        "op": "build_md_report",
        "results": [],
        "tier_counts": {},
        "transport_counts": {},
        "ts": "2026-06-25 12:00 UTC",
    }));
    let rs = build_md_report(
        &[],
        &std::collections::BTreeMap::new(),
        &[],
        "2026-06-25 12:00 UTC",
    );
    assert_eq!(py["md"].as_str().unwrap(), rs);
}

#[test]
fn parity_build_md_report_single_tier_single_transport() {
    let results_py = vec![mock_result_json(
        0.97,
        "PHANTOM",
        "snowflake",
        "snowflake x",
    )];
    let results_rs = vec![mock_result(0.97, "PHANTOM", "snowflake", "snowflake x")];
    let tier_counts = json!({"PHANTOM": 1});
    let transport_counts = json!({"snowflake": 1});
    let py = python_iran_anti_siam(&json!({
        "op": "build_md_report",
        "results": results_py,
        "tier_counts": tier_counts,
        "transport_counts": transport_counts,
        "ts": "2026-06-25 12:00 UTC",
    }));
    let rs = build_md_report(
        &results_rs,
        &serde_json::from_value(tier_counts).unwrap(),
        &[("snowflake".to_string(), 1)],
        "2026-06-25 12:00 UTC",
    );
    assert_eq!(py["md"].as_str().unwrap(), rs);
}

#[test]
fn parity_build_md_report_multi_tier_distinct_transport_counts() {
    // Use distinct counts so the sort-by-descending-count order is the same
    // regardless of insertion order (Python stable-sort vs Rust alphabetical
    // tie-break).
    let results_py = vec![
        mock_result_json(0.97, "PHANTOM", "snowflake", "snowflake x"),
        mock_result_json(0.50, "STEALTH", "obfs4", "obfs4 y"),
        mock_result_json(0.50, "STEALTH", "obfs4", "obfs4 z"),
        mock_result_json(0.30, "EXPOSED", "vanilla", "vanilla w"),
    ];
    let results_rs: Vec<SiamResult> = vec![
        mock_result(0.97, "PHANTOM", "snowflake", "snowflake x"),
        mock_result(0.50, "STEALTH", "obfs4", "obfs4 y"),
        mock_result(0.50, "STEALTH", "obfs4", "obfs4 z"),
        mock_result(0.30, "EXPOSED", "vanilla", "vanilla w"),
    ];
    let tier_counts = json!({"PHANTOM": 1, "STEALTH": 2, "EXPOSED": 1});
    let transport_counts = json!({"snowflake": 1, "obfs4": 2, "vanilla": 1});
    let py = python_iran_anti_siam(&json!({
        "op": "build_md_report",
        "results": results_py,
        "tier_counts": tier_counts,
        "transport_counts": transport_counts,
        "ts": "2026-06-25 12:00 UTC",
    }));
    // Insertion order: snowflake (first), obfs4 (second), vanilla (third).
    // Python preserves this order for the count=1 tie between snowflake and
    // vanilla.
    let rs = build_md_report(
        &results_rs,
        &serde_json::from_value(tier_counts).unwrap(),
        &[
            ("snowflake".to_string(), 1),
            ("obfs4".to_string(), 2),
            ("vanilla".to_string(), 1),
        ],
        "2026-06-25 12:00 UTC",
    );
    assert_eq!(py["md"].as_str().unwrap(), rs);
}

// ─────────────────────────────────────────────────────────────────────────────
// run_pipeline parity (mocked score_all on both sides)
// ─────────────────────────────────────────────────────────────────────────────

fn mock_results_full() -> Vec<SiamResult> {
    vec![
        SiamResult {
            bridge_line: "snowflake 1.2.3.4:443".to_string(),
            transport: "snowflake".to_string(),
            port: Some(443),
            iran_siam_score: 0.97,
            bypass_tier: "PHANTOM".to_string(),
            layers_bypassed: 8,
            evasion_flags: vec![],
            layer_scores: std::collections::BTreeMap::new(),
            recommendation: "rec phantom".to_string(),
        },
        SiamResult {
            bridge_line: "obfs4 5.6.7.8:9001".to_string(),
            transport: "obfs4".to_string(),
            port: Some(9001),
            iran_siam_score: 0.50,
            bypass_tier: "STEALTH".to_string(),
            layers_bypassed: 6,
            evasion_flags: vec![],
            layer_scores: std::collections::BTreeMap::new(),
            recommendation: "rec stealth".to_string(),
        },
        SiamResult {
            bridge_line: "vanilla 9.10.11.12:443".to_string(),
            transport: "vanilla".to_string(),
            port: Some(443),
            iran_siam_score: 0.10,
            bypass_tier: "DETECTED".to_string(),
            layers_bypassed: 1,
            evasion_flags: vec![],
            layer_scores: std::collections::BTreeMap::new(),
            recommendation: "rec detected".to_string(),
        },
    ]
}

fn mock_results_full_json() -> Vec<Value> {
    mock_results_full()
        .iter()
        .map(|r| {
            json!({
                "bridge_line": r.bridge_line,
                "transport": r.transport,
                "port": r.port,
                "iran_siam_score": r.iran_siam_score,
                "bypass_tier": r.bypass_tier,
                "layers_bypassed": r.layers_bypassed,
                "evasion_flags": r.evasion_flags,
                "layer_scores": r.layer_scores,
                "recommendation": r.recommendation,
            })
        })
        .collect()
}

#[test]
fn parity_run_pipeline_empty_bridges_writes_empty_report() {
    let py = python_iran_anti_siam(&json!({
        "op": "main",
        "bridge_files": [],
        "ja3_content": null,
        "results": [],
        "now": NOW_ISO,
    }));

    let rust_dir = case_dir("pipeline_empty_rust");
    let bridge_dir = rust_dir.join("bridge");
    let data_dir = rust_dir.join("data");
    let export_dir = rust_dir.join("export");
    let docs_dir = rust_dir.join("docs");
    fs::create_dir_all(&bridge_dir).unwrap();
    let ja3_path = rust_dir.join("ja3_rotation_plan.json");

    let _ = run_pipeline(
        &bridge_dir,
        &data_dir,
        &export_dir,
        &docs_dir,
        &ja3_path,
        parse_utc(NOW_ISO),
        |_, _| Vec::new(),
    )
    .expect("rust run_pipeline empty succeeds");

    let py_report = py["outputs"]["data/iran_siam_report.json"]
        .as_str()
        .unwrap();
    let rust_report = fs::read_to_string(data_dir.join("iran_siam_report.json")).unwrap();
    let py_v: Value = serde_json::from_str(py_report).unwrap();
    let rs_v: Value = serde_json::from_str(&rust_report).unwrap();
    assert_eq!(py_v, rs_v);

    let _ = fs::remove_dir_all(&rust_dir);
}

#[test]
fn parity_run_pipeline_full_multi_tier_compares_all_outputs() {
    let results_json = mock_results_full_json();
    let py = python_iran_anti_siam(&json!({
        "op": "main",
        "bridge_files": [
            {"name": "bridge_list_for_testing.json", "content": r#"["snowflake 1.2.3.4:443","obfs4 5.6.7.8:9001","vanilla 9.10.11.12:443"]"#}
        ],
        "ja3_content": r#"{"bridge_ja3_map":{}}"#,
        "results": results_json,
        "now": NOW_ISO,
    }));

    let rust_dir = case_dir("pipeline_full_rust");
    let bridge_dir = rust_dir.join("bridge");
    let data_dir = rust_dir.join("data");
    let export_dir = rust_dir.join("export");
    let docs_dir = rust_dir.join("docs");
    fs::create_dir_all(&bridge_dir).unwrap();
    write_file(
        &bridge_dir.join("bridge_list_for_testing.json"),
        r#"["snowflake 1.2.3.4:443","obfs4 5.6.7.8:9001","vanilla 9.10.11.12:443"]"#,
    );
    let ja3_path = rust_dir.join("ja3_rotation_plan.json");
    write_file(&ja3_path, r#"{"bridge_ja3_map":{}}"#);

    let fixed_results = mock_results_full();
    let _ = run_pipeline(
        &bridge_dir,
        &data_dir,
        &export_dir,
        &docs_dir,
        &ja3_path,
        parse_utc(NOW_ISO),
        move |_lines, _ja3| fixed_results.clone(),
    )
    .expect("rust run_pipeline full succeeds");

    // Compare JSON report (parsed — key order may differ).
    let py_report = py["outputs"]["data/iran_siam_report.json"]
        .as_str()
        .unwrap();
    let rust_report = fs::read_to_string(data_dir.join("iran_siam_report.json")).unwrap();
    let py_v: Value = serde_json::from_str(py_report).unwrap();
    let rs_v: Value = serde_json::from_str(&rust_report).unwrap();
    assert_eq!(py_v, rs_v, "JSON report mismatch");

    // Compare export files (exact strings).
    for file_name in [
        "iran_phantom_bridges.txt",
        "iran_stealth_bridges.txt",
        "iran_siam_best_bridges.txt",
    ] {
        let py_key = format!("export/{file_name}");
        let py_content = py["outputs"].get(&py_key).and_then(|v| v.as_str());
        let rust_path = export_dir.join(file_name);
        let rust_content = fs::read_to_string(&rust_path).ok();
        assert_eq!(
            py_content,
            rust_content.as_deref(),
            "export file mismatch for {file_name}"
        );
    }

    // Compare markdown report (exact string).
    let py_md = py["outputs"]["docs/iran-siam-analysis.md"]
        .as_str()
        .unwrap();
    let rust_md = fs::read_to_string(docs_dir.join("iran-siam-analysis.md")).unwrap();
    assert_eq!(py_md, rust_md, "markdown report mismatch");

    let _ = fs::remove_dir_all(&rust_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust-only edge cases (no Python subprocess needed)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_load_bridges_json_dict_with_non_dict_entry_returns_empty() {
    // Python's `b.get("line")` raises AttributeError for non-dict entries,
    // which the broad `except` swallows and returns []. The Rust port returns
    // Err internally, which the public wrapper converts to [].
    let tmp = case_dir("lbj_non_dict_entry_rust");
    let path = tmp.join("input.json");
    write_file(&path, r#"{"bridges":["not a dict",{"line":"ok"}]}"#);
    let lines = load_bridges_json(&path);
    assert!(lines.is_empty(), "non-dict entry should yield empty list");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn rust_load_bridges_txt_missing_dir_returns_empty_without_panic() {
    let dir = std::env::temp_dir().join("iran_anti_siam_missing_txt_dir");
    let _ = fs::remove_dir_all(&dir);
    let lines = load_bridges_txt(&dir);
    assert!(lines.is_empty());
}

#[test]
fn rust_run_pipeline_creates_output_dirs() {
    let dir = case_dir("pipeline_mkdirs_rust");
    let bridge_dir = dir.join("bridge");
    let data_dir = dir.join("data");
    let export_dir = dir.join("export");
    let docs_dir = dir.join("docs");
    fs::create_dir_all(&bridge_dir).unwrap();
    let ja3_path = dir.join("ja3.json");

    let out = run_pipeline(
        &bridge_dir,
        &data_dir,
        &export_dir,
        &docs_dir,
        &ja3_path,
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap(),
        |_, _| Vec::new(),
    )
    .expect("rust run_pipeline creates dirs");
    assert_eq!(out.total_scored, 0);
    assert!(data_dir.exists());
    assert!(export_dir.exists());
    assert!(docs_dir.exists());
    let _ = fs::remove_dir_all(&dir);
}

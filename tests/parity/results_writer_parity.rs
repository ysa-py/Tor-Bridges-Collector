use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{json, Value};
use torshield_ir_ultra::results_writer::{
    load_iran_results, write_result_files, ResultsWriterError,
};

const OUTPUT_FILES: &[&str] = &[
    "iran_likely_working_obfs4.txt",
    "iran_likely_working_webtunnel.txt",
    "iran_likely_working_vanilla.txt",
    "iran_likely_working_snowflake.txt",
    "iran_likely_working_meek_lite.txt",
    "iran_likely_working_all.txt",
    "iran_blocked.txt",
    "tested_global_obfs4.txt",
    "tested_global_webtunnel.txt",
    "tested_global_vanilla.txt",
];

fn case_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield_results_writer_parity_{}_{}",
        name,
        std::process::id()
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean stale parity tempdir");
    }
    fs::create_dir_all(&dir).expect("create parity tempdir");
    dir
}

fn python_write(repo_root: &Path, bridge_dir: &Path, bridges: &Value) -> BTreeMap<String, usize> {
    let script = r#"
import json
import os
import pathlib
import sys
os.environ["BRIDGE_DIR"] = sys.argv[1]
import results_writer
results_writer.BRIDGE_DIR = pathlib.Path(sys.argv[1])
bridges = json.loads(sys.argv[2])
stats = results_writer.write_result_files(bridges)
print(json.dumps(stats, sort_keys=True, separators=(",", ":")))
"#;
    let output = Command::new("python")
        .current_dir(repo_root)
        .arg("-c")
        .arg(script)
        .arg(bridge_dir)
        .arg(serde_json::to_string(bridges).expect("bridges JSON serializes"))
        .output()
        .expect("python parity helper must execute");
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("python helper must emit JSON stats")
}

fn snapshot(dir: &Path) -> BTreeMap<String, String> {
    OUTPUT_FILES
        .iter()
        .filter_map(|name| {
            let path = dir.join(name);
            path.exists().then(|| {
                (
                    (*name).to_string(),
                    fs::read_to_string(path).expect("read output"),
                )
            })
        })
        .collect()
}

fn assert_parity(name: &str, bridges: Value) {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let py_dir = case_dir(&format!("{name}_py"));
    let rust_dir = case_dir(&format!("{name}_rust"));

    let py_stats = python_write(repo_root, &py_dir, &bridges);
    let rust_stats = write_result_files(
        &rust_dir,
        bridges.as_array().expect("parity bridges input is a list"),
    )
    .expect("rust writer succeeds");

    assert_eq!(rust_stats, py_stats);
    assert_eq!(snapshot(&rust_dir), snapshot(&py_dir));
}

fn python_load(repo_root: &Path, bridge_dir: &Path) -> (bool, String, String) {
    let script = r#"
import json
import os
import pathlib
import sys
os.environ["BRIDGE_DIR"] = sys.argv[1]
import results_writer
results_writer.BRIDGE_DIR = pathlib.Path(sys.argv[1])
results_writer.IRAN_RESULTS_PATH = pathlib.Path(sys.argv[1]) / "iran_results.json"
try:
    data = results_writer.load_iran_results()
    print(json.dumps(data, sort_keys=True, separators=(",", ":")))
except SystemExit as exc:
    print(f"SystemExit:{exc.code}", file=sys.stderr)
    raise
"#;
    let output = Command::new("python")
        .current_dir(repo_root)
        .arg("-c")
        .arg(script)
        .arg(bridge_dir)
        .output()
        .expect("python load parity helper must execute");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn assert_load_success_parity(name: &str, file_text: &str) {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let py_dir = case_dir(&format!("load_{name}_py"));
    let rust_dir = case_dir(&format!("load_{name}_rust"));
    fs::write(py_dir.join("iran_results.json"), file_text).expect("write python input");
    fs::write(rust_dir.join("iran_results.json"), file_text).expect("write rust input");

    let (py_ok, py_stdout, py_stderr) = python_load(repo_root, &py_dir);
    assert!(py_ok, "python helper failed: {py_stderr}");
    let py_value: Value = serde_json::from_str(&py_stdout).expect("python helper emitted JSON");
    let rust_value =
        load_iran_results(&rust_dir.join("iran_results.json")).expect("rust load succeeds");
    assert_eq!(rust_value, py_value);
}

#[test]
fn parity_load_iran_results_happy_path_object() {
    assert_load_success_parity(
        "object",
        r#"{"summary":{"total":2},"bridges":[{"line":"obfs4 a"},{"line":"wt b"}]}"#,
    );
}

#[test]
fn parity_load_iran_results_accepts_invalid_schema_data() {
    assert_load_success_parity(
        "invalid_schema",
        r#"["python", "does", "not", "validate", 7]"#,
    );
}

#[test]
fn parity_load_iran_results_missing_file_exits_vs_typed_error() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let py_dir = case_dir("load_missing_py");
    let rust_dir = case_dir("load_missing_rust");

    let (py_ok, _py_stdout, py_stderr) = python_load(repo_root, &py_dir);
    assert!(!py_ok);
    assert!(
        py_stderr.contains("SystemExit:1"),
        "stderr was: {py_stderr}"
    );

    let err = load_iran_results(&rust_dir.join("iran_results.json")).expect_err("missing is typed");
    assert!(matches!(err, ResultsWriterError::MissingIranResults { .. }));
}

#[test]
fn parity_load_iran_results_malformed_json_errors() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let py_dir = case_dir("load_malformed_py");
    let rust_dir = case_dir("load_malformed_rust");
    fs::write(py_dir.join("iran_results.json"), "{not valid json").expect("write python input");
    fs::write(rust_dir.join("iran_results.json"), "{not valid json").expect("write rust input");

    let (py_ok, _py_stdout, py_stderr) = python_load(repo_root, &py_dir);
    assert!(!py_ok);
    assert!(
        py_stderr.contains("JSONDecodeError"),
        "stderr was: {py_stderr}"
    );

    let err = load_iran_results(&rust_dir.join("iran_results.json")).expect_err("parse is typed");
    assert!(matches!(err, ResultsWriterError::ParseIranResults { .. }));
}

#[test]
fn parity_load_iran_results_directory_read_error() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let py_dir = case_dir("load_directory_py");
    let rust_dir = case_dir("load_directory_rust");
    fs::create_dir(py_dir.join("iran_results.json")).expect("create python directory path");
    fs::create_dir(rust_dir.join("iran_results.json")).expect("create rust directory path");

    let (py_ok, _py_stdout, py_stderr) = python_load(repo_root, &py_dir);
    assert!(!py_ok);
    assert!(
        py_stderr.contains("IsADirectoryError"),
        "stderr was: {py_stderr}"
    );

    let err = load_iran_results(&rust_dir.join("iran_results.json")).expect_err("read is typed");
    assert!(matches!(err, ResultsWriterError::ReadIranResults { .. }));
}

#[test]
fn parity_mixed_tiers_blocked_global_and_deduplication() {
    assert_parity(
        "mixed",
        json!([
            {"line":" obfs4 b ","transport":"obfs4","iran_status":"iran_likely_working","tcp_reachable":false},
            {"line":"obfs4 a","transport":"obfs4","iran_status":"iran_likely_working","tcp_reachable":true},
            {"line":"obfs4 a","transport":"obfs4","iran_status":"iran_likely_working","tcp_reachable":true},
            {"line":"ignored tier2 because tier1 exists","transport":"obfs4","iran_status":"iran_unknown","tcp_reachable":true},
            {"line":"wt fallback without tcp","transport":"webtunnel","iran_status":"iran_unknown","tcp_reachable":false},
            {"line":"snowflake fallback without tcp","transport":"snowflake","iran_status":"iran_unknown","tcp_reachable":false},
            {"line":"vanilla fallback","transport":"vanilla","iran_status":"iran_unknown","tcp_reachable":true},
            {"line":"blocked one","transport":"vanilla","iran_status":"iran_likely_blocked","tcp_reachable":true},
            {"line":"blocked two","transport":"vanilla","iran_status":"iran_frequently_blocked","tcp_reachable":false},
            {"line":"","transport":"obfs4","iran_status":"iran_likely_working","tcp_reachable":true},
            {"line":"unknown transport","transport":"unknown","iran_status":"iran_likely_working","tcp_reachable":true}
        ]),
    );
}

#[test]
fn parity_empty_input_still_writes_mandatory_empty_files() {
    assert_parity("empty", json!([]));
}

/// Regression: URL-only domain-fronted WebTunnel bridges (the form published
/// by BridgeDB — fingerprint + url=, no literal IP:PORT) arrive from the Go
/// iran_tester with `host: ""`, `tcp_reachable: false`, and
/// `iran_status: tcp_unreachable` because raw TCP cannot dial them. The
/// results stage reclassifies them via the line's url= front domain so the
/// WebTunnel special-case promotes them into
/// `iran_likely_working_webtunnel.txt` instead of leaving that file empty.
#[test]
fn rust_url_only_webtunnel_tcp_unreachable_is_reclassified() {
    let dir = case_dir("rust_url_only_webtunnel");
    let bridges = json!([
        {
            "line": "webtunnel 68674E54A17AEB1C9ADE878BBBB46C6975DD3105 url=https://vika7.space/83c1327ea78e32b5d151e872ca123f7858aec2e1 ver=0.0.4",
            "transport": "webtunnel",
            "host": "",
            "iran_status": "tcp_unreachable",
            "tcp_reachable": false
        },
        {
            // Documentation-prefix IPv6 placeholder must NOT be reclassified:
            // it carries a literal endpoint token.
            "line": "webtunnel [2001:db8:1218:1de7:3a91:22cc:8d7f:197c]:443 DF343521735ABE129910A998817B3A93AA2390FE url=https://coellen.xyz ver=0.0.3",
            "transport": "webtunnel",
            "host": "2001:db8:1218:1de7:3a91:22cc:8d7f:197c",
            "iran_status": "tcp_unreachable",
            "tcp_reachable": false
        }
    ]);
    let stats = write_result_files(
        &dir,
        bridges.as_array().expect("bridges list"),
    )
    .expect("rust writer succeeds");

    let wt = fs::read_to_string(dir.join("iran_likely_working_webtunnel.txt"))
        .expect("webtunnel working file written");
    assert!(
        wt.contains("vika7.space"),
        "URL-only webtunnel must be promoted into iran_likely_working_webtunnel.txt, got: {wt:?}"
    );
    assert!(
        !wt.contains("2001:db8"),
        "documentation-prefix IPv6 placeholder must not be reclassified as a working domain-front bridge, got: {wt:?}"
    );
    let count = stats
        .get("iran_likely_working_webtunnel.txt")
        .copied()
        .unwrap_or(0);
    assert_eq!(count, 1, "exactly one URL-only webtunnel promoted");
}

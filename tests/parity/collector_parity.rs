#![allow(warnings)]
// Differential parity tests for `src/collector.rs` vs `core/collector.py`.
//
// Each test invokes a fresh Python interpreter on `core/collector.py`,
// captures its output, and asserts the Rust port produces byte-identical
// results. Covers the pure decision logic: `_port_of` and the stable
// `prioritize_port_443` partition. (The async `collect_all` orchestration
// performs real network I/O and is covered by the in-crate unit tests
// with injected sources, not differentially.)

use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::collector::{port_of, prioritize_port_443};

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(script: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        // Preserve PATH so the interpreter resolves after env_clear()
        // (the dt_utils portability fix, applied consistently here).
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Run `_port_of(json_literal)` in the Python oracle.
fn py_port_of(bridge: &Value) -> String {
    let compact = serde_json::to_string(bridge).unwrap();
    run_python(&format!(
        "import json; from core.collector import _port_of; \
         print(_port_of(json.loads(r'''{compact}''')))"
    ))
}

#[test]
fn parity_port_of_variants() {
    let cases = vec![
        json!({"port": 443}),
        json!({"port": 80}),
        json!({"port": 8080}),
        json!({"port": 0}),
        json!({"port": 9001}),
        json!({"port": "443"}),        // string port -> int()
        json!({"port": "abc"}),        // non-numeric -> except -> 0
        json!({"port": ""}),           // empty string -> falsy -> 0
        json!({ "port": null }),       // None -> 0
        json!({}),                     // missing -> 0
        json!({"transport": "obfs4"}), // unrelated fields only
    ];
    for c in &cases {
        let py = py_port_of(c);
        let rs = port_of(c).to_string();
        assert_eq!(py, rs, "port_of divergence for {c}");
    }
}

/// Run `prioritize_port_443` in the oracle and return the ordered `id`s.
fn py_prioritize_ids(bridges: &Value) -> String {
    let compact = serde_json::to_string(bridges).unwrap();
    run_python(&format!(
        "import json; from core.collector import prioritize_port_443; \
         out = prioritize_port_443(json.loads(r'''{compact}''')); \
         print(','.join(str(b['id']) for b in out))"
    ))
}

fn rs_prioritize_ids(bridges: &[Value]) -> String {
    prioritize_port_443(bridges)
        .iter()
        .map(|b| b["id"].as_i64().unwrap().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn parity_prioritize_port_443_stable_partition() {
    // Mixed ports: 443 entries must float to the front, both partitions
    // keeping their original relative order (stable partition).
    let list = json!([
        {"id": 0, "port": 80},
        {"id": 1, "port": 443},
        {"id": 2, "port": 9001},
        {"id": 3, "port": 443},
        {"id": 4, "port": "443"},
        {"id": 5, "port": 8080},
        {"id": 6, "port": null},
        {"id": 7, "port": 443},
    ]);
    let bridges: Vec<Value> = list.as_array().unwrap().clone();
    assert_eq!(py_prioritize_ids(&list), rs_prioritize_ids(&bridges));
}

#[test]
fn parity_prioritize_port_443_no_443() {
    let list = json!([
        {"id": 10, "port": 80},
        {"id": 11, "port": 9001},
        {"id": 12, "port": 8080},
    ]);
    let bridges: Vec<Value> = list.as_array().unwrap().clone();
    assert_eq!(py_prioritize_ids(&list), rs_prioritize_ids(&bridges));
}

#[test]
fn parity_prioritize_port_443_all_443() {
    let list = json!([
        {"id": 20, "port": 443},
        {"id": 21, "port": "443"},
        {"id": 22, "port": 443},
    ]);
    let bridges: Vec<Value> = list.as_array().unwrap().clone();
    assert_eq!(py_prioritize_ids(&list), rs_prioritize_ids(&bridges));
}

#[test]
fn parity_prioritize_port_443_empty() {
    let list = json!([]);
    let bridges: Vec<Value> = vec![];
    assert_eq!(py_prioritize_ids(&list), rs_prioritize_ids(&bridges));
}

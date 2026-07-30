#![allow(warnings)]
// Parity tests for `src/static_bridges.rs` vs `sources/static_bridges.py`.
//
// Verifies that the four hardcoded bridge lists are byte-identical to the
// Python source and that `get_all()` returns the documented 12-tuple order
// (snowflake×4, meek_lite×3, obfs4×5). At least one test invokes the
// Python `sources.static_bridges.get_all()` via subprocess and asserts the
// Rust output matches exactly.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::static_bridges::{get_all, MEEK_BRIDGES, OBFS4_BRIDGES, SNOWFLAKE_BRIDGES};

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

/// Invoke `sources.static_bridges.get_all()` via Python subprocess and
/// return the JSON-serialized list of `[bridge_line, transport, ip_version]`
/// tuples. The output is sorted-key stable so Rust can compare directly.
fn python_get_all() -> Value {
    let script = r#"
import json
from sources.static_bridges import get_all
result = [[line, transport, ip_version] for (line, transport, ip_version) in get_all()]
print(json.dumps(result))
"#;
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python static_bridges helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python static_bridges helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python static_bridges helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// Invoke `sources.static_bridges.{SNOWFLAKE,MEEK,OBFS4}_BRIDGES` via Python
/// subprocess and return the JSON-serialized list of bridge strings.
fn python_bridge_list(name: &str) -> Value {
    let script = format!(
        r#"
import json
from sources import static_bridges
print(json.dumps(getattr(static_bridges, {name:?})))
"#,
        name = name
    );
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python static_bridges helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python static_bridges helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python static_bridges helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Length / order tests (no Python subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn snowflake_bridges_has_four_entries() {
    assert_eq!(SNOWFLAKE_BRIDGES.len(), 4);
}

#[test]
fn meek_bridges_has_three_entries() {
    assert_eq!(MEEK_BRIDGES.len(), 3);
}

#[test]
fn obfs4_bridges_has_five_entries() {
    assert_eq!(OBFS4_BRIDGES.len(), 5);
}

#[test]
fn get_all_returns_twelve_tuples_in_documented_order() {
    let all = get_all();
    assert_eq!(all.len(), 12);

    // snowflake ×4 (indices 0..4)
    for (i, entry) in all[0..4].iter().enumerate() {
        assert_eq!(
            entry.0, SNOWFLAKE_BRIDGES[i],
            "snowflake bridge {i} must match"
        );
        assert_eq!(entry.1, "snowflake");
        assert_eq!(entry.2, "ipv4");
    }
    // meek_lite ×3 (indices 4..7)
    for (i, entry) in all[4..7].iter().enumerate() {
        assert_eq!(entry.0, MEEK_BRIDGES[i], "meek bridge {i} must match");
        assert_eq!(entry.1, "meek_lite");
        assert_eq!(entry.2, "ipv4");
    }
    // obfs4 ×5 (indices 7..12)
    for (i, entry) in all[7..12].iter().enumerate() {
        assert_eq!(entry.0, OBFS4_BRIDGES[i], "obfs4 bridge {i} must match");
        assert_eq!(entry.1, "obfs4");
        assert_eq!(entry.2, "ipv4");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-identical parity with Python (subprocess)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_snowflake_bridges_byte_identical_to_python() {
    let py = python_bridge_list("SNOWFLAKE_BRIDGES");
    let rs: Value = json!(SNOWFLAKE_BRIDGES);
    assert_eq!(py, rs);
    assert_eq!(py.as_array().map(|a| a.len()), Some(4));
}

#[test]
fn parity_meek_bridges_byte_identical_to_python() {
    let py = python_bridge_list("MEEK_BRIDGES");
    let rs: Value = json!(MEEK_BRIDGES);
    assert_eq!(py, rs);
    assert_eq!(py.as_array().map(|a| a.len()), Some(3));
}

#[test]
fn parity_obfs4_bridges_byte_identical_to_python() {
    let py = python_bridge_list("OBFS4_BRIDGES");
    let rs: Value = json!(OBFS4_BRIDGES);
    assert_eq!(py, rs);
    assert_eq!(py.as_array().map(|a| a.len()), Some(5));
}

#[test]
fn parity_get_all_byte_identical_to_python() {
    let py = python_get_all();
    let rs: Vec<Value> = get_all()
        .iter()
        .map(|(line, transport, ip_version)| json!([line, transport, ip_version]))
        .collect();
    let rs_value: Value = json!(rs);
    assert_eq!(py, rs_value);
    let py_arr = py.as_array().expect("python get_all must be a list");
    assert_eq!(py_arr.len(), 12);
    // Verify the documented ordering inside the parity check as well so the
    // subprocess test catches ordering regressions, not just contents.
    for entry in &py_arr[0..4] {
        assert_eq!(entry[1], json!("snowflake"));
        assert_eq!(entry[2], json!("ipv4"));
    }
    for entry in &py_arr[4..7] {
        assert_eq!(entry[1], json!("meek_lite"));
        assert_eq!(entry[2], json!("ipv4"));
    }
    for entry in &py_arr[7..12] {
        assert_eq!(entry[1], json!("obfs4"));
        assert_eq!(entry[2], json!("ipv4"));
    }
}

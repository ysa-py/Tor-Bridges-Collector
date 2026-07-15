use std::{fs, path::Path, process::Command};

use serde_json::{json, Value};
use torshield_ir_ultra::generated_json_loader::{
    load_generated_json, load_generated_json_with_status, GeneratedJsonLoadStatus,
};

fn python_load(path: &Path, fallback: &Value) -> Value {
    let script = r#"
import json
import pathlib
import sys
from generated_json_loader import load_generated_json
path = pathlib.Path(sys.argv[1])
fallback = json.loads(sys.argv[2])
print(json.dumps(load_generated_json(path, fallback), sort_keys=True, separators=(",", ":")))
"#;
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("migration crate stays under rust/torshield-ir-ultra");
    let output = Command::new("python")
        .current_dir(repo_root)
        .arg("-c")
        .arg(script)
        .arg(path)
        .arg(serde_json::to_string(fallback).expect("test fallback JSON must serialize"))
        .output()
        .expect("python parity helper must execute");
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("python helper must emit JSON")
}

fn case_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "torshield_generated_json_loader_parity_{}_{}",
        name,
        std::process::id()
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean stale parity tempdir");
    }
    fs::create_dir_all(&dir).expect("create parity tempdir");
    dir
}

#[test]
fn parity_missing_file_returns_fallback() {
    let dir = case_dir("missing");
    let path = dir.join("missing.json");
    let fallback = json!({"bridges": ["fallback"]});

    assert_eq!(
        load_generated_json(&path, fallback.clone()),
        python_load(&path, &fallback)
    );
    assert_eq!(
        load_generated_json_with_status(&path, fallback).1,
        GeneratedJsonLoadStatus::MissingOrUnreadable
    );
}

#[test]
fn parity_empty_file_returns_fallback() {
    let dir = case_dir("empty");
    let path = dir.join("artifact.json");
    fs::write(&path, "  \n\t  ").expect("write empty artifact");
    let fallback = json!([]);

    assert_eq!(
        load_generated_json(&path, fallback.clone()),
        python_load(&path, &fallback)
    );
    assert_eq!(
        load_generated_json_with_status(&path, fallback).1,
        GeneratedJsonLoadStatus::Empty
    );
}

#[test]
fn parity_invalid_json_returns_fallback() {
    let dir = case_dir("invalid");
    let path = dir.join("artifact.json");
    fs::write(&path, "{not-json").expect("write invalid artifact");
    let fallback = json!({"results": []});

    assert_eq!(
        load_generated_json(&path, fallback.clone()),
        python_load(&path, &fallback)
    );
    assert_eq!(
        load_generated_json_with_status(&path, fallback).1,
        GeneratedJsonLoadStatus::InvalidJson
    );
}

#[test]
fn parity_type_mismatch_returns_fallback() {
    let dir = case_dir("type_mismatch");
    let path = dir.join("artifact.json");
    fs::write(&path, "[]").expect("write artifact");
    let fallback = json!({"bridges": []});

    assert_eq!(
        load_generated_json(&path, fallback.clone()),
        python_load(&path, &fallback)
    );
    assert_eq!(
        load_generated_json_with_status(&path, fallback).1,
        GeneratedJsonLoadStatus::TypeMismatch
    );
}

#[test]
fn parity_object_normalizes_common_list_fields() {
    let dir = case_dir("normalize");
    let path = dir.join("artifact.json");
    fs::write(&path, r#"{"bridges":"bad","other":1}"#).expect("write artifact");
    let fallback = json!({"results": ["fallback-result"]});

    let rust_value = load_generated_json(&path, fallback.clone());
    let python_value = python_load(&path, &fallback);
    assert_eq!(rust_value, python_value);
    assert_eq!(
        rust_value,
        json!({"bridges": [], "other": 1, "results": []})
    );
}

#[test]
fn parity_valid_array_passes_through() {
    let dir = case_dir("array");
    let path = dir.join("artifact.json");
    fs::write(&path, r#"[3,1,2]"#).expect("write artifact");
    let fallback = json!([]);

    assert_eq!(
        load_generated_json(&path, fallback.clone()),
        python_load(&path, &fallback)
    );
}

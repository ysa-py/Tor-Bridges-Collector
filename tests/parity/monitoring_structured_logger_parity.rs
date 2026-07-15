// Live-Python differential parity test for `monitoring/structured_logger.py`
// vs the Rust port `src/monitoring_structured_logger.rs`.
//
// For each `log_*` method the REAL CPython `StructuredLogger` writes a record
// into a temp directory; the parity test reads back the emitted JSON line and
// compares, against the Rust port:
//   * the exact ordered key sequence (insertion order, incl. the trailing
//     `timestamp`/`log_type`), and
//   * every field value (with the non-deterministic `timestamp` normalised and
//     the float `latency_ms` compared numerically).

use std::process::Command;

use serde_json::Value;
use torshield_ir_ultra::monitoring_structured_logger::{LogValue, StructuredLogger};

fn python_executable() -> &'static str {
    if Command::new("python")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        "python"
    } else {
        "python3"
    }
}

const ORACLE: &str = r#"
import sys, json, tempfile, os
from monitoring.structured_logger import StructuredLogger

method = sys.argv[1]
params = json.loads(sys.argv[2])

tmp = tempfile.mkdtemp()
sl = StructuredLogger(log_dir=tmp)
getattr(sl, method)(**params)

fname = {
    "log_diagnostics": "diagnostics.log",
    "log_monitor": "monitor.log",
    "log_recovery": "recovery.log",
    "log_gateway": "gateway.log",
}[method]
with open(os.path.join(tmp, fname), "r", encoding="utf-8") as f:
    line = f.readlines()[-1].rstrip("\n")

# Preserve insertion order of keys explicitly.
keys = list(json.loads(line, object_pairs_hook=lambda p: dict(p)).keys())
obj = json.loads(line)
obj["timestamp"] = "T"                      # normalise the wall-clock field
print(json.dumps({"keys": keys, "obj": obj}, ensure_ascii=False))
"#;

fn oracle(method: &str, params_json: &str) -> (Vec<String>, Value) {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(ORACLE)
        .arg(method)
        .arg(params_json)
        .output()
        .expect("python structured_logger oracle must execute");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value = serde_json::from_slice(&output.stdout).expect("oracle JSON");
    let keys = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    (keys, v["obj"].clone())
}

/// Turn a Rust `Entry` (plus the appended timestamp/log_type) into the same
/// `(keys, normalised-object)` representation the oracle emits.
fn rust_repr(mut entry: torshield_ir_ultra::monitoring_structured_logger::Entry, log_type: &str) -> (Vec<String>, Value) {
    entry.push("timestamp", LogValue::Str("T".into()));
    entry.push("log_type", LogValue::Str(log_type.into()));
    let keys = entry.keys();
    let obj: Value = serde_json::from_str(&entry.to_json_line()).expect("rust JSON parses");
    (keys, obj)
}

#[test]
fn parity_log_diagnostics() {
    let params = r#"{"level":"INFO","provider":"cloudflare","slot":3,"model":"gpt","error_code":"E1","message":"probe ok"}"#;
    let (py_keys, py_obj) = oracle("log_diagnostics", params);
    let entry =
        StructuredLogger::diagnostics_entry("INFO", "cloudflare", 3, "gpt", "E1", "probe ok", &[]);
    let (r_keys, r_obj) = rust_repr(entry, "diagnostics");
    assert_eq!(py_keys, r_keys, "diagnostics key order");
    assert_eq!(py_obj, r_obj, "diagnostics values");
}

#[test]
fn parity_log_monitor_with_kwargs() {
    let params = r#"{"level":"WARN","event_type":"dpi_block","provider":"portkey","slot":7,"model":"m","error_code":"","message":"blocked","bridge":"obfs4","port":443}"#;
    let (py_keys, py_obj) = oracle("log_monitor", params);
    let entry = StructuredLogger::monitor_entry(
        "WARN",
        "dpi_block",
        "portkey",
        7,
        "m",
        "",
        "blocked",
        &[
            ("bridge", LogValue::Str("obfs4".into())),
            ("port", LogValue::Int(443)),
        ],
    );
    let (r_keys, r_obj) = rust_repr(entry, "monitor");
    assert_eq!(py_keys, r_keys, "monitor key order (incl. kwargs)");
    assert_eq!(py_obj, r_obj, "monitor values");
}

#[test]
fn parity_log_recovery_lists() {
    let params = r#"{"level":"INFO","action":"rotate","trigger":"timeout","slots_affected":[1,2,3],"models_rotated":["a","b"],"message":"healed"}"#;
    let (py_keys, py_obj) = oracle("log_recovery", params);
    let entry = StructuredLogger::recovery_entry(
        "INFO",
        "rotate",
        "timeout",
        vec![LogValue::Int(1), LogValue::Int(2), LogValue::Int(3)],
        vec![LogValue::Str("a".into()), LogValue::Str("b".into())],
        "healed",
        &[],
    );
    let (r_keys, r_obj) = rust_repr(entry, "recovery");
    assert_eq!(py_keys, r_keys, "recovery key order");
    assert_eq!(py_obj, r_obj, "recovery values");
}

#[test]
fn parity_log_recovery_default_empty_lists() {
    // Omit slots_affected/models_rotated so Python's `x or []` defaults apply.
    let params = r#"{"level":"INFO","action":"noop","trigger":"","message":""}"#;
    let (py_keys, py_obj) = oracle("log_recovery", params);
    let entry = StructuredLogger::recovery_entry("INFO", "noop", "", vec![], vec![], "", &[]);
    let (r_keys, r_obj) = rust_repr(entry, "recovery");
    assert_eq!(py_keys, r_keys);
    assert_eq!(py_obj, r_obj);
}

#[test]
fn parity_log_gateway_latency_rounding() {
    // Values chosen so `round(x, 1)` is unambiguous across implementations.
    for latency in [0.0_f64, 5.5, 12.34, 250.0, 88.42, 7.96] {
        // `{latency:?}` guarantees a float literal (e.g. `0.0`, not `0`) so the
        // Python oracle receives a float, matching real gateway usage.
        let params = format!(
            r#"{{"level":"INFO","provider":"cf","slot":2,"model":"m","latency_ms":{latency:?},"success":true,"error_code":"","message":"ok"}}"#
        );
        let (py_keys, py_obj) = oracle("log_gateway", &params);
        let entry = StructuredLogger::gateway_entry(
            "INFO", "cf", 2, "m", latency, true, "", "ok", &[],
        );
        let (r_keys, r_obj) = rust_repr(entry, "gateway");
        assert_eq!(py_keys, r_keys, "gateway key order latency={latency}");
        assert_eq!(py_obj, r_obj, "gateway values latency={latency}");
    }
}

#[test]
fn parity_unicode_message_not_escaped() {
    // ensure_ascii=False: non-ASCII must be preserved verbatim in both.
    let params = r#"{"level":"INFO","provider":"","slot":0,"model":"","error_code":"","message":"فیلترینگ هوشمند"}"#;
    let (py_keys, py_obj) = oracle("log_diagnostics", params);
    let entry = StructuredLogger::diagnostics_entry(
        "INFO", "", 0, "", "", "فیلترینگ هوشمند", &[],
    );
    let (r_keys, r_obj) = rust_repr(entry, "diagnostics");
    assert_eq!(py_keys, r_keys);
    assert_eq!(py_obj, r_obj);
}

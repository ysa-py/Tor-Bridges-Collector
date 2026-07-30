#![allow(warnings)]
// Parity tests for `src/retry_engine.rs` vs `gateway/retry_engine.py`.
//
// The Python `RetryEngine.decide()` uses non-deterministic jitter in
// `_compute_backoff`, so we inject a deterministic backoff function on
// both sides (Python via monkeypatching, Rust via the `with_backoff`
// constructor) and compare the resulting `RetryDecision` field-by-field.

use std::process::Command;

use serde_json::{json, Value};
use torshield_ir_ultra::retry_engine::{default_backoff, RetryAction, RetryConfig, RetryEngine};

/// Normalize numeric JSON values so `0` and `0.0` compare equal.
/// Python's `json.dumps` emits `0` for ints and `0.0` for floats; serde_json
/// preserves the distinction. We collapse both to f64 for parity comparison.
fn normalize_numbers(value: Value) -> Value {
    match value {
        Value::Number(n) => {
            let f = n
                .as_f64()
                .unwrap_or_else(|| panic!("JSON number not f64-convertible: {n:?}"));
            json!(f)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(normalize_numbers).collect()),
        Value::Object(obj) => {
            let mapped: serde_json::Map<String, Value> = obj
                .into_iter()
                .map(|(k, v)| (k, normalize_numbers(v)))
                .collect();
            Value::Object(mapped)
        }
        other => other,
    }
}

fn python_executable() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return std::path::PathBuf::from(path);
    }
    for candidate in [
        "/root/.pyenv/shims/python",
        "/usr/local/bin/python",
        "/usr/bin/python3",
    ] {
        let path = std::path::PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    std::path::PathBuf::from("python")
}

/// Run the Python `RetryEngine.decide()` with a deterministic backoff
/// function (always returns `delay_override`) and return the decision as
/// JSON. The Python `random.uniform` is also patched to a no-op so jitter
/// can't perturb the result.
fn python_decide(
    error_code: i64,
    attempt: i64,
    provider: &str,
    slot: i64,
    model: &str,
    delay_override: f64,
) -> Value {
    let script = format!(
        r#"
import json, random
from gateway.retry_engine import RetryEngine, RetryAction
engine = RetryEngine()
engine._compute_backoff = lambda attempt: {delay}
# Neutralize random jitter inside the original implementation (defensive —
# the override above already short-circuits _compute_backoff).
random.uniform = lambda a, b: 0.0
decision = engine.decide({error_code}, {attempt}, "{provider}", {slot}, "{model}")
out = {{
    "action": decision.action.value,
    "delay_secs": decision.delay_secs,
    "reason": decision.reason,
    "attempt_number": decision.attempt_number,
    "max_attempts": decision.max_attempts,
}}
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
"#,
        delay = delay_override,
        error_code = error_code,
        attempt = attempt,
        provider = provider,
        slot = slot,
        model = model,
    );
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python retry_engine helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn rust_decide(
    error_code: i64,
    attempt: i64,
    provider: &str,
    slot: i64,
    model: &str,
    delay_override: f64,
) -> Value {
    let engine = RetryEngine::with_backoff(RetryConfig::default(), move |_| delay_override);
    engine
        .decide(error_code, attempt, provider, slot, model)
        .to_json()
}

#[test]
fn parity_http_400_rotates_model() {
    let py = python_decide(400, 0, "cloudflare", 1, "llama-3", 0.0);
    let rs = rust_decide(400, 0, "cloudflare", 1, "llama-3", 0.0);
    assert_eq!(normalize_numbers(py), normalize_numbers(rs));
}

#[test]
fn parity_http_429_retry_same_with_backoff() {
    let py = python_decide(429, 0, "cloudflare", 1, "llama-3", 2.5);
    let rs = rust_decide(429, 0, "cloudflare", 1, "llama-3", 2.5);
    assert_eq!(normalize_numbers(py), normalize_numbers(rs));
}

#[test]
fn parity_http_429_max_retries_rotate_slot() {
    // Python default max_attempts_429 = 5 → attempt=5 triggers rotate
    let py = python_decide(429, 5, "cloudflare", 1, "llama-3", 0.0);
    let rs = rust_decide(429, 5, "cloudflare", 1, "llama-3", 0.0);
    assert_eq!(normalize_numbers(py), normalize_numbers(rs));
}

#[test]
fn parity_http_503_retry_same_then_rotate() {
    let py0 = python_decide(503, 0, "cloudflare", 1, "llama-3", 1.5);
    let rs0 = rust_decide(503, 0, "cloudflare", 1, "llama-3", 1.5);
    assert_eq!(normalize_numbers(py0), normalize_numbers(rs0));

    // Python default max_attempts_5xx = 3 → attempt=3 triggers rotate
    let py3 = python_decide(503, 3, "cloudflare", 1, "llama-3", 0.0);
    let rs3 = rust_decide(503, 3, "cloudflare", 1, "llama-3", 0.0);
    assert_eq!(normalize_numbers(py3), normalize_numbers(rs3));
}

#[test]
fn parity_http_401_rotates_slot() {
    let py = python_decide(401, 0, "cloudflare", 1, "llama-3", 0.0);
    let rs = rust_decide(401, 0, "cloudflare", 1, "llama-3", 0.0);
    assert_eq!(normalize_numbers(py), normalize_numbers(rs));
}

#[test]
fn parity_http_403_rotates_slot() {
    let py = python_decide(403, 0, "cloudflare", 1, "llama-3", 0.0);
    let rs = rust_decide(403, 0, "cloudflare", 1, "llama-3", 0.0);
    assert_eq!(normalize_numbers(py), normalize_numbers(rs));
}

#[test]
fn parity_timeout_rotates_immediately() {
    let py = python_decide(0, 0, "cloudflare", 1, "llama-3", 0.0);
    let rs = rust_decide(0, 0, "cloudflare", 1, "llama-3", 0.0);
    assert_eq!(normalize_numbers(py), normalize_numbers(rs));
}

#[test]
fn parity_unknown_code_rotates_slot() {
    let py = python_decide(418, 0, "cloudflare", 1, "llama-3", 0.0);
    let rs = rust_decide(418, 0, "cloudflare", 1, "llama-3", 0.0);
    assert_eq!(normalize_numbers(py), normalize_numbers(rs));
}

#[test]
fn default_backoff_curve_matches_python_algorithm() {
    // Python: base_delay = min(2 ** attempt, self._backoff_cap)
    // The default cap is 60.0; jitter is non-deterministic so we test the
    // base curve only. Default Rust `default_backoff` omits jitter.
    assert_eq!(default_backoff(0), 1.0); // 2^0 = 1
    assert_eq!(default_backoff(1), 2.0); // 2^1 = 2
    assert_eq!(default_backoff(2), 4.0); // 2^2 = 4
    assert_eq!(default_backoff(3), 8.0); // 2^3 = 8
    assert_eq!(default_backoff(6), 60.0); // 2^6 = 64, capped to 60
}

#[test]
fn retry_action_strings_match_python_enum_values() {
    assert_eq!(RetryAction::RetrySame.as_str(), "retry_same");
    assert_eq!(RetryAction::RotateModel.as_str(), "rotate_model");
    assert_eq!(RetryAction::RotateSlot.as_str(), "rotate_slot");
    assert_eq!(RetryAction::RotateProvider.as_str(), "rotate_provider");
    assert_eq!(RetryAction::Fail.as_str(), "fail");
}

#[test]
fn decision_json_shape_includes_all_python_dataclass_fields() {
    let engine = RetryEngine::new(RetryConfig::default());
    let json = engine.decide(429, 0, "", 0, "").to_json();
    let obj = json.as_object().expect("decision must serialize to object");
    for key in [
        "action",
        "delay_secs",
        "reason",
        "attempt_number",
        "max_attempts",
    ] {
        assert!(
            obj.contains_key(key),
            "missing field {key} in decision JSON"
        );
    }
    // Smoke-check a specific value to ensure the JSON isn't all-null.
    assert_eq!(json["action"], json!("retry_same"));
}

#![allow(warnings)]
// Parity tests for `src/feature_flags.rs` vs `config/feature_flags.py`.
//
// Each test invokes a fresh Python interpreter on `config/feature_flags.py`,
// captures the JSON output of `get_all_config()`, and asserts byte-identical
// output from the Rust port under the same environment.

use std::{collections::BTreeMap, process::Command};

use serde_json::Value;
use torshield_ir_ultra::feature_flags::{EnvMap, FeatureFlags};

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

use std::path::PathBuf;

fn python_config(env: &BTreeMap<&str, &str>) -> Value {
    let script = r#"
import json
from config.feature_flags import get_all_config
print(json.dumps(get_all_config(), sort_keys=True, separators=(",", ":")))
"#;
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let mut command = Command::new(python_executable());
    command
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python feature_flags parity helper must execute: {err}"));
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

fn rust_config(env: &BTreeMap<&str, &str>) -> Value {
    let mapped: EnvMap = env
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    FeatureFlags::from_env_map(&mapped)
        .unwrap_or_else(|err| panic!("rust feature_flags parsed valid env: {err}"))
        .get_all_config()
}

#[test]
fn parity_default_config() {
    let env = BTreeMap::new();
    assert_eq!(rust_config(&env), python_config(&env));
}

#[test]
fn parity_overridden_flags_and_params() {
    let env = BTreeMap::from([
        ("ENABLE_CIRCUIT_BREAKER", "false"),
        ("ENABLE_TELEMETRY", "false"),
        ("ENABLE_UTLS_EVASION", "false"),
        ("ENABLE_ANTI_DPI_IRAN", "FALSE"),
        ("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "7"),
        ("CIRCUIT_BREAKER_COOLDOWN_SECS", "90.5"),
        ("CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES", "3"),
        ("RETRY_MAX_ATTEMPTS_400", "1"),
        ("RETRY_MAX_ATTEMPTS_429", "9"),
        ("RETRY_MAX_ATTEMPTS_5XX", "4"),
        ("RETRY_BACKOFF_CAP_SECS", "120.25"),
        ("SELF_HEAL_TRIGGER_THRESHOLD", "5"),
        ("SELF_HEAL_COOLDOWN_SECS", "600.0"),
        ("MODEL_REGISTRY_REFRESH_HOURS", "12"),
        ("IRST_HIGH_CENSORSHIP_START", "17"),
        ("IRST_HIGH_CENSORSHIP_END", "2"),
        ("IRST_ULTRA_STEALTH_START", "21"),
        ("IRST_ULTRA_STEALTH_END", "23"),
        (
            "PROVIDER_FALLBACK_ORDER",
            "cerebras,portkey,cloudflare_ai_gateway",
        ),
        ("LOG_DIR", "custom_logs"),
        ("LOG_MAX_MB", "25"),
    ]);
    assert_eq!(rust_config(&env), python_config(&env));
}

#[test]
fn parity_invalid_int_env_propagates_typed_error() {
    let mapped = EnvMap::from([(
        "CIRCUIT_BREAKER_FAILURE_THRESHOLD".to_string(),
        "not-an-int".to_string(),
    )]);
    let err = FeatureFlags::from_env_map(&mapped).unwrap_err();
    assert_eq!(
        err,
        torshield_ir_ultra::feature_flags::FeatureFlagError::InvalidInt {
            name: "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
            value: "not-an-int".to_string(),
        }
    );
}

#[test]
fn parity_invalid_float_env_propagates_typed_error() {
    let mapped = EnvMap::from([(
        "RETRY_BACKOFF_CAP_SECS".to_string(),
        "not-a-float".to_string(),
    )]);
    let err = FeatureFlags::from_env_map(&mapped).unwrap_err();
    assert_eq!(
        err,
        torshield_ir_ultra::feature_flags::FeatureFlagError::InvalidFloat {
            name: "RETRY_BACKOFF_CAP_SECS",
            value: "not-a-float".to_string(),
        }
    );
}

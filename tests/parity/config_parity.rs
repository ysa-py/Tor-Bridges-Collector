use std::{collections::BTreeMap, path::PathBuf, process::Command};

use serde_json::{json, Value};
use torshield_ir_ultra::config::{from_env_map, ConfigError, EnvMap};

const CONFIG_KEYS: &[&str] = &[
    "MAX_WORKERS", "CONNECTION_TIMEOUT", "SSL_TIMEOUT", "MAX_RETRIES", "MAX_TEST_PER_TYPE",
    "RECENT_HOURS", "HISTORY_RETENTION_DAYS", "BRIDGE_DIR", "EXPORT_DIR", "HISTORY_FILE",
    "SCORES_FILE", "REPO_URL", "IS_GITHUB", "CF_N_SLOTS", "CF_ACCOUNT_IDS", "CF_API_TOKENS",
    "CF_AI_GATEWAY_URLS", "CF_VALID_SLOTS", "CEREBRAS_API_KEY", "PORTKEY_API_KEY",
    "PORTKEY_GATEWAY_URL", "PORTKEY_VIRTUAL_KEYS", "GROQ_API_KEY", "GITHUB_TOKEN",
    "GITHUB_REPOSITORY", "GITHUB_SHA", "GH_PAT_AUTOFIX", "GH_REPO_OWNER", "GH_REPO_NAME",
    "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_UPLOAD", "HTTP_PROXY", "HTTPS_PROXY",
    "USE_TORPROJECT_SCRAPER", "USE_MOAT_API", "USE_BRIDGEDB_API", "USE_TELEGRAM_SOURCES",
    "USE_STATIC_BRIDGES", "USE_GITHUB_SOURCES", "DEEP_TEST", "IRAN_PREFERRED_PORTS",
    "IRAN_CDN_FRONTS", "NIN_MODE", "IRAN_BRIDGE_PRIORITIZATION_ENABLED",
    "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT", "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT",
    "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY", "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY",
    "RIPE_ATLAS_API_KEY", "ANTI_DPI_MODE", "ANTI_FILTER_MODE", "TORSHIELD_IRAN_MODE",
    "AUTO_DEBUG_MODE", "UTLS_EVASION_MODE", "UTLS_PROFILE_ROTATION", "ELITE_REGISTRY_ENABLED",
    "ELITE_REGISTRY_REFRESH_HRS", "CIRCUIT_BREAKER_ENABLED", "CIRCUIT_BREAKER_MAX_FAILURES",
    "CIRCUIT_BREAKER_RESET_SECS", "SESSION_BLACKLIST_DURATION_SECS", "TELEMETRY_ENABLED",
    "TELEMETRY_AUTO_DEBUG_THRESHOLD", "TELEMETRY_LOG_MAX_MB", "IRST_HIGH_CENSORSHIP_START",
    "IRST_HIGH_CENSORSHIP_END", "IRST_ULTRA_STEALTH_START", "IRST_ULTRA_STEALTH_END",
];


fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    for candidate in ["/root/.pyenv/shims/python", "/usr/local/bin/python", "/usr/bin/python3"] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("python")
}

fn python_config(env: &BTreeMap<&str, &str>) -> Value {
    let keys_json = serde_json::to_string(CONFIG_KEYS)
        .unwrap_or_else(|err| panic!("config key list must serialize: {err}"));
    let script = format!(
        r#"
import json
import config
keys = {keys}
print(json.dumps({{key: getattr(config, key) for key in keys}}, sort_keys=True, separators=(",", ":")))
"#,
        keys = keys_json
    );
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let mut command = Command::new(python_executable());
    command.current_dir(repo_root).env_clear().env("PYTHONPATH", repo_root);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.arg("-c").arg(script).output().unwrap_or_else(|err| {
        panic!("python config parity helper must execute: {err}");
    });
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!("python helper must emit JSON: {err}; stdout={}", String::from_utf8_lossy(&output.stdout));
    })
}

fn rust_config(env: &BTreeMap<&str, &str>) -> Value {
    let mapped: EnvMap = env.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
    from_env_map(&mapped)
        .unwrap_or_else(|err| panic!("rust config parsed valid env: {err}"))
        .to_json_value()
}

#[test]
fn parity_default_import_time_config() {
    let env = BTreeMap::new();
    assert_eq!(rust_config(&env), python_config(&env));
}

#[test]
fn parity_overridden_config_and_slot_filtering() {
    let env = BTreeMap::from([
        ("MAX_WORKERS", "7"),
        ("CONNECTION_TIMEOUT", "1.25"),
        ("SSL_TIMEOUT", "2.5"),
        ("MAX_RETRIES", "4"),
        ("MAX_TEST_PER_TYPE", "9"),
        ("RECENT_HOURS", "12"),
        ("HISTORY_RETENTION_DAYS", "3"),
        ("BRIDGE_DIR", "custom_bridge"),
        ("EXPORT_DIR", "custom_export"),
        ("REPO_URL", "https://example.invalid/repo"),
        ("GITHUB_ACTIONS", "true"),
        ("CF_N_SLOTS", "3"),
        ("CF_ACCOUNT_ID_1", " acc-one "),
        ("CF_API_TOKEN_1", " tok-one "),
        ("CF_AI_GATEWAY_URL_1", " gw-one "),
        ("CF_ACCOUNT_ID_2", "acc-two"),
        ("CF_API_TOKEN_2", ""),
        ("CF_AI_GATEWAY_URL_2", "gw-two"),
        ("CF_ACCOUNT_ID_3", "acc-three"),
        ("CF_API_TOKEN_3", "tok-three"),
        ("CF_AI_GATEWAY_URL_3", ""),
        ("CEREBRAS_API_KEY", "cerebras"),
        ("PORTKEY_API_KEY", "portkey"),
        ("PORTKEY_GATEWAY_URL", "https://gateway.example"),
        ("PORTKEY_VIRTUAL_KEY_1", "pvk1"),
        ("PORTKEY_VIRTUAL_KEY_2", "pvk2"),
        ("PORTKEY_VIRTUAL_KEY_3", "pvk3"),
        ("GROQ_API_KEY", "groq"),
        ("GITHUB_TOKEN", "gh-token"),
        ("GITHUB_REPOSITORY", "owner/repo"),
        ("GITHUB_SHA", "abc123"),
        ("GH_PAT_AUTOFIX", "pat"),
        ("GH_REPO_OWNER", "owner"),
        ("GH_REPO_NAME", "repo"),
        ("TELEGRAM_BOT_TOKEN", "bot"),
        ("TELEGRAM_CHAT_ID", "chat"),
        ("TELEGRAM_UPLOAD", "TRUE"),
        ("HTTP_PROXY", "socks5://127.0.0.1:9050"),
        ("HTTPS_PROXY", "http://127.0.0.1:8080"),
        ("USE_TORPROJECT_SCRAPER", "false"),
        ("USE_MOAT_API", "false"),
        ("USE_BRIDGEDB_API", "false"),
        ("USE_TELEGRAM_SOURCES", "true"),
        ("USE_STATIC_BRIDGES", "false"),
        ("USE_GITHUB_SOURCES", "false"),
        ("DEEP_TEST", "true"),
        ("NIN_MODE", "true"),
        ("IRAN_BRIDGE_PRIORITIZATION_ENABLED", "true"),
        ("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT", "2.0"),
        ("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT", "3.5"),
        ("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY", "4.25"),
        ("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY", "5.75"),
        ("RIPE_ATLAS_API_KEY", "ripe"),
        ("ANTI_DPI_MODE", "true"),
        ("ANTI_FILTER_MODE", "true"),
        ("TORSHIELD_IRAN_MODE", "true"),
        ("AUTO_DEBUG_MODE", "true"),
        ("UTLS_EVASION_MODE", "false"),
        ("UTLS_PROFILE_ROTATION", "61"),
        ("ELITE_REGISTRY_ENABLED", "false"),
        ("ELITE_REGISTRY_REFRESH_HRS", "8"),
        ("CIRCUIT_BREAKER_ENABLED", "false"),
        ("CIRCUIT_BREAKER_MAX_FAILURES", "6"),
        ("CIRCUIT_BREAKER_RESET_SECS", "42.5"),
        ("SESSION_BLACKLIST_DURATION_SECS", "84.25"),
        ("TELEMETRY_ENABLED", "false"),
        ("TELEMETRY_AUTO_DEBUG_THRESHOLD", "5"),
        ("TELEMETRY_LOG_MAX_MB", "11"),
        ("IRST_HIGH_CENSORSHIP_START", "17"),
        ("IRST_HIGH_CENSORSHIP_END", "2"),
        ("IRST_ULTRA_STEALTH_START", "21"),
        ("IRST_ULTRA_STEALTH_END", "23"),
    ]);
    assert_eq!(rust_config(&env), python_config(&env));
}

#[test]
fn invalid_integer_env_is_reported_without_panic() {
    let mapped = EnvMap::from([("MAX_WORKERS".to_string(), "not-an-int".to_string())]);
    assert_eq!(
        from_env_map(&mapped).unwrap_err(),
        ConfigError::InvalidInt {
            name: "MAX_WORKERS",
            value: "not-an-int".to_string()
        }
    );
}

#[test]
fn invalid_float_env_is_reported_without_panic() {
    let mapped = EnvMap::from([("CONNECTION_TIMEOUT".to_string(), "not-a-float".to_string())]);
    assert_eq!(
        from_env_map(&mapped).unwrap_err(),
        ConfigError::InvalidFloat {
            name: "CONNECTION_TIMEOUT",
            value: "not-a-float".to_string()
        }
    );
}

#[test]
fn parity_python_invalid_integer_import_fails() {
    let env = BTreeMap::from([("MAX_WORKERS", "not-an-int")]);
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .env("MAX_WORKERS", env["MAX_WORKERS"])
        .arg("-c")
        .arg("import config")
        .output()
        .unwrap_or_else(|err| panic!("python invalid-env helper must execute: {err}"));
    assert!(!output.status.success(), "Python import should fail on invalid int env");
}

#[test]
fn config_json_shape_includes_all_python_constants() {
    let value = rust_config(&BTreeMap::new());
    assert_eq!(value.as_object().map(|object| object.len()), Some(CONFIG_KEYS.len()));
    assert_eq!(value["IRAN_PREFERRED_PORTS"], json!([443, 80, 8080, 8443, 2083, 2087, 2096]));
}

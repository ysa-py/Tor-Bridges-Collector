//! Parity port of `config/feature_flags.py`.
//!
//! Centralized feature flags and tuning parameters for the TorShield-IR
//! runtime. All flags default to ON (matching the Python "secure by default"
//! policy) and are overridden via environment variables. The Python original
//! is the source of truth until every importer has a parity-verified Rust
//! replacement.

use std::collections::BTreeMap;

use serde_json::{json, Value};

/// Typed errors for Python-compatible feature-flag parsing.
#[derive(Debug, Eq, PartialEq)]
pub enum FeatureFlagError {
    InvalidInt { name: &'static str, value: String },
    InvalidFloat { name: &'static str, value: String },
}

impl std::fmt::Display for FeatureFlagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInt { name, value } => write!(f, "invalid integer for {name}: {value}"),
            Self::InvalidFloat { name, value } => write!(f, "invalid float for {name}: {value}"),
        }
    }
}

impl std::error::Error for FeatureFlagError {}

/// Mirror of Python's `os.getenv` map — keys are uppercase env var names,
/// values are the raw string values (already trimmed by the caller if needed).
pub type EnvMap = BTreeMap<String, String>;

fn parse_bool(env: &EnvMap, name: &str, default: bool) -> bool {
    match env.get(name) {
        Some(value) => value.eq_ignore_ascii_case("true"),
        None => default,
    }
}

fn parse_int(env: &EnvMap, name: &'static str, default: i64) -> Result<i64, FeatureFlagError> {
    match env.get(name) {
        Some(value) => value
            .parse::<i64>()
            .map_err(|_| FeatureFlagError::InvalidInt {
                name,
                value: value.clone(),
            }),
        None => Ok(default),
    }
}

fn parse_float(env: &EnvMap, name: &'static str, default: f64) -> Result<f64, FeatureFlagError> {
    match env.get(name) {
        Some(value) => value
            .parse::<f64>()
            .map_err(|_| FeatureFlagError::InvalidFloat {
                name,
                value: value.clone(),
            }),
        None => Ok(default),
    }
}

fn parse_str(env: &EnvMap, name: &str, default: &str) -> String {
    env.get(name)
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn parse_csv(env: &EnvMap, name: &str, default: &str) -> Vec<String> {
    match env.get(name) {
        Some(value) => value.split(',').map(|s| s.to_string()).collect(),
        None => default.split(',').map(|s| s.to_string()).collect(),
    }
}

/// Snapshot of every constant exported by `config/feature_flags.py`.
#[derive(Debug, Clone, PartialEq)]
pub struct FeatureFlags {
    pub enable_endpoint_validation: bool,
    pub enable_circuit_breaker: bool,
    pub enable_model_registry: bool,
    pub enable_retry_failover: bool,
    pub enable_self_healing: bool,
    pub enable_structured_logging: bool,
    pub enable_report_generation: bool,
    pub enable_anti_dpi_iran: bool,
    pub enable_utls_evasion: bool,
    pub enable_irst_routing: bool,
    pub enable_compat_path_fix: bool,
    pub enable_telemetry: bool,

    pub circuit_breaker_failure_threshold: i64,
    pub circuit_breaker_cooldown_secs: f64,
    pub circuit_breaker_half_open_max_probes: i64,

    pub retry_max_attempts_400: i64,
    pub retry_max_attempts_429: i64,
    pub retry_max_attempts_5xx: i64,
    pub retry_backoff_cap_secs: f64,

    pub self_heal_trigger_threshold: i64,
    pub self_heal_cooldown_secs: f64,

    pub model_registry_refresh_hours: i64,

    pub irst_high_censorship_start: i64,
    pub irst_high_censorship_end: i64,
    pub irst_ultra_stealth_start: i64,
    pub irst_ultra_stealth_end: i64,

    pub provider_fallback_order: Vec<String>,

    pub log_dir: String,
    pub log_max_mb: i64,
}

impl FeatureFlags {
    /// Parse feature flags from the given environment map.
    /// Mirrors the import-time side effects in `config/feature_flags.py`.
    pub fn from_env_map(env: &EnvMap) -> Result<Self, FeatureFlagError> {
        Ok(Self {
            enable_endpoint_validation: parse_bool(env, "ENABLE_ENDPOINT_VALIDATION", true),
            enable_circuit_breaker: parse_bool(env, "ENABLE_CIRCUIT_BREAKER", true),
            enable_model_registry: parse_bool(env, "ENABLE_MODEL_REGISTRY", true),
            enable_retry_failover: parse_bool(env, "ENABLE_RETRY_FAILOVER", true),
            enable_self_healing: parse_bool(env, "ENABLE_SELF_HEALING", true),
            enable_structured_logging: parse_bool(env, "ENABLE_STRUCTURED_LOGGING", true),
            enable_report_generation: parse_bool(env, "ENABLE_REPORT_GENERATION", true),
            enable_anti_dpi_iran: parse_bool(env, "ENABLE_ANTI_DPI_IRAN", true),
            enable_utls_evasion: parse_bool(env, "ENABLE_UTLS_EVASION", true),
            enable_irst_routing: parse_bool(env, "ENABLE_IRST_ROUTING", true),
            enable_compat_path_fix: parse_bool(env, "ENABLE_COMPAT_PATH_FIX", true),
            enable_telemetry: parse_bool(env, "ENABLE_TELEMETRY", true),

            circuit_breaker_failure_threshold: parse_int(
                env,
                "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
                3,
            )?,
            circuit_breaker_cooldown_secs: parse_float(env, "CIRCUIT_BREAKER_COOLDOWN_SECS", 60.0)?,
            circuit_breaker_half_open_max_probes: parse_int(
                env,
                "CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES",
                1,
            )?,

            retry_max_attempts_400: parse_int(env, "RETRY_MAX_ATTEMPTS_400", 0)?,
            retry_max_attempts_429: parse_int(env, "RETRY_MAX_ATTEMPTS_429", 5)?,
            retry_max_attempts_5xx: parse_int(env, "RETRY_MAX_ATTEMPTS_5XX", 3)?,
            retry_backoff_cap_secs: parse_float(env, "RETRY_BACKOFF_CAP_SECS", 60.0)?,

            self_heal_trigger_threshold: parse_int(env, "SELF_HEAL_TRIGGER_THRESHOLD", 2)?,
            self_heal_cooldown_secs: parse_float(env, "SELF_HEAL_COOLDOWN_SECS", 300.0)?,

            model_registry_refresh_hours: parse_int(env, "MODEL_REGISTRY_REFRESH_HOURS", 6)?,

            irst_high_censorship_start: parse_int(env, "IRST_HIGH_CENSORSHIP_START", 18)?,
            irst_high_censorship_end: parse_int(env, "IRST_HIGH_CENSORSHIP_END", 1)?,
            irst_ultra_stealth_start: parse_int(env, "IRST_ULTRA_STEALTH_START", 20)?,
            irst_ultra_stealth_end: parse_int(env, "IRST_ULTRA_STEALTH_END", 23)?,

            provider_fallback_order: parse_csv(
                env,
                "PROVIDER_FALLBACK_ORDER",
                "cloudflare_ai_gateway,cloudflare_workers_ai,cerebras,portkey",
            ),

            log_dir: parse_str(env, "LOG_DIR", "logs"),
            log_max_mb: parse_int(env, "LOG_MAX_MB", 10)?,
        })
    }

    /// Mirror of `get_all_flags()` — returns the 12 boolean flags keyed by
    /// their Python constant name.
    pub fn get_all_flags(&self) -> Value {
        json!({
            "ENABLE_ENDPOINT_VALIDATION": self.enable_endpoint_validation,
            "ENABLE_CIRCUIT_BREAKER": self.enable_circuit_breaker,
            "ENABLE_MODEL_REGISTRY": self.enable_model_registry,
            "ENABLE_RETRY_FAILOVER": self.enable_retry_failover,
            "ENABLE_SELF_HEALING": self.enable_self_healing,
            "ENABLE_STRUCTURED_LOGGING": self.enable_structured_logging,
            "ENABLE_REPORT_GENERATION": self.enable_report_generation,
            "ENABLE_ANTI_DPI_IRAN": self.enable_anti_dpi_iran,
            "ENABLE_UTLS_EVASION": self.enable_utls_evasion,
            "ENABLE_IRST_ROUTING": self.enable_irst_routing,
            "ENABLE_COMPAT_PATH_FIX": self.enable_compat_path_fix,
            "ENABLE_TELEMETRY": self.enable_telemetry,
        })
    }

    /// Mirror of `get_all_config()` — nested dictionary combining feature
    /// flags and tuning parameters. Used by the parity test to compare
    /// Rust vs Python output verbatim.
    pub fn get_all_config(&self) -> Value {
        json!({
            "feature_flags": self.get_all_flags(),
            "circuit_breaker": {
                "failure_threshold": self.circuit_breaker_failure_threshold,
                "cooldown_secs": self.circuit_breaker_cooldown_secs,
                "half_open_max_probes": self.circuit_breaker_half_open_max_probes,
            },
            "retry": {
                "max_attempts_400": self.retry_max_attempts_400,
                "max_attempts_429": self.retry_max_attempts_429,
                "max_attempts_5xx": self.retry_max_attempts_5xx,
                "backoff_cap_secs": self.retry_backoff_cap_secs,
            },
            "self_healing": {
                "trigger_threshold": self.self_heal_trigger_threshold,
                "cooldown_secs": self.self_heal_cooldown_secs,
            },
            "model_registry": {
                "refresh_hours": self.model_registry_refresh_hours,
            },
            "irst": {
                "high_censorship_start": self.irst_high_censorship_start,
                "high_censorship_end": self.irst_high_censorship_end,
                "ultra_stealth_start": self.irst_ultra_stealth_start,
                "ultra_stealth_end": self.irst_ultra_stealth_end,
            },
            "provider_fallback_order": self.provider_fallback_order,
            "logging": {
                "log_dir": self.log_dir,
                "log_max_mb": self.log_max_mb,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_python_constants() {
        let flags = FeatureFlags::from_env_map(&EnvMap::new()).unwrap();
        assert!(flags.enable_endpoint_validation);
        assert!(flags.enable_circuit_breaker);
        assert_eq!(flags.circuit_breaker_failure_threshold, 3);
        assert_eq!(flags.circuit_breaker_cooldown_secs, 60.0);
        assert_eq!(flags.retry_max_attempts_429, 5);
        assert_eq!(
            flags.provider_fallback_order,
            vec![
                "cloudflare_ai_gateway".to_string(),
                "cloudflare_workers_ai".to_string(),
                "cerebras".to_string(),
                "portkey".to_string(),
            ]
        );
    }

    #[test]
    fn invalid_int_env_reports_typed_error() {
        let mut env = EnvMap::new();
        env.insert(
            "CIRCUIT_BREAKER_FAILURE_THRESHOLD".to_string(),
            "not-an-int".to_string(),
        );
        let err = FeatureFlags::from_env_map(&env).unwrap_err();
        assert_eq!(
            err,
            FeatureFlagError::InvalidInt {
                name: "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
                value: "not-an-int".to_string(),
            }
        );
    }

    #[test]
    fn invalid_float_env_reports_typed_error() {
        let mut env = EnvMap::new();
        env.insert(
            "RETRY_BACKOFF_CAP_SECS".to_string(),
            "not-a-float".to_string(),
        );
        let err = FeatureFlags::from_env_map(&env).unwrap_err();
        assert_eq!(
            err,
            FeatureFlagError::InvalidFloat {
                name: "RETRY_BACKOFF_CAP_SECS",
                value: "not-a-float".to_string(),
            }
        );
    }

    #[test]
    fn bool_env_is_case_insensitive() {
        let mut env = EnvMap::new();
        env.insert("ENABLE_CIRCUIT_BREAKER".to_string(), "FALSE".to_string());
        env.insert("ENABLE_TELEMETRY".to_string(), "False".to_string());
        let flags = FeatureFlags::from_env_map(&env).unwrap();
        assert!(!flags.enable_circuit_breaker);
        assert!(!flags.enable_telemetry);
    }
}

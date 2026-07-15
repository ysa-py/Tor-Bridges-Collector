//! Parity port of `config.py`.
//!
//! The Python module is still the source of truth until every importing module
//! has a verified Rust replacement. This module mirrors `config.py`'s import-time
//! environment parsing so parity tests can compare Rust values against a fresh
//! Python interpreter under the same environment.

use std::collections::BTreeMap;

const DEFAULT_REPO_URL: &str =
    "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main";
const DEFAULT_PORTKEY_GATEWAY_URL: &str = "https://api.portkey.ai/v1";

/// Typed errors for Python-compatible configuration parsing.
#[derive(Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidInt { name: &'static str, value: String },
    InvalidFloat { name: &'static str, value: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInt { name, value } => {
                write!(f, "invalid integer for {name}: {value}")
            }
            Self::InvalidFloat { name, value } => {
                write!(f, "invalid float for {name}: {value}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Complete snapshot of `config.py` module-level constants.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub max_workers: i64,
    pub connection_timeout: f64,
    pub ssl_timeout: f64,
    pub max_retries: i64,
    pub max_test_per_type: i64,
    pub recent_hours: i64,
    pub history_retention_days: i64,
    pub bridge_dir: String,
    pub export_dir: String,
    pub history_file: String,
    pub scores_file: String,
    pub repo_url: String,
    pub is_github: bool,
    pub cf_n_slots: i64,
    pub cf_account_ids: Vec<String>,
    pub cf_api_tokens: Vec<String>,
    pub cf_ai_gateway_urls: Vec<String>,
    pub cf_valid_slots: Vec<(String, String, String)>,
    pub cerebras_api_key: String,
    pub portkey_api_key: String,
    pub portkey_gateway_url: String,
    pub portkey_virtual_keys: Vec<String>,
    pub groq_api_key: String,
    pub github_token: String,
    pub github_repository: String,
    pub github_sha: String,
    pub gh_pat_autofix: String,
    pub gh_repo_owner: String,
    pub gh_repo_name: String,
    pub telegram_bot_token: String,
    pub telegram_chat_id: String,
    pub telegram_upload: bool,
    pub http_proxy: String,
    pub https_proxy: String,
    pub use_torproject_scraper: bool,
    pub use_moat_api: bool,
    pub use_bridgedb_api: bool,
    pub use_telegram_sources: bool,
    pub use_static_bridges: bool,
    pub use_github_sources: bool,
    pub deep_test: bool,
    pub iran_preferred_ports: Vec<i64>,
    pub iran_cdn_fronts: Vec<String>,
    pub nin_mode: bool,
    pub iran_bridge_prioritization_enabled: bool,
    pub iran_bridge_prioritization_weight_port: f64,
    pub iran_bridge_prioritization_weight_transport: f64,
    pub iran_bridge_prioritization_weight_recency: f64,
    pub iran_bridge_prioritization_weight_reachability: f64,
    pub ripe_atlas_api_key: String,
    pub anti_dpi_mode: bool,
    pub anti_filter_mode: bool,
    pub torshield_iran_mode: bool,
    pub auto_debug_mode: bool,
    pub utls_evasion_mode: bool,
    pub utls_profile_rotation: i64,
    pub elite_registry_enabled: bool,
    pub elite_registry_refresh_hrs: i64,
    pub circuit_breaker_enabled: bool,
    pub circuit_breaker_max_failures: i64,
    pub circuit_breaker_reset_secs: f64,
    pub session_blacklist_duration_secs: f64,
    pub telemetry_enabled: bool,
    pub telemetry_auto_debug_threshold: i64,
    pub telemetry_log_max_mb: i64,
    pub irst_high_censorship_start: i64,
    pub irst_high_censorship_end: i64,
    pub irst_ultra_stealth_start: i64,
    pub irst_ultra_stealth_end: i64,
}

impl Config {
    /// Serialize with Python module constant names for parity comparisons.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "MAX_WORKERS": self.max_workers,
            "CONNECTION_TIMEOUT": self.connection_timeout,
            "SSL_TIMEOUT": self.ssl_timeout,
            "MAX_RETRIES": self.max_retries,
            "MAX_TEST_PER_TYPE": self.max_test_per_type,
            "RECENT_HOURS": self.recent_hours,
            "HISTORY_RETENTION_DAYS": self.history_retention_days,
            "BRIDGE_DIR": self.bridge_dir,
            "EXPORT_DIR": self.export_dir,
            "HISTORY_FILE": self.history_file,
            "SCORES_FILE": self.scores_file,
            "REPO_URL": self.repo_url,
            "IS_GITHUB": self.is_github,
            "CF_N_SLOTS": self.cf_n_slots,
            "CF_ACCOUNT_IDS": self.cf_account_ids,
            "CF_API_TOKENS": self.cf_api_tokens,
            "CF_AI_GATEWAY_URLS": self.cf_ai_gateway_urls,
            "CF_VALID_SLOTS": self.cf_valid_slots,
            "CEREBRAS_API_KEY": self.cerebras_api_key,
            "PORTKEY_API_KEY": self.portkey_api_key,
            "PORTKEY_GATEWAY_URL": self.portkey_gateway_url,
            "PORTKEY_VIRTUAL_KEYS": self.portkey_virtual_keys,
            "GROQ_API_KEY": self.groq_api_key,
            "GITHUB_TOKEN": self.github_token,
            "GITHUB_REPOSITORY": self.github_repository,
            "GITHUB_SHA": self.github_sha,
            "GH_PAT_AUTOFIX": self.gh_pat_autofix,
            "GH_REPO_OWNER": self.gh_repo_owner,
            "GH_REPO_NAME": self.gh_repo_name,
            "TELEGRAM_BOT_TOKEN": self.telegram_bot_token,
            "TELEGRAM_CHAT_ID": self.telegram_chat_id,
            "TELEGRAM_UPLOAD": self.telegram_upload,
            "HTTP_PROXY": self.http_proxy,
            "HTTPS_PROXY": self.https_proxy,
            "USE_TORPROJECT_SCRAPER": self.use_torproject_scraper,
            "USE_MOAT_API": self.use_moat_api,
            "USE_BRIDGEDB_API": self.use_bridgedb_api,
            "USE_TELEGRAM_SOURCES": self.use_telegram_sources,
            "USE_STATIC_BRIDGES": self.use_static_bridges,
            "USE_GITHUB_SOURCES": self.use_github_sources,
            "DEEP_TEST": self.deep_test,
            "IRAN_PREFERRED_PORTS": self.iran_preferred_ports,
            "IRAN_CDN_FRONTS": self.iran_cdn_fronts,
            "NIN_MODE": self.nin_mode,
            "IRAN_BRIDGE_PRIORITIZATION_ENABLED": self.iran_bridge_prioritization_enabled,
            "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT": self.iran_bridge_prioritization_weight_port,
            "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT": self.iran_bridge_prioritization_weight_transport,
            "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY": self.iran_bridge_prioritization_weight_recency,
            "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY": self.iran_bridge_prioritization_weight_reachability,
            "RIPE_ATLAS_API_KEY": self.ripe_atlas_api_key,
            "ANTI_DPI_MODE": self.anti_dpi_mode,
            "ANTI_FILTER_MODE": self.anti_filter_mode,
            "TORSHIELD_IRAN_MODE": self.torshield_iran_mode,
            "AUTO_DEBUG_MODE": self.auto_debug_mode,
            "UTLS_EVASION_MODE": self.utls_evasion_mode,
            "UTLS_PROFILE_ROTATION": self.utls_profile_rotation,
            "ELITE_REGISTRY_ENABLED": self.elite_registry_enabled,
            "ELITE_REGISTRY_REFRESH_HRS": self.elite_registry_refresh_hrs,
            "CIRCUIT_BREAKER_ENABLED": self.circuit_breaker_enabled,
            "CIRCUIT_BREAKER_MAX_FAILURES": self.circuit_breaker_max_failures,
            "CIRCUIT_BREAKER_RESET_SECS": self.circuit_breaker_reset_secs,
            "SESSION_BLACKLIST_DURATION_SECS": self.session_blacklist_duration_secs,
            "TELEMETRY_ENABLED": self.telemetry_enabled,
            "TELEMETRY_AUTO_DEBUG_THRESHOLD": self.telemetry_auto_debug_threshold,
            "TELEMETRY_LOG_MAX_MB": self.telemetry_log_max_mb,
            "IRST_HIGH_CENSORSHIP_START": self.irst_high_censorship_start,
            "IRST_HIGH_CENSORSHIP_END": self.irst_high_censorship_end,
            "IRST_ULTRA_STEALTH_START": self.irst_ultra_stealth_start,
            "IRST_ULTRA_STEALTH_END": self.irst_ultra_stealth_end,
        })
    }

    /// Build a config snapshot from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Build a config snapshot from an injected lookup for deterministic parity tests.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |name: &'static str, default: &'static str| {
            lookup(name).unwrap_or_else(|| default.to_string())
        };
        let get_trimmed =
            |name: &'static str, default: &'static str| get(name, default).trim().to_string();
        let int = |name: &'static str, default: &'static str| parse_int(name, &get(name, default));
        let float =
            |name: &'static str, default: &'static str| parse_float(name, &get(name, default));
        let boolv =
            |name: &'static str, default: &'static str| get(name, default).to_lowercase() == "true";

        let bridge_dir = get("BRIDGE_DIR", "bridge");
        let export_dir = get("EXPORT_DIR", "export");
        let cf_n_slots = int("CF_N_SLOTS", "11")?;
        let cf_account_ids = numbered_values(cf_n_slots, "CF_ACCOUNT_ID", &get_trimmed);
        let cf_api_tokens = numbered_values(cf_n_slots, "CF_API_TOKEN", &get_trimmed);
        let cf_ai_gateway_urls = numbered_values(cf_n_slots, "CF_AI_GATEWAY_URL", &get_trimmed);
        let cf_valid_slots = cf_account_ids
            .iter()
            .zip(cf_api_tokens.iter())
            .zip(cf_ai_gateway_urls.iter())
            .filter_map(|((acc, tok), gw)| {
                if acc.is_empty() || tok.is_empty() {
                    None
                } else {
                    Some((acc.clone(), tok.clone(), gw.clone()))
                }
            })
            .collect();

        Ok(Self {
            max_workers: int("MAX_WORKERS", "150")?,
            connection_timeout: float("CONNECTION_TIMEOUT", "8")?,
            ssl_timeout: float("SSL_TIMEOUT", "6")?,
            max_retries: int("MAX_RETRIES", "2")?,
            max_test_per_type: int("MAX_TEST_PER_TYPE", "1000")?,
            recent_hours: int("RECENT_HOURS", "72")?,
            history_retention_days: int("HISTORY_RETENTION_DAYS", "45")?,
            history_file: format!("{bridge_dir}/bridge_history.json"),
            scores_file: format!("{bridge_dir}/bridge_scores.json"),
            bridge_dir,
            export_dir,
            repo_url: get("REPO_URL", DEFAULT_REPO_URL),
            is_github: lookup("GITHUB_ACTIONS").as_deref() == Some("true"),
            cf_n_slots,
            cf_account_ids,
            cf_api_tokens,
            cf_ai_gateway_urls,
            cf_valid_slots,
            cerebras_api_key: get("CEREBRAS_API_KEY", ""),
            portkey_api_key: get("PORTKEY_API_KEY", ""),
            portkey_gateway_url: get("PORTKEY_GATEWAY_URL", DEFAULT_PORTKEY_GATEWAY_URL),
            portkey_virtual_keys: (1..=3)
                .map(|i| get_owned(&lookup, format!("PORTKEY_VIRTUAL_KEY_{i}"), ""))
                .collect(),
            groq_api_key: get("GROQ_API_KEY", ""),
            github_token: get("GITHUB_TOKEN", ""),
            github_repository: get("GITHUB_REPOSITORY", ""),
            github_sha: get("GITHUB_SHA", ""),
            gh_pat_autofix: get("GH_PAT_AUTOFIX", ""),
            gh_repo_owner: get("GH_REPO_OWNER", ""),
            gh_repo_name: get("GH_REPO_NAME", ""),
            telegram_bot_token: get("TELEGRAM_BOT_TOKEN", ""),
            telegram_chat_id: get("TELEGRAM_CHAT_ID", ""),
            telegram_upload: boolv("TELEGRAM_UPLOAD", "false"),
            http_proxy: get("HTTP_PROXY", ""),
            https_proxy: get("HTTPS_PROXY", ""),
            use_torproject_scraper: boolv("USE_TORPROJECT_SCRAPER", "true"),
            use_moat_api: boolv("USE_MOAT_API", "true"),
            use_bridgedb_api: boolv("USE_BRIDGEDB_API", "true"),
            use_telegram_sources: boolv("USE_TELEGRAM_SOURCES", "false"),
            use_static_bridges: boolv("USE_STATIC_BRIDGES", "true"),
            use_github_sources: boolv("USE_GITHUB_SOURCES", "true"),
            deep_test: boolv("DEEP_TEST", "false"),
            iran_preferred_ports: vec![443, 80, 8080, 8443, 2083, 2087, 2096],
            iran_cdn_fronts: vec![
                "fastly.net".to_string(),
                "cdn.arvancloud.com".to_string(),
                "arvancloud.ir".to_string(),
                "cloudfront.net".to_string(),
                "azureedge.net".to_string(),
                "ajax.aspnetcdn.com".to_string(),
                "googlevideo.com".to_string(),
                "gstatic.com".to_string(),
            ],
            nin_mode: boolv("NIN_MODE", "false"),
            iran_bridge_prioritization_enabled: boolv(
                "IRAN_BRIDGE_PRIORITIZATION_ENABLED",
                "false",
            ),
            iran_bridge_prioritization_weight_port: float(
                "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT",
                "1.0",
            )?,
            iran_bridge_prioritization_weight_transport: float(
                "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT",
                "1.0",
            )?,
            iran_bridge_prioritization_weight_recency: float(
                "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY",
                "1.0",
            )?,
            iran_bridge_prioritization_weight_reachability: float(
                "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY",
                "1.0",
            )?,
            ripe_atlas_api_key: get("RIPE_ATLAS_API_KEY", ""),
            anti_dpi_mode: boolv("ANTI_DPI_MODE", "false"),
            anti_filter_mode: boolv("ANTI_FILTER_MODE", "false"),
            torshield_iran_mode: boolv("TORSHIELD_IRAN_MODE", "false"),
            auto_debug_mode: boolv("AUTO_DEBUG_MODE", "false"),
            utls_evasion_mode: boolv("UTLS_EVASION_MODE", "true"),
            utls_profile_rotation: int("UTLS_PROFILE_ROTATION", "30")?,
            elite_registry_enabled: boolv("ELITE_REGISTRY_ENABLED", "true"),
            elite_registry_refresh_hrs: int("ELITE_REGISTRY_REFRESH_HRS", "6")?,
            circuit_breaker_enabled: boolv("CIRCUIT_BREAKER_ENABLED", "true"),
            circuit_breaker_max_failures: int("CIRCUIT_BREAKER_MAX_FAILURES", "3")?,
            circuit_breaker_reset_secs: float("CIRCUIT_BREAKER_RESET_SECS", "300")?,
            session_blacklist_duration_secs: float("SESSION_BLACKLIST_DURATION_SECS", "3600")?,
            telemetry_enabled: boolv("TELEMETRY_ENABLED", "true"),
            telemetry_auto_debug_threshold: int("TELEMETRY_AUTO_DEBUG_THRESHOLD", "2")?,
            telemetry_log_max_mb: int("TELEMETRY_LOG_MAX_MB", "10")?,
            irst_high_censorship_start: int("IRST_HIGH_CENSORSHIP_START", "18")?,
            irst_high_censorship_end: int("IRST_HIGH_CENSORSHIP_END", "1")?,
            irst_ultra_stealth_start: int("IRST_ULTRA_STEALTH_START", "20")?,
            irst_ultra_stealth_end: int("IRST_ULTRA_STEALTH_END", "23")?,
        })
    }
}

fn parse_int(name: &'static str, value: &str) -> Result<i64, ConfigError> {
    value.parse::<i64>().map_err(|_| ConfigError::InvalidInt {
        name,
        value: value.to_string(),
    })
}

fn parse_float(name: &'static str, value: &str) -> Result<f64, ConfigError> {
    value.parse::<f64>().map_err(|_| ConfigError::InvalidFloat {
        name,
        value: value.to_string(),
    })
}

fn get_owned<F>(lookup: &F, name: String, default: &'static str) -> String
where
    F: Fn(&str) -> Option<String>,
{
    lookup(&name).unwrap_or_else(|| default.to_string())
}

fn numbered_values<F>(count: i64, prefix: &str, get_trimmed: &F) -> Vec<String>
where
    F: Fn(&'static str, &'static str) -> String,
{
    (1..=count)
        .map(|i| {
            let name = format!("{prefix}_{i}");
            // The generated variable names are bounded by this function and do not escape.
            let leaked: &'static str = Box::leak(name.into_boxed_str());
            get_trimmed(leaked, "")
        })
        .collect()
}

/// Test helper type used by parity tests to inject an environment map.
pub type EnvMap = BTreeMap<String, String>;

/// Build a config snapshot from a [`BTreeMap`] of environment variables.
pub fn from_env_map(env: &EnvMap) -> Result<Config, ConfigError> {
    Config::from_lookup(|name| env.get(name).cloned())
}

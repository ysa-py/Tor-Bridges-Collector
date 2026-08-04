//! Configuration and static transport registry for the unified collector.

use std::env;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// Default user agent shared by source fetches and WebSocket liveness checks.
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// BridgeDB HTML endpoint used by both legacy Python collectors.
pub const BRIDGEDB_BASE_URL: &str = "https://bridges.torproject.org/bridges";

/// Community seed-list source used to enrich BridgeDB results.
pub const DELTA_RAW_BASE_URL: &str =
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge";

/// Canonical public raw-file base used in generated documentation.
pub const DEFAULT_RAW_REPO_URL: &str =
    "https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge";

/// Transport families published by the collector.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Transport {
    /// Direct Tor ORPort bridge line.
    Vanilla,
    /// obfs4 pluggable transport bridge.
    Obfs4,
    /// WebTunnel WebSocket-over-TLS bridge.
    WebTunnel,
    /// Snowflake broker/fronted transport.
    Snowflake,
    /// Tor Browser's `meek_lite` token, published as `meek-azure`.
    MeekAzure,
    /// Conjure registration/fronted transport.
    Conjure,
}

impl Transport {
    /// Pooled transports collected from BridgeDB and the community seed list.
    pub const POOLED: [Self; 3] = [Self::Obfs4, Self::WebTunnel, Self::Vanilla];

    /// Fixed fronted transports, for which BridgeDB does not publish a rotating pool.
    pub const FRONTED: [Self; 3] = [Self::Snowflake, Self::MeekAzure, Self::Conjure];

    /// Stable filename stem used by the Python collectors.
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Vanilla => "vanilla",
            Self::Obfs4 => "obfs4",
            Self::WebTunnel => "webtunnel",
            Self::Snowflake => "snowflake",
            Self::MeekAzure => "meek-azure",
            Self::Conjure => "conjure",
        }
    }

    /// BridgeDB query token.
    pub const fn bridgedb_name(self) -> &'static str {
        match self {
            Self::Vanilla => "vanilla",
            Self::Obfs4 => "obfs4",
            Self::WebTunnel => "webtunnel",
            Self::Snowflake => "snowflake",
            Self::MeekAzure => "meek-azure",
            Self::Conjure => "conjure",
        }
    }

    /// Leading token expected in a bridge line when one exists.
    pub const fn line_token(self) -> &'static str {
        match self {
            Self::MeekAzure => "meek_lite",
            _ => self.file_name(),
        }
    }

    /// Whether this transport is reached through a front/broker rather than
    /// the placeholder endpoint in its bridge line.
    pub const fn is_fronted(self) -> bool {
        matches!(self, Self::Snowflake | Self::MeekAzure | Self::Conjure)
    }

    /// Whether this transport is sourced from BridgeDB and Delta lists.
    pub const fn is_pooled(self) -> bool {
        matches!(self, Self::Vanilla | Self::Obfs4 | Self::WebTunnel)
    }

    /// Parse an accepted user-facing transport name.
    pub fn from_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "vanilla" => Some(Self::Vanilla),
            "obfs4" => Some(Self::Obfs4),
            "webtunnel" | "web-tunnel" => Some(Self::WebTunnel),
            "snowflake" => Some(Self::Snowflake),
            "meek-azure" | "meek_azure" | "meek_lite" | "meek" => Some(Self::MeekAzure),
            "conjure" => Some(Self::Conjure),
            _ => None,
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.file_name())
    }
}

/// A transport/IP-family output projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListSpec {
    /// The transport represented by this projection.
    pub transport: Transport,
    /// `true` for bracketed IPv6 bridge-line lists.
    pub ipv6: bool,
}

impl ListSpec {
    /// Full archive filename, preserving the established naming convention.
    pub fn archive_name(self) -> String {
        if self.ipv6 {
            format!("{}_ipv6.txt", self.transport.file_name())
        } else {
            format!("{}.txt", self.transport.file_name())
        }
    }

    /// Recent-list filename, preserving `*_ipv6_72h.txt` naming.
    pub fn recent_name(self) -> String {
        if self.ipv6 {
            format!("{}_ipv6_72h.txt", self.transport.file_name())
        } else {
            format!("{}_72h.txt", self.transport.file_name())
        }
    }

    /// Tested-list filename.
    pub fn tested_name(self) -> String {
        if self.ipv6 {
            format!("{}_ipv6_tested.txt", self.transport.file_name())
        } else {
            format!("{}_tested.txt", self.transport.file_name())
        }
    }
}

/// Runtime settings. Every field can be supplied through an environment
/// variable and key collection settings can also be overridden by CLI flags.
#[derive(Clone, Debug)]
pub struct CollectorConfig {
    /// Output directory containing bridge lists and history.
    pub bridge_dir: PathBuf,
    /// Dynamic README destination.
    pub readme_path: PathBuf,
    /// Persistent first-seen/health database path.
    pub history_path: PathBuf,
    /// Generated ZIP destination.
    pub zip_path: PathBuf,
    /// BridgeDB base URL; configurable for controlled integration tests.
    pub bridgedb_base_url: String,
    /// Community raw-list base URL; configurable for controlled integration tests.
    pub delta_raw_base_url: String,
    /// Raw GitHub base shown in README links.
    pub raw_repo_url: String,
    /// HTTP and network handshake timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Timeout for an obfs4 SOCKS handshake in seconds.
    pub obfs4_handshake_timeout_secs: u64,
    /// Number of source/probe attempts before a failure is recorded.
    pub max_retries: usize,
    /// Initial maximum parallel probes.
    pub max_workers: usize,
    /// Lower bound selected by the adaptive concurrency controller.
    pub min_workers: usize,
    /// Maximum candidates tested for each output list.
    pub max_test_per_list: usize,
    /// Number of hours in the recent/fresh window.
    pub recent_hours: i64,
    /// Number of days retained in bridge history.
    pub history_retention_days: i64,
    /// Minimum verified fraction before obfs4 harness results replace TCP results.
    pub obfs4_verify_min_fraction: f64,
    /// Consecutive front-domain failures before its circuit opens.
    pub front_failure_threshold: u32,
    /// Front-domain circuit-breaker cooldown in seconds.
    pub front_cooldown_secs: u64,
    /// Number of fetch attempts, including the first attempt.
    pub fetch_retries: usize,
    /// Optional Prometheus text-file destination.
    pub metrics_output: Option<PathBuf>,
    /// Do all collection/probing and report changes without writing output files.
    pub dry_run: bool,
    /// Whether verbose diagnostic logging is requested.
    pub verbose: bool,
    /// Telegram bot token; never logged.
    pub telegram_bot_token: Option<String>,
    /// Telegram chat ID; never logged.
    pub telegram_chat_id: Option<String>,
    /// Explicit Telegram upload opt-in.
    pub telegram_upload: bool,
    /// GitHub Actions marker used by the legacy midnight trigger.
    pub github_actions: bool,
}

impl CollectorConfig {
    /// Load collector settings from the process environment.
    pub fn from_env() -> Result<Self> {
        let bridge_dir = PathBuf::from(env_string("BRIDGE_DIR", "bridge"));
        let history_path = env_path(
            "BRIDGE_HISTORY_FILE",
            bridge_dir.join("bridge_history.json"),
        );
        let zip_path = env_path("TOR_BRIDGES_ZIP", bridge_dir.join("tor_bridges.zip"));
        let max_workers = env_usize("MAX_WORKERS", 50, 1, 1_000)?;
        let min_workers = env_usize("MIN_WORKERS", 4, 1, max_workers)?;

        Ok(Self {
            bridge_dir,
            readme_path: env_path("README_PATH", PathBuf::from("README.md")),
            history_path,
            zip_path,
            bridgedb_base_url: env_string("BRIDGEDB_BASE_URL", BRIDGEDB_BASE_URL),
            delta_raw_base_url: env_string("DELTA_RAW_BASE_URL", DELTA_RAW_BASE_URL),
            raw_repo_url: env_string("RAW_REPO_URL", DEFAULT_RAW_REPO_URL),
            connect_timeout_secs: env_u64("CONNECT_TIMEOUT", 8, 1, 120)?,
            obfs4_handshake_timeout_secs: env_u64("OBFS4_HANDSHAKE_TIMEOUT", 12, 1, 120)?,
            max_retries: env_usize("MAX_RETRIES", 2, 1, 10)?,
            max_workers,
            min_workers,
            max_test_per_list: env_usize("MAX_TEST_PER_LIST", 600, 1, 20_000)?,
            recent_hours: env_i64("RECENT_HOURS", 72, 1, 24 * 30)?,
            history_retention_days: env_i64("HISTORY_RETENTION_DAYS", 30, 1, 365)?,
            obfs4_verify_min_fraction: env_fraction("OBFS4_VERIFY_MIN_FRACTION", 0.2)?,
            front_failure_threshold: env_u32("FRONT_FAILURE_THRESHOLD", 3, 1, 100)?,
            front_cooldown_secs: env_u64("FRONT_COOLDOWN_SECS", 300, 1, 86_400)?,
            fetch_retries: env_usize("FETCH_RETRIES", 3, 1, 10)?,
            metrics_output: env::var_os("METRICS_OUTPUT").map(PathBuf::from),
            dry_run: env_bool("DRY_RUN", false),
            verbose: env_bool("VERBOSE", false),
            telegram_bot_token: nonempty_env("TELEGRAM_BOT_TOKEN"),
            telegram_chat_id: nonempty_env("TELEGRAM_CHAT_ID"),
            telegram_upload: env_bool("TELEGRAM_UPLOAD", false),
            github_actions: env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true"),
        })
    }

    /// Update derived paths after a CLI `--bridge-dir` override.
    pub fn set_bridge_dir(&mut self, bridge_dir: PathBuf) {
        let old_bridge_dir = self.bridge_dir.clone();
        self.bridge_dir = bridge_dir.clone();
        if self.history_path == old_bridge_dir.join("bridge_history.json") {
            self.history_path = bridge_dir.join("bridge_history.json");
        }
        if self.zip_path == old_bridge_dir.join("tor_bridges.zip") {
            self.zip_path = bridge_dir.join("tor_bridges.zip");
        }
    }

    /// Return whether the legacy Telegram trigger should run at `hour_utc`.
    pub fn telegram_triggered_at(&self, hour_utc: u32) -> bool {
        self.github_actions && (hour_utc == 0 || self.telegram_upload)
    }
}

/// Tor Browser default lines for fronted transports. The literal addresses are
/// documentation placeholders; verification deliberately targets `url=`,
/// `fronts=`, or `front=` hosts instead.
pub fn fronted_defaults(transport: Transport) -> &'static [&'static str] {
    match transport {
        Transport::Snowflake => &[
            "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478 utls-imitate=hellorandomizedalpn",
            "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478 utls-imitate=hellorandomizedalpn",
        ],
        Transport::MeekAzure => &[
            "meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
        ],
        Transport::Conjure => &[
            "conjure 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://registration.refraction.network/api fronts=cdn.sstatic.net,assets.cloud.censys.io transport=min",
        ],
        _ => &[],
    }
}

fn env_string(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn env_path(name: &str, default: PathBuf) -> PathBuf {
    env::var_os(name).map_or(default, PathBuf::from)
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize, min: usize, max: usize) -> Result<usize> {
    let value = match env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .map_err(|_| anyhow!("{name} must be an integer, got {raw:?}"))?,
        Err(_) => default,
    };
    if !(min..=max).contains(&value) {
        return Err(anyhow!("{name} must be in {min}..={max}, got {value}"));
    }
    Ok(value)
}

fn env_u64(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|_| anyhow!("{name} must be an integer, got {raw:?}"))?,
        Err(_) => default,
    };
    if !(min..=max).contains(&value) {
        return Err(anyhow!("{name} must be in {min}..={max}, got {value}"));
    }
    Ok(value)
}

fn env_u32(name: &str, default: u32, min: u32, max: u32) -> Result<u32> {
    let value = match env::var(name) {
        Ok(raw) => raw
            .parse::<u32>()
            .map_err(|_| anyhow!("{name} must be an integer, got {raw:?}"))?,
        Err(_) => default,
    };
    if !(min..=max).contains(&value) {
        return Err(anyhow!("{name} must be in {min}..={max}, got {value}"));
    }
    Ok(value)
}

fn env_i64(name: &str, default: i64, min: i64, max: i64) -> Result<i64> {
    let value = match env::var(name) {
        Ok(raw) => raw
            .parse::<i64>()
            .map_err(|_| anyhow!("{name} must be an integer, got {raw:?}"))?,
        Err(_) => default,
    };
    if !(min..=max).contains(&value) {
        return Err(anyhow!("{name} must be in {min}..={max}, got {value}"));
    }
    Ok(value)
}

fn env_fraction(name: &str, default: f64) -> Result<f64> {
    let value = match env::var(name) {
        Ok(raw) => raw
            .parse::<f64>()
            .map_err(|_| anyhow!("{name} must be a number, got {raw:?}"))?,
        Err(_) => default,
    };
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(anyhow!(
            "{name} must be a finite value in 0.0..=1.0, got {value}"
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_names_match_legacy_convention() {
        let ipv4 = ListSpec {
            transport: Transport::Obfs4,
            ipv6: false,
        };
        let ipv6 = ListSpec {
            transport: Transport::Obfs4,
            ipv6: true,
        };
        assert_eq!(ipv4.archive_name(), "obfs4.txt");
        assert_eq!(ipv4.recent_name(), "obfs4_72h.txt");
        assert_eq!(ipv4.tested_name(), "obfs4_tested.txt");
        assert_eq!(ipv6.archive_name(), "obfs4_ipv6.txt");
        assert_eq!(ipv6.recent_name(), "obfs4_ipv6_72h.txt");
        assert_eq!(ipv6.tested_name(), "obfs4_ipv6_tested.txt");
    }

    #[test]
    fn transport_aliases_keep_meek_lite_token() {
        assert_eq!(
            Transport::from_name("meek_lite"),
            Some(Transport::MeekAzure)
        );
        assert_eq!(Transport::MeekAzure.line_token(), "meek_lite");
        assert!(Transport::MeekAzure.is_fronted());
        assert!(Transport::Obfs4.is_pooled());
    }

    #[test]
    fn fronted_defaults_are_present() {
        assert!(!fronted_defaults(Transport::Snowflake).is_empty());
        assert!(fronted_defaults(Transport::MeekAzure)[0].contains("meek_lite"));
        assert!(fronted_defaults(Transport::Conjure)[0].contains("conjure"));
    }
}

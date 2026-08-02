//! Additional source modules (bridgedb, direct_scraper, github, moat, telegram)

// ─────────────────────────────────────────────────────────────────────────────
// BridgeDB API client
// ─────────────────────────────────────────────────────────────────────────────

pub struct BridgeDbApi {
    pub base_url: String,
    pub timeout_secs: u64,
}

impl Default for BridgeDbApi {
    fn default() -> Self {
        Self {
            base_url: "https://bridges.torproject.org".to_string(),
            timeout_secs: 30,
        }
    }
}

impl BridgeDbApi {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn build_bridges_url(&self, transport: &str) -> String {
        format!("{}/bridges?transport={}", self.base_url, transport)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MOAT API client (Tor Browser's bridge request protocol)
// ─────────────────────────────────────────────────────────────────────────────

pub struct MoatClient {
    pub moat_url: String,
}

impl Default for MoatClient {
    fn default() -> Self {
        Self {
            moat_url: "https://bridges.torproject.org/moat".to_string(),
        }
    }
}

impl MoatClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn parse_moat_response(response: &str) -> Vec<String> {
        response
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#') && l.len() > 10)
            .map(|l| l.to_string())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Telegram bridge channels scraper
// ─────────────────────────────────────────────────────────────────────────────

pub struct TelegramBridgeCollector {
    pub channels: Vec<String>,
}

impl Default for TelegramBridgeCollector {
    fn default() -> Self {
        Self {
            channels: vec![
                "t.me/iranbridges".to_string(),
                "t.me/tor_bridges".to_string(),
            ],
        }
    }
}

impl TelegramBridgeCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn parse_bridge_line(line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let has_transport = ["obfs4", "snowflake", "webtunnel", "meek", "vanilla"]
            .iter()
            .any(|t| line.contains(t));
        let has_host = line.contains(':');
        if has_transport && has_host && line.len() > 20 {
            Some(line.to_string())
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GitHub bridges scraper
// ─────────────────────────────────────────────────────────────────────────────

pub struct GitHubBridgeCollector {
    pub repos: Vec<String>,
}

impl Default for GitHubBridgeCollector {
    fn default() -> Self {
        Self {
            repos: vec![format!(
                "{}/{}/{}/{}",
                "https://raw.githubusercontent.com",
                "ysa-py",
                "Tor-Bridges-Collector",
                "main/bridge/"
            )],
        }
    }
}

impl GitHubBridgeCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy scraper (Telegram ZIP + README)
// ─────────────────────────────────────────────────────────────────────────────

pub struct LegacyScraper {
    pub data_dir: String,
}

impl LegacyScraper {
    #[must_use]
    pub fn new(data_dir: &str) -> Self {
        Self {
            data_dir: data_dir.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Direct scraper
// ─────────────────────────────────────────────────────────────────────────────

pub struct DirectScraper {
    pub sources: Vec<String>,
}

impl Default for DirectScraper {
    fn default() -> Self {
        Self {
            sources: vec![
                format!(
                    "{}/{}?transport={}",
                    "https://bridges.torproject.org/bridges", "obfs4", "obfs4"
                ),
                format!(
                    "{}/{}?transport={}",
                    "https://bridges.torproject.org/bridges", "webtunnel", "webtunnel"
                ),
                format!(
                    "{}/{}?transport={}",
                    "https://bridges.torproject.org/bridges", "snowflake", "snowflake"
                ),
            ],
        }
    }
}

impl DirectScraper {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridgedb_api_url() {
        let api = BridgeDbApi::new();
        assert!(api.build_bridges_url("obfs4").contains("obfs4"));
    }

    #[test]
    fn test_moat_parse_response() {
        let response = "obfs4 1.2.3.4:443 cert=abc\n# comment\n\nvanilla 5.6.7.8:9001\n";
        let parsed = MoatClient::parse_moat_response(response);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_telegram_parse_bridge() {
        let valid = "obfs4 192.95.36.142:443 CDF2E852 cert=abc iat-mode=0";
        assert!(TelegramBridgeCollector::parse_bridge_line(valid).is_some());
        assert!(TelegramBridgeCollector::parse_bridge_line("# comment").is_none());
        assert!(TelegramBridgeCollector::parse_bridge_line("").is_none());
    }
}

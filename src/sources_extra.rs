//! Additional source modules (bridgedb, direct_scraper, github, moat, telegram)

use serde_json::{json, Value};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// BridgeDB API client
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BridgeDbApi {
    pub base_url: String,
    pub timeout_secs: u64,
}

impl BridgeDbApi {
    pub fn new() -> Self {
        Self {
            base_url: "https://bridges.torproject.org".to_string(),
            timeout_secs: 30,
        }
    }

    pub fn build_bridges_url(&self, transport: &str) -> String {
        format!("{}/bridges?transport={}", self.base_url, transport)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MOAT API client (Tor Browser's bridge request protocol)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MoatClient {
    pub moat_url: String,
}

impl MoatClient {
    pub fn new() -> Self {
        Self {
            moat_url: "https://bridges.torproject.org/moat".to_string(),
        }
    }

    /// Parse a MOAT bridge response
    pub fn parse_moat_response(response: &str) -> Vec<String> {
        response.lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#') && l.len() > 10)
            .map(|l| l.to_string())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Telegram bridge channels scraper
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TelegramBridgeCollector {
    pub channels: Vec<String>,
}

impl TelegramBridgeCollector {
    pub fn new() -> Self {
        Self {
            channels: vec![
                "t.me/iranbridges".to_string(),
                "t.me/tor_bridges".to_string(),
            ],
        }
    }

    /// Parse a Telegram bridge message line
    pub fn parse_bridge_line(line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        // Validate it looks like a bridge line (has transport + host:port)
        let has_transport = ["obfs4", "snowflake", "webtunnel", "meek", "vanilla"]
            .iter().any(|t| line.contains(t));
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

#[derive(Debug, Clone)]
pub struct GitHubBridgeCollector {
    pub repos: Vec<String>,
}

impl GitHubBridgeCollector {
    pub fn new() -> Self {
        Self {
            repos: vec![
                "https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/main/bridge/".to_string(),
            ],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy scraper (Telegram ZIP + README)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LegacyScraper {
    pub data_dir: String,
}

impl LegacyScraper {
    pub fn new(data_dir: &str) -> Self {
        Self {
            data_dir: data_dir.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Direct scraper
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DirectScraper {
    pub sources: Vec<String>,
}

impl DirectScraper {
    pub fn new() -> Self {
        Self {
            sources: vec![
                "https://bridges.torproject.org/bridges?transport=obfs4".to_string(),
                "https://bridges.torproject.org/bridges?transport=webtunnel".to_string(),
                "https://bridges.torproject.org/bridges?transport=snowflake".to_string(),
            ],
        }
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

        let invalid = "# comment line";
        assert!(TelegramBridgeCollector::parse_bridge_line(invalid).is_none());

        let empty = "";
        assert!(TelegramBridgeCollector::parse_bridge_line(empty).is_none());
    }
}

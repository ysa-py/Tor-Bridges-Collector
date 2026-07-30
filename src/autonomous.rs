//! Rust port of autonomous/ Python modules
//! Resilient orchestrator, anti-censorship router, bridge management

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Anti-censorship bridge configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub address: String,
    pub port: u16,
    pub protocol: ObfuscationProtocol,
    pub fingerprint: Option<String>,
    pub extra_params: HashMap<String, String>,
    pub priority: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationProtocol {
    Obfs4,
    Snowflake,
    Webtunnel,
    MeekAzure,
    MeekLite,
    Vanilla,
    Hysteria2,
    Reality,
    Shadowsocks,
}

impl ObfuscationProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Obfs4 => "obfs4",
            Self::Snowflake => "snowflake",
            Self::Webtunnel => "webtunnel",
            Self::MeekAzure => "meek-azure",
            Self::MeekLite => "meek_lite",
            Self::Vanilla => "vanilla",
            Self::Hysteria2 => "hysteria2",
            Self::Reality => "reality",
            Self::Shadowsocks => "shadowsocks",
        }
    }

    pub fn dpi_resistance(&self) -> f64 {
        match self {
            Self::Reality => 0.98,
            Self::Hysteria2 => 0.97,
            Self::MeekAzure => 0.95,
            Self::Snowflake => 0.92,
            Self::Webtunnel => 0.88,
            Self::MeekLite => 0.80,
            Self::Obfs4 => 0.72,
            Self::Shadowsocks => 0.65,
            Self::Vanilla => 0.10,
        }
    }
}

impl BridgeConfig {
    pub fn to_bridge_line(&self) -> String {
        let mut line = format!("{} {}:{}", self.protocol.as_str(), self.address, self.port);
        if let Some(ref fp) = self.fingerprint {
            line.push_str(&format!(" {}", fp));
        }
        for (k, v) in &self.extra_params {
            line.push_str(&format!(" {}={}", k, v));
        }
        line
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Iran bypass configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IranBypassConfig {
    pub bridges: Vec<BridgeConfig>,
    pub dns_over_https_url: String,
    pub preferred_protocol: ObfuscationProtocol,
    pub allow_direct_fallback: bool,
    pub recheck_interval_s: f64,
    pub timing_jitter: bool,
}

impl Default for IranBypassConfig {
    fn default() -> Self {
        Self {
            bridges: Vec::new(),
            dns_over_https_url: "https://cloudflare-dns.com/dns-query".into(),
            preferred_protocol: ObfuscationProtocol::MeekAzure,
            allow_direct_fallback: true,
            recheck_interval_s: 120.0,
            timing_jitter: true,
        }
    }
}

impl IranBypassConfig {
    pub fn recommended() -> Self {
        let mut bridges = Vec::new();
        let mut params = HashMap::new();
        params.insert("url".into(), "https://meek.azurefd.net/".into());
        bridges.push(BridgeConfig {
            address: "20.186.13.205".into(),
            port: 443,
            protocol: ObfuscationProtocol::MeekAzure,
            fingerprint: None,
            extra_params: params,
            priority: 10,
        });
        bridges.push(BridgeConfig {
            address: "snowflake-broker.torproject.net".into(),
            port: 443,
            protocol: ObfuscationProtocol::Snowflake,
            fingerprint: None,
            extra_params: HashMap::new(),
            priority: 20,
        });
        bridges.push(BridgeConfig {
            address: "192.95.36.142".into(),
            port: 443,
            protocol: ObfuscationProtocol::Obfs4,
            fingerprint: Some("CDF2E852BF539B82BD10E27E9115A31734E378C2".into()),
            extra_params: {
                let mut m = HashMap::new();
                                m.insert(
                    "cert".into(),
                    "qUVQ0srL1JI/vO6V6m/24anYXiJD3zP8o7ULQzu2RDy6GIVCbvGrDlhk9MhFBlRmFBMf+Q"
                        .into(),
                );
                m.insert("iat-mode".into(), "0".into());
                m
            },
            priority: 30,
        });

        Self {
            bridges,
            ..Default::default()
        }
    }

    pub fn is_likely_blocked(&self, hostname: &str) -> bool {
        let blocked = [
            "twitter.com", "x.com", "facebook.com", "youtube.com",
            "telegram.org", "t.me", "instagram.com", "github.com",
            "raw.githubusercontent.com", "google.com",
        ];
        let h = hostname.to_lowercase();
        for domain in &blocked {
            if h == *domain || h.ends_with(&format!(".{}", domain)) {
                return true;
            }
        }
        false
    }

    pub fn build_torrc(&self) -> String {
        let mut lines = vec![
            "# Generated by TorShield-IR autonomous anti-censorship module".to_string(),
            "# Optimised for Iran (IR) network conditions".to_string(),
            "UseBridges 1".to_string(),
            "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy".to_string(),
            "ClientTransportPlugin meek exec /usr/bin/meek-client".to_string(),
            "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client".to_string(),
            "SocksPort 9050".to_string(),
            "StrictNodes 1".to_string(),
            "ExcludeNodes {ir}".to_string(),
            "".to_string(),
        ];
        for bridge in &self.bridges {
            lines.push(format!("Bridge {}", bridge.to_bridge_line()));
        }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Smart anti-censorship router
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SmartAntiCensorshipRouter {
    pub bypass_config: IranBypassConfig,
    pub initialized: bool,
    pub current_route: Option<String>,
    pub health_status: HashMap<String, bool>,
}

impl SmartAntiCensorshipRouter {
    pub fn new(bypass_config: IranBypassConfig) -> Self {
        Self {
            bypass_config,
            initialized: false,
            current_route: None,
            health_status: HashMap::new(),
        }
    }

    pub fn initialize(&mut self) {
        self.initialized = true;
        for bridge in &self.bypass_config.bridges {
            self.health_status.insert(bridge.address.clone(), true);
        }
    }

    pub fn get_status(&self) -> Value {
        json!({
            "initialized": self.initialized,
            "current_route": self.current_route,
            "bridge_count": self.bypass_config.bridges.len(),
            "health_status": self.health_status,
        })
    }

    pub fn select_bridge(&self, blocked: &[String]) -> Option<&BridgeConfig> {
        self.bypass_config.bridges.iter().find(|b| !blocked.contains(&b.address))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resilient orchestrator
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResilientOrchestrator {
    pub name: String,
    pub max_retries: u32,
    pub circuit_breaker_threshold: u32,
    pub failure_count: u32,
    pub cooldown_until: Option<DateTime<Utc>>,
}

impl ResilientOrchestrator {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            max_retries: 3,
            circuit_breaker_threshold: 5,
            failure_count: 0,
            cooldown_until: None,
        }
    }

    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.cooldown_until = None;
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        if self.failure_count >= self.circuit_breaker_threshold {
            self.cooldown_until = Some(Utc::now() + chrono::Duration::seconds(30));
        }
    }

    pub fn is_circuit_open(&self) -> bool {
        match self.cooldown_until {
            Some(t) => Utc::now() < t,
            None => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Iran-specific constants
// ─────────────────────────────────────────────────────────────────────────────

pub const IRAN_POISON_IPS: &[&str] = &[
    "10.10.34.34", "10.10.34.35", "127.0.0.1",
    "10.10.33.36", "10.10.34.36",
];

pub const IRAN_CENSOR_ASNS: &[u32] = &[
    44244,  // IRANCELL
    16322,  // Pars Online
    12880,  // ITC
    197207, // MCCI
    58224,  // Iran Telecom
    43754,  // Asiatech
    48159,  // TIC
];

pub const IRAN_SAFE_DNS: &[&str] = &[
    "10.202.10.10",  // Shecan
    "10.202.10.11",  // Shecan secondary
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_config_to_bridge_line() {
        let bc = BridgeConfig {
            address: "1.2.3.4".into(),
            port: 443,
            protocol: ObfuscationProtocol::Obfs4,
            fingerprint: Some("ABCD".into()),
            extra_params: HashMap::new(),
            priority: 1,
        };
        assert!(bc.to_bridge_line().contains("obfs4 1.2.3.4:443 ABCD"));
    }

    #[test]
    fn test_dpi_resistance_reality_is_highest() {
        assert!(ObfuscationProtocol::Reality.dpi_resistance() > 0.95);
        assert!(ObfuscationProtocol::Vanilla.dpi_resistance() < 0.5);
    }

    #[test]
    fn test_iran_bypass_config_recommended() {
        let cfg = IranBypassConfig::recommended();
        assert_eq!(cfg.bridges.len(), 3);
        assert_eq!(cfg.bridges[0].protocol, ObfuscationProtocol::MeekAzure);
    }

    #[test]
    fn test_is_likely_blocked() {
        let cfg = IranBypassConfig::default();
        assert!(cfg.is_likely_blocked("twitter.com"));
        assert!(cfg.is_likely_blocked("foo.twitter.com"));
        assert!(!cfg.is_likely_blocked("example.com"));
    }

    #[test]
    fn test_build_torrc() {
        let cfg = IranBypassConfig::recommended();
        let torrc = cfg.build_torrc();
        assert!(torrc.contains("UseBridges 1"));
        assert!(torrc.contains("ExcludeNodes {ir}"));
    }

    #[test]
    fn test_router_initialize() {
        let cfg = IranBypassConfig::default();
        let mut router = SmartAntiCensorshipRouter::new(cfg);
        assert!(!router.initialized);
        router.initialize();
        assert!(router.initialized);
    }

    #[test]
    fn test_resilient_orchestrator_circuit_breaker() {
        let mut orch = ResilientOrchestrator::new("test");
        assert!(!orch.is_circuit_open());
        for _ in 0..5 { orch.record_failure(); }
        assert!(orch.is_circuit_open());
        orch.record_success();
        assert!(!orch.is_circuit_open());
    }

    #[test]
    fn test_iran_poison_ips() {
        assert!(IRAN_POISON_IPS.contains(&"10.10.34.34"));
        assert!(IRAN_POISON_IPS.contains(&"127.0.0.1"));
    }

    #[test]
    fn test_iran_censor_asns() {
        assert!(IRAN_CENSOR_ASNS.contains(&44244));
        assert!(IRAN_CENSOR_ASNS.contains(&58224));
    }
}

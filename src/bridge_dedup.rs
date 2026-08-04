//! ML-Assisted Bridge Deduplication at Scale (Phase 3 — Feature 3)
//!
//! Implements scalable fuzzy/heuristic deduplication to eliminate duplicate
//! bridge identities across heterogeneous sources. Uses fingerprinting,
//! network subnet proximity, and transport parameter matching.
//!
//! # Design
//!
//! Bridge lines from different sources may represent the same physical relay:
//! - Same IP:port with different transport parameters
//! - Same subnet with similar ports (load-balanced relays)
//! - Same fingerprint with different front domains
//!
//! The [`BridgeDeduplicator`] maintains a fingerprint index and uses
//! configurable similarity thresholds to identify duplicates.
//!
//! # Thread Safety
//!
//! [`BridgeDeduplicator`] is `Send + Sync` and can be shared via `Arc<Mutex<_>>`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use regex::Regex;
use serde_json::{json, Value};

/// Default subnet mask for IPv4 proximity detection (/24 = 256 addresses).
const DEFAULT_SUBNET_MASK: u8 = 24;

/// Default port similarity threshold (ports within this range are "similar").
const DEFAULT_PORT_THRESHOLD: u16 = 10;

/// Deduplication strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupStrategy {
    /// Exact match on IP:port (strictest).
    Exact,
    /// Fuzzy match: same IP + similar ports + same transport.
    Fuzzy,
    /// Subnet-aware: same /24 subnet + similar ports + same transport.
    SubnetAware,
}

/// A deduplicated bridge entry with provenance tracking.
#[derive(Debug, Clone)]
pub struct DedupBridge {
    /// Canonical bridge line (first seen or highest quality).
    pub bridge_line: String,
    /// Transport type (obfs4, webtunnel, etc.).
    pub transport: String,
    /// IPv4 address (if parseable).
    pub ip: Option<Ipv4Addr>,
    /// Port number.
    pub port: u16,
    /// Fingerprint (if present in bridge line).
    pub fingerprint: Option<String>,
    /// Sources that reported this bridge.
    pub sources: BTreeSet<String>,
    /// Quality score (highest among duplicates).
    pub quality_score: f64,
    /// Number of duplicate entries merged.
    pub duplicate_count: usize,
}

impl DedupBridge {
    /// Convert to JSON for export/telemetry.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "bridge_line": self.bridge_line,
            "transport": self.transport,
            "ip": self.ip.map(|ip| ip.to_string()),
            "port": self.port,
            "fingerprint": self.fingerprint,
            "sources": self.sources.iter().collect::<Vec<_>>(),
            "quality_score": self.quality_score,
            "duplicate_count": self.duplicate_count,
        })
    }
}

/// Fingerprint for fast duplicate detection.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct BridgeFingerprint {
    ip: Option<Ipv4Addr>,
    port: u16,
    transport: String,
    subnet_24: Option<[u8; 3]>,
}

/// Scalable bridge deduplicator with configurable strategies.
#[derive(Debug)]
pub struct BridgeDeduplicator {
    /// Exact fingerprint index: fingerprint → canonical bridge line.
    exact_index: BTreeMap<BridgeFingerprint, String>,
    /// Subnet index: subnet_24 → set of fingerprints.
    subnet_index: BTreeMap<[u8; 3], BTreeSet<BridgeFingerprint>>,
    /// Deduplicated bridges: bridge_line → DedupBridge.
    bridges: BTreeMap<String, DedupBridge>,
    /// Deduplication strategy.
    strategy: DedupStrategy,
    /// Port similarity threshold.
    port_threshold: u16,
    /// Statistics.
    stats: DedupStats,
}

/// Deduplication statistics.
#[derive(Debug, Clone, Default)]
pub struct DedupStats {
    pub total_input: usize,
    pub unique_output: usize,
    pub duplicates_removed: usize,
    pub subnet_merges: usize,
    pub fuzzy_merges: usize,
}

impl BridgeDeduplicator {
    /// Create a new deduplicator with the given strategy.
    #[must_use]
    pub fn new(strategy: DedupStrategy) -> Self {
        Self {
            exact_index: BTreeMap::new(),
            subnet_index: BTreeMap::new(),
            bridges: BTreeMap::new(),
            strategy,
            port_threshold: DEFAULT_PORT_THRESHOLD,
            stats: DedupStats::default(),
        }
    }

    /// Create with default strategy (SubnetAware).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DedupStrategy::SubnetAware)
    }

    /// Set port similarity threshold.
    pub fn set_port_threshold(&mut self, threshold: u16) {
        self.port_threshold = threshold;
    }

    /// Add a bridge line from a source. Returns true if it was a new unique bridge.
    pub fn add_bridge(
        &mut self,
        bridge_line: &str,
        source: &str,
        quality_score: f64,
    ) -> bool {
        self.stats.total_input += 1;

        let parsed = parse_bridge_line(bridge_line);
        let fingerprint = BridgeFingerprint {
            ip: parsed.ip,
            port: parsed.port,
            transport: parsed.transport.clone(),
            subnet_24: parsed.ip.map(|ip| {
                let octets = ip.octets();
                [octets[0], octets[1], octets[2]]
            }),
        };

        // Check for exact match
        if let Some(canonical) = self.exact_index.get(&fingerprint) {
            // Duplicate: merge into existing entry
            if let Some(entry) = self.bridges.get_mut(canonical) {
                entry.sources.insert(source.to_string());
                entry.duplicate_count += 1;
                if quality_score > entry.quality_score {
                    entry.quality_score = quality_score;
                }
            }
            self.stats.duplicates_removed += 1;
            return false;
        }

        // Check for fuzzy/subnet match
        if self.strategy != DedupStrategy::Exact {
            if let Some(matched) = self.find_similar(&fingerprint) {
                // Similar bridge found: merge
                if let Some(entry) = self.bridges.get_mut(&matched) {
                    entry.sources.insert(source.to_string());
                    entry.duplicate_count += 1;
                    if quality_score > entry.quality_score {
                        entry.quality_score = quality_score;
                    }
                }
                self.exact_index.insert(fingerprint, matched);
                self.stats.duplicates_removed += 1;
                if self.strategy == DedupStrategy::SubnetAware {
                    self.stats.subnet_merges += 1;
                } else {
                    self.stats.fuzzy_merges += 1;
                }
                return false;
            }
        }

        // New unique bridge
        let canonical = bridge_line.to_string();
        self.exact_index.insert(fingerprint.clone(), canonical.clone());

        if let Some(subnet) = fingerprint.subnet_24 {
            self.subnet_index
                .entry(subnet)
                .or_default()
                .insert(fingerprint);
        }

        let mut sources = BTreeSet::new();
        sources.insert(source.to_string());

        self.bridges.insert(
            canonical.clone(),
            DedupBridge {
                bridge_line: canonical,
                transport: parsed.transport,
                ip: parsed.ip,
                port: parsed.port,
                fingerprint: parsed.fingerprint,
                sources,
                quality_score,
                duplicate_count: 0,
            },
        );

        self.stats.unique_output = self.bridges.len();
        true
    }

    /// Find a similar bridge using fuzzy/subnet matching.
    fn find_similar(&self, fp: &BridgeFingerprint) -> Option<String> {
        // Fuzzy: same IP + similar port + same transport
        if let Some(ip) = fp.ip {
            for (existing_fp, canonical) in &self.exact_index {
                if existing_fp.transport == fp.transport
                    && existing_fp.ip == Some(ip)
                    && port_similar(existing_fp.port, fp.port, self.port_threshold)
                {
                    return Some(canonical.clone());
                }
            }
        }

        // Subnet-aware: same /24 + similar port + same transport
        if self.strategy == DedupStrategy::SubnetAware {
            if let Some(subnet) = fp.subnet_24 {
                if let Some(subnet_fps) = self.subnet_index.get(&subnet) {
                    for existing_fp in subnet_fps {
                        if existing_fp.transport == fp.transport
                            && port_similar(existing_fp.port, fp.port, self.port_threshold)
                        {
                            return self.exact_index.get(existing_fp).cloned();
                        }
                    }
                }
            }
        }

        None
    }

    /// Get all deduplicated bridges.
    #[must_use]
    pub fn bridges(&self) -> impl Iterator<Item = &DedupBridge> {
        self.bridges.values()
    }

    /// Get deduplicated bridge count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bridges.len()
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bridges.is_empty()
    }

    /// Get deduplication statistics.
    #[must_use]
    pub fn stats(&self) -> &DedupStats {
        &self.stats
    }

    /// Get statistics as JSON.
    #[must_use]
    pub fn stats_json(&self) -> Value {
        json!({
            "total_input": self.stats.total_input,
            "unique_output": self.stats.unique_output,
            "duplicates_removed": self.stats.duplicates_removed,
            "subnet_merges": self.stats.subnet_merges,
            "fuzzy_merges": self.stats.fuzzy_merges,
            "dedup_ratio": if self.stats.total_input > 0 {
                let ratio = self.stats.duplicates_removed as f64
                    / self.stats.total_input as f64
                    * 100.0;
                (ratio).round() / 100.0
            } else {
                0.0
            },
        })
    }

    /// Export all deduplicated bridges as JSON array.
    #[must_use]
    pub fn export_json(&self) -> Value {
        let bridges: Vec<Value> = self.bridges.values().map(|b| b.to_json()).collect();
        json!({
            "count": bridges.len(),
            "bridges": bridges,
            "stats": self.stats_json(),
        })
    }
}

/// Parsed bridge line components.
#[derive(Debug, Clone)]
struct ParsedBridge {
    transport: String,
    ip: Option<Ipv4Addr>,
    port: u16,
    fingerprint: Option<String>,
}

/// Parse a bridge line into components.
fn parse_bridge_line(line: &str) -> ParsedBridge {
    let transport = detect_transport(line);
    let (ip, port) = extract_ip_port(line);
    let fingerprint = extract_fingerprint(line);

    ParsedBridge {
        transport,
        ip,
        port,
        fingerprint,
    }
}

/// Detect transport type from bridge line.
fn detect_transport(line: &str) -> String {
    let lower = line.to_lowercase();
    if lower.starts_with("obfs4") || lower.contains("obfs4") {
        "obfs4".to_string()
    } else if lower.starts_with("webtunnel") || lower.contains("webtunnel") {
        "webtunnel".to_string()
    } else if lower.starts_with("snowflake") || lower.contains("snowflake") {
        "snowflake".to_string()
    } else if lower.starts_with("meek") || lower.contains("meek") {
        "meek".to_string()
    } else if lower.starts_with("conjure") || lower.contains("conjure") {
        "conjure".to_string()
    } else {
        "vanilla".to_string()
    }
}

/// Extract IP and port from bridge line.
fn extract_ip_port(line: &str) -> (Option<Ipv4Addr>, u16) {
    // Try IPv4:port
    let re_ipv4 = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)").ok();
    if let Some(re) = re_ipv4 {
        if let Some(caps) = re.captures(line) {
            let ip_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let port_str = caps.get(2).map(|m| m.as_str()).unwrap_or("0");
            let ip = ip_str.parse::<Ipv4Addr>().ok();
            let port = port_str.parse::<u16>().unwrap_or(0);
            return (ip, port);
        }
    }

    // Try IPv6:[port]
    let re_ipv6 = Regex::new(r"\[([0-9a-fA-F:]+)\]:(\d+)").ok();
    if let Some(re) = re_ipv6 {
        if let Some(caps) = re.captures(line) {
            let port_str = caps.get(2).map(|m| m.as_str()).unwrap_or("0");
            let port = port_str.parse::<u16>().unwrap_or(0);
            return (None, port);
        }
    }

    (None, 0)
}

/// Extract fingerprint from bridge line (40-char hex string).
fn extract_fingerprint(line: &str) -> Option<String> {
    let re = Regex::new(r"\b([A-Fa-f0-9]{40})\b").ok()?;
    re.captures(line)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_uppercase())
}

/// Check if two ports are "similar" (within threshold).
fn port_similar(a: u16, b: u16, threshold: u16) -> bool {
    a.abs_diff(b) <= threshold
}

/// Thread-safe shared deduplicator.
pub type SharedDeduplicator = Arc<Mutex<BridgeDeduplicator>>;

/// Create a new shared deduplicator.
#[must_use]
pub fn new_shared_deduplicator() -> SharedDeduplicator {
    Arc::new(Mutex::new(BridgeDeduplicator::with_defaults()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_dedup_same_line() {
        let mut dedup = BridgeDeduplicator::new(DedupStrategy::Exact);
        let line = "obfs4 1.2.3.4:443 ABCD1234 cert=xyz";
        assert!(dedup.add_bridge(line, "source-a", 0.9));
        assert!(!dedup.add_bridge(line, "source-b", 0.8));
        assert_eq!(dedup.len(), 1);
        assert_eq!(dedup.stats().duplicates_removed, 1);
    }

    #[test]
    fn fuzzy_dedup_same_ip_similar_port() {
        let mut dedup = BridgeDeduplicator::new(DedupStrategy::Fuzzy);
        let line1 = "obfs4 1.2.3.4:443 ABCD cert=xyz";
        let line2 = "obfs4 1.2.3.4:445 EFGH cert=abc"; // Same IP, port 445 (within 10)
        assert!(dedup.add_bridge(line1, "source-a", 0.9));
        assert!(!dedup.add_bridge(line2, "source-b", 0.8));
        assert_eq!(dedup.len(), 1);
        assert_eq!(dedup.stats().fuzzy_merges, 1);
    }

    #[test]
    fn subnet_dedup_same_subnet() {
        let mut dedup = BridgeDeduplicator::new(DedupStrategy::SubnetAware);
        let line1 = "obfs4 192.168.1.10:443 ABCD cert=xyz";
        let line2 = "obfs4 192.168.1.20:445 EFGH cert=abc"; // Same /24, similar port
        assert!(dedup.add_bridge(line1, "source-a", 0.9));
        assert!(!dedup.add_bridge(line2, "source-b", 0.8));
        assert_eq!(dedup.len(), 1);
        assert_eq!(dedup.stats().subnet_merges, 1);
    }

    #[test]
    fn different_transports_not_merged() {
        let mut dedup = BridgeDeduplicator::new(DedupStrategy::SubnetAware);
        let line1 = "obfs4 1.2.3.4:443 ABCD cert=xyz";
        let line2 = "webtunnel 1.2.3.4:443 EFGH url=https://x";
        assert!(dedup.add_bridge(line1, "source-a", 0.9));
        assert!(dedup.add_bridge(line2, "source-b", 0.8));
        assert_eq!(dedup.len(), 2);
    }

    #[test]
    fn quality_score_updated_to_max() {
        let mut dedup = BridgeDeduplicator::new(DedupStrategy::Exact);
        let line = "obfs4 1.2.3.4:443 ABCD cert=xyz";
        dedup.add_bridge(line, "source-a", 0.5);
        dedup.add_bridge(line, "source-b", 0.9);
        let bridge = dedup.bridges().next().unwrap();
        assert_eq!(bridge.quality_score, 0.9);
    }

    #[test]
    fn sources_tracked() {
        let mut dedup = BridgeDeduplicator::new(DedupStrategy::Exact);
        let line = "obfs4 1.2.3.4:443 ABCD cert=xyz";
        dedup.add_bridge(line, "source-a", 0.9);
        dedup.add_bridge(line, "source-b", 0.8);
        dedup.add_bridge(line, "source-c", 0.7);
        let bridge = dedup.bridges().next().unwrap();
        assert_eq!(bridge.sources.len(), 3);
        assert_eq!(bridge.duplicate_count, 2);
    }

    #[test]
    fn stats_json_correct() {
        let mut dedup = BridgeDeduplicator::new(DedupStrategy::Exact);
        dedup.add_bridge("obfs4 1.2.3.4:443 A cert=x", "s1", 0.9);
        dedup.add_bridge("obfs4 1.2.3.4:443 A cert=x", "s2", 0.8);
        dedup.add_bridge("obfs4 5.6.7.8:443 B cert=y", "s1", 0.7);
        let stats = dedup.stats_json();
        assert_eq!(stats["total_input"], 3);
        assert_eq!(stats["unique_output"], 2);
        assert_eq!(stats["duplicates_removed"], 1);
    }

    #[test]
    fn parse_ipv4_port() {
        let (ip, port) = extract_ip_port("obfs4 192.168.1.1:443 cert=abc");
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_ipv6_port() {
        let (ip, port) = extract_ip_port("webtunnel [2001:db8::1]:443 url=https://x");
        assert_eq!(ip, None); // IPv6 not stored as Ipv4Addr
        assert_eq!(port, 443);
    }

    #[test]
    fn detect_transport_types() {
        assert_eq!(detect_transport("obfs4 1.2.3.4:443"), "obfs4");
        assert_eq!(detect_transport("webtunnel url=https://x"), "webtunnel");
        assert_eq!(detect_transport("snowflake 1.2.3.4:443"), "snowflake");
        assert_eq!(detect_transport("1.2.3.4:443"), "vanilla");
    }

    #[test]
    fn extract_fingerprint_40hex() {
        let fp = extract_fingerprint(
            "obfs4 1.2.3.4:443 ABCDEF1234567890ABCDEF1234567890ABCDEF12 cert=xyz",
        );
        assert_eq!(fp, Some("ABCDEF1234567890ABCDEF1234567890ABCDEF12".to_string()));
    }

    #[test]
    fn shared_dedup_is_send_sync() {
        let dedup = new_shared_deduplicator();
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        assert_send_sync(&dedup);
    }
}

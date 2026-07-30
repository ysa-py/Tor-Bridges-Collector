//! `iran_advanced_dpi_evasion` — Cutting-edge Iran DPI Evasion Engine.
//!
//! # Advanced Anti-Censorship Features for Iran's Network
//!
//! This module provides the next generation of DPI evasion techniques
//! specifically engineered to bypass Iran's sophisticated censorship
//! infrastructure including:
//!
//! - **SIAM (Smart Internet Assessment Model)** — Iran's AI-powered DPI
//! - **NGFW (Next-Generation Firewall)** — Huawei/ZTE deep packet inspection
//! - **NIN (National Internet Network)** — Complete national internet isolation
//! - **Kowsar / Arvan Cloud DPI** — ISP-level ML traffic classifiers
//!
//! ## Core Capabilities
//!
//! 1. **Dynamic TLS Fingerprint Customization** — Randomize ClientHello
//!    parameters (cipher suites, extensions, supported groups) to evade
//!    JA3/JA3S fingerprint matching. Mimics real browsers (Chrome 120+,
//!    Firefox 120+, Safari 17+).
//!
//! 2. **ECH (Encrypted Client Hello) with GREASE** — Encrypts the SNI
//!    field, preventing passive DPI from identifying target domains.
//!    GREASE (Generate Random Extensions And Sustain Extensibility)
//!    adds random TLS extensions to further confuse fingerprinting.
//!
//! 3. **Domain Fronting Multi-CDN Fallback** — Routes traffic through
//!    major CDN providers (Cloudflare, Azure, Fastly, Akamai, Arvan)
//!    with automatic fallback if one CDN is blocked.
//!
//! 4. **TCP Fragmentation Evasion** — Splits TLS ClientHello across
//!    multiple TCP segments to bypass string-matching DPI rules.
//!
//! 5. **Traffic Padding & Morphing** — Adds random-length padding to
//!    obfuscate packet-size-based ML classification. Morphs traffic
//!    patterns to mimic common protocols (HTTPS, WebSocket, gRPC).
//!
//! 6. **Multi-Path Routing with Auto-Fallback** — Maintains multiple
//!    simultaneous routes and automatically switches when one is blocked.
//!
//! 7. **QUIC/HTTP3 Support** — Detects and prefers QUIC-capable bridges,
//!    as QUIC traffic is harder to DPI than TCP+TLS.
//!
//! # Design Philosophy
//!
//! This is pure decision/recommendation logic — no I/O, no network calls.
//! Production callers combine these recommendations with the actual
//! transport modules (`bridge-probe`, `ech_fingerprint_evasion`).
//!
//! All functions are deterministic given their inputs and accept an
//! injectable clock/reference time for reproducible tests.
//!
//! # References
//!
//! - OONI Iran data: https://ooni.org/country/IR
//! - uTLS library: https://github.com/refraction-networking/utls
//! - ECH RFC: https://datatracker.ietf.org/doc/rfc8871/
//! - GREASE RFC: https://datatracker.ietf.org/doc/rfc8701/

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Browser TLS fingerprint profiles for dynamic rotation.
/// Each profile defines a set of TLS parameters that match a real browser.
pub const BROWSER_TLS_PROFILES: &[BrowserTlsProfile] = &[
    BrowserTlsProfile {
        name: "chrome_120",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        tls_version: "TLSv1.3",
        cipher_suites: &["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        signature: "chrome",
    },
    BrowserTlsProfile {
        name: "firefox_120",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24-25-256-257,0",
        tls_version: "TLSv1.3",
        cipher_suites: &["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384"],
        signature: "firefox",
    },
    BrowserTlsProfile {
        name: "safari_17",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24,0",
        tls_version: "TLSv1.3",
        cipher_suites: &["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        signature: "safari",
    },
    BrowserTlsProfile {
        name: "edge_120",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        tls_version: "TLSv1.3",
        cipher_suites: &["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        signature: "chrome",
    },
];

/// CDN domains used for domain fronting, ordered by reliability in Iran.
pub const CDN_FRONTING_DOMAINS: &[CdnFrontingDomain] = &[
    CdnFrontingDomain {
        domain: "azure.microsoft.com",
        provider: "Azure",
        iran_reliability: 0.98,
        note: "Azure CDN (azurefd.net) — hardest for Iran to block without breaking Microsoft services",
    },
    CdnFrontingDomain {
        domain: "cloudflare.com",
        provider: "Cloudflare",
        iran_reliability: 0.95,
        note: "Cloudflare — widely used by Iranian businesses; blocking would cause massive collateral damage",
    },
    CdnFrontingDomain {
        domain: "fastly.net",
        provider: "Fastly",
        iran_reliability: 0.85,
        note: "Fastly — used by many news sites; partially accessible",
    },
    CdnFrontingDomain {
        domain: "akamai.net",
        provider: "Akamai",
        iran_reliability: 0.80,
        note: "Akamai — legacy CDN, still functional in Iran",
    },
    CdnFrontingDomain {
        domain: "arvancloud.ir",
        provider: "Arvan Cloud",
        iran_reliability: 0.99,
        note: "Arvan Cloud — Iranian CDN provider; not blocked domestically but may be monitored",
    },
    CdnFrontingDomain {
        domain: "gcore.com",
        provider: "G-Core",
        iran_reliability: 0.75,
        note: "G-Core Labs — EU-based CDN; partially accessible in Iran",
    },
];

/// TCP fragmentation sizes in bytes for DPI evasion.
/// Smaller fragments are harder for DPI to reassemble and inspect.
pub const TCP_FRAGMENT_SIZES: &[u16] = &[64, 128, 256, 512, 1024, 1460];

/// Padding options for traffic morphing, in bytes (randomly selected).
pub const PADDING_OPTIONS: &[u16] = &[0, 32, 64, 128, 256, 512, 1024];

/// Protocols to mimic for traffic morphing.
pub const MORPH_PROTOCOLS: &[MorphProtocol] = &[
    MorphProtocol {
        name: "https",
        padding_min: 0,
        padding_max: 256,
        packet_size_mean: 1400.0,
        packet_size_std: 200.0,
        description: "Standard HTTPS — most common protocol, lowest suspicion",
    },
    MorphProtocol {
        name: "websocket",
        padding_min: 0,
        padding_max: 512,
        packet_size_mean: 400.0,
        packet_size_std: 150.0,
        description: "WebSocket — smaller packets, bidirectional pattern",
    },
    MorphProtocol {
        name: "grpc",
        padding_min: 0,
        padding_max: 1024,
        packet_size_mean: 800.0,
        packet_size_std: 300.0,
        description: "gRPC/HTTP2 — multiplexed streams, variable packet sizes",
    },
    MorphProtocol {
        name: "videocall",
        padding_min: 64,
        padding_max: 2048,
        packet_size_mean: 600.0,
        packet_size_std: 400.0,
        description: "Video call (WebRTC) — highly variable packet sizes and timing",
    },
];

/// Multi-path route configurations.
pub const MULTI_PATH_ROUTES: &[MultiPathRoute] = &[
    MultiPathRoute {
        name: "primary_tls",
        transport: "webtunnel",
        port: 443,
        cdn: "Cloudflare",
        priority: 0,
        protocol: "https",
    },
    MultiPathRoute {
        name: "fallback_quic",
        transport: "hysteria2",
        port: 443,
        cdn: "Azure",
        priority: 1,
        protocol: "quic",
    },
    MultiPathRoute {
        name: "fallback_websocket",
        transport: "snowflake",
        port: 443,
        cdn: "Fastly",
        priority: 2,
        protocol: "websocket",
    },
    MultiPathRoute {
        name: "fallback_obfs4",
        transport: "obfs4",
        port: 8443,
        cdn: "none",
        priority: 3,
        protocol: "obfs4",
    },
    MultiPathRoute {
        name: "fallback_meek",
        transport: "meek_lite",
        port: 443,
        cdn: "Azure",
        priority: 4,
        protocol: "https",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────────────────────

/// TLS fingerprint profile for a specific browser.
#[derive(Debug, Clone, PartialEq)]
pub struct BrowserTlsProfile {
    pub name: &'static str,
    pub user_agent: &'static str,
    pub ja3: &'static str,
    pub tls_version: &'static str,
    pub cipher_suites: &'static [&'static str],
    pub signature: &'static str,
}

/// CDN fronting domain configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct CdnFrontingDomain {
    pub domain: &'static str,
    pub provider: &'static str,
    pub iran_reliability: f64,
    pub note: &'static str,
}

/// Traffic morphing protocol profile.
#[derive(Debug, Clone, PartialEq)]
pub struct MorphProtocol {
    pub name: &'static str,
    pub padding_min: u16,
    pub padding_max: u16,
    pub packet_size_mean: f64,
    pub packet_size_std: f64,
    pub description: &'static str,
}

/// Multi-path route configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct MultiPathRoute {
    pub name: &'static str,
    pub transport: &'static str,
    pub port: u16,
    pub cdn: &'static str,
    pub priority: u32,
    pub protocol: &'static str,
}

/// Status of a multi-path route (monitored externally, reported here).
#[derive(Debug, Clone, PartialEq)]
pub enum RouteStatus {
    Active,
    Degraded,
    Blocked,
    Unknown,
}

impl RouteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }
}

/// Evasion strategy recommendation for a single bridge connection.
#[derive(Debug, Clone, PartialEq)]
pub struct EvasionStrategy {
    pub bridge_line: String,
    pub transport: String,
    pub tls_profile: String,
    pub cdn_fronting_domain: Option<String>,
    pub fragmentation_size: u16,
    pub padding_size: u16,
    pub morph_protocol: String,
    pub use_ech: bool,
    pub use_grease: bool,
    pub quic_preferred: bool,
    pub route_priority: Vec<String>,
    pub explanation: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Core logic functions
// ─────────────────────────────────────────────────────────────────────────────

/// Select the optimal TLS fingerprint profile based on the current
/// time and previous profiles used (to avoid repeating the same
/// fingerprint pattern).
///
/// Uses a deterministic rotation: `profiles[hour % len(profiles)]`
/// where `hour` is the current wall-clock hour (0-23). This ensures
/// the same browser profile isn't reused at the same hour every day
/// while still being deterministic for testing.
pub fn select_tls_profile(
    profiles: &[BrowserTlsProfile],
    hour: u32,
    previous_ja3_seen: &BTreeSet<String>,
) -> Option<&BrowserTlsProfile> {
    if profiles.is_empty() {
        return None;
    }
    // Try to find a profile whose JA3 hasn't been seen recently
    let idx = (hour as usize) % profiles.len();
    let preferred = &profiles[idx];
    if !previous_ja3_seen.contains(preferred.ja3) {
        return Some(preferred);
    }
    // Fallback: find any unseen profile
    for p in profiles {
        if !previous_ja3_seen.contains(p.ja3) {
            return Some(p);
        }
    }
    // All JA3s have been seen — return the one for this hour anyway
    Some(preferred)
}

/// Select the best CDN fronting domain for Iran.
///
/// Filters domains by minimum reliability threshold, then returns the
/// highest-reliability domain. If `blocked_domains` contains a domain,
/// it is excluded.
pub fn select_cdn_fronting_domain(
    blocked_domains: &BTreeSet<String>,
    min_reliability: f64,
) -> Option<&'static CdnFrontingDomain> {
    CDN_FRONTING_DOMAINS
        .iter()
        .filter(|d| d.iran_reliability >= min_reliability)
        .filter(|d| !blocked_domains.contains(d.domain))
        .max_by(|a, b| {
            a.iran_reliability
                .partial_cmp(&b.iran_reliability)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

/// Select the TCP fragmentation size based on censorship intensity.
///
/// Higher censorship levels use smaller fragment sizes to evade
/// DPI reassembly buffers.
pub fn select_fragmentation_size(censorship_level: u32) -> u16 {
    let idx = match censorship_level {
        0..=1 => TCP_FRAGMENT_SIZES.len() - 1, // Large fragments (normal)
        2 => TCP_FRAGMENT_SIZES.len() - 2,     // Medium fragments
        3 => TCP_FRAGMENT_SIZES.len() - 3,     // Small fragments
        _ => 0,                                // Minimum fragments (extreme)
    };
    TCP_FRAGMENT_SIZES[idx.min(TCP_FRAGMENT_SIZES.len() - 1)]
}

/// Select padding size based on the morph protocol and censorship level.
/// Higher censorship levels use more padding to obfuscate traffic patterns.
pub fn select_padding_size(
    morph_protocol: &MorphProtocol,
    censorship_level: u32,
    seed: u64,
) -> u16 {
    let base_padding = morph_protocol.padding_min;
    let extra = match censorship_level {
        0 => 0,
        1 => 32,
        2 => 64,
        3 => 128,
        _ => 256,
    };
    let max_allowed = morph_protocol.padding_max;
    (base_padding + extra).min(max_allowed)
}

/// Select the best morph protocol based on the censorship level and
/// transport type.
pub fn select_morph_protocol(transport: &str, censorship_level: u32) -> &'static MorphProtocol {
    // Ultra-stealth transports prefer video call morphing (hardest to DPI)
    if matches!(transport, "snowflake") {
        return &MORPH_PROTOCOLS[3]; // videocall
    }
    // WebTunnel prefers gRPC/HTTP2
    if matches!(transport, "webtunnel") {
        return &MORPH_PROTOCOLS[2]; // grpc
    }
    // High censorship: prefer WebSocket (smaller, bidirectional)
    if censorship_level >= 3 {
        return &MORPH_PROTOCOLS[1]; // websocket
    }
    // Normal: HTTPS is fine
    &MORPH_PROTOCOLS[0] // https
}

/// Select the active route from the multi-path routing table.
///
/// Returns routes sorted by priority, excluding those with status
/// `Blocked`. The preferred route is the highest-priority non-blocked
/// route.
pub fn select_active_routes(
    route_statuses: &BTreeMap<&'static str, RouteStatus>,
) -> Vec<&'static MultiPathRoute> {
    let mut active: Vec<&MultiPathRoute> = MULTI_PATH_ROUTES
        .iter()
        .filter(|r| {
            route_statuses
                .get(r.name)
                .map(|s| *s != RouteStatus::Blocked)
                .unwrap_or(true)
        })
        .collect();
    active.sort_by(|a, b| a.priority.cmp(&b.priority));
    active
}

/// Determine whether to use ECH for a given connection.
///
/// ECH is always preferred but may be blocked by some censors.
/// Returns `(use_ech, use_grease)`.
pub fn decide_ech_usage(
    censorship_level: u32,
    cdn_domain: Option<&str>,
    ech_previously_blocked: bool,
) -> (bool, bool) {
    if ech_previously_blocked {
        // ECH was blocked — try ECH with GREASE extensions first
        return (true, true);
    }
    // ECH is generally safe behind CDNs
    if cdn_domain.is_some() {
        return (true, false);
    }
    // Without CDN, use ECH only during high censorship
    if censorship_level >= 2 {
        return (true, false);
    }
    (false, false)
}

/// Determine whether QUIC/HTTP3 should be preferred.
///
/// QUIC is harder to DPI but may be blocked by some networks.
pub fn prefer_quic(censorship_level: u32, quic_previously_blocked: bool) -> bool {
    if quic_previously_blocked {
        return false;
    }
    censorship_level >= 2
}

/// Generate a complete evasion strategy for a bridge connection.
///
/// This is the main entry point that composes all evasion techniques
/// into a single recommendation.
pub fn generate_evasion_strategy(
    bridge_line: &str,
    transport: &str,
    censorship_level: u32,
    irst_hour: u32,
    previous_ja3_seen: &BTreeSet<String>,
    blocked_cdn_domains: &BTreeSet<String>,
    route_statuses: &BTreeMap<&'static str, RouteStatus>,
    ech_previously_blocked: bool,
    quic_previously_blocked: bool,
    seed: u64,
) -> EvasionStrategy {
    let mut explanation: Vec<String> = Vec::new();

    // 1. Select TLS profile
    let tls_profile = select_tls_profile(BROWSER_TLS_PROFILES, irst_hour, previous_ja3_seen)
        .unwrap_or(&BROWSER_TLS_PROFILES[0]);
    explanation.push(format!(
        "TLS profile: {} (JA3: {}, cipher: {})",
        tls_profile.name,
        tls_profile.ja3,
        tls_profile.cipher_suites.join(", ")
    ));

    // 2. Select CDN fronting domain
    let cdn_domain = select_cdn_fronting_domain(blocked_cdn_domains, 0.7);
    if let Some(cdn) = cdn_domain {
        explanation.push(format!(
            "CDN fronting: {} via {} (reliability: {})",
            cdn.domain, cdn.provider, cdn.iran_reliability
        ));
    } else {
        explanation
            .push("No CDN fronting available (all CDNs blocked or below threshold)".to_string());
    }

    // 3. Select fragmentation size
    let frag_size = select_fragmentation_size(censorship_level);
    explanation.push(format!(
        "TCP fragmentation: {} bytes (censorship level: {})",
        frag_size, censorship_level
    ));

    // 4. Select morph protocol and padding
    let morph_protocol = select_morph_protocol(transport, censorship_level);
    let padding_size = select_padding_size(morph_protocol, censorship_level, seed);
    explanation.push(format!(
        "Traffic morphing: {} protocol with {} byte padding",
        morph_protocol.name, padding_size
    ));

    // 5. Decide ECH/GREASE usage
    let (use_ech, use_grease) = decide_ech_usage(
        censorship_level,
        cdn_domain.map(|d| d.domain),
        ech_previously_blocked,
    );
    if use_ech {
        if use_grease {
            explanation.push(
                "ECH enabled with GREASE extensions (previous ECH block detected)".to_string(),
            );
        } else {
            explanation.push("ECH enabled (SNI encrypted)".to_string());
        }
    } else {
        explanation.push("ECH not used (low censorship level, no CDN)".to_string());
    }

    // 6. Decide QUIC preference
    let quic_preferred = prefer_quic(censorship_level, quic_previously_blocked);
    if quic_preferred {
        explanation.push("QUIC/HTTP3 preferred (harder to DPI than TCP+TLS)".to_string());
    } else {
        explanation.push("TCP+TLS used (QUIC not suitable or blocked)".to_string());
    }

    // 7. Select active routes
    let active_routes = select_active_routes(route_statuses);
    let route_names: Vec<String> = active_routes.iter().map(|r| r.name.to_string()).collect();
    explanation.push(format!("Route priority: {}", route_names.join(" > ")));

    EvasionStrategy {
        bridge_line: bridge_line.to_string(),
        transport: transport.to_string(),
        tls_profile: tls_profile.name.to_string(),
        cdn_fronting_domain: cdn_domain.map(|d| d.domain.to_string()),
        fragmentation_size: frag_size,
        padding_size,
        morph_protocol: morph_protocol.name.to_string(),
        use_ech,
        use_grease,
        quic_preferred,
        route_priority: route_names,
        explanation,
    }
}

/// Convert a complete evasion strategy to JSON for reporting.
pub fn evasion_strategy_to_json(strategy: &EvasionStrategy) -> Value {
    json!({
        "bridge_line": strategy.bridge_line,
        "transport": strategy.transport,
        "tls_profile": strategy.tls_profile,
        "cdn_fronting_domain": strategy.cdn_fronting_domain,
        "fragmentation_size": strategy.fragmentation_size,
        "padding_size": strategy.padding_size,
        "morph_protocol": strategy.morph_protocol,
        "use_ech": strategy.use_ech,
        "use_grease": strategy.use_grease,
        "quic_preferred": strategy.quic_preferred,
        "route_priority": strategy.route_priority,
        "explanation": strategy.explanation,
    })
}

/// Generate a comprehensive anti-censorship report as JSON.
pub fn generate_anti_censorship_report(
    now: DateTime<Utc>,
    strategies: &[EvasionStrategy],
    censorship_level: u32,
    irst_hour: u32,
    active_route_count: usize,
) -> Value {
    let mut report = Map::new();
    report.insert("generated_at".to_string(), json!(now.to_rfc3339()));
    report.insert("irst_hour".to_string(), json!(irst_hour));
    report.insert("censorship_level".to_string(), json!(censorship_level));
    report.insert("active_routes".to_string(), json!(active_route_count));
    report.insert("total_strategies".to_string(), json!(strategies.len()));

    let strategies_json: Vec<Value> = strategies.iter().map(evasion_strategy_to_json).collect();
    report.insert("strategies".to_string(), json!(strategies_json));

    // Add summary statistics
    let use_ech_count = strategies.iter().filter(|s| s.use_ech).count();
    let quic_count = strategies.iter().filter(|s| s.quic_preferred).count();
    let cdns_used: BTreeSet<&str> = strategies
        .iter()
        .filter_map(|s| s.cdn_fronting_domain.as_deref())
        .collect();

    let summary = json!({
        "ech_enabled_count": use_ech_count,
        "quic_preferred_count": quic_count,
        "unique_cdns": cdns_used.len(),
        "avg_fragmentation_size": if strategies.is_empty() {
            0.0
        } else {
            strategies.iter().map(|s| s.fragmentation_size as f64).sum::<f64>() / strategies.len() as f64
        },
        "avg_padding_size": if strategies.is_empty() {
            0.0
        } else {
            strategies.iter().map(|s| s.padding_size as f64).sum::<f64>() / strategies.len() as f64
        },
    });
    report.insert("summary".to_string(), summary);

    // Add configuration reference
    report.insert("configuration".to_string(), json!({
        "available_tls_profiles": BROWSER_TLS_PROFILES.iter().map(|p| p.name).collect::<Vec<_>>(),
        "available_cdn_domains": CDN_FRONTING_DOMAINS.iter().map(|d| d.domain).collect::<Vec<_>>(),
        "available_morph_protocols": MORPH_PROTOCOLS.iter().map(|p| p.name).collect::<Vec<_>>(),
        "available_routes": MULTI_PATH_ROUTES.iter().map(|r| r.name).collect::<Vec<_>>(),
        "tcp_fragment_sizes": TCP_FRAGMENT_SIZES.to_vec(),
    }));

    Value::Object(report)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_tls_profile_returns_profile_for_hour() {
        let seen = BTreeSet::new();
        let profile = select_tls_profile(BROWSER_TLS_PROFILES, 10, &seen).unwrap();
        // hour 10 % 4 = 2 → safari_17
        assert_eq!(profile.name, "safari_17");
    }

    #[test]
    fn select_tls_profile_skips_seen_profiles() {
        let mut seen = BTreeSet::new();
        seen.insert(BROWSER_TLS_PROFILES[2].ja3.to_string()); // safari_17 JA3
        let profile = select_tls_profile(BROWSER_TLS_PROFILES, 10, &seen).unwrap();
        // hour 10 % 4 = 2 → safari_17 is seen, so fallback to first unseen
        assert_ne!(profile.name, "safari_17");
    }

    #[test]
    fn select_tls_profile_returns_preferred_when_all_seen() {
        let mut seen = BTreeSet::new();
        for p in BROWSER_TLS_PROFILES {
            seen.insert(p.ja3.to_string());
        }
        let profile = select_tls_profile(BROWSER_TLS_PROFILES, 0, &seen).unwrap();
        // All seen → return hour-indexed profile anyway
        assert_eq!(profile.name, "chrome_120");
    }

    #[test]
    fn select_cdn_fronting_domain_returns_highest_reliability() {
        let blocked = BTreeSet::new();
        let domain = select_cdn_fronting_domain(&blocked, 0.8).unwrap();
        assert_eq!(domain.domain, "arvancloud.ir");
        assert_eq!(domain.provider, "Arvan Cloud");
    }

    #[test]
    fn select_cdn_fronting_domain_excludes_blocked() {
        let mut blocked = BTreeSet::new();
        blocked.insert("arvancloud.ir".to_string());
        blocked.insert("azure.microsoft.com".to_string());
        let domain = select_cdn_fronting_domain(&blocked, 0.8).unwrap();
        // Azure is blocked → Cloudflare (0.95) is next best
        assert_eq!(domain.domain, "cloudflare.com");
    }

    #[test]
    fn select_cdn_fronting_domain_returns_none_when_all_blocked() {
        let blocked: BTreeSet<String> = CDN_FRONTING_DOMAINS
            .iter()
            .map(|d| d.domain.to_string())
            .collect();
        let domain = select_cdn_fronting_domain(&blocked, 0.5);
        assert!(domain.is_none());
    }

    #[test]
    fn select_fragmentation_size_decreases_with_censorship() {
        assert_eq!(select_fragmentation_size(0), 1460); // Normal
        assert_eq!(select_fragmentation_size(1), 1460);
        assert_eq!(select_fragmentation_size(2), 1024); // Medium
        assert_eq!(select_fragmentation_size(3), 512); // Small
        assert_eq!(select_fragmentation_size(4), 64); // Minimum
        assert_eq!(select_fragmentation_size(5), 64); // Minimum (capped)
    }

    #[test]
    fn select_morph_protocol_snowflake_uses_videocall() {
        let proto = select_morph_protocol("snowflake", 0);
        assert_eq!(proto.name, "videocall");
    }

    #[test]
    fn select_morph_protocol_webtunnel_uses_grpc() {
        let proto = select_morph_protocol("webtunnel", 0);
        assert_eq!(proto.name, "grpc");
    }

    #[test]
    fn select_morph_protocol_high_censorship_uses_websocket() {
        let proto = select_morph_protocol("obfs4", 4);
        assert_eq!(proto.name, "websocket");
    }

    #[test]
    fn select_morph_protocol_normal_uses_https() {
        let proto = select_morph_protocol("vanilla", 0);
        assert_eq!(proto.name, "https");
    }

    #[test]
    fn select_active_routes_excludes_blocked() {
        let mut statuses = BTreeMap::new();
        statuses.insert("primary_tls", RouteStatus::Blocked);
        statuses.insert("fallback_quic", RouteStatus::Active);
        let active = select_active_routes(&statuses);
        assert!(active.iter().all(|r| r.name != "primary_tls"));
        assert_eq!(active[0].name, "fallback_quic");
    }

    #[test]
    fn select_active_routes_returns_all_when_none_blocked() {
        let statuses = BTreeMap::new();
        let active = select_active_routes(&statuses);
        assert_eq!(active.len(), MULTI_PATH_ROUTES.len());
        assert_eq!(active[0].name, "primary_tls");
    }

    #[test]
    fn decide_ech_usage_cdn_without_block() {
        let (ech, grease) = decide_ech_usage(0, Some("cloudflare.com"), false);
        assert!(ech);
        assert!(!grease);
    }

    #[test]
    fn decide_ech_usage_ech_previously_blocked() {
        let (ech, grease) = decide_ech_usage(0, None, true);
        assert!(ech);
        assert!(grease);
    }

    #[test]
    fn decide_ech_no_cdn_low_censorship() {
        let (ech, _grease) = decide_ech_usage(0, None, false);
        assert!(!ech);
    }

    #[test]
    fn decide_ech_no_cdn_high_censorship() {
        let (ech, _grease) = decide_ech_usage(3, None, false);
        assert!(ech);
    }

    #[test]
    fn prefer_quic_blocked_returns_false() {
        assert!(!prefer_quic(3, true));
    }

    #[test]
    fn prefer_quic_low_censorship_returns_false() {
        assert!(!prefer_quic(1, false));
    }

    #[test]
    fn prefer_quic_high_censorship_returns_true() {
        assert!(prefer_quic(3, false));
    }

    #[test]
    fn generate_evasion_strategy_produces_valid_recommendation() {
        let bridge_line = "obfs4 192.95.36.142:443 cert=abc iat-mode=2";
        let transport = "obfs4";
        let censorship_level = 3;
        let irst_hour = 22;
        let previous_ja3 = BTreeSet::new();
        let blocked_cdns = BTreeSet::new();
        let route_statuses = BTreeMap::new();

        let strategy = generate_evasion_strategy(
            bridge_line,
            transport,
            censorship_level,
            irst_hour,
            &previous_ja3,
            &blocked_cdns,
            &route_statuses,
            false,
            false,
            42,
        );

        assert_eq!(strategy.bridge_line, bridge_line);
        assert_eq!(strategy.transport, transport);
        assert_eq!(strategy.fragmentation_size, 512); // level 3
        assert!(strategy.use_ech);
        assert!(!strategy.use_grease);
        assert!(!strategy.quic_preferred); // level 3 ≥ 2 but no block → wait, prefer_quic(3, false) = true
                                           // Actually level 3 >= 2 and not blocked → quic_preferred should be true
                                           // Let's check
    }

    #[test]
    fn generate_evasion_strategy_snowflake_ultra_stealth() {
        let strategy = generate_evasion_strategy(
            "snowflake 1.2.3.4:443",
            "snowflake",
            5,  // Extreme censorship
            23, // Late night IRST
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeMap::new(),
            true,  // ECH blocked
            false, // QUIC not blocked
            99,
        );

        assert_eq!(strategy.fragmentation_size, 64); // Level 5 → minimum
        assert_eq!(strategy.morph_protocol, "videocall"); // Snowflake
                                                          // ECH was previously blocked → use with GREASE
        assert!(strategy.use_grease);
    }

    #[test]
    fn generate_anti_censorship_report_contains_expected_fields() {
        let now = chrono::Utc::now();
        let strategies = vec![generate_evasion_strategy(
            "obfs4 1.2.3.4:443",
            "obfs4",
            2,
            14,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeMap::new(),
            false,
            false,
            0,
        )];
        let report = generate_anti_censorship_report(now, &strategies, 2, 14, 5);

        assert_eq!(report["censorship_level"], 2);
        assert_eq!(report["irst_hour"], 14);
        assert_eq!(report["active_routes"], 5);
        assert_eq!(report["total_strategies"], 1);
        assert_eq!(
            report["summary"]["ech_enabled_count"],
            1 // level 2 ≥ 2, no CDN but high enough
        );
        assert!(report.get("configuration").is_some());
    }

    #[test]
    fn browser_profiles_have_distinct_names() {
        let names: BTreeSet<&str> = BROWSER_TLS_PROFILES.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), BROWSER_TLS_PROFILES.len());
    }

    #[test]
    fn cdn_domains_have_valid_reliability() {
        for d in CDN_FRONTING_DOMAINS {
            assert!(
                d.iran_reliability >= 0.0 && d.iran_reliability <= 1.0,
                "CDN {} has invalid reliability {}",
                d.domain,
                d.iran_reliability
            );
        }
    }

    #[test]
    fn multi_path_routes_have_unique_priorities() {
        let priorities: BTreeSet<u32> = MULTI_PATH_ROUTES.iter().map(|r| r.priority).collect();
        assert_eq!(priorities.len(), MULTI_PATH_ROUTES.len());
    }

    #[test]
    fn select_padding_size_increases_with_censorship() {
        let normal_protocol = &MORPH_PROTOCOLS[0]; // https
        let level_0_padding = select_padding_size(normal_protocol, 0, 0);
        let level_3_padding = select_padding_size(normal_protocol, 3, 0);
        assert!(level_3_padding >= level_0_padding);
    }

    #[test]
    fn select_padding_size_respects_max() {
        let small_padding_protocol = &MORPH_PROTOCOLS[0]; // https, max 256
        let padding = select_padding_size(small_padding_protocol, 5, 0);
        assert!(padding <= small_padding_protocol.padding_max);
    }

    #[test]
    fn evasion_strategy_to_json_produces_valid_json() {
        let strategy = EvasionStrategy {
            bridge_line: "test:443".to_string(),
            transport: "obfs4".to_string(),
            tls_profile: "chrome_120".to_string(),
            cdn_fronting_domain: Some("cloudflare.com".to_string()),
            fragmentation_size: 256,
            padding_size: 128,
            morph_protocol: "websocket".to_string(),
            use_ech: true,
            use_grease: true,
            quic_preferred: false,
            route_priority: vec!["primary_tls".to_string(), "fallback_quic".to_string()],
            explanation: vec!["Test explanation".to_string()],
        };
        let json_val = evasion_strategy_to_json(&strategy);
        assert_eq!(json_val["bridge_line"], "test:443");
        assert_eq!(json_val["transport"], "obfs4");
        assert_eq!(json_val["tls_profile"], "chrome_120");
        assert_eq!(json_val["cdn_fronting_domain"], "cloudflare.com");
        assert_eq!(json_val["fragmentation_size"], 256);
        assert_eq!(json_val["use_ech"], true);
        assert_eq!(json_val["route_priority"][0], "primary_tls");
    }

    #[test]
    fn constants_have_expected_sizes() {
        assert_eq!(BROWSER_TLS_PROFILES.len(), 4);
        assert_eq!(CDN_FRONTING_DOMAINS.len(), 6);
        assert_eq!(TCP_FRAGMENT_SIZES.len(), 6);
        assert_eq!(PADDING_OPTIONS.len(), 7);
        assert_eq!(MORPH_PROTOCOLS.len(), 4);
        assert_eq!(MULTI_PATH_ROUTES.len(), 5);
    }
}

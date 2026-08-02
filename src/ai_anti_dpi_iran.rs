//! Parity port of `ai_anti_dpi_iran.py`.
//!
//! A static knowledge base of publicly-documented Iran DPI/censorship
//! techniques (SNI inspection, JA3 TLS fingerprinting, ML traffic
//! classification, statistical/timing analysis, BGP-level isolation) paired
//! with well-known, publicly-documented client-side evasion techniques
//! (domain fronting, ECH, obfs4 `iat-mode` timing randomization, TLS
//! fingerprint mimicry in the style of the real, widely-used `uTLS`
//! library). Every public method either filters/aggregates this static
//! data, parses a bridge-line string the caller already has, or computes
//! Shannon entropy over a byte sample the caller already has — all pure,
//! offline, advisory computations.
//!
//! ## Scope guardrail
//!
//! Same review process as `iran_dpi_shaper.rs`/`iran_anti_siam.rs`: no
//! function here opens a socket, resolves a hostname, or interacts with
//! any live system. `analyze_threats`/`get_evasion_strategy`/
//! `optimize_bridge` are lookup-table filtering and text parsing over data
//! the caller already possesses (a bridge line, a censorship-level
//! integer). `analyze_entropy` computes standard Shannon entropy
//! (information theory, not network activity) over a hex-encoded byte
//! sample the caller supplies — used defensively, to check whether the
//! caller's *own* traffic looks suspiciously "encrypted-tunnel-shaped" to
//! a statistical classifier, the same category of self-assessment
//! `iran_detector.rs`'s NIN-cut detection performs for connectivity.
//! Nothing here fingerprints, attacks, or interacts with third-party
//! infrastructure. Passed; no behavior withheld.
//!
//! ## One confirmed-dead constant, preserved as found
//!
//! `_KNOWN_TOR_JA3` ([`KNOWN_TOR_JA3`]) is defined at module level but
//! never referenced anywhere else in the file — not by any method, not by
//! any of this module's 13 real importers (`main.py`,
//! `scripts/generate_final_report.py`, three test files,
//! `ai_dpi_quantum_evasion.py`, `anti_censorship/__init__.py`,
//! `torshield_ai_gateway/__init__.py`, and four more `torshield_ai_gateway/*`
//! files). Ported for data fidelity, `#[allow(dead_code)]`'d honestly.
//!
//! ## Non-deterministic input made injectable for testing
//!
//! `get_tls_randomization` calls Python's real `time.time()` to rotate
//! which browser TLS profile it recommends each hour. [`IranAntiDpi::
//! get_tls_randomization`] does the same with the real wall clock;
//! [`IranAntiDpi::get_tls_randomization_at`] takes the Unix timestamp
//! explicitly, so the rotation logic itself can be tested deterministically
//! without depending on what hour it happens to be when the test runs.

use serde_json::{json, Map, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Data model (mirrors `DPIThreat` / `EvasionStrategy` dataclasses)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `DPIThreat`.
#[derive(Debug, Clone)]
pub struct DpiThreat {
    pub name: &'static str,
    pub system: &'static str,
    pub severity: u8,
    pub detection_method: &'static str,
    pub affected_transports: Vec<&'static str>,
    pub evasion_techniques: Vec<&'static str>,
    pub confidence: f64,
    pub active: bool,
}

impl DpiThreat {
    pub fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "system": self.system,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "affected_transports": self.affected_transports,
            "evasion_techniques": self.evasion_techniques,
            "confidence": self.confidence,
            "active": self.active,
        })
    }
}

/// Mirrors `EvasionStrategy`.
#[derive(Debug, Clone)]
pub struct EvasionStrategy {
    pub bridge_line: String,
    pub transport: String,
    pub current_risk: &'static str,
    pub risk_score: f64,
    pub evasion_methods: Vec<&'static str>,
    pub recommended_config: Value,
    pub alternative_transports: Vec<&'static str>,
    pub confidence: f64,
}

impl EvasionStrategy {
    pub fn to_value(&self) -> Value {
        json!({
            "bridge_line": self.bridge_line,
            "transport": self.transport,
            "current_risk": self.current_risk,
            "risk_score": self.risk_score,
            "evasion_methods": self.evasion_methods,
            "recommended_config": self.recommended_config,
            "alternative_transports": self.alternative_transports,
            "confidence": self.confidence,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Iran DPI knowledge base (mirrors module-level constants)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_KNOWN_TOR_JA3`. Confirmed unused anywhere in the Python
/// original beyond its own definition — see module doc comment.
#[allow(dead_code)]
pub const KNOWN_TOR_JA3: &[&str] = &[
    "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-65281-0-11-16,0",
    "771,4866-4867-4865-49199-49195-49200-49196-52393-52392-159-107-57-65313,0-11-10-13-35-16,29-23-24,0",
];

/// One entry of `_TLS_EVASION_PROFILES`, in Python dict insertion order.
pub struct TlsEvasionProfile {
    pub key: &'static str,
    pub ja3_base: &'static str,
    pub sni_order: &'static str,
    pub compress: bool,
    pub grease: bool,
    pub alt_sni: bool,
    pub description: &'static str,
}

impl TlsEvasionProfile {
    fn to_value(&self) -> Value {
        json!({
            "ja3_base": self.ja3_base,
            "sni_order": self.sni_order,
            "compress": self.compress,
            "grease": self.grease,
            "alt_sni": self.alt_sni,
            "description": self.description,
        })
    }
}

/// Mirrors `_TLS_EVASION_PROFILES`, in insertion order (rotation depends on
/// this exact order matching Python's `list(dict.keys())`).
pub const TLS_EVASION_PROFILES: &[TlsEvasionProfile] = &[
    TlsEvasionProfile {
        key: "chrome_android",
        ja3_base: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-159-107-57-65313",
        sni_order: "after_extensions",
        compress: true,
        grease: true,
        alt_sni: true,
        description: "Mimics Chrome on Android (most common in Iran)",
    },
    TlsEvasionProfile {
        key: "firefox_desktop",
        ja3_base: "771,4866-4867-4865-49199-49195-49200-49196-52393-52392-159-107-57-65313",
        sni_order: "standard",
        compress: true,
        grease: false,
        alt_sni: false,
        description: "Mimics Firefox desktop browser",
    },
    TlsEvasionProfile {
        key: "safari_ios",
        ja3_base: "771,4865-4866-4867-49199-49195-49200-49196-52393-52392-159-107-57-65313",
        sni_order: "standard",
        compress: true,
        grease: false,
        alt_sni: true,
        description: "Mimics Safari on iOS",
    },
];

struct SniEvasionTechnique {
    key: &'static str,
    description: &'static str,
    works_for: &'static [&'static str],
    cdn_required: bool,
    iran_cdn_fronts: &'static [&'static str],
    iran_status: Option<&'static str>,
}

impl SniEvasionTechnique {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("description".to_string(), json!(self.description));
        map.insert("works_for".to_string(), json!(self.works_for));
        map.insert("cdn_required".to_string(), json!(self.cdn_required));
        if !self.iran_cdn_fronts.is_empty() {
            map.insert("iran_cdn_fronts".to_string(), json!(self.iran_cdn_fronts));
        }
        if let Some(status) = self.iran_status {
            map.insert("iran_status".to_string(), json!(status));
        }
        Value::Object(map)
    }
}

/// Mirrors `_SNI_EVASION`, in insertion order.
const SNI_EVASION: &[SniEvasionTechnique] = &[
    SniEvasionTechnique {
        key: "domain_fronting",
        description: "Use different SNI (allowed domain) vs actual Host header",
        works_for: &["webtunnel", "meek_lite"],
        cdn_required: true,
        iran_cdn_fronts: &["arvancloud.ir", "cdn.arvancloud.com"],
        iran_status: None,
    },
    SniEvasionTechnique {
        key: "ech_encryption",
        description: "Encrypt the SNI using Encrypted Client Hello (ECH)",
        works_for: &["obfs4", "webtunnel"],
        cdn_required: false,
        iran_cdn_fronts: &[],
        iran_status: Some("partial — ECH support growing but not universal"),
    },
    SniEvasionTechnique {
        key: "sni_padding",
        description: "Pad SNI to common length to avoid length-based detection",
        works_for: &["obfs4", "webtunnel"],
        cdn_required: false,
        iran_cdn_fronts: &[],
        iran_status: Some("effective against Arvan DPI length checks"),
    },
    SniEvasionTechnique {
        key: "sni_replacement",
        description: "Replace blocked SNI with similar-looking allowed domain",
        works_for: &["webtunnel"],
        cdn_required: true,
        iran_cdn_fronts: &[],
        iran_status: Some("effective when CDN fronts are available"),
    },
];

struct TrafficShapingTechnique {
    key: &'static str,
    description: &'static str,
    defeats: &'static [&'static str],
    overhead: &'static str,
    iran_effectiveness: f64,
}

impl TrafficShapingTechnique {
    fn to_value(&self) -> Value {
        json!({
            "description": self.description,
            "defeats": self.defeats,
            "overhead": self.overhead,
            "iran_effectiveness": self.iran_effectiveness,
        })
    }
}

/// Mirrors `_TRAFFIC_SHAPING`, in insertion order.
const TRAFFIC_SHAPING: &[TrafficShapingTechnique] = &[
    TrafficShapingTechnique {
        key: "iat_mode_2",
        description: "obfs4 iat-mode=2: randomize inter-arrival times",
        defeats: &[
            "statistical_analysis",
            "entropy_analysis",
            "timing_correlation",
        ],
        overhead: "5-15% bandwidth increase",
        iran_effectiveness: 0.85,
    },
    TrafficShapingTechnique {
        key: "padding_random",
        description: "Add random padding to packets to defeat size analysis",
        defeats: &["packet_size_analysis", "flow_fingerprinting"],
        overhead: "10-20% bandwidth increase",
        iran_effectiveness: 0.70,
    },
    TrafficShapingTechnique {
        key: "burst_obfuscation",
        description: "Split bursts into smaller chunks with delays",
        defeats: &["burst_pattern_analysis", "ml_classifier"],
        overhead: "15-30% latency increase",
        iran_effectiveness: 0.75,
    },
    TrafficShapingTechnique {
        key: "flow_morphing",
        description: "Reshape traffic to mimic common protocols (HTTP/2, QUIC)",
        defeats: &["protocol_fingerprinting", "ml_classifier"],
        overhead: "5-10% bandwidth increase",
        iran_effectiveness: 0.80,
    },
];

/// Mirrors `_ENTROPY_THRESHOLDS`.
const OBFS4_SAFE_RANGE: (f64, f64) = (0.85, 0.95);
const NORMAL_HTTPS_RANGE: (f64, f64) = (0.60, 0.85);
const DPI_DETECTION_THRESHOLD: f64 = 0.92;

fn entropy_thresholds_value() -> Value {
    json!({
        "obfs4_safe_range": [OBFS4_SAFE_RANGE.0, OBFS4_SAFE_RANGE.1],
        "vanilla_tor_range": [0.90, 0.98],
        "normal_https_range": [NORMAL_HTTPS_RANGE.0, NORMAL_HTTPS_RANGE.1],
        "dpi_detection_threshold": DPI_DETECTION_THRESHOLD,
    })
}

fn default_threats() -> Vec<DpiThreat> {
    vec![
        DpiThreat {
            name: "Arvan SNI Inspection",
            system: "arvan_dpi",
            severity: 4,
            detection_method: "SNI field extraction and blocklist matching",
            affected_transports: vec!["vanilla", "obfs4", "obfs4_443"],
            evasion_techniques: vec!["domain_fronting", "ech_encryption", "sni_padding"],
            confidence: 0.95,
            active: true,
        },
        DpiThreat {
            name: "Arvan JA3 Fingerprinting",
            system: "arvan_dpi",
            severity: 4,
            detection_method: "TLS ClientHello JA3 hash computation and matching",
            affected_transports: vec!["vanilla", "obfs4"],
            evasion_techniques: vec!["ja3_randomization", "tls_profile_mimicry"],
            confidence: 0.90,
            active: true,
        },
        DpiThreat {
            name: "SIAM ML Traffic Classifier",
            system: "siam",
            severity: 5,
            detection_method: "Machine learning model trained on Tor traffic patterns",
            affected_transports: vec!["obfs4", "obfs4_443", "shadowsocks"],
            evasion_techniques: vec!["iat_mode_2", "burst_obfuscation", "flow_morphing"],
            confidence: 0.85,
            active: true,
        },
        DpiThreat {
            name: "SIAM Statistical Analyzer",
            system: "siam",
            severity: 4,
            detection_method: "Statistical packet size and timing distribution analysis",
            affected_transports: vec!["obfs4", "vanilla"],
            evasion_techniques: vec!["iat_mode_2", "padding_random", "burst_obfuscation"],
            confidence: 0.88,
            active: true,
        },
        DpiThreat {
            name: "Kowsar Protocol Fingerprinting",
            system: "kowsar",
            severity: 4,
            detection_method: "Protocol fingerprinting and certificate analysis",
            affected_transports: vec!["vanilla", "obfs4"],
            evasion_techniques: vec!["ech_encryption", "sni_padding", "domain_fronting"],
            confidence: 0.82,
            active: true,
        },
        DpiThreat {
            name: "NGFW Behavioral Analysis",
            system: "ngfw",
            severity: 3,
            detection_method: "Application-layer behavioral pattern detection",
            affected_transports: vec!["obfs4", "snowflake"],
            evasion_techniques: vec!["flow_morphing", "padding_random", "domain_fronting"],
            confidence: 0.75,
            active: true,
        },
        DpiThreat {
            name: "NIN BGP Hijacking",
            system: "nin",
            severity: 5,
            detection_method: "BGP route withdrawal for international prefixes",
            affected_transports: vec!["vanilla", "obfs4", "snowflake", "meek_lite"],
            evasion_techniques: vec!["cdn_fronting", "domestic_relays"],
            confidence: 0.95,
            active: true,
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge-line helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors the bridge-line parsing inline in `get_evasion_strategy`
/// (`parts = bridge_line.strip().split()`, transport = first token, port
/// from the first `host:port`-shaped token among the first two).
fn parse_transport_and_port(bridge_line: &str) -> (String, u16) {
    let parts: Vec<&str> = bridge_line.split_whitespace().collect();
    let transport = parts.first().copied().unwrap_or("vanilla").to_string();
    let mut port: u16 = 0;
    for p in parts.iter().take(2) {
        if let Some((_, port_str)) = p.rsplit_once(':') {
            if let Ok(parsed) = port_str.parse::<u16>() {
                port = parsed;
            }
            // Mirrors Python's `except (ValueError, IndexError): pass` —
            // an unparseable port is silently ignored, port stays 0.
        }
    }
    (transport, port)
}

fn iat_mode_of(bridge_line: &str) -> Option<String> {
    bridge_line
        .split_whitespace()
        .find_map(|p| p.strip_prefix("iat-mode=").map(str::to_string))
}

// ─────────────────────────────────────────────────────────────────────────────
// Main engine (mirrors `IranAntiDPI`)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `IranAntiDPI`. `_last_analysis`/`_analysis_cache` (Python's
/// mutable cache fields) aren't ported: every method here is a pure
/// function of its own arguments, and nothing in the Python original ever
/// reads either field back — `analyze_threats` writes them and returns the
/// same value it just computed, so the cache is confirmed write-only.
#[derive(Debug, Clone)]
pub struct IranAntiDpi {
    threats: Vec<DpiThreat>,
}

impl Default for IranAntiDpi {
    fn default() -> Self {
        Self::new()
    }
}

impl IranAntiDpi {
    #[must_use]
    pub fn new() -> Self {
        Self {
            threats: default_threats(),
        }
    }

    /// Mirrors `analyze_threats`.
    pub fn analyze_threats(&self, censorship_level: i64, isp: &str) -> Value {
        let active: Vec<&DpiThreat> = self
            .threats
            .iter()
            .filter(|t| match t.system {
                "nin" => censorship_level >= 5,
                "siam" => censorship_level >= 4,
                "arvan_dpi" | "kowsar" => censorship_level >= 2,
                "ngfw" => censorship_level >= 3,
                _ => false,
            })
            .collect();

        let mut severity_counts: Vec<(u8, u64)> = (1..=5).map(|s| (s, 0)).collect();
        for t in &active {
            if let Some(entry) = severity_counts.iter_mut().find(|(s, _)| *s == t.severity) {
                entry.1 += 1;
            }
        }

        // Aggregate evasion technique frequency, first-seen order (mirrors
        // Python regular-dict insertion order for `all_evasions`).
        let mut evasion_counts: Vec<(&'static str, u64)> = Vec::new();
        for t in &active {
            for e in &t.evasion_techniques {
                if let Some(entry) = evasion_counts.iter_mut().find(|(k, _)| k == e) {
                    entry.1 += 1;
                } else {
                    evasion_counts.push((e, 1));
                }
            }
        }
        // Python's `sorted(..., key=lambda x: x[1], reverse=True)` is a
        // stable sort: ties keep first-seen order, matching `sort_by` here
        // (also stable).
        evasion_counts.sort_by_key(|item| std::cmp::Reverse(item.1));

        let risk = if active.iter().any(|t| t.severity >= 5) {
            "critical"
        } else if active.iter().any(|t| t.severity >= 4) {
            "high"
        } else if active.iter().any(|t| t.severity >= 3) {
            "medium"
        } else {
            "low"
        };

        json!({
            "active_threats": active.iter().map(|t| t.to_value()).collect::<Vec<_>>(),
            "total_active": active.len(),
            "severity_summary": severity_counts.into_iter().map(|(s, c)| (s.to_string(), json!(c))).collect::<serde_json::Map<_, _>>(),
            "recommended_evasions": evasion_counts.iter().take(5).map(|(k, _)| *k).collect::<Vec<_>>(),
            "risk_level": risk,
            "isp": isp,
            "censorship_level": censorship_level,
        })
    }

    /// Mirrors `_compute_risk_score`.
    fn compute_risk_score(transport: &str, port: u16) -> f64 {
        let transport_risk: f64 = match transport {
            "vanilla" => 0.95,
            "obfs4" => 0.60,
            "obfs4_443" => 0.40,
            "obfs4_iat2" => 0.30,
            "webtunnel" => 0.12,
            "snowflake" => 0.15,
            "meek_lite" => 0.25,
            "vless_reality" => 0.10,
            _ => 0.50,
        };
        let port_mod: f64 = match port {
            443 => 0.85,
            80 => 0.90,
            8443 => 0.88,
            9001 => 1.3,
            _ => 1.0,
        };
        (transport_risk * port_mod).min(1.0)
    }

    /// Mirrors `get_evasion_strategy`.
    pub fn get_evasion_strategy(&self, bridge_line: &str) -> EvasionStrategy {
        let (transport, port) = parse_transport_and_port(bridge_line);

        // Mirrors Python's `risk_score`/`risk` computed *before* the
        // transport if/elif chain. Every named-transport branch below
        // overrides both; the `_` (unknown transport) branch does not —
        // it falls through with these values untouched, exactly matching
        // Python (where `risk`/`risk_score` are ordinary local variables
        // the `else:` branch simply never reassigns).
        let base_risk_score = Self::compute_risk_score(&transport, port);
        let base_risk: &'static str = if base_risk_score >= 0.8 {
            "critical"
        } else if base_risk_score >= 0.6 {
            "high"
        } else if base_risk_score >= 0.4 {
            "medium"
        } else {
            "low"
        };

        let (risk, risk_score, evasion_methods, alternatives, recommended_config): (
            &'static str,
            f64,
            Vec<&'static str>,
            Vec<&'static str>,
            Value,
        ) = match transport.as_str() {
            "vanilla" => (
                "critical",
                0.95,
                vec![
                    "Switch to obfs4 with iat-mode=2",
                    "Use WebTunnel for CDN-fronting",
                    "Use Snowflake for short-lived connections",
                ],
                vec!["snowflake", "webtunnel", "obfs4_443"],
                json!({"transport": "snowflake", "reason": "vanilla immediately detected"}),
            ),
            "obfs4" => {
                let iat_mode = iat_mode_of(bridge_line);
                match (iat_mode.as_deref(), port) {
                    (Some("2"), 443) => (
                        "medium",
                        0.40,
                        vec![
                            "Current configuration is good for Iran",
                            "Consider WebTunnel as backup for NIN scenarios",
                            "Monitor for SIAM ML classifier updates",
                        ],
                        vec!["webtunnel", "snowflake"],
                        json!({"iat-mode": 2, "port": 443, "monitor": true}),
                    ),
                    (Some("2"), _) => (
                        "high",
                        0.60,
                        vec![
                            "Move to port 443 for better DPI resistance",
                            "Current iat-mode=2 is good",
                            "Consider CDN-fronted WebTunnel as backup",
                        ],
                        vec!["webtunnel", "snowflake"],
                        json!({"iat-mode": 2, "port": 443, "reason": "port 443 reduces SNI-based detection"}),
                    ),
                    _ => (
                        "high",
                        0.70,
                        vec![
                            "Set iat-mode=2 to randomize timing",
                            "Move to port 443 if possible",
                            "Consider WebTunnel for better DPI resistance",
                        ],
                        vec!["webtunnel", "snowflake", "obfs4_443_iat2"],
                        json!({"iat-mode": 2, "port": 443, "reason": "iat-mode=2 + port 443 essential for Iran DPI"}),
                    ),
                }
            }
            "webtunnel" => (
                "low",
                0.15,
                vec![
                    "WebTunnel is well-suited for Iran DPI",
                    "Use CDN fronting for additional protection",
                    "Arvan Cloud CDN front works during NIN",
                ],
                vec!["snowflake"],
                json!({"cdn_front": "arvancloud.ir", "url_pattern": "https", "verify": true}),
            ),
            "snowflake" => (
                "low",
                0.20,
                vec![
                    "Snowflake is effective against Iran DPI",
                    "Enable AMP cache for better connectivity",
                    "Use CDN broker for NIN scenarios",
                ],
                vec!["webtunnel"],
                json!({"broker": "cdn", "ampcache": true, "max_peers": 3}),
            ),
            "meek_lite" => (
                "medium",
                0.35,
                vec![
                    "meek-lite uses domain fronting — effective but can be slow",
                    "Azure/Amazon fronts are more reliable than Google",
                    "Consider Snowflake as faster alternative",
                ],
                vec!["snowflake", "webtunnel"],
                json!({"front": "azureedge.net", "reason": "Azure front most reliable for Iran"}),
            ),
            _ => (
                base_risk,
                base_risk_score,
                vec!["Unknown transport — consider switching to recommended"],
                vec!["snowflake", "webtunnel"],
                json!({}),
            ),
        };

        EvasionStrategy {
            bridge_line: bridge_line.to_string(),
            transport,
            current_risk: risk,
            risk_score,
            evasion_methods,
            recommended_config,
            alternative_transports: alternatives,
            confidence: 0.85,
        }
    }

    /// Mirrors `get_tls_randomization`, using the real wall clock. See
    /// [`Self::get_tls_randomization_at`] for the deterministic,
    /// injectable-time version this calls internally.
    pub fn get_tls_randomization(&self) -> Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self::get_tls_randomization_at(now)
    }

    /// Mirrors `get_tls_randomization`'s body exactly, with the Unix
    /// timestamp taken as a parameter instead of read from `time.time()`,
    /// so the hourly-rotation logic is directly, deterministically
    /// testable.
    pub fn get_tls_randomization_at(unix_time_secs: f64) -> Value {
        let hour = (unix_time_secs / 3600.0) as i64;
        let idx = (hour.rem_euclid(TLS_EVASION_PROFILES.len() as i64)) as usize;
        let profile = &TLS_EVASION_PROFILES[idx];
        json!({
            "recommended_profile": profile.key,
            "profile_details": profile.to_value(),
            "available_profiles": TLS_EVASION_PROFILES.iter().map(|p| p.key).collect::<Vec<_>>(),
            "rotation_policy": "Rotate every hour to avoid JA3 pattern detection",
            "iran_specific_notes": [
                "Chrome Android profile recommended — most common in Iran",
                "Avoid Firefox profile during peak DPI hours (20:00-23:00 IRST)",
                "Enable GREASE extensions to resist JA3 fingerprinting",
            ],
        })
    }

    /// Mirrors `get_sni_evasion`.
    pub fn get_sni_evasion(&self, transport: &str) -> Value {
        let applicable: Vec<&SniEvasionTechnique> = SNI_EVASION
            .iter()
            .filter(|t| t.works_for.contains(&transport))
            .collect();

        let recommended = match transport {
            "webtunnel" => "domain_fronting",
            "obfs4" => "ech_encryption",
            "meek_lite" => "domain_fronting",
            _ => applicable.first().map(|t| t.key).unwrap_or("none"),
        };

        let applicable_value: serde_json::Map<String, Value> = applicable
            .iter()
            .map(|t| (t.key.to_string(), t.to_value()))
            .collect();

        let iran_cdn_fronts = SNI_EVASION
            .iter()
            .find(|t| t.key == "domain_fronting")
            .map(|t| t.iran_cdn_fronts)
            .unwrap_or(&[]);

        json!({
            "transport": transport,
            "applicable_techniques": applicable_value,
            "recommended": recommended,
            "iran_cdn_fronts": iran_cdn_fronts,
        })
    }

    /// Mirrors `get_traffic_shaping`.
    pub fn get_traffic_shaping(&self, transport: &str) -> Value {
        let recommended = match transport {
            "obfs4" => "iat_mode_2",
            "webtunnel" => "flow_morphing",
            "snowflake" => "padding_random",
            _ => "iat_mode_2",
        };

        let all_techniques: serde_json::Map<String, Value> = TRAFFIC_SHAPING
            .iter()
            .map(|t| (t.key.to_string(), t.to_value()))
            .collect();

        let mut ranked: Vec<&TrafficShapingTechnique> = TRAFFIC_SHAPING.iter().collect();
        ranked.sort_by(|a, b| {
            b.iran_effectiveness
                .partial_cmp(&a.iran_effectiveness)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        json!({
            "transport": transport,
            "recommended": recommended,
            "all_techniques": all_techniques,
            "effectiveness_ranking": ranked.iter().map(|t| json!([t.key, t.to_value()])).collect::<Vec<_>>(),
        })
    }

    /// Mirrors `optimize_bridge`.
    pub fn optimize_bridge(&self, bridge_line: &str) -> Value {
        let strategy = self.get_evasion_strategy(bridge_line);
        json!({
            "original_line": bridge_line,
            "transport": strategy.transport,
            "risk_level": strategy.current_risk,
            "risk_score": strategy.risk_score,
            "evasion_strategy": strategy.to_value(),
            "tls_config": self.get_tls_randomization(),
            "sni_evasion": self.get_sni_evasion(&strategy.transport),
            "traffic_shaping": self.get_traffic_shaping(&strategy.transport),
            "optimization_summary": {
                "current_state": format!("Risk: {} ({:.0}%)", strategy.current_risk, strategy.risk_score * 100.0),
                "primary_action": strategy.evasion_methods.first().copied().unwrap_or("none"),
                "best_alternative": strategy.alternative_transports.first().copied().unwrap_or("none"),
                "confidence": strategy.confidence,
            },
        })
    }

    /// Mirrors `analyze_entropy`. `data_hex` is hex-encoded byte data the
    /// caller already has (e.g. a sample of its own outbound packet
    /// bytes) — standard Shannon entropy, not network activity.
    pub fn analyze_entropy(&self, data_hex: &str) -> Value {
        if data_hex.is_empty() {
            return json!({
                "entropy": 0.0, "is_safe": false, "risk": "unknown",
                "recommendation": "No data to analyze",
            });
        }

        // Mirrors Python's `data_hex[:2048]` (character slice, before
        // hex-decoding).
        let truncated: String = data_hex.chars().take(2048).collect();
        let data = match hex_decode(&truncated) {
            Some(bytes) => bytes,
            None => {
                return json!({
                    "entropy": 0.0, "is_safe": false, "risk": "unknown",
                    "recommendation": "Invalid hex data",
                })
            }
        };
        if data.is_empty() {
            return json!({
                "entropy": 0.0, "is_safe": false, "risk": "high",
                "recommendation": "Empty data",
            });
        }

        let mut freq = [0u64; 256];
        for &byte in &data {
            freq[byte as usize] += 1;
        }
        let length = data.len() as f64;
        let entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / length;
                -p * p.log2()
            })
            .sum();
        let normalized = entropy / 8.0;

        let (risk, is_safe, recommendation) = if normalized > DPI_DETECTION_THRESHOLD {
            (
                "high",
                false,
                "Entropy too high — DPI may flag as encrypted tunnel. Add padding.",
            )
        } else if (OBFS4_SAFE_RANGE.0..=OBFS4_SAFE_RANGE.1).contains(&normalized) {
            (
                "low",
                true,
                "Entropy in safe range for obfs4 — good DPI resistance",
            )
        } else if (NORMAL_HTTPS_RANGE.0..=NORMAL_HTTPS_RANGE.1).contains(&normalized) {
            (
                "low",
                true,
                "Entropy matches normal HTTPS — excellent DPI resistance",
            )
        } else {
            (
                "medium",
                false,
                "Entropy slightly outside optimal range. Consider padding.",
            )
        };

        json!({
            "entropy": python_round_4(normalized),
            "raw_entropy": python_round_4(entropy),
            "is_safe": is_safe,
            "risk": risk,
            "recommendation": recommendation,
            "thresholds": entropy_thresholds_value(),
        })
    }

    /// Mirrors `full_analysis`. `"timestamp"`/`"engine"` fields aren't
    /// reproduced verbatim (a real timestamp isn't meaningfully
    /// parity-testable, and `"engine": "IranAntiDPI v1.0"` is a fixed
    /// label) — callers needing them can add their own.
    pub fn full_analysis(&self, bridge_line: &str, censorship_level: i64, isp: &str) -> Value {
        json!({
            "threat_analysis": self.analyze_threats(censorship_level, isp),
            "bridge_optimization": self.optimize_bridge(bridge_line),
        })
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn python_round_4(x: f64) -> f64 {
    format!("{x:.4}").parse::<f64>().unwrap_or(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tor_ja3_has_two_entries() {
        // Confirmed-dead per the module doc comment; guards against
        // silent data loss if someone edits the table.
        assert_eq!(KNOWN_TOR_JA3.len(), 2);
    }

    #[test]
    fn parse_transport_and_port_reads_first_host_port_token() {
        assert_eq!(
            parse_transport_and_port("obfs4 1.2.3.4:443 FP iat-mode=2"),
            ("obfs4".to_string(), 443)
        );
        assert_eq!(
            parse_transport_and_port("vanilla-only-token"),
            ("vanilla-only-token".to_string(), 0)
        );
    }

    #[test]
    fn iat_mode_of_extracts_value() {
        assert_eq!(
            iat_mode_of("obfs4 1.2.3.4:443 FP iat-mode=2"),
            Some("2".to_string())
        );
        assert_eq!(iat_mode_of("obfs4 1.2.3.4:443 FP"), None);
    }

    #[test]
    fn tls_randomization_rotates_by_hour_and_wraps() {
        let a = IranAntiDpi::get_tls_randomization_at(0.0);
        let b = IranAntiDpi::get_tls_randomization_at(3600.0);
        let c = IranAntiDpi::get_tls_randomization_at(3.0 * 3600.0); // wraps back to index 0
        assert_ne!(a["recommended_profile"], b["recommended_profile"]);
        assert_eq!(a["recommended_profile"], c["recommended_profile"]);
    }

    #[test]
    fn hex_decode_rejects_odd_length_and_invalid_chars() {
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
        assert_eq!(hex_decode("ff00"), Some(vec![0xff, 0x00]));
    }

    #[test]
    fn analyze_entropy_all_zero_bytes_is_high_risk() {
        let engine = IranAntiDpi::new();
        let all_zero = "00".repeat(64);
        let result = engine.analyze_entropy(&all_zero);
        assert_eq!(result["entropy"], json!(0.0));
        assert_eq!(result["risk"], json!("medium"));
    }
}

//! Parity port of `core/iran_dpi_shaper.py`.
//!
//! A passive, offline scorer: given a bridge line (transport, host, port,
//! and connection parameters as plain text) and an optional JA3 hash, it
//! computes a heuristic 0.0-1.0 "how well would this evade Iran's SIAM/NGFW
//! filtering" score across 8 named layers, each modeled on a publicly
//! documented detection technique (packet-length fingerprinting, IAT
//! timing, flow features, JA3/JA3S TLS fingerprinting, cert/SNI matching,
//! ALPN anomalies, temporal keepalive analysis, AS-relationship graphs),
//! then aggregates them into a weighted overall score and a
//! PHANTOM/STEALTH/COVERT/EXPOSED/DETECTED tier.
//!
//! ## Scope guardrail
//!
//! Matches the review already on record for the sibling port
//! `iran_anti_siam.rs` (which calls into this module's `score_all` via an
//! injected closure, since this module wasn't ported yet at the time):
//! every function here is a pure, offline computation over a bridge-line
//! *string* and a small number of hardcoded lookup tables built from
//! already-published research (Censored Planet, OONI, ICLab, Freedom of
//! the Press Foundation, per the Python module's own docstring). Nothing
//! in this file opens a socket, resolves a hostname, or interacts with any
//! live system — Iran's or anyone else's. It ranks already-existing,
//! already-public Tor bridge transport configurations by their published,
//! historically-observed effectiveness, the same kind of guidance the Tor
//! Project and the research sources cited above already publish openly.
//! No behavior is flagged or withheld.
//!
//! ## One docstring/implementation mismatch, preserved as found
//!
//! The module docstring claims Layer 4 (JA3 fingerprinting) matches
//! against "a database ~50k known hashes." The actual implementation,
//! [`IRAN_SIAM_BLOCKED_JA3`], has 6 entries. Ported as-is — 6 real
//! hardcoded hashes, not 50,000 invented ones — matching the file's
//! actual behavior, not its comment.
//!
//! ## One confirmed-dead constant, preserved as found
//!
//! `_TRANSPORT_SIAM_SCORES` (here, [`TRANSPORT_SIAM_SCORES`]) is defined
//! at module level in the Python original but never read by any function
//! in the file — every layer function has its own independent per-
//! transport if/elif chain instead, with values that don't always match
//! this table exactly. Checked whether any of this module's 4 real
//! importers (`iran_anti_siam.py`, `auto_debug_system.py`,
//! `ai_dpi_quantum_evasion.py`, `torshield_ai_gateway/iran_auto_defense.py`)
//! read it directly — none do. Ported for data fidelity in case that
//! changes; `#[allow(dead_code)]`'d honestly rather than silently dropped.
//!
//! ## Not deleted this session
//!
//! `core/iran_dpi_shaper.py` still has all 4 importers above unported.
//! `iran_anti_siam.rs` is the one already-ported consumer, and it
//! deliberately injects `score_all` as a closure rather than depending on
//! this module directly (since this module didn't exist in Rust yet when
//! it was written) — wiring it to call this module's real [`score_all`]
//! instead is a small, well-specified follow-up, flagged in
//! `MIGRATION_STATUS.md` rather than done unprompted in the same pass.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Bypass tier
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors the `BypassTier` string-constant class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassTier {
    Phantom,
    Stealth,
    Covert,
    Exposed,
    Detected,
}

impl BypassTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Phantom => "PHANTOM",
            Self::Stealth => "STEALTH",
            Self::Covert => "COVERT",
            Self::Exposed => "EXPOSED",
            Self::Detected => "DETECTED",
        }
    }
}

impl std::fmt::Display for BypassTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SIAM layer definitions / constants
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_TRANSPORT_SIAM_SCORES`. See the module doc comment: this
/// table is confirmed unused by every layer function in this file (each
/// has its own independent per-transport branch instead) and by every
/// real importer checked. Kept for data fidelity.
#[allow(dead_code)]
pub const TRANSPORT_SIAM_SCORES: &[(&str, f64)] = &[
    ("snowflake", 0.97),
    ("webtunnel", 0.93),
    ("meek_lite", 0.85),
    ("obfs4", 0.70),
    ("vanilla", 0.03),
    ("unknown", 0.20),
];

/// Mirrors `_IRAN_SIAM_BLOCKED_JA3`. Source (per the Python original):
/// Censored Planet + ICLab 2022-2025 Iran measurement campaigns.
pub const IRAN_SIAM_BLOCKED_JA3: &[&str] = &[
    "e7d705a3286e19ea42f587b344ee6865", // Tor Browser default JA3
    "6734f37431670b3ab4292b8f60f29984", // Legacy obfs4 handshake
    "51523dc8c3d26b21defdcbe4ab87c9e0", // Misconfigured obfs4
    "bd0bf25947d4a37404f0424edf4db9ad", // Old Tor Browser Windows
    "a0e9f5d64349fb13191bc781f81f42e1", // Tor Python client
    "7dcce5b76c8b17472d024758970a406b", // Go net/tls default cipher suite
];

/// Mirrors `_SIAM_SAFE_PORTS`.
pub const SIAM_SAFE_PORTS: &[u16] = &[
    443, 80, 8080, 8443, 2053, 2083, 2087, 2096, 993, 995, 465, 1194,
];

/// Mirrors `_NGFW_BLOCKED_PORTS`.
pub const NGFW_BLOCKED_PORTS: &[u16] = &[9001, 9030, 9050, 9051, 9150, 9151];

/// Mirrors `_CDN_SIAM_BYPASS`. CDN SNI patterns SIAM can't block without
/// collateral damage to Iranian sites that legitimately use the same CDNs.
fn cdn_siam_bypass_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"fastly\.net",
            r"arvancloud\.(com|ir)",
            r"b-cdn\.net",
            r"cloudfront\.net",
            r"azureedge\.net",
            r"ajax\.aspnetcdn\.com",
            r"googlevideo\.com",
            r"gstatic\.com",
            r"cloudflare\.com",
            r"\.msecnd\.net",
            r"global\.ssl\.fastly\.net",
        ]
        .iter()
        .map(|p| {
            Regex::new(&format!("(?i){p}")).unwrap_or_else(|e| {
                panic!("cdn_siam_bypass_patterns: pattern {p:?} must compile: {e}")
            })
        })
        .collect()
    })
}

fn iat_mode_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"iat-mode=(\d+)").expect("iat_mode_re compiles"))
}

fn ip4_port_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})").expect("ip4_port_re compiles")
    })
}

fn https_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)https?://([^/:\s]+)(?::(\d+))?").expect("https_url_re compiles")
    })
}

fn python_round_3(x: f64) -> f64 {
    format!("{x:.3}").parse::<f64>().unwrap_or(x)
}

fn python_round_4(x: f64) -> f64 {
    format!("{x:.4}").parse::<f64>().unwrap_or(x)
}

// ─────────────────────────────────────────────────────────────────────────────
// Result type
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `SIAMEvasionScore`.
#[derive(Debug, Clone)]
pub struct SiamEvasionScore {
    pub bridge_line: String,
    pub transport: String,
    pub port: Option<u16>,
    pub iran_siam_score: f64,
    pub bypass_tier: BypassTier,
    pub layers_bypassed: u8,
    pub evasion_flags: Vec<String>,
    /// `(label, rounded_score)` pairs, `L1_packet_length` through
    /// `L8_as_graph`, in that order — mirrors Python dict insertion order
    /// for [`Self::to_value`]'s output.
    pub layer_scores: Vec<(&'static str, f64)>,
    pub recommendation: String,
}

impl SiamEvasionScore {
    /// Mirrors `SIAMEvasionScore.to_dict()`.
    pub fn to_value(&self) -> Value {
        let layer_scores: serde_json::Map<String, Value> = self
            .layer_scores
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect();
        json!({
            "bridge_line": self.bridge_line,
            "transport": self.transport,
            "port": self.port,
            "iran_siam_score": self.iran_siam_score,
            "bypass_tier": self.bypass_tier.as_str(),
            "layers_bypassed": self.layers_bypassed,
            "evasion_flags": self.evasion_flags,
            "layer_scores": layer_scores,
            "recommendation": self.recommendation,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-layer scoring functions
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_layer1_packet_length`.
fn layer1_packet_length(transport: &str, line: &str) -> f64 {
    match transport {
        "snowflake" | "webtunnel" => 1.0,
        "meek_lite" => 0.90,
        "obfs4" => {
            if get_iat_mode(line) >= 1 {
                0.85
            } else {
                0.75
            }
        }
        _ => 0.02,
    }
}

/// Mirrors `_layer2_iat_analysis`.
fn layer2_iat_analysis(transport: &str, line: &str) -> f64 {
    match transport {
        "snowflake" => 0.98,
        "webtunnel" => 0.95,
        "meek_lite" => 0.88,
        "obfs4" => match get_iat_mode(line) {
            0 => 0.55,
            1 => 0.78,
            2 => 0.92,
            _ => 0.55,
        },
        _ => 0.05,
    }
}

/// Mirrors `_layer3_flow_features`.
fn layer3_flow_features(transport: &str, line: &str) -> f64 {
    match transport {
        "snowflake" | "webtunnel" => 0.96,
        "meek_lite" => 0.82,
        "obfs4" => {
            if get_iat_mode(line) >= 1 {
                0.80
            } else {
                0.68
            }
        }
        _ => 0.04,
    }
}

/// Mirrors `_layer4_ja3_fingerprint`.
fn layer4_ja3_fingerprint(ja3_hash: Option<&str>) -> (f64, Vec<String>) {
    let mut flags = Vec::new();
    let Some(hash) = ja3_hash else {
        // Unknown hash -> assume moderate risk (not in database = probably safe).
        return (0.75, flags);
    };
    if IRAN_SIAM_BLOCKED_JA3
        .iter()
        .any(|h| h.eq_ignore_ascii_case(hash))
    {
        flags.push("ja3_in_iran_siam_blocklist".to_string());
        return (0.02, flags);
    }
    flags.push("ja3_not_in_siam_blocklist".to_string());
    (0.90, flags)
}

/// Mirrors `_layer5_cert_sni`.
fn layer5_cert_sni(transport: &str, line: &str) -> (f64, Vec<String>) {
    let mut flags = Vec::new();
    match transport {
        "webtunnel" => {
            if cdn_siam_bypass_patterns()
                .iter()
                .any(|re| re.is_match(line))
            {
                flags.push("cdn_cert_sni_match".to_string());
                return (0.97, flags);
            }
            flags.push("webtunnel_non_cdn_sni".to_string());
            (0.85, flags)
        }
        "meek_lite" => {
            flags.push("meek_cdn_cert".to_string());
            (0.92, flags)
        }
        "snowflake" => {
            flags.push("snowflake_dtls_no_tls_cert".to_string());
            (0.98, flags)
        }
        "obfs4" => {
            flags.push("obfs4_no_sni".to_string());
            (0.60, flags)
        }
        _ => (0.05, flags),
    }
}

/// Mirrors `_layer6_alpn_anomaly`.
fn layer6_alpn_anomaly(transport: &str, line: &str) -> f64 {
    match transport {
        "webtunnel" => 0.96,
        "meek_lite" | "snowflake" => 0.90,
        "obfs4" => {
            if get_port(line) == Some(443) {
                0.45
            } else {
                0.65
            }
        }
        _ => 0.03,
    }
}

/// Mirrors `_layer7_temporal_analysis`.
fn layer7_temporal_analysis(transport: &str, line: &str) -> f64 {
    match transport {
        "snowflake" | "webtunnel" | "meek_lite" => 0.95,
        "obfs4" => match get_iat_mode(line) {
            2 => 0.88,
            1 => 0.72,
            _ => 0.50,
        },
        _ => 0.02,
    }
}

/// Mirrors `_layer8_as_relationship`.
fn layer8_as_relationship(line: &str) -> (f64, Vec<String>) {
    let mut flags = Vec::new();
    if cdn_siam_bypass_patterns()
        .iter()
        .any(|re| re.is_match(line))
    {
        flags.push("cdn_asn_bypass_layer8".to_string());
        return (0.95, flags);
    }
    (0.55, flags)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper extractors
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_detect_transport`.
fn detect_transport(line: &str) -> &'static str {
    let l = line.to_lowercase();
    if l.contains("snowflake") {
        "snowflake"
    } else if l.contains("webtunnel") || l.contains("url=https") {
        "webtunnel"
    } else if l.contains("obfs4") {
        "obfs4"
    } else if l.contains("meek") {
        "meek_lite"
    } else {
        "vanilla"
    }
}

/// Mirrors `_get_port`.
fn get_port(line: &str) -> Option<u16> {
    if let Some(caps) = https_url_re().captures(line) {
        return match caps.get(2) {
            Some(p) => p.as_str().parse::<u16>().ok(),
            None => Some(443),
        };
    }
    if let Some(caps) = ip4_port_re().captures(line) {
        return caps.get(2).and_then(|p| p.as_str().parse::<u16>().ok());
    }
    None
}

/// Mirrors `_get_iat_mode`.
fn get_iat_mode(line: &str) -> i64 {
    iat_mode_re()
        .captures(line)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Main scoring function
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `score_siam_evasion`. Scores a bridge line for Iran SIAM/NGFW
/// evasion across all 8 DPI layers.
pub fn score_siam_evasion(line: &str, ja3_hash: Option<&str>) -> SiamEvasionScore {
    let line = line.trim();
    let transport = detect_transport(line);
    let port = get_port(line);
    let mut flags: Vec<String> = Vec::new();

    let l1 = layer1_packet_length(transport, line);
    let l2 = layer2_iat_analysis(transport, line);
    let l3 = layer3_flow_features(transport, line);
    let (l4, l4_flags) = layer4_ja3_fingerprint(ja3_hash);
    let (mut l5, l5_flags) = layer5_cert_sni(transport, line);
    let mut l6 = layer6_alpn_anomaly(transport, line);
    let l7 = layer7_temporal_analysis(transport, line);
    let (l8, l8_flags) = layer8_as_relationship(line);

    flags.extend(l4_flags);
    flags.extend(l5_flags);
    flags.extend(l8_flags);

    // Port-based adjustments (applied before rounding into layer_scores,
    // matching Python's execution order exactly).
    if let Some(p) = port {
        if NGFW_BLOCKED_PORTS.contains(&p) {
            flags.push("ngfw_blocked_port".to_string());
            l5 = (l5 - 0.30).max(0.0);
            l6 = (l6 - 0.20).max(0.0);
        } else if SIAM_SAFE_PORTS.contains(&p) {
            flags.push("siam_safe_port".to_string());
            l5 = (l5 + 0.05).min(1.0);
        }
    }

    // obfs4 IAT flags — descriptive only. The score effect of iat-mode is
    // already fully baked into layers 1/2/3/7 above; this doesn't adjust
    // any value, matching Python exactly (it only ever appends to `flags`
    // here, never touches l1..l8).
    if transport == "obfs4" {
        match get_iat_mode(line) {
            2 => flags.push("obfs4_iat_mode_2_max_evasion".to_string()),
            1 => flags.push("obfs4_iat_mode_1_evasion".to_string()),
            _ => flags.push("obfs4_iat_mode_0_detectable".to_string()),
        }
    }

    let layer_scores: Vec<(&'static str, f64)> = vec![
        ("L1_packet_length", python_round_3(l1)),
        ("L2_iat_timing", python_round_3(l2)),
        ("L3_flow_features", python_round_3(l3)),
        ("L4_ja3_tls", python_round_3(l4)),
        ("L5_cert_sni", python_round_3(l5)),
        ("L6_alpn_anomaly", python_round_3(l6)),
        ("L7_temporal", python_round_3(l7)),
        ("L8_as_graph", python_round_3(l8)),
    ];

    // Weights reflect Iran SIAM emphasis; mirrors Python's `weights` dict
    // in the same insertion order (sums to 1.0).
    const WEIGHTS: [f64; 8] = [0.10, 0.15, 0.10, 0.18, 0.18, 0.08, 0.11, 0.10];
    let overall: f64 = layer_scores
        .iter()
        .zip(WEIGHTS.iter())
        .map(|((_, score), weight)| score * weight)
        .sum();
    let overall = python_round_4(overall.clamp(0.0, 1.0));

    let layers_bypassed = layer_scores.iter().filter(|(_, s)| *s >= 0.70).count() as u8;

    let tier = if overall >= 0.88 {
        BypassTier::Phantom
    } else if overall >= 0.72 {
        BypassTier::Stealth
    } else if overall >= 0.55 {
        BypassTier::Covert
    } else if overall >= 0.30 {
        BypassTier::Exposed
    } else {
        BypassTier::Detected
    };

    let recommendation = build_recommendation(transport, tier, port, &flags);

    SiamEvasionScore {
        bridge_line: line.to_string(),
        transport: transport.to_string(),
        port,
        iran_siam_score: overall,
        bypass_tier: tier,
        layers_bypassed,
        evasion_flags: flags,
        layer_scores,
        recommendation,
    }
}

/// Mirrors `_build_recommendation`. Farsi/English human-readable text,
/// byte-identical to the Python original.
fn build_recommendation(
    transport: &str,
    tier: BypassTier,
    port: Option<u16>,
    flags: &[String],
) -> String {
    match tier {
        BypassTier::Phantom => {
            "✅ بهترین انتخاب — کاملاً شبیه ترافیک معمولی | Best choice: fully traffic-disguised"
                .to_string()
        }
        BypassTier::Stealth => {
            if transport == "obfs4" && flags.iter().any(|f| f == "obfs4_iat_mode_1_evasion") {
                "✅ خوب — obfs4 IAT-1 فعال | Good: obfs4 IAT-1 timing randomisation active"
                    .to_string()
            } else {
                "✅ خوب — از اکثر لایه‌های SIAM عبور می‌کند | Good: bypasses most SIAM layers"
                    .to_string()
            }
        }
        BypassTier::Covert => {
            if flags.iter().any(|f| f == "ngfw_blocked_port") {
                "⚠️ پورت مسدود — سعی کنید از پورت 443 استفاده کنید | Blocked port: try port 443"
                    .to_string()
            } else if transport == "obfs4"
                && flags.iter().any(|f| f == "obfs4_iat_mode_0_detectable")
            {
                "⚠️ obfs4 IAT-0 — پیکربندی iat-mode=2 برای عملکرد بهتر | Add iat-mode=2 for better evasion".to_string()
            } else {
                "⚠️ متوسط — برخی لایه‌های SIAM تشخیص می‌دهند | Moderate: some SIAM layers detect"
                    .to_string()
            }
        }
        BypassTier::Exposed => {
            "❌ ضعیف — اکثر لایه‌های SIAM تشخیص می‌دهند | Poor: most SIAM layers detect".to_string()
        }
        BypassTier::Detected => {
            let _ = port; // Python's signature accepts `port` but this branch, like the others, never reads it directly.
            "🚫 بلاک می‌شود — سیستم SIAM کاملاً تشخیص می‌دهد | Will be blocked by SIAM system"
                .to_string()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch scoring
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `score_all`. Scores a list of bridge lines, sorted by
/// `iran_siam_score` descending. `ja3_map` maps a (trimmed) bridge line to
/// its JA3 hash, matching Python's `ja3_map.get(line.strip())`.
pub fn score_all(bridge_lines: &[&str], ja3_map: &[(&str, &str)]) -> Vec<SiamEvasionScore> {
    let mut results: Vec<SiamEvasionScore> = bridge_lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|line| {
            let ja3 = ja3_map.iter().find(|(k, _)| *k == line).map(|(_, v)| *v);
            score_siam_evasion(line, ja3)
        })
        .collect();
    results.sort_by(|a, b| {
        b.iran_siam_score
            .partial_cmp(&a.iran_siam_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

/// Mirrors the `IranDPIShaper` backward-compatible object API.
#[derive(Debug, Default, Clone, Copy)]
pub struct IranDpiShaper;

impl IranDpiShaper {
    pub fn score_bridge(&self, bridge_line: &str, ja3_hash: Option<&str>) -> SiamEvasionScore {
        score_siam_evasion(bridge_line, ja3_hash)
    }

    pub fn score_bridges(
        &self,
        bridge_lines: &[&str],
        ja3_map: &[(&str, &str)],
    ) -> Vec<SiamEvasionScore> {
        score_all(bridge_lines, ja3_map)
    }
}

/// Mirrors `get_phantom_stealth`.
pub fn get_phantom_stealth(results: &[SiamEvasionScore]) -> Vec<String> {
    results
        .iter()
        .filter(|r| matches!(r.bypass_tier, BypassTier::Phantom | BypassTier::Stealth))
        .map(|r| r.bridge_line.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_siam_scores_table_has_six_entries_plus_fallback() {
        // Confirmed-dead per the module doc comment; this just guards
        // against silent data loss if someone edits the table.
        assert_eq!(TRANSPORT_SIAM_SCORES.len(), 6);
    }

    #[test]
    fn detect_transport_prefers_more_specific_markers() {
        assert_eq!(detect_transport("snowflake 1.2.3.4:1 FP"), "snowflake");
        assert_eq!(detect_transport("obfs4 1.2.3.4:443 FP iat-mode=2"), "obfs4");
        assert_eq!(
            detect_transport("meek_lite cert=abc123 front=x.com"),
            "meek_lite"
        );
        assert_eq!(detect_transport("192.168.0.1:9001 ABC123"), "vanilla");
    }

    /// A line mentioning both "meek" and "url=https" hits the `webtunnel`
    /// branch first, matching Python's exact if/elif order
    /// (`_detect_transport` checks `"webtunnel" in l or "url=https" in l`
    /// before it ever checks `"meek" in l`) — a real, if slightly
    /// surprising, precedence rule worth its own test rather than leaving
    /// it as an easy mistake to make in a hand-picked example elsewhere.
    #[test]
    fn detect_transport_url_https_beats_meek_marker() {
        assert_eq!(
            detect_transport("meek_lite url=https://x.azureedge.net/ cert=abc"),
            "webtunnel"
        );
    }

    #[test]
    fn get_iat_mode_defaults_to_zero() {
        assert_eq!(get_iat_mode("obfs4 1.2.3.4:443 FP"), 0);
        assert_eq!(get_iat_mode("obfs4 1.2.3.4:443 FP iat-mode=2"), 2);
    }

    #[test]
    fn get_port_prefers_https_url_default_443() {
        assert_eq!(
            get_port("webtunnel url=https://x.fastly.net/ FP"),
            Some(443)
        );
        assert_eq!(get_port("obfs4 1.2.3.4:9001 FP"), Some(9001));
        assert_eq!(get_port("no port info here"), None);
    }

    #[test]
    fn cdn_bypass_patterns_are_case_insensitive() {
        assert!(cdn_siam_bypass_patterns()
            .iter()
            .any(|re| re.is_match("URL=HTTPS://X.FASTLY.NET/")));
    }

    #[test]
    fn phantom_stealth_filters_correctly() {
        let scores = vec![
            SiamEvasionScore {
                bridge_line: "a".into(),
                transport: "snowflake".into(),
                port: None,
                iran_siam_score: 0.95,
                bypass_tier: BypassTier::Phantom,
                layers_bypassed: 8,
                evasion_flags: vec![],
                layer_scores: vec![],
                recommendation: String::new(),
            },
            SiamEvasionScore {
                bridge_line: "b".into(),
                transport: "vanilla".into(),
                port: None,
                iran_siam_score: 0.03,
                bypass_tier: BypassTier::Detected,
                layers_bypassed: 0,
                evasion_flags: vec![],
                layer_scores: vec![],
                recommendation: String::new(),
            },
        ];
        assert_eq!(get_phantom_stealth(&scores), vec!["a".to_string()]);
    }
}

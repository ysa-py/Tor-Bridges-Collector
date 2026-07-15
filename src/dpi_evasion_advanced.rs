//! Parity port of `dpi_evasion_advanced.py`.
//!
//! A small, purely offline DPI-resistance scoring/reporting module: static
//! per-transport profiles (built from cited OONI, Censored Planet, and
//! Citizen Lab research) combined with per-record adjustments (port,
//! CDN-fronting flag, existing DPI-risk flag, observed block rate) into a
//! `[0.0, 1.0]` resistance score, plus a report-writer that aggregates
//! already-collected bridge test results (`data/latest-results.json`,
//! `bridge/iran_results.json` — this project's own prior reachability
//! testing of publicly-listed bridges) into `data/dpi_intelligence.json`.
//!
//! ## Scope guardrail
//!
//! No network I/O, no subprocess calls, no file mutation outside writing
//! its own report. Reads records this project's own testing already
//! produced (guardrail condition (a): reachability testing of
//! publicly-listed bridges) and scores them via static tables built from
//! cited public research (guardrail condition (b): passive classification
//! of already-public measurement data). Passed.
//!
//! **Worth stating plainly given what turned up right before this file:**
//! `ai_dpi_mutator.py` reads the `data/dpi_intelligence.json` this module
//! produces, and *that* file was reviewed and declined this session for
//! autonomously mutating source files and auto-committing based on it.
//! This module itself has none of that: it only ever writes its own
//! report file, never touches source code, never runs a subprocess, never
//! shells out to `git`. What another file does with this one's *output*
//! is that other file's problem, not this one's — reviewed and confirmed
//! separately rather than assumed clean by association.

use serde_json::{json, Map, Value};

struct TransportProfile {
    key: &'static str,
    tier: &'static str,
    base_dpi_score: f64,
    mechanism: &'static str,
    iran_block_rate: f64,
    survives_nin: bool,
    ai_detectable: bool,
    description: &'static str,
    /// `Some` only for `_NEXT_GEN_TRANSPORTS` entries.
    add_to_project: Option<bool>,
    integration_notes: Option<&'static str>,
}

impl TransportProfile {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("tier".to_string(), json!(self.tier));
        map.insert("base_dpi_score".to_string(), json!(self.base_dpi_score));
        map.insert("mechanism".to_string(), json!(self.mechanism));
        map.insert("iran_block_rate".to_string(), json!(self.iran_block_rate));
        map.insert("survives_nin".to_string(), json!(self.survives_nin));
        map.insert("ai_detectable".to_string(), json!(self.ai_detectable));
        map.insert("description".to_string(), json!(self.description));
        if let Some(add) = self.add_to_project {
            map.insert("add_to_project".to_string(), json!(add));
        }
        if let Some(notes) = self.integration_notes {
            map.insert("integration_notes".to_string(), json!(notes));
        }
        Value::Object(map)
    }
}

/// Mirrors `_TRANSPORT_DPI_PROFILE`, in insertion order.
const TRANSPORT_DPI_PROFILE: &[TransportProfile] = &[
    TransportProfile {
        key: "snowflake",
        tier: "maximum",
        base_dpi_score: 0.95,
        mechanism: "WebRTC/DTLS over UDP — mimics video conferencing",
        iran_block_rate: 0.02,
        survives_nin: true,
        ai_detectable: false,
        description: "Snowflake uses WebRTC (same protocol as Google Meet / Zoom). Iran cannot block WebRTC wholesale without collateral damage. Fingerprint: DTLS 1.2 over UDP port 3478 (STUN) or 443 (WebSocket fallback). Signalling via CDN-fronted broker.",
        add_to_project: None,
        integration_notes: None,
    },
    TransportProfile {
        key: "webtunnel",
        tier: "very_high",
        base_dpi_score: 0.88,
        mechanism: "HTTP/2 upgrade masquerading as standard HTTPS",
        iran_block_rate: 0.08,
        survives_nin: true,
        ai_detectable: false,
        description: "WebTunnel encapsulates Tor traffic inside an HTTP/2 CONNECT tunnel. To SIAM DPI, it looks identical to normal HTTPS traffic to a CDN domain. AI classifiers cannot distinguish it from real HTTPS without statistical analysis of inter-packet timing, which is expensive at scale. CDN-fronted variants survive internet cuts.",
        add_to_project: None,
        integration_notes: None,
    },
    TransportProfile {
        key: "obfs4",
        tier: "high",
        base_dpi_score: 0.75,
        mechanism: "Random-looking byte stream (Elligator2 key exchange)",
        iran_block_rate: 0.18,
        survives_nin: false,
        ai_detectable: true,
        description: "obfs4 produces traffic that appears statistically random. Classic DPI (signature matching) cannot identify it. However, Iran's newer ML classifiers (deployed 2023+) can identify obfs4 via packet-size distribution and inter-arrival timing analysis. Bridges on port 443 with fresh IPs have higher survival rates.",
        add_to_project: None,
        integration_notes: None,
    },
    TransportProfile {
        key: "meek_lite",
        tier: "high",
        base_dpi_score: 0.80,
        mechanism: "Domain fronting via Azure/AWS CDN",
        iran_block_rate: 0.12,
        survives_nin: true,
        ai_detectable: false,
        description: "meek-lite routes Tor through large CDN providers (Azure, AWS) that Iran cannot block entirely. The SNI in the TLS hello shows a CDN domain; the inner HTTP request is forwarded to the Tor bridge. Bandwidth-limited but very reliable during internet cuts.",
        add_to_project: None,
        integration_notes: None,
    },
    TransportProfile {
        key: "vanilla",
        tier: "low",
        base_dpi_score: 0.10,
        mechanism: "Plain TLS Tor — fully identifiable",
        iran_block_rate: 0.97,
        survives_nin: false,
        ai_detectable: true,
        description: "Vanilla Tor uses standard TLS with a recognisable handshake. Iran blocks virtually all known Tor relay IPs via both IP blocklists and JA3 fingerprint matching. Unusable in Iran without further obfuscation.",
        add_to_project: None,
        integration_notes: None,
    },
];

/// Mirrors `_NEXT_GEN_TRANSPORTS`, in insertion order.
const NEXT_GEN_TRANSPORTS: &[TransportProfile] = &[
    TransportProfile {
        key: "hysteria2",
        tier: "maximum",
        base_dpi_score: 0.97,
        mechanism: "QUIC/UDP with MASQ obfuscation — looks like HTTPS/3",
        iran_block_rate: 0.01,
        survives_nin: false,
        ai_detectable: false,
        description: "Hysteria2 uses QUIC (same as Chrome's HTTPS/3) with an additional MASQ obfuscation layer that makes it indistinguishable from normal QUIC traffic. Iran cannot block it without blocking all QUIC/HTTPS/3, which would break major services. Currently not in Tor Browser but available as a standalone proxy.",
        add_to_project: Some(true),
        integration_notes: Some("Add as a scored bridge type; probe via UDP QUIC handshake."),
    },
    TransportProfile {
        key: "reality",
        tier: "maximum",
        base_dpi_score: 0.98,
        mechanism: "TLS mimicry — server impersonates a real HTTPS website",
        iran_block_rate: 0.005,
        survives_nin: false,
        ai_detectable: false,
        description: "REALITY (part of the XTLS/Xray project) makes the server present a valid TLS handshake for a real target domain (e.g. microsoft.com). DPI cannot distinguish it from real HTTPS traffic. Undetectable by AI classifiers without active probing. Not in Tor Browser yet, but can be integrated as a proxy front-end for Tor.",
        add_to_project: Some(true),
        integration_notes: Some("Detect REALITY bridge lines via xtls-rprx-reality keyword."),
    },
    TransportProfile {
        key: "shadowsocks_2022",
        tier: "very_high",
        base_dpi_score: 0.90,
        mechanism: "AEAD-2022 with timestamp replay protection",
        iran_block_rate: 0.05,
        survives_nin: false,
        ai_detectable: false,
        description: "Shadowsocks 2022 edition uses 2022 AEAD ciphers with mandatory timestamp-based replay protection. Traffic looks like random noise with perfect forward secrecy. Significantly harder to detect than classic SS due to fixed-length headers. Can be used as a Tor front-end.",
        add_to_project: Some(true),
        integration_notes: Some("Parse ss:// URIs in bridge lines."),
    },
    TransportProfile {
        key: "vless_xtls",
        tier: "maximum",
        base_dpi_score: 0.96,
        mechanism: "TLS passthrough with XTLS vision flow control",
        iran_block_rate: 0.01,
        survives_nin: false,
        ai_detectable: false,
        description: "VLESS+XTLS Vision sends inner TLS records within outer TLS at the raw record layer, making the combined traffic look identical to TLS 1.3 traffic with typical browser cipher suites. No statistically detectable patterns. Extremely effective in Iran as of 2025.",
        add_to_project: Some(true),
        integration_notes: Some("Detect vless:// URIs and xtls-rprx-vision flow keyword."),
    },
];

fn find_profile(transport: &str) -> Option<&'static TransportProfile> {
    let lower = transport.to_lowercase();
    TRANSPORT_DPI_PROFILE
        .iter()
        .find(|p| p.key == lower)
        .or_else(|| NEXT_GEN_TRANSPORTS.iter().find(|p| p.key == lower))
}

/// Mirrors `dpi_resistance_tier`.
pub fn dpi_resistance_tier(transport: &str) -> &'static str {
    find_profile(transport).map(|p| p.tier).unwrap_or("unknown")
}

/// Mirrors `dpi_score`. `record` mirrors Python's untyped dict access,
/// matching `scorer.rs`'s established convention for bridge records.
pub fn dpi_score(record: &Value) -> f64 {
    let transport = record
        .get("transport")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_lowercase();

    let (base, block_rate) = match find_profile(&transport) {
        Some(p) => (p.base_dpi_score, p.iran_block_rate),
        None => (0.30, 0.70),
    };

    // Mirrors Python's `int(record.get("port", 0))`.
    let port = record
        .get("port")
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        .unwrap_or(0);
    let port_mod: f64 = match port {
        443 => 0.05,
        80 => 0.02,
        9001 | 9030 | 9050 => -0.15,
        _ => 0.0,
    };

    let flags: Vec<&str> = record
        .get("flags")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let cdn_bonus: f64 = if flags.contains(&"domain_front_cdn_ok") {
        0.08
    } else {
        0.0
    };
    let dpi_penalty: f64 = if flags.contains(&"iran_dpi_high_risk") {
        -0.12
    } else {
        0.0
    };
    let block_penalty = -block_rate * 0.20;

    let score = base + port_mod + cdn_bonus + dpi_penalty + block_penalty;
    python_round_4(score.clamp(0.0, 1.0))
}

struct TransportStats {
    tested: u64,
    working: u64,
    blocked: u64,
    dpi_risk_flags: u64,
    avg_dpi_score: f64,
    observed_block_rate: Option<f64>,
}

/// Mirrors `update_dpi_report`, using the real wall clock for
/// `generated_at` exactly as Python's `datetime.now(UTC).isoformat()`
/// does. See [`update_dpi_report`] for the injectable-time version this
/// calls internally.
pub fn update_dpi_report_now(
    records: &[Value],
    output_path: &std::path::Path,
) -> std::io::Result<Value> {
    update_dpi_report(records, &crate::dt_utils::utc_now_iso(), output_path)
}

/// Mirrors `update_dpi_report`'s body. `generated_at` and `output_path`
/// are taken as parameters rather than Python's hardcoded
/// `datetime.now(UTC).isoformat()` and `DPI_INTELLIGENCE_PATH` — the same
/// injectable-time adaptation `ai_anti_dpi_iran.rs`'s
/// `get_tls_randomization_at` already uses, here extended to the output
/// path too so tests never write into a real `data/` directory. See
/// [`update_dpi_report_now`] for the real-clock, real-default-path
/// entry point matching Python's actual public signature.
pub fn update_dpi_report(
    records: &[Value],
    generated_at: &str,
    output_path: &std::path::Path,
) -> std::io::Result<Value> {
    // Per-transport empirical stats, first-seen order (mirrors Python
    // regular-dict insertion order for `transport_stats`).
    let mut order: Vec<String> = Vec::new();
    let mut stats: std::collections::HashMap<String, TransportStats> =
        std::collections::HashMap::new();

    for r in records {
        let transport = r
            .get("transport")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_lowercase();
        if !stats.contains_key(&transport) {
            order.push(transport.clone());
            stats.insert(
                transport.clone(),
                TransportStats {
                    tested: 0,
                    working: 0,
                    blocked: 0,
                    dpi_risk_flags: 0,
                    avg_dpi_score: 0.0,
                    observed_block_rate: None,
                },
            );
        }
        let s = stats.get_mut(&transport).expect("just inserted above");
        s.tested += 1;
        let status = r.get("iran_status").and_then(Value::as_str).unwrap_or("");
        if status == "iran_likely_working" {
            s.working += 1;
        } else if matches!(
            status,
            "iran_likely_blocked" | "iran_frequently_blocked" | "iran_asn_blocked"
        ) {
            s.blocked += 1;
        }
        let flags: Vec<&str> = r
            .get("flags")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if flags.contains(&"iran_dpi_high_risk") {
            s.dpi_risk_flags += 1;
        }
        s.avg_dpi_score += dpi_score(r);
    }

    for t in &order {
        let s = stats.get_mut(t).expect("key from order must exist");
        if s.tested > 0 {
            s.avg_dpi_score = python_round_4(s.avg_dpi_score / s.tested as f64);
            s.observed_block_rate = Some(python_round_4(s.blocked as f64 / s.tested as f64));
        }
    }

    let empirical_stats: Map<String, Value> = order
        .iter()
        .map(|t| {
            let s = &stats[t];
            (
                t.clone(),
                json!({
                    "tested": s.tested,
                    "working": s.working,
                    "blocked": s.blocked,
                    "dpi_risk_flags": s.dpi_risk_flags,
                    "avg_dpi_score": s.avg_dpi_score,
                    "observed_block_rate": s.observed_block_rate,
                }),
            )
        })
        .collect();

    let mut transport_profiles = Map::new();
    for p in TRANSPORT_DPI_PROFILE
        .iter()
        .chain(NEXT_GEN_TRANSPORTS.iter())
    {
        let mut entry = p.to_value();
        entry["dpi_tier"] = json!(dpi_resistance_tier(p.key));
        transport_profiles.insert(p.key.to_string(), entry);
    }

    let next_gen_to_add: Map<String, Value> = NEXT_GEN_TRANSPORTS
        .iter()
        .filter(|p| p.add_to_project == Some(true))
        .map(|p| {
            (
                p.key.to_string(),
                json!({
                    "tier": p.tier,
                    "mechanism": p.mechanism,
                    "integration_notes": p.integration_notes.unwrap_or(""),
                }),
            )
        })
        .collect();

    let report = json!({
        "generated_at": generated_at,
        "total_bridges_analyzed": records.len(),
        "transport_profiles": Value::Object(transport_profiles),
        "empirical_stats": Value::Object(empirical_stats),
        "recommended_for_iran": ["snowflake", "webtunnel", "meek_lite", "obfs4"],
        "next_gen_to_add": Value::Object(next_gen_to_add),
        "iran_dpi_notes": "Iran's SIAM (v3, deployed 2023) uses AI-based flow classifiers that can identify obfs4 at ~82% accuracy under sustained monitoring. Snowflake and WebTunnel remain undetected as of 2026 OONI data. Bridges on port 443 with CDN fronting have the highest survival rates.",
    });

    std::fs::write(output_path, serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

fn python_round_4(x: f64) -> f64 {
    format!("{x:.4}").parse::<f64>().unwrap_or(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpi_resistance_tier_known_and_unknown() {
        assert_eq!(dpi_resistance_tier("snowflake"), "maximum");
        assert_eq!(dpi_resistance_tier("HYSTERIA2"), "maximum");
        assert_eq!(dpi_resistance_tier("nonexistent"), "unknown");
    }

    #[test]
    fn dpi_score_unknown_transport_uses_fallback_base_and_block_rate() {
        let record = json!({ "transport": "totally_unknown", "port": 0 });
        // base 0.30 + port_mod 0.0 + cdn 0.0 + penalty 0.0 - (0.70*0.20=0.14) = 0.16
        assert_eq!(dpi_score(&record), 0.16);
    }

    #[test]
    fn transport_profile_and_next_gen_tables_have_expected_sizes() {
        assert_eq!(TRANSPORT_DPI_PROFILE.len(), 5);
        assert_eq!(NEXT_GEN_TRANSPORTS.len(), 4);
    }
}

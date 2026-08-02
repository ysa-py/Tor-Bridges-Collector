//! Parity port of `iran_nin_bypass.py`.
//!
//! Advanced Iran NIN (National Internet Network) bypass engine. When Iran
//! activates the NIN during internet shutdowns, international connectivity
//! is severed. This module:
//!   1. Detects whether the current host can reach the international internet.
//!   2. Classifies bridges by their NIN-survivability score.
//!   3. Generates a prioritised NIN emergency pack.
//!   4. Detects next-gen protocols (Hysteria2, REALITY, VLESS, etc.).
//!
//! SCOPE GUARDRAIL (Phase 5): This module tests reachability of public DNS
//! endpoints (1.1.1.1, 8.8.8.8, etc.) and passively classifies already-public
//! bridge records. No offensive fingerprinting of third-party infrastructure.
//! Ported faithfully.

use std::collections::BTreeMap;
use std::path::Path;

use regex::Regex;
use serde_json::{json, Value};

/// International probes — reachable normally, blocked during NIN.
/// Mirrors `_INTL_PROBES` in the Python original.
pub const INTL_PROBES: &[(&str, u16)] = &[
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
    ("208.67.222.222", 53),
    ("9.9.9.9", 53),
    ("104.16.0.1", 443),
];

/// Local probes — may survive NIN (Iran's CDN / ArvanCloud).
/// Mirrors `_LOCAL_PROBES` in the Python original.
pub const LOCAL_PROBES: &[(&str, u16)] = &[("4.2.2.4", 53), ("185.51.200.2", 53)];

/// CDN ASNs with their survivability weights. Mirrors `_CDN_ASNS`.
pub fn cdn_asns() -> BTreeMap<&'static str, (&'static str, f64)> {
    let mut m = BTreeMap::new();
    m.insert("AS13335", ("Cloudflare", 1.0));
    m.insert("AS54113", ("Fastly", 0.9));
    m.insert("AS16509", ("AWS CloudFront", 0.85));
    m.insert("AS8075", ("Microsoft Azure", 0.80));
    m.insert("AS15169", ("Google GCP", 0.75));
    m.insert("AS20940", ("Akamai", 0.80));
    m.insert("AS200000", ("ArvanCloud IR", 0.95));
    m.insert("AS202468", ("ArvanCloud Global", 0.70));
    m
}

/// Preferred ports with their survivability weights. Mirrors `_PREFERRED_PORTS`.
pub fn preferred_ports() -> BTreeMap<u16, f64> {
    let mut m = BTreeMap::new();
    m.insert(443, 1.0);
    m.insert(2053, 0.95);
    m.insert(2083, 0.90);
    m.insert(2087, 0.90);
    m.insert(8443, 0.80);
    m.insert(80, 0.50);
    m
}

/// Trait for TCP reachability probes. Production impl uses
/// `std::net::TcpStream::connect_timeout`; tests inject a mock.
pub trait TcpProbe: Sync {
    fn is_reachable(&self, host: &str, port: u16, timeout_secs: f64) -> bool;
}

/// Production TCP probe. Mirrors Python's `socket.create_connection`.
pub struct StdTcpProbe;

impl TcpProbe for StdTcpProbe {
    fn is_reachable(&self, host: &str, port: u16, timeout_secs: f64) -> bool {
        use std::net::ToSocketAddrs;
        let timeout = std::time::Duration::from_secs_f64(timeout_secs.max(0.001));
        let addrs = match (host, port).to_socket_addrs() {
            Ok(iter) => iter.collect::<Vec<_>>(),
            Err(_) => return false,
        };
        for addr in addrs {
            if std::net::TcpStream::connect_timeout(&addr, timeout).is_ok() {
                return true;
            }
        }
        false
    }
}

/// Mirror of `detect_nin_status()`. Returns `(international_ok, nin_likely_active)`.
/// `intl_ok` = at least one international probe is reachable.
/// `nin_active` = `!intl_ok`.
pub fn detect_nin_status(probe: &dyn TcpProbe) -> (bool, bool) {
    let intl_ok = INTL_PROBES
        .iter()
        .any(|(h, p)| probe.is_reachable(h, *p, 3.0));
    let nin_active = !intl_ok;
    tracing::info!("NIN detection: international_ok={intl_ok} nin_likely_active={nin_active}");
    (intl_ok, nin_active)
}

/// Mirror of `_nin_score(bridge_record)`. Computes a 0–1 NIN survivability
/// score based on transport, ASN, port, and composite score.
pub fn nin_score(bridge_record: &Value) -> f64 {
    let transport = bridge_record
        .get("transport")
        .and_then(Value::as_str)
        .unwrap_or("");
    let asn = bridge_record
        .get("asn")
        .and_then(Value::as_str)
        .unwrap_or("");
    let port = bridge_record
        .get("port")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n as u16)
                .or_else(|| v.as_str().and_then(|s| s.parse::<u16>().ok()))
        })
        .unwrap_or(0);
    let composite = bridge_record
        .get("composite_score")
        .and_then(Value::as_f64)
        .unwrap_or(0.5);

    // Transport weight
    let t_weight = match transport {
        "snowflake" => 1.00,
        "webtunnel" => 0.95,
        "meek_lite" => 0.90,
        "obfs4" => 0.40,
        "vanilla" => 0.10,
        _ => 0.30,
    };

    // ASN bonus
    let asn_bonus = cdn_asns().get(asn).map(|(_, w)| w * 0.3).unwrap_or(0.0);

    // Port bonus
    let port_bonus = preferred_ports().get(&port).copied().unwrap_or(0.0) * 0.2;

    let score = 0.50 * t_weight + 0.30 * composite + asn_bonus + port_bonus;
    score.min(1.0)
}

/// Next-gen protocol patterns. Mirrors `_NEXTGEN_PATTERNS`.
pub const NEXTGEN_PATTERNS: &[(&str, &str)] = &[
    ("hysteria2", r"hysteria2://"),
    ("hysteria", r"hysteria://"),
    ("reality", r"reality"),
    ("vless", r"vless://"),
    ("vmess", r"vmess://"),
    ("trojan", r"trojan://"),
    ("shadowsocks", r"ss://"),
];

/// Mirror of `_detect_nextgen(bridge_line)`. Returns the protocol name
/// if a next-gen pattern is found, else `None`.
pub fn detect_nextgen(bridge_line: &str) -> Option<&'static str> {
    let line_lower = bridge_line.to_ascii_lowercase();
    for (proto, pattern) in NEXTGEN_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(&line_lower) {
                return Some(proto);
            }
        }
    }
    None
}

/// Mirror of `run()`. Executes the full NIN bypass analysis pipeline.
/// Reads `bridge/iran_results.json`, scores each bridge, writes
/// `export/iran_nin_pack.txt` and `data/nin_analysis.json`.
///
/// I/O paths are injectable. `probe` is the TCP probe trait.
pub fn run(
    bridge_dir: &Path,
    export_dir: &Path,
    data_dir: &Path,
    probe: &dyn TcpProbe,
) -> Result<Value, std::io::Error> {
    std::fs::create_dir_all(export_dir)?;
    std::fs::create_dir_all(data_dir)?;

    // 1. NIN detection
    let (intl_ok, nin_active) = detect_nin_status(probe);

    // 2. Load iran_tester results
    let iran_results_path = bridge_dir.join("iran_results.json");
    let bridges: Vec<Value> = if iran_results_path.exists() {
        match std::fs::read_to_string(&iran_results_path) {
            Ok(text) => serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("bridges").and_then(Value::as_array).cloned())
                .unwrap_or_default(),
            Err(e) => {
                tracing::warn!("Cannot load iran_results.json: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    if bridges.is_empty() {
        tracing::warn!("No bridge records found — NIN analysis skipped.");
        return Ok(json!({
            "nin_active": nin_active,
            "bridges_scored": 0,
        }));
    }

    // 3. Score each bridge
    let mut scored: Vec<Value> = bridges
        .iter()
        .map(|b| {
            let nin_s = nin_score(b);
            let nextgen = detect_nextgen(b.get("line").and_then(Value::as_str).unwrap_or(""));
            let mut rec = b.clone();
            rec["nin_score"] = json!((nin_s * 1000.0).round() / 1000.0);
            rec["nextgen_proto"] = match nextgen {
                Some(p) => json!(p),
                None => Value::Null,
            };
            rec
        })
        .collect();

    // Sort by nin_score descending (stable sort, matching Python's sorted)
    scored.sort_by(|a, b| {
        let av = a["nin_score"].as_f64().unwrap_or(0.0);
        let bv = b["nin_score"].as_f64().unwrap_or(0.0);
        bv.partial_cmp(&av).unwrap_or(std::cmp::Ordering::Equal)
    });

    // 4. Write NIN pack (top 50 survivable bridges with score >= 0.70)
    let nin_pack: Vec<String> = scored
        .iter()
        .filter(|b| {
            let s = b["nin_score"].as_f64().unwrap_or(0.0);
            s >= 0.70
        })
        .filter_map(|b| {
            let line = b.get("line").and_then(Value::as_str).unwrap_or("");
            if !line.is_empty() {
                Some(line.to_string())
            } else {
                None
            }
        })
        .take(50)
        .collect();

    let nin_pack_path = export_dir.join("iran_nin_pack.txt");
    let mut pack_text = nin_pack.join("\n");
    if !pack_text.is_empty() {
        pack_text.push('\n');
    }
    std::fs::write(&nin_pack_path, pack_text)?;
    tracing::info!(
        "NIN pack: {} bridges → {}",
        nin_pack.len(),
        nin_pack_path.display()
    );

    // 5. Write full analysis
    let report = json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "nin_detected": nin_active,
        "international_ok": intl_ok,
        "total_scored": scored.len(),
        "nin_pack_size": nin_pack.len(),
        "top_bridges": scored.iter().take(20).cloned().collect::<Vec<_>>(),
    });
    std::fs::write(
        data_dir.join("nin_analysis.json"),
        serde_json::to_string_pretty(&report)?,
    )?;
    tracing::info!("NIN analysis saved: {} bridges scored.", scored.len());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysReachable;
    impl TcpProbe for AlwaysReachable {
        fn is_reachable(&self, _: &str, _: u16, _: f64) -> bool {
            true
        }
    }

    struct AlwaysUnreachable;
    impl TcpProbe for AlwaysUnreachable {
        fn is_reachable(&self, _: &str, _: u16, _: f64) -> bool {
            false
        }
    }

    #[test]
    fn detect_nin_status_returns_true_false_when_intl_reachable() {
        let (intl_ok, nin_active) = detect_nin_status(&AlwaysReachable);
        assert!(intl_ok);
        assert!(!nin_active);
    }

    #[test]
    fn detect_nin_status_returns_false_true_when_intl_unreachable() {
        let (intl_ok, nin_active) = detect_nin_status(&AlwaysUnreachable);
        assert!(!intl_ok);
        assert!(nin_active);
    }

    #[test]
    fn nin_score_snowflake_with_cdn_asn_and_preferred_port() {
        let record = json!({
            "transport": "snowflake",
            "asn": "AS13335",
            "port": 443,
            "composite_score": 0.8,
        });
        let score = nin_score(&record);
        // t_weight=1.0 → 0.50*1.0=0.50
        // composite=0.8 → 0.30*0.8=0.24
        // asn_bonus=1.0*0.3=0.30
        // port_bonus=1.0*0.2=0.20
        // total = 0.50+0.24+0.30+0.20 = 1.24 → clamped to 1.0
        assert_eq!(score, 1.0);
    }

    #[test]
    fn nin_score_vanilla_no_cdn_no_preferred_port() {
        let record = json!({
            "transport": "vanilla",
            "asn": "",
            "port": 9001,
            "composite_score": 0.5,
        });
        let score = nin_score(&record);
        // t_weight=0.10 → 0.50*0.10=0.05
        // composite=0.5 → 0.30*0.5=0.15
        // asn_bonus=0
        // port_bonus=0
        // total = 0.20
        assert!((score - 0.20).abs() < 0.001);
    }

    #[test]
    fn nin_score_obfs4_with_arvancloud_asn() {
        let record = json!({
            "transport": "obfs4",
            "asn": "AS200000",
            "port": 443,
            "composite_score": 0.6,
        });
        let score = nin_score(&record);
        // t_weight=0.40 → 0.50*0.40=0.20
        // composite=0.6 → 0.30*0.6=0.18
        // asn_bonus=0.95*0.3=0.285
        // port_bonus=1.0*0.2=0.20
        // total = 0.20+0.18+0.285+0.20 = 0.865
        assert!((score - 0.865).abs() < 0.001);
    }

    #[test]
    fn detect_nextgen_finds_hysteria2() {
        assert_eq!(
            detect_nextgen("hysteria2://user@host:443/?insecure=1"),
            Some("hysteria2")
        );
    }

    #[test]
    fn detect_nextgen_finds_vless() {
        assert_eq!(
            detect_nextgen("vless://uuid@host:443?encryption=none"),
            Some("vless")
        );
    }

    #[test]
    fn detect_nextgen_finds_reality() {
        assert_eq!(
            detect_nextgen("reality pubkey=abc dest=example.com:443"),
            Some("reality")
        );
    }

    #[test]
    fn detect_nextgen_returns_none_for_tor_bridge() {
        assert_eq!(detect_nextgen("obfs4 1.2.3.4:443 cert=abc"), None);
    }

    #[test]
    fn run_with_empty_bridges_returns_early() {
        let dir = std::env::temp_dir().join(format!("nin_bypass_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result = run(
            &dir.join("bridge"),
            &dir.join("export"),
            &dir.join("data"),
            &AlwaysUnreachable,
        )
        .unwrap();
        assert_eq!(result["bridges_scored"], 0);
        assert_eq!(result["nin_active"], true);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_with_bridges_writes_nin_pack_and_analysis() {
        let dir = std::env::temp_dir().join(format!("nin_bypass_test2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).unwrap();
        let iran_results = json!({
            "bridges": [
                {"line": "snowflake 192.0.2.3:1 url=https://x", "transport": "snowflake", "asn": "AS13335", "port": 443, "composite_score": 0.9},
                {"line": "vanilla 1.2.3.4:9001", "transport": "vanilla", "asn": "", "port": 9001, "composite_score": 0.3},
            ]
        });
        std::fs::write(
            bridge_dir.join("iran_results.json"),
            serde_json::to_string_pretty(&iran_results).unwrap(),
        )
        .unwrap();

        let result = run(
            &bridge_dir,
            &dir.join("export"),
            &dir.join("data"),
            &AlwaysReachable,
        )
        .unwrap();
        assert_eq!(result["total_scored"], 2);
        // The snowflake bridge should be in the NIN pack (score >= 0.70)
        let pack = std::fs::read_to_string(dir.join("export/iran_nin_pack.txt")).unwrap();
        assert!(pack.contains("snowflake"));
        // The analysis file should exist
        assert!(dir.join("data/nin_analysis.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

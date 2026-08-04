//! Parity port of `nin_cut_tester.py`.
//!
//! Stage 8k: NIN Internet-Cut Survivability Tester. Tests Tor bridges for
//! reachability inside Iran's National Information Network during complete
//! international internet blackout events. Operates exclusively on IP
//! addresses and ports — zero DNS lookups — because DNS is fully blocked
//! during NIN-isolation events.
//!
//! Scoring criteria (0.0–1.0):
//!   a. IP falls within Iranian CDN or domestic ASN range → +0.40
//!   b. Port is NIN-allowed (80, 443, 8080, 8443) → +0.30
//!   c. Transport is WebTunnel or obfs4 → +0.30
//!   d. TCP reachable bonus → +0.15 (capped at 1.0)
//!
//! SCOPE GUARDRAIL (Phase 5): This module tests reachability of
//! publicly-listed Tor bridges and classifies them against public Iranian
//! ASN CIDR data. No offensive fingerprinting. Ported faithfully.

use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use regex::Regex;
use serde_json::{json, Value};

/// NIN-allowed ports. Mirrors `NIN_ALLOWED_PORTS`.
pub const NIN_ALLOWED_PORTS: &[u16] = &[80, 443, 8080, 8443];

/// High-survivability transport types. Mirrors `HIGH_SURVIVAL_TRANSPORTS`.
pub const HIGH_SURVIVAL_TRANSPORTS: &[&str] = &["webtunnel", "obfs4"];

/// Raw Iranian domestic CIDR list. Mirrors `_RAW_IRAN_CIDRS`.
pub const RAW_IRAN_CIDRS: &[&str] = &[
    "5.22.192.0/18",
    "5.23.112.0/21",
    "5.53.32.0/19",
    "5.160.0.0/14",
    "5.200.64.0/18",
    "5.201.128.0/17",
    "5.250.0.0/17",
    "2.144.0.0/13",
    "2.176.0.0/12",
    "37.137.0.0/15",
    "78.38.0.0/15",
    "85.185.0.0/16",
    "91.92.0.0/22",
    "91.186.188.0/22",
    "94.182.0.0/16",
    "94.183.0.0/16",
    "109.122.192.0/18",
    "185.1.74.0/24",
    "91.108.4.0/22",
    "91.108.56.0/22",
    "185.143.232.0/22",
    "185.215.232.0/22",
    "179.43.145.0/24",
    "87.247.168.0/21",
    "94.74.128.0/17",
    "85.204.100.0/22",
    "79.175.128.0/17",
    "185.213.176.0/22",
    "31.14.80.0/20",
    "31.184.128.0/18",
    "5.34.192.0/19",
    "5.56.128.0/17",
    "46.143.196.0/22",
    "46.209.0.0/16",
    "78.109.192.0/18",
    "78.157.32.0/19",
    "80.75.0.0/17",
    "80.191.0.0/16",
    "82.99.192.0/18",
    "82.138.128.0/17",
    "185.8.172.0/22",
    "185.55.224.0/22",
    "188.136.128.0/17",
    "193.151.128.0/17",
    "194.5.174.0/23",
    "194.60.240.0/21",
];

/// Parsed Iranian domestic CIDR table. Pre-parsed at construction time
/// for O(1) containment checks.
pub struct IranCidrTable {
    networks: Vec<(u32, u32)>, // (network_addr, netmask)
}

impl IranCidrTable {
    /// Build from the raw CIDR list. Invalid CIDRs are silently skipped
    /// (mirrors Python's `except ValueError: pass`).
    pub fn new() -> Self {
        let mut networks = Vec::new();
        for cidr in RAW_IRAN_CIDRS {
            if let Some((net, mask)) = parse_ipv4_cidr(cidr) {
                networks.push((net, mask));
            }
        }
        Self { networks }
    }

    /// Returns `true` if `ip` is an IPv4 address contained in any of the
    /// Iranian domestic CIDRs. IPv6 always returns `false` (mirrors Python's
    /// `isinstance(ip_obj, IPv4Address)` check).
    pub fn contains(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(v4) = ip else {
            return false;
        };
        let ip_u32 = u32::from(v4);
        for (net, mask) in &self.networks {
            if (ip_u32 & mask) == *net {
                return true;
            }
        }
        false
    }
}

impl Default for IranCidrTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an IPv4 CIDR string like "5.22.192.0/18" into (network, netmask).
fn parse_ipv4_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip_part, prefix_len) = cidr.split_once('/')?;
    let prefix_len: u32 = prefix_len.parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let ip: std::net::Ipv4Addr = ip_part.parse().ok()?;
    let ip_u32 = u32::from(ip);
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        (!0u32) << (32 - prefix_len)
    };
    Some((ip_u32 & mask, mask))
}

/// Parsed bridge line. Mirrors the dict returned by `_parse_bridge_line`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedBridge {
    pub raw: String,
    pub ip: String,
    pub port: u16,
    pub transport: String,
    pub ip_obj: IpAddr,
}

/// Mirror of `_parse_bridge_line(line)`. Returns `None` for empty lines,
/// comments, or unparseable lines. No DNS lookups — IP addresses only.
pub fn parse_bridge_line(line: &str) -> Option<ParsedBridge> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut transport = "vanilla".to_string();
    let mut rest = line.to_string();

    // Detect pluggable transport prefix. Regex construction is fallible even
    // for literals, so malformed build-time patterns safely yield no parse.
    let pt_re = Regex::new(r"(?i)^(obfs4|webtunnel|snowflake|meek_lite|obfs3)\s+").ok()?;
    if let Some(caps) = pt_re.captures(line) {
        let token = caps.get(1)?;
        let full = caps.get(0)?;
        transport = token.as_str().to_ascii_lowercase();
        rest = line[full.end()..].to_string();
    }

    // Try IPv4 first.
    let ipv4_re = Regex::new(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b").ok()?;
    let (ip_str, port_str) = if let Some(caps) = ipv4_re.captures(&rest) {
        (
            caps.get(1)?.as_str().to_string(),
            caps.get(2)?.as_str().to_string(),
        )
    } else {
        // Try IPv6 [addr]:port.
        let ipv6_re = Regex::new(r"\[([0-9a-fA-F:]+)\]:(\d{2,5})").ok()?;
        let caps = ipv6_re.captures(&rest)?;
        (
            caps.get(1)?.as_str().to_string(),
            caps.get(2)?.as_str().to_string(),
        )
    };

    let port: u16 = port_str.parse().ok()?;
    if !(1..=65535).contains(&port) {
        return None;
    }

    let ip_obj: IpAddr = ip_str.parse().ok()?;

    Some(ParsedBridge {
        raw: line.to_string(),
        ip: ip_obj.to_string(),
        port,
        transport,
        ip_obj,
    })
}

/// Mirror of `_is_iran_domestic(ip_obj)`.
pub fn is_iran_domestic(ip: IpAddr, table: &IranCidrTable) -> bool {
    table.contains(ip)
}

/// Mirror of `_score_bridge(parsed)`. Computes NIN-cut survivability
/// score 0.0–1.0 (without the TCP reachability bonus).
pub fn score_bridge(parsed: &ParsedBridge, table: &IranCidrTable) -> f64 {
    let mut score = 0.0_f64;

    // Criterion a: domestic IP
    if is_iran_domestic(parsed.ip_obj, table) {
        score += 0.40;
    }

    // Criterion b: NIN-allowed port
    if NIN_ALLOWED_PORTS.contains(&parsed.port) {
        score += 0.30;
    }

    // Criterion c: high-survivability transport
    if HIGH_SURVIVAL_TRANSPORTS.contains(&parsed.transport.to_ascii_lowercase().as_str()) {
        score += 0.30;
    }

    round4(score.min(1.0))
}

/// Round to 4 decimal places, matching Python's `round(x, 4)`.
fn round4(x: f64) -> f64 {
    (x * 10000.0).round() / 10000.0
}

/// Default maximum number of bridge lines that Stage 8k actively probes in one
/// invocation. The source list can be much larger; scoring still remains
/// deterministic, while the cap keeps a pathological all-timeout run bounded.
pub const DEFAULT_MAX_PROBES: usize = 2_000;

/// Default worker count for Stage 8k's bounded synchronous TCP pool. At the
/// historical three-second timeout this caps a 1,584-line input at roughly 75
/// seconds rather than the 79 minutes caused by the former sequential loop.
pub const DEFAULT_MAX_WORKERS: usize = 64;

/// Probe execution settings for the NIN-cut tester.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProbeOptions {
    /// Maximum concurrent blocking TCP probes.
    pub max_workers: usize,
    /// Maximum parsed bridge lines to probe during one run.
    pub max_bridges: usize,
    /// Per-socket timeout supplied to the probe implementation.
    pub timeout_secs: f64,
}

impl ProbeOptions {
    /// Construct resilient settings from environment overrides. Invalid values
    /// safely fall back to defaults so a typo cannot reintroduce a stuck CI run.
    pub fn from_env() -> Self {
        let max_workers = positive_usize_env("NIN_CUT_MAX_WORKERS", DEFAULT_MAX_WORKERS, 512);
        let max_bridges = positive_usize_env("NIN_CUT_MAX_BRIDGES", DEFAULT_MAX_PROBES, 20_000);
        let timeout_secs = std::env::var("NIN_CUT_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value > 0.0 && *value <= 60.0)
            .unwrap_or(3.0);
        Self {
            max_workers,
            max_bridges,
            timeout_secs,
        }
    }
}

fn positive_usize_env(name: &str, default: usize, maximum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0 && *value <= maximum)
        .unwrap_or(default)
}

/// Trait for TCP reachability probes with latency measurement.
pub trait TcpProbe: Sync {
    /// Returns `(reachable, latency_ms)`. `latency_ms` is `None` if not reachable.
    fn probe(&self, ip: &str, port: u16, timeout_secs: f64) -> (bool, Option<f64>);
}

/// Production TCP probe using `std::net::TcpStream::connect_timeout`.
pub struct StdTcpProbe;

impl TcpProbe for StdTcpProbe {
    fn probe(&self, ip: &str, port: u16, timeout_secs: f64) -> (bool, Option<f64>) {
        use std::net::ToSocketAddrs;
        let timeout = std::time::Duration::from_secs_f64(timeout_secs.max(0.001));
        let addrs = match (ip, port).to_socket_addrs() {
            Ok(iter) => iter.collect::<Vec<_>>(),
            Err(_) => return (false, None),
        };
        for addr in addrs {
            let t0 = std::time::Instant::now();
            if std::net::TcpStream::connect_timeout(&addr, timeout).is_ok() {
                let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;
                return (true, Some((latency_ms * 10.0).round() / 10.0));
            }
        }
        (false, None)
    }
}

/// Mirror of `_probe_bridge(parsed)`. Probes a single bridge with the legacy
/// three-second timeout and returns the enriched record with
/// `tcp_reachable`, `tcp_latency_ms`, and the TCP-reachability score bonus
/// (+0.15, capped at 1.0).
pub fn probe_bridge(parsed: &ParsedBridge, table: &IranCidrTable, probe: &dyn TcpProbe) -> Value {
    probe_bridge_with_timeout(parsed, table, probe, 3.0)
}

/// Variant of [`probe_bridge`] used by the bounded Stage 8k pool. Making the
/// timeout explicit preserves the existing public helper while allowing CI to
/// configure a safe upper bound via `NIN_CUT_TIMEOUT_SECS`.
pub fn probe_bridge_with_timeout(
    parsed: &ParsedBridge,
    table: &IranCidrTable,
    probe: &dyn TcpProbe,
    timeout_secs: f64,
) -> Value {
    let base_score = score_bridge(parsed, table);
    let (tcp_reachable, tcp_latency_ms) = probe.probe(&parsed.ip, parsed.port, timeout_secs);

    let nin_score = if tcp_reachable {
        round4((base_score + 0.15).min(1.0))
    } else {
        base_score
    };

    json!({
        "raw": parsed.raw,
        "ip": parsed.ip,
        "port": parsed.port,
        "transport": parsed.transport,
        "domestic_ip": is_iran_domestic(parsed.ip_obj, table),
        "nin_port": NIN_ALLOWED_PORTS.contains(&parsed.port),
        "nin_transport": HIGH_SURVIVAL_TRANSPORTS
            .contains(&parsed.transport.to_ascii_lowercase().as_str()),
        "nin_score": nin_score,
        "tcp_reachable": tcp_reachable,
        "tcp_latency_ms": tcp_latency_ms,
    })
}

/// Mirror of `_load_bridges()`. Loads and parses bridge lines from `input_file`.
///
/// The production input is `bridge/bridge_list_for_testing.json`, a JSON array
/// of strings. The old Rust port treated that array as newline-delimited text,
/// leaving quotes/commas in every raw line and, more importantly, feeding 1,584
/// sequential three-second probes to CI. This decoder accepts JSON arrays,
/// `{"bridges": [...]}` objects, and legacy newline text without changing the
/// public input path.
pub fn load_bridges(input_file: &Path) -> Vec<ParsedBridge> {
    if !input_file.exists() {
        tracing::warn!(
            "Input file not found: {} — returning empty list.",
            input_file.display()
        );
        return Vec::new();
    }
    let text = match std::fs::read_to_string(input_file) {
        Ok(t) => t,
        Err(error) => {
            tracing::warn!("Cannot read {input_file:?}: {error}");
            return Vec::new();
        }
    };
    let lines = json_bridge_lines(&text).unwrap_or_else(|| {
        text.lines()
            .map(str::to_owned)
            .collect::<Vec<String>>()
    });
    let mut parsed = Vec::new();
    let mut skipped = 0_u32;
    for line in lines {
        if let Some(result) = parse_bridge_line(&line) {
            parsed.push(result);
        } else if !line.trim().is_empty() && !line.starts_with('#') {
            skipped = skipped.saturating_add(1);
        }
    }
    tracing::info!(
        "Loaded {} bridges from {} ({skipped} skipped / unparseable).",
        parsed.len(),
        input_file.display()
    );
    parsed
}

fn json_bridge_lines(text: &str) -> Option<Vec<String>> {
    let root: Value = serde_json::from_str(text).ok()?;
    let values = match root {
        Value::Array(values) => values,
        Value::Object(mut object) => object.remove("bridges")?.as_array()?.to_vec(),
        _ => return None,
    };
    Some(
        values
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect(),
    )
}

/// Mirror of `_write_outputs(results)`. Writes the JSON report and the
/// survivable bridge list.
pub fn write_outputs(
    results: &[Value],
    report_path: &Path,
    export_path: &Path,
) -> Result<(), std::io::Error> {
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = export_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let survivable: Vec<&Value> = results
        .iter()
        .filter(|r| r.get("nin_score").and_then(Value::as_f64).unwrap_or(0.0) >= 0.60)
        .collect();
    let reachable: Vec<&Value> = results
        .iter()
        .filter(|r| {
            r.get("tcp_reachable")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .collect();

    let report = json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "total_bridges": results.len(),
        "survivable_count": survivable.len(),
        "tcp_reachable_count": reachable.len(),
        "score_threshold": 0.60,
        "scoring_note": "Score components: domestic_ip (+0.40), nin_port (+0.30), nin_transport (+0.30), tcp_reachable_bonus (+0.15, capped at 1.0). NIN-cut scenario: international internet fully blocked; only traffic through Iranian ASNs remains reachable.",
        "iran_asns_checked": [
            "AS44244 ITC", "AS16322 ParsOnline", "AS48159 TCI",
            "AS58224 Iran Telecom", "AS24631 Afranet", "ArvanCloud",
        ],
        "bridges": results,
    });
    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)?;
    tracing::info!(
        "NIN-cut report written: {} bridges, {} survivable → {}",
        results.len(),
        survivable.len(),
        report_path.display()
    );

    let lines: Vec<String> = survivable
        .iter()
        .filter_map(|r| r.get("raw").and_then(Value::as_str).map(|s| s.to_string()))
        .collect();
    let mut export_text = lines.join("\n");
    if !lines.is_empty() {
        export_text.push('\n');
    }
    std::fs::write(export_path, export_text)?;
    tracing::info!(
        "Survivable bridges written: {} → {}",
        lines.len(),
        export_path.display()
    );
    Ok(())
}

/// Mirror of `_write_empty_outputs()`.
pub fn write_empty_outputs(
    input_file: &Path,
    report_path: &Path,
    export_path: &Path,
) -> Result<(), std::io::Error> {
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = export_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let empty_report = json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "total_bridges": 0,
        "survivable_count": 0,
        "bridges": [],
        "note": format!("Input file not found: {}", input_file.display()),
    });
    std::fs::write(report_path, serde_json::to_string_pretty(&empty_report)?)?;
    std::fs::write(export_path, "")?;
    tracing::info!("Empty outputs written (input file missing).");
    Ok(())
}

/// Mirror of `main()`. Returns 0 on success, using environment-configured
/// bounded concurrency so CI cannot exceed its stage timeout on a large
/// all-timeout input list.
pub fn run_main(
    input_file: &Path,
    report_path: &Path,
    export_path: &Path,
    probe: &dyn TcpProbe,
) -> Result<i32, std::io::Error> {
    run_main_with_options(
        input_file,
        report_path,
        export_path,
        probe,
        ProbeOptions::from_env(),
    )
}

/// Run Stage 8k with explicit options. This is public to make concurrency and
/// cap behavior deterministic in tests and reusable by future schedulers.
pub fn run_main_with_options(
    input_file: &Path,
    report_path: &Path,
    export_path: &Path,
    probe: &dyn TcpProbe,
    options: ProbeOptions,
) -> Result<i32, std::io::Error> {
    tracing::info!("═══ Stage 8k: NIN Internet-Cut Survivability Tester ════════");

    let mut bridges = load_bridges(input_file);
    if bridges.is_empty() {
        write_empty_outputs(input_file, report_path, export_path)?;
        tracing::info!("No bridges to test — exiting cleanly.");
        return Ok(0);
    }
    let skipped_by_cap = bridges.len().saturating_sub(options.max_bridges);
    bridges.truncate(options.max_bridges);
    tracing::info!(
        "Running bounded TCP probes on {} bridges (workers={}, timeout={}s, skipped_by_cap={skipped_by_cap}; no DNS)…",
        bridges.len(),
        options.max_workers,
        options.timeout_secs,
    );
    let table = IranCidrTable::new();
    let results = probe_bridges_bounded(&bridges, &table, probe, options);

    write_outputs_with_execution_metadata(
        &results,
        report_path,
        export_path,
        options,
        skipped_by_cap,
    )?;

    let survivable = results
        .iter()
        .filter(|record| record.get("nin_score").and_then(Value::as_f64).unwrap_or(0.0) >= 0.60)
        .count();
    tracing::info!(
        "═══ Stage 8k done: {survivable}/{} bridges NIN-cut survivable ════════",
        results.len()
    );
    Ok(0)
}

/// Probe bridge records in a scoped thread pool while preserving input order in
/// the emitted report. The `TcpProbe: Sync` contract permits safe shared access
/// to the production probe and deterministic test doubles alike.
pub fn probe_bridges_bounded(
    bridges: &[ParsedBridge],
    table: &IranCidrTable,
    probe: &dyn TcpProbe,
    options: ProbeOptions,
) -> Vec<Value> {
    let count = bridges.len().min(options.max_bridges);
    if count == 0 {
        return Vec::new();
    }
    let workers = options.max_workers.max(1).min(count);
    let next = AtomicUsize::new(0);
    let results = Mutex::new(vec![None; count]);

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            handles.push(scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= count {
                    break;
                }
                let value = probe_bridge_with_timeout(&bridges[index], table, probe, options.timeout_secs);
                let mut guard = match results.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                guard[index] = Some(value);
            }));
        }
        for handle in handles {
            if handle.join().is_err() {
                tracing::error!("NIN-cut worker panicked; preserving completed probe records");
            }
        }
    });

    let guard = match results.into_inner() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.into_iter().flatten().collect()
}

fn write_outputs_with_execution_metadata(
    results: &[Value],
    report_path: &Path,
    export_path: &Path,
    options: ProbeOptions,
    skipped_by_cap: usize,
) -> Result<(), std::io::Error> {
    write_outputs(results, report_path, export_path)?;
    let text = std::fs::read_to_string(report_path)?;
    let mut report: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({}));
    if let Some(object) = report.as_object_mut() {
        object.insert("probe_workers".to_owned(), Value::from(options.max_workers));
        object.insert("probe_timeout_secs".to_owned(), Value::from(options.timeout_secs));
        object.insert("skipped_by_probe_cap".to_owned(), Value::from(skipped_by_cap));
    }
    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysReachable;
    impl TcpProbe for AlwaysReachable {
        fn probe(&self, _: &str, _: u16, _: f64) -> (bool, Option<f64>) {
            (true, Some(42.5))
        }
    }

    struct AlwaysUnreachable;
    impl TcpProbe for AlwaysUnreachable {
        fn probe(&self, _: &str, _: u16, _: f64) -> (bool, Option<f64>) {
            (false, None)
        }
    }

    #[test]
    fn parse_bridge_line_vanilla() {
        let p = parse_bridge_line("vanilla 1.2.3.4:443").unwrap();
        assert_eq!(p.transport, "vanilla");
        assert_eq!(p.ip, "1.2.3.4");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_bridge_line_obfs4() {
        let p = parse_bridge_line("obfs4 1.2.3.4:443 cert=abc iat-mode=2").unwrap();
        assert_eq!(p.transport, "obfs4");
        assert_eq!(p.ip, "1.2.3.4");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_bridge_line_webtunnel() {
        let p = parse_bridge_line("webtunnel 192.0.2.4:443 url=https://example.com").unwrap();
        assert_eq!(p.transport, "webtunnel");
        assert_eq!(p.ip, "192.0.2.4");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_bridge_line_ipv6() {
        let p = parse_bridge_line("obfs4 [2001:db8::1]:443 cert=abc").unwrap();
        assert_eq!(p.transport, "obfs4");
        assert_eq!(p.ip, "2001:db8::1");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_bridge_line_returns_none_for_empty() {
        assert!(parse_bridge_line("").is_none());
        assert!(parse_bridge_line("   ").is_none());
    }

    #[test]
    fn parse_bridge_line_returns_none_for_comment() {
        assert!(parse_bridge_line("# this is a comment").is_none());
    }

    #[test]
    fn parse_bridge_line_returns_none_for_invalid_port() {
        assert!(parse_bridge_line("vanilla 1.2.3.4:99999").is_none());
        assert!(parse_bridge_line("vanilla 1.2.3.4:0").is_none());
    }

    #[test]
    fn iran_cidr_table_contains_domestic_ip() {
        let table = IranCidrTable::new();
        // 5.22.192.0/18 is in the table → 5.22.200.1 should match
        assert!(table.contains("5.22.200.1".parse().unwrap()));
    }

    #[test]
    fn iran_cidr_table_excludes_international_ip() {
        let table = IranCidrTable::new();
        // 1.1.1.1 is Cloudflare, not Iranian
        assert!(!table.contains("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn iran_cidr_table_excludes_ipv6() {
        let table = IranCidrTable::new();
        assert!(!table.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn score_bridge_domestic_nin_port_nin_transport() {
        let table = IranCidrTable::new();
        let p = parse_bridge_line("obfs4 5.22.200.1:443 cert=abc").unwrap();
        let score = score_bridge(&p, &table);
        // domestic=0.40 + nin_port=0.30 + nin_transport=0.30 = 1.0
        assert_eq!(score, 1.0);
    }

    #[test]
    fn score_bridge_international_non_nin_port_non_nin_transport() {
        let table = IranCidrTable::new();
        let p = parse_bridge_line("vanilla 1.1.1.1:9001").unwrap();
        let score = score_bridge(&p, &table);
        // no bonuses → 0.0
        assert_eq!(score, 0.0);
    }

    #[test]
    fn probe_bridge_adds_tcp_bonus() {
        let table = IranCidrTable::new();
        let p = parse_bridge_line("obfs4 5.22.200.1:443 cert=abc").unwrap();
        let result = probe_bridge(&p, &table, &AlwaysReachable);
        // base=1.0 + tcp_bonus=0.15 → clamped to 1.0
        assert_eq!(result["nin_score"], 1.0);
        assert_eq!(result["tcp_reachable"], true);
        assert_eq!(result["tcp_latency_ms"], 42.5);
    }

    #[test]
    fn probe_bridge_no_bonus_when_unreachable() {
        let table = IranCidrTable::new();
        let p = parse_bridge_line("vanilla 1.1.1.1:9001").unwrap();
        let result = probe_bridge(&p, &table, &AlwaysUnreachable);
        assert_eq!(result["nin_score"], 0.0);
        assert_eq!(result["tcp_reachable"], false);
        assert!(result["tcp_latency_ms"].is_null());
    }

    #[test]
    fn run_main_with_missing_input_writes_empty_outputs() {
        let dir = std::env::temp_dir().join(format!("nin_cut_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let input = dir.join("input.txt");
        let report = dir.join("data/report.json");
        let export = dir.join("export/survivable.txt");
        let rc = run_main(&input, &report, &export, &AlwaysReachable).unwrap();
        assert_eq!(rc, 0);
        assert!(report.exists());
        assert!(export.exists());
        let report_text = std::fs::read_to_string(&report).unwrap();
        let report_json: Value = serde_json::from_str(&report_text).unwrap();
        assert_eq!(report_json["total_bridges"], 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_array_input_is_decoded_as_bridge_lines_not_json_syntax() {
        let dir = std::env::temp_dir().join(format!("nin_cut_json_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture directory");
        let input = dir.join("bridges.json");
        std::fs::write(
            &input,
            r#"["obfs4 5.22.200.1:443 cert=abc", "vanilla 1.1.1.1:9001"]"#,
        )
        .expect("fixture input");
        let bridges = load_bridges(&input);
        assert_eq!(bridges.len(), 2);
        assert_eq!(bridges[0].transport, "obfs4");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounded_pool_honors_probe_cap_and_preserves_input_order() {
        let table = IranCidrTable::new();
        let bridges = vec![
            parse_bridge_line("vanilla 1.1.1.1:443").expect("fixture bridge one"),
            parse_bridge_line("obfs4 5.22.200.1:443 cert=abc").expect("fixture bridge two"),
            parse_bridge_line("vanilla 8.8.8.8:443").expect("fixture bridge three"),
        ];
        let results = probe_bridges_bounded(
            &bridges,
            &table,
            &AlwaysUnreachable,
            ProbeOptions {
                max_workers: 2,
                max_bridges: 2,
                timeout_secs: 0.1,
            },
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["raw"], "vanilla 1.1.1.1:443");
        assert_eq!(results[1]["raw"], "obfs4 5.22.200.1:443 cert=abc");
    }

    #[test]
    fn run_main_with_bridges_writes_outputs() {
        let dir = std::env::temp_dir().join(format!("nin_cut_test2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let input = dir.join("input.txt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &input,
            "obfs4 5.22.200.1:443 cert=abc iat-mode=2\nvanilla 1.1.1.1:9001\n",
        )
        .unwrap();
        let report = dir.join("data/report.json");
        let export = dir.join("export/survivable.txt");
        let rc = run_main(&input, &report, &export, &AlwaysUnreachable).unwrap();
        assert_eq!(rc, 0);
        let report_text = std::fs::read_to_string(&report).unwrap();
        let report_json: Value = serde_json::from_str(&report_text).unwrap();
        assert_eq!(report_json["total_bridges"], 2);
        // Only the domestic obfs4 bridge should be survivable (score=1.0 >= 0.60)
        assert_eq!(report_json["survivable_count"], 1);
        let export_text = std::fs::read_to_string(&export).unwrap();
        assert!(export_text.contains("5.22.200.1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

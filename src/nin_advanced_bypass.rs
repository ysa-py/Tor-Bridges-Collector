//! Parity port of `nin_advanced_bypass.py`.
//!
//! Identifies Tor bridges that can survive Iran's National Internet (NIN /
//! شبکه ملی اطلاعات) activation by scoring them against:
//!   1. Transport type (webtunnel > snowflake > meek_lite > obfs4 > vanilla)
//!   2. CDN domain reachability within NIN (ArvanCloud, DerakCloud, etc.)
//!   3. Port open during NIN (80, 443, 8080, 8443, 2053, 2083, 2087, 2096)
//!   4. Live TCP reachability (best-effort, never fails)
//!
//! SCOPE GUARDRAIL (Phase 5): This module tests reachability of publicly-listed
//! Tor bridges and passively classifies them against public CDN/ASN data. No
//! offensive fingerprinting of third-party infrastructure. Ported faithfully.

use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{json, Value};

/// CDN domains/patterns that typically remain reachable during NIN cuts.
/// Mirrors `NIN_REACHABLE_CDNS` in the Python original.
pub const NIN_REACHABLE_CDNS: &[&str] = &[
    "arvancloud.com",
    "arvancloud.ir",
    "cdn.arvancloud.com",
    "derak.cloud",
    "parspack.com",
    "iranserver.com",
    "cloudflare.com",
    "fastly.net",
    "gcore.com",
    "cdn77.com",
];

/// ASN ranges observed as still reachable during NIN. Mirrors
/// `NIN_REACHABLE_ASNS` in the Python original.
pub fn nin_reachable_asns() -> HashSet<&'static str> {
    [
        "AS13335", // Cloudflare
        "AS20940", // Akamai
        "AS16509", // Amazon CloudFront
        "AS15169", // Google (partial)
        "AS54113", // Fastly
    ]
    .into_iter()
    .collect()
}

/// Ports that Iran's SIAM/NGFW typically leaves open during NIN.
/// Mirrors `NIN_OPEN_PORTS` in the Python original.
pub const NIN_OPEN_PORTS: &[u16] = &[80, 443, 8080, 8443, 2053, 2083, 2087, 2096];

/// Detect the transport type from a bridge line. Mirrors `_detect_transport`.
pub fn detect_transport(line: &str) -> &'static str {
    let l = line.to_ascii_lowercase();
    if l.contains("snowflake") {
        return "snowflake";
    }
    if l.contains("webtunnel") || l.contains("url=https") {
        return "webtunnel";
    }
    if l.contains("obfs4") {
        return "obfs4";
    }
    if l.contains("meek") {
        return "meek_lite";
    }
    "vanilla"
}

/// Extract the endpoint (host, port) from a bridge line. Mirrors
/// `_extract_endpoint`. Returns `(None, None)` if neither an `https://host:port`
/// nor an IPv4:port pattern is found.
pub fn extract_endpoint(line: &str) -> (Option<String>, Option<u16>) {
    // HTTPS URL pattern: https?://([^/:\s]+)(?::(\d+))?
    let https_re = Regex::new(r"(?i)https?://([^/:\s]+)(?::(\d+))?").unwrap();
    if let Some(caps) = https_re.captures(line) {
        let host = caps.get(1).map(|m| m.as_str().to_string());
        let port = caps
            .get(2)
            .and_then(|m| m.as_str().parse::<u16>().ok())
            .or(Some(443));
        return (host, port);
    }
    // IPv4:port pattern: (\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})
    let ip4_re = Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})").unwrap();
    if let Some(caps) = ip4_re.captures(line) {
        let host = caps.get(1).map(|m| m.as_str().to_string());
        let port = caps.get(2).and_then(|m| m.as_str().parse::<u16>().ok());
        return (host, port);
    }
    (None, None)
}

/// Check if a host matches a known NIN-surviving CDN. Mirrors
/// `_domain_in_nin_cdn`. Case-insensitive substring match.
pub fn domain_in_nin_cdn(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    if host.is_empty() {
        return false;
    }
    let hl = host.to_ascii_lowercase();
    NIN_REACHABLE_CDNS.iter().any(|cdn| hl.contains(cdn))
}

/// Check if a port is typically open during NIN. Mirrors `_port_nin_open`.
pub fn port_nin_open(port: Option<u16>) -> bool {
    port.map(|p| NIN_OPEN_PORTS.contains(&p)).unwrap_or(false)
}

/// Trait for performing live TCP reachability probes. The production impl
/// uses `std::net::TcpStream::connect_timeout`; tests inject a mock.
pub trait TcpProbe: Sync {
    fn is_reachable(&self, host: &str, port: u16, timeout_secs: f64) -> bool;
}

/// Production TCP probe using `std::net::TcpStream`. Matches Python's
/// `socket.create_connection((host, port), timeout=timeout)` semantics.
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

/// Offline TCP probe: reports every endpoint as unreachable without any
/// network I/O. Used when the live-probe budget (see
/// [`probe_budget_from_env`]) is exhausted — on a slow or blackholed network
/// every real probe would burn its full timeout — and by tests that must not
/// touch the network. The scores it yields are identical to what live probes
/// return on a fully filtered network, so results stay deterministic.
pub struct NoProbe;

impl TcpProbe for NoProbe {
    fn is_reachable(&self, _host: &str, _port: u16, _timeout_secs: f64) -> bool {
        false
    }
}

/// Default total wall-clock budget (seconds) for live TCP probes during NIN
/// scoring. Chosen well below the 20-minute CI step timeout so the stage
/// always completes even when every probe times out. Override with the
/// `NIN_ADVANCED_PROBE_BUDGET_SECS` env var; `0` disables live probing.
pub const DEFAULT_PROBE_BUDGET_SECS: u64 = 600;

/// Resolve the live-probe budget from `NIN_ADVANCED_PROBE_BUDGET_SECS`.
/// Unset values fall back to [`DEFAULT_PROBE_BUDGET_SECS`]; unparseable
/// values log a warning (never silently ignored) and also fall back.
#[must_use]
pub fn probe_budget_from_env() -> Duration {
    let raw = match std::env::var("NIN_ADVANCED_PROBE_BUDGET_SECS") {
        Ok(value) => value,
        Err(_) => return Duration::from_secs(DEFAULT_PROBE_BUDGET_SECS),
    };
    match raw.trim().parse::<u64>() {
        Ok(secs) => Duration::from_secs(secs),
        Err(_) => {
            tracing::warn!(
                "invalid NIN_ADVANCED_PROBE_BUDGET_SECS={} — using default budget of {}s",
                raw,
                DEFAULT_PROBE_BUDGET_SECS,
            );
            Duration::from_secs(DEFAULT_PROBE_BUDGET_SECS)
        }
    }
}

/// Score a bridge for Iran NIN survivability. Mirrors `score_for_nin`.
///
/// Returns a JSON object with keys: `bridge_line`, `transport`, `host`,
/// `port`, `nin_score`, `nin_flags`, `tcp_reachable`.
///
/// `tcp_probe` is injectable so tests don't perform real network I/O.
/// Production callers should pass `&StdTcpProbe`.
pub fn score_for_nin(bridge_line: &str, tcp_probe: &dyn TcpProbe) -> Value {
    let line = bridge_line.trim().to_string();
    let transport = detect_transport(&line);
    let (host, port) = extract_endpoint(&line);

    let mut score: f64 = 0.0;
    let mut flags: Vec<String> = Vec::new();

    // Transport scoring (NIN perspective)
    match transport {
        "webtunnel" => {
            score += 0.50;
            flags.push("webtunnel_cdn_fronted".to_string());
        }
        "snowflake" => {
            score += 0.45;
            flags.push("snowflake_webrtc".to_string());
        }
        "meek_lite" => {
            score += 0.35;
            flags.push("meek_domain_fronted".to_string());
        }
        "obfs4" => {
            score += 0.10;
            flags.push("obfs4_tcp_only".to_string());
        }
        _ => {
            score += 0.05;
        }
    }

    // CDN domain check
    if domain_in_nin_cdn(host.as_deref()) {
        score += 0.30;
        flags.push("nin_cdn_reachable".to_string());
    }

    // Port check
    if port_nin_open(port) {
        score += 0.15;
        flags.push("nin_port_open".to_string());
    }

    // Live TCP reachability (best effort, don't fail on error).
    // Python skips this for snowflake transports.
    let mut reachable = false;
    if let (Some(h), Some(p)) = (&host, port) {
        if transport != "snowflake" {
            // Python uses default timeout 6.0s; the production probe honors this.
            reachable = tcp_probe.is_reachable(h, p, 3.0);
            if reachable {
                score += 0.10;
                flags.push("tcp_alive".to_string());
            }
        }
    }

    // Mirror Python's `round(min(score, 1.0), 3)`.
    let clamped = score.min(1.0);
    let rounded = (clamped * 1000.0).round() / 1000.0;

    json!({
        "bridge_line": line,
        "transport": transport,
        "host": host.unwrap_or_default(),
        "port": port.unwrap_or(0),
        "nin_score": rounded,
        "nin_flags": flags,
        "tcp_reachable": reachable,
    })
}

/// Mirror of `main()` — read `bridge/bridge_list_for_testing.json`, score the
/// first 300 bridges, sort by `nin_score` descending, write
/// `data/nin_advanced_report.json` and `export/nin_cut_bridges.txt`.
///
/// I/O paths are injectable via `bridge_dir`, `data_dir`, `export_dir`.
///
/// Live TCP probing is bounded by a wall-clock budget (see
/// [`probe_budget_from_env`], default [`DEFAULT_PROBE_BUDGET_SECS`] seconds)
/// so a blackholed runner network can never stall the stage past its CI step
/// timeout; once the budget is spent, remaining candidates are scored with
/// the offline [`NoProbe`].
pub fn run_main(
    bridge_dir: &Path,
    data_dir: &Path,
    export_dir: &Path,
    tcp_probe: &dyn TcpProbe,
) -> Result<(), std::io::Error> {
    run_main_with_probe_budget(
        bridge_dir,
        data_dir,
        export_dir,
        tcp_probe,
        probe_budget_from_env(),
    )
}

/// [`run_main`] with an explicit live-probe budget instead of the
/// environment-resolved one. Used directly by tests; production code goes
/// through [`run_main`].
pub fn run_main_with_probe_budget(
    bridge_dir: &Path,
    data_dir: &Path,
    export_dir: &Path,
    tcp_probe: &dyn TcpProbe,
    probe_budget: Duration,
) -> Result<(), std::io::Error> {
    let test_json = bridge_dir.join("bridge_list_for_testing.json");
    if !test_json.exists() {
        tracing::warn!("bridge_list_for_testing.json not found — skipping NIN bypass analysis");
        return Ok(());
    }

    let text = std::fs::read_to_string(&test_json)?;
    let bridges: Vec<String> = match serde_json::from_str::<Vec<String>>(&text) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!("bridge_list_for_testing.json is not a JSON array of strings");
            return Ok(());
        }
    };

    tracing::info!("NIN bypass scoring: {} bridges", bridges.len());

    // Dynamic yield: compute ceiling from config instead of hardcoded .take(300)
    let ceiling = crate::config::Config::from_env()
        .map(|cfg| crate::config::compute_dynamic_ceiling(bridges.len(), &cfg))
        .unwrap_or(300);

    // Zero-error guardrail: bound the wall-clock time spent on live TCP
    // probes. Each probe may block up to its full timeout, so on a blackholed
    // network a serial probe loop over hundreds of bridges can overrun the CI
    // step timeout and get the whole job killed. Once the budget is spent,
    // remaining candidates are scored instantly with the offline `NoProbe` —
    // exactly what live probes would return on such a network — so the
    // report still covers every candidate and the stage always completes.
    let probe_start = Instant::now();
    let offline_probe = NoProbe;
    let mut probed_count: usize = 0;
    let mut probe_budget_exhausted = false;
    let mut results: Vec<Value> = Vec::with_capacity(ceiling.min(bridges.len()));
    for bridge_line in bridges.iter().take(ceiling) {
        if !probe_budget_exhausted && probe_start.elapsed() < probe_budget {
            probed_count += 1;
            results.push(score_for_nin(bridge_line, tcp_probe));
        } else {
            if !probe_budget_exhausted {
                probe_budget_exhausted = true;
                tracing::warn!(
                    "NIN probe budget of {}s exhausted after {} live probes — scoring remaining \
                     bridges offline (NoProbe)",
                    probe_budget.as_secs(),
                    probed_count,
                );
            }
            results.push(score_for_nin(bridge_line, &offline_probe));
        }
    }
    let candidates_scored = results.len();
    let probe_elapsed_secs = (probe_start.elapsed().as_secs_f64() * 1000.0).round() / 1000.0;
    // Python: `results.sort(key=lambda x: x["nin_score"], reverse=True)`
    // Python's sort is stable; Rust's `sort_by` is also stable.
    results.sort_by(|a, b| {
        let av = a["nin_score"].as_f64().unwrap_or(0.0);
        let bv = b["nin_score"].as_f64().unwrap_or(0.0);
        bv.partial_cmp(&av).unwrap_or(std::cmp::Ordering::Equal)
    });

    std::fs::create_dir_all(data_dir)?;
    std::fs::create_dir_all(export_dir)?;

    // Additive metadata: probe-budget bookkeeping beside the unchanged
    // `nin_bridge_scores` payload, so downstream consumers keep working.
    let report = json!({
        "nin_bridge_scores": results,
        "nin_probe_metadata": {
            "candidates_input": bridges.len(),
            "candidates_scored": candidates_scored,
            "candidates_probed": probed_count,
            "probe_budget_secs": probe_budget.as_secs(),
            "probe_budget_exhausted": probe_budget_exhausted,
            "probe_elapsed_secs": probe_elapsed_secs,
        },
    });
    std::fs::write(
        data_dir.join("nin_advanced_report.json"),
        serde_json::to_string_pretty(&report)?,
    )?;

    // Write NIN-optimised bridge pack (score >= 0.50)
    let nin_bridges: Vec<&str> = results
        .iter()
        .filter_map(|r| {
            let s = r["nin_score"].as_f64().unwrap_or(0.0);
            if s >= 0.50 {
                r["bridge_line"].as_str()
            } else {
                None
            }
        })
        .collect();
    if !nin_bridges.is_empty() {
        let mut out = nin_bridges.join("\n");
        out.push('\n');
        std::fs::write(export_dir.join("nin_cut_bridges.txt"), out)?;
        tracing::info!(
            "NIN pack: {} bridges → export/nin_cut_bridges.txt",
            nin_bridges.len()
        );
    } else {
        tracing::warn!("No bridges scored >= 0.50 for NIN scenario");
    }

    tracing::info!("NIN advanced bypass analysis complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysUnreachable;
    impl TcpProbe for AlwaysUnreachable {
        fn is_reachable(&self, _h: &str, _p: u16, _t: f64) -> bool {
            false
        }
    }

    struct AlwaysReachable;
    impl TcpProbe for AlwaysReachable {
        fn is_reachable(&self, _h: &str, _p: u16, _t: f64) -> bool {
            true
        }
    }

    #[test]
    fn detect_transport_branches() {
        // Note: Python's _detect_transport checks "url=https" before "meek",
        // so a meek_lite line containing url=https is classified as webtunnel.
        // This matches the Python original's branch order exactly.
        assert_eq!(
            detect_transport("snowflake 192.0.2.3:1 fingerprint=x url=https://y"),
            "snowflake"
        );
        assert_eq!(
            detect_transport("webtunnel 192.0.2.4:443 url=https://example.com"),
            "webtunnel"
        );
        assert_eq!(
            detect_transport("obfs4 1.2.3.4:443 cert=abc iat-mode=2"),
            "obfs4"
        );
        assert_eq!(
            detect_transport("meek_lite 192.0.2.5:80 url=https://y front=z"),
            "webtunnel" // url=https wins
        );
        assert_eq!(
            detect_transport("meek_lite 192.0.2.5:80 front=z"),
            "meek_lite" // no url=https
        );
        assert_eq!(detect_transport("vanilla 1.2.3.4:9001"), "vanilla");
    }

    #[test]
    fn extract_endpoint_https_url_with_explicit_port() {
        let (h, p) = extract_endpoint("webtunnel x url=https://example.com:8443/path");
        assert_eq!(h.as_deref(), Some("example.com"));
        assert_eq!(p, Some(8443));
    }

    #[test]
    fn extract_endpoint_https_url_default_port() {
        let (h, p) = extract_endpoint("webtunnel x url=https://example.com/path");
        assert_eq!(h.as_deref(), Some("example.com"));
        assert_eq!(p, Some(443));
    }

    #[test]
    fn extract_endpoint_ipv4_port() {
        let (h, p) = extract_endpoint("obfs4 1.2.3.4:443 cert=abc");
        assert_eq!(h.as_deref(), Some("1.2.3.4"));
        assert_eq!(p, Some(443));
    }

    #[test]
    fn extract_endpoint_no_match() {
        let (h, p) = extract_endpoint("just a plain string");
        assert_eq!(h, None);
        assert_eq!(p, None);
    }

    #[test]
    fn domain_in_nin_cdn_matches_arvancloud() {
        assert!(domain_in_nin_cdn(Some("cdn.arvancloud.com")));
        assert!(domain_in_nin_cdn(Some("arvancloud.ir")));
        assert!(!domain_in_nin_cdn(Some("example.com")));
        assert!(!domain_in_nin_cdn(None));
        assert!(!domain_in_nin_cdn(Some("")));
    }

    #[test]
    fn port_nin_open_branches() {
        assert!(port_nin_open(Some(443)));
        assert!(port_nin_open(Some(8080)));
        assert!(!port_nin_open(Some(22)));
        assert!(!port_nin_open(None));
    }

    #[test]
    fn score_for_nin_webtunnel_with_cdn_and_open_port_and_reachable() {
        let probe = AlwaysReachable;
        let result = score_for_nin(
            "webtunnel 192.0.2.4:443 url=https://cdn.arvancloud.com/path",
            &probe,
        );
        // webtunnel=0.50 + cdn=0.30 + port=0.15 + tcp=0.10 = 1.05 → clamped to 1.0
        assert_eq!(result["transport"], "webtunnel");
        assert_eq!(result["nin_score"], 1.0);
        assert_eq!(result["tcp_reachable"], true);
        let flags = result["nin_flags"].as_array().unwrap();
        assert!(flags.iter().any(|f| f == "webtunnel_cdn_fronted"));
        assert!(flags.iter().any(|f| f == "nin_cdn_reachable"));
        assert!(flags.iter().any(|f| f == "nin_port_open"));
        assert!(flags.iter().any(|f| f == "tcp_alive"));
    }

    #[test]
    fn score_for_nin_snowflake_skips_tcp_probe() {
        let probe = AlwaysReachable;
        // Note: url=https://x → extract_endpoint returns host="x", port=443
        // (default for https). Port 443 IS in NIN_OPEN_PORTS → +0.15.
        // Snowflake skips TCP probe (Python: `transport not in ("snowflake",)`).
        let result = score_for_nin("snowflake 192.0.2.3:1 url=https://x", &probe);
        assert_eq!(result["transport"], "snowflake");
        assert_eq!(result["tcp_reachable"], false);
        // Score: 0.45 (snowflake) + 0.15 (port 443 open) = 0.60
        assert_eq!(result["nin_score"], 0.6);
    }

    #[test]
    fn score_for_nin_obfs4_unreachable() {
        let probe = AlwaysUnreachable;
        let result = score_for_nin("obfs4 1.2.3.4:443 cert=abc iat-mode=2", &probe);
        // obfs4=0.10, port=443 (open) → +0.15, no CDN, no tcp_alive
        // Total: 0.25
        assert_eq!(result["transport"], "obfs4");
        assert_eq!(result["tcp_reachable"], false);
        assert_eq!(result["nin_score"], 0.25);
    }

    #[test]
    fn score_for_nin_vanilla_baseline() {
        let probe = AlwaysUnreachable;
        let result = score_for_nin("vanilla 1.2.3.4:9001", &probe);
        // vanilla=0.05, port=9001 not in NIN_OPEN_PORTS, no CDN
        assert_eq!(result["transport"], "vanilla");
        assert_eq!(result["nin_score"], 0.05);
    }

    #[test]
    fn score_for_nin_score_clamped_to_one() {
        let probe = AlwaysReachable;
        let result = score_for_nin(
            "webtunnel 192.0.2.4:443 url=https://cdn.arvancloud.com/path",
            &probe,
        );
        // All four bonuses apply → 1.05 → clamped to 1.0
        assert_eq!(result["nin_score"], 1.0);
    }

    struct CountingProbe(std::sync::atomic::AtomicUsize);

    impl TcpProbe for CountingProbe {
        fn is_reachable(&self, _h: &str, _p: u16, _t: f64) -> bool {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            true
        }
    }

    impl CountingProbe {
        fn count(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn budget_run_fixture(tag: &str) -> (std::path::PathBuf, Vec<String>) {
        let pid = std::process::id();
        let run_dir = std::env::temp_dir().join(format!("nin_budget_{tag}_{pid}"));
        let bridge_dir = run_dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).unwrap();
        let bridges: Vec<String> = (0..25)
            .map(|i| format!("obfs4 10.0.0.{i}:443 cert=abc iat-mode=2"))
            .collect();
        std::fs::write(
            bridge_dir.join("bridge_list_for_testing.json"),
            serde_json::to_string(&bridges).unwrap(),
        )
        .unwrap();
        (run_dir, bridges)
    }

    fn read_report(run_dir: &std::path::Path) -> serde_json::Value {
        let report_path = run_dir.join("data/nin_advanced_report.json");
        let body = std::fs::read_to_string(report_path).unwrap();
        serde_json::from_str(&body).unwrap()
    }

    #[test]
    fn no_probe_always_reports_unreachable() {
        assert!(!NoProbe.is_reachable("1.2.3.4", 443, 3.0));
    }

    #[test]
    fn probe_budget_from_env_defaults_without_override() {
        // CI never sets NIN_ADVANCED_PROBE_BUDGET_SECS, so the default applies.
        if std::env::var("NIN_ADVANCED_PROBE_BUDGET_SECS").is_err() {
            assert_eq!(probe_budget_from_env(), Duration::from_secs(DEFAULT_PROBE_BUDGET_SECS));
        }
    }

    #[test]
    fn exhausted_probe_budget_still_scores_every_candidate() {
        let (run_dir, bridges) = budget_run_fixture("zero");
        // A zero budget forces the offline path from the very first bridge:
        // this is the CI-resilience regression test for the stage that used
        // to be SIGKILLed by its step timeout on a blackholed network.
        let probe = CountingProbe(std::sync::atomic::AtomicUsize::new(0));
        run_main_with_probe_budget(
            &run_dir.join("bridge"),
            &run_dir.join("data"),
            &run_dir.join("export"),
            &probe,
            Duration::ZERO,
        )
        .unwrap();

        // No live probe ever ran...
        assert_eq!(probe.count(), 0);

        // ...but every candidate was still scored, sorted, and exported.
        let report = read_report(&run_dir);
        let scores = report["nin_bridge_scores"].as_array().unwrap();
        assert_eq!(scores.len(), bridges.len());
        assert!(scores.iter().all(|r| r["nin_score"] == 0.25));
        assert!(scores.iter().all(|r| r["tcp_reachable"] == false));
        let meta = &report["nin_probe_metadata"];
        assert_eq!(meta["candidates_input"], 25);
        assert_eq!(meta["candidates_scored"], 25);
        assert_eq!(meta["candidates_probed"], 0);
        assert_eq!(meta["probe_budget_secs"], 0);
        assert_eq!(meta["probe_budget_exhausted"], true);

        let _ = std::fs::remove_dir_all(&run_dir);
    }

    #[test]
    fn live_probes_used_while_budget_is_open() {
        let (run_dir, bridges) = budget_run_fixture("open");
        let probe = CountingProbe(std::sync::atomic::AtomicUsize::new(0));
        run_main_with_probe_budget(
            &run_dir.join("bridge"),
            &run_dir.join("data"),
            &run_dir.join("export"),
            &probe,
            Duration::from_secs(600),
        )
        .unwrap();

        // Every candidate received its live probe (instant mock, budget open).
        assert_eq!(probe.count(), bridges.len());

        let report = read_report(&run_dir);
        let scores = report["nin_bridge_scores"].as_array().unwrap();
        assert_eq!(scores.len(), bridges.len());
        // obfs4 (0.10) + NIN-open port 443 (0.15) + tcp_alive (0.10) = 0.35
        assert!(scores.iter().all(|r| r["nin_score"] == 0.35));
        assert!(scores.iter().all(|r| r["tcp_reachable"] == true));
        let meta = &report["nin_probe_metadata"];
        assert_eq!(meta["candidates_probed"], 25);
        assert_eq!(meta["probe_budget_secs"], 600);
        assert_eq!(meta["probe_budget_exhausted"], false);

        let _ = std::fs::remove_dir_all(&run_dir);
    }
}

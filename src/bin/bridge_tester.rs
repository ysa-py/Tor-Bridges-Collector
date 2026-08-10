//! Bounded Rust-native bridge reachability tester.
//!
//! The test deliberately records exactly what a GitHub runner can establish:
//! a TCP connection (or a transport-capability check for Snowflake / WebTunnel).
//! It does not claim that a result proves Iranian reachability, a full Tor
//! circuit, or successful pluggable-transport negotiation.  Those distinctions
//! remain in the JSON report consumed by the publication layer.
//!
//! WebTunnel bridges that carry only a `url=https://front/path` (no routable
//! IP endpoint) are probed via TLS+WebSocket Upgrade to the front domain.
//! IPv6 bridges with documentation-range addresses (2001:db8::/32) are
//! actively rejected before any TCP attempt — the guard in `probe_one()`
//! uses `contains_documentation_or_reserved_endpoint()` which covers RFC 3849
//! (2001:db8::/32), RFC 5737 (TEST-NET), link-local, loopback, and multicast.

use std::collections::BTreeMap;
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use base64::Engine;
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use rand::RngCore;
use regex::Regex;
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use tokio_rustls::TlsConnector;
use torshield_ir_ultra::scraper::contains_documentation_or_reserved_endpoint;
use torshield_ir_ultra::tester::extract_endpoint;

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[derive(Debug)]
struct Options {
    input: PathBuf,
    output: PathBuf,
    workers: usize,
    timeout: Duration,
    max_bridges: usize,
}

fn usage() -> &'static str {
    "Usage: bridge_tester [OPTIONS]\n\
     \n\
     Options:\n\
       --input PATH        JSON bridge list (default: bridge/bridge_list_for_testing.json)\n\
       --output PATH       JSON report (default: bridge/iran_results.json)\n\
       --workers N         Bounded concurrent TCP probes (default: 48)\n\
       --timeout-seconds N Per-probe TCP timeout (default: 5)\n\
       --max-bridges N     Hard safety limit (default: 2500)\n\
       --help              Print this help"
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| invalid(format!("{flag} requires a value")))
}

fn parse_positive<T>(value: String, flag: &str) -> Result<T, Box<dyn std::error::Error>>
where
    T: std::str::FromStr + PartialOrd + From<u8>,
{
    let parsed = value
        .parse::<T>()
        .map_err(|_| invalid(format!("{flag} must be a positive integer")))?;
    if parsed <= T::from(0) {
        return Err(invalid(format!("{flag} must be positive")));
    }
    Ok(parsed)
}

fn parse_args() -> Result<Options, Box<dyn std::error::Error>> {
    let mut options = Options {
        input: PathBuf::from("bridge/bridge_list_for_testing.json"),
        output: PathBuf::from("bridge/iran_results.json"),
        workers: 48,
        timeout: Duration::from_secs(5),
        max_bridges: 2500,
    };
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--input" => options.input = PathBuf::from(next_value(&mut args, "--input")?),
            "--output" => options.output = PathBuf::from(next_value(&mut args, "--output")?),
            "--workers" => {
                options.workers = parse_positive(next_value(&mut args, "--workers")?, "--workers")?
            }
            "--timeout-seconds" => {
                let seconds: u64 = parse_positive(
                    next_value(&mut args, "--timeout-seconds")?,
                    "--timeout-seconds",
                )?;
                options.timeout = Duration::from_secs(seconds);
            }
            "--max-bridges" => {
                options.max_bridges =
                    parse_positive(next_value(&mut args, "--max-bridges")?, "--max-bridges")?
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            unknown => return Err(invalid(format!("unknown argument: {unknown}\n{}", usage()))),
        }
    }
    Ok(options)
}

fn normalise_transport(line: &str, extracted: &str) -> String {
    let first = line
        .trim()
        .strip_prefix("Bridge ")
        .unwrap_or(line.trim())
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match first.as_str() {
        "obfs4" | "webtunnel" | "vanilla" | "snowflake" | "meek_lite" | "conjure"
        | "meek-azure" => first,
        "meek-lite" => "meek_lite".to_string(),
        _ => extracted.to_string(),
    }
}

fn snowflake_capability_result(line: String) -> Value {
    json!({
        "line": line,
        "transport": "snowflake",
        "host": null,
        "port": null,
        "tcp_reachable": false,
        "transport_capable": true,
        "probe_status": "transport_capability",
        "probe_method": "snowflake-webRTC-capability",
        "latency_ms": null,
        "iran_status": "iran_unknown",
        "evidence_scope": "Transport capability only; no TCP socket or Iran-vantage assertion was made.",
        "composite_score": 0.55,
    })
}

// ── TLS / WebSocket Upgrade probe (all targets except ARM-musl CI-only type-check) ──

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
mod tls_probe {
    use super::*;

    /// A certificate verifier for reachability probes. It deliberately permits
    /// self-signed bridge/cdn-front certificates because the collector validates
    /// liveness/protocol behavior, not a public-Web PKI identity.
    #[derive(Debug)]
    struct ReachabilityVerifier;

    impl rustls::client::danger::ServerCertVerifier for ReachabilityVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    fn make_tls_config() -> Arc<rustls::ClientConfig> {
        let provider = rustls::crypto::ring::default_provider();
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("TLS protocol versions");
        let mut config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ReachabilityVerifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Probe a WebTunnel bridge by performing TLS + HTTP WebSocket Upgrade to
    /// the front domain extracted from the `url=` parameter. Returns
    /// `transport_capable: true` when the front responds with HTTP 101.
    pub async fn probe_webtunnel_front(line: String, timeout_duration: Duration) -> Value {
        let https_re = Regex::new(r"(?i)https?://([^/:\s]+)(?::(\d+))?").unwrap();
        let (host, port) = match https_re.captures(&line) {
            Some(caps) => {
                let h = caps.get(1).unwrap().as_str().to_string();
                let p = caps
                    .get(2)
                    .and_then(|m| m.as_str().parse::<u16>().ok())
                    .unwrap_or(443);
                (h, p)
            }
            None => {
                return json!({
                    "line": line,
                    "transport": "webtunnel",
                    "host": null,
                    "port": null,
                    "tcp_reachable": false,
                    "transport_capable": false,
                    "probe_status": "unparseable",
                    "probe_method": "websocket-upgrade",
                    "latency_ms": null,
                    "iran_status": "iran_unknown",
                    "evidence_scope": "WebTunnel line has no url= front domain; cannot probe.",
                    "composite_score": 0.0,
                });
            }
        };

        let started = Instant::now();

        // 1. TCP connect to front domain
        let tcp = match timeout(timeout_duration, TcpStream::connect((host.as_str(), port))).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => {
                return json!({
                    "line": line,
                    "transport": "webtunnel",
                    "host": host,
                    "port": port,
                    "tcp_reachable": false,
                    "transport_capable": false,
                    "probe_status": "refused",
                    "probe_method": "websocket-upgrade",
                    "latency_ms": started.elapsed().as_millis(),
                    "iran_status": "tcp_unreachable",
                    "evidence_scope": "TCP connect to WebTunnel front domain failed (refused).",
                    "composite_score": 0.0,
                });
            }
            Err(_) => {
                return json!({
                    "line": line,
                    "transport": "webtunnel",
                    "host": host,
                    "port": port,
                    "tcp_reachable": false,
                    "transport_capable": false,
                    "probe_status": "timeout",
                    "probe_method": "websocket-upgrade",
                    "latency_ms": started.elapsed().as_millis(),
                    "iran_status": "tcp_unreachable",
                    "evidence_scope": "TCP connect to WebTunnel front domain timed out.",
                    "composite_score": 0.0,
                });
            }
        };

        // 2. TLS handshake
        let server_name = match ServerName::try_from(host.clone()) {
            Ok(sn) => sn,
            Err(_) => {
                return json!({
                    "line": line,
                    "transport": "webtunnel",
                    "host": host,
                    "port": port,
                    "tcp_reachable": true,
                    "transport_capable": false,
                    "probe_status": "tls_invalid_name",
                    "probe_method": "websocket-upgrade",
                    "latency_ms": started.elapsed().as_millis(),
                    "iran_status": "iran_unknown",
                    "evidence_scope": "WebTunnel front domain is not a valid TLS server name.",
                    "composite_score": 0.3,
                });
            }
        };

        let config = make_tls_config();
        let connector = TlsConnector::from(config);
        let mut stream = match timeout(timeout_duration, connector.connect(server_name, tcp)).await
        {
            Ok(Ok(s)) => s,
            _ => {
                return json!({
                    "line": line,
                    "transport": "webtunnel",
                    "host": host,
                    "port": port,
                    "tcp_reachable": true,
                    "transport_capable": false,
                    "probe_status": "tls_handshake_failed",
                    "probe_method": "websocket-upgrade",
                    "latency_ms": started.elapsed().as_millis(),
                    "iran_status": "iran_unknown",
                    "evidence_scope": "TLS handshake to WebTunnel front domain failed.",
                    "composite_score": 0.3,
                });
            }
        };

        // 3. WebSocket Upgrade
        let mut key_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        if (timeout(timeout_duration, stream.write_all(request.as_bytes())).await).is_err() {
            return json!({
                "line": line,
                "transport": "webtunnel",
                "host": host,
                "port": port,
                "tcp_reachable": true,
                "transport_capable": false,
                "probe_status": "tls_reachable",
                "probe_method": "websocket-upgrade",
                "latency_ms": started.elapsed().as_millis(),
                "iran_status": "iran_unknown",
                "evidence_scope": "TLS to WebTunnel front succeeded but upgrade request write failed.",
                "composite_score": 0.4,
            });
        }

        let mut response = vec![0u8; 512];
        let n = match timeout(timeout_duration, stream.read(&mut response)).await {
            Ok(Ok(n)) => n,
            _ => {
                return json!({
                    "line": line,
                    "transport": "webtunnel",
                    "host": host,
                    "port": port,
                    "tcp_reachable": true,
                    "transport_capable": false,
                    "probe_status": "tls_reachable",
                    "probe_method": "websocket-upgrade",
                    "latency_ms": started.elapsed().as_millis(),
                    "iran_status": "iran_unknown",
                    "evidence_scope": "TLS to WebTunnel front succeeded but no HTTP response received.",
                    "composite_score": 0.4,
                });
            }
        };

        let response_text = String::from_utf8_lossy(&response[..n]);
        let has_101 = response_text.contains("101");
        let elapsed = started.elapsed().as_millis();

        json!({
            "line": line,
            "transport": "webtunnel",
            "host": host,
            "port": port,
            "tcp_reachable": true,
            "transport_capable": has_101,
            "probe_status": if has_101 { "websocket_101" } else { "http_response" },
            "probe_method": "websocket-upgrade",
            "latency_ms": elapsed,
            "iran_status": "iran_unknown",
            "evidence_scope": format!(
                "TLS+WebSocket Upgrade probe to WebTunnel front domain. {}",
                if has_101 {
                    "Front returned 101 Switching Protocols — WebTunnel handshake succeeded."
                } else {
                    "Front responded but did not return 101. CDN front is alive but bridge may be offline."
                }
            ),
            "composite_score": if has_101 { 0.7 } else { 0.45 },
        })
    }
} // mod tls_probe

// Re-export TLS probe for non-ARM targets; ARM-musl gets a no-TLS stub below.
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use tls_probe::probe_webtunnel_front;

#[cfg(all(target_arch = "arm", target_env = "musl"))]
async fn probe_webtunnel_front(line: String, _timeout_duration: Duration) -> Value {
    // ARMv7-musl is a CI-only type-check target (no C toolchain, no ring).
    // WebTunnel probes require TLS, so this stub returns an advisory result
    // without performing actual network operations.
    let https_re = Regex::new(r"(?i)https?://([^/:]+)(?::(\d+))?").unwrap();
    let (host, port) = https_re
        .captures(&line)
        .map(|caps| {
            (
                caps.get(1).unwrap().as_str().to_string(),
                caps.get(2)
                    .and_then(|m| m.as_str().parse::<u16>().ok())
                    .unwrap_or(443),
            )
        })
        .unwrap_or_default();
    json!({
        "line": line,
        "transport": "webtunnel",
        "host": if host.is_empty() { None } else { Some(&host) },
        "port": if host.is_empty() { None } else { Some(port) },
        "tcp_reachable": false,
        "transport_capable": false,
        "probe_status": "unsupported_target",
        "probe_method": "websocket-upgrade",
        "latency_ms": null,
        "iran_status": "iran_unknown",
        "evidence_scope": "ARMv7-musl is a CI-only type-check target — WebTunnel TLS probe not available on this platform.",
        "composite_score": 0.0,
    })
}

async fn probe_one(line: String, timeout_duration: Duration) -> Value {
    // Reject documentation-range/reserved IP addresses BEFORE any TCP attempt.
    // This covers RFC 3849 (2001:db8::/32), RFC 5737 (TEST-NET), RFC 1918,
    // link-local, loopback, and multicast — none are ever routable.
    if contains_documentation_or_reserved_endpoint(&line) {
        let transport = normalise_transport(&line, extract_endpoint(&line).2);
        return json!({
            "line": line,
            "transport": transport,
            "host": null,
            "port": null,
            "tcp_reachable": false,
            "transport_capable": false,
            "probe_status": "non_routable_endpoint",
            "probe_method": "none",
            "latency_ms": null,
            "iran_status": "non_routable",
            "evidence_scope": "Bridge line contains a documentation-range or reserved IP address that is never routable from any vantage point.",
            "composite_score": 0.0,
        });
    }

    let (host, port, extracted_transport) = extract_endpoint(&line);
    let transport = normalise_transport(&line, extracted_transport);
    if transport == "snowflake" {
        return snowflake_capability_result(line);
    }
    // v2.6.1: Domain-only WebTunnel bridges (no routable IP, only url=)
    // are probed via TLS+WebSocket Upgrade to the front domain.
    if transport == "webtunnel" {
        return probe_webtunnel_front(line, timeout_duration).await;
    }
    let Some(host) = host else {
        return json!({
            "line": line,
            "transport": transport,
            "host": null,
            "port": null,
            "tcp_reachable": false,
            "transport_capable": false,
            "probe_status": "unparseable",
            "probe_method": "none",
            "latency_ms": null,
            "iran_status": "iran_unknown",
            "evidence_scope": "No endpoint could be parsed; no reachability claim was made.",
            "composite_score": 0.0,
        });
    };
    let Some(port) = port else {
        return json!({
            "line": line,
            "transport": transport,
            "host": host,
            "port": null,
            "tcp_reachable": false,
            "transport_capable": false,
            "probe_status": "unparseable",
            "probe_method": "none",
            "latency_ms": null,
            "iran_status": "iran_unknown",
            "evidence_scope": "No endpoint could be parsed; no reachability claim was made.",
            "composite_score": 0.0,
        });
    };

    let started = Instant::now();
    let connection = timeout(timeout_duration, TcpStream::connect((host.as_str(), port))).await;
    let (tcp_reachable, probe_status) = match connection {
        Ok(Ok(_stream)) => (true, "reachable"),
        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => (false, "refused"),
        Ok(Err(_)) => (false, "error"),
        Err(_) => (false, "timeout"),
    };
    let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let composite_score = if tcp_reachable { 0.6 } else { 0.0 };
    json!({
        "line": line,
        "transport": transport,
        "host": host,
        "port": port,
        "tcp_reachable": tcp_reachable,
        "transport_capable": false,
        "probe_status": probe_status,
        "probe_method": "tcp-connect",
        "latency_ms": latency,
        "iran_status": if tcp_reachable { "iran_unknown" } else { "tcp_unreachable" },
        "evidence_scope": "TCP connect from the CI runner only; this is not an Iran-vantage or full Tor-circuit test.",
        "composite_score": composite_score,
    })
}

fn read_lines(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let body = std::fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&body)?;
    let entries = value
        .as_array()
        .ok_or_else(|| invalid("bridge test input must be a JSON array of bridge strings"))?;
    Ok(entries
        .iter()
        .filter_map(Value::as_str)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid(format!("output has no valid file name: {}", path.display())))?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let mut body = serde_json::to_string_pretty(value)?;
    body.push('\n');
    std::fs::write(&temporary, body)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

async fn run(options: &Options) -> Result<Value, Box<dyn std::error::Error>> {
    let lines = read_lines(&options.input)?;
    if lines.len() > options.max_bridges {
        return Err(invalid(format!(
            "refusing to probe {} bridges; --max-bridges is {}",
            lines.len(),
            options.max_bridges
        )));
    }
    let started = chrono::Utc::now();
    let semaphore = Arc::new(Semaphore::new(options.workers));
    let mut tasks = JoinSet::new();
    for line in lines {
        let semaphore = Arc::clone(&semaphore);
        let timeout_duration = options.timeout;
        tasks.spawn(async move {
            let permit = semaphore
                .acquire_owned()
                .await
                .expect("probe semaphore is open");
            let result = probe_one(line, timeout_duration).await;
            drop(permit);
            result
        });
    }

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.map_err(|error| invalid(format!("probe task failed: {error}")))?);
    }
    results.sort_by(|left, right| {
        left.get("line")
            .and_then(Value::as_str)
            .cmp(&right.get("line").and_then(Value::as_str))
    });

    let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut transport_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut reachable = 0_usize;
    let mut capable = 0_usize;
    for result in &results {
        if result.get("tcp_reachable").and_then(Value::as_bool) == Some(true) {
            reachable += 1;
        }
        if result.get("transport_capable").and_then(Value::as_bool) == Some(true) {
            capable += 1;
        }
        if let Some(status) = result.get("probe_status").and_then(Value::as_str) {
            *status_counts.entry(status.to_string()).or_default() += 1;
        }
        if let Some(transport) = result.get("transport").and_then(Value::as_str) {
            *transport_counts.entry(transport.to_string()).or_default() += 1;
        }
    }
    Ok(json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "started_at": started.to_rfc3339(),
        "engine": "torshield-rust-bridge-tester-v1",
        "evidence_scope": "Bounded TCP reachability observations from the executing runner. No Iran-vantage, OONI, ASN, PT-handshake, or full Tor-circuit guarantee is implied.",
        "summary": {
            "total_tested": results.len(),
            "runner_tcp_reachable": reachable,
            "transport_capability_checks": capable,
            "probe_statuses": status_counts,
            "transports": transport_counts,
        },
        "bridges": results,
    }))
}

#[tokio::main]
async fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("bridge_tester: {error}");
        std::process::exit(2);
    });
    match run(&options).await {
        Ok(report) => {
            if let Err(error) = write_json(&options.output, &report) {
                eprintln!(
                    "bridge_tester: failed to write {}: {error}",
                    options.output.display()
                );
                std::process::exit(1);
            }
            let summary = &report["summary"];
            println!(
                "bridge_tester: tested={} runner_tcp_reachable={} capability_checks={} -> {}",
                summary["total_tested"],
                summary["runner_tcp_reachable"],
                summary["transport_capability_checks"],
                options.output.display()
            );
        }
        Err(error) => {
            eprintln!("bridge_tester: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snowflake_is_explicitly_capability_checked_not_falsely_tcp_tested() {
        let result = snowflake_capability_result("snowflake example".to_string());
        assert_eq!(result["tcp_reachable"], false);
        assert_eq!(result["transport_capable"], true);
        assert_eq!(result["iran_status"], "iran_unknown");
    }

    #[test]
    fn explicit_meek_transport_is_not_reclassified_by_its_https_url() {
        assert_eq!(
            normalise_transport(
                "meek_lite 192.0.2.1:80 url=https://cdn.example",
                "webtunnel"
            ),
            "meek_lite"
        );
    }
}

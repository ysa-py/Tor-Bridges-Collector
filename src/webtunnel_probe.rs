//! TLS+WebSocket Upgrade probe for domain-fronted WebTunnel bridges.
//!
//! Domain-fronted WebTunnel bridges have no routable IP — only a `url=`
//! front domain. Raw TCP is the wrong probe. This module performs TLS
//! connect + HTTP WebSocket Upgrade request and checks for HTTP 101
//! Switching Protocols.
//!
//! Probe is gated behind `#[cfg]` for the ARMv7-musl CI-only target
//! (which excludes ring/rustls).

use std::collections::HashSet;
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Value};

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use std::io::{Read, Write};
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use std::thread::sleep;

/// Maximum retry attempts for domain-fronted WebTunnel probes.
const MAX_PROBE_RETRIES: u32 = 3;
/// Base backoff between retries (milliseconds), doubled each attempt.
const RETRY_BASE_MS: u64 = 500;

/// Check whether an IPv6 address string is in the RFC 3849 documentation
/// prefix `2001:db8::/32`. BridgeDB intentionally substitutes these for
/// webtunnel IPv6 entries as an anti-enumeration measure.
pub fn is_documentation_ipv6(addr: &str) -> bool {
    let lower = addr.to_lowercase();
    // Strip brackets if present
    let stripped = lower.strip_prefix('[').unwrap_or(&lower);
    let stripped = stripped.strip_suffix(']').unwrap_or(stripped);
    stripped.starts_with("2001:db8:") || stripped == "2001:db8"
}

/// Extract the front domain host and port from a WebTunnel bridge line.
/// Returns None if the line doesn't contain a url= parameter.
fn extract_front_domain(line: &str) -> Option<(String, u16)> {
    let re = Regex::new(r"(?i)https?://([^/:\s]+)(?::(\d+))?").unwrap();
    re.captures(line).map(|caps| {
        let host = caps.get(1).unwrap().as_str().to_string();
        let port = caps
            .get(2)
            .and_then(|m| m.as_str().parse::<u16>().ok())
            .unwrap_or(443);
        (host, port)
    })
}

/// Strip any existing IP:PORT or [IPv6]:PORT endpoint from the beginning
/// of a webtunnel bridge body (the part after "webtunnel ").
/// Returns the remainder after the fingerprint/url/ver fields.
///
/// Examples:
///   "FINGERPRINT url=... ver=..." → "FINGERPRINT url=... ver=..." (no IP:PORT)
///   "1.2.3.4:443 FINGERPRINT url=..." → "FINGERPRINT url=..." (strips IPv4:port)
///   "[2001:db8::1]:443 FINGERPRINT url=..." → "FINGERPRINT url=..." (strips [IPv6]:port)
fn strip_existing_ip_port(body: &str) -> &str {
    // IPv6 bracket form: [addr]:port ...
    if body.starts_with('[') {
        if let Some(after_bracket) = body.strip_prefix('[') {
            if let Some((_ipv6_part, rest)) = after_bracket.split_once("]:") {
                // Skip past the port number too
                if let Some(after_port) = rest.find(' ') {
                    return rest[after_port..].trim_start();
                }
                return "";
            }
        }
        return body;
    }
    // IPv4 form: addr:port ...
    // Check if the first token looks like IP:PORT (contains a colon and
    // the part before it parses as IPv4)
    if let Some((host, rest)) = body.split_once(':') {
        if let Some((_port_str, after_port)) = rest.split_once(' ') {
            if host.parse::<std::net::Ipv4Addr>().is_ok() {
                return after_port.trim_start();
            }
        } else if host.parse::<std::net::Ipv4Addr>().is_ok() {
            // Body is just "IPv4:PORT" with nothing after — return empty
            return "";
        }
    }
    body
}

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use std::sync::Arc;

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
mod tls_ws {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::ClientConnection;

    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

    fn tls_config() -> Arc<rustls::ClientConfig> {
        let provider = rustls::crypto::ring::default_provider();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .expect("TLS versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        )
    }

    /// Synchronous TLS+WebSocket Upgrade probe for a single WebTunnel
    /// front domain. Returns (raw HTTP status line, resolved IP) on success,
    /// or an error string describing the failure mode.
    pub fn probe_sync(
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<(String, String), String> {
        // 1. DNS + TCP connect
        let addr = format!("{host}:{port}");
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolve {host}: {e}"))?
            .next()
            .ok_or_else(|| format!("DNS returned no addresses for {host}"))?;
        let resolved_ip = socket_addr.ip().to_string();
        let mut tcp = TcpStream::connect_timeout(&socket_addr, timeout)
            .map_err(|e| format!("TCP connect failed: {e}"))?;
        tcp.set_read_timeout(Some(timeout))
            .map_err(|e| format!("set read timeout: {e}"))?;
        tcp.set_write_timeout(Some(timeout))
            .map_err(|e| format!("set write timeout: {e}"))?;

        // 2. TLS handshake
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|e| format!("invalid SNI: {e}"))?;
        let config = tls_config();
        let mut conn = ClientConnection::new(config, server_name)
            .map_err(|e| format!("TLS client config: {e}"))?;

        // Stream::new takes ownership of conn and tcp; handshake is
        // triggered on first read/write through the stream.
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);

        // 3. WebSocket Upgrade request
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("WS upgrade write: {e}"))?;
        stream.flush().map_err(|e| format!("flush: {e}"))?;

        // 4. Read response
        let mut buf = [0u8; 512];
        let n = stream
            .read(&mut buf)
            .map_err(|e| format!("read response: {e}"))?;
        let response = String::from_utf8_lossy(&buf[..n]).to_string();
        Ok((response, resolved_ip))
    }
}

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
pub(crate) use tls_ws::probe_sync;

#[cfg(all(target_arch = "arm", target_env = "musl"))]
fn probe_sync(_host: &str, _port: u16, _timeout: Duration) -> Result<(String, String), String> {
    // ARMv7-musl CI-only type-check target — no ring/rustls available
    Err("unsupported_target: ARMv7-musl CI-only".to_string())
}

/// Probe a single WebTunnel bridge line and return an updated bridge record
/// with evidence from the WebSocket Upgrade probe. Retries with exponential
/// backoff on transient failures (connection refused, timeout, DNS).
pub fn probe_webtunnel_bridge(bridge: &Value, timeout: Duration) -> Value {
    let line = bridge.get("line").and_then(Value::as_str).unwrap_or("");

    let (host, port) = match extract_front_domain(line) {
        Some(hp) => hp,
        None => {
            // No front domain found — keep original status
            return bridge.clone();
        }
    };

    // Retry with exponential backoff for transient failures
    let mut last_result: Option<Result<(String, String), String>> = None;
    for attempt in 0..MAX_PROBE_RETRIES {
        if attempt > 0 {
            let delay_ms = RETRY_BASE_MS * (1u64 << (attempt - 1));
            eprintln!(
                "webtunnel-probe: {host}:{port} retry {attempt}/{max} after {delay_ms}ms",
                max = MAX_PROBE_RETRIES - 1
            );
            #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
            sleep(Duration::from_millis(delay_ms));
            #[cfg(all(target_arch = "arm", target_env = "musl"))]
            drop(delay_ms); // no-op on ARM musl (no std::thread::sleep in CI stub)
        }

        let result = probe_sync(&host, port, timeout);
        match &result {
            Ok(_) => {
                last_result = Some(result);
                break; // success — don't retry
            }
            Err(error) => {
                let is_transient = error.contains("timed out")
                    || error.contains("Connection refused")
                    || error.contains("DNS resolve")
                    || error.contains("Temporary failure")
                    || error.contains("HandshakeFailure");
                if !is_transient || attempt + 1 >= MAX_PROBE_RETRIES {
                    last_result = Some(result);
                    break;
                }
                // Transient failure — will retry
                last_result = Some(result);
            }
        }
    }

    match last_result.unwrap_or(Err("probe did not execute".to_string())) {
        Ok((response, resolved_ip)) => {
            let has_101 = response.contains("101");
            let mut result = bridge.clone();
            if let Some(obj) = result.as_object_mut() {
                obj.insert("iran_status".to_string(), json!("iran_unknown"));
                obj.insert("tcp_reachable".to_string(), json!(true));
                obj.insert("transport_capable".to_string(), json!(has_101));
                obj.insert(
                    "probe_status".to_string(),
                    json!(if has_101 {
                        "websocket_101"
                    } else {
                        "http_response"
                    }),
                );
                obj.insert("probe_method".to_string(), json!("websocket-upgrade"));
                obj.insert(
                    "evidence_scope".to_string(),
                    json!(format!(
                        "TLS+WebSocket Upgrade probe to webtunnel front domain {}:{}. {}",
                        &host,
                        port,
                        if has_101 {
                            "Front returned 101 Switching Protocols."
                        } else {
                            "Front responded but no 101 — CDN alive, bridge may be offline."
                        }
                    )),
                );
                obj.insert(
                    "composite_score".to_string(),
                    json!(if has_101 { 0.7 } else { 0.45 }),
                );
                // Rebuild the bridge line to include the resolved IP:PORT.
                // Domain-fronted webtunnel bridges from upstream lack the
                // mandatory <IP>:<PORT> field that Tor Browser requires.
                // Format: webtunnel <IP>:<PORT> <FINGERPRINT> url=<URL> ver=<VERSION>
                //
                // Per Tor spec, IPv6 addresses MUST be bracketed:
                //   webtunnel [IPv6]:PORT ...
                // IPv4 addresses are bare:
                //   webtunnel IPv4:PORT ...
                if !line.is_empty() && !resolved_ip.is_empty() {
                    if let Some(rest) = line.strip_prefix("webtunnel ") {
                        // Strip any existing IP:PORT from the original line
                        // (URL-only bridges have none; IPv6 bridges may have one)
                        // so we don't duplicate the endpoint field.
                        let rest_no_endpoint = strip_existing_ip_port(rest.trim());
                        let ip_str: String = match resolved_ip.parse::<std::net::IpAddr>() {
                            Ok(std::net::IpAddr::V6(_)) => {
                                format!("[{}]:{}", resolved_ip, port)
                            }
                            _ => {
                                format!("{}:{}", resolved_ip, port)
                            }
                        };
                        let new_line = format!("webtunnel {} {}", ip_str, rest_no_endpoint);
                        obj.insert("line".to_string(), json!(new_line));
                    }
                }
            }
            result
        }
        Err(error) => {
            // Probe failed — leave status as-is but record the attempt
            let mut result = bridge.clone();
            if let Some(obj) = result.as_object_mut() {
                obj.insert("probe_status".to_string(), json!("websocket_failed"));
                obj.insert("probe_method".to_string(), json!("websocket-upgrade"));
                obj.insert(
                    "evidence_scope".to_string(),
                    json!(format!(
                        "WebSocket probe to webtunnel front {}:{} failed: {}",
                        &host, port, &error
                    )),
                );
            }
            result
        }
    }
}

/// Decision reached for one candidate WebTunnel bridge record.
#[derive(Debug, PartialEq, Eq)]
enum ProbeDecision {
    /// Bridge carries a domain-front URL (or a literal FQDN host); probe it
    /// via TLS+WebSocket Upgrade at `(front_host, front_port)`.
    Probe(String, u16),
    /// Bridge carries an RFC 3849 `2001:db8::/32` placeholder endpoint.
    SkipDocIpv6,
    /// Bridge has only a literal IP endpoint and no front domain — TCP is
    /// the correct probe for it and the Go tester already ran that.
    SkipIpHost,
    /// Bridge has neither a url= front domain nor an FQDN host.
    SkipNoFront,
}

/// True if the line's first endpoint token (immediately after the
/// `webtunnel ` transport token) is a bracketed RFC 3849 documentation
/// IPv6 address. BridgeDB substitutes these placeholders into webtunnel
/// IPv6 lines as an anti-enumeration measure.
fn line_has_documentation_ipv6(line: &str) -> bool {
    let body = line.strip_prefix("webtunnel").unwrap_or(line).trim_start();
    let Some(after_bracket) = body.strip_prefix('[') else {
        return false;
    };
    after_bracket
        .split_once(']')
        .map(|(addr, _)| is_documentation_ipv6(addr))
        .unwrap_or(false)
}

/// Pure gating logic for a single WebTunnel bridge record.
///
/// Domain-fronted WebTunnel bridges carry their reachable CDN endpoint
/// inside `url=`; the Go iran_tester leaves the `host` field empty for
/// these URL-only lines. The probe target therefore must be derived from
/// the bridge line's url= parameter, falling back to the literal `host`
/// field only when it is itself a domain name (e.g. an FQDN:PORT endpoint).
/// True when the line carries a literal endpoint token directly after the
/// `webtunnel ` transport token — either a bracketed `[IPv6]:PORT` form or a
/// bare `IPv4:PORT` form. Such a line has a directly dialable address and is
/// covered by the ordinary raw-TCP tester even if the tester's parsed
/// `host` field was left empty; it is not a URL-only domain-front bridge.
fn line_has_literal_ip_endpoint(line: &str) -> bool {
    let body = line.strip_prefix("webtunnel").unwrap_or(line).trim_start();
    if let Some(after_bracket) = body.strip_prefix('[') {
        // [addr]:port form — take the address before the closing bracket.
        if let Some((addr, _rest)) = after_bracket.split_once(']') {
            return addr.parse::<std::net::IpAddr>().is_ok();
        }
        return false;
    }
    // Bare form: the first token must be IPv4:PORT (an FQDN:PORT first token
    // is itself a frontable host and handled separately).
    let first = body.split_whitespace().next().unwrap_or("");
    if let Some((addr, _port)) = first.split_once(':') {
        return addr.parse::<std::net::Ipv4Addr>().is_ok();
    }
    false
}

fn front_probe_decision(host: &str, line: &str) -> ProbeDecision {
    if is_documentation_ipv6(host) || line_has_documentation_ipv6(line) {
        return ProbeDecision::SkipDocIpv6;
    }
    if let Some((front_host, front_port)) = extract_front_domain(line) {
        // A url= host that is itself a literal IP is a directly dialable
        // endpoint: TCP/TLS to it is not domain-fronting and is covered by
        // the ordinary TCP tester.
        return if front_host.parse::<std::net::IpAddr>().is_ok() {
            ProbeDecision::SkipIpHost
        } else {
            ProbeDecision::Probe(front_host, front_port)
        };
    }
    if !host.is_empty() {
        return if host.parse::<std::net::IpAddr>().is_err() {
            ProbeDecision::Probe(host.to_string(), 443)
        } else {
            ProbeDecision::SkipIpHost
        };
    }
    // The tester left `host` empty and there is no url= front domain. A
    // literal IP:PORT token in the line is still covered by the raw-TCP
    // tester; only a truly endpoint-less fingerprint line has nothing for
    // the domain-front probe to dial.
    if line_has_literal_ip_endpoint(line) {
        return ProbeDecision::SkipIpHost;
    }
    ProbeDecision::SkipNoFront
}

/// Probe all domain-fronted WebTunnel bridges in the results, updating
/// their statuses in-place. Returns (probed, succeeded, failed) counts.
///
/// Also reports front-domain diversity and reasons for skipped bridges
/// (documentation-prefix IPv6, non-domain host, etc.).
pub fn probe_all_webtunnel_bridges(
    bridges: &mut [Value],
    timeout: Duration,
) -> (usize, usize, usize) {
    let mut probed = 0;
    let mut succeeded = 0;
    let mut failed = 0;
    let mut doc_ipv6_skipped = 0u32;
    let mut ip_host_skipped = 0u32;
    let mut already_working_skipped = 0u32;
    let mut front_domains: HashSet<String> = HashSet::new();

    for bridge in bridges.iter_mut() {
        let transport = bridge
            .get("transport")
            .and_then(Value::as_str)
            .unwrap_or("");
        if transport != "webtunnel" {
            continue;
        }
        let status = bridge
            .get("iran_status")
            .and_then(Value::as_str)
            .unwrap_or("");
        // Probe bridges marked unreachable AND bridges not yet probed (iran_unknown)
        let needs_probe =
            status == "tcp_unreachable" || status.is_empty() || status == "iran_unknown";
        if !needs_probe {
            already_working_skipped += 1;
            continue;
        }
        let host = bridge.get("host").and_then(Value::as_str).unwrap_or("");
        let line = bridge.get("line").and_then(Value::as_str).unwrap_or("");

        let (front_host, front_port) = match front_probe_decision(host, line) {
            ProbeDecision::Probe(front_host, front_port) => (front_host, front_port),
            ProbeDecision::SkipDocIpv6 => {
                doc_ipv6_skipped += 1;
                let label = if host.is_empty() { line } else { host };
                eprintln!(
                    "webtunnel-probe: skipping documentation-prefix IPv6 bridge ({label}) — \
                     this is an intentional BridgeDB anti-enumeration placeholder, not a \
                     real bridge address"
                );
                continue;
            }
            ProbeDecision::SkipIpHost => {
                ip_host_skipped += 1;
                eprintln!(
                    "webtunnel-probe: skipping IP-endpoint bridge (host={host}, \
                     line={line}) — it is covered by the raw TCP tester; webtunnel \
                     front-domain probing requires a domain in url="
                );
                continue;
            }
            ProbeDecision::SkipNoFront => {
                eprintln!(
                    "webtunnel-probe: skipping bridge with no front domain (no url= \
                     parameter): {line}"
                );
                continue;
            }
        };

        front_domains.insert(front_host.clone());

        probed += 1;
        let updated = probe_webtunnel_bridge(bridge, timeout);
        let probe_status = updated
            .get("probe_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let evidence = updated
            .get("evidence_scope")
            .and_then(Value::as_str)
            .unwrap_or("");
        if updated.get("iran_status").and_then(Value::as_str) == Some("iran_unknown") {
            succeeded += 1;
            println!("webtunnel-probe: {front_host}:{front_port} => {probe_status} 101");
        } else {
            failed += 1;
            println!("webtunnel-probe: {front_host}:{front_port} => {probe_status}: {evidence}");
        }
        *bridge = updated;
    }

    // Emit diversity summary
    println!(
        "webtunnel-probe: summary probed={probed} ws_101={succeeded} ws_fail={failed} \
         doc_ipv6_skipped={doc_ipv6_skipped} ip_host_skipped={ip_host_skipped} \
         already_working_skipped={already_working_skipped} \
         unique_front_domains={front_domains}",
        front_domains = front_domains.len(),
    );

    (probed, succeeded, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_from_webtunnel_line() {
        let line = "webtunnel ABC123 url=https://example.com/path ver=0.0.3";
        let (host, port) = extract_front_domain(line).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn extract_domain_with_custom_port() {
        let line = "webtunnel DEF456 url=https://example.com:8443/path";
        let (host, port) = extract_front_domain(line).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn strip_ipv4_endpoint_from_body() {
        let body = "1.2.3.4:443 FINGERPRINT url=https://x ver=0.0.4";
        let result = strip_existing_ip_port(body);
        assert_eq!(result, "FINGERPRINT url=https://x ver=0.0.4");
    }

    #[test]
    fn strip_ipv6_endpoint_from_body() {
        let body = "[2001:db8::1]:443 FINGERPRINT url=https://x ver=0.0.3";
        let result = strip_existing_ip_port(body);
        assert_eq!(result, "FINGERPRINT url=https://x ver=0.0.3");
    }

    #[test]
    fn strip_no_endpoint_from_body() {
        let body = "FINGERPRINT url=https://x ver=0.0.4";
        let result = strip_existing_ip_port(body);
        // No IP:PORT to strip — body returned as-is
        assert_eq!(result, "FINGERPRINT url=https://x ver=0.0.4");
    }

    #[test]
    fn strip_ipv4_no_fingerprint_returns_empty() {
        // If body starts with IP:PORT but has nothing after, returns empty
        let body = "1.2.3.4:443";
        let result = strip_existing_ip_port(body);
        assert!(result.is_empty());
    }

    #[test]
    fn probe_skips_non_webtunnel() {
        let bridges = vec![
            json!({"transport": "obfs4", "iran_status": "tcp_unreachable", "host": "1.2.3.4", "line": "obfs4 1.2.3.4:443"}),
        ];
        let mut bridges = bridges;
        let (p, s, f) = probe_all_webtunnel_bridges(&mut bridges, Duration::from_secs(2));
        assert_eq!(p, 0);
        assert_eq!(s, 0);
        assert_eq!(f, 0);
    }

    #[test]
    fn is_doc_prefix_detects_2001_db8() {
        assert!(is_documentation_ipv6("2001:db8::1"));
        assert!(is_documentation_ipv6("2001:DB8:1234::1"));
        assert!(is_documentation_ipv6("[2001:db8::1]"));
        assert!(is_documentation_ipv6("2001:db8"));
        assert!(!is_documentation_ipv6("2001:4860:4860::8888"));
        assert!(!is_documentation_ipv6("2a00:1450::1"));
        assert!(!is_documentation_ipv6(""));
        assert!(!is_documentation_ipv6("example.com"));
    }

    #[test]
    fn probe_skips_doc_ipv6_host() {
        // Bridges with documentation-range IPv6 hosts are skipped
        let bridges = vec![
            json!({"transport": "webtunnel", "iran_status": "tcp_unreachable", "host": "2001:db8::1", "line": "webtunnel [2001:db8::1]:443 FINGERPRINT url=https://example.com/x ver=0.0.3"}),
        ];
        let mut bridges = bridges;
        let (p, _s, _f) = probe_all_webtunnel_bridges(&mut bridges, Duration::from_secs(2));
        assert_eq!(p, 0, "doc-prefix IPv6 bridge should be skipped");
    }

    // ── PART B: Edge-case regression tests for WebTunnel probe ──────────

    #[test]
    fn edge_case_no_url_returns_none() {
        // A webtunnel line without url= has no front domain to probe
        let line = "webtunnel 1.2.3.4:443 FINGERPRINT ver=0.0.4";
        assert!(extract_front_domain(line).is_none());
    }

    #[test]
    fn edge_case_malformed_url_returns_none() {
        // A url= with no real URL structure should not be extracted
        let line = "webtunnel FINGERPRINT url=not-a-url ver=0.0.3";
        assert!(extract_front_domain(line).is_none());
    }

    #[test]
    fn edge_case_url_with_ip_instead_of_domain() {
        // url=https://1.2.3.4:8443/path — should still extract
        let line = "webtunnel FINGERPRINT url=https://1.2.3.4:8443/path ver=0.0.3";
        let (host, port) = extract_front_domain(line).unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 8443);
    }

    #[test]
    fn edge_case_url_with_no_path() {
        let line = "webtunnel FINGERPRINT url=https://example.com ver=0.0.4";
        let (host, port) = extract_front_domain(line).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn edge_case_strip_existing_ipv6_with_no_fingerprint() {
        // IPv6 endpoint with nothing after, returns empty
        let body = "[2001:db8::1]:443";
        let result = strip_existing_ip_port(body);
        assert!(result.is_empty());
    }

    #[test]
    fn edge_case_strip_existing_ipv6_keeps_passthrough() {
        // When body starts with [ but doesn't match the pattern, pass through
        let body = "[not-an-ipv6";
        let result = strip_existing_ip_port(body);
        assert_eq!(result, "[not-an-ipv6");
    }

    #[test]
    fn edge_case_decision_skips_literal_ip_endpoint() {
        // A webtunnel bridge with a literal IP endpoint (no url= front) is
        // covered by the ordinary TCP tester and is skipped by the
        // domain-front probe.
        let decision =
            front_probe_decision("1.2.3.4", "webtunnel 1.2.3.4:443 FINGERPRINT ver=0.0.4");
        assert_eq!(decision, ProbeDecision::SkipIpHost);
        // url= pointing at an IP rather than a front domain is also not
        // domain-fronting.
        let decision = front_probe_decision(
            "",
            "webtunnel FINGERPRINT url=https://1.2.3.4:8443/path ver=0.0.3",
        );
        assert_eq!(decision, ProbeDecision::SkipIpHost);
    }

    #[test]
    fn edge_case_decision_probes_url_only_webtunnel() {
        // URL-only WebTunnel lines (the form published by BridgeDB with
        // domain fronting) carry the reachable endpoint in url=; the Go
        // tester leaves `host` empty. These MUST be probed against the url=
        // front domain — this is the regression that previously produced
        // empty webtunnel*_tested.txt and iran_likely_working_webtunnel.txt.
        let decision = front_probe_decision(
            "",
            "webtunnel 68674E54A17AEB1C9ADE878BBBB46C6975DD3105 url=https://vika7.space/83c1327ea78e32b5d151e872ca123f7858aec2e1 ver=0.0.4",
        );
        match decision {
            ProbeDecision::Probe(host, port) => {
                assert_eq!(host, "vika7.space");
                assert_eq!(port, 443);
            }
            other => panic!("expected Probe(vika7.space, 443), got {other:?}"),
        }

        // Custom port in the front URL is preserved.
        let decision = front_probe_decision(
            "",
            "webtunnel FINGERPRINT url=https://front.example.com:8443/p ver=0.0.3",
        );
        assert_eq!(
            decision,
            ProbeDecision::Probe("front.example.com".to_string(), 8443)
        );
    }

    #[test]
    fn edge_case_decision_falls_back_to_fqdn_host() {
        // No url= but a literal FQDN host field: probe that domain.
        let decision = front_probe_decision(
            "cdn.example.com",
            "webtunnel cdn.example.com:443 FINGERPRINT ver=0.0.3",
        );
        assert_eq!(
            decision,
            ProbeDecision::Probe("cdn.example.com".to_string(), 443)
        );
    }

    #[test]
    fn edge_case_decision_skips_when_no_front_and_no_host() {
        // No url= front domain and empty host: nothing to probe.
        let decision = front_probe_decision("", "webtunnel 1.2.3.4:443 FINGERPRINT ver=0.0.4");
        assert_eq!(decision, ProbeDecision::SkipIpHost);

        // A bare fingerprint-only line without url= and no host is skipped.
        let decision = front_probe_decision("", "webtunnel FINGERPRINT ver=0.0.3");
        assert_eq!(decision, ProbeDecision::SkipNoFront);
    }

    #[test]
    fn edge_case_decision_skips_doc_ipv6_in_line() {
        // BridgeDB placeholder endpoint in the line (host field empty) is
        // detected from the bracketed token, not just the host field.
        let decision = front_probe_decision(
            "",
            "webtunnel [2001:db8:1218:1de7:3a91:22cc:8d7f:197c]:443 FINGERPRINT url=https://coellen.xyz ver=0.0.3",
        );
        assert_eq!(decision, ProbeDecision::SkipDocIpv6);
    }

    #[test]
    fn edge_case_decision_detects_doc_ipv6_in_host_field() {
        let decision = front_probe_decision(
            "2001:db8::1",
            "webtunnel FINGERPRINT url=https://example.com/x ver=0.0.3",
        );
        assert_eq!(decision, ProbeDecision::SkipDocIpv6);
    }
}

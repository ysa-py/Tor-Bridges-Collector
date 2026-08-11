//! TLS+WebSocket Upgrade probe for domain-fronted WebTunnel bridges.
//!
//! Domain-fronted WebTunnel bridges have no routable IP — only a `url=`
//! front domain. Raw TCP is the wrong probe. This module performs TLS
//! connect + HTTP WebSocket Upgrade request and checks for HTTP 101
//! Switching Protocols.
//!
//! Probe is gated behind `#[cfg]` for the ARMv7-musl CI-only target
//! (which excludes ring/rustls).

use std::time::Duration;

use regex::Regex;
use serde_json::{json, Value};

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use std::io::{Read, Write};
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use std::net::{TcpStream, ToSocketAddrs};

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
use tls_ws::probe_sync;

#[cfg(all(target_arch = "arm", target_env = "musl"))]
fn probe_sync(_host: &str, _port: u16, _timeout: Duration) -> Result<(String, String), String> {
    // ARMv7-musl CI-only type-check target — no ring/rustls available
    Err("unsupported_target: ARMv7-musl CI-only".to_string())
}

/// Probe a single WebTunnel bridge line and return an updated bridge record
/// with evidence from the WebSocket Upgrade probe.
pub fn probe_webtunnel_bridge(bridge: &Value, timeout: Duration) -> Value {
    let line = bridge.get("line").and_then(Value::as_str).unwrap_or("");

    let (host, port) = match extract_front_domain(line) {
        Some(hp) => hp,
        None => {
            // No front domain found — keep original status
            return bridge.clone();
        }
    };

    match probe_sync(&host, port, timeout) {
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
                if !line.is_empty() && !resolved_ip.is_empty() {
                    if let Some(rest) = line.strip_prefix("webtunnel ") {
                        let new_line =
                            format!("webtunnel {}:{} {}", resolved_ip, port, rest.trim());
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

/// Probe all domain-fronted WebTunnel bridges in the results, updating
/// their statuses in-place. Returns (probed, succeeded, failed) counts.
pub fn probe_all_webtunnel_bridges(
    bridges: &mut [Value],
    timeout: Duration,
) -> (usize, usize, usize) {
    let mut probed = 0;
    let mut succeeded = 0;
    let mut failed = 0;

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
        // Only probe bridges that the Go tester marked unreachable
        if status != "tcp_unreachable" {
            continue;
        }
        let host = bridge.get("host").and_then(Value::as_str).unwrap_or("");
        // Only probe domain-fronted bridges (host is a domain, not an IP)
        if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }

        let line = bridge.get("line").and_then(Value::as_str).unwrap_or("");
        let (front_host, front_port) =
            extract_front_domain(line).unwrap_or((host.to_string(), 443));

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
    fn probe_skips_already_working() {
        let bridges = vec![
            json!({"transport": "webtunnel", "iran_status": "iran_unknown", "host": "example.com", "line": "webtunnel ... url=https://example.com/x"}),
        ];
        let mut bridges = bridges;
        let (p, s, f) = probe_all_webtunnel_bridges(&mut bridges, Duration::from_secs(2));
        assert_eq!(p, 0);
        assert_eq!(s, 0);
        assert_eq!(f, 0);
    }
}

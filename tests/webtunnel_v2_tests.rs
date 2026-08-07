//! Hermetic (offline) integration tests for WebTunnel v0.0.4.
//!
//! These tests validate:
//! - IPv4 and [IPv6] WebTunnel bridge-line serialization/deserialization
//! - Canonical fingerprint accept/reject gates (40-char SHA-1, 64-char SHA-256)
//! - ver=0.0.4 enforcement
//! - Mock HTTP upgrade (101 Switching Protocols) validation
//!
//! All tests are self-contained and run without external network connectivity.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use torshield_ir_ultra::tor_collector::parsing;
use torshield_ir_ultra::webtunnel_v2;

/// Start a mock HTTP server that responds with 101 Switching Protocols.
/// Returns the bound port.
fn start_mock_websocket_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_mock_upgrade(stream);
        }
    });

    // Give the thread a moment to start
    thread::sleep(Duration::from_millis(50));
    port
}

fn handle_mock_upgrade(mut stream: TcpStream) {
    let mut buf = [0u8; 4096];
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.read(&mut buf);

    let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                     \r\n";
    let _ = stream.write_all(response);
}

#[test]
fn webtunnel_v2_parses_ipv4_line() {
    let info = webtunnel_v2::parse_line(
        "webtunnel 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
         url=https://cdn.cloudflare.com/ws/tunnel ver=0.0.4",
    )
    .expect("valid IPv4 webtunnel line should parse");

    assert_eq!(info.host, "192.0.2.1");
    assert_eq!(info.port, 443);
    assert_eq!(info.family, "ipv4");
    assert_eq!(info.version, "0.0.4");
    assert!(info.url.is_some());
}

#[test]
fn webtunnel_v2_parses_ipv6_line() {
    let info = webtunnel_v2::parse_line(
        "webtunnel [2001:db8::1]:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
         url=https://cdn.cloudflare.com/ws/tunnel ver=0.0.4",
    )
    .expect("valid IPv6 webtunnel line should parse");

    assert_eq!(info.host, "2001:db8::1");
    assert_eq!(info.port, 443);
    assert_eq!(info.family, "ipv6");
    assert_eq!(info.version, "0.0.4");
}

#[test]
fn webtunnel_v2_serialization_roundtrips() {
    let line = "webtunnel 192.0.2.1:443 \
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
                url=https://example.com/path ver=0.0.4";
    let info = webtunnel_v2::parse_line(line).expect("parse");
    let json = webtunnel_v2::as_json(&info);

    assert_eq!(json["host"], "192.0.2.1");
    assert_eq!(json["port"], 443);
    assert_eq!(json["family"], "ipv4");
    assert_eq!(json["version"], "0.0.4");

    // Re-parse from JSON
    let json_str = serde_json::to_string(&json).unwrap();
    let parsed_back: serde_json::Value =
        serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed_back["host"], "192.0.2.1");
}

#[test]
fn canonical_fingerprint_accepts_40_char_sha1() {
    assert!(parsing::is_canonical_fingerprint(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ));
    assert!(parsing::is_canonical_fingerprint(
        "abcdefABCDEF1234567890abcdefABCDEF12345678"
    ));
}

#[test]
fn canonical_fingerprint_accepts_64_char_sha256() {
    assert!(parsing::is_canonical_fingerprint(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ));
    assert!(parsing::is_canonical_fingerprint(
        "abcdefABCDEF1234567890abcdefABCDEF12345678abcdefABCDEF1234567890abcd"
    ));
}

#[test]
fn canonical_fingerprint_rejects_short_strings() {
    assert!(!parsing::is_canonical_fingerprint("short"));
    assert!(!parsing::is_canonical_fingerprint(""));
    assert!(!parsing::is_canonical_fingerprint("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"));
}

#[test]
fn canonical_fingerprint_rejects_wrong_lengths() {
    assert!(!parsing::is_canonical_fingerprint("abc123")); // 6 chars
    assert!(!parsing::is_canonical_fingerprint(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 41 chars
    ));
    assert!(!parsing::is_canonical_fingerprint(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 63 chars
    ));
}

#[test]
fn is_valid_bridge_line_requires_ver_0_0_4_for_webtunnel() {
    // ver=0.0.4 — should pass
    assert!(parsing::is_valid_bridge_line(
        "webtunnel 192.0.2.1:443 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
         url=https://example.com ver=0.0.4"
    ));

    // ver=0.0.3 — should fail
    assert!(!parsing::is_valid_bridge_line(
        "webtunnel 192.0.2.1:443 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
         url=https://example.com ver=0.0.3"
    ));

    // no ver= — should fail
    assert!(!parsing::is_valid_bridge_line(
        "webtunnel 192.0.2.1:443 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
         url=https://example.com"
    ));
}

#[test]
fn is_valid_bridge_line_rejects_url_only_webtunnel() {
    // No literal IP endpoint, only URL — should fail
    assert!(!parsing::is_valid_bridge_line(
        "webtunnel FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF url=https://example.com"
    ));
}

#[test]
fn is_valid_bridge_line_accepts_ipv6_webtunnel() {
    assert!(parsing::is_valid_bridge_line(
        "webtunnel [2001:db8::1]:443 \
         FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
         url=https://example.com ver=0.0.4"
    ));
}

#[test]
fn is_valid_bridge_line_rejects_non_hex_fingerprint() {
    // Contains 'G' which is not a hex character
    assert!(!parsing::is_valid_bridge_line(
        "webtunnel 192.0.2.1:443 GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG \
         url=https://example.com ver=0.0.4"
    ));
}

#[test]
fn is_valid_bridge_line_rejects_reserved_ips() {
    assert!(!parsing::is_valid_bridge_line(
        "webtunnel 127.0.0.1:443 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
         url=https://example.com ver=0.0.4"
    ));
    assert!(!parsing::is_valid_bridge_line(
        "webtunnel 192.168.1.1:443 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
         url=https://example.com ver=0.0.4"
    ));
}

#[test]
fn extract_endpoint_ipv4_vs_ipv6() {
    // IPv4
    let ep = parsing::extract_endpoint("webtunnel 1.2.3.4:443 url=https://x ver=0.0.4").unwrap();
    assert_eq!(ep.host, "1.2.3.4");
    assert_eq!(ep.port, 443);
    assert_eq!(ep.address_family, "ipv4");

    // IPv6
    let ep = parsing::extract_endpoint(
        "webtunnel [2001:db8::7]:443 FINGER url=https://x ver=0.0.4",
    )
    .unwrap();
    assert_eq!(ep.host, "2001:db8::7");
    assert_eq!(ep.port, 443);
}

#[test]
fn mock_websocket_upgrade_responds_101() {
    let port = start_mock_websocket_server();

    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to mock");

    let request = b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    stream.write_all(request).expect("write request");

    let mut response = [0u8; 1024];
    let n = stream.read(&mut response).expect("read response");
    let response_str = String::from_utf8_lossy(&response[..n]);

    assert!(
        response_str.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {response_str}"
    );
    assert!(response_str.contains("Upgrade: websocket"));
}

#[test]
fn webtunnel_v2_empty_line_returns_none() {
    assert!(webtunnel_v2::parse_line("").is_none());
    assert!(webtunnel_v2::parse_line("   ").is_none());
}

#[test]
fn webtunnel_v2_non_webtunnel_line_returns_none() {
    assert!(webtunnel_v2::parse_line("obfs4 1.2.3.4:443 cert=abc").is_none());
}

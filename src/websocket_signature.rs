//! Strict WebSocket opening-handshake validation shared by the Rust probes.
//!
//! A literal `101` substring is not evidence of a WebSocket handshake. The
//! response must have an HTTP/1.1 101 status, `Upgrade: websocket`, a
//! `Connection` token containing `upgrade`, and the exact RFC 6455
//! `Sec-WebSocket-Accept` for the request key.

use base64::Engine;
use sha1::{Digest, Sha1};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the RFC 6455 `Sec-WebSocket-Accept` value for a request key.
#[must_use]
pub fn expected_accept(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest.finalize())
}

/// True only for a complete, valid WebSocket upgrade response to `key`.
#[must_use]
pub fn has_valid_upgrade_signature(response: &str, key: &str) -> bool {
    let Some(head_end) = response.find("\r\n\r\n") else {
        return false;
    };
    let head = &response[..head_end];
    let mut lines = head.split("\r\n");
    let Some(status_line) = lines.next() else {
        return false;
    };
    let mut status_parts = status_line.split_ascii_whitespace();
    if status_parts.next() != Some("HTTP/1.1") || status_parts.next() != Some("101") {
        return false;
    }

    let mut upgrades = Vec::new();
    let mut connections = Vec::new();
    let mut accepts = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.trim().eq_ignore_ascii_case("upgrade") {
            upgrades.push(value);
        } else if name.trim().eq_ignore_ascii_case("connection") {
            connections.push(value);
        } else if name.trim().eq_ignore_ascii_case("sec-websocket-accept") {
            accepts.push(value);
        }
    }

    // Reject duplicate security-sensitive headers rather than relying on
    // parser-specific first/last-header behavior.
    upgrades.len() == 1
        && connections.len() == 1
        && accepts.len() == 1
        && upgrades[0].eq_ignore_ascii_case("websocket")
        && connections[0]
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        && accepts[0] == expected_accept(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    #[test]
    fn matches_the_rfc6455_accept_vector() {
        assert_eq!(expected_accept(SAMPLE_KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: keep-alive, Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            expected_accept(SAMPLE_KEY)
        );
        assert!(has_valid_upgrade_signature(&response, SAMPLE_KEY));
    }

    #[test]
    fn rejects_generic_101_invalid_accept_and_truncated_headers() {
        for response in [
            "HTTP/1.1 101 Switching Protocols\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
            "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            "prefix 101 is not a status line",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
        ] {
            assert!(
                !has_valid_upgrade_signature(response, SAMPLE_KEY),
                "invalid response accepted: {response:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_accept_headers() {
        let accept = expected_accept(SAMPLE_KEY);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        assert!(!has_valid_upgrade_signature(&response, SAMPLE_KEY));
    }

    #[test]
    fn rejects_http_1_0_and_duplicate_upgrade_headers() {
        let accept = expected_accept(SAMPLE_KEY);
        let http10 = format!(
            "HTTP/1.0 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        let duplicate_upgrade = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        assert!(!has_valid_upgrade_signature(&http10, SAMPLE_KEY));
        assert!(!has_valid_upgrade_signature(&duplicate_upgrade, SAMPLE_KEY));
    }
}

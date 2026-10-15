//! WebTunnel HTTP/WebSocket upgrade probe.
//!
//! A WebTunnel bridge is reached by an HTTP upgrade request served **over
//! TLS** on the `url=` front domain (the CDN routes by SNI, so the TLS
//! session must name the same host the request does). The engine establishes
//! that TLS session (`crate::tls`) before this probe runs. This probe drives
//! the `tbc-transports` WebTunnel codec over the socket: it sends the upgrade
//! request derived from the bridge's `url=` parameter, then verifies the
//! response against the CANONICAL WebTunnel contract — `101 Switching
//! Protocols` + `Upgrade: websocket` + `Connection: upgrade` — which is
//! exactly what the reference `transport/httpupgrade` implementation accepts
//! and emits. The reference server sends no `Sec-WebSocket-Accept` header
//! (it is not an RFC 6455 endpoint), so the accept echo is verified ONLY
//! when a server actually sends one: present-but-wrong rejects a forged
//! endpoint, absent stays compatible with every deployed bridge. A plain
//! TCP listener that answers `200` or a bare `101` without the upgrade
//! echo is rejected as not-a-WebTunnel-bridge.

use base64::Engine as _;
use rand::RngCore;
use tbc_core::BridgeLine;
use tbc_transports::bridge::webtunnel_request;
use tbc_transports::webtunnel::UpgradeResponse;

use crate::config::ProbeConfig;
use crate::error::ProbeError;
use crate::http;
use crate::socket::Socket;

/// The RFC 6455 §1.3 accept GUID.
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Maximum HTTP response bytes accepted for an upgrade exchange.
const MAX_RESPONSE: usize = 65_536;

/// Run the WebTunnel HTTP upgrade handshake against a socket.
pub async fn handshake(
    bridge: &BridgeLine,
    socket: &mut Socket,
    config: &ProbeConfig,
) -> Result<String, ProbeError> {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let request =
        webtunnel_request(bridge, nonce).map_err(|error| ProbeError::Codec(error.to_string()))?;
    let request_bytes = request
        .encode()
        .map_err(|error| ProbeError::Codec(error.to_string()))?;
    socket
        .write_all(&request_bytes, config.write_timeout)
        .await?;

    let response =
        http::read_http_response(socket, config.read_timeout, MAX_RESPONSE, "webtunnel").await?;
    let upgrade = UpgradeResponse::parse(&response.head)
        .map_err(|error| ProbeError::Codec(error.to_string()))?;

    if !upgrade.is_upgrade_accepted() {
        return Err(ProbeError::HttpStatus {
            transport: "webtunnel",
            code: upgrade.status_code,
        });
    }

    verify_upgrade_acceptance(&upgrade, &request.sec_websocket_key())
}

/// Verify an upgraded (`101`) response against the canonical WebTunnel
/// contract, with the optional RFC 6455 accept echo as the stronger check.
///
/// Evidence mapping (run 38613981417 root cause: every real bridge — 89
/// observations — failed here with `missing Sec-WebSocket-Accept header`
/// because the reference implementation never sends that header):
///
/// * `Sec-WebSocket-Accept` present and correct → verified (RFC 6455
///   server, strongest webtunnel evidence).
/// * present and wrong → `AuthFailed` (forged or misconfigured endpoint).
/// * absent + canonical `101`/`Upgrade: websocket`/`Connection: upgrade`
///   echo → verified (the reference contract every deployed bridge speaks).
/// * absent + missing/foreign upgrade headers → `AuthFailed` (a bare `101`
///   proves nothing about webtunnel).
fn verify_upgrade_acceptance(
    upgrade: &UpgradeResponse,
    request_key: &str,
) -> Result<String, ProbeError> {
    match upgrade.sec_websocket_accept() {
        Some(value) => {
            let expected = websocket_accept(request_key);
            if value == expected {
                Ok("webtunnel: 101 + Sec-WebSocket-Accept verified (RFC 6455)".to_owned())
            } else {
                Err(ProbeError::AuthFailed {
                    transport: "webtunnel",
                    message: "Sec-WebSocket-Accept mismatch".to_owned(),
                })
            }
        }
        None if upgrade.is_canonical_webtunnel_upgrade() => {
            Ok("webtunnel: 101 + Upgrade: websocket verified (canonical contract)".to_owned())
        }
        None => Err(ProbeError::AuthFailed {
            transport: "webtunnel",
            message: "101 response without the canonical WebSocket upgrade echo".to_owned(),
        }),
    }
}

/// Compute the RFC 6455 `Sec-WebSocket-Accept` value for a `Sec-WebSocket-Key`.
pub fn websocket_accept(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(WEBSOCKET_GUID);
    let digest = Sha1::digest(&input);
    base64::engine::general_purpose::STANDARD.encode(digest)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn websocket_accept_matches_rfc6455_test_vector() {
        // The canonical vector from RFC 6455 §1.3.
        let accept = websocket_accept("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    fn parsed_response(bytes: &[u8]) -> UpgradeResponse {
        UpgradeResponse::parse(bytes).unwrap()
    }

    #[test]
    fn canonical_server_without_accept_header_is_verified() {
        // The exact bytes the reference webtunnel httpupgrade server writes.
        let upgrade = parsed_response(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Connection: upgrade\r\n\
              Upgrade: websocket\r\n\
              \r\n",
        );
        let detail = verify_upgrade_acceptance(&upgrade, "dGhlIHNhbXBsZSBub25jZQ==").unwrap();
        assert!(
            detail.contains("canonical contract"),
            "the canonical path must name its contract: {detail}"
        );
    }

    #[test]
    fn rfc6455_server_with_correct_accept_is_verified() {
        let upgrade = parsed_response(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Connection: upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              \r\n",
        );
        let detail = verify_upgrade_acceptance(&upgrade, "dGhlIHNhbXBsZSBub25jZQ==").unwrap();
        assert!(detail.contains("RFC 6455"), "{detail}");
    }

    #[test]
    fn wrong_accept_header_is_an_auth_failure() {
        let upgrade = parsed_response(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Connection: upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Accept: forged\r\n\
              \r\n",
        );
        assert!(matches!(
            verify_upgrade_acceptance(&upgrade, "dGhlIHNhbXBsZSBub25jZQ=="),
            Err(ProbeError::AuthFailed {
                transport: "webtunnel",
                ..
            })
        ));
    }

    #[test]
    fn bare_101_without_upgrade_echo_is_an_auth_failure() {
        // A 101 with no Upgrade/Connection echo proves nothing about
        // webtunnel; it must never become a positive observation.
        let upgrade = parsed_response(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              X-Proxy: middlebox\r\n\
              \r\n",
        );
        assert!(matches!(
            verify_upgrade_acceptance(&upgrade, "dGhlIHNhbXBsZSBub25jZQ=="),
            Err(ProbeError::AuthFailed {
                transport: "webtunnel",
                ..
            })
        ));
    }
}

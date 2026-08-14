//! WebTunnel HTTP/WebSocket upgrade probe.
//!
//! A WebTunnel bridge is reached by an RFC 6455 §4.2.1 HTTP upgrade request.
//! This probe drives the `tbc-transports` WebTunnel codec over a socket: it
//! sends the upgrade request derived from the bridge's `url=` parameter, then
//! verifies both the `101 Switching Protocols` status and the
//! `Sec-WebSocket-Accept` header (SHA-1 of the client nonce plus the RFC
//! magic GUID). A plain TCP listener that answers `200` or a wrong accept
//! value is therefore rejected as not-a-WebTunnel-bridge.

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

    let expected = websocket_accept(&request.sec_websocket_key());
    match http::header_value(&upgrade.headers, "sec-websocket-accept") {
        Some(value) if value == expected => {
            Ok("webtunnel: 101 + Sec-WebSocket-Accept verified".to_owned())
        }
        Some(_) => Err(ProbeError::AuthFailed {
            transport: "webtunnel",
            message: "Sec-WebSocket-Accept mismatch".to_owned(),
        }),
        None => Err(ProbeError::AuthFailed {
            transport: "webtunnel",
            message: "missing Sec-WebSocket-Accept header".to_owned(),
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
}

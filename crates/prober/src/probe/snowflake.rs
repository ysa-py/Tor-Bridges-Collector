//! Snowflake broker rendezvous probe.
//!
//! Snowflake clients and proxies do not know each other's addresses; they
//! meet through a broker over HTTPS. This probe drives the `tbc-transports`
//! Snowflake codec over a socket by `POST`ing a broker poll message
//! (`/client` with `Sid`/`Version`) and validating the broker's status
//! response. It targets the *broker rendezvous endpoint* (the bridge's
//! `url=`), not the WebRTC data-channel peer, which is only reachable after a
//! match through the broker.

use rand::RngCore;
use tbc_core::BridgeLine;
use tbc_transports::snowflake::{ClientPollRequest, ClientPollResponse, PROTOCOL_VERSION};

use crate::config::ProbeConfig;
use crate::error::ProbeError;
use crate::http;
use crate::socket::Socket;

/// Maximum HTTP response bytes accepted for a broker exchange.
const MAX_RESPONSE: usize = 65_536;

/// Run the Snowflake broker poll against a socket.
pub async fn handshake(
    bridge: &BridgeLine,
    socket: &mut Socket,
    config: &ProbeConfig,
) -> Result<String, ProbeError> {
    let url = bridge
        .params
        .url
        .as_deref()
        .ok_or_else(|| ProbeError::Config("snowflake bridge missing url".to_owned()))?;
    let (host, _, path) = http::url_parts(url)?;

    let poll = ClientPollRequest {
        sid: random_sid(),
        version: PROTOCOL_VERSION.to_owned(),
    };
    let body = poll
        .encode()
        .map_err(|error| ProbeError::Codec(error.to_string()))?;
    let request = http::build_post(&host, &path, &body);
    socket.write_all(&request, config.write_timeout).await?;

    let response =
        http::read_http_response(socket, config.read_timeout, MAX_RESPONSE, "snowflake").await?;
    if !(200..300).contains(&response.status_code) {
        return Err(ProbeError::HttpStatus {
            transport: "snowflake",
            code: response.status_code,
        });
    }
    let parsed = ClientPollResponse::decode(&response.body)
        .map_err(|error| ProbeError::Codec(error.to_string()))?;
    Ok(format!(
        "snowflake: broker reachable, status {:?}",
        parsed.status
    ))
}

/// A random, opaque broker session id (32 hex characters).
fn random_sid() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    to_hex(&bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn random_sid_is_32_hex_chars() {
        let sid = random_sid();
        assert_eq!(sid.len(), 32);
        assert!(sid.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn to_hex_encodes_bytes() {
        assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}

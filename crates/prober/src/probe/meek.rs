//! meek domain-fronted POST probe.
//!
//! A meek bridge is reached by `POST`ing chunks of application data to a
//! rendezvous URL through a CDN front. This probe drives the `tbc-transports`
//! meek codec over a socket: it sends a well-formed `POST` envelope carrying
//! an `X-Session-Id`, then checks the HTTP status. A 2xx response proves the
//! front accepted the envelope (handshake-level reachability); a 4xx/5xx or
//! non-HTTP response is classified accordingly.

use rand::RngCore;
use tbc_core::BridgeLine;
use tbc_transports::meek::{MeekRequest, MeekResponse};

use crate::config::ProbeConfig;
use crate::error::ProbeError;
use crate::http;
use crate::socket::Socket;

/// Maximum HTTP response bytes accepted for a meek exchange.
const MAX_RESPONSE: usize = 65_536;

/// Run the meek POST envelope probe against a socket.
pub async fn handshake(
    bridge: &BridgeLine,
    socket: &mut Socket,
    config: &ProbeConfig,
) -> Result<String, ProbeError> {
    let front = front_domain(bridge)?;
    let mut session_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut session_id);

    let request = MeekRequest::new(front, session_id, Vec::new())
        .with_content_type("application/octet-stream".to_owned());
    let request_bytes = request
        .encode()
        .map_err(|error| ProbeError::Codec(error.to_string()))?;
    socket
        .write_all(&request_bytes, config.write_timeout)
        .await?;

    let response =
        http::read_http_response(socket, config.read_timeout, MAX_RESPONSE, "meek").await?;
    let envelope = MeekResponse {
        status_code: response.status_code,
        headers: response.headers,
        body: response.body,
    };
    if envelope.is_success() {
        Ok(format!("meek: HTTP {} accepted", envelope.status_code))
    } else {
        Err(ProbeError::HttpStatus {
            transport: "meek",
            code: envelope.status_code,
        })
    }
}

/// The front domain used for the `Host` header (and TLS SNI in production):
/// the explicit `front=` value when present, else the rendezvous URL host.
fn front_domain(bridge: &BridgeLine) -> Result<String, ProbeError> {
    if let Some(front) = &bridge.params.servername {
        return Ok(front.clone());
    }
    let url = bridge
        .params
        .url
        .as_deref()
        .ok_or_else(|| ProbeError::Config("meek bridge missing url".to_owned()))?;
    let (host, _, _) = http::url_parts(url)?;
    Ok(host)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn front_domain_prefers_front_param() {
        let line = "meek 127.0.0.1:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://cdn.example/ front=ajax.example.com";
        let bridge = BridgeLine::parse(line, now()).unwrap();
        assert_eq!(front_domain(&bridge).unwrap(), "ajax.example.com");
    }

    #[test]
    fn front_domain_falls_back_to_url_host() {
        let line =
            "meek 127.0.0.1:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://cdn.example/";
        let bridge = BridgeLine::parse(line, now()).unwrap();
        assert_eq!(front_domain(&bridge).unwrap(), "cdn.example");
    }
}

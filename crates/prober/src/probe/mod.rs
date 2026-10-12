//! Transport-specific probes and their dispatch.
//!
//! Each module implements a handshake-level probe for one transport. The
//! [`target`] function resolves where to connect for a bridge (its published
//! endpoint for obfs4/WebTunnel/vanilla, or its rendezvous URL for
//! meek/Snowflake), and [`handshake`] dispatches on the transport family.

pub mod meek;
pub mod obfs4;
pub mod snowflake;
pub mod vanilla;
pub mod webtunnel;

use tbc_core::{BridgeLine, Clock, TransportKind};

use crate::config::ProbeConfig;
use crate::error::ProbeError;
use crate::http;
use crate::socket::Socket;

/// Resolve the `(host, port)` a probe should connect to for a bridge.
pub fn target(bridge: &BridgeLine) -> Result<(String, u16), ProbeError> {
    match bridge.transport {
        TransportKind::Obfs4 | TransportKind::Vanilla => Ok((bridge.host.clone(), bridge.port)),
        TransportKind::WebTunnel | TransportKind::Meek | TransportKind::Snowflake => {
            let url = bridge
                .params
                .url
                .as_deref()
                .ok_or_else(|| ProbeError::Config("fronted transport missing url".to_owned()))?;
            let parsed = url::Url::parse(url)
                .map_err(|error| ProbeError::Config(format!("invalid rendezvous URL: {error}")))?;
            if bridge.transport == TransportKind::WebTunnel && parsed.scheme() != "https" {
                return Err(ProbeError::Config(
                    "WebTunnel dial target must use HTTPS".to_owned(),
                ));
            }
            let (host, port, _) = http::url_parts(url)?;
            Ok((host, port))
        }
        TransportKind::Conjure | TransportKind::Other(_) => Err(ProbeError::UnsupportedTransport(
            bridge.transport.to_string(),
        )),
    }
}

/// Run the handshake-level probe for `bridge` on a connected [`Socket`],
/// returning a metric-safe evidence string on success.
pub async fn handshake(
    bridge: &BridgeLine,
    socket: &mut Socket,
    config: &ProbeConfig,
    clock: &dyn Clock,
) -> Result<String, ProbeError> {
    match bridge.transport {
        TransportKind::Obfs4 => obfs4::handshake(bridge, socket, config, clock).await,
        TransportKind::WebTunnel => webtunnel::handshake(bridge, socket, config).await,
        TransportKind::Vanilla => vanilla::handshake(bridge, socket, config, clock).await,
        TransportKind::Snowflake => snowflake::handshake(bridge, socket, config).await,
        TransportKind::Meek => meek::handshake(bridge, socket, config).await,
        TransportKind::Conjure | TransportKind::Other(_) => Err(ProbeError::UnsupportedTransport(
            bridge.transport.to_string(),
        )),
    }
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
    fn webtunnel_target_uses_public_url_not_placeholder_endpoint() {
        let line = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://front.example.com:8443/tunnel/path ver=0.0.4";
        let bridge = BridgeLine::parse(line, now()).unwrap();

        assert_eq!(bridge.host, "2001:db8::1");
        assert_eq!(
            target(&bridge).unwrap(),
            ("front.example.com".to_owned(), 8443)
        );
    }

    #[test]
    fn webtunnel_target_rejects_plain_http_url() {
        let line = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=http://front.example.com/path ver=0.0.4";
        let bridge = BridgeLine::parse(line, now()).unwrap();
        assert!(matches!(target(&bridge), Err(ProbeError::Config(_))));
    }

    #[test]
    fn url_fronted_target_requires_url() {
        let line = "snowflake 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567";
        let bridge = BridgeLine::parse(line, now()).unwrap();
        assert!(matches!(target(&bridge), Err(ProbeError::Config(_))));
    }
}

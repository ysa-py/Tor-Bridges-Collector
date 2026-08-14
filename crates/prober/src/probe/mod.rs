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
        TransportKind::Obfs4 | TransportKind::Vanilla | TransportKind::WebTunnel => {
            Ok((bridge.host.clone(), bridge.port))
        }
        TransportKind::Meek | TransportKind::Snowflake => {
            let url =
                bridge.params.url.as_deref().ok_or_else(|| {
                    ProbeError::Config("fronted transport missing url".to_owned())
                })?;
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

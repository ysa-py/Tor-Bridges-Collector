//! Vanilla (ORPort) link handshake probe.
//!
//! A Tor relay's ORPort speaks fixed-width 514-byte cells. This probe performs
//! the tor-spec §3/§4 negotiation: send a `VERSIONS` cell, read cells until a
//! `VERSIONS` response is received (tolerating the `CERTS`/`AUTH_CHALLENGE`
//! cells a real responder sends in between), then send `NETINFO` and read
//! until a `NETINFO` response is observed. Reaching `VERSIONS` already proves
//! the endpoint is a Tor ORPort, not a bare TCP listener.

use std::time::Duration;

use tbc_core::{BridgeLine, Clock};
use tbc_transports::vanilla::{
    Cell, NetinfoCell, VersionsCell, CELL_LEN, CMD_AUTH_CHALLENGE, CMD_CERTS, CMD_NETINFO,
    CMD_PADDING, CMD_VERSIONS,
};

use crate::config::ProbeConfig;
use crate::error::ProbeError;
use crate::socket::Socket;

/// Maximum link cells read per negotiation phase (bounds a hostile peer).
const MAX_LINK_CELLS: usize = 8;

/// Link protocol versions the prober offers.
const SUPPORTED_VERSIONS: [u16; 3] = [3, 4, 5];

/// Run the ORPort `VERSIONS` + `NETINFO` handshake against a socket.
pub async fn handshake(
    _bridge: &BridgeLine,
    socket: &mut Socket,
    config: &ProbeConfig,
    clock: &dyn Clock,
) -> Result<String, ProbeError> {
    let versions = VersionsCell {
        versions: SUPPORTED_VERSIONS.to_vec(),
    }
    .to_cell(0)
    .map_err(codec_error)?;
    socket
        .write_all(&versions.encode(), config.write_timeout)
        .await?;

    // Phase 1: read cells until a VERSIONS response arrives.
    let mut saw_versions = false;
    for _ in 0..MAX_LINK_CELLS {
        let cell = read_cell(socket, config.read_timeout).await?;
        match cell.command {
            CMD_VERSIONS => {
                VersionsCell::from_cell(&cell).map_err(protocol_error)?;
                saw_versions = true;
                break;
            }
            CMD_CERTS | CMD_AUTH_CHALLENGE | CMD_NETINFO | CMD_PADDING => {}
            other => {
                return Err(ProbeError::Protocol {
                    transport: "vanilla",
                    message: format!("unexpected link cell command {other}"),
                })
            }
        }
    }
    if !saw_versions {
        return Err(ProbeError::Protocol {
            transport: "vanilla",
            message: "no VERSIONS cell received".to_owned(),
        });
    }

    // Phase 2: send NETINFO and read cells until a NETINFO response arrives.
    let netinfo = NetinfoCell {
        timestamp: clock.now().timestamp() as u32,
        other_addr: None,
        my_addrs: Vec::new(),
    }
    .to_cell(0)
    .map_err(codec_error)?;
    socket
        .write_all(&netinfo.encode(), config.write_timeout)
        .await?;

    for _ in 0..MAX_LINK_CELLS {
        let cell = read_cell(socket, config.read_timeout).await?;
        match cell.command {
            CMD_NETINFO => {
                NetinfoCell::from_cell(&cell).map_err(protocol_error)?;
                return Ok("vanilla: VERSIONS + NETINFO handshake completed".to_owned());
            }
            CMD_CERTS | CMD_AUTH_CHALLENGE | CMD_PADDING | CMD_VERSIONS => {}
            other => {
                return Err(ProbeError::Protocol {
                    transport: "vanilla",
                    message: format!("unexpected link cell command {other}"),
                })
            }
        }
    }

    // VERSIONS was verified even if NETINFO never completed.
    Ok("vanilla: VERSIONS received (NETINFO not completed)".to_owned())
}

/// Read exactly one fixed-width link cell.
async fn read_cell(socket: &mut Socket, timeout: Duration) -> Result<Cell, ProbeError> {
    let mut bytes = [0u8; CELL_LEN];
    socket.read_exact(&mut bytes, timeout).await?;
    Cell::decode(&bytes).map_err(|error| ProbeError::Protocol {
        transport: "vanilla",
        message: error.to_string(),
    })
}

fn codec_error(error: tbc_transports::TransportError) -> ProbeError {
    ProbeError::Codec(error.to_string())
}

fn protocol_error(error: tbc_transports::TransportError) -> ProbeError {
    ProbeError::Protocol {
        transport: "vanilla",
        message: error.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn supported_versions_are_non_empty_and_sorted() {
        assert!(!SUPPORTED_VERSIONS.is_empty());
        assert!(SUPPORTED_VERSIONS.windows(2).all(|w| w[0] < w[1]));
    }
}

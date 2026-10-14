//! Vanilla (ORPort) link handshake probe.
//!
//! A Tor relay's ORPort speaks the link protocol **inside a TLS session**
//! (tor-spec §2: the TLS handshake happens first). The engine establishes
//! that TLS session (`crate::tls`) before this probe runs. This probe then
//! performs the tor-spec §3/§4 negotiation:
//!
//! 1. send the client `VERSIONS` as a **pre-negotiation variable-length
//!    cell with a TWO-byte circuit id** — tor-spec §3: "The first VERSIONS
//!    cell, and any cells sent before the first VERSIONS cell, always have
//!    CIRCID_LEN == 2 for backward compatibility". (A four-byte-circid
//!    VERSIONS cell parses as a PADDING cell on the responder and the
//!    connection goes silently idle; a fixed-width VERSIONS cell is an
//!    outright protocol violation answered with a reset — both observed
//!    against live bridges before this format was corrected.)
//! 2. read cells (variable- or fixed-width, bounded) until the responder's
//!    `VERSIONS` arrives (tolerating `VPADDING` and fixed-width
//!    `CERTS`/`AUTH_CHALLENGE`/`PADDING` cells), then pick the highest
//!    commonly supported version. The prober offers **4 and 5** only, so
//!    the post-negotiation fixed-width cell format is uniformly 514 bytes
//!    with a four-byte circuit id (CIRCID_LEN is 2 for link protocols 1-3
//!    and 4 for v4+);
//! 3. send `NETINFO` as a post-negotiation fixed-width cell — timestamp 0
//!    (tor-spec §4.5: "Clients SHOULD send 0 as their timestamp, to avoid
//!    fingerprinting") and a parseable `other_addr` — then read until the
//!    responder's `NETINFO` is observed.
//!
//! Reaching the responder's `VERSIONS` already proves the endpoint is a Tor
//! ORPort, not a bare TCP listener behind TLS.

use std::net::IpAddr;
use std::time::Duration;

use tbc_core::{BridgeLine, Clock};
use tbc_transports::vanilla::{
    versions_from_variable_payload, versions_variable_cell, Addr, Cell, NetinfoCell, CELL_LEN,
    CMD_AUTH_CHALLENGE, CMD_CERTS, CMD_NETINFO, CMD_PADDING, CMD_VERSIONS,
};

use crate::config::ProbeConfig;
use crate::error::ProbeError;
use crate::socket::Socket;

/// Maximum link cells read per negotiation phase (bounds a hostile peer).
const MAX_LINK_CELLS: usize = 8;

/// Link protocol versions the prober offers. Version 3 and below use a
/// two-byte circuit id for post-negotiation fixed cells; offering 4+ keeps
/// the fixed-width codec uniform (CIRCID_LEN 4, CELL_LEN 514) while staying
/// within the spec's "MUST NOT list any version before 3" rule for the
/// in-protocol handshake.
const SUPPORTED_VERSIONS: [u16; 2] = [4, 5];

/// A cell read before the link version is known: either a variable-length
/// cell (the responder's `VERSIONS`, or `VPADDING`) or a fixed-width cell.
enum PreNegotiationCell {
    Variable { command: u8, value: Vec<u8> },
    Fixed(Cell),
}

/// Run the ORPort `VERSIONS` + `NETINFO` handshake against a TLS-wrapped
/// socket.
pub async fn handshake(
    bridge: &BridgeLine,
    socket: &mut Socket,
    config: &ProbeConfig,
    _clock: &dyn Clock,
) -> Result<String, ProbeError> {
    // Phase 1: variable-length VERSIONS exchange (two-byte circuit id).
    let versions = versions_variable_cell(&SUPPORTED_VERSIONS).map_err(codec_error)?;
    socket.write_all(&versions, config.write_timeout).await?;

    let mut negotiated: Option<u16> = None;
    for _ in 0..MAX_LINK_CELLS {
        match read_pre_negotiation_cell(socket, config.read_timeout).await? {
            PreNegotiationCell::Variable { command, value } => {
                if command == CMD_VERSIONS {
                    let theirs = versions_from_variable_payload(&value).map_err(protocol_error)?;
                    negotiated = SUPPORTED_VERSIONS
                        .iter()
                        .rev()
                        .find(|ours| theirs.contains(ours))
                        .copied();
                    break;
                }
                // VPADDING (or another variable-length command): skip.
            }
            PreNegotiationCell::Fixed(cell) => match cell.command {
                CMD_CERTS | CMD_AUTH_CHALLENGE | CMD_NETINFO | CMD_PADDING => {}
                other => {
                    return Err(ProbeError::Protocol {
                        transport: "vanilla",
                        message: format!("unexpected pre-negotiation link cell command {other}"),
                    })
                }
            },
        }
    }
    let link_version = negotiated.ok_or_else(|| ProbeError::Protocol {
        transport: "vanilla",
        message: "no VERSIONS cell received".to_owned(),
    })?;

    // Phase 2: NETINFO as a post-negotiation fixed-width cell (v4+: 514
    // bytes, four-byte circuit id).
    //
    // `other_addr` must be a parseable or-address (the bridge reads it before
    // anything else); leaving it absent would make the bridge parse the
    // address-count byte as an address type and reject the cell. The most
    // honest value is the endpoint we actually connected to. The timestamp is
    // 0 per tor-spec §4.5 (client anti-fingerprinting), and the my-addr list
    // is empty (count 0), leaving no trailing structure to misparse.
    let netinfo = NetinfoCell {
        timestamp: 0,
        other_addr: Some(other_addr_for(bridge)),
        my_addrs: Vec::new(),
    }
    .to_cell(0)
    .map_err(codec_error)?;
    socket
        .write_all(&netinfo.encode(), config.write_timeout)
        .await?;

    // The responder pipelines CERTS/AUTH_CHALLENGE/NETINFO right after its
    // VERSIONS; its NETINFO is the completion marker we look for. A teardown
    // during this phase does not un-verify the VERSIONS exchange, so those
    // failures degrade to the VERSIONS-only evidence instead of discarding
    // the handshake result.
    for _ in 0..MAX_LINK_CELLS {
        match read_post_negotiation_cell(socket, config.read_timeout).await {
            Ok(PostNegotiationCell::Fixed(cell)) => match cell.command {
                CMD_NETINFO => {
                    NetinfoCell::from_cell(&cell).map_err(protocol_error)?;
                    return Ok(format!(
                        "vanilla: link v{link_version} VERSIONS + NETINFO handshake completed"
                    ));
                }
                CMD_CERTS | CMD_AUTH_CHALLENGE | CMD_PADDING => {}
                other => {
                    return Ok(format!(
                        "vanilla: link v{link_version} VERSIONS received (unexpected cell command {other} before NETINFO)"
                    ));
                }
            },
            Ok(PostNegotiationCell::Variable { command }) => {
                // VPADDING between CERTS and NETINFO: skip.
                tracing::trace!(command, "post-negotiation variable cell skipped");
            }
            Err(error) => {
                return Ok(format!(
                    "vanilla: link v{link_version} VERSIONS received (NETINFO not completed: {error})"
                ));
            }
        }
    }

    // VERSIONS was verified even if NETINFO never completed.
    Ok(format!(
        "vanilla: link v{link_version} VERSIONS received (NETINFO not completed)"
    ))
}

/// The or-address for our `NETINFO` cell: the bridge endpoint we actually
/// connected to, or an unspecified IPv4 address when the endpoint is not an
/// IP literal.
fn other_addr_for(bridge: &BridgeLine) -> Addr {
    match bridge.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Addr::Ipv4(ip.octets()),
        Ok(IpAddr::V6(ip)) => Addr::Ipv6(ip.octets()),
        Err(_) => Addr::Ipv4([0, 0, 0, 0]),
    }
}

/// Read one cell whose width is not yet known. Pre-negotiation cells always
/// carry a two-byte circuit id (tor-spec §3); variable-length commands are
/// `VERSIONS` (7) and anything >= 128 (`VPADDING`, ...).
async fn read_pre_negotiation_cell(
    socket: &mut Socket,
    timeout: Duration,
) -> Result<PreNegotiationCell, ProbeError> {
    const PRE_NEG_CIRCID_LEN: usize = 2;
    let mut header = [0u8; PRE_NEG_CIRCID_LEN + 3];
    socket.read_exact(&mut header, timeout).await?;
    let command = header[PRE_NEG_CIRCID_LEN];
    if command == CMD_VERSIONS || command >= 128 {
        let value_len = u16::from_be_bytes([
            header[PRE_NEG_CIRCID_LEN + 1],
            header[PRE_NEG_CIRCID_LEN + 2],
        ]) as usize;
        let mut value = vec![0u8; value_len];
        socket.read_exact(&mut value, timeout).await?;
        return Ok(PreNegotiationCell::Variable { command, value });
    }

    // Fixed-width pre-negotiation cell: 512 bytes (2-byte circuit id, 1-byte
    // command, 509-byte payload). The first five bytes (circuit id + command
    // + the first two payload bytes) are already read.
    let mut rest = [0u8; 512 - 5];
    socket.read_exact(&mut rest, timeout).await?;
    let mut bytes = [0u8; CELL_LEN];
    // Re-frame into the 514-byte codec shape (four-byte circuit id):
    // [0,0] pad + original 2-byte circid | command | 509-byte payload.
    bytes[..2].copy_from_slice(&[0, 0]);
    bytes[2..4].copy_from_slice(&header[..2]);
    bytes[4] = command;
    bytes[5..7].copy_from_slice(&header[3..5]);
    bytes[7..].copy_from_slice(&rest);
    let cell = Cell::decode(&bytes).map_err(|error| ProbeError::Protocol {
        transport: "vanilla",
        message: error.to_string(),
    })?;
    Ok(PreNegotiationCell::Fixed(cell))
}

/// A post-negotiation (link v4+) cell: fixed-width 514 bytes or a
/// variable-length cell with a four-byte circuit id.
enum PostNegotiationCell {
    Fixed(Cell),
    /// A variable-length cell (e.g. `VPADDING`); its value is skipped.
    Variable {
        command: u8,
    },
}

/// Read one post-negotiation cell, tolerating responder padding.
async fn read_post_negotiation_cell(
    socket: &mut Socket,
    timeout: Duration,
) -> Result<PostNegotiationCell, ProbeError> {
    const CIRCID_LEN: usize = 4;
    let mut header = [0u8; CIRCID_LEN + 3];
    socket.read_exact(&mut header, timeout).await?;
    let command = header[CIRCID_LEN];
    if command == CMD_VERSIONS || command >= 128 {
        let value_len =
            u16::from_be_bytes([header[CIRCID_LEN + 1], header[CIRCID_LEN + 2]]) as usize;
        let mut value = vec![0u8; value_len];
        socket.read_exact(&mut value, timeout).await?;
        drop(value);
        return Ok(PostNegotiationCell::Variable { command });
    }

    let mut rest = [0u8; CELL_LEN - 7];
    socket.read_exact(&mut rest, timeout).await?;
    let mut bytes = [0u8; CELL_LEN];
    bytes[..CIRCID_LEN].copy_from_slice(&header[..CIRCID_LEN]);
    bytes[CIRCID_LEN] = command;
    // The header already carried the first two payload bytes.
    bytes[CIRCID_LEN + 1..CIRCID_LEN + 3].copy_from_slice(&header[CIRCID_LEN + 1..]);
    bytes[CIRCID_LEN + 3..].copy_from_slice(&rest);
    let cell = Cell::decode(&bytes).map_err(|error| ProbeError::Protocol {
        transport: "vanilla",
        message: error.to_string(),
    })?;
    Ok(PostNegotiationCell::Fixed(cell))
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
    use tbc_transports::vanilla::{versions_variable_cell, CELL_PAYLOAD_LEN};

    #[test]
    fn supported_versions_are_v4_plus() {
        assert_eq!(SUPPORTED_VERSIONS, [4, 5]);
        // Link protocol 4 is the first version with the four-byte circuit id
        // our post-negotiation fixed-width codec assumes.
        assert!(SUPPORTED_VERSIONS.iter().all(|v| *v >= 4));
    }

    // Regression: the client's opening VERSIONS cell MUST use the
    // pre-negotiation variable-length format with a TWO-byte circuit id
    // (tor-spec §3). The previous fixed-width 514-byte encoding was parsed
    // as a PADDING cell (silence) and earlier still as a protocol violation
    // (connection reset) — both observed against live bridges.
    #[test]
    fn client_versions_cell_uses_two_byte_circid_variable_format() {
        let bytes = versions_variable_cell(&SUPPORTED_VERSIONS).unwrap();
        assert_eq!(bytes.len(), 5 + SUPPORTED_VERSIONS.len() * 2);
        assert_eq!(&bytes[..2], &[0, 0], "circuit id 0, TWO-byte width");
        assert_eq!(bytes[2], CMD_VERSIONS);
        assert_eq!(&bytes[3..5], &[0, 4], "value length: 2 versions * 2 bytes");
        assert_eq!(&bytes[5..], &[0, 4, 0, 5]);
    }

    #[test]
    fn server_versions_payload_decodes() {
        let advertised = versions_from_variable_payload(&[0, 3, 0, 4, 0, 5]).unwrap();
        assert_eq!(advertised, vec![3, 4, 5]);
        assert!(versions_from_variable_payload(&[0, 3, 0]).is_err());
    }

    #[test]
    fn versions_cell_encoding_rejects_empty_list() {
        assert!(versions_variable_cell(&[]).is_err());
    }

    #[test]
    fn netinfo_client_cell_is_spec_shaped() {
        // timestamp 0 (client anti-fingerprinting), parseable other_addr,
        // empty my-addr list, and post-negotiation fixed-width framing.
        let cell = NetinfoCell {
            timestamp: 0,
            other_addr: Some(Addr::Ipv4([192, 0, 2, 7])),
            my_addrs: Vec::new(),
        }
        .to_cell(0)
        .unwrap();
        let encoded = cell.encode();
        assert_eq!(encoded.len(), CELL_LEN);
        // Payload: timestamp(4) + ATYPE(1)+ALEN(1)+AVAL(4) + NMYADDR(1) = 11.
        assert_eq!(encoded[4], CMD_NETINFO, "command");
        assert_eq!(&encoded[5..9], &[0, 0, 0, 0], "timestamp 0");
        assert_eq!(encoded[9], 0x04, "ATYPE IPv4");
        assert_eq!(encoded[10], 4, "ALEN MUST be 4 for IPv4 (tor-spec 4.5)");
        assert_eq!(&encoded[11..15], &[192, 0, 2, 7]);
        assert_eq!(encoded[15], 0, "NMYADDR = 0");
    }

    #[test]
    fn netinfo_decode_accepts_spec_shaped_server_cells() {
        // A real responder sends ALEN=4 for IPv4; the previous decoder only
        // accepted the non-spec ALEN=6 form and would have failed here.
        let mut payload = vec![0u8; CELL_PAYLOAD_LEN];
        payload[..4].copy_from_slice(&1_760_000_000u32.to_be_bytes());
        payload[4] = 0x04;
        payload[5] = 4;
        payload[6..10].copy_from_slice(&[203, 0, 113, 7]);
        payload[10] = 0;
        let cell = Cell::new(0, CMD_NETINFO, &payload).unwrap();
        let netinfo = NetinfoCell::from_cell(&cell).unwrap();
        assert_eq!(netinfo.timestamp, 1_760_000_000);
        assert_eq!(netinfo.other_addr, Some(Addr::Ipv4([203, 0, 113, 7])));
        assert!(netinfo.my_addrs.is_empty());
    }
}

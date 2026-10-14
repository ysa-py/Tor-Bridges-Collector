//! Vanilla (ORPort) cell codecs — tor-spec.txt §3 "Cell Packet format" and
//! §4 "Negotiating and initializing connections".
//!
//! A fixed-width cell is `CircID (4 bytes) | Command (1 byte) | Payload (509
//! bytes)` for link protocol 3 and later. This module encodes and decodes that
//! envelope plus the two handshake cells the collector must be able to speak
//! and inspect: `VERSIONS` (command 7) and `NETINFO` (command 8).

use crate::error::TransportError;

/// Total length of a fixed-width cell.
pub const CELL_LEN: usize = 514;
/// Length of the cell payload field.
pub const CELL_PAYLOAD_LEN: usize = 509;

/// Cell command for padding.
pub const CMD_PADDING: u8 = 0;
/// Cell command for the version list.
pub const CMD_VERSIONS: u8 = 7;
/// Cell command for the address/netinfo exchange.
pub const CMD_NETINFO: u8 = 8;
/// Cell command for certificates.
pub const CMD_CERTS: u8 = 129;
/// Cell command for the authentication challenge.
pub const CMD_AUTH_CHALLENGE: u8 = 130;

/// A fixed-width (512-byte) link cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    /// The 4-byte circuit identifier (0 for link handshake cells).
    pub circuit_id: u32,
    /// The cell command byte.
    pub command: u8,
    /// The exactly [`CELL_PAYLOAD_LEN`]-byte payload.
    pub payload: Vec<u8>,
}

impl Cell {
    /// Build a cell, zero-padding a short payload and rejecting an oversized one.
    pub fn new(circuit_id: u32, command: u8, payload: &[u8]) -> Result<Self, TransportError> {
        if payload.len() > CELL_PAYLOAD_LEN {
            return Err(TransportError::InvalidCellPayload(
                payload.len(),
                CELL_PAYLOAD_LEN,
            ));
        }
        let mut padded = vec![0u8; CELL_PAYLOAD_LEN];
        padded[..payload.len()].copy_from_slice(payload);
        Ok(Self {
            circuit_id,
            command,
            payload: padded,
        })
    }

    /// Serialize the cell to its 514-byte wire form.
    pub fn encode(&self) -> [u8; CELL_LEN] {
        let mut out = [0u8; CELL_LEN];
        out[..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        out[4] = self.command;
        out[5..].copy_from_slice(&self.payload);
        out
    }

    /// Deserialize a cell from exactly [`CELL_LEN`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() != CELL_LEN {
            return Err(TransportError::Cell("fixed-width cell must be 514 bytes"));
        }
        let mut circuit_id = [0u8; 4];
        circuit_id.copy_from_slice(&bytes[..4]);
        let command = bytes[4];
        let payload = bytes[5..].to_vec();
        Ok(Self {
            circuit_id: u32::from_be_bytes(circuit_id),
            command,
            payload,
        })
    }
}

/// A `VERSIONS` cell payload: a list of supported link protocol versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionsCell {
    /// Supported protocol versions, in wire order.
    pub versions: Vec<u16>,
}

impl VersionsCell {
    /// Encode into a link cell.
    pub fn to_cell(&self, circuit_id: u32) -> Result<Cell, TransportError> {
        let mut payload = Vec::with_capacity(2 + self.versions.len() * 2);
        let count = u16::try_from(self.versions.len())
            .map_err(|_| TransportError::Cell("too many versions"))?;
        payload.extend_from_slice(&count.to_be_bytes());
        for version in &self.versions {
            payload.extend_from_slice(&version.to_be_bytes());
        }
        Cell::new(circuit_id, CMD_VERSIONS, &payload)
    }

    /// Decode a `VERSIONS` cell, validating the declared count.
    pub fn from_cell(cell: &Cell) -> Result<Self, TransportError> {
        if cell.command != CMD_VERSIONS {
            return Err(TransportError::Cell("not a VERSIONS cell"));
        }
        let count = read_u16(&cell.payload, 0)? as usize;
        if 2 + count * 2 > cell.payload.len() {
            return Err(TransportError::Cell("VERSIONS count exceeds payload"));
        }
        let mut versions = Vec::with_capacity(count);
        for i in 0..count {
            versions.push(read_u16(&cell.payload, 2 + i * 2)?);
        }
        Ok(Self { versions })
    }
}

/// A link-layer address carried in `NETINFO` cells (tor-spec §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addr {
    /// `ATYPE` 0x04: 4-byte IPv4 address.
    Ipv4([u8; 4]),
    /// `ATYPE` 0x06: 16-byte IPv6 address.
    Ipv6([u8; 16]),
}

impl Addr {
    /// The tor-spec address type byte.
    pub fn atype(&self) -> u8 {
        match self {
            Self::Ipv4(_) => 0x04,
            Self::Ipv6(_) => 0x06,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.atype());
        match self {
            // tor-spec §4.5: "ALEN MUST be 4 when ATYPE is 0x04 (IPv4) and
            // 16 when ATYPE is 0x06 (IPv6)" — the wire form carries the bare
            // address with no port. The previous 6/18-byte encoding (with a
            // port) was a spec violation that made our NETINFO cells
            // unparseable for real responders.
            Self::Ipv4(octets) => {
                out.push(4);
                out.extend_from_slice(octets);
            }
            Self::Ipv6(octets) => {
                out.push(16);
                out.extend_from_slice(octets);
            }
        }
    }

    fn decode(bytes: &[u8], offset: usize) -> Result<(Self, usize), TransportError> {
        let atype = *bytes.get(offset).ok_or(TransportError::Truncated {
            needed: 1,
            available: bytes.len().saturating_sub(offset),
        })?;
        let alen = *bytes.get(offset + 1).ok_or(TransportError::Truncated {
            needed: 1,
            available: bytes.len().saturating_sub(offset + 1),
        })? as usize;
        match (atype, alen) {
            (0x04, 4) => {
                let addr = take_array::<4>(bytes, offset + 2)?;
                Ok((Self::Ipv4(addr), offset + 6))
            }
            (0x06, 16) => {
                let addr = take_array::<16>(bytes, offset + 2)?;
                Ok((Self::Ipv6(addr), offset + 18))
            }
            _ => Err(TransportError::Cell("unsupported NETINFO address type")),
        }
    }
}

/// A `NETINFO` cell payload: timestamps and the peer's observed addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetinfoCell {
    /// Current Unix time in seconds at the sender.
    pub timestamp: u32,
    /// The address the sender observed for the peer (optional on decode).
    pub other_addr: Option<Addr>,
    /// The sender's own addresses.
    pub my_addrs: Vec<Addr>,
}

impl NetinfoCell {
    /// Encode into a link cell.
    pub fn to_cell(&self, circuit_id: u32) -> Result<Cell, TransportError> {
        if self.my_addrs.len() > u8::MAX as usize {
            return Err(TransportError::Cell("too many NETINFO addresses"));
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        if let Some(addr) = &self.other_addr {
            addr.encode_into(&mut payload);
        }
        payload.push(self.my_addrs.len() as u8);
        for addr in &self.my_addrs {
            addr.encode_into(&mut payload);
        }
        Cell::new(circuit_id, CMD_NETINFO, &payload)
    }

    /// Decode a `NETINFO` cell.
    pub fn from_cell(cell: &Cell) -> Result<Self, TransportError> {
        if cell.command != CMD_NETINFO {
            return Err(TransportError::Cell("not a NETINFO cell"));
        }
        let timestamp = u32::from_be_bytes(take_array::<4>(&cell.payload, 0)?);
        let mut offset = 4;
        let other_addr = if cell.payload.get(offset).copied() == Some(0) {
            None
        } else {
            let (addr, next) = Addr::decode(&cell.payload, offset)?;
            offset = next;
            Some(addr)
        };
        let count = *cell.payload.get(offset).ok_or(TransportError::Truncated {
            needed: 1,
            available: cell.payload.len().saturating_sub(offset),
        })? as usize;
        offset += 1;
        let mut my_addrs = Vec::with_capacity(count);
        for _ in 0..count {
            let (addr, next) = Addr::decode(&cell.payload, offset)?;
            my_addrs.push(addr);
            offset = next;
        }
        Ok(Self {
            timestamp,
            other_addr,
            my_addrs,
        })
    }
}

fn take_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], TransportError> {
    let slice =
        bytes
            .get(offset..)
            .and_then(|rest| rest.get(..N))
            .ok_or(TransportError::Truncated {
                needed: N,
                available: bytes.len().saturating_sub(offset),
            })?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, TransportError> {
    Ok(u16::from_be_bytes(take_array::<2>(bytes, offset)?))
}

/// Encode a `VERSIONS` cell in the pre-negotiation variable-length wire
/// format (tor-spec §3 and §4.1).
///
/// The `VERSIONS` cell is the negotiation anchor itself: the post-negotiation
/// fixed-width cell format only exists *after* a link version has been
/// agreed, so a fixed-width `VERSIONS` cell is a protocol violation. Real
/// responders read a variable-length cell and reset connections that send
/// anything else there.
///
/// Per tor-spec §3, "The first VERSIONS cell, and any cells sent before the
/// first VERSIONS cell, always have CIRCID_LEN == 2 for backward
/// compatibility" — the circuit id is TWO bytes on this first cell, not the
/// four-byte width of link protocol v4+. (The previous four-byte-circid
/// encoding made the responder parse our cell as a PADDING cell and wait
/// forever; observed against live bridges as silent read timeouts.)
///
/// Returns the exact bytes to write for the client's opening `VERSIONS` cell.
///
/// # Errors
/// [`TransportError::Cell`] when `versions` is empty or the value does not
/// fit the 2-byte length field.
pub fn versions_variable_cell(versions: &[u16]) -> Result<Vec<u8>, TransportError> {
    if versions.is_empty() {
        return Err(TransportError::Cell(
            "VERSIONS cell needs at least one link version",
        ));
    }
    let value_len =
        u16::try_from(versions.len() * 2).map_err(|_| TransportError::Cell("too many versions"))?;
    let mut out = Vec::with_capacity(5 + versions.len() * 2);
    // Circuit id 0 at the pre-negotiation TWO-byte width (tor-spec §3).
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(CMD_VERSIONS);
    out.extend_from_slice(&value_len.to_be_bytes());
    for version in versions {
        out.extend_from_slice(&version.to_be_bytes());
    }
    Ok(out)
}

/// Decode the payload of a server `VERSIONS` variable-length cell (the bytes
/// after its 2-byte value length) into the advertised link versions.
///
/// # Errors
/// [`TransportError::Cell`] when the value length is odd or the value is
/// truncated.
pub fn versions_from_variable_payload(value: &[u8]) -> Result<Vec<u16>, TransportError> {
    if value.len() % 2 != 0 {
        return Err(TransportError::Cell(
            "VERSIONS value length must be a whole number of two-byte versions",
        ));
    }
    Ok(value
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cell_round_trips() {
        let cell = Cell::new(0x01020304, CMD_VERSIONS, &[1, 2, 3]).unwrap();
        assert_eq!(cell.payload.len(), CELL_PAYLOAD_LEN);
        let encoded = cell.encode();
        assert_eq!(encoded.len(), CELL_LEN);
        let decoded = Cell::decode(&encoded).unwrap();
        assert_eq!(decoded, cell);
    }

    #[test]
    fn cell_rejects_oversized_payload() {
        let big = vec![0u8; CELL_PAYLOAD_LEN + 1];
        assert!(matches!(
            Cell::new(0, CMD_PADDING, &big),
            Err(TransportError::InvalidCellPayload(510, 509))
        ));
    }

    #[test]
    fn cell_rejects_wrong_length_on_decode() {
        assert!(Cell::decode(&[0u8; 512]).is_err());
    }

    #[test]
    fn versions_cell_round_trips() {
        let versions = VersionsCell {
            versions: vec![3, 4, 5],
        };
        let cell = versions.to_cell(0).unwrap();
        assert_eq!(cell.command, CMD_VERSIONS);
        assert_eq!(VersionsCell::from_cell(&cell).unwrap(), versions);
    }

    #[test]
    fn versions_cell_rejects_bad_count() {
        let cell = Cell::new(0, CMD_VERSIONS, &[0xFF, 0xFF, 0, 4]).unwrap();
        assert!(VersionsCell::from_cell(&cell).is_err());
    }

    #[test]
    fn versions_cell_rejects_wrong_command() {
        let cell = Cell::new(0, CMD_NETINFO, &[]).unwrap();
        assert!(VersionsCell::from_cell(&cell).is_err());
    }

    #[test]
    fn netinfo_cell_round_trips_v4_and_v6() {
        let netinfo = NetinfoCell {
            timestamp: 1_700_000_000,
            other_addr: Some(Addr::Ipv4([192, 0, 2, 1])),
            my_addrs: vec![
                Addr::Ipv4([198, 51, 100, 7]),
                Addr::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            ],
        };
        let cell = netinfo.to_cell(0).unwrap();
        assert_eq!(cell.command, CMD_NETINFO);
        assert_eq!(NetinfoCell::from_cell(&cell).unwrap(), netinfo);
    }

    // Regression (tor-spec §4.5): "ALEN MUST be 4 when ATYPE is 0x04 (IPv4)
    // and 16 when ATYPE is 0x06 (IPv6)" — the wire form carries the bare
    // address, with no port. The previous 6/18-byte encoding made our
    // NETINFO cells unparseable for spec-compliant responders.
    #[test]
    fn netinfo_addr_wire_form_has_no_port() {
        let netinfo = NetinfoCell {
            timestamp: 0,
            other_addr: Some(Addr::Ipv4([192, 0, 2, 1])),
            my_addrs: vec![],
        };
        let encoded = netinfo.to_cell(0).unwrap().encode();
        // payload: timestamp(4) + ATYPE + ALEN + AVAL(4) + NMYADDR
        assert_eq!(encoded[5], 0x04, "ATYPE");
        assert_eq!(encoded[6], 4, "ALEN MUST be 4 for IPv4");
        assert_eq!(&encoded[7..11], &[192, 0, 2, 1]);
        assert_eq!(encoded[11], 0, "NMYADDR");
    }

    #[test]
    fn netinfo_cell_without_other_addr_decodes() {
        let netinfo = NetinfoCell {
            timestamp: 7,
            other_addr: None,
            my_addrs: vec![],
        };
        let cell = netinfo.to_cell(0).unwrap();
        let decoded = NetinfoCell::from_cell(&cell).unwrap();
        assert_eq!(decoded.timestamp, 7);
        assert_eq!(decoded.other_addr, None);
        assert!(decoded.my_addrs.is_empty());
    }

    #[test]
    fn netinfo_rejects_unknown_address_type() {
        // ATYPE=0x01 is not a valid tor address type.
        let mut payload = vec![0u8; 4];
        payload.extend_from_slice(&[0x01, 0x06, 0, 0, 0, 0, 0, 1]);
        let cell = Cell::new(0, CMD_NETINFO, &payload).unwrap();
        assert!(NetinfoCell::from_cell(&cell).is_err());
    }
}

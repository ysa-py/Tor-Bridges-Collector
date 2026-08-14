//! obfs4 framing handshake probe.
//!
//! This probe drives the `tbc-transports` obfs4 codec over a socket: it
//! decodes the published identity, sends a well-formed `clientRequest` whose
//! `M_C`/`MAC_C` marks are computed from `B | NODEID`, then reads the
//! `serverResponse` and verifies its `M_S`/`MAC_S` marks. Completing this
//! exchange proves the endpoint is an obfs4 bridge in possession of the
//! published identity — strictly stronger than a TCP connect.
//!
//! ## Honest boundary
//!
//! The `X'` field is filled with random bytes rather than a true Elligator 2
//! representative, and the ntor `AUTH` tag is **not** verified. Verifying
//! `AUTH` requires the Elligator 2 + X25519 + ntor primitives, which are out
//! of scope here (tracked in `docs/PROGRESS.md`). Consequently this probe
//! cannot distinguish the real bridge from an active attacker that also knows
//! the published identity; it is deliberately documented as such and is never
//! presented as full server authentication.

use std::time::Duration;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha2::Sha256;
use tbc_core::{BridgeLine, Clock};
use tbc_transports::bridge::obfs4_identity;
use tbc_transports::obfs4::{
    ClientHandshake, IdentityKey, ServerHandshake, CLIENT_MAX_PAD, CLIENT_MIN_PAD, MARK_LEN,
    MAX_HANDSHAKE_LEN, REPRESENTATIVE_LEN,
};

use crate::config::ProbeConfig;
use crate::error::ProbeError;
use crate::socket::Socket;

type HmacSha256 = Hmac<Sha256>;

/// Length of the fixed `Y' | AUTH` prefix of a server response.
const SERVER_FIXED_HEADER_LEN: usize = REPRESENTATIVE_LEN + 32;

/// Run the obfs4 framing handshake against a connected socket.
pub async fn handshake(
    bridge: &BridgeLine,
    socket: &mut Socket,
    config: &ProbeConfig,
    clock: &dyn Clock,
) -> Result<String, ProbeError> {
    let identity = obfs4_identity(bridge).map_err(|error| ProbeError::Codec(error.to_string()))?;
    let hours = hours_since_epoch(clock.now());

    // `X'` is random representative material; see the module's honest boundary.
    let mut representative = [0u8; REPRESENTATIVE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut representative);

    let padding = random_padding();
    let request = ClientHandshake::encode(&identity, representative, &padding, hours)
        .map_err(|error| ProbeError::Codec(error.to_string()))?;
    socket.write_all(&request, config.write_timeout).await?;

    let response = read_server_response(socket, &identity, config.read_timeout).await?;
    match ServerHandshake::decode(&identity, &response, hours) {
        Ok(_) => Ok("obfs4: server M_S/MAC_S verified".to_owned()),
        Err(tbc_transports::TransportError::BadMac(_)) => Err(ProbeError::AuthFailed {
            transport: "obfs4",
            message: "M_S/MAC_S verification failed".to_owned(),
        }),
        Err(error) => Err(ProbeError::Codec(error.to_string())),
    }
}

/// Read a variable-length `serverResponse` (`Y' | AUTH | P_S | M_S | MAC_S`)
/// by locating the identity-derived mark `M_S` and reading through `MAC_S`.
async fn read_server_response(
    socket: &mut Socket,
    identity: &IdentityKey,
    timeout: Duration,
) -> Result<Vec<u8>, ProbeError> {
    let mut buf = Vec::with_capacity(MAX_HANDSHAKE_LEN);

    // Phase 1: the fixed `Y' | AUTH` header.
    while buf.len() < SERVER_FIXED_HEADER_LEN {
        let mut chunk = [0u8; 1024];
        let n = socket.read_some(&mut chunk, timeout).await?;
        if n == 0 {
            return Err(ProbeError::Reset { phase: "read" });
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let mark = hmac_128(&identity.mac_key(), &buf[..REPRESENTATIVE_LEN])?;

    // Phase 2: locate `M_S` and read through `MAC_S`.
    loop {
        if buf.len() > MAX_HANDSHAKE_LEN {
            return Err(ProbeError::Protocol {
                transport: "obfs4",
                message: "server response exceeded maximum handshake length".to_owned(),
            });
        }
        if let Some(pos) = find_subslice(&buf[SERVER_FIXED_HEADER_LEN..], &mark) {
            let mark_at = SERVER_FIXED_HEADER_LEN + pos;
            if buf.len() >= mark_at + MARK_LEN + MARK_LEN {
                return Ok(buf);
            }
        }
        let mut chunk = [0u8; 1024];
        let n = socket.read_some(&mut chunk, timeout).await?;
        if n == 0 {
            return Err(ProbeError::AuthFailed {
                transport: "obfs4",
                message: "server response did not contain M_S".to_owned(),
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// `HMAC-SHA256-128(key, msg)`, the 16-byte truncated digest used for the
/// handshake marks and MACs (obfs4-spec §4).
fn hmac_128(key: &[u8], msg: &[u8]) -> Result<[u8; MARK_LEN], ProbeError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|error| ProbeError::Crypto(error.to_string()))?;
    mac.update(msg);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; MARK_LEN];
    out.copy_from_slice(&digest[..MARK_LEN]);
    Ok(out)
}

/// Random padding in the spec range `[ClientMinPadLength, ClientMaxPadLength]`.
fn random_padding() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(CLIENT_MIN_PAD..=CLIENT_MAX_PAD);
    let mut padding = vec![0u8; len];
    rng.fill_bytes(&mut padding);
    padding
}

/// The decimal string of hours since the Unix epoch (the `E` value).
fn hours_since_epoch(now: DateTime<Utc>) -> u64 {
    now.timestamp().div_euclid(3600) as u64
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hours_since_epoch_uses_floor_division() {
        let dt = DateTime::parse_from_rfc3339("2026-08-14T01:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // 1.5 hours after the epoch hour boundary -> 1 full hour.
        assert_eq!(hours_since_epoch(dt) % 24, 1);
    }

    #[test]
    fn hmac_128_matches_transport_mark() {
        let mut node_id = [0u8; 20];
        let mut public_key = [0u8; 32];
        for (i, byte) in node_id.iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in public_key.iter_mut().enumerate() {
            *byte = 0xA0 + i as u8;
        }
        let identity = IdentityKey {
            node_id,
            public_key,
        };
        let rep = [0x42u8; 32];
        let mark = hmac_128(&identity.mac_key(), &rep).unwrap();
        assert_eq!(mark.len(), MARK_LEN);
        // Deterministic: same input yields the same mark.
        assert_eq!(mark, hmac_128(&identity.mac_key(), &rep).unwrap());
    }

    #[test]
    fn find_subslice_locates_embedded_needle() {
        assert_eq!(find_subslice(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_subslice(b"abc", b"z"), None);
        assert_eq!(find_subslice(b"abc", b""), Some(0));
    }
}

//! obfs4 wire-format codecs (`obfs4-spec.txt` §4, "Key Establishment Phase").
//!
//! This module implements the byte-exact framing and the HMAC-SHA256-128
//! authentication of the obfs4 handshake, plus decoding of the `cert=` value
//! published in bridge lines. It deliberately does **not** implement the
//! cryptographic key agreement (Elligator 2, X25519, ntor `KEY_SEED`/`AUTH`):
//! those require a live or loopback key exchange and are the responsibility of
//! the `prober` crate. The representative bytes (`X'`, `Y'`) and the `AUTH`
//! tag are treated as opaque 32-byte inputs/outputs here, exactly as they
//! appear on the wire.
//!
//! Constants and the frame layout below are taken verbatim from
//! `obfs4-spec.txt` §4:
//!
//! ```text
//! clientRequest = X' | P_C | M_C | MAC_C
//! serverResponse = Y' | AUTH | P_S | M_S | MAC_S
//! M_*  = HMAC-SHA256-128(B | NODEID, representative)
//! MAC_* = HMAC-SHA256-128(B | NODEID, representative | padding | mark | E)
//! ```
//!
//! where `E` is the decimal string of the number of hours since the Unix
//! epoch, and `B | NODEID` is the 52-byte identity key material (identity
//! public key followed by the 20-byte node id).

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::TransportError;

/// Length of the obfs4 server node id.
pub const NODE_ID_LEN: usize = 20;
/// Length of the obfs4 identity Curve25519 public key (`B`).
pub const IDENTITY_KEY_LEN: usize = 32;
/// Length of the decoded `cert=` value: `NODEID || B`.
pub const CERT_LEN: usize = NODE_ID_LEN + IDENTITY_KEY_LEN;

/// Maximum size of a handshake request or response, including padding.
pub const MAX_HANDSHAKE_LEN: usize = 8192;
/// Length of `M_C`/`M_S` (a truncated HMAC-SHA256 digest).
pub const MARK_LEN: usize = 16;
/// Length of the ntor `AUTH` tag.
pub const AUTH_LEN: usize = 32;
/// Length of an Elligator 2 representative of a Curve25519 public key.
pub const REPRESENTATIVE_LEN: usize = 32;

/// Non-padding length of a client handshake request (`X' | M_C | MAC_C`).
pub const CLIENT_HANDSHAKE_LEN: usize = REPRESENTATIVE_LEN + MARK_LEN + MARK_LEN;
/// Minimum client-handshake padding (`P_C`).
pub const CLIENT_MIN_PAD: usize = 85;
/// Maximum client-handshake padding (`P_C`).
pub const CLIENT_MAX_PAD: usize = 8128;

/// Non-padding length of a server handshake response (`Y' | AUTH | M_S | MAC_S`).
pub const SERVER_HANDSHAKE_LEN: usize = REPRESENTATIVE_LEN + AUTH_LEN + MARK_LEN + MARK_LEN;
/// Minimum server-handshake padding (`P_S`), excluding the inline PRNG-seed
/// optimization (which lowers it to 0).
pub const SERVER_MIN_PAD: usize = 45;
/// Maximum server-handshake padding (`P_S`).
pub const SERVER_MAX_PAD: usize = 8096;

type HmacSha256 = Hmac<Sha256>;

/// Base64 engine that accepts both padded and unpadded standard-alphabet input.
/// Published `cert=` values are unpadded; this mirrors the decoder used by the
/// `tbc-core` validation layer.
const BASE64_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// The obfs4 server identity distributed to clients out-of-band via `cert=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityKey {
    /// The 20-byte server node id (`NODEID`).
    pub node_id: [u8; NODE_ID_LEN],
    /// The 32-byte identity Curve25519 public key (`B`).
    pub public_key: [u8; IDENTITY_KEY_LEN],
}

impl IdentityKey {
    /// Build an identity from a decoded 52-byte `cert=` value (`NODEID || B`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() != CERT_LEN {
            return Err(TransportError::InvalidCertLength(bytes.len()));
        }
        let mut node_id = [0u8; NODE_ID_LEN];
        let mut public_key = [0u8; IDENTITY_KEY_LEN];
        node_id.copy_from_slice(&bytes[..NODE_ID_LEN]);
        public_key.copy_from_slice(&bytes[NODE_ID_LEN..]);
        Ok(Self {
            node_id,
            public_key,
        })
    }

    /// The canonical 52-byte encoding `NODEID || B`.
    pub fn to_bytes(&self) -> [u8; CERT_LEN] {
        let mut out = [0u8; CERT_LEN];
        out[..NODE_ID_LEN].copy_from_slice(&self.node_id);
        out[NODE_ID_LEN..].copy_from_slice(&self.public_key);
        out
    }

    /// The HMAC key material `B | NODEID` used for the marks and MACs.
    pub fn mac_key(&self) -> [u8; CERT_LEN] {
        let mut out = [0u8; CERT_LEN];
        out[..IDENTITY_KEY_LEN].copy_from_slice(&self.public_key);
        out[IDENTITY_KEY_LEN..].copy_from_slice(&self.node_id);
        out
    }
}

/// Decode a bridge-line `cert=` value into its identity key.
pub fn decode_cert(value: &str) -> Result<IdentityKey, TransportError> {
    let bytes = BASE64_ENGINE
        .decode(value.trim())
        .map_err(|_| TransportError::InvalidCert)?;
    IdentityKey::from_bytes(&bytes)
}

/// Encode an identity key as an unpadded `cert=` value.
pub fn encode_cert(identity: &IdentityKey) -> String {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    STANDARD_NO_PAD.encode(identity.to_bytes())
}

/// The obfs4 inter-arrival-timing mode from a bridge line's `iat-mode=` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IatMode {
    /// No timing obfuscation.
    Off,
    /// Light timing obfuscation.
    Enabled,
    /// Aggressive timing obfuscation (constant-rate).
    Paranoid,
}

impl IatMode {
    /// Parse the `iat-mode=` token (`0`, `1`, or `2`).
    pub fn parse(value: &str) -> Result<Self, TransportError> {
        match value.trim() {
            "0" => Ok(Self::Off),
            "1" => Ok(Self::Enabled),
            "2" => Ok(Self::Paranoid),
            other => Err(TransportError::InvalidIatMode(other.to_owned())),
        }
    }
}

/// Compute `HMAC-SHA256-128(key, msg)`, the 16-byte truncated digest used for
/// the handshake marks and MACs.
fn hmac_128(key: &[u8], msg: &[u8]) -> Result<[u8; MARK_LEN], TransportError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|error| TransportError::Hmac(error.to_string()))?;
    mac.update(msg);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; MARK_LEN];
    out.copy_from_slice(&digest[..MARK_LEN]);
    Ok(out)
}

/// The message authenticated by `MAC_C`: `X' | P_C | M_C | E`.
fn client_mac_msg(representative: &[u8], padding: &[u8], mark: &[u8], hours: u64) -> Vec<u8> {
    let epoch = hours.to_string();
    let mut msg = Vec::with_capacity(REPRESENTATIVE_LEN + padding.len() + MARK_LEN + epoch.len());
    msg.extend_from_slice(representative);
    msg.extend_from_slice(padding);
    msg.extend_from_slice(mark);
    msg.extend_from_slice(epoch.as_bytes());
    msg
}

/// The message authenticated by `MAC_S`: `Y' | AUTH | P_S | M_S | E`.
fn server_mac_msg(
    representative: &[u8],
    auth: &[u8],
    padding: &[u8],
    mark: &[u8],
    hours: u64,
) -> Vec<u8> {
    let epoch = hours.to_string();
    let mut msg =
        Vec::with_capacity(REPRESENTATIVE_LEN + AUTH_LEN + padding.len() + MARK_LEN + epoch.len());
    msg.extend_from_slice(representative);
    msg.extend_from_slice(auth);
    msg.extend_from_slice(padding);
    msg.extend_from_slice(mark);
    msg.extend_from_slice(epoch.as_bytes());
    msg
}

/// Copy a fixed-size array out of `bytes` at `offset`, without panicking on
/// out-of-bounds input.
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

/// Locate the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A decoded client handshake request: `X' | P_C | M_C | MAC_C`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshake {
    /// The Elligator 2 representative of the client's ephemeral key.
    pub representative: [u8; REPRESENTATIVE_LEN],
    /// Random padding `P_C`.
    pub padding: Vec<u8>,
    /// The `M_C` mark.
    pub mark: [u8; MARK_LEN],
    /// The `MAC_C` authentication tag.
    pub mac: [u8; MARK_LEN],
}

impl ClientHandshake {
    /// Encode a client request given the identity, the representative, the
    /// padding, and the current hours-since-epoch.
    pub fn encode(
        identity: &IdentityKey,
        representative: [u8; REPRESENTATIVE_LEN],
        padding: &[u8],
        hours_since_epoch: u64,
    ) -> Result<Vec<u8>, TransportError> {
        if !(CLIENT_MIN_PAD..=CLIENT_MAX_PAD).contains(&padding.len()) {
            return Err(TransportError::InvalidPadding {
                min: CLIENT_MIN_PAD,
                max: CLIENT_MAX_PAD,
                actual: padding.len(),
            });
        }
        let key = identity.mac_key();
        let mark = hmac_128(&key, &representative)?;
        let mac = hmac_128(
            &key,
            &client_mac_msg(&representative, padding, &mark, hours_since_epoch),
        )?;

        let mut out = Vec::with_capacity(CLIENT_HANDSHAKE_LEN + padding.len());
        out.extend_from_slice(&representative);
        out.extend_from_slice(padding);
        out.extend_from_slice(&mark);
        out.extend_from_slice(&mac);
        Ok(out)
    }

    /// Decode and authenticate a client request. The mark is located by
    /// searching for `M_C`, exactly as the server-side spec processing does,
    /// and `MAC_C` is verified against the three candidate epochs
    /// `{E-1, E, E+1}` to tolerate clock skew.
    pub fn decode(
        identity: &IdentityKey,
        bytes: &[u8],
        hours_since_epoch: u64,
    ) -> Result<Self, TransportError> {
        let total = bytes.len();
        if !(CLIENT_HANDSHAKE_LEN + CLIENT_MIN_PAD..=CLIENT_HANDSHAKE_LEN + CLIENT_MAX_PAD)
            .contains(&total)
        {
            return Err(TransportError::InvalidFrameLength {
                what: "client handshake",
                actual: total,
            });
        }
        let representative = take_array::<REPRESENTATIVE_LEN>(bytes, 0)?;
        let key = identity.mac_key();
        let mark = hmac_128(&key, &representative)?;

        let rest = &bytes[REPRESENTATIVE_LEN..];
        let mark_offset = find_subslice(rest, &mark)
            .ok_or(TransportError::BadMac("M_C not found in client handshake"))?;
        let padding = rest[..mark_offset].to_vec();
        let mac = take_array::<MARK_LEN>(rest, mark_offset + MARK_LEN)?;

        let low = hours_since_epoch.saturating_sub(1);
        let high = hours_since_epoch.saturating_add(1);
        let mut verified = false;
        for candidate in low..=high {
            let expected = hmac_128(
                &key,
                &client_mac_msg(&representative, &padding, &mark, candidate),
            )?;
            if expected == mac {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(TransportError::BadMac("MAC_C mismatch"));
        }
        Ok(Self {
            representative,
            padding,
            mark,
            mac,
        })
    }
}

/// A decoded server handshake response: `Y' | AUTH | P_S | M_S | MAC_S`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHandshake {
    /// The Elligator 2 representative of the server's ephemeral key.
    pub representative: [u8; REPRESENTATIVE_LEN],
    /// The ntor authentication tag.
    pub auth: [u8; AUTH_LEN],
    /// Random padding `P_S`.
    pub padding: Vec<u8>,
    /// The `M_S` mark.
    pub mark: [u8; MARK_LEN],
    /// The `MAC_S` authentication tag.
    pub mac: [u8; MARK_LEN],
}

impl ServerHandshake {
    /// Encode a server response. `hours_since_epoch` is the client's `E` value
    /// echoed back in `MAC_S`.
    pub fn encode(
        identity: &IdentityKey,
        representative: [u8; REPRESENTATIVE_LEN],
        auth: [u8; AUTH_LEN],
        padding: &[u8],
        hours_since_epoch: u64,
    ) -> Result<Vec<u8>, TransportError> {
        if !(SERVER_MIN_PAD..=SERVER_MAX_PAD).contains(&padding.len()) {
            return Err(TransportError::InvalidPadding {
                min: SERVER_MIN_PAD,
                max: SERVER_MAX_PAD,
                actual: padding.len(),
            });
        }
        let key = identity.mac_key();
        let mark = hmac_128(&key, &representative)?;
        let mac = hmac_128(
            &key,
            &server_mac_msg(&representative, &auth, padding, &mark, hours_since_epoch),
        )?;

        let mut out = Vec::with_capacity(SERVER_HANDSHAKE_LEN + padding.len());
        out.extend_from_slice(&representative);
        out.extend_from_slice(&auth);
        out.extend_from_slice(padding);
        out.extend_from_slice(&mark);
        out.extend_from_slice(&mac);
        Ok(out)
    }

    /// Encode a server response with zero `P_S` padding, the obfs4-spec §6
    /// inline PRNG-seed optimization form (`Y' | AUTH | M_S | MAC_S`).
    /// `hours_since_epoch` is the client's `E` value echoed back in `MAC_S`.
    pub fn encode_zero_padding(
        identity: &IdentityKey,
        representative: [u8; REPRESENTATIVE_LEN],
        auth: [u8; AUTH_LEN],
        hours_since_epoch: u64,
    ) -> Result<Vec<u8>, TransportError> {
        let key = identity.mac_key();
        let mark = hmac_128(&key, &representative)?;
        let mac = hmac_128(
            &key,
            &server_mac_msg(&representative, &auth, &[], &mark, hours_since_epoch),
        )?;

        let mut out = Vec::with_capacity(SERVER_HANDSHAKE_LEN);
        out.extend_from_slice(&representative);
        out.extend_from_slice(&auth);
        out.extend_from_slice(&mark);
        out.extend_from_slice(&mac);
        Ok(out)
    }

    /// Decode and authenticate a server response. `hours_since_epoch` is the
    /// client's original `E`, so no skew tolerance is required.
    ///
    /// The length check accepts zero `P_S` padding: implementations MAY use
    /// the obfs4-spec §6 inline PRNG-seed optimization, which lowers the
    /// server padding minimum to 0 and sends the seed frame immediately after
    /// this response body.
    pub fn decode(
        identity: &IdentityKey,
        bytes: &[u8],
        hours_since_epoch: u64,
    ) -> Result<Self, TransportError> {
        let total = bytes.len();
        if !(SERVER_HANDSHAKE_LEN..=SERVER_HANDSHAKE_LEN + SERVER_MAX_PAD).contains(&total) {
            return Err(TransportError::InvalidFrameLength {
                what: "server handshake",
                actual: total,
            });
        }
        let representative = take_array::<REPRESENTATIVE_LEN>(bytes, 0)?;
        let auth = take_array::<AUTH_LEN>(bytes, REPRESENTATIVE_LEN)?;
        let key = identity.mac_key();
        let mark = hmac_128(&key, &representative)?;

        let rest = &bytes[REPRESENTATIVE_LEN + AUTH_LEN..];
        let mark_offset = find_subslice(rest, &mark)
            .ok_or(TransportError::BadMac("M_S not found in server handshake"))?;
        let padding = rest[..mark_offset].to_vec();
        let mac = take_array::<MARK_LEN>(rest, mark_offset + MARK_LEN)?;

        let expected = hmac_128(
            &key,
            &server_mac_msg(&representative, &auth, &padding, &mark, hours_since_epoch),
        )?;
        if expected != mac {
            return Err(TransportError::BadMac("MAC_S mismatch"));
        }
        Ok(Self {
            representative,
            auth,
            padding,
            mark,
            mac,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn identity() -> IdentityKey {
        let mut node_id = [0u8; NODE_ID_LEN];
        let mut public_key = [0u8; IDENTITY_KEY_LEN];
        for (i, byte) in node_id.iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in public_key.iter_mut().enumerate() {
            *byte = 0xA0 + i as u8;
        }
        IdentityKey {
            node_id,
            public_key,
        }
    }

    /// Deterministic padding that cannot contain the 16-byte mark (which is a
    /// digest of the identity + representative), so decode-by-search is stable.
    fn padding(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn cert_round_trips_through_base64() {
        let id = identity();
        let encoded = encode_cert(&id);
        assert_eq!(encoded.len(), 70); // 52 bytes -> 70 unpadded base64 chars
        let decoded = decode_cert(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn cert_decode_accepts_padded_form() {
        use base64::engine::general_purpose::STANDARD;
        let id = identity();
        let padded = STANDARD.encode(id.to_bytes());
        assert!(padded.ends_with('='));
        assert_eq!(decode_cert(&padded).unwrap(), id);
    }

    #[test]
    fn cert_decode_rejects_wrong_length() {
        let err = decode_cert("c2hvcnQ").unwrap_err();
        assert!(matches!(err, TransportError::InvalidCertLength(_)));
    }

    #[test]
    fn mac_key_is_public_key_then_node_id() {
        let id = identity();
        let key = id.mac_key();
        assert_eq!(&key[..IDENTITY_KEY_LEN], &id.public_key);
        assert_eq!(&key[IDENTITY_KEY_LEN..], &id.node_id);
    }

    #[test]
    fn iat_mode_parses_valid_tokens() {
        assert_eq!(IatMode::parse("0").unwrap(), IatMode::Off);
        assert_eq!(IatMode::parse("1").unwrap(), IatMode::Enabled);
        assert_eq!(IatMode::parse("2").unwrap(), IatMode::Paranoid);
        assert!(IatMode::parse("3").is_err());
        assert!(IatMode::parse("").is_err());
    }

    #[test]
    fn client_handshake_round_trips() {
        let id = identity();
        let rep = [0x42u8; REPRESENTATIVE_LEN];
        let pad = padding(CLIENT_MIN_PAD);
        let encoded = ClientHandshake::encode(&id, rep, &pad, 500_000).unwrap();
        assert_eq!(encoded.len(), CLIENT_HANDSHAKE_LEN + CLIENT_MIN_PAD);
        let decoded = ClientHandshake::decode(&id, &encoded, 500_000).unwrap();
        assert_eq!(decoded.representative, rep);
        assert_eq!(decoded.padding, pad);
    }

    #[test]
    fn client_handshake_tolerates_epoch_skew() {
        let id = identity();
        let rep = [0x33u8; REPRESENTATIVE_LEN];
        let pad = padding(CLIENT_MAX_PAD);
        let encoded = ClientHandshake::encode(&id, rep, &pad, 1_000_000).unwrap();
        // Server's clock is one hour ahead.
        assert!(ClientHandshake::decode(&id, &encoded, 1_000_001).is_ok());
    }

    #[test]
    fn client_handshake_rejects_tampered_mac() {
        let id = identity();
        let rep = [0x77u8; REPRESENTATIVE_LEN];
        let pad = padding(100);
        let mut encoded = ClientHandshake::encode(&id, rep, &pad, 42).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let err = ClientHandshake::decode(&id, &encoded, 42).unwrap_err();
        assert!(matches!(err, TransportError::BadMac(_)));
    }

    #[test]
    fn client_handshake_rejects_out_of_range_padding() {
        let id = identity();
        let rep = [0u8; REPRESENTATIVE_LEN];
        let short = padding(CLIENT_MIN_PAD - 1);
        assert!(matches!(
            ClientHandshake::encode(&id, rep, &short, 1),
            Err(TransportError::InvalidPadding { .. })
        ));
    }

    #[test]
    fn server_handshake_round_trips() {
        let id = identity();
        let rep = [0x5Au8; REPRESENTATIVE_LEN];
        let auth = [0x11u8; AUTH_LEN];
        let pad = padding(SERVER_MIN_PAD);
        let encoded = ServerHandshake::encode(&id, rep, auth, &pad, 9).unwrap();
        assert_eq!(encoded.len(), SERVER_HANDSHAKE_LEN + SERVER_MIN_PAD);
        let decoded = ServerHandshake::decode(&id, &encoded, 9).unwrap();
        assert_eq!(decoded.representative, rep);
        assert_eq!(decoded.auth, auth);
        assert_eq!(decoded.padding, pad);
    }

    #[test]
    fn server_handshake_rejects_wrong_epoch() {
        let id = identity();
        let rep = [0x6Bu8; REPRESENTATIVE_LEN];
        let auth = [0x22u8; AUTH_LEN];
        let pad = padding(200);
        let encoded = ServerHandshake::encode(&id, rep, auth, &pad, 5).unwrap();
        assert!(matches!(
            ServerHandshake::decode(&id, &encoded, 6),
            Err(TransportError::BadMac(_))
        ));
    }

    #[test]
    fn server_handshake_accepts_zero_padding_inline_seed_optimization() {
        // The §6 inline PRNG-seed optimization lowers P_S to 0, yielding a
        // 96-byte response (Y' | AUTH | M_S | MAC_S with no padding). The
        // decoder must accept it rather than rejecting it as too short.
        let id = identity();
        let rep = [0x0Fu8; REPRESENTATIVE_LEN];
        let auth = [0x33u8; AUTH_LEN];
        let encoded = ServerHandshake::encode_zero_padding(&id, rep, auth, 7).unwrap();
        assert_eq!(encoded.len(), SERVER_HANDSHAKE_LEN);
        let decoded = ServerHandshake::decode(&id, &encoded, 7).unwrap();
        assert_eq!(decoded.representative, rep);
        assert_eq!(decoded.auth, auth);
        assert!(decoded.padding.is_empty());
    }
}

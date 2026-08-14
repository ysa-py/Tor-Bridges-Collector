//! Cross-codec integration tests for `tbc-transports`.
//!
//! These exercise the codecs together with the `tbc-core` bridge model: a real
//! published bridge line is parsed and its `cert=` value is fed through the
//! obfs4 identity decoder, and a full handshake request/response pair is
//! encoded, decoded, and authenticated end-to-end.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use proptest::prelude::*;
use tbc_core::BridgeLine;
use tbc_transports::obfs4::{
    ClientHandshake, IdentityKey, ServerHandshake, AUTH_LEN, CLIENT_HANDSHAKE_LEN, CLIENT_MIN_PAD,
    REPRESENTATIVE_LEN, SERVER_HANDSHAKE_LEN, SERVER_MIN_PAD,
};
use tbc_transports::{MeekRequest, MeekResponse, VersionsCell};

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

/// A deterministic identity: node id `0x00..0x13`, public key `0xA0..0xBF`.
fn identity() -> IdentityKey {
    let mut node_id = [0u8; 20];
    let mut public_key = [0u8; 32];
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

fn cert52() -> String {
    STANDARD_NO_PAD.encode([0x5Au8; 52])
}

/// Deterministic padding that cannot contain the handshake mark (the mark is a
/// digest of the identity key and representative, so a low-period counter
/// pattern avoids the search ambiguity).
fn padding(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn parses_published_bridge_cert_into_identity() {
    // A representative obfs4 line from the published bridge lists; the cert is
    // the standard 52-byte `NODEID || B` value.
    let line = format!(
        "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 cert={} iat-mode=0",
        cert52()
    );
    let bridge = BridgeLine::parse(&line, now()).unwrap();
    let identity = tbc_transports::bridge::obfs4_identity(&bridge).unwrap();
    assert_eq!(identity.node_id, [0x5Au8; 20]);
    assert_eq!(identity.public_key, [0x5Au8; 32]);
    assert_eq!(tbc_transports::obfs4::encode_cert(&identity), cert52());
}

#[test]
fn full_obfs4_handshake_round_trips_across_frames() {
    let identity = identity();
    let client_rep = [0x11u8; REPRESENTATIVE_LEN];
    let server_rep = [0x22u8; REPRESENTATIVE_LEN];
    let auth = [0x33u8; AUTH_LEN];
    let hours = 505_000;

    let request =
        ClientHandshake::encode(&identity, client_rep, &padding(CLIENT_MIN_PAD), hours).unwrap();
    assert_eq!(request.len(), CLIENT_HANDSHAKE_LEN + CLIENT_MIN_PAD);

    let decoded_request = ClientHandshake::decode(&identity, &request, hours).unwrap();
    assert_eq!(decoded_request.representative, client_rep);

    let response =
        ServerHandshake::encode(&identity, server_rep, auth, &padding(SERVER_MIN_PAD), hours)
            .unwrap();
    assert_eq!(response.len(), SERVER_HANDSHAKE_LEN + SERVER_MIN_PAD);

    let decoded_response = ServerHandshake::decode(&identity, &response, hours).unwrap();
    assert_eq!(decoded_response.representative, server_rep);
    assert_eq!(decoded_response.auth, auth);
}

#[test]
fn obfs4_frames_reject_wrong_identity() {
    let request = ClientHandshake::encode(
        &identity(),
        [0x44u8; REPRESENTATIVE_LEN],
        &padding(CLIENT_MIN_PAD),
        7,
    )
    .unwrap();

    let mut other = identity();
    other.node_id[0] ^= 0xFF;
    assert!(ClientHandshake::decode(&other, &request, 7).is_err());
}

#[test]
fn meek_envelope_round_trips_response_body() {
    let request = MeekRequest::new(
        "cdn.example.com".to_owned(),
        [0x09u8; 16],
        b"payload".to_vec(),
    );
    let encoded = request.encode().unwrap();
    let text = String::from_utf8(encoded).unwrap();
    assert!(text.contains("Host: cdn.example.com\r\n"));
    assert!(text.contains("X-Session-Id: "));

    let response =
        MeekResponse::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong").unwrap();
    assert!(response.is_success());
    assert_eq!(response.body, b"pong");
}

proptest! {
    #[test]
    fn versions_cell_round_trips_any_version_list(versions in prop::collection::vec(1u16..0xFFFF, 0..20)) {
        let cell = VersionsCell { versions: versions.clone() }.to_cell(0).unwrap();
        let decoded = VersionsCell::from_cell(&cell).unwrap();
        prop_assert_eq!(decoded.versions, versions);
    }
}

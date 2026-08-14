//! Loopback integration tests for the prober.
//!
//! Each test stands up a small in-process server stub that implements the
//! *server side* of one transport handshake (using the same `tbc-transports`
//! codecs the probe drives), then asserts the prober's verdict. These stubs
//! are test fixtures — never real network data — and they exercise the
//! framing the transports crate implements; the obfs4 `AUTH` field is left
//! opaque because the ntor key establishment is out of scope (see
//! `docs/PROGRESS.md`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use tbc_core::{BridgeLine, Clock, TestClock, TransportKind, Verdict};
use tbc_prober::probe::webtunnel::websocket_accept;
use tbc_prober::ProbeConfig;
use tbc_prober::Prober;
use tbc_transports::obfs4::{
    encode_cert, ClientHandshake, IdentityKey, ServerHandshake, MARK_LEN, MAX_HANDSHAKE_LEN,
    REPRESENTATIVE_LEN,
};
use tbc_transports::vanilla::{Cell, NetinfoCell, VersionsCell, CELL_LEN};

const FINGERPRINT: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

fn test_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn hours_since_epoch(now: DateTime<Utc>) -> u64 {
    now.timestamp().div_euclid(3600) as u64
}

fn test_identity() -> IdentityKey {
    IdentityKey {
        node_id: [0u8; 20],
        public_key: [0xAAu8; 32],
    }
}

fn other_identity() -> IdentityKey {
    IdentityKey {
        node_id: [1u8; 20],
        public_key: [0xBBu8; 32],
    }
}

fn config(max_attempts: u32) -> ProbeConfig {
    ProbeConfig {
        connect_timeout: Duration::from_secs(3),
        read_timeout: Duration::from_secs(2),
        write_timeout: Duration::from_secs(2),
        max_attempts,
        backoff_base: Duration::from_millis(1),
        backoff_max: Duration::from_millis(5),
        max_bridges_per_run: 1024,
    }
}

fn prober(clock: TestClock) -> Prober {
    let clock: Arc<dyn Clock> = Arc::new(clock);
    Prober::new(config(1), clock).unwrap()
}

async fn closed_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn hmac_128(key: &[u8], msg: &[u8]) -> Result<[u8; MARK_LEN], String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|error| error.to_string())?;
    mac.update(msg);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; MARK_LEN];
    out.copy_from_slice(&digest[..MARK_LEN]);
    Ok(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_header(text: &str, name: &str) -> Option<String> {
    for line in text.split("\r\n") {
        if let Some((header_name, value)) = line.split_once(':') {
            if header_name.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim().to_owned());
            }
        }
    }
    None
}

async fn read_until_header_end(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    loop {
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        let mut chunk = [0u8; 512];
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF before HTTP header end".to_owned());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn read_obfs4_client_request(
    stream: &mut TcpStream,
    identity: &IdentityKey,
) -> Result<Vec<u8>, String> {
    let mut head = [0u8; REPRESENTATIVE_LEN];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|error| error.to_string())?;
    let mark = hmac_128(&identity.mac_key(), &head)?;
    let mut buf = head.to_vec();
    loop {
        if let Some(pos) = find_subslice(&buf[REPRESENTATIVE_LEN..], &mark) {
            let mark_at = REPRESENTATIVE_LEN + pos;
            if buf.len() >= mark_at + MARK_LEN + MARK_LEN {
                return Ok(buf);
            }
        }
        if buf.len() > MAX_HANDSHAKE_LEN {
            return Err("client request exceeded maximum handshake length".to_owned());
        }
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF before M_C".to_owned());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Serve one obfs4 framing handshake, validating the client request and
/// responding with a well-formed (correctly marked) server response.
async fn serve_obfs4(identity: IdentityKey, hours: u64) -> (u16, JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let request = read_obfs4_client_request(&mut stream, &identity).await?;
        ClientHandshake::decode(&identity, &request, hours).map_err(|e| e.to_string())?;
        let response =
            ServerHandshake::encode(&identity, [0x42u8; 32], [0x11u8; 32], &[0u8; 45], hours)
                .map_err(|e| e.to_string())?;
        stream
            .write_all(&response)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, handle)
}

/// Serve an obfs4 response whose `MAC_S` is tampered (a forged responder).
async fn serve_obfs4_tampered(
    identity: IdentityKey,
    hours: u64,
) -> (u16, JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let request = read_obfs4_client_request(&mut stream, &identity).await?;
        ClientHandshake::decode(&identity, &request, hours).map_err(|e| e.to_string())?;
        let mut response =
            ServerHandshake::encode(&identity, [0x42u8; 32], [0x11u8; 32], &[0u8; 45], hours)
                .map_err(|e| e.to_string())?;
        let last = response.len() - 1;
        response[last] ^= 0x01;
        stream
            .write_all(&response)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, handle)
}

/// Serve an obfs4 response signed with a *different* identity (an attacker
/// that does not possess the published key).
async fn serve_obfs4_wrong_identity(
    real: IdentityKey,
    wrong: IdentityKey,
    hours: u64,
) -> (u16, JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let request = read_obfs4_client_request(&mut stream, &real).await?;
        ClientHandshake::decode(&real, &request, hours).map_err(|e| e.to_string())?;
        let response =
            ServerHandshake::encode(&wrong, [0x42u8; 32], [0x11u8; 32], &[0u8; 45], hours)
                .map_err(|e| e.to_string())?;
        stream
            .write_all(&response)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, handle)
}

/// Serve a vanilla ORPort `VERSIONS` + `NETINFO` handshake.
async fn serve_vanilla() -> (u16, JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let mut bytes = [0u8; CELL_LEN];

        stream
            .read_exact(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        let versions = VersionsCell::from_cell(&Cell::decode(&bytes).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        assert!(!versions.versions.is_empty());
        let response = VersionsCell {
            versions: vec![3, 4, 5],
        }
        .to_cell(0)
        .map_err(|e| e.to_string())?;
        stream
            .write_all(&response.encode())
            .await
            .map_err(|e| e.to_string())?;

        stream
            .read_exact(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        let netinfo = NetinfoCell::from_cell(&Cell::decode(&bytes).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let _ = netinfo;
        let response = NetinfoCell {
            timestamp: 1_700_000_000,
            other_addr: None,
            my_addrs: Vec::new(),
        }
        .to_cell(0)
        .map_err(|e| e.to_string())?;
        stream
            .write_all(&response.encode())
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, handle)
}

/// Serve a single PADDING cell (not a Tor responder), then close.
async fn serve_not_tor() -> (u16, JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let cell = Cell::new(0, 0, &[]).map_err(|e| e.to_string())?;
        stream
            .write_all(&cell.encode())
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, handle)
}

/// Serve a WebTunnel HTTP upgrade response with the given status, optionally
/// returning a wrong `Sec-WebSocket-Accept` value.
async fn serve_webtunnel(status: u16, wrong_accept: bool) -> (u16, JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let request = read_until_header_end(&mut stream).await?;
        let text = String::from_utf8(request).map_err(|e| e.to_string())?;
        let key = find_header(&text, "Sec-WebSocket-Key").ok_or("missing Sec-WebSocket-Key")?;
        let mut accept = websocket_accept(&key);
        if wrong_accept {
            accept = "wrong-accept-value".to_owned();
        }
        let response = if status == 101 {
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
        } else {
            format!("HTTP/1.1 {status} Forbidden\r\nContent-Length: 0\r\n\r\n")
        };
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, handle)
}

/// Serve a meek `200 OK` envelope.
async fn serve_meek() -> (u16, JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let _request = read_until_header_end(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, handle)
}

/// Serve a Snowflake broker poll response.
async fn serve_snowflake() -> (u16, JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let _request = read_until_header_end(&mut stream).await?;
        let body = r#"{"Status":"no match"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, handle)
}

// ── obfs4 ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn obfs4_handshake_succeeds_against_framing_stub() {
    let identity = test_identity();
    let now = test_now();
    let hours = hours_since_epoch(now);
    let (port, server) = serve_obfs4(identity, hours).await;
    let cert = encode_cert(&identity);
    let line = format!("obfs4 127.0.0.1:{port} {FINGERPRINT} cert={cert} iat-mode=0");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::Reachable);
    assert_eq!(result.attempts, 1);
    assert!(result.outcome.rtt_ms.is_some());

    let server_result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(server_result.is_ok());
}

#[tokio::test]
async fn obfs4_handshake_rejects_tampered_mac() {
    let identity = test_identity();
    let now = test_now();
    let hours = hours_since_epoch(now);
    let (port, server) = serve_obfs4_tampered(identity, hours).await;
    let cert = encode_cert(&identity);
    let line = format!("obfs4 127.0.0.1:{port} {FINGERPRINT} cert={cert} iat-mode=0");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::HandshakeAuthFail);
    assert_eq!(result.attempts, 1);

    let _ = server.await;
}

#[tokio::test]
async fn obfs4_handshake_rejects_wrong_identity() {
    let identity = test_identity();
    let now = test_now();
    let hours = hours_since_epoch(now);
    let (port, server) = serve_obfs4_wrong_identity(identity, other_identity(), hours).await;
    let cert = encode_cert(&identity);
    let line = format!("obfs4 127.0.0.1:{port} {FINGERPRINT} cert={cert} iat-mode=0");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::HandshakeAuthFail);

    let _ = server.await;
}

#[tokio::test]
async fn obfs4_handshake_times_out_against_a_silent_peer() {
    let identity = test_identity();
    let now = test_now();
    let cert = encode_cert(&identity);

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let line = format!("obfs4 127.0.0.1:{port} {FINGERPRINT} cert={cert} iat-mode=0");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let mut cfg = config(1);
    cfg.read_timeout = Duration::from_millis(200);
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now));
    let result = Prober::new(cfg, clock).unwrap().probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::Timeout);

    server.abort();
}

// ── vanilla ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn vanilla_handshake_succeeds() {
    let now = test_now();
    let (port, server) = serve_vanilla().await;
    let line = format!("127.0.0.1:{port} {FINGERPRINT}");
    let bridge = BridgeLine::parse(&line, now).unwrap();
    assert_eq!(bridge.transport, TransportKind::Vanilla);

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::Reachable);
    assert!(result
        .outcome
        .evidence
        .as_deref()
        .unwrap()
        .contains("VERSIONS"));

    let server_result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(server_result.is_ok());
}

#[tokio::test]
async fn vanilla_rejects_a_non_tor_responder() {
    let now = test_now();
    let (port, server) = serve_not_tor().await;
    let line = format!("127.0.0.1:{port} {FINGERPRINT}");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert!(!matches!(result.outcome.verdict, Verdict::Reachable));

    let _ = server.await;
}

// ── WebTunnel ────────────────────────────────────────────────────────────

#[tokio::test]
async fn webtunnel_upgrade_succeeds() {
    let now = test_now();
    let (port, server) = serve_webtunnel(101, false).await;
    let line =
        format!("webtunnel 127.0.0.1:{port} {FINGERPRINT} url=https://127.0.0.1/path ver=0.0.3");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::Reachable);
    assert!(result.outcome.evidence.as_deref().unwrap().contains("101"));

    let server_result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(server_result.is_ok());
}

#[tokio::test]
async fn webtunnel_rejects_wrong_accept() {
    let now = test_now();
    let (port, server) = serve_webtunnel(101, true).await;
    let line =
        format!("webtunnel 127.0.0.1:{port} {FINGERPRINT} url=https://127.0.0.1/path ver=0.0.3");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::HandshakeAuthFail);

    let _ = server.await;
}

#[tokio::test]
async fn webtunnel_maps_http_error_status() {
    let now = test_now();
    let (port, server) = serve_webtunnel(403, false).await;
    let line =
        format!("webtunnel 127.0.0.1:{port} {FINGERPRINT} url=https://127.0.0.1/path ver=0.0.3");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::HttpError { code: 403 });

    let _ = server.await;
}

// ── meek / Snowflake ─────────────────────────────────────────────────────

#[tokio::test]
async fn meek_post_envelope_succeeds() {
    let now = test_now();
    let (port, server) = serve_meek().await;
    let line =
        format!("meek 127.0.0.1:{port} {FINGERPRINT} url=http://127.0.0.1:{port}/ front=127.0.0.1");
    let bridge = BridgeLine::parse(&line, now).unwrap();
    assert_eq!(bridge.transport, TransportKind::Meek);

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::Reachable);

    let server_result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(server_result.is_ok());
}

#[tokio::test]
async fn snowflake_broker_poll_succeeds() {
    let now = test_now();
    let (port, server) = serve_snowflake().await;
    let line = format!("snowflake 127.0.0.1:{port} {FINGERPRINT} url=http://127.0.0.1:{port}/");
    let bridge = BridgeLine::parse(&line, now).unwrap();
    assert_eq!(bridge.transport, TransportKind::Snowflake);

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::Reachable);
    assert!(result
        .outcome
        .evidence
        .as_deref()
        .unwrap()
        .contains("broker"));

    let server_result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(server_result.is_ok());
}

// ── policy / budget ──────────────────────────────────────────────────────

#[tokio::test]
async fn connection_refused_maps_to_refused() {
    let now = test_now();
    let port = closed_port().await;
    let line = format!("127.0.0.1:{port} {FINGERPRINT}");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::Refused);
}

#[tokio::test]
async fn unsupported_transport_yields_inconclusive() {
    let now = test_now();
    let line = format!("conjure 127.0.0.1:443 {FINGERPRINT}");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let result = prober(TestClock::new(now)).probe_bridge(&bridge).await;
    assert_eq!(result.outcome.verdict, Verdict::Inconclusive);
    assert_eq!(
        result.outcome.error_class.as_deref(),
        Some("unsupported_transport")
    );
    assert_eq!(result.attempts, 0);
}

#[tokio::test]
async fn probe_many_respects_budget() {
    let now = test_now();
    let port = closed_port().await;
    let line = format!("127.0.0.1:{port} {FINGERPRINT}");
    let bridge = BridgeLine::parse(&line, now).unwrap();

    let mut cfg = config(1);
    cfg.max_bridges_per_run = 2;
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now));
    let prober = Prober::new(cfg, clock).unwrap();

    let report = prober
        .probe_many(&[bridge.clone(), bridge.clone(), bridge.clone()])
        .await;
    assert_eq!(report.results.len(), 2);
    assert!(report.budget_exhausted);
    assert_eq!(report.skipped, 1);
}

#[test]
fn invalid_config_is_rejected() {
    let now = test_now();
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now));
    let mut cfg = config(1);
    cfg.max_attempts = 0;
    assert!(Prober::new(cfg, clock).is_err());
}

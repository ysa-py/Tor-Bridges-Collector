//! Integration tests for the volunteer agent.
//!
//! These tests exercise the real HTTP server over loopback sockets and the
//! real probe engine against loopback listeners. The only outbound traffic is
//! a single `*.invalid` DNS query (guaranteed NXDOMAIN per RFC 2606); no real
//! bridge, obfs4, Globalping, RIPE Atlas, or OONI endpoint is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use tbc_agent::{AgentConfig, AgentServer, ProbeEngine, ProbeRequest, ReportSource};
use tbc_core::ProbeKind;

fn probe_request(target: &str, port: u16, kind: ProbeKind) -> ProbeRequest {
    ProbeRequest {
        target: target.to_owned(),
        port,
        probe_kind: kind,
    }
}

/// Bind a listener that accepts exactly one connection then exits, and return
/// its port. The port therefore stays open until that connection arrives.
async fn open_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _accepted = listener.accept().await;
    });
    port
}

/// Bind a listener and immediately drop it to obtain a port with nothing
/// listening.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn localhost_config() -> AgentConfig {
    AgentConfig {
        bind_host: "127.0.0.1".to_owned(),
        bind_port: 0,
        connect_timeout: Duration::from_secs(3),
        ..AgentConfig::default()
    }
}

async fn start_server(config: AgentConfig) -> (u16, tokio::task::JoinHandle<()>) {
    let server = AgentServer::new(config).unwrap();
    server.grant_consent("test");
    let listener = server.bind().await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let _ = server.run(listener).await;
    });
    (port, handle)
}

/// Send one raw HTTP request and read the response to EOF (the agent closes
/// every connection after responding). Returns `(status, json_body)`.
async fn round_trip(port: u16, raw_request: &[u8]) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(raw_request).await.unwrap();
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let text = String::from_utf8(buffer).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let json = serde_json::from_slice(body.as_bytes()).unwrap();
    (status, json)
}

fn http_post(body: &str) -> Vec<u8> {
    format!(
        "POST /probe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

#[tokio::test]
async fn engine_reports_reachable_for_an_open_port() {
    let port = open_port().await;
    let engine = ProbeEngine::new(Duration::from_secs(3), "agent".to_owned()).unwrap();
    engine.grant_consent("test");
    let response = engine
        .probe(&probe_request("127.0.0.1", port, ProbeKind::TcpConnect))
        .await
        .unwrap();
    assert_eq!(response.verdict, "reachable");
    assert!(response.rtt_ms.is_some());
    assert!(response.error_class.is_none());
}

#[tokio::test]
async fn engine_reports_refused_for_a_closed_port() {
    let port = closed_port().await;
    let engine = ProbeEngine::new(Duration::from_secs(3), "agent".to_owned()).unwrap();
    engine.grant_consent("test");
    let response = engine
        .probe(&probe_request("127.0.0.1", port, ProbeKind::TcpConnect))
        .await
        .unwrap();
    assert_eq!(response.verdict, "refused");
    assert_eq!(response.error_class.as_deref(), Some("connection_refused"));
    assert!(response.evidence.is_some());
}

#[tokio::test]
async fn engine_reports_non_reachable_for_a_bogus_dns_name() {
    let engine = ProbeEngine::new(Duration::from_secs(3), "agent".to_owned()).unwrap();
    engine.grant_consent("test");
    let response = engine
        .probe(&probe_request(
            "nonexistent.invalid",
            443,
            ProbeKind::TcpConnect,
        ))
        .await
        .unwrap();
    assert_ne!(response.verdict, "reachable");
    assert!(response.error_class.is_some());
}

#[tokio::test]
async fn server_round_trip_reports_refused_for_a_closed_port() {
    let target = closed_port().await;
    let (port, handle) = start_server(localhost_config()).await;

    let body = serde_json::json!({
        "target": "127.0.0.1",
        "port": target,
        "probe_kind": "tcp_connect"
    });
    let (status, json) = round_trip(port, &http_post(&body.to_string())).await;

    assert_eq!(status, 200);
    assert_eq!(json["verdict"], "refused");
    assert_eq!(json["error_class"], "connection_refused");
    assert!(json["measurement_ref"]
        .as_str()
        .unwrap()
        .starts_with("agent-"));

    handle.abort();
}

#[tokio::test]
async fn server_returns_405_for_wrong_method() {
    let (port, handle) = start_server(localhost_config()).await;

    let raw = b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let (status, json) = round_trip(port, raw).await;

    assert_eq!(status, 405);
    assert_eq!(json["error"], "method_not_allowed");

    handle.abort();
}

#[tokio::test]
async fn server_returns_404_for_unknown_path() {
    let (port, handle) = start_server(localhost_config()).await;

    let raw = b"POST /other HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}";
    let (status, json) = round_trip(port, raw).await;

    assert_eq!(status, 404);
    assert_eq!(json["error"], "not_found");

    handle.abort();
}

#[tokio::test]
async fn server_returns_400_for_invalid_json() {
    let (port, handle) = start_server(localhost_config()).await;

    let raw = b"POST /probe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 9\r\n\r\nnot json!";
    let (status, json) = round_trip(port, raw).await;

    assert_eq!(status, 400);
    assert_eq!(json["error"], "invalid_json");

    handle.abort();
}

#[tokio::test]
async fn server_returns_422_for_unsupported_probe_kind() {
    let (port, handle) = start_server(localhost_config()).await;

    let body = serde_json::json!({
        "target": "127.0.0.1",
        "port": 443,
        "probe_kind": "tls_sni"
    });
    let (status, json) = round_trip(port, &http_post(&body.to_string())).await;

    assert_eq!(status, 422);
    assert_eq!(json["error"], "unsupported_probe_kind");

    handle.abort();
}

#[tokio::test]
async fn server_rate_limits_after_the_configured_burst() {
    let config = AgentConfig {
        rate_limit_burst: 2,
        ..localhost_config()
    };
    let target = closed_port().await;
    let (port, handle) = start_server(config).await;

    let body = serde_json::json!({
        "target": "127.0.0.1",
        "port": target,
        "probe_kind": "tcp_connect"
    });
    let raw = http_post(&body.to_string());

    let first = round_trip(port, &raw).await;
    let second = round_trip(port, &raw).await;
    let third = round_trip(port, &raw).await;

    assert_eq!(first.0, 200);
    assert_eq!(second.0, 200);
    assert_eq!(third.0, 429);
    assert_eq!(third.1["error"], "rate_limited");

    handle.abort();
}

#[tokio::test]
async fn engine_refuses_to_probe_without_consent() {
    let engine = ProbeEngine::new(Duration::from_secs(3), "agent".to_owned()).unwrap();
    let error = engine
        .probe(&probe_request("127.0.0.1", 9, ProbeKind::TcpConnect))
        .await
        .unwrap_err();
    assert_eq!(error.kind_name(), "consent_required");
}

#[tokio::test]
async fn engine_probe_report_emits_only_allowlisted_fields() {
    let port = open_port().await;
    let engine = ProbeEngine::new(Duration::from_secs(3), "agent".to_owned()).unwrap();
    engine.grant_consent("test");
    let report = engine
        .probe_report(
            &probe_request("127.0.0.1", port, ProbeKind::TcpConnect),
            Some(197_207),
        )
        .await
        .unwrap();
    let json = serde_json::to_value(&report).unwrap();
    let object = json.as_object().unwrap();
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["asn_class", "outcome", "rtt_bucket", "source", "token"]
    );
    assert_eq!(object["outcome"], "success");
    assert_eq!(object["asn_class"], "large");
    assert_eq!(object["source"], "phase5_volunteer");
    assert!(object.get("rtt_ms").is_none());
    assert!(object.get("evidence").is_none());
    assert!(object.get("measurement_ref").is_none());
}

#[tokio::test]
async fn server_withholds_and_emits_reports_at_k_threshold() {
    let config = AgentConfig {
        bind_host: "127.0.0.1".to_owned(),
        bind_port: 0,
        k_anonymity_threshold: 2,
        ..AgentConfig::default()
    };
    let server = AgentServer::new(config).unwrap();
    server.grant_consent("test");
    let listener = server.bind().await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_task = server.clone();
    let handle = tokio::spawn(async move {
        let _ = server_task.run(listener).await;
    });

    let target = closed_port().await;
    let body = serde_json::json!({
        "target": "127.0.0.1",
        "port": target,
        "probe_kind": "tcp_connect"
    });
    let raw = http_post(&body.to_string());

    let first = round_trip(port, &raw).await;
    assert_eq!(first.0, 200);
    assert_eq!(server.held_reports(), 1);
    assert_eq!(server.emitted_batches(), 0);

    let second = round_trip(port, &raw).await;
    assert_eq!(second.0, 200);
    assert_eq!(server.held_reports(), 0);

    let batches = server.take_emitted_batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].len(), 2);
    assert_eq!(batches[0][0].source, ReportSource::Phase5Volunteer);

    handle.abort();
}

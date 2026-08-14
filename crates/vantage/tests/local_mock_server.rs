//! End-to-end tests for the four in-country measurement adapters against a
//! **local HTTP server** using the real production [`ReqwestTransport`].
//!
//! This is the "real invocation against whatever CI CAN reach" gate from the
//! Item 4 directive: the adapters speak real HTTP/1.1 over a real TCP socket
//! (request building, header/body encoding, response reading, status
//! classification, JSON deserialization, and verdict normalization), with the
//! server scripting the platform's documented response shape.
//!
//! ## Honest label (required by the directive)
//!
//! This is a **local simulation of each platform's response shape, NOT the
//! live Iranian endpoint**. It proves the client-side adapter logic end to
//! end; it does **not** prove that a real Iranian vantage point (RIPE Atlas
//! in-country probe, a volunteer agent inside Iran, or Globalping's global
//! probe network) would return these bytes. Live Iranian reachability is the
//! manual out-of-CI gate documented in `examples/vantage_probe.rs` and in the
//! Item 4 table.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tbc_core::{ProbeKind, Verdict};
use tbc_vantage::{
    AgentVantage, Budget, GlobalpingVantage, MeasurementRequest, OoniVantage, ReqwestTransport,
    RipeAtlasVantage, Vantage,
};

/// A single parsed HTTP request received by the local mock server.
#[derive(Debug, Clone)]
struct IncomingRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

/// A canned HTTP response the mock server writes back.
#[derive(Debug)]
struct MockResponse {
    status: u16,
    body: Vec<u8>,
    delay: Option<Duration>,
}

impl MockResponse {
    fn json(status: u16, body: serde_json::Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&body).unwrap(),
            delay: None,
        }
    }

    fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.as_bytes().to_vec(),
            delay: None,
        }
    }

    fn delayed(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

type Handler = Box<dyn Fn(&IncomingRequest) -> MockResponse + Send + Sync + 'static>;

/// A minimal single-threaded HTTP/1.1 server bound to an ephemeral loopback
/// port, used to script platform responses for the adapters.
struct MockServer {
    base_url: String,
    shutdown: Arc<AtomicBool>,
    recorded: Arc<Mutex<Vec<IncomingRequest>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn start(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");

        let shutdown = Arc::new(AtomicBool::new(false));
        let recorded: Arc<Mutex<Vec<IncomingRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let thread_shutdown = shutdown.clone();
        let thread_recorded = recorded.clone();

        let handle = thread::spawn(move || loop {
            if thread_shutdown.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let Some(request) = read_request(&mut stream) else {
                        continue;
                    };
                    thread_recorded.lock().unwrap().push(request.clone());
                    write_response(&mut stream, handler(&request));
                }
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        });

        Self {
            base_url,
            shutdown,
            recorded,
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn recorded(&self) -> Vec<IncomingRequest> {
        self.recorded.lock().unwrap().clone()
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one HTTP/1.1 request (head + `Content-Length` body) from a stream.
fn read_request(stream: &mut TcpStream) -> Option<IncomingRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > 1_000_000 {
            return None;
        }
    }

    let head_end = buffer.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&buffer[..head_end]);
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut content_length = 0usize;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = buffer[head_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Some(IncomingRequest {
        method,
        path,
        body,
        headers,
    })
}

/// Write one HTTP/1.1 response (optionally after a scripted delay, which the
/// timeout test uses to prove the client's real deadline).
fn write_response(stream: &mut TcpStream, response: MockResponse) {
    if let Some(delay) = response.delay {
        thread::sleep(delay);
    }
    let reason = match response.status {
        200 => "OK",
        202 => "Accepted",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

fn real_transport() -> Arc<ReqwestTransport> {
    Arc::new(ReqwestTransport::new(Duration::from_secs(5), "tbc-vantage-test/0.1.0").unwrap())
}

fn request() -> MeasurementRequest {
    MeasurementRequest {
        target: "1.2.3.4".to_owned(),
        port: 443,
        probe_kind: ProbeKind::TcpConnect,
        country: None,
        asn: None,
    }
}

// ── Globalping ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn globalping_submits_and_polls_against_a_local_http_server() {
    let mut server = MockServer::start(Box::new(|request| {
        if request.method == "POST" && request.path == "/v1/measurements" {
            MockResponse::json(202, serde_json::json!({ "id": "gp-local-1" }))
        } else if request.method == "GET" && request.path == "/v1/measurements/gp-local-1" {
            MockResponse::json(
                200,
                serde_json::json!({
                    "status": "finished",
                    "results": [{
                        "result": {
                            "status": "finished",
                            "resolvedAddress": "1.2.3.4",
                            "rawOutput": "64 bytes from 1.2.3.4",
                            "timings": [{ "rtt": 12.5 }]
                        }
                    }]
                }),
            )
        } else {
            MockResponse::json(404, serde_json::json!({ "error": "not found" }))
        }
    }));

    let adapter = GlobalpingVantage::new(
        server.base_url().to_owned(),
        real_transport(),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let result = adapter.run(&request(), &mut budget).await.unwrap();
    assert_eq!(result.verdict, Verdict::Reachable);
    assert_eq!(result.rtt_ms, Some(13));
    assert_eq!(result.measurement_ref, "gp-local-1");
    assert_eq!(budget.remaining(), 8, "submit + one poll = two calls");

    let recorded = server.recorded();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].method, "POST");
    assert_eq!(recorded[1].method, "GET");
    server.stop();
}

#[tokio::test]
async fn globalping_maps_429_to_rate_limited_over_real_http() {
    let mut server = MockServer::start(Box::new(|_| {
        MockResponse::text(429, r#"{"error":"rate limited"}"#)
    }));

    let adapter = GlobalpingVantage::new(
        server.base_url().to_owned(),
        real_transport(),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let error = adapter.run(&request(), &mut budget).await.unwrap_err();
    assert_eq!(error.kind_name(), "rate_limited");
    assert!(error.is_retryable());
    server.stop();
}

#[tokio::test]
async fn globalping_maps_non_2xx_to_http_error_over_real_http() {
    let mut server =
        MockServer::start(Box::new(|_| MockResponse::text(500, r#"{"error":"boom"}"#)));

    let adapter = GlobalpingVantage::new(
        server.base_url().to_owned(),
        real_transport(),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let error = adapter.run(&request(), &mut budget).await.unwrap_err();
    assert_eq!(error.kind_name(), "http_error");
    server.stop();
}

#[tokio::test]
async fn globalping_reports_parse_error_on_malformed_json_over_real_http() {
    let mut server = MockServer::start(Box::new(|_| MockResponse::text(200, "not json")));

    let adapter = GlobalpingVantage::new(
        server.base_url().to_owned(),
        real_transport(),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let error = adapter.run(&request(), &mut budget).await.unwrap_err();
    assert_eq!(error.kind_name(), "parse_error");
    server.stop();
}

#[tokio::test]
async fn globalping_times_out_against_a_slow_server() {
    let mut server = MockServer::start(Box::new(|_| {
        MockResponse::json(202, serde_json::json!({ "id": "gp-slow" }))
            .delayed(Duration::from_millis(900))
    }));

    // A 200 ms client deadline proves the real reqwest timeout, not a fake one.
    let transport = Arc::new(
        ReqwestTransport::new(Duration::from_millis(200), "tbc-vantage-test/0.1.0").unwrap(),
    );
    let adapter = GlobalpingVantage::new(
        server.base_url().to_owned(),
        transport,
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let error = adapter.run(&request(), &mut budget).await.unwrap_err();
    assert_eq!(error.kind_name(), "transport_error");
    server.stop();
}

// ── RIPE Atlas ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn ripe_atlas_requires_an_api_key_without_calling_out() {
    let mut server = MockServer::start(Box::new(|_| {
        MockResponse::json(200, serde_json::json!({ "measurements": [1] }))
    }));

    let adapter = RipeAtlasVantage::new(
        server.base_url().to_owned(),
        real_transport(),
        None,
        "IR".to_owned(),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let error = adapter.run(&request(), &mut budget).await.unwrap_err();
    assert_eq!(error.kind_name(), "missing_api_key");
    assert_eq!(budget.remaining(), 10, "no call was made");
    assert!(server.recorded().is_empty());
    server.stop();
}

#[tokio::test]
async fn ripe_atlas_sends_auth_header_and_normalizes_over_real_http() {
    let mut server = MockServer::start(Box::new(|request| {
        if request.method == "POST" && request.path == "/api/v2/measurements/" {
            MockResponse::json(200, serde_json::json!({ "measurements": [12345] }))
        } else if request.method == "GET" && request.path.contains("latest") {
            MockResponse::json(
                200,
                serde_json::json!([{ "avg": 20.0, "rcvd": 3, "status": "done" }]),
            )
        } else {
            MockResponse::json(404, serde_json::json!({ "error": "not found" }))
        }
    }));

    let adapter = RipeAtlasVantage::new(
        server.base_url().to_owned(),
        real_transport(),
        Some("secret-key".to_owned()),
        "IR".to_owned(),
        5,
        Duration::from_millis(1),
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let result = adapter.run(&request(), &mut budget).await.unwrap();
    assert_eq!(result.verdict, Verdict::Reachable);
    assert_eq!(result.rtt_ms, Some(20));
    assert_eq!(result.measurement_ref, "12345");

    let recorded = server.recorded();
    assert_eq!(recorded.len(), 2);
    assert!(recorded[0].headers.iter().any(|(name, value)| name
        .eq_ignore_ascii_case("authorization")
        && value == "Key secret-key"));
    let body: serde_json::Value = serde_json::from_slice(&recorded[0].body).unwrap();
    assert_eq!(body["probes"][0]["value"], "IR");
    server.stop();
}

// ── OONI ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ooni_queries_probe_cc_and_normalizes_confirmed_over_real_http() {
    let mut server = MockServer::start(Box::new(|request| {
        assert!(request.method == "GET" && request.path.starts_with("/api/v1/measurements"));
        assert!(request.path.contains("probe_cc=IR"));
        assert!(request.path.contains("test_name=web_connectivity"));
        MockResponse::json(
            200,
            serde_json::json!({
                "results": [{
                    "confirmed": true,
                    "anomaly": false,
                    "test_name": "web_connectivity",
                    "measurement_start_time": "2026-08-14T00:00:00Z",
                    "report_id": "r-ooni-1"
                }]
            }),
        )
    }));

    let adapter = OoniVantage::new(
        server.base_url().to_owned(),
        real_transport(),
        "IR".to_owned(),
        10,
    )
    .unwrap();
    let mut budget = Budget::new(10);

    let result = adapter.run(&request(), &mut budget).await.unwrap();
    assert!(matches!(result.verdict, Verdict::Blocked { .. }));
    assert_eq!(result.error_class.as_deref(), Some("confirmed_blocked"));
    assert_eq!(result.measurement_ref, "r-ooni-1");
    server.stop();
}

// ── Volunteer agent ────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_posts_probe_and_normalizes_verdict_over_real_http() {
    let mut server = MockServer::start(Box::new(|request| {
        assert!(request.method == "POST" && request.path == "/probe");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["target"], "1.2.3.4");
        assert_eq!(body["port"], 443);
        MockResponse::json(
            200,
            serde_json::json!({
                "verdict": "blocked",
                "evidence": "SYN drop",
                "measurement_ref": "agent-local-1"
            }),
        )
    }));

    let adapter = AgentVantage::new(server.base_url().to_owned(), real_transport()).unwrap();
    let mut budget = Budget::new(10);

    let result = adapter.run(&request(), &mut budget).await.unwrap();
    assert_eq!(
        result.verdict,
        Verdict::Blocked {
            evidence: "SYN drop".to_owned()
        }
    );
    assert_eq!(result.measurement_ref, "agent-local-1");
    server.stop();
}

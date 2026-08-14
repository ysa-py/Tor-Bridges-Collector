//! The agent's HTTP server.
//!
//! The agent speaks a deliberately minimal HTTP/1.1 subset: it accepts a
//! `POST /probe` request with a JSON body, rate-limits and concurrency-guards
//! the measurement, runs it, and returns a JSON verdict — then closes the
//! connection (no keep-alive). This keeps the volunteer-side attack surface
//! small while remaining wire-compatible with the `AgentVantage` adapter in
//! `tbc-vantage`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use tbc_core::Metrics;

use crate::config::AgentConfig;
use crate::consent::ConsentRecord;
use crate::error::AgentError;
use crate::k_anonymity::{KAnonymityBatcher, Submission};
use crate::probe::ProbeEngine;
use crate::protocol::ProbeRequest;
use crate::rate_limit::RateLimiter;
use crate::report::AnonymizedReport;

/// A parsed HTTP/1.1 request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The HTTP method, upper-cased.
    pub method: String,
    /// The request path (no query-string handling is performed).
    pub path: String,
    /// Headers in order, names lower-cased.
    pub headers: Vec<(String, String)>,
    /// The request body (empty when no `Content-Length` was sent).
    pub body: Vec<u8>,
}

/// A JSON HTTP response ready to be serialized onto the wire.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The response body (always JSON).
    pub body: Vec<u8>,
}

/// The parsed request line and headers of an HTTP/1.1 request.
#[derive(Debug, Clone)]
pub struct RequestHead {
    /// The HTTP method, upper-cased.
    pub method: String,
    /// The request path.
    pub path: String,
    /// Headers in order, names lower-cased.
    pub headers: Vec<(String, String)>,
    /// The declared body length in bytes.
    pub content_length: usize,
}

#[derive(Clone)]
pub struct AgentServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    config: AgentConfig,
    engine: ProbeEngine,
    limiter: RateLimiter,
    semaphore: Arc<Semaphore>,
    metrics: Metrics,
    batcher: Mutex<KAnonymityBatcher>,
    emitted: Mutex<Vec<Vec<AnonymizedReport>>>,
}

impl AgentServer {
    /// Build a server from a validated configuration.
    pub fn new(config: AgentConfig) -> Result<Self, AgentError> {
        config.validate()?;
        let engine =
            ProbeEngine::new(config.connect_timeout, config.measurement_id_prefix.clone())?;
        let limiter = RateLimiter::new(config.rate_limit_burst, config.rate_limit_per_second);
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_probes));
        let metrics = Metrics::new();
        let batcher = KAnonymityBatcher::new(config.k_anonymity_threshold)?;
        Ok(Self {
            inner: Arc::new(ServerInner {
                config,
                engine,
                limiter,
                semaphore,
                metrics,
                batcher: Mutex::new(batcher),
                emitted: Mutex::new(Vec::new()),
            }),
        })
    }

    /// The server's metrics registry (counters for requests, rate limits, and
    /// probe errors).
    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    /// Record the volunteer's consent on the shared gate. Until this is
    /// called the server answers every probe with 403 `consent_required` and
    /// sends no probe traffic.
    pub fn grant_consent(&self, method: &str) -> ConsentRecord {
        self.inner.engine.grant_consent(method)
    }

    /// Whether consent has been recorded.
    pub fn consented(&self) -> bool {
        self.inner.engine.consented()
    }

    /// Submit an anonymized report through the k-anonymity batcher. Reports
    /// are withheld until the configured threshold is met; emitted batches
    /// are retained for the upstream transport (see
    /// [`take_emitted_batches`]).
    pub fn record_report(&self, report: AnonymizedReport) -> Submission {
        let submission = self.batcher().submit(report);
        if let Submission::Emitted(batch) = &submission {
            self.emitted().push(batch.clone());
        }
        submission
    }

    /// How many anonymized reports are currently withheld below the
    /// k-anonymity threshold.
    pub fn held_reports(&self) -> usize {
        self.batcher().held()
    }

    /// How many k-anonymous batches have been emitted and not yet drained.
    pub fn emitted_batches(&self) -> usize {
        self.emitted().len()
    }

    /// Drain the emitted k-anonymous batches for the upstream transport.
    pub fn take_emitted_batches(&self) -> Vec<Vec<AnonymizedReport>> {
        let mut emitted = self.emitted();
        std::mem::take(&mut *emitted)
    }

    fn batcher(&self) -> MutexGuard<'_, KAnonymityBatcher> {
        self.inner
            .batcher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn emitted(&self) -> MutexGuard<'_, Vec<Vec<AnonymizedReport>>> {
        self.inner
            .emitted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Bind the configured listen address. Port `0` selects an OS-assigned
    /// port (used by the integration tests).
    pub async fn bind(&self) -> Result<TcpListener, AgentError> {
        let address = format!(
            "{}:{}",
            self.inner.config.bind_host, self.inner.config.bind_port
        );
        TcpListener::bind(&address)
            .await
            .map_err(|error| AgentError::Io {
                phase: "bind",
                message: error.to_string(),
            })
    }

    /// Accept connections until the process is stopped, serving each one on
    /// its own task.
    pub async fn run(&self, listener: TcpListener) -> Result<(), AgentError> {
        loop {
            let (stream, peer) = listener.accept().await.map_err(|error| AgentError::Io {
                phase: "accept",
                message: error.to_string(),
            })?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(error) = server.serve_connection(stream, peer).await {
                    tracing::warn!(kind = error.kind_name(), %error, "agent connection failed");
                }
            });
        }
    }

    /// Serve a single connection: read one request, dispatch it, write the
    /// response, and close.
    pub async fn serve_connection(
        &self,
        mut stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<(), AgentError> {
        let request = read_request(
            &mut stream,
            self.inner.config.read_timeout,
            self.inner.config.max_body_bytes,
        )
        .await?;
        let client_key = peer.ip().to_string();
        let response = self.handle_request(request, &client_key).await;
        let bytes = build_response(response.status, &response.body);
        write_all(&mut stream, &bytes, self.inner.config.read_timeout).await?;
        if let Err(error) = stream.shutdown().await {
            tracing::debug!(%error, "connection shutdown failed (non-fatal)");
        }
        Ok(())
    }

    /// Dispatch a parsed request to a measurement, applying the routing,
    /// rate-limit, validation, and concurrency policies. Pure with respect to
    /// the network (the probe itself runs through the engine), which makes it
    /// directly testable.
    pub async fn handle_request(&self, request: HttpRequest, client_key: &str) -> HttpResponse {
        self.inner.metrics.increment("tbc_agent_requests_total", 1);

        if request.method != "POST" {
            return self.error_response(
                405,
                "method_not_allowed",
                "only POST /probe is supported".to_owned(),
            );
        }
        if request.path != "/probe" {
            return self.error_response(404, "not_found", "unknown path".to_owned());
        }
        if !self.inner.limiter.allow(client_key) {
            self.inner
                .metrics
                .increment("tbc_agent_rate_limited_total", 1);
            return self.error_response(
                429,
                "rate_limited",
                "agent per-client rate limit exceeded".to_owned(),
            );
        }

        let probe_request: ProbeRequest = match serde_json::from_slice(&request.body) {
            Ok(parsed) => parsed,
            Err(error) => {
                return self.error_response(
                    400,
                    "invalid_json",
                    format!("request body is not valid JSON: {error}"),
                );
            }
        };
        if let Err(error) = probe_request.validate(&self.inner.config) {
            return self.error_response(400, "invalid_request", error.to_string());
        }

        let _permit = match self.inner.semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return self.error_response(
                    429,
                    "overloaded",
                    "agent is at maximum concurrent probes".to_owned(),
                );
            }
        };

        self.inner
            .metrics
            .increment("tbc_agent_probe_requests_total", 1);
        match self.inner.engine.probe(&probe_request).await {
            Ok(response) => {
                let report = AnonymizedReport::from_probe_response(&response, None);
                self.record_report(report);
                match serde_json::to_vec(&response) {
                    Ok(body) => HttpResponse { status: 200, body },
                    Err(error) => self.error_response(
                        500,
                        "serialization_failed",
                        format!("failed to serialize probe response: {error}"),
                    ),
                }
            }
            Err(AgentError::ConsentRequired) => self.error_response(
                403,
                "consent_required",
                "volunteer consent has not been recorded".to_owned(),
            ),
            Err(AgentError::UnsupportedProbe(kind)) => self.error_response(
                422,
                "unsupported_probe_kind",
                format!("probe kind not supported: {kind}"),
            ),
            Err(error) => {
                self.inner
                    .metrics
                    .increment("tbc_agent_probe_errors_total", 1);
                self.error_response(500, error.kind_name(), error.to_string())
            }
        }
    }

    fn error_response(&self, status: u16, code: &str, message: String) -> HttpResponse {
        let body = serde_json::json!({ "error": code, "message": message });
        match serde_json::to_vec(&body) {
            Ok(body) => HttpResponse { status, body },
            Err(_) => HttpResponse {
                status: 500,
                body: br#"{"error":"internal","message":"failed to serialize error"}"#.to_vec(),
            },
        }
    }
}

/// Serialize a JSON body into a complete HTTP/1.1 response (with
/// `Connection: close`, since each connection serves exactly one request).
pub fn build_response(status: u16, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    );
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Read one bounded HTTP/1.1 request (head plus `Content-Length` body) from a
/// stream, enforcing the timeout and the byte limit on both the header block
/// and the body.
pub async fn read_request(
    stream: &mut TcpStream,
    timeout: Duration,
    max_body: usize,
) -> Result<HttpRequest, AgentError> {
    let mut buf = Vec::new();
    let header_end = loop {
        if buf.len() > max_body {
            return Err(AgentError::BodyTooLarge(max_body));
        }
        if let Some(position) = find_subslice(&buf, b"\r\n\r\n") {
            break position + 4;
        }
        let mut chunk = [0u8; 1024];
        let read = read_some(stream, &mut chunk, timeout).await?;
        if read == 0 {
            return Err(AgentError::Protocol(
                "connection closed before the request head completed".to_owned(),
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
    };

    let head = parse_request_head(&buf[..header_end])?;
    if head.content_length > max_body {
        return Err(AgentError::BodyTooLarge(max_body));
    }
    let total = header_end.saturating_add(head.content_length);
    while buf.len() < total {
        let mut chunk = [0u8; 1024];
        let read = read_some(stream, &mut chunk, timeout).await?;
        if read == 0 {
            return Err(AgentError::Protocol(
                "connection closed before the request body completed".to_owned(),
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let body = buf[header_end..total].to_vec();
    Ok(HttpRequest {
        method: head.method,
        path: head.path,
        headers: head.headers,
        body,
    })
}

/// Parse a request head into its method, path, headers, and `Content-Length`.
pub fn parse_request_head(head: &[u8]) -> Result<RequestHead, AgentError> {
    let text = std::str::from_utf8(head)
        .map_err(|_| AgentError::Protocol("request head is not valid UTF-8".to_owned()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| AgentError::Protocol("empty request".to_owned()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| AgentError::Protocol("missing HTTP method".to_owned()))?
        .to_ascii_uppercase();
    let path = parts
        .next()
        .ok_or_else(|| AgentError::Protocol("missing request path".to_owned()))?
        .to_owned();
    let version = parts
        .next()
        .ok_or_else(|| AgentError::Protocol("missing HTTP version".to_owned()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(AgentError::Protocol(format!(
            "unsupported HTTP version: {version}"
        )));
    }

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| AgentError::Protocol(format!("malformed header: {line}")))?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        if name == "content-length" {
            content_length = value
                .parse::<usize>()
                .map_err(|_| AgentError::Protocol(format!("invalid content-length: {value}")))?;
        }
        headers.push((name, value));
    }
    Ok(RequestHead {
        method,
        path,
        headers,
        content_length,
    })
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

async fn read_some(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<usize, AgentError> {
    match tokio::time::timeout(timeout, stream.read(buf)).await {
        Ok(Ok(read)) => Ok(read),
        Ok(Err(error)) => Err(AgentError::Io {
            phase: "read",
            message: error.to_string(),
        }),
        Err(_) => Err(AgentError::Timeout { phase: "read" }),
    }
}

async fn write_all(
    stream: &mut TcpStream,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), AgentError> {
    match tokio::time::timeout(timeout, stream.write_all(bytes)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(AgentError::Io {
            phase: "write",
            message: error.to_string(),
        }),
        Err(_) => Err(AgentError::Timeout { phase: "write" }),
    }
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
    fn parse_request_head_extracts_method_path_and_content_length() {
        let head = b"POST /probe HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n";
        let parsed = parse_request_head(head).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/probe");
        assert_eq!(parsed.content_length, 5);
        assert!(parsed
            .headers
            .iter()
            .any(|(name, value)| name == "host" && value == "localhost"));
    }

    #[test]
    fn parse_request_head_rejects_malformed_version() {
        let head = b"POST /probe HTTP/2.0\r\n\r\n";
        assert!(parse_request_head(head).is_err());
    }

    #[test]
    fn build_response_has_status_and_body() {
        let bytes = build_response(200, br#"{"verdict":"reachable"}"#);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 23\r\n"));
        assert!(text.ends_with("{\"verdict\":\"reachable\"}"));
    }

    #[tokio::test]
    async fn read_request_round_trips_over_loopback() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream, Duration::from_secs(2), 4096)
                .await
                .unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.body, b"hello");
        });

        let raw = b"POST /probe HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(raw).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handle_request_rejects_wrong_method() {
        let server = AgentServer::new(AgentConfig::default()).unwrap();
        let response = server
            .handle_request(
                HttpRequest {
                    method: "GET".to_owned(),
                    path: "/probe".to_owned(),
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                "127.0.0.1",
            )
            .await;
        assert_eq!(response.status, 405);
    }

    #[tokio::test]
    async fn handle_request_rejects_invalid_json() {
        let server = AgentServer::new(AgentConfig::default()).unwrap();
        let response = server
            .handle_request(
                HttpRequest {
                    method: "POST".to_owned(),
                    path: "/probe".to_owned(),
                    headers: Vec::new(),
                    body: b"not json".to_vec(),
                },
                "127.0.0.1",
            )
            .await;
        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["error"], "invalid_json");
    }

    #[tokio::test]
    async fn handle_request_requires_consent_before_probing() {
        let server = AgentServer::new(AgentConfig::default()).unwrap();
        let response = server
            .handle_request(
                HttpRequest {
                    method: "POST".to_owned(),
                    path: "/probe".to_owned(),
                    headers: Vec::new(),
                    body: br#"{"target":"127.0.0.1","port":9,"probe_kind":"tcp_connect"}"#.to_vec(),
                },
                "127.0.0.1",
            )
            .await;
        assert_eq!(response.status, 403);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["error"], "consent_required");
    }
}

//! Protocol-accurate async bridge verification and adaptive probe control.
//!
//! TCP reachability is deliberately not treated as a generic success signal:
//!
//! * vanilla and IPv6 obfs4 use bounded TCP connects;
//! * IPv4 obfs4 is additionally validated through a real obfs4proxy/lyrebird
//!   SOCKS harness when available;
//! * WebTunnel requires an HTTPS WebSocket Upgrade with a `101` response;
//! * fronted transports verify TLS to their broker/front domain.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use rand::{thread_rng, Rng, RngCore};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{lookup_host, TcpSocket, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::config::{CollectorConfig, Transport, USER_AGENT};
use super::parsing::{extract_endpoint, extract_front_host, extract_url, parse_obfs4_ipv4};

/// One completed protocol probe.
#[derive(Clone, Debug)]
pub struct ProbeResult {
    /// Original clean bridge line.
    pub line: String,
    /// Whether the transport-specific handshake succeeded.
    pub reachable: bool,
    /// End-to-end elapsed time for a successful probe.
    pub latency_ms: Option<f64>,
    /// Friendly probe mode for logs and Prometheus metrics.
    pub mode: &'static str,
    /// Recoverable failure context, intentionally excluding secret parameters.
    pub error: Option<String>,
}

/// Result of an optional obfs4 harness run.
#[derive(Clone, Debug, Default)]
pub struct Obfs4Verification {
    /// Lines that completed SOCKS CONNECT after the obfs4 layer.
    pub verified: Vec<String>,
    /// TCP-reachable lines that could not be represented by the IPv4 harness
    /// parser. OnionHop.py preserves these rather than discarding a valid
    /// bridge because of a parser limitation.
    pub unparseable: Vec<String>,
    /// Whether a usable harness was actually started.
    pub ran: bool,
    /// Human-readable fallback diagnostic.
    pub diagnostic: String,
}

/// Prometheus-compatible in-memory probe accounting.
#[derive(Clone, Debug, Default)]
pub struct ProbeMetrics {
    inner: Arc<Mutex<BTreeMap<String, TransportMetrics>>>,
}

#[derive(Clone, Debug, Default)]
struct TransportMetrics {
    attempts: u64,
    successes: u64,
    failures: u64,
    latency_le_100_ms: u64,
    latency_le_500_ms: u64,
    latency_le_1_s: u64,
    latency_le_5_s: u64,
    latency_sum_ms: f64,
}

impl ProbeMetrics {
    /// Record a probe without allowing a poisoned diagnostic mutex to crash a run.
    pub fn record(&self, transport: Transport, result: &ProbeResult) {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = guard.entry(transport.file_name().to_owned()).or_default();
        entry.attempts = entry.attempts.saturating_add(1);
        if result.reachable {
            entry.successes = entry.successes.saturating_add(1);
            if let Some(latency) = result.latency_ms {
                entry.latency_sum_ms += latency;
                if latency <= 100.0 {
                    entry.latency_le_100_ms = entry.latency_le_100_ms.saturating_add(1);
                }
                if latency <= 500.0 {
                    entry.latency_le_500_ms = entry.latency_le_500_ms.saturating_add(1);
                }
                if latency <= 1_000.0 {
                    entry.latency_le_1_s = entry.latency_le_1_s.saturating_add(1);
                }
                if latency <= 5_000.0 {
                    entry.latency_le_5_s = entry.latency_le_5_s.saturating_add(1);
                }
            }
        } else {
            entry.failures = entry.failures.saturating_add(1);
        }
    }

    /// Render stable Prometheus text exposition.
    pub fn render(&self) -> String {
        let guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut output = String::from(
            "# HELP tor_bridge_probe_total Completed bridge protocol probes.\n\
# TYPE tor_bridge_probe_total counter\n\
# HELP tor_bridge_probe_latency_ms Probe latency histogram in milliseconds.\n\
# TYPE tor_bridge_probe_latency_ms histogram\n",
        );
        for (transport, metric) in guard.iter() {
            output.push_str(&format!(
                "tor_bridge_probe_total{{transport=\"{transport}\",result=\"success\"}} {}\n\
tor_bridge_probe_total{{transport=\"{transport}\",result=\"failure\"}} {}\n\
tor_bridge_probe_latency_ms_bucket{{transport=\"{transport}\",le=\"100\"}} {}\n\
tor_bridge_probe_latency_ms_bucket{{transport=\"{transport}\",le=\"500\"}} {}\n\
tor_bridge_probe_latency_ms_bucket{{transport=\"{transport}\",le=\"1000\"}} {}\n\
tor_bridge_probe_latency_ms_bucket{{transport=\"{transport}\",le=\"5000\"}} {}\n\
tor_bridge_probe_latency_ms_bucket{{transport=\"{transport}\",le=\"+Inf\"}} {}\n\
tor_bridge_probe_latency_ms_sum{{transport=\"{transport}\"}} {:.3}\n\
tor_bridge_probe_latency_ms_count{{transport=\"{transport}\"}} {}\n",
                metric.successes,
                metric.failures,
                metric.latency_le_100_ms,
                metric.latency_le_500_ms,
                metric.latency_le_1_s,
                metric.latency_le_5_s,
                metric.successes,
                metric.latency_sum_ms,
                metric.successes,
            ));
        }
        output
    }
}

/// Per-transport adaptive concurrency state. A weak transport is probed with
/// fewer outstanding sockets on subsequent chunks, while a healthy one can
/// recover toward the configured ceiling.
#[derive(Clone, Debug)]
pub struct AdaptiveConcurrency {
    min_workers: usize,
    max_workers: usize,
    state: Arc<Mutex<BTreeMap<Transport, BatchHealth>>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct BatchHealth {
    successes: u64,
    failures: u64,
}

impl AdaptiveConcurrency {
    /// Construct a controller with inclusive worker bounds.
    pub fn new(min_workers: usize, max_workers: usize) -> Self {
        Self {
            min_workers,
            max_workers: max_workers.max(min_workers),
            state: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Return a current permit count for one transport.
    pub fn permits_for(&self, transport: Transport) -> usize {
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(health) = guard.get(&transport).copied() else {
            return self.max_workers;
        };
        let total = health.successes.saturating_add(health.failures);
        if total < 8 {
            return self.max_workers;
        }
        let rate = health.successes as f64 / total as f64;
        if rate < 0.20 {
            self.min_workers
        } else if rate < 0.50 {
            (self.max_workers / 4).max(self.min_workers)
        } else if rate < 0.75 {
            (self.max_workers / 2).max(self.min_workers)
        } else {
            self.max_workers
        }
    }

    /// Feed a chunk outcome into the controller.
    pub fn record_batch(&self, transport: Transport, results: &[ProbeResult]) {
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let health = guard.entry(transport).or_default();
        for result in results {
            if result.reachable {
                health.successes = health.successes.saturating_add(1);
            } else {
                health.failures = health.failures.saturating_add(1);
            }
        }
    }
}

/// Per-front circuit breaker state.
#[derive(Clone, Debug)]
struct FrontCircuitBreaker {
    threshold: u32,
    cooldown: Duration,
    state: Arc<Mutex<BTreeMap<String, FrontState>>>,
}

#[derive(Clone, Debug, Default)]
struct FrontState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl FrontCircuitBreaker {
    fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            threshold,
            cooldown,
            state: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn allow(&self, host: &str) -> bool {
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let state = guard.entry(host.to_ascii_lowercase()).or_default();
        match state.open_until {
            Some(until) if until > now => false,
            Some(_) => {
                state.open_until = None;
                state.consecutive_failures = 0;
                true
            }
            None => true,
        }
    }

    fn record(&self, host: &str, success: bool) {
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state = guard.entry(host.to_ascii_lowercase()).or_default();
        if success {
            state.consecutive_failures = 0;
            state.open_until = None;
            return;
        }
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.threshold {
            state.open_until = Some(Instant::now() + self.cooldown);
            tracing::warn!(
                host,
                cooldown_secs = self.cooldown.as_secs(),
                "front-domain circuit opened"
            );
        }
    }
}

/// Async transport verification engine.
#[derive(Clone)]
pub struct ProbeEngine {
    config: CollectorConfig,
    circuit_breaker: FrontCircuitBreaker,
    adaptive: AdaptiveConcurrency,
    metrics: ProbeMetrics,
}

impl ProbeEngine {
    /// Create a probe engine from collector settings.
    pub fn new(config: CollectorConfig) -> Self {
        Self {
            adaptive: AdaptiveConcurrency::new(config.min_workers, config.max_workers),
            circuit_breaker: FrontCircuitBreaker::new(
                config.front_failure_threshold,
                Duration::from_secs(config.front_cooldown_secs),
            ),
            metrics: ProbeMetrics::default(),
            config,
        }
    }

    /// Expose Prometheus metrics for optional file export.
    pub fn metrics(&self) -> ProbeMetrics {
        self.metrics.clone()
    }

    /// Test candidates in adaptive chunks. Each chunk owns a Semaphore whose
    /// permit count is recalculated from the transport's observed success rate.
    pub async fn test_many(
        &self,
        lines: Vec<String>,
        transport: Transport,
        ipv6: bool,
    ) -> Vec<ProbeResult> {
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < lines.len() {
            let permits = self.adaptive.permits_for(transport).max(1);
            let chunk_len = permits.saturating_mul(2).max(1);
            let end = offset.saturating_add(chunk_len).min(lines.len());
            let chunk = &lines[offset..end];
            let semaphore = Arc::new(Semaphore::new(permits));
            let mut tasks = JoinSet::new();

            for line in chunk {
                let engine = self.clone();
                let candidate = line.clone();
                let semaphore = semaphore.clone();
                tasks.spawn(async move {
                    let permit = semaphore.acquire_owned().await;
                    match permit {
                        Ok(permit) => {
                            let _permit = permit;
                            engine.probe(candidate, transport, ipv6).await
                        }
                        Err(_) => ProbeResult {
                            line: candidate,
                            reachable: false,
                            latency_ms: None,
                            mode: "cancelled",
                            error: Some("probe semaphore closed".to_owned()),
                        },
                    }
                });
            }

            let mut chunk_results = Vec::new();
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok(result) => chunk_results.push(result),
                    Err(error) => {
                        tracing::warn!(%error, "probe task ended unexpectedly; skipping candidate")
                    }
                }
            }
            self.adaptive.record_batch(transport, &chunk_results);
            output.extend(chunk_results);
            offset = end;
        }
        output
    }

    /// Run a transport-specific probe with bounded retries and jitter.
    pub async fn probe(&self, line: String, transport: Transport, ipv6: bool) -> ProbeResult {
        let started = Instant::now();
        let mut last_error = None;
        let mode = probe_mode(transport, ipv6);
        for attempt in 0..self.config.max_retries {
            let result = self.probe_once(&line, transport, ipv6).await;
            match result {
                Ok(()) => {
                    let result = ProbeResult {
                        line,
                        reachable: true,
                        latency_ms: Some(started.elapsed().as_secs_f64() * 1_000.0),
                        mode,
                        error: None,
                    };
                    self.metrics.record(transport, &result);
                    return result;
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                    if attempt + 1 < self.config.max_retries {
                        let jitter = thread_rng().gen_range(50_u64..=250_u64);
                        sleep(Duration::from_millis(jitter)).await;
                    }
                }
            }
        }
        let result = ProbeResult {
            line,
            reachable: false,
            latency_ms: None,
            mode,
            error: last_error,
        };
        self.metrics.record(transport, &result);
        result
    }

    async fn probe_once(&self, line: &str, transport: Transport, ipv6: bool) -> Result<()> {
        if transport.is_fronted() {
            let host = extract_front_host(line)
                .ok_or_else(|| anyhow!("fronted line has no front/broker host"))?;
            if !self.circuit_breaker.allow(&host) {
                return Err(anyhow!("front-domain circuit is open for {host}"));
            }
            let result = self.tls_probe(&host, 443, false).await;
            self.circuit_breaker.record(&host, result.is_ok());
            return result;
        }

        if transport == Transport::WebTunnel {
            let url =
                extract_url(line).ok_or_else(|| anyhow!("WebTunnel line has no valid url="))?;
            return self.websocket_upgrade(url).await;
        }

        let endpoint =
            extract_endpoint(line).ok_or_else(|| anyhow!("bridge line has no endpoint"))?;
        // IPv4 obfs4 intentionally starts with a TCP prefilter; the service
        // subsequently invokes the real obfs4 SOCKS handshake on survivors.
        // IPv6 obfs4 remains TCP-only because CI runners commonly lack IPv6.
        let _ = ipv6;
        self.tcp_probe(&endpoint.host, endpoint.port).await
    }

    async fn tcp_probe(&self, host: &str, port: u16) -> Result<()> {
        let stream = self.connect(host, port).await?;
        drop(stream);
        Ok(())
    }

    async fn tls_probe(&self, host: &str, port: u16, websocket: bool) -> Result<()> {
        let stream = self.tls_connect(host, port, websocket).await?;
        drop(stream);
        Ok(())
    }

    /// Perform a real HTTP/1.1 WebSocket Upgrade and require `101 Switching
    /// Protocols`. A CDN TLS handshake or ordinary HTTP success is not enough.
    async fn websocket_upgrade(&self, url: url::Url) -> Result<()> {
        if url.scheme() != "https" {
            return Err(anyhow!("WebTunnel url must use https"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("WebTunnel url has no host"))?;
        let port = url.port_or_known_default().unwrap_or(443);
        let mut stream = self.tls_connect(host, port, true).await?;
        let mut random_key = [0_u8; 16];
        thread_rng().fill_bytes(&mut random_key);
        let key = base64::engine::general_purpose::STANDARD.encode(random_key);
        let mut target = url.path().to_owned();
        if target.is_empty() {
            target.push('/');
        }
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        let host_header = match url.port() {
            Some(explicit_port) if explicit_port != 443 => format!("{host}:{explicit_port}"),
            _ => host.to_owned(),
        };
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\n\
Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\n\
Sec-WebSocket-Version: 13\r\n\r\n"
        );
        timeout(
            Duration::from_secs(self.config.connect_timeout_secs),
            stream.write_all(request.as_bytes()),
        )
        .await
        .context("WebTunnel write timed out")??;
        timeout(
            Duration::from_secs(self.config.connect_timeout_secs),
            stream.flush(),
        )
        .await
        .context("WebTunnel flush timed out")??;

        let mut response = Vec::with_capacity(512);
        let mut buffer = [0_u8; 128];
        while response.len() < 2_048 && !response.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = timeout(
                Duration::from_secs(self.config.connect_timeout_secs),
                stream.read(&mut buffer),
            )
            .await
            .context("WebTunnel response timed out")??;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read]);
        }
        let response_text = String::from_utf8_lossy(&response);
        let status = response_text.lines().next().unwrap_or_default();
        if status.split_whitespace().nth(1) == Some("101") {
            Ok(())
        } else {
            Err(anyhow!("WebTunnel Upgrade did not return HTTP 101"))
        }
    }

    async fn tls_connect(
        &self,
        host: &str,
        port: u16,
        websocket: bool,
    ) -> Result<TlsStream<TcpStream>> {
        let tcp = self.connect(host, port).await?;
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| anyhow!("invalid TLS server name"))?;
        let config = tls_config(websocket)?;
        let connector = TlsConnector::from(config);
        timeout(
            Duration::from_secs(self.config.connect_timeout_secs),
            connector.connect(server_name, tcp),
        )
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake failed")
    }

    /// Resolve a DNS host once, then attempt every returned address with a
    /// separately configured socket. `SO_REUSEADDR`, TCP keepalive, and
    /// `TCP_NODELAY` are applied before/after connection where supported.
    async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let addresses = if let Ok(address) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(address, port)]
        } else {
            lookup_host((host, port))
                .await
                .with_context(|| format!("DNS lookup failed for {host}"))?
                .collect::<Vec<_>>()
        };
        if addresses.is_empty() {
            return Err(anyhow!("DNS lookup returned no addresses"));
        }

        let mut last_error = None;
        for address in addresses {
            match self.connect_address(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("no address could be reached")))
    }

    async fn connect_address(&self, address: SocketAddr) -> Result<TcpStream> {
        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .context("unable to create TCP socket")?;
        // These options are best effort only on platforms that reject them;
        // rejecting a tuning option must not make a bridge appear unavailable.
        if let Err(error) = socket.set_reuse_address(true) {
            tracing::debug!(%error, "SO_REUSEADDR unavailable for probe socket");
        }
        if let Err(error) = socket.set_keepalive(true) {
            tracing::debug!(%error, "TCP keepalive unavailable for probe socket");
        }
        if let Err(error) = socket.set_nodelay(true) {
            tracing::debug!(%error, "TCP_NODELAY unavailable for probe socket");
        }
        socket
            .set_nonblocking(true)
            .context("unable to configure nonblocking probe socket")?;
        let std_stream: std::net::TcpStream = socket.into();
        let socket = TcpSocket::from_std_stream(std_stream);
        let stream = timeout(
            Duration::from_secs(self.config.connect_timeout_secs),
            socket.connect(address),
        )
        .await
        .context("TCP connect timed out")??;
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%error, "TCP_NODELAY unavailable after connect");
        }
        Ok(stream)
    }

    /// Drive an installed `obfs4proxy` or `lyrebird` client through SOCKS5.
    /// A successful CONNECT reply is proof that the obfs4 layer completed,
    /// unlike a direct TCP connection to an obfs4 port.
    pub async fn verify_obfs4_handshakes(&self, lines: &[String]) -> Obfs4Verification {
        let Some(binary) = find_obfs4_binary() else {
            return Obfs4Verification {
                ran: false,
                diagnostic: "obfs4proxy/lyrebird not found; retaining TCP-reachable set".to_owned(),
                ..Obfs4Verification::default()
            };
        };
        let mut parsed = Vec::new();
        let mut unparseable = Vec::new();
        for line in lines {
            match parse_obfs4_ipv4(line) {
                Some(endpoint) => parsed.push((line.clone(), endpoint)),
                None => unparseable.push(line.clone()),
            }
        }
        if parsed.is_empty() {
            return Obfs4Verification {
                unparseable,
                ran: false,
                diagnostic: "no TCP-reachable IPv4 obfs4 lines had cert= parameters".to_owned(),
                ..Obfs4Verification::default()
            };
        }

        let harness = start_obfs4_proxy(&binary).await;
        let (mut child, socks) = match harness {
            Ok(value) => value,
            Err(error) => {
                return Obfs4Verification {
                    ran: false,
                    diagnostic: format!("obfs4 harness unavailable: {error}"),
                    ..Obfs4Verification::default()
                }
            }
        };
        let mut tasks = JoinSet::new();
        let workers = self.config.max_workers.min(parsed.len()).max(1);
        let semaphore = Arc::new(Semaphore::new(workers));
        for (line, endpoint) in parsed {
            let semaphore = semaphore.clone();
            let socks_address = socks;
            let handshake_timeout = self.config.obfs4_handshake_timeout_secs;
            tasks.spawn(async move {
                let permit = semaphore.acquire_owned().await;
                match permit {
                    Ok(permit) => {
                        let _permit = permit;
                        let passed =
                            obfs4_socks_connect(&socks_address, &endpoint, handshake_timeout).await;
                        (line, passed)
                    }
                    Err(_) => (line, false),
                }
            });
        }

        let mut verified = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((line, true)) => verified.push(line),
                Ok((_, false)) => {}
                Err(error) => tracing::warn!(%error, "obfs4 handshake task ended unexpectedly"),
            }
        }
        stop_child(&mut child).await;
        Obfs4Verification {
            verified,
            unparseable,
            ran: true,
            diagnostic: "obfs4 SOCKS harness completed".to_owned(),
        }
    }
}

fn probe_mode(transport: Transport, ipv6: bool) -> &'static str {
    match transport {
        Transport::WebTunnel => "websocket-101",
        Transport::Snowflake | Transport::MeekAzure | Transport::Conjure => "front-tls",
        Transport::Obfs4 if !ipv6 => "tcp-prefilter",
        _ => "tcp",
    }
}

/// A certificate verifier for reachability probes. It deliberately permits
/// private, self-signed bridge certificates because the collector validates
/// liveness/protocol behavior, not a public-Web PKI identity. It is never used
/// for upstream source downloads or Telegram uploads, which retain normal TLS
/// verification through reqwest.
#[derive(Debug)]
struct ReachabilityVerifier;

impl ServerCertVerifier for ReachabilityVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Construct one TLS configuration. Rustls exposes cipher-suite and key-share
/// ordering, so each non-WebSocket probe rotates those and ALPN profile. Rustls
/// intentionally does not expose arbitrary extension ordering; this is a
/// bounded, standards-compliant fingerprint rotation rather than a claim of
/// byte-for-byte browser uTLS impersonation.
fn tls_config(force_http1: bool) -> Result<Arc<ClientConfig>> {
    let mut provider = rustls::crypto::ring::default_provider();
    let profile = thread_rng().gen_range(0_u8..3_u8);
    if profile % 2 == 1 {
        provider.cipher_suites.reverse();
    }
    if profile == 2 {
        provider.kx_groups.reverse();
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("unable to select TLS protocol versions")?;
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ReachabilityVerifier))
        .with_no_client_auth();
    config.alpn_protocols = if force_http1 {
        vec![b"http/1.1".to_vec()]
    } else {
        match profile {
            0 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            1 => vec![b"http/1.1".to_vec(), b"h2".to_vec()],
            _ => vec![b"http/1.1".to_vec()],
        }
    };
    Ok(Arc::new(config))
}

fn find_obfs4_binary() -> Option<std::path::PathBuf> {
    if let Some(value) = std::env::var_os("OBFS4_BIN") {
        let candidate = std::path::PathBuf::from(value);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        for name in ["obfs4proxy", "lyrebird"] {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for candidate in ["/usr/bin/obfs4proxy", "/usr/bin/lyrebird"] {
        let path = std::path::PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

async fn start_obfs4_proxy(binary: &std::path::Path) -> Result<(Child, SocketAddr)> {
    let state = std::env::temp_dir().join(format!(
        "tor-bridge-obfs4-{}-{}",
        std::process::id(),
        thread_rng().gen::<u64>()
    ));
    tokio::fs::create_dir_all(&state)
        .await
        .context("unable to create obfs4 state directory")?;
    let mut child = Command::new(binary)
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_STATE_LOCATION", &state)
        .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
        .env("TOR_PT_CLIENT_TRANSPORTS", "obfs4")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("unable to start {}", binary.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("obfs4 client did not expose stdout"))?;
    let mut lines = BufReader::new(stdout).lines();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut socks = None;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let next = timeout(remaining, lines.next_line())
            .await
            .context("obfs4 client startup timed out")??;
        let Some(line) = next else {
            break;
        };
        if let Some(address) = parse_cmethod(&line) {
            socks = Some(address);
        }
        if line.trim() == "CMETHODS DONE" {
            break;
        }
    }
    match socks {
        Some(address) => Ok((child, address)),
        None => {
            stop_child(&mut child).await;
            Err(anyhow!("obfs4 client did not announce a SOCKS5 CMETHOD"))
        }
    }
}

fn parse_cmethod(line: &str) -> Option<SocketAddr> {
    let mut words = line.split_whitespace();
    if words.next()? != "CMETHOD" || words.next()? != "obfs4" || words.next()? != "socks5" {
        return None;
    }
    words.next()?.parse().ok()
}

async fn obfs4_socks_connect(
    socks: &SocketAddr,
    endpoint: &super::parsing::Obfs4Endpoint,
    timeout_secs: u64,
) -> bool {
    let duration = Duration::from_secs(timeout_secs);
    let stream = match timeout(duration, TcpStream::connect(socks)).await {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };
    let mut stream = stream;
    let handshake = async {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting != [0x05, 0x02] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS auth rejected",
            ));
        }
        let raw = endpoint.socks_args.as_bytes();
        let (username, password) = if raw.len() <= 255 {
            (raw, &[][..])
        } else {
            raw.split_at(255)
        };
        let username_len = u8::try_from(username.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "SOCKS username too long")
        })?;
        let password_len = u8::try_from(password.len().min(255)).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "SOCKS password too long")
        })?;
        let mut auth = Vec::with_capacity(3 + username.len() + password.len().min(255));
        auth.push(0x01);
        auth.push(username_len);
        auth.extend_from_slice(username);
        auth.push(password_len);
        auth.extend_from_slice(&password[..usize::from(password_len)]);
        stream.write_all(&auth).await?;
        let mut auth_reply = [0_u8; 2];
        stream.read_exact(&mut auth_reply).await?;
        if auth_reply != [0x01, 0x00] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SOCKS auth failed",
            ));
        }
        let ipv4: std::net::Ipv4Addr = endpoint.host.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid obfs4 IPv4")
        })?;
        let mut connect = vec![0x05, 0x01, 0x00, 0x01];
        connect.extend_from_slice(&ipv4.octets());
        connect.extend_from_slice(&endpoint.port.to_be_bytes());
        stream.write_all(&connect).await?;
        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await?;
        Ok::<bool, std::io::Error>(reply[0] == 0x05 && reply[1] == 0x00)
    };
    matches!(timeout(duration, handshake).await, Ok(Ok(true)))
}

async fn stop_child(child: &mut Child) {
    if let Err(error) = child.start_kill() {
        tracing::debug!(%error, "unable to signal obfs4 child shutdown");
    }
    if let Err(error) = timeout(Duration::from_secs(5), child.wait()).await {
        tracing::debug!(%error, "obfs4 child wait timed out");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CollectorConfig {
        CollectorConfig {
            bridge_dir: "bridge".into(),
            readme_path: "README.md".into(),
            history_path: "bridge/bridge_history.json".into(),
            zip_path: "bridge/tor_bridges.zip".into(),
            bridgedb_base_url: "https://example.invalid".to_owned(),
            delta_raw_base_url: "https://example.invalid".to_owned(),
            raw_repo_url: "https://example.invalid".to_owned(),
            connect_timeout_secs: 1,
            obfs4_handshake_timeout_secs: 1,
            max_retries: 1,
            max_workers: 8,
            min_workers: 2,
            max_test_per_list: 10,
            recent_hours: 72,
            history_retention_days: 30,
            obfs4_verify_min_fraction: 0.2,
            front_failure_threshold: 2,
            front_cooldown_secs: 1,
            fetch_retries: 1,
            metrics_output: None,
            dry_run: true,
            verbose: false,
            telegram_bot_token: None,
            telegram_chat_id: None,
            telegram_upload: false,
            github_actions: false,
        }
    }

    #[test]
    fn adaptive_controller_reduces_blocked_transport_workers() {
        let controller = AdaptiveConcurrency::new(2, 16);
        let failed = ProbeResult {
            line: "x".to_owned(),
            reachable: false,
            latency_ms: None,
            mode: "tcp",
            error: None,
        };
        controller.record_batch(Transport::Obfs4, &vec![failed; 10]);
        assert_eq!(controller.permits_for(Transport::Obfs4), 2);
    }

    #[test]
    fn metrics_exposes_success_failure_and_histogram() {
        let metrics = ProbeMetrics::default();
        metrics.record(
            Transport::Vanilla,
            &ProbeResult {
                line: "x".to_owned(),
                reachable: true,
                latency_ms: Some(42.0),
                mode: "tcp",
                error: None,
            },
        );
        let rendered = metrics.render();
        assert!(rendered.contains("tor_bridge_probe_total"));
        assert!(rendered.contains("transport=\"vanilla\""));
    }

    #[test]
    fn cmethod_parser_accepts_obfs4_socks_announcement() {
        assert_eq!(
            parse_cmethod("CMETHOD obfs4 socks5 127.0.0.1:43210"),
            Some("127.0.0.1:43210".parse().expect("fixture socket address"))
        );
        assert_eq!(parse_cmethod("CMETHODS DONE"), None);
    }

    #[test]
    fn engine_uses_config_without_panicking() {
        let engine = ProbeEngine::new(config());
        assert!(engine.metrics().render().contains("# HELP"));
    }
}

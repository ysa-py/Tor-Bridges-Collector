//! The measurement engine: runs a validated probe request and returns a
//! normalized [`ProbeResponse`].
//!
//! The engine reuses [`tbc_prober::socket::Socket`] for timed DNS resolution
//! and TCP connect with error classification, so the agent and the
//! out-of-country prober share one verdict taxonomy. A probe-layer error is a
//! *measurement outcome* (for example a refused connect is a legitimate
//! `refused` verdict), never a server crash: the engine maps every
//! [`tbc_prober::ProbeError`] into a response instead of propagating it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tbc_core::{ProbeKind, Verdict};
use tbc_prober::socket::Socket;

use crate::consent::{ConsentGate, ConsentRecord};
use crate::error::AgentError;
use crate::protocol::{verdict_token, ProbeRequest, ProbeResponse};
use crate::report::AnonymizedReport;

/// The in-country measurement engine.
#[derive(Debug)]
pub struct ProbeEngine {
    connect_timeout: Duration,
    id_prefix: String,
    counter: AtomicU64,
    consent: ConsentGate,
}

impl ProbeEngine {
    /// Build an engine with the given connect budget and measurement-ref
    /// prefix. An empty prefix falls back to `agent`.
    pub fn new(connect_timeout: Duration, id_prefix: String) -> Result<Self, AgentError> {
        if connect_timeout.is_zero() {
            return Err(AgentError::Config(
                "connect_timeout must be greater than zero".to_owned(),
            ));
        }
        let id_prefix = if id_prefix.trim().is_empty() {
            "agent".to_owned()
        } else {
            id_prefix
        };
        Ok(Self {
            connect_timeout,
            id_prefix,
            counter: AtomicU64::new(0),
            consent: ConsentGate::new(),
        })
    }

    /// Record the volunteer's consent, enabling probes. No probe runs before
    /// this has been called with explicit consent.
    pub fn grant_consent(&self, method: &str) -> ConsentRecord {
        self.consent.grant(method)
    }

    /// Whether consent has been recorded.
    pub fn consented(&self) -> bool {
        self.consent.is_granted()
    }

    /// Run a probe for `request`. Unsupported probe kinds fail explicitly
    /// with [`AgentError::UnsupportedProbe`] rather than returning a fake
    /// result; missing consent fails with [`AgentError::ConsentRequired`]
    /// before any traffic is sent.
    pub async fn probe(&self, request: &ProbeRequest) -> Result<ProbeResponse, AgentError> {
        self.consent.try_token()?;
        match request.probe_kind {
            ProbeKind::TcpConnect => self.probe_tcp_connect(request).await,
            other => Err(AgentError::UnsupportedProbe(
                probe_kind_token(other).to_owned(),
            )),
        }
    }

    /// Run a probe and return the field-limited [`AnonymizedReport`] that is
    /// the only data emitted upstream. Uses the same consent gate as
    /// [`probe`] and the same measurement path.
    pub async fn probe_report(
        &self,
        request: &ProbeRequest,
        asn: Option<u32>,
    ) -> Result<AnonymizedReport, AgentError> {
        self.consent.try_token()?;
        match request.probe_kind {
            ProbeKind::TcpConnect => {
                let start = Instant::now();
                match Socket::connect(&request.target, request.port, self.connect_timeout).await {
                    Ok(_) => Ok(AnonymizedReport::new(
                        &Verdict::Reachable,
                        Some(elapsed_ms(start)),
                        asn,
                    )),
                    Err(error) => Ok(AnonymizedReport::new(&error.verdict(), None, asn)),
                }
            }
            other => Err(AgentError::UnsupportedProbe(
                probe_kind_token(other).to_owned(),
            )),
        }
    }

    async fn probe_tcp_connect(&self, request: &ProbeRequest) -> Result<ProbeResponse, AgentError> {
        let measurement_ref = self.next_ref();
        let start = Instant::now();
        match Socket::connect(&request.target, request.port, self.connect_timeout).await {
            Ok(_stream) => Ok(ProbeResponse {
                verdict: verdict_token(&Verdict::Reachable),
                rtt_ms: Some(elapsed_ms(start)),
                error_class: None,
                evidence: None,
                measurement_ref,
                http_status: None,
            }),
            Err(error) => Ok(response_for_probe_error(&error, measurement_ref)),
        }
    }

    fn next_ref(&self) -> String {
        let sequence = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}", self.id_prefix, sequence)
    }
}

/// Build a normalized response from a probe-layer error, carrying the stable
/// error classifier and the raw evidence.
pub fn response_for_probe_error(
    error: &tbc_prober::ProbeError,
    measurement_ref: String,
) -> ProbeResponse {
    let verdict = error.verdict();
    let mut response = ProbeResponse {
        verdict: verdict_token(&verdict),
        rtt_ms: None,
        error_class: Some(error.kind_name().to_owned()),
        evidence: Some(error.to_string()),
        measurement_ref,
        http_status: None,
    };
    if let Verdict::HttpError { code } = verdict {
        response.http_status = Some(code);
    }
    response
}

fn probe_kind_token(kind: ProbeKind) -> &'static str {
    match kind {
        ProbeKind::TcpConnect => "tcp_connect",
        ProbeKind::Obfs4Handshake => "obfs4_handshake",
        ProbeKind::WebTunnelUpgrade => "webtunnel_upgrade",
        ProbeKind::TorBootstrap => "tor_bootstrap",
        ProbeKind::TlsSni => "tls_sni",
        ProbeKind::TcpTraceroute => "tcp_traceroute",
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    let millis = start.elapsed().as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn engine_rejects_zero_connect_timeout() {
        let error = ProbeEngine::new(Duration::ZERO, "agent".to_owned()).unwrap_err();
        assert_eq!(error.kind_name(), "config_error");
    }

    #[test]
    fn engine_falls_back_on_empty_id_prefix() {
        let engine = ProbeEngine::new(Duration::from_secs(1), "  ".to_owned()).unwrap();
        assert!(engine.next_ref().starts_with("agent-"));
    }

    #[tokio::test]
    async fn unsupported_probe_kind_fails_explicitly() {
        let engine = ProbeEngine::new(Duration::from_secs(1), "agent".to_owned()).unwrap();
        engine.grant_consent("test");
        let request = ProbeRequest {
            target: "1.2.3.4".to_owned(),
            port: 443,
            probe_kind: ProbeKind::TlsSni,
        };
        let error = engine.probe(&request).await.unwrap_err();
        assert_eq!(error.kind_name(), "unsupported_probe_kind");
    }

    #[tokio::test]
    async fn probe_requires_recorded_consent() {
        let engine = ProbeEngine::new(Duration::from_secs(1), "agent".to_owned()).unwrap();
        let request = ProbeRequest {
            target: "127.0.0.1".to_owned(),
            port: 9,
            probe_kind: ProbeKind::TcpConnect,
        };
        let error = engine.probe(&request).await.unwrap_err();
        assert_eq!(error.kind_name(), "consent_required");
        engine.grant_consent("test");
        assert!(engine.consented());
    }

    #[test]
    fn probe_errors_map_to_verdict_tokens() {
        let cases = [
            (
                tbc_prober::ProbeError::Refused,
                "refused",
                "connection_refused",
            ),
            (
                tbc_prober::ProbeError::Timeout { phase: "connect" },
                "timeout",
                "timeout",
            ),
            (
                tbc_prober::ProbeError::Reset { phase: "read" },
                "reset_injected",
                "connection_reset",
            ),
            (
                tbc_prober::ProbeError::Dns {
                    host: "x".to_owned(),
                },
                "dns_failure",
                "dns_failure",
            ),
        ];
        for (error, token, kind) in cases {
            let response = response_for_probe_error(&error, "agent-0".to_owned());
            assert_eq!(response.verdict, token);
            assert_eq!(response.error_class.as_deref(), Some(kind));
            assert!(response.evidence.is_some());
            assert_eq!(response.measurement_ref, "agent-0");
        }
    }

    #[test]
    fn http_error_verdict_carries_http_status() {
        let error = tbc_prober::ProbeError::HttpStatus {
            transport: "webtunnel",
            code: 403,
        };
        let response = response_for_probe_error(&error, "agent-1".to_owned());
        assert_eq!(response.verdict, "http_error");
        assert_eq!(response.http_status, Some(403));
    }
}

//! Volunteer-agent adapter.
//!
//! The collector POSTs a probe request to a volunteer agent endpoint and the
//! agent performs the in-country measurement and returns a normalized
//! verdict. The wire protocol is intentionally minimal and documented here:
//!
//! ```text
//! POST /probe  {"target":"...", "port":443, "probe_kind":"tcp_connect"}
//! 200          {"verdict":"reachable","rtt_ms":64,"error_class":null,
//!                "evidence":"...","measurement_ref":"agent-1"}
//! ```
//!
//! `verdict` is one of the `tbc_core::Verdict` snake_case tokens
//! (`reachable`, `refused`, `timeout`, `reset_injected`, `tls_alert`,
//! `handshake_auth_fail`, `dns_failure`, `blocked`, `http_error`,
//! `inconclusive`). `blocked` carries its evidence in `evidence`;
//! `http_error` carries the status in `http_status`. The other side of this
//! protocol (the agent software itself) is `crates/agent`.

use std::sync::Arc;

use chrono::Utc;
use serde::Deserialize;
use tbc_core::{VantageKind, Verdict};

use crate::budget::Budget;
use crate::error::VantageError;
use crate::platform;
use crate::request::{MeasurementRequest, ProbeResult};
use crate::transport::{HttpTransport, Method, VantageRequest};
use crate::vantage::Vantage;
use crate::BoxFuture;

/// A volunteer-agent in-country measurement adapter.
#[derive(Debug, Clone)]
pub struct AgentVantage {
    base_url: String,
    http: Arc<dyn HttpTransport>,
}

impl AgentVantage {
    /// Build the adapter from a base URL (no trailing slash) and a transport.
    pub fn new(base_url: String, http: Arc<dyn HttpTransport>) -> Result<Self, VantageError> {
        if base_url.trim().is_empty() {
            return Err(VantageError::Config(
                "agent base_url must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http,
        })
    }
}

#[derive(Debug, Deserialize)]
struct AgentResponse {
    verdict: String,
    #[serde(default)]
    rtt_ms: Option<u64>,
    #[serde(default)]
    error_class: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    measurement_ref: String,
    #[serde(default)]
    http_status: Option<u16>,
}

impl Vantage for AgentVantage {
    fn kind(&self) -> VantageKind {
        VantageKind::VolunteerAgent
    }

    fn run<'a>(
        &'a self,
        request: &'a MeasurementRequest,
        budget: &'a mut Budget,
    ) -> BoxFuture<'a, Result<ProbeResult, VantageError>> {
        Box::pin(async move {
            let body = serde_json::json!({
                "target": request.target,
                "port": request.port,
                "probe_kind": serde_json::to_value(request.probe_kind)?,
            });
            let body_bytes = serde_json::to_vec(&body)?;

            budget.spend()?;
            let response = platform::call(
                self.http.as_ref(),
                &VantageRequest {
                    method: Method::Post,
                    url: format!("{}/probe", self.base_url),
                    headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                    body: Some(body_bytes),
                },
            )
            .await?;
            let parsed: AgentResponse = platform::parse_json(response, "agent")?;

            let verdict =
                parse_verdict(&parsed.verdict, parsed.evidence.clone(), parsed.http_status)?;
            Ok(ProbeResult {
                verdict,
                rtt_ms: parsed.rtt_ms,
                error_class: parsed.error_class,
                raw_evidence: parsed.evidence,
                measurement_ref: if parsed.measurement_ref.is_empty() {
                    "agent".to_owned()
                } else {
                    parsed.measurement_ref
                },
                measured_at: Utc::now(),
            })
        })
    }
}

/// Map an agent verdict token (and its evidence/status) to a [`Verdict`].
fn parse_verdict(
    token: &str,
    evidence: Option<String>,
    http_status: Option<u16>,
) -> Result<Verdict, VantageError> {
    match token {
        "reachable" => Ok(Verdict::Reachable),
        "refused" => Ok(Verdict::Refused),
        "timeout" => Ok(Verdict::Timeout),
        "reset_injected" => Ok(Verdict::ResetInjected),
        "tls_alert" => Ok(Verdict::TlsAlert),
        "handshake_auth_fail" => Ok(Verdict::HandshakeAuthFail),
        "dns_failure" => Ok(Verdict::DnsFailure),
        "inconclusive" => Ok(Verdict::Inconclusive),
        "blocked" => Ok(Verdict::Blocked {
            evidence: evidence.unwrap_or_else(|| "agent_blocked".to_owned()),
        }),
        "http_error" => Ok(Verdict::HttpError {
            code: http_status.unwrap_or(0),
        }),
        other => Err(VantageError::Parse(format!(
            "agent returned unknown verdict {other:?}"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_verdict_maps_tokens() {
        assert_eq!(
            parse_verdict("reachable", None, None).unwrap(),
            Verdict::Reachable
        );
        assert_eq!(
            parse_verdict("http_error", None, Some(403)).unwrap(),
            Verdict::HttpError { code: 403 }
        );
        assert_eq!(
            parse_verdict("blocked", Some("SYN drop".to_owned()), None).unwrap(),
            Verdict::Blocked {
                evidence: "SYN drop".to_owned()
            }
        );
    }

    #[test]
    fn parse_verdict_rejects_unknown_token() {
        assert!(parse_verdict("banana", None, None).is_err());
    }
}

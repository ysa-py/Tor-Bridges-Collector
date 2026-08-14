//! The `AgentVantage` wire protocol types.
//!
//! This is the server side of the protocol documented in
//! `crates/vantage/src/agent.rs`:
//!
//! ```text
//! POST /probe  {"target":"1.2.3.4", "port":443, "probe_kind":"tcp_connect"}
//! 200          {"verdict":"reachable","rtt_ms":64,"error_class":null,
//!                "evidence":null,"measurement_ref":"agent-1","http_status":null}
//! ```
//!
//! [`verdict_token`] must stay byte-identical to the token set parsed by
//! `AgentVantage::parse_verdict` in `tbc-vantage`: `reachable`, `refused`,
//! `timeout`, `reset_injected`, `tls_alert`, `handshake_auth_fail`,
//! `dns_failure`, `blocked`, `http_error`, and `inconclusive`.

use serde::{Deserialize, Serialize};
use tbc_core::{ProbeKind, Verdict};

use crate::config::AgentConfig;
use crate::error::AgentError;

/// A probe request posted to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    /// The bridge target: an IP literal or DNS name, without a port.
    pub target: String,
    /// The bridge TCP port (1..=65535).
    pub port: u16,
    /// The probe kind to perform.
    pub probe_kind: ProbeKind,
}

impl ProbeRequest {
    /// Reject requests that are empty, oversized, or carry characters that a
    /// valid IP literal or hostname can never contain (which also prevents
    /// header/URL injection into the downstream probe).
    pub fn validate(&self, config: &AgentConfig) -> Result<(), AgentError> {
        if self.target.is_empty() {
            return Err(AgentError::BadRequest(
                "target must not be empty".to_owned(),
            ));
        }
        if self.target.len() > config.max_target_bytes {
            return Err(AgentError::BadRequest(format!(
                "target exceeds the {}-byte limit",
                config.max_target_bytes
            )));
        }
        if !self
            .target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-' | b'_'))
        {
            return Err(AgentError::BadRequest(
                "target contains disallowed characters".to_owned(),
            ));
        }
        if self.port == 0 {
            return Err(AgentError::BadRequest(
                "port must be in 1..=65535".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A normalized measurement response returned to the collector.
///
/// The optional fields are omitted from the JSON body when absent, matching
/// the collector's `AgentResponse` deserialization shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResponse {
    /// The normalized verdict token (see [`verdict_token`]).
    pub verdict: String,
    /// Connect-completion round-trip time in milliseconds, if measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    /// A classified error code, when the verdict is not reachable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Raw, unredacted evidence from the measurement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// The agent-generated measurement identifier.
    pub measurement_ref: String,
    /// The HTTP status the target returned, for `http_error` verdicts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
}

/// The canonical lower-case token for a [`Verdict`], matching the token set
/// parsed by the `AgentVantage` adapter in `tbc-vantage`.
pub fn verdict_token(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Reachable => "reachable",
        Verdict::Refused => "refused",
        Verdict::Timeout => "timeout",
        Verdict::ResetInjected => "reset_injected",
        Verdict::TlsAlert => "tls_alert",
        Verdict::HandshakeAuthFail => "handshake_auth_fail",
        Verdict::DnsFailure => "dns_failure",
        Verdict::Blocked { .. } => "blocked",
        Verdict::HttpError { .. } => "http_error",
        Verdict::Inconclusive => "inconclusive",
    }
    .to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn verdict_tokens_match_the_collector_protocol() {
        let tokens = [
            (Verdict::Reachable, "reachable"),
            (Verdict::Refused, "refused"),
            (Verdict::Timeout, "timeout"),
            (Verdict::ResetInjected, "reset_injected"),
            (Verdict::TlsAlert, "tls_alert"),
            (Verdict::HandshakeAuthFail, "handshake_auth_fail"),
            (Verdict::DnsFailure, "dns_failure"),
            (
                Verdict::Blocked {
                    evidence: "e".to_owned(),
                },
                "blocked",
            ),
            (Verdict::HttpError { code: 403 }, "http_error"),
            (Verdict::Inconclusive, "inconclusive"),
        ];
        for (verdict, token) in tokens {
            assert_eq!(verdict_token(&verdict), token);
        }
    }

    #[test]
    fn request_serde_round_trips() {
        let request = ProbeRequest {
            target: "1.2.3.4".to_owned(),
            port: 443,
            probe_kind: ProbeKind::TcpConnect,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            "{\"target\":\"1.2.3.4\",\"port\":443,\"probe_kind\":\"tcp_connect\"}"
        );
        let decoded: ProbeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn validate_rejects_bad_targets() {
        let config = AgentConfig::default();
        for target in ["", "has space", "a/b", "host\0nul"] {
            let request = ProbeRequest {
                target: target.to_owned(),
                port: 443,
                probe_kind: ProbeKind::TcpConnect,
            };
            assert!(request.validate(&config).is_err(), "target {target:?}");
        }
    }

    #[test]
    fn validate_rejects_port_zero() {
        let config = AgentConfig::default();
        let request = ProbeRequest {
            target: "1.2.3.4".to_owned(),
            port: 0,
            probe_kind: ProbeKind::TcpConnect,
        };
        assert!(request.validate(&config).is_err());
    }

    #[test]
    fn validate_accepts_ip_literal_and_hostname() {
        let config = AgentConfig::default();
        for target in ["1.2.3.4", "2001:db8::1", "bridge.example.com"] {
            let request = ProbeRequest {
                target: target.to_owned(),
                port: 443,
                probe_kind: ProbeKind::TcpConnect,
            };
            assert!(request.validate(&config).is_ok(), "target {target:?}");
        }
    }
}

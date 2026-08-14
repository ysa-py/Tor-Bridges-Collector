//! Typed error taxonomy for the volunteer agent.
//!
//! Every fallible operation in the agent returns an [`AgentError`] instead of
//! panicking. Each variant carries enough information to (a) classify the
//! failure with a stable, metric-safe name, (b) map it to the HTTP status the
//! server should return, and (c) map probe-layer failures to a
//! [`tbc_core::Verdict`] for an observation.

use tbc_core::Verdict;

/// Errors raised while serving or performing agent measurements.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The agent configuration is invalid.
    #[error("invalid agent configuration: {0}")]
    Config(String),

    /// The HTTP request could not be parsed as HTTP/1.1.
    #[error("HTTP protocol error: {0}")]
    Protocol(String),

    /// The request head or body exceeded the configured byte limit.
    #[error("request exceeded the {0}-byte limit")]
    BodyTooLarge(usize),

    /// A JSON payload failed to deserialize.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// A request was well-formed JSON but semantically invalid.
    #[error("invalid probe request: {0}")]
    BadRequest(String),

    /// The caller exceeded its per-client rate budget.
    #[error("rate limit exceeded")]
    RateLimited,

    /// The volunteer has not yet recorded consent; the agent refuses to probe.
    #[error("volunteer consent has not been recorded")]
    ConsentRequired,

    /// The volunteer gave an unrecognized answer to the consent prompt.
    #[error("unrecognized consent response: {0}")]
    ConsentInput(String),

    /// The requested probe kind is not implemented by this agent.
    #[error("unsupported probe kind: {0:?}")]
    UnsupportedProbe(String),

    /// The underlying probe engine failed to run a measurement.
    #[error("probe failed: {0}")]
    Probe(#[from] tbc_prober::ProbeError),

    /// An operation timed out during `phase`.
    #[error("timed out during {phase}")]
    Timeout {
        /// The I/O phase that exceeded its budget (`read`, `write`).
        phase: &'static str,
    },

    /// An unclassified I/O error during `phase`.
    #[error("I/O error during {phase}: {message}")]
    Io {
        /// The I/O phase in which the error occurred.
        phase: &'static str,
        /// The underlying error text.
        message: String,
    },
}

impl AgentError {
    /// A stable, metric-safe classifier for the error, suitable for counters
    /// and structured logs. Values never include attacker-controlled data.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Config(_) => "config_error",
            Self::Protocol(_) => "http_protocol_error",
            Self::BodyTooLarge(_) => "body_too_large",
            Self::Json(_) => "invalid_json",
            Self::BadRequest(_) => "bad_request",
            Self::RateLimited => "rate_limited",
            Self::ConsentRequired => "consent_required",
            Self::ConsentInput(_) => "consent_input_error",
            Self::UnsupportedProbe(_) => "unsupported_probe_kind",
            Self::Probe(inner) => inner.kind_name(),
            Self::Timeout { .. } => "timeout",
            Self::Io { .. } => "io_error",
        }
    }

    /// The HTTP status code the server should return for this error.
    /// Request-shape failures are 4xx (the caller can fix them); internal or
    /// environmental failures are 5xx.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Config(_) => 500,
            Self::Protocol(_) => 400,
            Self::BodyTooLarge(_) => 413,
            Self::Json(_) => 400,
            Self::BadRequest(_) => 400,
            Self::RateLimited => 429,
            Self::ConsentRequired => 403,
            Self::ConsentInput(_) => 400,
            Self::UnsupportedProbe(_) => 422,
            Self::Probe(_) => 500,
            Self::Timeout { .. } => 504,
            Self::Io { .. } => 500,
        }
    }

    /// Map the error to a [`Verdict`], delegating to the probe layer's own
    /// mapping when the failure came from the network probe.
    pub fn verdict(&self) -> Verdict {
        match self {
            Self::Probe(inner) => inner.verdict(),
            _ => Verdict::Inconclusive,
        }
    }

    /// Whether a retry could plausibly change the outcome. Only transient
    /// network/transport failures are retryable; policy and parse failures are
    /// not.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Probe(inner) => inner.is_retryable(),
            Self::Timeout { .. } => true,
            _ => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_are_stable() {
        assert_eq!(AgentError::RateLimited.kind_name(), "rate_limited");
        assert_eq!(
            AgentError::UnsupportedProbe("tls_sni".to_owned()).kind_name(),
            "unsupported_probe_kind"
        );
        assert_eq!(
            AgentError::Probe(tbc_prober::ProbeError::Timeout { phase: "connect" }).kind_name(),
            "timeout"
        );
    }

    #[test]
    fn status_codes_map_request_vs_internal_failures() {
        assert_eq!(AgentError::BadRequest("x".to_owned()).status_code(), 400);
        assert_eq!(AgentError::BodyTooLarge(4096).status_code(), 413);
        assert_eq!(AgentError::RateLimited.status_code(), 429);
        assert_eq!(
            AgentError::UnsupportedProbe("x".to_owned()).status_code(),
            422
        );
        assert_eq!(
            AgentError::Io {
                phase: "read",
                message: "boom".to_owned()
            }
            .status_code(),
            500
        );
    }

    #[test]
    fn verdict_delegates_to_probe_error() {
        let error = AgentError::Probe(tbc_prober::ProbeError::Refused);
        assert_eq!(error.verdict(), Verdict::Refused);
        assert!(error.is_retryable());

        let parse = AgentError::BadRequest("x".to_owned());
        assert_eq!(parse.verdict(), Verdict::Inconclusive);
        assert!(!parse.is_retryable());
    }
}

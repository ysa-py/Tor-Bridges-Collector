//! Typed error taxonomy for the collector layer.
//!
//! Every fallible operation in this crate returns a [`SourceError`] (or a
//! report that carries one), so callers can classify failures precisely and
//! apply the right policy: retry with backoff, degrade, or skip-and-record.

use thiserror::Error;

/// Errors produced while configuring or running a bridge source.
#[derive(Debug, Error)]
pub enum SourceError {
    /// A collector was configured with an invalid value.
    #[error("collector configuration error: {0}")]
    Config(String),

    /// A string that should have been a URL was not.
    #[error("invalid URL: {0:?}")]
    InvalidUrl(String),

    /// The server answered with a status outside the expected 2xx/304 set.
    #[error("HTTP {status} for {url}")]
    Http { url: String, status: u16 },

    /// The server answered HTTP 429 (or otherwise signaled a quota limit).
    #[error("rate limited (HTTP 429) for {url}")]
    RateLimited { url: String },

    /// The per-host circuit breaker is open and refused the request.
    #[error("circuit breaker open for host {host:?}")]
    CircuitOpen { host: String },

    /// A transport-level failure (DNS, connect, timeout, TLS) occurred.
    #[error("transport failure for {url}: {message}")]
    Transport { url: String, message: String },

    /// A response body could not be parsed into bridge lines.
    #[error("response parse failure: {0}")]
    Parse(String),

    /// The global rate limiter was misconfigured.
    #[error("rate limiter misconfigured: {0}")]
    RateLimit(String),

    /// A cached HTTP validator header could not be reconstructed.
    #[error("invalid cached HTTP header: {0}")]
    Header(String),
}

impl SourceError {
    /// Whether this error should be retried (with backoff) rather than treated
    /// as a permanent, skip-and-record failure.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } | Self::RateLimited { .. } => true,
            Self::Http { status, .. } => {
                // 408 Request Timeout and the 5xx class are transient.
                *status == 408 || (500..=599).contains(status)
            }
            Self::Config(_)
            | Self::InvalidUrl(_)
            | Self::CircuitOpen { .. }
            | Self::Parse(_)
            | Self::RateLimit(_)
            | Self::Header(_) => false,
        }
    }

    /// A stable, metric-safe name for the failure class (no URL/host data).
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::InvalidUrl(_) => "invalid_url",
            Self::Http { .. } => "http",
            Self::RateLimited { .. } => "rate_limited",
            Self::CircuitOpen { .. } => "circuit_open",
            Self::Transport { .. } => "transport",
            Self::Parse(_) => "parse",
            Self::RateLimit(_) => "rate_limit_config",
            Self::Header(_) => "header",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn retryability_classification() {
        assert!(SourceError::Transport {
            url: "u".into(),
            message: "timeout".into()
        }
        .is_retryable());
        assert!(SourceError::RateLimited { url: "u".into() }.is_retryable());
        assert!(SourceError::Http {
            url: "u".into(),
            status: 503
        }
        .is_retryable());
        assert!(SourceError::Http {
            url: "u".into(),
            status: 408
        }
        .is_retryable());
        assert!(!SourceError::Http {
            url: "u".into(),
            status: 404
        }
        .is_retryable());
        assert!(!SourceError::Parse("x".into()).is_retryable());
        assert!(!SourceError::CircuitOpen { host: "h".into() }.is_retryable());
    }

    #[test]
    fn kind_names_are_stable_and_data_free() {
        assert_eq!(
            SourceError::Transport {
                url: "https://example.invalid/secret".into(),
                message: "boom".into()
            }
            .kind_name(),
            "transport"
        );
        assert_eq!(
            SourceError::CircuitOpen {
                host: "sensitive-host".into()
            }
            .kind_name(),
            "circuit_open"
        );
    }
}

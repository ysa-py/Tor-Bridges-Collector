//! Typed error taxonomy for the vantage adapters.
//!
//! Every fallible operation returns a [`VantageError`] instead of panicking.
//! Each variant carries enough information to classify the failure (stable,
//! metric-safe name), decide retryability, and map it to a
//! [`tbc_core::Verdict`] for an observation.

use tbc_core::Verdict;

/// Errors raised while submitting or collecting a vantage measurement.
#[derive(Debug, thiserror::Error)]
pub enum VantageError {
    /// The adapter or request configuration is invalid.
    #[error("invalid vantage configuration: {0}")]
    Config(String),

    /// The quota budget was exhausted before the call could be made.
    #[error("quota budget exhausted")]
    QuotaExhausted,

    /// A required API key is missing for the platform.
    #[error("missing API key for {platform}")]
    MissingApiKey {
        /// The platform whose key is required (e.g. `ripe_atlas`).
        platform: &'static str,
    },

    /// The HTTP transport failed (DNS, TLS, connection, timeout).
    #[error("transport error for {url}: {message}")]
    Transport {
        /// The URL that failed.
        url: String,
        /// The underlying error text.
        message: String,
    },

    /// The platform returned a non-success HTTP status.
    #[error("HTTP {status} from {url}")]
    Http {
        /// The URL that was requested.
        url: String,
        /// The HTTP status code.
        status: u16,
    },

    /// The platform rate-limited the caller (HTTP 429).
    #[error("rate limited by {url}")]
    RateLimited {
        /// The URL that was rate-limited.
        url: String,
    },

    /// A JSON payload failed to serialize or deserialize.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A platform response was well-formed JSON but failed semantic parsing.
    #[error("parse error: {0}")]
    Parse(String),

    /// The platform reported that the measurement itself failed.
    #[error("measurement failed on {platform}: {message}")]
    MeasurementFailed {
        /// The platform that reported the failure.
        platform: &'static str,
        /// The failure detail.
        message: String,
    },

    /// The measurement did not reach a terminal state within the poll budget.
    #[error("measurement on {platform} did not finish within the poll budget")]
    PollExhausted {
        /// The platform being polled.
        platform: &'static str,
    },
}

impl VantageError {
    /// A stable, metric-safe classifier for the error, suitable for counters
    /// and structured logs. Values never include attacker-controlled data.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Config(_) => "config_error",
            Self::QuotaExhausted => "quota_exhausted",
            Self::MissingApiKey { .. } => "missing_api_key",
            Self::Transport { .. } => "transport_error",
            Self::Http { .. } => "http_error",
            Self::RateLimited { .. } => "rate_limited",
            Self::Json(_) => "json_error",
            Self::Parse(_) => "parse_error",
            Self::MeasurementFailed { .. } => "measurement_failed",
            Self::PollExhausted { .. } => "poll_exhausted",
        }
    }

    /// Map the error to a [`Verdict`] for an [`tbc_core::Observation`].
    pub fn verdict(&self) -> Verdict {
        match self {
            Self::Config(_) => Verdict::Inconclusive,
            Self::QuotaExhausted => Verdict::Inconclusive,
            Self::MissingApiKey { .. } => Verdict::Inconclusive,
            Self::Transport { .. } => Verdict::Inconclusive,
            Self::Http { .. } => Verdict::Inconclusive,
            Self::RateLimited { .. } => Verdict::Inconclusive,
            Self::Json(_) => Verdict::Inconclusive,
            Self::Parse(_) => Verdict::Inconclusive,
            Self::MeasurementFailed { .. } => Verdict::Inconclusive,
            Self::PollExhausted { .. } => Verdict::Inconclusive,
        }
    }

    /// Whether a retry could plausibly change the outcome. Transport errors
    /// and rate limits are transient; quota, key, and parse failures are not.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport { .. } | Self::RateLimited { .. })
    }
}

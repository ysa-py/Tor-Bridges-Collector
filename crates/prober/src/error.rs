//! Typed error taxonomy for the prober.
//!
//! Every fallible probe operation returns a [`ProbeError`] instead of
//! panicking. Each variant carries enough information to (a) classify the
//! failure with a stable, metric-safe name, (b) map it to a
//! [`tbc_core::Verdict`], and (c) decide whether a retry could plausibly
//! succeed (see [`ProbeError::is_retryable`]).

use tbc_core::Verdict;

/// Errors raised while connecting to or probing a bridge.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// The bridge host could not be resolved.
    #[error("DNS resolution failed for host {host:?}")]
    Dns {
        /// The host that failed to resolve.
        host: String,
    },

    /// The TCP connection was actively refused.
    #[error("connection refused")]
    Refused,

    /// The peer reset or closed the connection during `phase`.
    #[error("connection reset during {phase}")]
    Reset {
        /// The I/O phase in which the reset occurred (`connect`, `read`, `write`).
        phase: &'static str,
    },

    /// An operation timed out during `phase`.
    #[error("timed out during {phase}")]
    Timeout {
        /// The I/O phase that exceeded its budget (`connect`, `dns`, `read`, `write`).
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

    /// A transport codec rejected input or failed to encode output.
    #[error("transport codec error: {0}")]
    Codec(String),

    /// The endpoint did not speak the expected protocol.
    #[error("protocol error ({transport}): {message}")]
    Protocol {
        /// The transport family being probed.
        transport: &'static str,
        /// The protocol-level failure detail.
        message: String,
    },

    /// A cryptographic primitive (HMAC, SHA) could not be initialized.
    #[error("crypto primitive error: {0}")]
    Crypto(String),

    /// The endpoint failed handshake authentication.
    #[error("handshake authentication failed ({transport}): {message}")]
    AuthFailed {
        /// The transport family being probed.
        transport: &'static str,
        /// The authentication failure detail.
        message: String,
    },

    /// The endpoint returned an HTTP status outside the success range.
    #[error("HTTP {code} from {transport}")]
    HttpStatus {
        /// The transport family being probed.
        transport: &'static str,
        /// The HTTP status code returned.
        code: u16,
    },

    /// The transport has no probe implemented.
    #[error("unsupported transport {0:?}")]
    UnsupportedTransport(String),

    /// The probe configuration is invalid.
    #[error("invalid probe configuration: {0}")]
    Config(String),
}

impl ProbeError {
    /// A stable, metric-safe classifier for the error, suitable for counters
    /// and structured logs. Values never include attacker-controlled data.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Dns { .. } => "dns_failure",
            Self::Refused => "connection_refused",
            Self::Reset { .. } => "connection_reset",
            Self::Timeout { .. } => "timeout",
            Self::Io { .. } => "io_error",
            Self::Codec(_) => "codec_error",
            Self::Protocol { .. } => "protocol_error",
            Self::Crypto(_) => "crypto_error",
            Self::AuthFailed { .. } => "handshake_auth_fail",
            Self::HttpStatus { .. } => "http_error",
            Self::UnsupportedTransport(_) => "unsupported_transport",
            Self::Config(_) => "config_error",
        }
    }

    /// Map the error to a [`Verdict`] for an [`tbc_core::Observation`].
    pub fn verdict(&self) -> Verdict {
        match self {
            Self::Dns { .. } => Verdict::DnsFailure,
            Self::Refused => Verdict::Refused,
            Self::Reset { .. } => Verdict::ResetInjected,
            Self::Timeout { .. } => Verdict::Timeout,
            Self::Io { .. } => Verdict::Inconclusive,
            Self::Codec(_) => Verdict::Inconclusive,
            Self::Protocol { .. } => Verdict::Inconclusive,
            Self::Crypto(_) => Verdict::Inconclusive,
            Self::AuthFailed { .. } => Verdict::HandshakeAuthFail,
            Self::HttpStatus { code, .. } => Verdict::HttpError { code: *code },
            Self::UnsupportedTransport(_) => Verdict::Inconclusive,
            Self::Config(_) => Verdict::Inconclusive,
        }
    }

    /// Whether a retry (after backoff) could plausibly change the outcome.
    ///
    /// Transient network failures are retryable; definitive protocol,
    /// authentication, and policy failures are not.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Dns { .. }
                | Self::Refused
                | Self::Reset { .. }
                | Self::Timeout { .. }
                | Self::Io { .. }
        )
    }
}

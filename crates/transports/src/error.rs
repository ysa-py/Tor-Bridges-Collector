//! Typed error taxonomy for the transport codecs.
//!
//! Every fallible codec operation returns a [`TransportError`] instead of
//! panicking, so callers (the `prober`, `agent`, and `cli` crates) can
//! classify, log, and count failures without string matching.

/// Errors raised while encoding or decoding a transport wire format.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The obfs4 `cert=` value is not valid base64.
    #[error("invalid obfs4 certificate encoding")]
    InvalidCert,

    /// The obfs4 `cert=` value decodes to the wrong number of bytes.
    #[error("obfs4 certificate must decode to 52 bytes, got {0}")]
    InvalidCertLength(usize),

    /// The `iat-mode=` value is not `0`, `1`, or `2`.
    #[error("invalid iat-mode {0:?}; expected 0, 1, or 2")]
    InvalidIatMode(String),

    /// Handshake padding length is outside the permitted range.
    #[error("invalid handshake padding: expected [{min}, {max}] bytes, got {actual}")]
    InvalidPadding {
        /// Inclusive minimum padding length.
        min: usize,
        /// Inclusive maximum padding length.
        max: usize,
        /// The actual padding length supplied.
        actual: usize,
    },

    /// A handshake frame has an invalid total length.
    #[error("invalid {what} frame length: {actual} bytes")]
    InvalidFrameLength {
        /// Human-readable name of the frame being decoded.
        what: &'static str,
        /// The actual frame length.
        actual: usize,
    },

    /// A buffer ended before all expected bytes were available.
    #[error("truncated input: need {needed} bytes, have {available}")]
    Truncated {
        /// Bytes required at the current offset.
        needed: usize,
        /// Bytes actually remaining.
        available: usize,
    },

    /// An obfs4 mark or MAC did not verify.
    #[error("obfs4 MAC verification failed: {0}")]
    BadMac(&'static str),

    /// The HMAC-SHA256 primitive could not be initialized.
    #[error("failed to initialize HMAC-SHA256: {0}")]
    Hmac(String),

    /// A malformed or unexpected HTTP message.
    #[error("malformed HTTP message: {0}")]
    Http(String),

    /// A required input field was absent.
    #[error("missing field {0}")]
    MissingField(&'static str),

    /// The transport is not one this codec supports.
    #[error("unsupported transport {0:?}")]
    UnsupportedTransport(String),

    /// A Snowflake broker status token is not recognized.
    #[error("unrecognized snowflake status {0:?}")]
    InvalidStatus(String),

    /// A Snowflake broker message failed field validation.
    #[error("snowflake message validation failed: {0}")]
    Snowflake(String),

    /// An OR cell payload is not the fixed cell-payload length.
    #[error("invalid OR cell payload length {0}; expected {1}")]
    InvalidCellPayload(usize, usize),

    /// An OR cell could not be decoded.
    #[error("OR cell decode error: {0}")]
    Cell(&'static str),

    /// A JSON payload failed to serialize or deserialize.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl TransportError {
    /// A stable, metric-safe classifier for the error, suitable for counters
    /// and structured logs. Values never include attacker-controlled data.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::InvalidCert => "invalid_cert",
            Self::InvalidCertLength(_) => "invalid_cert_length",
            Self::InvalidIatMode(_) => "invalid_iat_mode",
            Self::InvalidPadding { .. } => "invalid_padding",
            Self::InvalidFrameLength { .. } => "invalid_frame_length",
            Self::Truncated { .. } => "truncated",
            Self::BadMac(_) => "bad_mac",
            Self::Hmac(_) => "hmac",
            Self::Http(_) => "http",
            Self::MissingField(_) => "missing_field",
            Self::UnsupportedTransport(_) => "unsupported_transport",
            Self::InvalidStatus(_) => "invalid_status",
            Self::Snowflake(_) => "snowflake",
            Self::InvalidCellPayload(_, _) => "invalid_cell_payload",
            Self::Cell(_) => "cell",
            Self::Json(_) => "json",
        }
    }
}

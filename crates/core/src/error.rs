//! Typed error taxonomy for the core domain model.
//!
//! Every fallible operation in this crate returns one of these variants (or a
//! type that wraps one), so callers can classify failures precisely instead of
//! matching on string content. Errors implement [`std::error::Error`] and
//! [`std::fmt::Display`] via `thiserror`, which keeps them usable with `?`,
//! `anyhow`, and structured loggers.

use thiserror::Error;

/// Errors produced while parsing or validating bridge and observation data.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ModelError {
    /// The input is not a bridge line at all (empty, comment, or too short).
    #[error("not a bridge line: {0}")]
    NotABridgeLine(&'static str),

    /// A host string that is neither a valid IP address nor a DNS name.
    #[error("invalid host: {0:?}")]
    InvalidHost(String),

    /// A malformed IPv4 literal.
    #[error("invalid IPv4 address: {0:?}")]
    InvalidIpv4(String),

    /// A malformed IPv6 literal.
    #[error("invalid IPv6 address: {0:?}")]
    InvalidIpv6(String),

    /// A port that is non-numeric or outside 1..=65535 (0 is reserved).
    #[error("invalid port: {0:?}")]
    InvalidPort(String),

    /// A fingerprint that is not exactly 40 hexadecimal characters.
    #[error("fingerprint must be exactly 40 hexadecimal characters, got {0:?}")]
    InvalidFingerprint(String),

    /// A certificate value that is not valid base64.
    #[error("certificate is not valid base64: {0}")]
    InvalidCert(String),

    /// A certificate whose decoded length is not the required byte count.
    #[error("certificate must decode to exactly 52 bytes, decoded {0} bytes")]
    InvalidCertLength(usize),

    /// A URL with a disallowed or unparsable scheme.
    #[error("invalid URL: {0:?}")]
    InvalidUrl(String),

    /// A required field was absent from a bridge line.
    #[error("bridge line missing required field: {0}")]
    MissingField(&'static str),

    /// A score outside the closed 0..=100 range.
    #[error("score out of range 0..=100: {0}")]
    InvalidScore(f64),

    /// A confidence value whose `k` agreements exceed its `n` observations.
    #[error("confidence k ({k}) exceeds n ({n})")]
    InvalidConfidence { k: u32, n: u32 },
}

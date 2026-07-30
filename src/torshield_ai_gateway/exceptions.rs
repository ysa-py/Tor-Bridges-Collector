//! Parity port of `torshield_ai_gateway/exceptions.py` — the AI-gateway
//! exception hierarchy.
//!
//! Python defines two exceptions, both subclassing `ValueError`:
//!   * `ProviderConfigurationError(message="", *, provider="")` — a permanent
//!     setup failure that must never be retried.
//!   * `BadRequestError(message="", *, provider="", slot=0)` — an HTTP 400
//!     request-level error (distinct from auth failures).
//!
//! Rust has no exception inheritance, so each is modelled as a struct that
//! carries the same fields and implements [`std::error::Error`]. The observable
//! Python contract preserved here is:
//!   * `str(exc)` equals the `message` string (empty string when omitted), which
//!     maps to the [`std::fmt::Display`] implementation;
//!   * the `provider` attribute (both) and `slot` attribute (`BadRequestError`)
//!     are readable and default to `""` / `0`.
//!
//! The `ValueError` base-class relationship (so callers catching `ValueError`
//! keep working) has no Rust analogue; it is documented as a behavioural
//! deviation in `MIGRATION_NOTES.md`.

use std::error::Error;
use std::fmt;

/// Parity port of Python `ProviderConfigurationError(ValueError)`.
///
/// Raised when provider setup is permanently invalid for this run. MUST NOT be
/// retried — the configuration will not change mid-run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProviderConfigurationError {
    /// The error message. `str(exc)` in Python; the `Display` output here.
    pub message: String,
    /// Optional originating provider name (Python keyword-only `provider=""`).
    pub provider: String,
}

impl ProviderConfigurationError {
    /// Mirrors `ProviderConfigurationError(message="")` — no provider.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            provider: String::new(),
        }
    }

    /// Mirrors `ProviderConfigurationError(message, provider=...)`.
    pub fn with_provider(message: impl Into<String>, provider: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            provider: provider.into(),
        }
    }
}

impl fmt::Display for ProviderConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `str(ValueError(message))` == message; empty when omitted.
        f.write_str(&self.message)
    }
}

impl Error for ProviderConfigurationError {}

/// Parity port of Python `BadRequestError(ValueError)`.
///
/// Raised when a provider returns HTTP 400 Bad Request — a request-level error
/// (wrong model, malformed payload, bad URL path), NOT an authentication
/// failure. Callers should try the next model in the fallback chain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BadRequestError {
    /// The error message. `str(exc)` in Python; the `Display` output here.
    pub message: String,
    /// Optional originating provider name (Python keyword-only `provider=""`).
    pub provider: String,
    /// Optional slot index (Python keyword-only `slot=0`).
    pub slot: i64,
}

impl BadRequestError {
    /// Mirrors `BadRequestError(message="")` — no provider, `slot=0`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            provider: String::new(),
            slot: 0,
        }
    }

    /// Mirrors `BadRequestError(message, provider=..., slot=...)`.
    pub fn with_context(
        message: impl Into<String>,
        provider: impl Into<String>,
        slot: i64,
    ) -> Self {
        Self {
            message: message.into(),
            provider: provider.into(),
            slot,
        }
    }
}

impl fmt::Display for BadRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for BadRequestError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_config_error_default_message_is_empty() {
        assert_eq!(ProviderConfigurationError::new("").to_string(), "");
        assert_eq!(ProviderConfigurationError::default().provider, "");
    }

    #[test]
    fn provider_config_error_carries_message_and_provider() {
        let e = ProviderConfigurationError::with_provider("all keys too short", "portkey");
        assert_eq!(e.to_string(), "all keys too short");
        assert_eq!(e.provider, "portkey");
    }

    #[test]
    fn bad_request_error_defaults() {
        let e = BadRequestError::new("");
        assert_eq!(e.to_string(), "");
        assert_eq!(e.provider, "");
        assert_eq!(e.slot, 0);
    }

    #[test]
    fn bad_request_error_carries_context() {
        let e = BadRequestError::with_context("bad model", "cloudflare", 3);
        assert_eq!(e.to_string(), "bad model");
        assert_eq!(e.provider, "cloudflare");
        assert_eq!(e.slot, 3);
    }
}

//! The validated one-time token and the single-use registry that invalidates
//! it after first use.

use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::FieldAllowlistError;

/// A validated one-time unlinkable token: exactly 32 lowercase hex digits,
/// the shape `tbc_agent::OneTimeToken::generate()` produces.
///
/// The inner string is private and construction only happens through
/// deserialization (which validates) or [`Token::from_upstream`] (which
/// validates), so an invalid token cannot exist in this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Token(String);

impl Token {
    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a raw string satisfies the one-time-token contract: exactly
    /// 32 lowercase hex digits. Shared by the boundary pre-check and by
    /// deserialization so both layers classify malformed tokens identically.
    pub fn is_valid(raw: &str) -> bool {
        raw.len() == 32
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    /// Validate a raw token string against the one-time-token contract.
    fn parse(raw: &str) -> Result<Self, FieldAllowlistError> {
        if Self::is_valid(raw) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(FieldAllowlistError::MalformedToken(raw.to_owned()))
        }
    }

    /// Convert a real upstream producer token (`tbc_agent::OneTimeToken`)
    /// into the allowlist's validated token. This is the real integration
    /// point with the producer crate, not a stub.
    pub fn from_upstream(upstream: &tbc_agent::OneTimeToken) -> Result<Self, FieldAllowlistError> {
        Self::parse(upstream.as_str())
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Single-use enforcement: a token may be consumed exactly once.
///
/// The first [`TokenRegistry::consume`] of a token succeeds; every later use
/// of the same token is rejected with
/// [`FieldAllowlistError::ReusedToken`] — a replayed report cannot pass the
/// boundary twice.
#[derive(Debug, Default)]
pub struct TokenRegistry {
    consumed: HashSet<String>,
}

impl TokenRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the token has already been consumed.
    pub fn is_consumed(&self, token: &Token) -> bool {
        self.consumed.contains(token.as_str())
    }

    /// How many distinct tokens have been consumed.
    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    /// Whether the registry holds no tokens.
    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }

    /// Consume a token. The first use records it; a second use of the same
    /// token is rejected.
    pub fn consume(&mut self, token: &Token) -> Result<(), FieldAllowlistError> {
        if !self.consumed.insert(token.as_str().to_owned()) {
            return Err(FieldAllowlistError::ReusedToken(token.as_str().to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn token(hex: &str) -> Token {
        serde_json::from_value(serde_json::json!(hex)).unwrap()
    }

    #[test]
    fn exactly_32_lowercase_hex_digits_is_valid() {
        let token = token("0123456789abcdef0123456789abcdef");
        assert_eq!(token.as_str().len(), 32);
    }

    #[test]
    fn short_tokens_are_rejected() {
        let error = serde_json::from_value::<Token>(serde_json::json!("short")).unwrap_err();
        assert!(error.to_string().contains("malformed"));
    }

    #[test]
    fn uppercase_hex_is_rejected() {
        let error =
            serde_json::from_value::<Token>(serde_json::json!("0123456789ABCDEF0123456789ABCDEF"))
                .unwrap_err();
        assert!(error.to_string().contains("malformed"));
    }

    #[test]
    fn non_hex_characters_are_rejected() {
        let error =
            serde_json::from_value::<Token>(serde_json::json!("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))
                .unwrap_err();
        assert!(error.to_string().contains("malformed"));
    }

    #[test]
    fn first_use_consumes_and_reuse_is_rejected() {
        let mut registry = TokenRegistry::new();
        let token = token("0123456789abcdef0123456789abcdef");

        assert!(!registry.is_consumed(&token));
        assert!(registry.consume(&token).is_ok());
        assert_eq!(registry.len(), 1);
        assert!(registry.is_consumed(&token));

        let error = registry.consume(&token).unwrap_err();
        assert_eq!(error.kind_name(), "reused_token");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn distinct_tokens_are_independent() {
        let mut registry = TokenRegistry::new();
        let first = token("0123456789abcdef0123456789abcdef");
        let second = token("fedcba9876543210fedcba9876543210");
        assert!(registry.consume(&first).is_ok());
        assert!(registry.consume(&second).is_ok());
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn from_upstream_accepts_real_producer_tokens() {
        let upstream = tbc_agent::OneTimeToken::generate();
        let token = Token::from_upstream(&upstream).unwrap();
        assert_eq!(token.as_str(), upstream.as_str());

        // A real producer token is consumable exactly once.
        let mut registry = TokenRegistry::new();
        assert!(registry.consume(&token).is_ok());
        assert!(matches!(
            registry.consume(&token),
            Err(FieldAllowlistError::ReusedToken(_))
        ));
    }
}

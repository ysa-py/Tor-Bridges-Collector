//! Provenance: which source reported which bridge, and when.
//!
//! The master spec requires full provenance tracking ("which sources saw which
//! bridge, when"). [`CollectedBridge`] pairs a parsed [`tbc_core::BridgeLine`]
//! with the [`SourceId`] that reported it and the instant it was collected,
//! so the store layer can accumulate a bridge's source set over its lifetime.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::SourceError;
use tbc_core::BridgeLine;

/// A stable, validated identifier for a bridge source (for example
/// `github:owner/repo`, `onionoo`, or `torproject:rdsys`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceId(String);

impl SourceId {
    /// Validate and construct a source identifier.
    ///
    /// Rejects empty and whitespace-only identifiers, and collapses internal
    /// whitespace runs so identifiers stay machine-friendly and dedupe-safe.
    pub fn new(value: impl Into<String>) -> Result<Self, SourceError> {
        let trimmed = value.into().trim().to_owned();
        if trimmed.is_empty() {
            return Err(SourceError::Config(
                "source identifier must not be empty".into(),
            ));
        }
        let collapsed = trimmed.split_whitespace().collect::<Vec<_>>().join("-");
        Ok(Self(collapsed))
    }

    /// The validated identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SourceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A bridge line together with the source that reported it and the time it was
/// collected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedBridge {
    /// The parsed and validated bridge line.
    pub bridge: BridgeLine,
    /// Which source reported this bridge.
    pub source: SourceId,
    /// When this bridge was collected (the `bridge.first_seen`/`last_seen`
    /// timestamps are also stamped with this instant during parsing).
    pub collected_at: DateTime<Utc>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn source_id_validates_and_collapses_whitespace() {
        assert!(SourceId::new("").is_err());
        assert!(SourceId::new("   ").is_err());
        let id = SourceId::new("  github: owner/repo  ").unwrap();
        assert_eq!(id.as_str(), "github:-owner/repo");
        assert_eq!(id.to_string(), "github:-owner/repo");
    }

    #[test]
    fn source_id_round_trips_json() {
        let id = SourceId::new("onionoo").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"onionoo\"");
        let back: SourceId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}

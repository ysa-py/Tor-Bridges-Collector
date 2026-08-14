//! Versioned JSON snapshot of the publication.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use tbc_core::{BridgeLine, BridgeScore};

use crate::error::PublishError;
use crate::model::Publication;

/// One bridge record inside a [`Snapshot`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    /// The bridge line.
    pub line: BridgeLine,
    /// The bridge's score, when one is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<BridgeScore>,
}

/// A deterministic, versioned JSON snapshot of every unique bridge.
///
/// Records are ordered by canonical bridge key; duplicate canonical keys are
/// collapsed to a single record (keeping the lexicographically smallest raw
/// line), so the snapshot is independent of input order and of which text
/// lists a bridge was assigned to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The schema version this document conforms to.
    pub schema_version: u32,
    /// When the snapshot was generated.
    pub generated_at: DateTime<Utc>,
    /// Number of unique bridges in this snapshot.
    pub bridge_count: usize,
    /// The bridges, ordered by canonical key.
    pub bridges: Vec<SnapshotRecord>,
}

impl Snapshot {
    /// Build a deterministic snapshot from a publication.
    pub fn from_publication(publication: &Publication) -> Result<Self, PublishError> {
        let mut unique: BTreeMap<String, SnapshotRecord> = BTreeMap::new();
        for entry in &publication.entries {
            let key = entry.bridge.canonical_key();
            let candidate = SnapshotRecord {
                line: entry.bridge.clone(),
                score: entry.score.clone(),
            };
            match unique.get(&key) {
                Some(existing) if existing.line.raw <= candidate.line.raw => {}
                _ => {
                    unique.insert(key, candidate);
                }
            }
        }
        let bridges: Vec<SnapshotRecord> = unique.into_values().collect();
        Ok(Self {
            schema_version: publication.schema_version,
            generated_at: publication.generated_at,
            bridge_count: bridges.len(),
            bridges,
        })
    }

    /// Serialize compactly.
    pub fn to_json(&self) -> Result<String, PublishError> {
        serde_json::to_string(self).map_err(PublishError::Json)
    }

    /// Serialize with stable pretty-printing.
    pub fn to_json_pretty(&self) -> Result<String, PublishError> {
        serde_json::to_string_pretty(self).map_err(PublishError::Json)
    }
}

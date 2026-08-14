//! Deterministic JSON snapshot export.
//!
//! A [`Snapshot`] is the git-committed history document: versioned, sorted,
//! and serialized with stable field order so that two runs over identical data
//! produce byte-identical output and diffs stay meaningful. Snapshots are
//! written to disk atomically (same-directory temp file + rename) so a reader
//! never observes a partially written file.

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use tbc_core::{BridgeLine, BridgeScore, Observation};

use crate::error::StoreError;

/// Version of the snapshot document shape. Bump on incompatible changes.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// A scored bridge as published inside a snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoredBridge {
    /// The bridge's canonical dedupe key.
    pub bridge_key: String,
    /// Its most recent score.
    pub score: BridgeScore,
}

/// A complete, deterministic snapshot of the store.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The snapshot document schema version.
    pub schema_version: u32,
    /// RFC 3339 instant at which the snapshot was generated (caller-supplied so
    /// reproducible runs can fix it).
    pub generated_at: String,
    /// Number of bridges in this snapshot.
    pub bridge_count: usize,
    /// Number of observations in this snapshot.
    pub observation_count: usize,
    /// Number of scores in this snapshot.
    pub score_count: usize,
    /// Bridges, sorted by canonical key (ties broken by serialized payload).
    pub bridges: Vec<BridgeLine>,
    /// Observations, sorted by bridge key, measurement time, reference, and
    /// serialized payload.
    pub observations: Vec<Observation>,
    /// Scores, sorted by bridge key.
    pub scores: Vec<ScoredBridge>,
}

impl Snapshot {
    /// Build a snapshot from the given rows, enforcing deterministic ordering
    /// and score-range validation.
    ///
    /// Ordering is total (a serialized tiebreak resolves any otherwise-equal
    /// keys), so the output is deterministic regardless of input order or sort
    /// stability.
    pub fn new(
        generated_at: DateTime<Utc>,
        bridges: Vec<BridgeLine>,
        observations: Vec<Observation>,
        scores: Vec<ScoredBridge>,
    ) -> Result<Self, StoreError> {
        let mut keyed_bridges: Vec<((String, String), BridgeLine)> = bridges
            .into_iter()
            .map(|bridge| {
                let tiebreak = serde_json::to_string(&bridge)?;
                Ok(((bridge.canonical_key(), tiebreak), bridge))
            })
            .collect::<Result<_, StoreError>>()?;
        keyed_bridges.sort_by(|left, right| left.0.cmp(&right.0));
        let bridges = keyed_bridges
            .into_iter()
            .map(|(_, bridge)| bridge)
            .collect::<Vec<_>>();

        let mut keyed_observations: Vec<((String, String), Observation)> = observations
            .into_iter()
            .map(|observation| {
                let tiebreak = serde_json::to_string(&observation)?;
                let prefix = format!(
                    "{}\u{1f}{}\u{1f}{}",
                    observation.bridge_key,
                    observation.measured_at.to_rfc3339(),
                    observation.measurement_ref.as_deref().unwrap_or("")
                );
                Ok(((prefix, tiebreak), observation))
            })
            .collect::<Result<_, StoreError>>()?;
        keyed_observations.sort_by(|left, right| left.0.cmp(&right.0));
        let observations = keyed_observations
            .into_iter()
            .map(|(_, observation)| observation)
            .collect::<Vec<_>>();

        let mut scores = scores;
        scores.sort_by(|left, right| left.bridge_key.cmp(&right.bridge_key));

        for scored in &scores {
            scored.score.validate().map_err(StoreError::Core)?;
        }

        Ok(Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            generated_at: generated_at.to_rfc3339(),
            bridge_count: bridges.len(),
            observation_count: observations.len(),
            score_count: scores.len(),
            bridges,
            observations,
            scores,
        })
    }

    /// Serialize to stable, pretty-printed JSON bytes ending in a newline.
    pub fn to_json(&self) -> Result<Vec<u8>, StoreError> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse a snapshot back from its JSON representation.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// Atomically write `bytes` to `path` via a same-directory temp file + rename.
///
/// The temp file is created with `create_new` (never clobbers an existing
/// file), written, flushed, and fsynced before the rename so the destination
/// only ever appears as a complete document.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };

    let file_name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name.to_owned(),
        None => {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "target path has no file name",
            )));
        }
    };

    let mut pending: Option<(PathBuf, std::fs::File)> = None;
    for attempt in 0..1000u32 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            attempt
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(handle) => {
                pending = Some((candidate, handle));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StoreError::Io(error)),
        }
    }

    let (temp_path, mut file) = pending.ok_or_else(|| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to allocate a unique temp file path",
        ))
    })?;

    if let Err(error) = file
        .write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
    {
        let _ = std::fs::remove_file(&temp_path);
        return Err(StoreError::Io(error));
    }

    drop(file);
    std::fs::rename(&temp_path, path)?;
    Ok(())
}

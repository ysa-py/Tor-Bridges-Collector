//! Machine-readable publication changelog (`data/publication_changelog.json`).
//!
//! ENGINEERING DIRECTIVE v37 §1 requires every collection run to commit its
//! results together with a timestamp and a machine-readable changelog. The
//! publisher (`sync_bridge_outputs`) appends one entry per successful
//! publication: an ISO-8601 UTC timestamp, the verified archive SHA-256, the
//! per-file entry counts, the evidence tier/result counts when available, and
//! the producer identity. Entries are capped at [`MAX_ENTRIES`] so the file
//! cannot grow without bound.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Maximum number of changelog entries retained (oldest entries are dropped
/// first, matching append-only ledger semantics with bounded growth).
pub const MAX_ENTRIES: usize = 1000;

/// Schema version of the changelog file.
pub const SCHEMA_VERSION: u8 = 1;

/// One publication event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangelogEntry {
    /// ISO-8601 UTC timestamp of the publication.
    pub run_timestamp: String,
    /// Producer binary that wrote the entry.
    pub producer: String,
    /// SHA-256 of the verified `tor_bridges.zip` archive.
    pub archive_sha256: String,
    /// Total bridge-history records published.
    pub history_records: usize,
    /// Total probe records published.
    pub probe_records: usize,
    /// Per-file entry counts (bridge/*.txt and JSON projections).
    pub file_counts: BTreeMap<String, usize>,
    /// Evidence tier -> count, when the stamping stage produced them.
    #[serde(default)]
    pub tiers: BTreeMap<String, usize>,
    /// Evidence result -> count, when the stamping stage produced them.
    #[serde(default)]
    pub results: BTreeMap<String, usize>,
    /// `ok` for a fully verified publication; anything else must explain.
    pub status: String,
}

/// Top-level changelog document: schema version plus an append-only list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangelogDocument {
    pub schema_version: u8,
    #[serde(default)]
    pub entries: Vec<ChangelogEntry>,
}

/// Failures reading or writing the changelog. No silent failure paths.
#[derive(Debug, thiserror::Error)]
pub enum ChangelogError {
    #[error("failed to read changelog {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("failed to parse changelog {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error("failed to serialize changelog {path}: {source}")]
    Serialize {
        path: String,
        source: serde_json::Error,
    },
    #[error("failed to write changelog {path}: {source}")]
    Write { path: String, source: io::Error },
    #[error("failed to create changelog directory {path}: {source}")]
    CreateDir { path: String, source: io::Error },
}

impl ChangelogError {
    fn path_display(path: &Path) -> String {
        path.display().to_string()
    }
}

/// Load the changelog document. A missing file is treated as an empty
/// document (first run), not an error.
pub fn load(path: &Path) -> Result<ChangelogDocument, ChangelogError> {
    if !path.is_file() {
        return Ok(ChangelogDocument {
            schema_version: SCHEMA_VERSION,
            entries: Vec::new(),
        });
    }
    let text = fs::read_to_string(path).map_err(|source| ChangelogError::Read {
        path: ChangelogError::path_display(path),
        source,
    })?;
    if text.trim().is_empty() {
        return Ok(ChangelogDocument {
            schema_version: SCHEMA_VERSION,
            entries: Vec::new(),
        });
    }
    serde_json::from_str(&text).map_err(|source| ChangelogError::Parse {
        path: ChangelogError::path_display(path),
        source,
    })
}

/// Append one entry and write the document back atomically. Returns the new
/// entry count. Oldest entries beyond [`MAX_ENTRIES`] are dropped.
pub fn append_entry(path: &Path, entry: ChangelogEntry) -> Result<usize, ChangelogError> {
    let mut doc = load(path)?;
    doc.schema_version = SCHEMA_VERSION;
    doc.entries.push(entry);
    if doc.entries.len() > MAX_ENTRIES {
        let excess = doc.entries.len() - MAX_ENTRIES;
        doc.entries.drain(..excess);
    }
    let count = doc.entries.len();

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            fs::create_dir_all(parent).map_err(|source| ChangelogError::CreateDir {
                path: parent.display().to_string(),
                source,
            })?;
        }
    }
    let json = serde_json::to_string_pretty(&doc).map_err(|source| ChangelogError::Serialize {
        path: ChangelogError::path_display(path),
        source,
    })?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, format!("{json}\n")).map_err(|source| ChangelogError::Write {
        path: ChangelogError::path_display(path),
        source,
    })?;
    fs::rename(&tmp, path).map_err(|source| ChangelogError::Write {
        path: ChangelogError::path_display(path),
        source,
    })?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn entry(ts: &str) -> ChangelogEntry {
        ChangelogEntry {
            run_timestamp: ts.to_string(),
            producer: "sync_bridge_outputs".to_string(),
            archive_sha256: "abc123".to_string(),
            history_records: 10,
            probe_records: 8,
            file_counts: BTreeMap::from([("obfs4.txt".to_string(), 5)]),
            tiers: BTreeMap::new(),
            results: BTreeMap::new(),
            status: "ok".to_string(),
        }
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "torshield_changelog_test_{}_{name}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir.join("publication_changelog.json")
    }

    #[test]
    fn load_missing_file_returns_empty_document() {
        let path = temp_path("missing");
        let doc = load(&path).unwrap();
        assert_eq!(doc.schema_version, SCHEMA_VERSION);
        assert!(doc.entries.is_empty());
    }

    #[test]
    fn append_writes_and_round_trips() {
        let path = temp_path("roundtrip");
        let count = append_entry(&path, entry("2026-08-12T10:20:55Z")).unwrap();
        assert_eq!(count, 1);
        let count = append_entry(&path, entry("2026-08-12T11:20:55Z")).unwrap();
        assert_eq!(count, 2);

        let doc = load(&path).unwrap();
        assert_eq!(doc.entries.len(), 2);
        assert_eq!(doc.entries[0].run_timestamp, "2026-08-12T10:20:55Z");
        assert_eq!(doc.entries[1].archive_sha256, "abc123");
    }

    #[test]
    fn append_is_append_only_and_ordered() {
        let path = temp_path("ordered");
        append_entry(&path, entry("t1")).unwrap();
        append_entry(&path, entry("t2")).unwrap();
        append_entry(&path, entry("t3")).unwrap();
        let doc = load(&path).unwrap();
        let stamps: Vec<&str> = doc
            .entries
            .iter()
            .map(|e| e.run_timestamp.as_str())
            .collect();
        assert_eq!(stamps, vec!["t1", "t2", "t3"]);
    }

    #[test]
    fn entries_are_capped_at_max() {
        let path = temp_path("cap");
        for i in 0..(MAX_ENTRIES + 25) {
            append_entry(&path, entry(&format!("t{i}"))).unwrap();
        }
        let doc = load(&path).unwrap();
        assert_eq!(doc.entries.len(), MAX_ENTRIES);
        // Oldest entries were dropped, newest retained.
        assert_eq!(doc.entries[0].run_timestamp, "t25");
        assert_eq!(
            doc.entries[MAX_ENTRIES - 1].run_timestamp,
            format!("t{}", MAX_ENTRIES + 24)
        );
    }

    #[test]
    fn parse_error_is_reported_not_swallowed() {
        let path = temp_path("corrupt");
        fs::write(&path, "{ not json").unwrap();
        let err = load(&path).unwrap_err();
        assert!(matches!(err, ChangelogError::Parse { .. }));
    }
}

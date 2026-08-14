//! The publication orchestrator: render, snapshot, archive, and manifest.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};

use crate::error::PublishError;
use crate::manifest::Manifest;
use crate::model::{is_safe_name, Publication};
use crate::snapshot::Snapshot;
use crate::{archive, atomic, text};

/// File name of the JSON snapshot inside every publication bundle.
pub const SNAPSHOT_FILE: &str = "snapshot.json";

/// Publication options that change packaging (kept out of the data model).
#[derive(Debug, Clone, PartialEq)]
pub struct PublishConfig {
    /// Whether rendered text lists end with a trailing newline.
    pub trailing_newline: bool,
    /// ZIP entry timestamp. `None` selects the fixed reproducible epoch
    /// (`1980-01-01 00:00:00`), so archives do not depend on wall-clock time.
    pub zip_timestamp: Option<DateTime<Utc>>,
    /// File name of the archive inside the output directory.
    pub archive_name: String,
    /// File name of the manifest inside the output directory.
    pub manifest_name: String,
}

impl Default for PublishConfig {
    fn default() -> Self {
        Self {
            trailing_newline: true,
            zip_timestamp: None,
            archive_name: "tor_bridges.zip".to_owned(),
            manifest_name: "manifest.json".to_owned(),
        }
    }
}

impl PublishConfig {
    /// Validate the packaging file names.
    pub fn validate(&self) -> Result<(), PublishError> {
        if !is_safe_name(&self.archive_name) {
            return Err(PublishError::InvalidEntryName {
                name: self.archive_name.clone(),
                reason: "archive name is not a safe file name",
            });
        }
        if !is_safe_name(&self.manifest_name) {
            return Err(PublishError::InvalidEntryName {
                name: self.manifest_name.clone(),
                reason: "manifest name is not a safe file name",
            });
        }
        if self.archive_name.eq_ignore_ascii_case(SNAPSHOT_FILE)
            || self.manifest_name.eq_ignore_ascii_case(SNAPSHOT_FILE)
            || self.archive_name.eq_ignore_ascii_case(&self.manifest_name)
        {
            return Err(PublishError::InvalidEntryName {
                name: self.archive_name.clone(),
                reason: "archive, manifest, and snapshot names must be distinct",
            });
        }
        Ok(())
    }
}

/// The deterministic artifacts produced for one publication.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationBundle {
    /// Archive contents: rendered text lists plus the JSON snapshot, keyed by
    /// file name.
    pub files: BTreeMap<String, Vec<u8>>,
    /// The complete ZIP archive bytes.
    pub archive: Vec<u8>,
    /// Lower-case hex SHA-256 of the archive bytes.
    pub archive_sha256: String,
    /// The SHA-256 manifest over the archive contents.
    pub manifest: Manifest,
}

/// What a [`Publisher::write`] call wrote to disk.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationReport {
    /// File names written, sorted.
    pub written: Vec<String>,
}

/// The deterministic publisher.
pub struct Publisher {
    config: PublishConfig,
}

impl Publisher {
    /// Construct a publisher from a validated configuration.
    pub fn new(config: PublishConfig) -> Result<Self, PublishError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// The configuration this publisher was built with.
    pub fn config(&self) -> &PublishConfig {
        &self.config
    }

    /// Render, snapshot, archive, and manifest a publication in memory.
    pub fn build(&self, publication: &Publication) -> Result<PublicationBundle, PublishError> {
        if publication.entries.is_empty() {
            return Err(PublishError::EmptyPublication);
        }
        self.validate_entries(publication)?;

        // Group bridge lines by their target file name, then render each group
        // deterministically (sorted, deduplicated, trailing newline).
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut by_name: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for entry in &publication.entries {
            by_name
                .entry(entry.name.as_str())
                .or_default()
                .push(entry.bridge.raw.as_str());
        }
        for (name, lines) in by_name {
            let rendered = text::render_text_list(lines, self.config.trailing_newline);
            files.insert(name.to_owned(), rendered.into_bytes());
        }

        let snapshot = Snapshot::from_publication(publication)?;
        files.insert(
            SNAPSHOT_FILE.to_owned(),
            snapshot.to_json_pretty()?.into_bytes(),
        );

        let archive = archive::deterministic_zip(&files, self.config.zip_timestamp)?;
        let archive_sha256 = crate::manifest::sha256_hex(&archive);
        let manifest = Manifest::compute(
            &files,
            &archive,
            publication.schema_version,
            publication.generated_at,
        );

        Ok(PublicationBundle {
            files,
            archive,
            archive_sha256,
            manifest,
        })
    }

    /// Render, snapshot, archive, and manifest a publication, then write every
    /// artifact atomically under `dir`.
    pub fn write(
        &self,
        publication: &Publication,
        dir: &Path,
    ) -> Result<PublicationReport, PublishError> {
        let bundle = self.build(publication)?;

        std::fs::create_dir_all(dir)
            .map_err(|source| PublishError::io("create_output_dir", source))?;

        let mut written: Vec<String> = Vec::new();
        for (name, bytes) in &bundle.files {
            atomic::write_atomic(&dir.join(name), bytes)?;
            written.push(name.clone());
        }
        atomic::write_atomic(&dir.join(&self.config.archive_name), &bundle.archive)?;
        written.push(self.config.archive_name.clone());
        atomic::write_atomic(
            &dir.join(&self.config.manifest_name),
            bundle.manifest.to_json_pretty()?.as_bytes(),
        )?;
        written.push(self.config.manifest_name.clone());

        written.sort();
        Ok(PublicationReport { written })
    }

    /// Reject unsafe or reserved entry names before rendering.
    fn validate_entries(&self, publication: &Publication) -> Result<(), PublishError> {
        for entry in &publication.entries {
            if !is_safe_name(&entry.name) {
                return Err(PublishError::InvalidEntryName {
                    name: entry.name.clone(),
                    reason: "entry name is not a safe file name",
                });
            }
            if entry.name.eq_ignore_ascii_case(SNAPSHOT_FILE)
                || entry.name.eq_ignore_ascii_case(&self.config.archive_name)
                || entry.name.eq_ignore_ascii_case(&self.config.manifest_name)
            {
                return Err(PublishError::InvalidEntryName {
                    name: entry.name.clone(),
                    reason: "entry name collides with a reserved output file",
                });
            }
        }
        Ok(())
    }
}

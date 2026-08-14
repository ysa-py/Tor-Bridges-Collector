//! SHA-256 inventory manifest.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PublishError;

/// One file entry in a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Path inside the archive.
    pub path: String,
    /// Lower-case hex SHA-256 of the file contents.
    pub sha256: String,
    /// Size of the file contents in bytes.
    pub size: u64,
}

/// A deterministic SHA-256 inventory of a publication archive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version of this manifest document.
    pub schema_version: u32,
    /// When the manifest was generated.
    pub generated_at: DateTime<Utc>,
    /// SHA-256 of the complete archive this manifest describes.
    pub archive_sha256: String,
    /// Number of file entries.
    pub entry_count: usize,
    /// File entries, ordered by path.
    pub files: Vec<ManifestEntry>,
}

impl Manifest {
    /// Compute a manifest over `files` (the archive's contents) and `archive`
    /// (the complete archive bytes).
    pub fn compute(
        files: &BTreeMap<String, Vec<u8>>,
        archive: &[u8],
        schema_version: u32,
        generated_at: DateTime<Utc>,
    ) -> Self {
        let mut entries: Vec<ManifestEntry> = files
            .iter()
            .map(|(path, bytes)| ManifestEntry {
                path: path.clone(),
                sha256: sha256_hex(bytes),
                size: bytes.len() as u64,
            })
            .collect();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Self {
            schema_version,
            generated_at,
            archive_sha256: sha256_hex(archive),
            entry_count: entries.len(),
            files: entries,
        }
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

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex encoding of a SHA-256 digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn manifest_json_round_trips() {
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_owned(), b"hello".to_vec());
        let archive = b"fake-archive-bytes".to_vec();
        let generated_at = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let manifest = Manifest::compute(&files, &archive, 1, generated_at);
        let json = manifest.to_json().unwrap();
        let decoded: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, decoded);
        assert_eq!(manifest.entry_count, 1);
        assert_eq!(manifest.files[0].path, "a.txt");
    }
}

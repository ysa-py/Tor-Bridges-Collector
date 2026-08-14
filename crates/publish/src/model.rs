//! Publication input model.

use chrono::{DateTime, Utc};

use tbc_core::{BridgeLine, BridgeScore};

/// One bridge destined for a single text-list file in the publication.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationEntry {
    /// The relative file name this bridge line belongs to (for example
    /// `obfs4.txt`). See [`is_safe_name`] for the accepted charset.
    pub name: String,
    /// The parsed bridge line.
    pub bridge: BridgeLine,
    /// The bridge's score, when one is available.
    pub score: Option<BridgeScore>,
}

/// A complete publication request: everything needed to render and package a
/// deterministic bridge distribution.
#[derive(Debug, Clone, PartialEq)]
pub struct Publication {
    /// The JSON schema version stamped into the snapshot and manifest.
    pub schema_version: u32,
    /// The timestamp stamped into the snapshot and manifest.
    pub generated_at: DateTime<Utc>,
    /// The bridge entries to publish.
    pub entries: Vec<PublicationEntry>,
}

/// Whether `name` is a safe single-segment file name for a publication.
///
/// A safe name is non-empty, at most 255 bytes, contains only ASCII letters,
/// digits, `.`, `_`, or `-`, and starts with a letter or digit (so it can
/// never be a hidden file, an absolute path, or a path traversal).
pub fn is_safe_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let bytes = name.as_bytes();
    let mut first = true;
    for &byte in bytes {
        if !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-') {
            return false;
        }
        if first {
            if !byte.is_ascii_alphanumeric() {
                return false;
            }
            first = false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn safe_names_are_accepted() {
        for name in [
            "obfs4.txt",
            "obfs4_72h_ipv6.txt",
            "meek-azure.txt",
            "2026-08.txt",
        ] {
            assert!(is_safe_name(name), "{name} should be safe");
        }
    }

    #[test]
    fn traversal_and_hidden_names_are_rejected() {
        for name in [
            "",
            ".",
            "..",
            "../obfs4.txt",
            "a/b.txt",
            "a\\b.txt",
            ".obfs4.txt",
            "_x",
            "-x",
            "a b.txt",
        ] {
            assert!(!is_safe_name(name), "{name:?} should be rejected");
        }
    }

    #[test]
    fn overlong_names_are_rejected() {
        assert!(!is_safe_name(&"a".repeat(256)));
        assert!(is_safe_name(&"a".repeat(255)));
    }
}

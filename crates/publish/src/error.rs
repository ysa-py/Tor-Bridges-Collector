//! Typed error taxonomy for the publication layer.
//!
//! Every fallible operation in this crate returns a [`PublishError`] rather
//! than panicking or silently swallowing a failure. [`PublishError::kind_name`]
//! exposes a stable, value-free name for metrics and structured logs.

use thiserror::Error;

/// Errors produced while validating or writing a publication.
#[derive(Debug, Error)]
pub enum PublishError {
    /// A publication entry or packaging name is not a safe file name.
    #[error("invalid publication name {name:?}: {reason}")]
    InvalidEntryName {
        /// The offending name.
        name: String,
        /// Why the name was rejected (stable, no value data).
        reason: &'static str,
    },

    /// A publication with no entries was refused rather than silently
    /// publishing an empty distribution.
    #[error("refusing to publish an empty publication")]
    EmptyPublication,

    /// JSON serialization failed.
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    /// ZIP construction failed.
    #[error("ZIP construction failed: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// A ZIP entry timestamp could not be represented in the DOS format.
    #[error("ZIP timestamp is not representable: {reason}")]
    InvalidZipTimestamp {
        /// Why the timestamp was rejected (stable, no value data).
        reason: &'static str,
    },

    /// An underlying I/O operation failed.
    #[error("I/O error while {context}: {source}")]
    Io {
        /// What the I/O operation was doing (stable label, no paths).
        context: &'static str,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl PublishError {
    /// A stable, metric-safe name for the failure class (no value data).
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::InvalidEntryName { .. } => "invalid_entry_name",
            Self::EmptyPublication => "empty_publication",
            Self::Json(_) => "json_serialization",
            Self::Zip(_) => "zip_construction",
            Self::InvalidZipTimestamp { .. } => "invalid_zip_timestamp",
            Self::Io { .. } => "io",
        }
    }

    /// Construct an I/O error with a stable context label.
    pub(crate) fn io(context: &'static str, source: std::io::Error) -> Self {
        Self::Io { context, source }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_are_stable_and_value_free() {
        assert_eq!(
            PublishError::InvalidEntryName {
                name: "../evil.txt".to_owned(),
                reason: "entry name is not a safe file name",
            }
            .kind_name(),
            "invalid_entry_name"
        );
        assert_eq!(
            PublishError::EmptyPublication.kind_name(),
            "empty_publication"
        );
        assert_eq!(
            PublishError::io(
                "write_temp_file",
                std::io::Error::from(std::io::ErrorKind::Other)
            )
            .kind_name(),
            "io"
        );
    }

    #[test]
    fn io_error_keeps_source() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let error = PublishError::io("rename_temp_file", source);
        assert!(error.to_string().contains("rename_temp_file"));
        assert!(error.to_string().contains("gone"));
    }
}

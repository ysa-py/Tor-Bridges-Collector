//! Typed error taxonomy for the persistence layer.
//!
//! Every fallible store operation returns a [`StoreError`], so callers can
//! classify failures (database, migration, serialization, i/o, or model
//! validation) instead of matching on string content.

use thiserror::Error;

/// Errors produced by the SQLite store and snapshot export.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A query, connection, or transaction failure reported by SQLx.
    ///
    /// Excluded from the ARMv7-musl type-check graph: `sqlx::Error` only
    /// exists there if the `sqlite` feature is compiled, and that feature
    /// pulls `libsqlite3-sys`'s bundled C build (no arm-musl cross compiler
    /// on the hosted runner). See `Cargo.toml` for the target-gated `sqlx`.
    #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// A schema migration failure (e.g. a versioned migration did not apply).
    #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
    #[error("schema migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// A JSON serialization/deserialization failure.
    #[error("json serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A filesystem failure while writing a snapshot.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A domain-model validation failure reported by `tbc-core`.
    #[error("core model error: {0}")]
    Core(#[from] tbc_core::ModelError),

    /// The requested record does not exist.
    #[error("record not found: {0}")]
    NotFound(String),

    /// A stored timestamp string could not be parsed back into a `DateTime`.
    #[error("invalid stored timestamp: {0}")]
    InvalidTimestamp(String),
}

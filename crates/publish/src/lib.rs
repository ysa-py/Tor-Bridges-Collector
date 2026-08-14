//! `tbc-publish` — deterministic multi-format publication (Phase 7 of the
//! master spec).
//!
//! This crate owns the publication responsibility: it turns a set of parsed
//! bridges (with optional scores) into the exact artifacts the legacy
//! `bridge/` contract publishes —
//!
//! * per-list text files (one bridge line per line, sorted and deduplicated),
//! * a versioned JSON snapshot of every unique bridge,
//! * a reproducible ZIP archive of the above, and
//! * a SHA-256 manifest over the archive.
//!
//! Every render is independent of input order: lists are sorted, the snapshot
//! is ordered by canonical bridge key, archive entries are written in
//! ascending name order with a fixed timestamp, and the manifest is ordered by
//! path. Given identical inputs the output bytes are byte-identical across
//! runs and machines.
//!
//! Production code in this crate contains no `unwrap()`, `expect()`, `panic!`,
//! `todo!()`, or `unimplemented!()`; the deny attributes below turn any of
//! those into a hard `cargo clippy` error. Test modules re-allow them.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

pub mod archive;
pub mod atomic;
pub mod error;
pub mod manifest;
pub mod model;
pub mod publisher;
pub mod snapshot;
pub mod text;

pub use error::PublishError;
pub use manifest::{sha256_hex, Manifest, ManifestEntry};
pub use model::{is_safe_name, Publication, PublicationEntry};
pub use publisher::{
    PublicationBundle, PublicationReport, PublishConfig, Publisher, SNAPSHOT_FILE,
};
pub use snapshot::{Snapshot, SnapshotRecord};
pub use text::render_text_list;

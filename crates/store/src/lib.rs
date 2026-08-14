//! `tbc-store` — SQLite persistence and deterministic JSON snapshot export.
//!
//! This crate implements the `crates/store` responsibility from the master
//! spec: versioned SQLite migrations, provenance tracking (which sources saw
//! which bridge, retained for the lifetime of the row), observation and score
//! storage, and a deterministic JSON snapshot export written atomically for
//! git-committed history.
//!
//! Queries are runtime-checked against the live schema and every query path is
//! exercised by the integration test suite (`tests/store_integration.rs`),
//! which applies all migrations and verifies round-trips, deduplication,
//! ordering, and atomic writes against a real SQLite database. Column reads
//! and writes are typed via `#[derive(sqlx::FromRow)]`, so a schema/type drift
//! surfaces as a test failure rather than a silent null or truncation.
//!
//! Production code in this crate contains no `unwrap()`, `expect()`, `panic!`,
//! `todo!()`, or `unimplemented!()`; the deny attributes below turn any of
//! those into a hard `cargo clippy` error so the invariant is enforced, not
//! aspirational.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

pub mod error;
pub mod snapshot;
pub mod store;

pub use error::StoreError;
pub use snapshot::{write_atomic, ScoredBridge, Snapshot, SNAPSHOT_SCHEMA_VERSION};
pub use store::{BridgeRecord, Store};

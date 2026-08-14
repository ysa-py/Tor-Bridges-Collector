//! `tbc-core` — shared domain model for the Tor Bridges Collector.
//!
//! This crate is the foundation of the enterprise-upgrade workspace. It owns
//! the typed bridge/observation/scoring model (Phase 2 of the master spec), a
//! `thiserror`-based error taxonomy, an injectable clock for zero-flaky tests,
//! and a small Prometheus-style metrics registry.
//!
//! Production code in this crate contains no `unwrap()`, `expect()`, or
//! `panic!`; the deny attributes below turn any of those into a hard
//! `cargo clippy` error so the invariant is enforced, not aspirational.
//! Test modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod clock;
pub mod error;
pub mod metrics;
pub mod types;
pub mod validate;

pub use clock::{Clock, SystemClock, TestClock};
pub use error::ModelError;
pub use metrics::Metrics;
pub use types::{
    BridgeLine, BridgeParams, BridgeScore, Confidence, EvasionProfile, Observation, ProbeKind,
    Tier, TransportKind, Vantage, VantageKind, Verdict,
};

/// Version of the JSON document schema produced from this model.
///
/// Bump this when the serde representation of any published type changes in a
/// way that is not backward-compatible. Published artifacts carry it so
/// consumers and the CI schema validator can reject stale or unknown shapes.
pub const SCHEMA_VERSION: u32 = 1;

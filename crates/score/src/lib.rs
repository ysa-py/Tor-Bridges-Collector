//! `tbc-score` — deterministic bridge scoring (Phase 6 of the master spec).
//!
//! This crate implements the scoring responsibility: a weighted model in
//! which real-handshake success outweighs TCP reachability, which outweighs
//! path evidence; exponential freshness decay; a k-of-n confidence multiplier
//! from observation count and vantage diversity; a burn-rate penalty; per-ASN
//! scores; and S/A/B/C/D tiering with thresholds read from configuration and a
//! minimum-confirmations gate above tier C.
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

pub mod config;
pub mod engine;
pub mod error;
pub mod evidence;

pub use config::{ClassWeights, ScoreConfig, TierThresholds};
pub use engine::{AsnBreakdown, ScoreBreakdown, ScoreEngine, ScoredBridge};
pub use error::ScoreError;
pub use evidence::{
    class_weight, is_blocking_verdict, observation_value, verdict_value, WORKING_THRESHOLD,
};

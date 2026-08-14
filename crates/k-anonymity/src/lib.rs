//! `tbc-k-anonymity` — k-anonymity threshold enforcement (Phase-2 item 2).
//!
//! Individual measurement reports are **withheld** until at least `k` of them
//! are held; only then is the whole batch released. The threshold `k` is
//! configurable ([`KAnonymityConfig`], default `k = 5` — matching the
//! `tbc-agent` `AgentConfig::default().k_anonymity_threshold`), so no
//! individual report can ever be isolated from a group of fewer than `k`.
//!
//! ```text
//! submit(r1) → Held { held: 1 }        (withheld)
//! submit(r2) → Held { held: 2 }        (withheld)
//! …            Held { held: k-1 }      (still withheld — nothing emitted)
//! submit(rk) → Emitted(Batch{size:k})  (released as a group of exactly k)
//! ```
//!
//! ## Enforcement, not a comment
//!
//! The batcher's only output channel is [`Submission::Emitted`], which carries
//! a [`Batch`] of at least `k` reports; below `k` the caller receives
//! [`Submission::Held`] with only a count. There is no public accessor that
//! returns an individual withheld report, so a below-k report cannot leak
//! into output by construction.
//!
//! ## Input contract
//!
//! This crate aggregates its own [`Report`] type (`id` + `recorded_at`). The
//! upstream producer (for example `tbc-agent::AnonymizedReport`) maps its
//! fields into `Report` (token → `id`, measured timestamp → `recorded_at`);
//! that producer-side `From` adapter is a tracked follow-up, not a stub here.
//!
//! Production code contains no `unwrap()`, `expect()`, or `panic!`; the deny
//! attributes below turn any of those into a hard `cargo clippy` error. Test
//! modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod batcher;
pub mod config;
pub mod error;
pub mod report;

pub use batcher::{Batch, KAnonymityBatcher, Submission};
pub use config::KAnonymityConfig;
pub use error::KAnonymityError;
pub use report::Report;

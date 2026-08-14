//! `tbc-consent` — explicit, unskippable volunteer consent (Phase-2 item 1).
//!
//! This crate is the standalone consent gate: a thread-safe [`ConsentGate`]
//! that starts **un-granted** and issues a [`ConsentProof`] only after consent
//! is recorded. Enforcement is structural, not a comment: [`ConsentProof`] has
//! no public constructor, so a protected operation cannot obtain one except by
//! calling [`ConsentGate::require`] on a granted gate. Before that call, the
//! gate returns [`ConsentError::NotGranted`], which downstream code must treat
//! as a refusal.
//!
//! ```text
//! gate.require()                 → Err(NotGranted)   (no consent yet)
//! gate.grant("terminal_prompt")  → records consent    (first grant authoritative)
//! gate.require()                 → Ok(ConsentProof)   (proof carries method + time)
//! ```
//!
//! The `consent-check` binary demonstrates the gate end-to-end: `--no` refuses
//! (exit 1) without emitting a proof, `--yes` records consent and emits the
//! proof as JSON.
//!
//! Production code contains no `unwrap()`, `expect()`, or `panic!`; the deny
//! attributes below turn any of those into a hard `cargo clippy` error. Test
//! modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod error;
pub mod gate;
pub mod parse;

pub use error::ConsentError;
pub use gate::{ConsentGate, ConsentProof, ConsentRecord};
pub use parse::parse_consent_input;

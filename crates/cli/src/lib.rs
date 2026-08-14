//! `tbc-cli` — the `tbc` subcommand surface (crate 10 of the master spec).
//!
//! This crate is the operator-facing entry point that wires the workspace
//! pipeline crates together behind one command-line interface:
//!
//! | Subcommand | Wires to | Responsibility |
//! |---|---|---|
//! | `version` / `schema` / `help` | `tbc-core` | version + schema + usage |
//! | `score` | `tbc-score` | deterministic scoring (executed offline) |
//! | `publish` | `tbc-publish` | deterministic publication (executed offline) |
//! | `collect` | `tbc-sources` | validate a sources configuration |
//! | `probe` | `tbc-prober` | validate a bridge set before probing |
//! | `vantage` | `tbc-vantage` | validate a bridge set for in-country measurement |
//! | `agent` | `tbc-agent` | validate a volunteer-agent bind configuration |
//!
//! ## Honest scope boundary
//!
//! `score` and `publish` are pure (computation plus file I/O), so this crate
//! executes them end-to-end and the test suite asserts on the real artifacts
//! they write. `collect`, `probe`, `vantage`, and `agent` are bound to live
//! network/services; this crate fully validates their inputs and configuration
//! (real file reads, typed errors) and reports readiness, while the network
//! execution itself is owned by the corresponding crate — the same "second
//! gate" boundary those crates document for their own live paths. No mocked
//! measurement is ever presented as real.
//!
//! Production code contains no `unwrap()`, `expect()`, or `panic!`; the deny
//! attributes below turn any of those into a hard `cargo clippy` error. Test
//! modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod command;
pub mod error;
pub mod parse;
pub mod run;

pub use command::{help_text, usage, Command, VERSION};
pub use error::CliError;
pub use parse::parse_command;
pub use run::run;

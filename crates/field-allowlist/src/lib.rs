//! `tbc-field-allowlist` — schema-enforced reported-field allowlist (Phase-2
//! item 3).
//!
//! The anonymized Phase-5 report is a *closed* contract. This crate defines
//! the only shape a report may take at the ingestion boundary — exactly five
//! fields, each with a coarse, non-fingerprinting domain:
//!
//! | field        | allowed domain (wire values)                                  |
//! |--------------|--------------------------------------------------------------|
//! | `outcome`    | `success` \| `failure` (collapsed verdict)                   |
//! | `rtt_bucket` | `rtt_0_50` \| `rtt_50_150` \| `rtt_150_400` \| `rtt_400_1000` \| `rtt_1000_plus` \| `rtt_unknown` |
//! | `asn_class`  | `small` \| `medium` \| `large` \| `unknown`                  |
//! | `token`      | exactly 32 lowercase hex digits (one-time, unlinkable)       |
//! | `source`     | `phase5_volunteer` \| `phase4_ci_runner` (Phase-5 source tag)|
//!
//! ## Enforced, not commented
//!
//! The allowlist is a compiled contract at both ends of the boundary:
//!
//! * **Deserialize** — [`AllowlistedReport`] carries
//!   `#[serde(deny_unknown_fields)]`, so any field outside the allowlist
//!   (an exact IP, an exact ASN, a raw timestamp, an evidence string, …)
//!   fails deserialization instead of being silently dropped; the field-value
//!   domains are typed enums, so an off-domain value (`"source": "phase3_x"`,
//!   `"rtt_bucket": "rtt_37"`) is rejected too.
//! * **Serialize** — the struct has no place for extra fields, so an
//!   allowlisted report can never serialize a non-allowlisted field.
//!
//! The boundary lives in [`parse_report`] and reports a typed
//! [`FieldAllowlistError`] naming the exact offending field or value.
//!
//! ## Upstream integration (real, not stubbed)
//!
//! The field-value domains reuse the real `tbc-agent` producer types
//! (`Outcome`, `RttBucket`, `AsnClass`, `ReportSource` — the Phase-4/Phase-5
//! source-tag enum defined in `crates/agent/src/report.rs`). The one-time
//! token is validated here in the exact shape `tbc_agent::OneTimeToken`
//! generates, and [`Token::from_upstream`] converts a real producer token.
//! Single-use enforcement lives in [`TokenRegistry`]: a token can be consumed
//! exactly once; any reuse is rejected with [`FieldAllowlistError::ReusedToken`].
//!
//! Production code contains no `unwrap()`, `expect()`, or `panic!`; the deny
//! attributes below turn any of those into a hard `cargo clippy` error. Test
//! modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod error;
pub mod model;
pub mod parse;
pub mod token;

pub use error::{kind_name, FieldAllowlistError};
pub use model::AllowlistedReport;
pub use parse::{parse_report, parse_report_value};
pub use token::{Token, TokenRegistry};

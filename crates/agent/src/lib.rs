//! `tbc-agent` — the volunteer in-country agent.
//!
//! This crate is the `crates/agent` responsibility from the master spec: the
//! software a volunteer runs *inside* the target country. It serves the
//! `AgentVantage` wire protocol (the same one the `tbc-vantage`
//! [`AgentVantage`] adapter posts to) and performs the actual in-country
//! measurement, so the collector never touches the volunteer's vantage point
//! directly.
//!
//! ```text
//! POST /probe  {"target":"1.2.3.4", "port":443, "probe_kind":"tcp_connect"}
//! 200          {"verdict":"reachable","rtt_ms":64,"error_class":null,
//!                "evidence":null,"measurement_ref":"agent-1","http_status":null}
//! ```
//!
//! ## What is implemented (and what is not)
//!
//! * `tcp_connect` is fully implemented: timed DNS resolution plus TCP
//!   connect, with refused/reset/timeout/DNS classification reused from
//!   `tbc-prober`. Every probe-layer failure is mapped to a verdict token and
//!   returned as a 200 *measurement outcome*, never as a silent failure.
//! * The other five [`tbc_core::ProbeKind`]s return an explicit 422
//!   `unsupported_probe_kind` response (a documented skip-and-record policy,
//!   not a stub). Handshake-level in-country probes (obfs4/WebTunnel) and
//!   traceroute are tracked follow-ups.
//! * Every external measurement is budget-guarded in code: a per-client token
//!   bucket bounds request rate, a semaphore bounds concurrent probes, and
//!   request bodies/targets are size-bounded.
//!
//! Production code contains no `unwrap()`, `expect()`, or `panic!`; the deny
//! attributes below turn any of those into a hard `cargo clippy` error. Test
//! modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod config;
pub mod consent;
pub mod error;
pub mod k_anonymity;
pub mod probe;
pub mod protocol;
pub mod rate_limit;
pub mod report;
pub mod server;

pub use config::AgentConfig;
pub use consent::{parse_consent_input, ConsentGate, ConsentRecord, ConsentToken};
pub use error::AgentError;
pub use k_anonymity::{KAnonymityBatcher, Submission};
pub use probe::{response_for_probe_error, ProbeEngine};
pub use protocol::{verdict_token, ProbeRequest, ProbeResponse};
pub use rate_limit::{RateLimiter, TokenBucket};
pub use report::{AnonymizedReport, AsnClass, OneTimeToken, Outcome, ReportSource, RttBucket};
pub use server::{
    build_response, parse_request_head, read_request, AgentServer, HttpRequest, HttpResponse,
    RequestHead,
};

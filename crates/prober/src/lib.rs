//! `tbc-prober` — handshake-level bridge prober.
//!
//! This crate is the "out-of-country prober" from the master spec: it drives
//! the [`tbc_transports`] wire-format codecs over a real TCP socket and turns
//! the result into a typed [`ProbeOutcome`] (and, via [`to_observation`], a
//! [`tbc_core::Observation`]) for the scoring and publication crates.
//!
//! Each transport probe is a *handshake*, not a TCP connect:
//!
//! | Transport | What is actually performed |
//! |---|---|
//! | obfs4 | identity decode, a well-formed `clientRequest` with correct `M_C`/`MAC_C` marks, and verification of the server `M_S`/`MAC_S` (see the honest boundary below) |
//! | WebTunnel | client TLS session to the `url=` front domain, RFC 6455 HTTP upgrade request, `101` response parse, and `Sec-WebSocket-Accept` verification |
//! | vanilla ORPort | client TLS session to the ORPort (tor-spec §2), then the `VERSIONS` + `NETINFO` link-cell exchange inside TLS (tor-spec §3/§4) |
//! | meek | domain-fronted `POST` envelope and response status parse |
//! | Snowflake | broker rendezvous poll (`/client`) and response parse |
//!
//! TLS-based probes establish the TLS session through [`tls::start_tls`] with
//! any-server-certificate acceptance — a deliberate liveness/protocol-shape
//! trust boundary documented in [`tls`].
//!
//! ## Honest scope boundary (obfs4)
//!
//! The obfs4 *cryptographic* key establishment — Elligator 2 representative
//! mapping, X25519 scalar multiplication, and the ntor `KEY_SEED`/`AUTH`
//! derivation — is **not** implemented in this crate. The obfs4 probe
//! verifies the server's `M_S`/`MAC_S` marks (which proves the endpoint knows
//! the published `B | NODEID` identity and completes the framing handshake),
//! but it does **not** verify the ntor `AUTH` tag, so it cannot detect an
//! active attacker that also knows the published identity. Full server
//! authentication requires the Elligator 2 + X25519 + ntor primitives, which
//! are a tracked follow-up (see `docs/PROGRESS.md`).
//!
//! Production code contains no `unwrap()`, `expect()`, or `panic!`; the deny
//! attributes below turn any of those into a hard `cargo clippy` error. Test
//! modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod config;
pub mod engine;
pub mod error;
pub mod http;
pub mod probe;
pub mod result;
pub mod retry;
pub mod socket;
pub mod tls;

pub use config::ProbeConfig;
pub use engine::Prober;
pub use error::ProbeError;
pub use result::{
    probe_kind_for, to_observation, BridgeProbeResult, ProbeDetail, ProbeOutcome, ProbeReport,
};

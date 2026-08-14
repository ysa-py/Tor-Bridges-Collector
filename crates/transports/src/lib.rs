//! `tbc-transports` — wire-format codecs for Tor pluggable transports.
//!
//! This crate implements the **encode/decode** layers of the five bridge
//! transports the collector tracks, without performing any network I/O:
//!
//! | Module | Transport | Wire format implemented |
//! |---|---|---|
//! | [`obfs4`] | obfs4 | `cert=` identity decoding, IAT mode, and the §4 handshake frames (`X' | P_C | M_C | MAC_C` / `Y' | AUTH | P_S | M_S | MAC_S`) with their HMAC-SHA256-128 marks and MACs |
//! | [`webtunnel`] | WebTunnel | RFC 6455 §4.2.1 HTTP/WebSocket upgrade request + `101` response parsing |
//! | [`vanilla`] | vanilla ORPort | tor-spec.txt §3/§4 fixed-width cells, `VERSIONS` and `NETINFO` payloads |
//! | [`snowflake`] | Snowflake | broker rendezvous messages (`/proxy`, `/client`, `/answer`) |
//! | [`meek`] | meek | domain-fronted HTTP `POST` envelope with `X-Session-Id` |
//!
//! ## Honest scope boundary
//!
//! The obfs4 *cryptographic* key establishment — Elligator 2 representative
//! generation, the X25519 scalar multiplication, and the ntor `KEY_SEED`/`AUTH`
//! derivation — is deliberately **not** in this crate. Those operations require
//! a live (or loopback) key exchange and belong to the `prober` crate, which
//! drives these codecs over a socket. What *is* implemented here is the exact
//! byte layout and the HMAC-SHA256-128 authentication framing from
//! `obfs4-spec.txt` §4, so a caller can produce and parse well-formed handshake
//! frames and verify their marks/MACs against a known identity key.
//!
//! Production code in this crate contains no `unwrap()`, `expect()`, or
//! `panic!`; the deny attributes below turn any of those into a hard
//! `cargo clippy` error. Test modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod bridge;
pub mod error;
pub mod meek;
pub mod obfs4;
pub mod snowflake;
pub mod vanilla;
pub mod webtunnel;

pub use error::TransportError;
pub use meek::{MeekRequest, MeekResponse};
pub use obfs4::{IatMode, IdentityKey};
pub use snowflake::{
    ClientOffer, ClientPollRequest, ClientPollResponse, ProxyAnswer, ProxyPollRequest,
    ProxyPollResponse,
};
pub use vanilla::{Addr, Cell, NetinfoCell, VersionsCell};
pub use webtunnel::{UpgradeRequest, UpgradeResponse};

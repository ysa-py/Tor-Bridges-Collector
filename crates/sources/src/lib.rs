//! `tbc-sources` — pluggable bridge collectors behind a single `trait Source`.
//!
//! This crate implements the `crates/sources` responsibility from the master
//! spec (Phase 3): every collector runs behind one interface, and every
//! collector inherits the same resilience stack —
//!
//! * a global token-bucket [`rate_limit::TokenBucket`],
//! * jittered exponential [`backoff::Backoff`],
//! * a per-host [`circuit_breaker::CircuitBreaker`],
//! * ETag / Last-Modified [`cache::ConditionalCache`] (conditional GETs), and
//! * provenance tracking ([`provenance::CollectedBridge`] records which source
//!   saw which bridge and when).
//!
//! The HTTP layer is abstracted behind [`http::HttpTransport`] so the real
//! [`http::ReqwestTransport`] and test transports share one code path. The
//! built-in collectors are [`sources::BridgeLineTextSource`],
//! [`sources::BridgeLineJsonSource`], and [`sources::GithubContentsSource`];
//! the generic [`source::HttpSource`] adapts any HTTPS bridge-list endpoint.
//!
//! Failures are never silent: a collection run returns a
//! [`source::CollectionReport`] in which every unreachable URL, rejected line,
//! rate-limit hit, or tripped circuit breaker is recorded as a
//! [`source::CollectionFailure`] (skip-and-record), while the run itself still
//! completes.
//!
//! Production code in this crate contains no `unwrap()`, `expect()`, `panic!`,
//! `todo!()`, or `unimplemented!()`; the deny attributes below make any of
//! those a hard `cargo clippy` error. Test modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

use std::future::Future;
use std::pin::Pin;

pub mod backoff;
pub mod cache;
pub mod circuit_breaker;
pub mod error;
pub mod http;
pub mod parsers;
pub mod provenance;
pub mod rate_limit;
pub mod source;
pub mod sources;

pub use backoff::Backoff;
pub use cache::{CacheEntry, ConditionalCache};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
pub use error::SourceError;
pub use http::{
    FetchOutcome, HttpClient, HttpRequest, HttpResponse, HttpTransport, ReqwestTransport,
};
pub use provenance::{CollectedBridge, SourceId};
pub use rate_limit::TokenBucket;
pub use source::{
    BodyFormat, BreakerRegistry, CollectionFailure, CollectionReport, HttpSource, Source,
    SourceContext,
};
pub use sources::{BridgeLineJsonSource, BridgeLineTextSource, GithubContentsSource};

/// An owned, boxed, `Send` future — used to define `async` behavior on the
/// object-safe [`Source`] and [`HttpTransport`] traits without pulling in an
/// `async-trait` dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

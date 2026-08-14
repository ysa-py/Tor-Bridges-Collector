//! `tbc-vantage` — in-country measurement adapters.
//!
//! This crate is the `crates/vantage` responsibility from the master spec: a
//! pluggable [`Vantage`] trait over external measurement platforms that
//! observe a bridge *from inside the target country*, plus a quota [`Budget`]
//! that bounds every external call in code (not just in documentation).
//!
//! | Adapter | Platform | Kind of measurement |
//! |---|---|---|
//! | [`GlobalpingVantage`] | Globalping (free tier) | ICMP ping / traceroute from a global probe |
//! | [`RipeAtlasVantage`] | RIPE Atlas (credits) | one-off ping from an in-country probe |
//! | [`OoniVantage`] | OONI open data | existing web-connectivity results for a front domain |
//! | [`AgentVantage`] | volunteer agent | POST a probe request to a volunteer endpoint |
//!
//! Each adapter returns a [`ProbeResult`] (a verdict plus structured
//! evidence), which [`to_observation`] maps into a
//! [`tbc_core::Observation`] for the store and scoring crates.
//!
//! ## Honest scope boundary
//!
//! The HTTP request/response shapes are modeled from each platform's public
//! documentation and are exercised against an in-memory mock transport — they
//! have **not** been run against the live APIs this session (RIPE Atlas
//! requires an API key and credits; live Globalping/OONI calls are a tracked
//! second gate). No mocked response is ever presented as a real measurement.
//!
//! Production code contains no `unwrap()`, `expect()`, or `panic!`; the deny
//! attributes below turn any of those into a hard `cargo clippy` error. Test
//! modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod agent;
pub mod budget;
pub mod config;
pub mod error;
pub mod globalping;
pub mod ooni;
mod platform;
pub mod request;
pub mod ripe;
pub mod transport;
pub mod vantage;

use std::future::Future;
use std::pin::Pin;

/// An owned, boxed, `Send` future — the async shape used by the [`vantage::Vantage`]
/// trait (mirroring the convention in `tbc-sources`).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub use agent::AgentVantage;
pub use budget::Budget;
pub use config::VantageConfig;
pub use error::VantageError;
pub use globalping::GlobalpingVantage;
pub use ooni::OoniVantage;
pub use request::{to_observation, MeasurementRequest, ProbeResult};
pub use ripe::RipeAtlasVantage;
pub use transport::{HttpTransport, Method, ReqwestTransport, VantageRequest, VantageResponse};
pub use vantage::Vantage;

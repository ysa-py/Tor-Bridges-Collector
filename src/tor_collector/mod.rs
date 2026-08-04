//! Unified, async implementation of the public bridge-collection workflow.
//!
//! This module is intentionally separate from the historical parity modules in
//! the repository.  Those modules remain available to preserve the broader
//! TorShield pipeline, while this module provides one production entry point
//! that combines the distinct behavior of `OnionHop.py` and `vip.py`:
//!
//! * multi-source BridgeDB and community-seed collection;
//! * durable, health-aware bridge history;
//! * protocol-appropriate async verification;
//! * README, ZIP, Telegram, metrics, and dry-run publication support.
//!
//! All fallible network and filesystem operations are represented as results
//! and handled at the pipeline boundary. A single unavailable source or probe
//! never terminates a collection session.

pub mod cli;
pub mod config;
pub mod fetch;
pub mod parsing;
pub mod readme;
pub mod service;
pub mod storage;
pub mod tester;

pub use cli::run_from_env;
pub use config::{CollectorConfig, Transport};
pub use service::CollectorService;

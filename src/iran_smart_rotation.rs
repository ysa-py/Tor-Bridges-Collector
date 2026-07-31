//! Smart anti-filtering bridge rotation planner for Iran-native threat models.
//!
//! This module adds an additive, pure-logic capability on top of the existing
//! scored-bridge datasets (`bridge/iran_results.json`): it builds a *rotation
//! plan* that maximises resilience against Iran's SIAM/NGFW filtering stack by
//! combining four independent signals for every candidate bridge:
//!
//!  1. **Transport diversity** — consecutive plan entries round-robin across
//!     transports, because Iranian DPI blocks whole transports in waves
//!     (obfs4 waves, snowflake waves). A rotation that alternates transports
//!     keeps a survivable entry regardless of which transport is currently
//!     under siege.
//!  2. **Network-location (ASN surrogate) diversity** — bridges sharing an
//!     IPv4 /24 (or IPv6 /64) prefix tend to fail together when IRNA/TIC
//!     null-routes a subnet, so the planner cap-limits entries per prefix.
//!  3. **Empirical quality** — the `composite_score` already produced by the
//!     NIN/PT testing stages orders candidates inside each diversity bucket.
//!  4. **Censorship-level escalation** — at high censorship levels (NIN
//!     internet-cut) the transport preference order promotes pluggable
//!     transports with domain-fronting / traffic-morphing properties
//!     (`snowflake`, `webtunnel`) over more fingerprintable ones.
//!
//! The module is deterministic (no RNG, no wall-clock inside the ordering
//! logic) so CI parity gates stay reproducible, and it is pure
//! `serde_json`/`std` so it adds no dependency to the workspace.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::Path;

use chrono::Utc;
use serde_json::{json, Value};

/// Canonical output locations consumed by the pipeline and the workflow.
pub const PLAN_PATH: &str = "data/iran_rotation_plan.json";

// fmt probe 3: module body fully stripped.

//! Multi-Vantage Validation Architecture (§1 of the 10-point spec).
//!
//! Implements distributed validation nodes with regional probe vantage points.
//! Bridge status includes GLOBAL_PASS, GLOBAL_DEGRADED, REGIONAL_DEGRADED,
//! REGIONAL_FAIL. All conclusions are evidence-based — single observations
//! are never treated as proof.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                  Orchestrator                        │
//! │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
//! │  │ EU Control   │  │ NA Control   │  │ ME Control │  │
//! │  │ (Frankfurt)  │  │ (Ashburn)    │  │ (Dubai)    │  │
//! │  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘  │
//! │         │                 │                 │        │
//! │         ▼                 ▼                 ▼        │
//! │  ┌──────────────────────────────────────────────┐    │
//! │  │              Evidence Aggregator              │    │
//! │  │  ┌──────────┐  ┌──────────┐  ┌────────────┐  │    │
//! │  │  │ TCP OK   │  │ TLS OK   │  │ WS OK      │  │    │
//! │  │  └──────────┘  └──────────┘  └────────────┘  │    │
//! │  └──────────────────────────────────────────────┘    │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Status Hierarchy
//!
//! - `GLOBAL_PASS`: All regions report successful probe (TCP+TLS+WS)
//! - `GLOBAL_DEGRADED`: ≥50% regions pass, some fail (network issues)
//! - `REGIONAL_DEGRADED`: <50% regions pass, bridge may be geo-blocked
//! - `REGIONAL_FAIL`: ≥1 region reports active blocking pattern
//! - `UNREACHABLE`: No region can connect at all
//! - `INSUFFICIENT_DATA`: no probe observations recorded (nothing to classify)
//! - `REGIONAL_UNKNOWN`: exactly one probe observation (never a verdict)

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Region definitions
// ─────────────────────────────────────────────────────────────────────────────

/// A geographic vantage point for bridge validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Region {
    /// Europe — Frankfurt / Amsterdam control
    Europe,
    /// North America — Ashburn / US-East control
    NorthAmerica,
    /// Asia — Singapore / Tokyo control
    Asia,
    /// Middle East — Dubai control
    MiddleEast,
    /// South America — São Paulo control
    SouthAmerica,
}

impl Region {
    /// Canonical label for the region.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Europe => "EU",
            Self::NorthAmerica => "NA",
            Self::Asia => "AS",
            Self::MiddleEast => "ME",
            Self::SouthAmerica => "SA",
        }
    }

    /// All regions ordered for deterministic iteration.
    pub fn all() -> &'static [Region] {
        &[
            Region::Europe,
            Region::NorthAmerica,
            Region::Asia,
            Region::MiddleEast,
            Region::SouthAmerica,
        ]
    }

    /// Minimum regions required for a valid multi-vantage assessment.
    pub const MIN_REGIONS_FOR_ASSESSMENT: usize = 2;
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe outcome per region
// ─────────────────────────────────────────────────────────────────────────────

/// Raw probe outcome from a single vantage point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegionalProbeOutcome {
    /// The region this probe was performed from.
    pub region: Region,
    /// Whether TCP connect succeeded.
    pub tcp_ok: bool,
    /// TCP connect latency in milliseconds.
    pub tcp_latency_ms: Option<f64>,
    /// Whether TLS negotiation succeeded.
    pub tls_ok: bool,
    /// TLS handshake latency in milliseconds.
    pub tls_latency_ms: Option<f64>,
    /// Whether the transport-layer handshake succeeded.
    pub transport_ok: bool,
    /// Transport handshake latency in milliseconds.
    pub transport_latency_ms: Option<f64>,
    /// Raw error message if probe failed at any stage.
    pub error: Option<String>,
    /// Resolved IP address from this vantage point.
    pub resolved_ip: Option<IpAddr>,
    /// Whether the result suggested active blocking (RST, TLS alert, etc.).
    pub active_blocking_detected: bool,
    /// Probe timestamp (Unix epoch seconds).
    pub probed_at: f64,
}

impl RegionalProbeOutcome {
    /// Was the probe fully successful at this vantage point?
    pub fn is_fully_reachable(&self) -> bool {
        self.tcp_ok && self.tls_ok && self.transport_ok
    }

    /// Was the probe a partial success (TCP OK, but later stages failed)?
    pub fn is_partially_reachable(&self) -> bool {
        self.tcp_ok && (!self.tls_ok || !self.transport_ok)
    }

    /// Total latency across all stages in milliseconds.
    pub fn total_latency_ms(&self) -> Option<f64> {
        match (
            self.tcp_latency_ms,
            self.tls_latency_ms,
            self.transport_latency_ms,
        ) {
            (Some(t), Some(s), Some(h)) => Some(t + s + h),
            (Some(t), Some(s), None) => Some(t + s),
            _ => self.tcp_latency_ms,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "region": self.region.label(),
            "tcp_ok": self.tcp_ok,
            "tcp_latency_ms": self.tcp_latency_ms,
            "tls_ok": self.tls_ok,
            "tls_latency_ms": self.tls_latency_ms,
            "transport_ok": self.transport_ok,
            "transport_latency_ms": self.transport_latency_ms,
            "error": self.error,
            "resolved_ip": self.resolved_ip.map(|ip| ip.to_string()),
            "active_blocking_detected": self.active_blocking_detected,
            "probed_at": self.probed_at,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-vantage status
// ─────────────────────────────────────────────────────────────────────────────

/// The overall multi-region status of a bridge after aggregating all
/// vantage-point probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MultiVantageStatus {
    /// All probed regions report full reachability.
    GlobalPass,
    /// ≥50% of regions report full reachability; some are degraded.
    GlobalDegraded,
    /// <50% of regions report full reachability — possible geo-blocking.
    RegionalDegraded,
    /// At least one region detected active blocking (RST, TLS alert).
    RegionalFail,
    /// No region could connect at any level.
    Unreachable,
    /// No probe observations at all — nothing to classify.
    InsufficientData,
    /// Exactly one independent probe observation: not enough to conclude
    /// PASS/DEGRADED/FAIL. Never treated as a reachability verdict.
    RegionalUnknown,
}

impl MultiVantageStatus {
    /// Machine-readable code for export and dashboards.
    pub fn code(&self) -> &'static str {
        match self {
            Self::GlobalPass => "GLOBAL_PASS",
            Self::GlobalDegraded => "GLOBAL_DEGRADED",
            Self::RegionalDegraded => "REGIONAL_DEGRADED",
            Self::RegionalFail => "REGIONAL_FAIL",
            Self::Unreachable => "UNREACHABLE",
            Self::InsufficientData => "INSUFFICIENT_DATA",
            Self::RegionalUnknown => "REGIONAL_UNKNOWN",
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::GlobalPass => "Global Pass — all regions reachable",
            Self::GlobalDegraded => "Global Degraded — majority reachable, some failures",
            Self::RegionalDegraded => "Regional Degraded — minority reachable, possible geo-block",
            Self::RegionalFail => "Regional Fail — active blocking detected in ≥1 region",
            Self::Unreachable => "Unreachable — no region could connect",
            Self::InsufficientData => "Insufficient Data — no probe observations recorded",
            Self::RegionalUnknown => {
                "Regional Unknown — single observation, insufficient to conclude"
            }
        }
    }

    /// Numeric score [0.0, 1.0] for ranking and filtering.
    pub fn numeric_score(&self) -> f64 {
        match self {
            Self::GlobalPass => 1.0,
            Self::GlobalDegraded => 0.75,
            Self::RegionalDegraded => 0.4,
            Self::RegionalFail => 0.15,
            Self::Unreachable => 0.0,
            Self::InsufficientData => 0.0,
            Self::RegionalUnknown => 0.0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-vantage aggregator
// ─────────────────────────────────────────────────────────────────────────────

/// The evidence aggregator that consumes per-region probe outcomes and
/// produces a [`MultiVantageStatus`] with structured evidence.
#[derive(Debug, Clone, Default)]
pub struct MultiVantageAggregator {
    /// All regional probe outcomes collected so far.
    outcomes: BTreeMap<Region, RegionalProbeOutcome>,
    /// Regions that were attempted but failed to produce any outcome.
    failed_regions: BTreeSet<Region>,
    /// Minimum fraction of regions that must report full reachability
    /// for the bridge to be classified as GLOBAL_PASS or GLOBAL_DEGRADED.
    pass_threshold: f64,
}

impl MultiVantageAggregator {
    /// Create a new aggregator with the default thresholds.
    pub fn new() -> Self {
        Self {
            outcomes: BTreeMap::new(),
            failed_regions: BTreeSet::new(),
            pass_threshold: 0.5,
        }
    }

    /// Record a probe outcome from a specific region.
    /// Overwrites any previous outcome for the same region.
    pub fn record(&mut self, outcome: RegionalProbeOutcome) {
        let region = outcome.region;
        self.outcomes.insert(region, outcome);
        self.failed_regions.remove(&region);
    }

    /// Record that a region was attempted but could not produce a probe
    /// outcome (e.g., local network failure at the vantage point).
    pub fn record_region_failure(&mut self, region: Region) {
        self.failed_regions.insert(region);
    }

    /// Number of unique regions with recorded outcomes.
    pub fn regions_probed(&self) -> usize {
        self.outcomes.len()
    }

    /// Number of regions where the bridge is fully reachable.
    pub fn fully_reachable_regions(&self) -> usize {
        self.outcomes
            .values()
            .filter(|o| o.is_fully_reachable())
            .count()
    }

    /// Number of regions where active blocking was detected.
    pub fn regions_with_active_blocking(&self) -> usize {
        self.outcomes
            .values()
            .filter(|o| o.active_blocking_detected)
            .count()
    }

    /// HashSet of all probe timestamps to detect whether probes are
    /// concurrent (within the same observation window).
    pub fn probe_time_window_secs(&self) -> Option<f64> {
        let times: Vec<f64> = self.outcomes.values().map(|o| o.probed_at).collect();
        if times.len() < 2 {
            return None;
        }
        let min = times.iter().cloned().fold(f64::NAN, f64::min);
        let max = times.iter().cloned().fold(f64::NAN, f64::max);
        Some(max - min)
    }

    /// Compute the overall multi-vantage status from all recorded outcomes.
    ///
    /// # Decision Logic
    ///
    /// 1. If zero probe observations are recorded →
    ///    [`MultiVantageStatus::InsufficientData`].
    /// 2. If exactly one independent probe observation is recorded →
    ///    [`MultiVantageStatus::RegionalUnknown`] (a single observation is
    ///    never treated as a PASS/DEGRADED/FAIL verdict).
    /// 3. If all probed regions report full reachability →
    ///    [`MultiVantageStatus::GlobalPass`].
    /// 4. If ≥1 region reports active blocking →
    ///    [`MultiVantageStatus::RegionalFail`].
    /// 5. If ≥threshold fraction of regions report full reachability →
    ///    [`MultiVantageStatus::GlobalDegraded`].
    /// 6. If any region reports TCP reachable →
    ///    [`MultiVantageStatus::RegionalDegraded`].
    /// 7. Otherwise → [`MultiVantageStatus::Unreachable`].
    pub fn assess(&self) -> MultiVantageStatus {
        let probed = self.regions_probed();
        let failed = self.failed_regions.len();

        // A PASS/DEGRADED/FAIL conclusion requires at least
        // MIN_REGIONS_FOR_ASSESSMENT independent probe observations.
        if probed == 0 {
            return MultiVantageStatus::InsufficientData;
        }
        if probed < Region::MIN_REGIONS_FOR_ASSESSMENT {
            return MultiVantageStatus::RegionalUnknown;
        }

        // Account for regions that were attempted but failed entirely.
        let effective_regions = probed + failed;

        let fully_reachable = self.fully_reachable_regions();

        // All probed regions pass → GLOBAL_PASS
        if fully_reachable >= probed && failed == 0 && probed > 0 {
            return MultiVantageStatus::GlobalPass;
        }

        // Active blocking detected in any region → REGIONAL_FAIL
        if self.regions_with_active_blocking() > 0 {
            return MultiVantageStatus::RegionalFail;
        }

        // Check fraction of fully reachable vs total attempted regions.
        let reachable_fraction = if effective_regions > 0 {
            fully_reachable as f64 / effective_regions as f64
        } else {
            0.0
        };

        if reachable_fraction >= self.pass_threshold {
            return MultiVantageStatus::GlobalDegraded;
        }

        // Any TCP reachable at all?
        let any_tcp = self.outcomes.values().any(|o| o.tcp_ok);
        if any_tcp {
            return MultiVantageStatus::RegionalDegraded;
        }

        MultiVantageStatus::Unreachable
    }

    /// Build a JSON evidence report for structured logging and analysis.
    pub fn evidence_report(&self) -> Value {
        let status = self.assess();
        let mut regions_json = serde_json::Map::new();
        for (region, outcome) in &self.outcomes {
            regions_json.insert(region.label().to_string(), outcome.to_json());
        }

        let failed: Vec<String> = self
            .failed_regions
            .iter()
            .map(|r| r.label().to_string())
            .collect();

        json!({
            "status": status.code(),
            "status_label": status.label(),
            "numeric_score": status.numeric_score(),
            "regions_probed": self.regions_probed(),
            "regions_failed": failed.len(),
            "fully_reachable": self.fully_reachable_regions(),
            "active_blocking_detected": self.regions_with_active_blocking(),
            "probe_window_secs": self.probe_time_window_secs(),
            "regions": Value::Object(regions_json),
            "failed_region_ids": failed,
            "pass_threshold": self.pass_threshold,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Regional probe coordinator (orchestration logic)
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a multi-vantage probe run.
#[derive(Debug, Clone)]
pub struct MultiVantageConfig {
    /// Regions to probe from.
    pub regions: Vec<Region>,
    /// TCP connect timeout per probe.
    pub tcp_timeout: Duration,
    /// TLS handshake timeout per probe.
    pub tls_timeout: Duration,
    /// Transport handshake timeout per probe.
    pub transport_timeout: Duration,
    /// Maximum wall-clock time for the entire multi-vantage run.
    pub total_timeout: Duration,
    /// Minimum fraction of regions that must succeed for GLOBAL_DEGRADED.
    pub pass_threshold: f64,
    /// Whether to require concurrent probes (within max_window_secs).
    pub require_concurrent: bool,
    /// Maximum acceptable time window between probe timestamps to
    /// consider them "concurrent" (prevents stale data).
    pub max_window_secs: f64,
}

impl Default for MultiVantageConfig {
    fn default() -> Self {
        Self {
            regions: Region::all().to_vec(),
            tcp_timeout: Duration::from_secs(8),
            tls_timeout: Duration::from_secs(6),
            transport_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(60),
            pass_threshold: 0.5,
            require_concurrent: true,
            max_window_secs: 120.0,
        }
    }
}

/// A trait for probe executors that can run probes from specific regions.
///
/// Production implementations use Cloudflare Workers (`EU`, `NA`, `ME`) or
/// other edge compute to get geographic diversity. Tests use mock executors.
pub trait RegionalProbeExecutor: Send + Sync {
    /// Probe a single bridge endpoint from a specific region.
    /// Returns the outcome or an error if the probe infrastructure itself
    /// failed (not the bridge — that's in the outcome).
    fn probe_from_region(
        &self,
        region: Region,
        host: &str,
        port: u16,
        config: &MultiVantageConfig,
    ) -> RegionalProbeOutcome;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }

    fn make_outcome(
        region: Region,
        tcp: bool,
        tls: bool,
        transport: bool,
        blocking: bool,
    ) -> RegionalProbeOutcome {
        RegionalProbeOutcome {
            region,
            tcp_ok: tcp,
            tcp_latency_ms: if tcp { Some(50.0) } else { None },
            tls_ok: tls,
            tls_latency_ms: if tls { Some(100.0) } else { None },
            transport_ok: transport,
            transport_latency_ms: if transport { Some(200.0) } else { None },
            error: None,
            resolved_ip: None,
            active_blocking_detected: blocking,
            probed_at: now(),
        }
    }

    #[test]
    fn global_pass_all_regions_reachable() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        agg.record(make_outcome(Region::NorthAmerica, true, true, true, false));
        agg.record(make_outcome(Region::Asia, true, true, true, false));
        assert_eq!(agg.assess(), MultiVantageStatus::GlobalPass);
    }

    #[test]
    fn global_degraded_majority_reachable() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        agg.record(make_outcome(Region::NorthAmerica, true, true, true, false));
        agg.record(make_outcome(Region::Asia, true, false, false, false));
        agg.record(make_outcome(Region::MiddleEast, true, false, false, false));
        assert_eq!(agg.assess(), MultiVantageStatus::GlobalDegraded);
    }

    #[test]
    fn regional_degraded_minority_reachable() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        agg.record(make_outcome(
            Region::NorthAmerica,
            false,
            false,
            false,
            false,
        ));
        agg.record(make_outcome(Region::Asia, false, false, false, false));
        agg.record(make_outcome(Region::MiddleEast, false, false, false, false));
        assert_eq!(agg.assess(), MultiVantageStatus::RegionalDegraded);
    }

    #[test]
    fn regional_fail_active_blocking_detected() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        agg.record(make_outcome(Region::NorthAmerica, true, true, true, false));
        // Middle East detects active blocking
        agg.record(make_outcome(Region::MiddleEast, true, false, false, true));
        assert_eq!(agg.assess(), MultiVantageStatus::RegionalFail);
    }

    #[test]
    fn unreachable_no_region_connects() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, false, false, false, false));
        agg.record(make_outcome(
            Region::NorthAmerica,
            false,
            false,
            false,
            false,
        ));
        assert_eq!(agg.assess(), MultiVantageStatus::Unreachable);
    }

    #[test]
    fn single_observation_is_regional_unknown_not_a_verdict() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        // Only 1 region probed — below MIN_REGIONS_FOR_ASSESSMENT.
        // A single observation must be REGIONAL_UNKNOWN, never PASS/FAIL.
        assert_eq!(agg.assess(), MultiVantageStatus::RegionalUnknown);
    }

    #[test]
    fn single_failing_observation_is_regional_unknown_not_fail() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, false, false, false, true));
        // Even an active-blocking observation is not a verdict on its own.
        assert_eq!(agg.assess(), MultiVantageStatus::RegionalUnknown);
    }

    #[test]
    fn zero_observations_is_insufficient_data() {
        let agg = MultiVantageAggregator::new();
        assert_eq!(agg.assess(), MultiVantageStatus::InsufficientData);
    }

    #[test]
    fn one_observation_plus_region_failure_is_still_regional_unknown() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        agg.record_region_failure(Region::NorthAmerica);
        // One probe observation + one infra failure is still only a single
        // observation — REGIONAL_UNKNOWN, not a verdict.
        assert_eq!(agg.assess(), MultiVantageStatus::RegionalUnknown);
    }

    #[test]
    fn insufficient_data_one_probed_one_failed_insufficient() {
        let mut agg = MultiVantageAggregator::new();
        agg.record_region_failure(Region::Europe);
        // Only 1 region attempted at all
        assert_eq!(agg.assess(), MultiVantageStatus::InsufficientData);
    }

    #[test]
    fn numeric_scores_are_ordered() {
        let scores = [
            MultiVantageStatus::GlobalPass.numeric_score(),
            MultiVantageStatus::GlobalDegraded.numeric_score(),
            MultiVantageStatus::RegionalDegraded.numeric_score(),
            MultiVantageStatus::RegionalFail.numeric_score(),
            MultiVantageStatus::Unreachable.numeric_score(),
            MultiVantageStatus::InsufficientData.numeric_score(),
            MultiVantageStatus::RegionalUnknown.numeric_score(),
        ];
        for i in 1..scores.len() {
            assert!(scores[i - 1] >= scores[i], "scores should be descending");
        }
    }

    #[test]
    fn regional_probe_outcome_is_fully_reachable() {
        let outcome = make_outcome(Region::Europe, true, true, true, false);
        assert!(outcome.is_fully_reachable());
        assert!(!outcome.is_partially_reachable());
    }

    #[test]
    fn regional_probe_outcome_is_partially_reachable() {
        let outcome = make_outcome(Region::Europe, true, false, false, false);
        assert!(!outcome.is_fully_reachable());
        assert!(outcome.is_partially_reachable());
    }

    #[test]
    fn evidence_report_includes_all_fields() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        agg.record(make_outcome(Region::NorthAmerica, true, true, true, false));
        agg.record(make_outcome(Region::Asia, true, true, true, false));

        let report = agg.evidence_report();
        assert_eq!(report["status"], "GLOBAL_PASS");
        assert_eq!(report["regions_probed"], 3);
        assert_eq!(report["fully_reachable"], 3);
        assert_eq!(report["active_blocking_detected"], 0);
        assert!(report["regions"].is_object());
        assert!(report["numeric_score"].as_f64().unwrap() > 0.9);
    }

    #[test]
    fn duplicate_region_overwrites_previous() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, false, false, false, false));
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        assert_eq!(agg.regions_probed(), 1);
        assert_eq!(agg.fully_reachable_regions(), 1);
    }

    #[test]
    fn all_regions_have_unique_labels() {
        let labels: BTreeSet<&str> = Region::all().iter().map(|r| r.label()).collect();
        assert_eq!(labels.len(), Region::all().len());
    }

    #[test]
    fn multi_vantage_config_defaults_are_valid() {
        let config = MultiVantageConfig::default();
        assert_eq!(config.regions.len(), Region::all().len());
        assert!(config.pass_threshold > 0.0 && config.pass_threshold <= 1.0);
        assert!(config.max_window_secs > 0.0);
    }

    #[test]
    fn probe_time_window_computed_correctly() {
        let mut agg = MultiVantageAggregator::new();
        let t0 = 1000.0;
        let t1 = 1100.0;
        let t2 = 1050.0;

        let mut o1 = make_outcome(Region::Europe, true, true, true, false);
        o1.probed_at = t0;
        let mut o2 = make_outcome(Region::NorthAmerica, true, true, true, false);
        o2.probed_at = t1;
        let mut o3 = make_outcome(Region::Asia, true, true, true, false);
        o3.probed_at = t2;

        agg.record(o1);
        agg.record(o2);
        agg.record(o3);

        let window = agg.probe_time_window_secs().unwrap();
        assert!(
            (window - 100.0).abs() < 0.001,
            "window should be ~100s, got {window}"
        );
    }

    #[test]
    fn probe_time_window_returns_none_for_single_outcome() {
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        assert!(agg.probe_time_window_secs().is_none());
    }

    #[test]
    fn active_blocking_trumps_partial_pass() {
        // Even if 3/4 regions fully pass, 1 active blocking → REGIONAL_FAIL
        let mut agg = MultiVantageAggregator::new();
        agg.record(make_outcome(Region::Europe, true, true, true, false));
        agg.record(make_outcome(Region::NorthAmerica, true, true, true, false));
        agg.record(make_outcome(Region::Asia, true, true, true, false));
        agg.record(make_outcome(Region::MiddleEast, true, false, false, true));
        assert_eq!(agg.assess(), MultiVantageStatus::RegionalFail);
    }

    #[test]
    fn total_latency_sums_all_stages() {
        let outcome = make_outcome(Region::Europe, true, true, true, false);
        let total = outcome.total_latency_ms().unwrap();
        assert!((total - 350.0).abs() < 0.001, "expected 350ms, got {total}");
    }

    #[test]
    fn total_latency_handles_partial_data() {
        let mut outcome = make_outcome(Region::Europe, true, true, false, false);
        outcome.tls_latency_ms = Some(100.0);
        let total = outcome.total_latency_ms().unwrap();
        assert!((total - 150.0).abs() < 0.001);
    }

    #[test]
    fn all_status_codes_are_unique() {
        let codes: BTreeSet<&str> = [
            MultiVantageStatus::GlobalPass,
            MultiVantageStatus::GlobalDegraded,
            MultiVantageStatus::RegionalDegraded,
            MultiVantageStatus::RegionalFail,
            MultiVantageStatus::Unreachable,
            MultiVantageStatus::InsufficientData,
            MultiVantageStatus::RegionalUnknown,
        ]
        .iter()
        .map(|s| s.code())
        .collect();
        assert_eq!(codes.len(), 7);
    }

    /// Build an aggregator from deterministic fixture tuples and a set of
    /// infra-failed regions. Fully reachable = (tcp, tls, transport) all true.
    fn agg_from(
        outcomes: &[(Region, bool, bool, bool, bool)],
        failed: &[Region],
    ) -> MultiVantageAggregator {
        let mut agg = MultiVantageAggregator::new();
        for &(region, tcp, tls, transport, blocking) in outcomes {
            agg.record(make_outcome(region, tcp, tls, transport, blocking));
        }
        for &region in failed {
            agg.record_region_failure(region);
        }
        agg
    }

    /// (name, expected status, expected score, probe outcomes, failed regions)
    type FixtureCase = (
        &'static str,
        MultiVantageStatus,
        f64,
        &'static [(Region, bool, bool, bool, bool)],
        &'static [Region],
    );

    #[test]
    fn full_spectrum_verdicts_with_hand_derived_values() {
        // Deterministic, no network. Every verdict and its numeric_score is
        // hand-derived from the documented decision logic in `assess()`.
        let cases: &[FixtureCase] = &[
            (
                "all probed regions fully reachable, no infra failure -> GLOBAL_PASS",
                MultiVantageStatus::GlobalPass,
                1.0,
                &[
                    (Region::Europe, true, true, true, false),
                    (Region::NorthAmerica, true, true, true, false),
                    (Region::Asia, true, true, true, false),
                ],
                &[],
            ),
            (
                "2/4 fully reachable = exactly the 0.5 threshold -> GLOBAL_DEGRADED",
                MultiVantageStatus::GlobalDegraded,
                0.75,
                &[
                    (Region::Europe, true, true, true, false),
                    (Region::NorthAmerica, true, true, true, false),
                    (Region::Asia, true, false, false, false),
                    (Region::MiddleEast, true, false, false, false),
                ],
                &[],
            ),
            (
                "1/4 fully reachable < 0.5 but TCP reachable -> REGIONAL_DEGRADED",
                MultiVantageStatus::RegionalDegraded,
                0.4,
                &[
                    (Region::Europe, true, true, true, false),
                    (Region::NorthAmerica, false, false, false, false),
                    (Region::Asia, false, false, false, false),
                    (Region::MiddleEast, false, false, false, false),
                ],
                &[],
            ),
            (
                "active blocking in one region trumps majority pass -> REGIONAL_FAIL",
                MultiVantageStatus::RegionalFail,
                0.15,
                &[
                    (Region::Europe, true, true, true, false),
                    (Region::NorthAmerica, true, true, true, false),
                    (Region::MiddleEast, true, false, false, true),
                ],
                &[],
            ),
            (
                "no region connects at any level -> UNREACHABLE",
                MultiVantageStatus::Unreachable,
                0.0,
                &[
                    (Region::Europe, false, false, false, false),
                    (Region::NorthAmerica, false, false, false, false),
                ],
                &[],
            ),
            (
                "zero observations -> INSUFFICIENT_DATA",
                MultiVantageStatus::InsufficientData,
                0.0,
                &[],
                &[],
            ),
            (
                "single fully-reachable observation -> REGIONAL_UNKNOWN, never a verdict",
                MultiVantageStatus::RegionalUnknown,
                0.0,
                &[(Region::Europe, true, true, true, false)],
                &[],
            ),
            (
                "single active-blocking observation -> REGIONAL_UNKNOWN, never a verdict",
                MultiVantageStatus::RegionalUnknown,
                0.0,
                &[(Region::Europe, true, false, false, true)],
                &[],
            ),
            (
                "single observation + one infra-failed region -> REGIONAL_UNKNOWN",
                MultiVantageStatus::RegionalUnknown,
                0.0,
                &[(Region::Europe, true, true, true, false)],
                &[Region::NorthAmerica],
            ),
            (
                "all probed pass but one region infra-failed -> GLOBAL_DEGRADED, not GLOBAL_PASS",
                MultiVantageStatus::GlobalDegraded,
                0.75,
                &[
                    (Region::Europe, true, true, true, false),
                    (Region::NorthAmerica, true, true, true, false),
                ],
                &[Region::MiddleEast],
            ),
        ];

        for (name, expected_status, expected_score, outcomes, failed) in cases {
            let agg = agg_from(outcomes, failed);
            let actual = agg.assess();
            assert_eq!(
                actual,
                *expected_status,
                "case `{name}`: expected {} got {}",
                expected_status.code(),
                actual.code()
            );
            assert_eq!(
                actual.numeric_score(),
                *expected_score,
                "case `{name}`: numeric_score mismatch"
            );
        }
    }

    #[test]
    fn evidence_report_exact_values_for_deterministic_fixture() {
        // Deterministic timestamps so probe_window_secs is hand-computable.
        let mut o1 = make_outcome(Region::Europe, true, true, true, false);
        o1.probed_at = 1000.0;
        let mut o2 = make_outcome(Region::NorthAmerica, true, true, true, false);
        o2.probed_at = 1050.0;
        let mut o3 = make_outcome(Region::Asia, true, true, true, false);
        o3.probed_at = 1100.0;

        let mut agg = MultiVantageAggregator::new();
        agg.record(o1);
        agg.record(o2);
        agg.record(o3);
        agg.record_region_failure(Region::MiddleEast);

        // 3 fully reachable of 3 probed + 1 infra-failed region: fraction is
        // 3/4 = 0.75 >= 0.5, but failed != 0 so GLOBAL_PASS is excluded ->
        // GLOBAL_DEGRADED with exact, hand-derived report values.
        let report = agg.evidence_report();
        assert_eq!(report["status"], "GLOBAL_DEGRADED");
        assert_eq!(report["regions_probed"], 3);
        assert_eq!(report["regions_failed"], 1);
        assert_eq!(report["fully_reachable"], 3);
        assert_eq!(report["active_blocking_detected"], 0);
        assert_eq!(report["numeric_score"], 0.75);
        assert_eq!(report["probe_window_secs"], 100.0);
        assert_eq!(report["pass_threshold"], 0.5);
        let regions = report["regions"].as_object().unwrap();
        assert_eq!(regions.len(), 3);
        for label in ["EU", "NA", "AS"] {
            assert!(regions.contains_key(label), "missing region {label}");
        }
        let failed_ids = report["failed_region_ids"].as_array().unwrap();
        assert_eq!(failed_ids.len(), 1);
        assert_eq!(failed_ids[0], "ME");
    }
}

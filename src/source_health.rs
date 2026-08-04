//! Adaptive Source-Health Feedback Loop (Phase 3 — Feature 1)
//!
//! Dynamically computes moving-average reliability scores for each bridge
//! source based on historical response latency, error rates, and payload
//! yield. Automatically downweights or quarantines degrading sources in
//! real time.
//!
//! # Design
//!
//! Each source (identified by URL or transport+IP combination) maintains a
//! [`SourceHealthRecord`] that tracks:
//! - Success/failure counts (exponential moving average)
//! - Average latency (exponential moving average)
//! - Payload yield (bridges returned per fetch)
//! - Composite health score (0.0–1.0)
//!
//! The [`SourceHealthTracker`] is thread-safe (`Send + Sync`) and can be
//! shared across concurrent fetchers via `Arc<Mutex<SourceHealthTracker>>`.
//!
//! # Integration
//!
//! This module feeds into `adaptive_selector.rs` and `sources_torproject.rs`
//! to dynamically deprioritize failing sources and re-promote recovering ones.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

/// Exponential moving average decay factor. Higher values give more weight
/// to recent observations. 0.3 means ~70% weight on history, 30% on latest.
const EMA_ALPHA: f64 = 0.3;

/// Health score threshold below which a source is quarantined (skipped).
const QUARANTINE_THRESHOLD: f64 = 0.2;

/// Health score threshold above which a quarantined source is re-promoted.
const RECOVERY_THRESHOLD: f64 = 0.5;

/// Maximum number of consecutive failures before hard quarantine.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Errors from the source health tracking system.
#[derive(Debug, thiserror::Error)]
pub enum SourceHealthError {
    #[error("source health: unknown source '{0}'")]
    UnknownSource(String),
    #[error("source health: lock poisoned")]
    LockPoisoned,
}

/// Per-source health metrics tracked as exponential moving averages.
#[derive(Debug, Clone)]
pub struct SourceHealthRecord {
    /// Source identifier (URL or transport+IP key).
    pub source_id: String,
    /// EMA of success rate (0.0–1.0). 1.0 = always succeeds.
    pub success_rate_ema: f64,
    /// EMA of latency in milliseconds.
    pub latency_ema_ms: f64,
    /// EMA of bridge yield per fetch.
    pub yield_ema: f64,
    /// Total fetch attempts.
    pub total_fetches: u64,
    /// Total successful fetches.
    pub total_successes: u64,
    /// Total bridges returned across all successful fetches.
    pub total_bridges: u64,
    /// Consecutive failure count (resets on success).
    pub consecutive_failures: u32,
    /// Whether this source is currently quarantined.
    pub quarantined: bool,
    /// Timestamp of last successful fetch (ISO 8601).
    pub last_success: String,
    /// Timestamp of last fetch attempt (ISO 8601).
    pub last_attempt: String,
}

impl SourceHealthRecord {
    /// Create a new record for a source with default (neutral) metrics.
    #[must_use]
    pub fn new(source_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            success_rate_ema: 1.0,
            latency_ema_ms: 0.0,
            yield_ema: 0.0,
            total_fetches: 0,
            total_successes: 0,
            total_bridges: 0,
            consecutive_failures: 0,
            quarantined: false,
            last_success: String::new(),
            last_attempt: String::new(),
        }
    }

    /// Compute composite health score (0.0–1.0).
    ///
    /// Weights:
    /// - Success rate: 50%
    /// - Latency penalty: 25% (lower is better, capped at 30s)
    /// - Yield: 25% (higher is better, capped at 100)
    #[must_use]
    pub fn health_score(&self) -> f64 {
        let success_component = self.success_rate_ema * 0.5;

        // Latency penalty: 0ms = 1.0, 30000ms+ = 0.0
        let latency_component = if self.latency_ema_ms <= 0.0 {
            1.0
        } else {
            (1.0 - (self.latency_ema_ms / 30_000.0)).max(0.0)
        } * 0.25;

        // Yield component: 0 = 0.0, 100+ = 1.0
        let yield_component = (self.yield_ema / 100.0).min(1.0) * 0.25;

        (success_component + latency_component + yield_component).min(1.0)
    }

    /// Record a successful fetch with the given latency and bridge count.
    pub fn record_success(&mut self, latency: Duration, bridge_count: usize, timestamp: &str) {
        let latency_ms = latency.as_secs_f64() * 1000.0;
        let yield_f = bridge_count as f64;

        // EMA updates
        self.success_rate_ema = EMA_ALPHA * 1.0 + (1.0 - EMA_ALPHA) * self.success_rate_ema;
        self.latency_ema_ms = if self.total_fetches == 0 {
            latency_ms
        } else {
            EMA_ALPHA * latency_ms + (1.0 - EMA_ALPHA) * self.latency_ema_ms
        };
        self.yield_ema = if self.total_successes == 0 {
            yield_f
        } else {
            EMA_ALPHA * yield_f + (1.0 - EMA_ALPHA) * self.yield_ema
        };

        self.total_fetches += 1;
        self.total_successes += 1;
        self.total_bridges += bridge_count as u64;
        self.consecutive_failures = 0;
        self.last_success = timestamp.to_string();
        self.last_attempt = timestamp.to_string();

        // Recovery: un-quarantine if health score exceeds recovery threshold
        if self.quarantined && self.health_score() >= RECOVERY_THRESHOLD {
            self.quarantined = false;
        }
    }

    /// Record a failed fetch attempt.
    pub fn record_failure(&mut self, timestamp: &str) {
        self.success_rate_ema = EMA_ALPHA * 0.0 + (1.0 - EMA_ALPHA) * self.success_rate_ema;
        self.total_fetches += 1;
        self.consecutive_failures += 1;
        self.last_attempt = timestamp.to_string();

        // Hard quarantine on consecutive failures
        if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            self.quarantined = true;
        }

        // Soft quarantine on low health score
        if self.health_score() < QUARANTINE_THRESHOLD {
            self.quarantined = true;
        }
    }

    /// Convert to JSON for telemetry/reporting.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "health_score": (self.health_score() * 1000.0).round() / 1000.0,
            "success_rate_ema": (self.success_rate_ema * 1000.0).round() / 1000.0,
            "latency_ema_ms": (self.latency_ema_ms * 10.0).round() / 10.0,
            "yield_ema": (self.yield_ema * 10.0).round() / 10.0,
            "total_fetches": self.total_fetches,
            "total_successes": self.total_successes,
            "total_bridges": self.total_bridges,
            "consecutive_failures": self.consecutive_failures,
            "quarantined": self.quarantined,
            "last_success": self.last_success,
            "last_attempt": self.last_attempt,
        })
    }
}

/// Thread-safe tracker for source health metrics across all bridge sources.
///
/// Designed to be shared via `Arc<Mutex<SourceHealthTracker>>` across
/// concurrent fetchers.
#[derive(Debug, Clone)]
pub struct SourceHealthTracker {
    records: BTreeMap<String, SourceHealthRecord>,
    /// Sources sorted by health score (descending) for priority selection.
    priority_order: Vec<String>,
}

impl SourceHealthTracker {
    /// Create a new empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            priority_order: Vec::new(),
        }
    }

    /// Register a source for tracking. Idempotent.
    pub fn register_source(&mut self, source_id: impl Into<String>) {
        let id = source_id.into();
        self.records.entry(id.clone()).or_insert_with(|| {
            SourceHealthRecord::new(id)
        });
    }

    /// Record a successful fetch for a source.
    pub fn record_success(
        &mut self,
        source_id: &str,
        latency: Duration,
        bridge_count: usize,
        timestamp: &str,
    ) {
        if let Some(record) = self.records.get_mut(source_id) {
            record.record_success(latency, bridge_count, timestamp);
            self.recompute_priority();
        }
    }

    /// Record a failed fetch for a source.
    pub fn record_failure(&mut self, source_id: &str, timestamp: &str) {
        if let Some(record) = self.records.get_mut(source_id) {
            record.record_failure(timestamp);
            self.recompute_priority();
        }
    }

    /// Check if a source is available (not quarantined).
    #[must_use]
    pub fn is_available(&self, source_id: &str) -> bool {
        self.records
            .get(source_id)
            .map(|r| !r.quarantined)
            .unwrap_or(true) // Unknown sources are assumed available
    }

    /// Get the health score for a source (0.0–1.0).
    #[must_use]
    pub fn health_score(&self, source_id: &str) -> f64 {
        self.records
            .get(source_id)
            .map(|r| r.health_score())
            .unwrap_or(1.0)
    }

    /// Get sources sorted by health score (descending), excluding quarantined.
    #[must_use]
    pub fn prioritized_sources(&self) -> &[String] {
        &self.priority_order
    }

    /// Get weight for a source (used for weighted random selection).
    /// Returns 0.0 for quarantined sources.
    #[must_use]
    pub fn source_weight(&self, source_id: &str) -> f64 {
        self.records
            .get(source_id)
            .map(|r| {
                if r.quarantined {
                    0.0
                } else {
                    r.health_score()
                }
            })
            .unwrap_or(1.0)
    }

    /// Get full status report as JSON.
    #[must_use]
    pub fn status_report(&self) -> Value {
        let sources: Vec<Value> = self
            .records
            .values()
            .map(|r| r.to_json())
            .collect();
        let quarantined: Vec<&str> = self
            .records
            .values()
            .filter(|r| r.quarantined)
            .map(|r| r.source_id.as_str())
            .collect();
        json!({
            "total_sources": self.records.len(),
            "available_sources": self.priority_order.len(),
            "quarantined_sources": quarantined.len(),
            "quarantined_ids": quarantined,
            "priority_order": self.priority_order,
            "sources": sources,
        })
    }

    /// Recompute priority order based on health scores.
    fn recompute_priority(&mut self) {
        let mut available: Vec<(String, f64)> = self
            .records
            .values()
            .filter(|r| !r.quarantined)
            .map(|r| (r.source_id.clone(), r.health_score()))
            .collect();
        available.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        self.priority_order = available.into_iter().map(|(id, _)| id).collect();
    }
}

impl Default for SourceHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe shared handle to a [`SourceHealthTracker`].
pub type SharedSourceHealth = Arc<Mutex<SourceHealthTracker>>;

/// Create a new shared source health tracker.
#[must_use]
pub fn new_shared_health() -> SharedSourceHealth {
    Arc::new(Mutex::new(SourceHealthTracker::new()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_record_has_perfect_health() {
        let record = SourceHealthRecord::new("https://bridges.torproject.org/obfs4");
        assert_eq!(record.health_score(), 1.0);
        assert!(!record.quarantined);
        assert_eq!(record.consecutive_failures, 0);
    }

    #[test]
    fn success_maintains_high_health() {
        let mut record = SourceHealthRecord::new("test-source");
        record.record_success(Duration::from_millis(500), 50, "2026-08-04T12:00:00Z");
        record.record_success(Duration::from_millis(600), 45, "2026-08-04T12:01:00Z");
        assert!(record.health_score() > 0.8);
        assert!(!record.quarantined);
    }

    #[test]
    fn consecutive_failures_trigger_quarantine() {
        let mut record = SourceHealthRecord::new("failing-source");
        for i in 0..MAX_CONSECUTIVE_FAILURES {
            record.record_failure(&format!("2026-08-04T12:{:02}:00Z", i));
        }
        assert!(record.quarantined);
        assert_eq!(record.consecutive_failures, MAX_CONSECUTIVE_FAILURES);
    }

    #[test]
    fn recovery_after_success() {
        let mut record = SourceHealthRecord::new("recovering-source");
        // Quarantine it
        for i in 0..MAX_CONSECUTIVE_FAILURES {
            record.record_failure(&format!("2026-08-04T12:{:02}:00Z", i));
        }
        assert!(record.quarantined);

        // Recover with several successes
        for i in 0..10 {
            record.record_success(
                Duration::from_millis(200),
                80,
                &format!("2026-08-04T13:{:02}:00Z", i),
            );
        }
        assert!(!record.quarantined);
        assert!(record.health_score() > RECOVERY_THRESHOLD);
    }

    #[test]
    fn health_score_components() {
        let mut record = SourceHealthRecord::new("test");
        // Perfect: fast, high yield, always succeeds
        record.record_success(Duration::from_millis(100), 100, "2026-08-04T12:00:00Z");
        let score = record.health_score();
        // success: 0.5, latency: ~0.25, yield: 0.25 = ~1.0
        assert!(score > 0.95, "expected >0.95, got {score}");
    }

    #[test]
    fn high_latency_reduces_health() {
        let mut record = SourceHealthRecord::new("slow-source");
        record.record_success(Duration::from_millis(25_000), 10, "2026-08-04T12:00:00Z");
        let score = record.health_score();
        // success: 0.5, latency: ~0.04 (25s/30s penalty), yield: 0.025 = ~0.565
        assert!(score < 0.7, "expected <0.7 for high latency, got {score}");
    }

    #[test]
    fn tracker_prioritizes_healthy_sources() {
        let mut tracker = SourceHealthTracker::new();
        tracker.register_source("healthy");
        tracker.register_source("degraded");
        tracker.register_source("failing");

        // Healthy: fast, high yield
        tracker.record_success("healthy", Duration::from_millis(100), 80, "t1");
        // Degraded: slow, low yield
        tracker.record_success("degraded", Duration::from_millis(5000), 5, "t1");
        // Failing: multiple failures
        for i in 0..3 {
            tracker.record_failure("failing", &format!("t{i}"));
        }

        let priority = tracker.prioritized_sources();
        assert_eq!(priority[0], "healthy");
        // Failing should still be available (not yet at MAX_CONSECUTIVE_FAILURES)
        assert!(priority.contains(&"failing".to_string()));
    }

    #[test]
    fn tracker_quarantines_failing_sources() {
        let mut tracker = SourceHealthTracker::new();
        tracker.register_source("source-a");

        for i in 0..MAX_CONSECUTIVE_FAILURES {
            tracker.record_failure("source-a", &format!("t{i}"));
        }

        assert!(!tracker.is_available("source-a"));
        assert_eq!(tracker.prioritized_sources().len(), 0);
    }

    #[test]
    fn tracker_weight_zero_for_quarantined() {
        let mut tracker = SourceHealthTracker::new();
        tracker.register_source("q-source");
        for i in 0..MAX_CONSECUTIVE_FAILURES {
            tracker.record_failure("q-source", &format!("t{i}"));
        }
        assert_eq!(tracker.source_weight("q-source"), 0.0);
    }

    #[test]
    fn tracker_status_report_json() {
        let mut tracker = SourceHealthTracker::new();
        tracker.register_source("s1");
        tracker.register_source("s2");
        tracker.record_success("s1", Duration::from_millis(200), 30, "t1");
        tracker.record_failure("s2", "t1");

        let report = tracker.status_report();
        assert_eq!(report["total_sources"], 2);
        assert_eq!(report["available_sources"], 2);
        assert!(report["sources"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn shared_health_is_send_sync() {
        let health = new_shared_health();
        // Verify Send + Sync at compile time
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        assert_send_sync(&health);
    }

    #[test]
    fn ema_converges_to_recent_value() {
        let mut record = SourceHealthRecord::new("ema-test");
        // Start with failures
        for i in 0..5 {
            record.record_failure(&format!("t{i}"));
        }
        assert!(record.success_rate_ema < 0.3);

        // Then many successes
        for i in 0..20 {
            record.record_success(Duration::from_millis(100), 50, &format!("s{i}"));
        }
        // EMA should converge toward 1.0
        assert!(
            record.success_rate_ema > 0.9,
            "EMA should converge: got {}",
            record.success_rate_ema
        );
    }
}

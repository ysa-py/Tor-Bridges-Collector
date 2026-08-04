//! Injected-Failure Verification Suite (Phase 4 — Feature 2)
//!
//! Integration test suite that explicitly injects failure modes and verifies
//! that the self-healing and circuit-breaker logic transparently recovers
//! without crashing the runtime process.
//!
//! # Failure Modes Tested
//!
//! 1. **Corrupted upstream payload** — Source returns invalid HTML/JSON
//! 2. **Timed-out network interfaces** — Source takes too long to respond
//! 3. **Invalid bridge signatures** — Source returns malformed bridge lines
//! 4. **Source outage** — Source returns HTTP 500/404
//! 5. **Partial data loss** — Source returns empty bridge list
//! 6. **Circuit breaker trip** — Source fails repeatedly, triggering CB
//! 7. **Circuit breaker recovery** — Source recovers after cooldown

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Value};

use crate::source_circuit_breaker::{SourceCircuitBreakerManager, SourceCircuitState};
use crate::source_health::SourceHealthTracker;
use crate::bridge_dedup::{BridgeDeduplicator, DedupStrategy};
use crate::yield_telemetry::{YieldTelemetry, SourceYieldMetrics, TelemetryAggregator};
use crate::censorship_scorer_fusion::CensorshipFusionScorer;

/// Result of an injected failure test.
#[derive(Debug, Clone)]
pub struct InjectedTestResult {
    pub test_name: String,
    pub passed: bool,
    pub description: String,
    pub details: Value,
}

impl InjectedTestResult {
    #[must_use]
    pub fn pass(name: impl Into<String>, desc: impl Into<String>, details: Value) -> Self {
        Self {
            test_name: name.into(),
            passed: true,
            description: desc.into(),
            details,
        }
    }

    #[must_use]
    pub fn fail(name: impl Into<String>, desc: impl Into<String>, details: Value) -> Self {
        Self {
            test_name: name.into(),
            passed: false,
            description: desc.into(),
            details,
        }
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "test_name": self.test_name,
            "passed": self.passed,
            "description": self.description,
            "details": self.details,
        })
    }
}

/// Run all injected-failure verification tests.
/// Returns a list of test results.
#[must_use]
pub fn run_all_injected_tests() -> Vec<InjectedTestResult> {
    let mut results = Vec::new();
    results.push(test_corrupted_payload_handling());
    results.push(test_timeout_handling());
    results.push(test_invalid_bridge_signatures());
    results.push(test_source_outage_circuit_breaker());
    results.push(test_partial_data_loss());
    results.push(test_circuit_breaker_trip_and_recovery());
    results.push(test_source_health_quarantine_recovery());
    results.push(test_dedup_under_mixed_sources());
    results.push(test_censorship_fusion_under_outage());
    results.push(test_telemetry_anomaly_detection());
    results
}

/// Generate a JSON report of all test results.
#[must_use]
pub fn test_report() -> Value {
    let results = run_all_injected_tests();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.iter().filter(|r| !r.passed).count();
    json!({
        "total_tests": results.len(),
        "passed": passed,
        "failed": failed,
        "all_passed": failed == 0,
        "tests": results.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual Test Implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Test 1: Corrupted upstream payload handling.
/// Verifies that the pipeline gracefully handles invalid HTML/JSON from sources.
fn test_corrupted_payload_handling() -> InjectedTestResult {
    let mut tracker = SourceHealthTracker::new();
    tracker.register_source("corrupted-source");

    // Simulate corrupted payload: 0 bridges returned
    tracker.record_success("corrupted-source", Duration::from_millis(500), 0, "t1");

    let health = tracker.health_score("corrupted-source");
    let available = tracker.is_available("corrupted-source");

    // Should still be available but with reduced health (0 yield)
    if available && health < 1.0 {
        InjectedTestResult::pass(
            "corrupted_payload_handling",
            "Pipeline handles corrupted payload (0 bridges) without crashing",
            json!({"health": health, "available": available}),
        )
    } else {
        InjectedTestResult::fail(
            "corrupted_payload_handling",
            format!("Expected available=true, health<1.0; got available={available}, health={health}"),
            json!({"health": health, "available": available}),
        )
    }
}

/// Test 2: Timeout handling.
/// Verifies that slow sources are penalized but not immediately quarantined.
fn test_timeout_handling() -> InjectedTestResult {
    let mut tracker = SourceHealthTracker::new();
    tracker.register_source("slow-source");

    // Simulate very slow response (25 seconds)
    tracker.record_success("slow-source", Duration::from_secs(25), 10, "t1");

    let health = tracker.health_score("slow-source");
    let available = tracker.is_available("slow-source");

    // Should be available but with reduced health due to high latency
    if available && health < 0.8 {
        InjectedTestResult::pass(
            "timeout_handling",
            "Slow source penalized but not quarantined",
            json!({"health": health, "available": available}),
        )
    } else {
        InjectedTestResult::fail(
            "timeout_handling",
            format!("Expected available=true, health<0.8; got available={available}, health={health}"),
            json!({"health": health, "available": available}),
        )
    }
}

/// Test 3: Invalid bridge signatures.
/// Verifies that malformed bridge lines are handled by deduplication.
fn test_invalid_bridge_signatures() -> InjectedTestResult {
    let mut dedup = BridgeDeduplicator::new(DedupStrategy::Exact);

    // Add valid bridge
    let valid = dedup.add_bridge("obfs4 1.2.3.4:443 ABCD cert=xyz", "source-a", 0.9);

    // Add malformed bridges (should not crash)
    let malformed1 = dedup.add_bridge("", "source-b", 0.0);
    let malformed2 = dedup.add_bridge("not-a-bridge-line", "source-c", 0.0);
    let malformed3 = dedup.add_bridge("obfs4", "source-d", 0.0);

    // Should have accepted all without crashing
    let count = dedup.len();
    if valid && count >= 1 {
        InjectedTestResult::pass(
            "invalid_bridge_signatures",
            format!("Dedup handles malformed bridges without crashing ({count} unique)"),
            json!({
                "valid_accepted": valid,
                "malformed_handled": [malformed1, malformed2, malformed3],
                "unique_count": count,
            }),
        )
    } else {
        InjectedTestResult::fail(
            "invalid_bridge_signatures",
            "Dedup failed to handle malformed bridges",
            json!({"valid": valid, "count": count}),
        )
    }
}

/// Test 4: Source outage triggers circuit breaker.
fn test_source_outage_circuit_breaker() -> InjectedTestResult {
    let mut mgr = SourceCircuitBreakerManager::with_defaults(3, 300, 2);
    mgr.register("failing-source");

    // Simulate 3 consecutive failures
    mgr.record_failure("failing-source");
    mgr.record_failure("failing-source");
    mgr.record_failure("failing-source");

    let state = mgr.state("failing-source");
    let open = mgr.open_circuits();

    if state == SourceCircuitState::Open && open.contains(&"failing-source") {
        InjectedTestResult::pass(
            "source_outage_circuit_breaker",
            "Circuit breaker trips after 3 consecutive failures",
            json!({"state": state.as_str(), "open_circuits": open}),
        )
    } else {
        InjectedTestResult::fail(
            "source_outage_circuit_breaker",
            format!("Expected Open state; got {:?}", state),
            json!({"state": state.as_str()}),
        )
    }
}

/// Test 5: Partial data loss handling.
fn test_partial_data_loss() -> InjectedTestResult {
    let mut dedup = BridgeDeduplicator::new(DedupStrategy::SubnetAware);

    // Add some valid bridges
    dedup.add_bridge("obfs4 1.2.3.4:443 A cert=x", "source-a", 0.9);
    dedup.add_bridge("obfs4 5.6.7.8:443 B cert=y", "source-a", 0.8);
    dedup.add_bridge("webtunnel [2001:db8::1]:443 C url=https://x", "source-a", 0.7);

    // Simulate partial loss: only 2 of 3 sources respond
    dedup.add_bridge("obfs4 1.2.3.4:443 A cert=x", "source-b", 0.85); // Duplicate

    let count = dedup.len();
    let stats = dedup.stats();

    if count == 3 && stats.duplicates_removed == 1 {
        InjectedTestResult::pass(
            "partial_data_loss",
            format!("Dedup correctly handles partial data ({count} unique, {dupes} dupes)", dupes = stats.duplicates_removed),
            dedup.stats_json(),
        )
    } else {
        InjectedTestResult::fail(
            "partial_data_loss",
            format!("Expected 3 unique, 1 dupe; got {count} unique, {} dupes", stats.duplicates_removed),
            dedup.stats_json(),
        )
    }
}

/// Test 6: Circuit breaker trip and recovery.
fn test_circuit_breaker_trip_and_recovery() -> InjectedTestResult {
    let mut mgr = SourceCircuitBreakerManager::with_defaults(2, 1, 2); // 1ms cooldown for test
    mgr.register("recovering-source");

    // Trip the circuit
    mgr.record_failure("recovering-source");
    mgr.record_failure("recovering-source");
    let tripped = mgr.state("recovering-source") == SourceCircuitState::Open;

    // Wait for cooldown
    std::thread::sleep(Duration::from_millis(5));

    // Probe should be allowed
    let probe_allowed = mgr.allow_request("recovering-source");

    // Successful probes should close the circuit
    mgr.record_success("recovering-source");
    mgr.record_success("recovering-source");
    let recovered = mgr.state("recovering-source") == SourceCircuitState::Closed;

    if tripped && probe_allowed && recovered {
        InjectedTestResult::pass(
            "circuit_breaker_trip_and_recovery",
            "Circuit breaker trips, allows probes after cooldown, recovers on success",
            json!({"tripped": tripped, "probe_allowed": probe_allowed, "recovered": recovered}),
        )
    } else {
        InjectedTestResult::fail(
            "circuit_breaker_trip_and_recovery",
            format!("tripped={tripped}, probe_allowed={probe_allowed}, recovered={recovered}"),
            json!({"tripped": tripped, "probe_allowed": probe_allowed, "recovered": recovered}),
        )
    }
}

/// Test 7: Source health quarantine and recovery.
fn test_source_health_quarantine_recovery() -> InjectedTestResult {
    let mut tracker = SourceHealthTracker::new();
    tracker.register_source("flaky-source");

    // Quarantine via consecutive failures
    for i in 0..5 {
        tracker.record_failure("flaky-source", &format!("t{i}"));
    }
    let quarantined = !tracker.is_available("flaky-source");

    // Recovery via successes
    for i in 0..15 {
        tracker.record_success(
            "flaky-source",
            Duration::from_millis(200),
            50,
            &format!("r{i}"),
        );
    }
    let recovered = tracker.is_available("flaky-source");

    if quarantined && recovered {
        InjectedTestResult::pass(
            "source_health_quarantine_recovery",
            "Source quarantined after failures, recovered after successes",
            json!({"quarantined": quarantined, "recovered": recovered}),
        )
    } else {
        InjectedTestResult::fail(
            "source_health_quarantine_recovery",
            format!("quarantined={quarantined}, recovered={recovered}"),
            json!({"quarantined": quarantined, "recovered": recovered}),
        )
    }
}

/// Test 8: Deduplication under mixed sources.
fn test_dedup_under_mixed_sources() -> InjectedTestResult {
    let mut dedup = BridgeDeduplicator::new(DedupStrategy::Fuzzy);

    // Same bridge from 3 different sources
    dedup.add_bridge("obfs4 1.2.3.4:443 A cert=x", "torproject", 0.9);
    dedup.add_bridge("obfs4 1.2.3.4:443 A cert=x", "telegram", 0.8);
    dedup.add_bridge("obfs4 1.2.3.4:443 A cert=x", "github", 0.7);

    // Different bridge
    dedup.add_bridge("webtunnel 5.6.7.8:443 B url=https://y", "torproject", 0.85);

    let count = dedup.len();
    let bridge = dedup.bridges().find(|b| b.transport == "obfs4").unwrap();
    let sources = bridge.sources.len();

    if count == 2 && sources == 3 {
        InjectedTestResult::pass(
            "dedup_under_mixed_sources",
            format!("Dedup merged 3 sources into 1 bridge ({count} unique, {sources} sources)"),
            json!({"unique": count, "sources_for_obfs4": sources}),
        )
    } else {
        InjectedTestResult::fail(
            "dedup_under_mixed_sources",
            format!("Expected 2 unique, 3 sources; got {count} unique, {sources} sources"),
            json!({"unique": count, "sources": sources}),
        )
    }
}

/// Test 9: Censorship fusion under source outage.
fn test_censorship_fusion_under_outage() -> InjectedTestResult {
    let mut scorer = CensorshipFusionScorer::new();
    scorer.set_censorship_level(4);
    scorer.set_ooni_factor("obfs4", 0.9); // obfs4 heavily blocked
    scorer.set_ooni_factor("webtunnel", 0.1); // webtunnel mostly clear

    let bridges = vec![
        json!({"transport": "obfs4", "final_score": 90.0}),
        json!({"transport": "webtunnel", "final_score": 70.0}),
    ];

    let adjusted = crate::censorship_scorer_fusion::apply_fusion_scoring(&bridges, &scorer);

    // Webtunnel should rank higher after adjustment despite lower base score
    let top_transport = adjusted[0]
        .get("transport")
        .and_then(Value::as_str)
        .unwrap_or("");

    if top_transport == "webtunnel" {
        InjectedTestResult::pass(
            "censorship_fusion_under_outage",
            "Censorship fusion correctly promotes webtunnel over blocked obfs4",
            json!({"top_transport": top_transport, "adjustments": scorer.status_json()["transport_adjustments"]}),
        )
    } else {
        InjectedTestResult::fail(
            "censorship_fusion_under_outage",
            format!("Expected webtunnel on top; got {top_transport}"),
            json!({"top_transport": top_transport}),
        )
    }
}

/// Test 10: Telemetry anomaly detection.
fn test_telemetry_anomaly_detection() -> InjectedTestResult {
    let mut agg = TelemetryAggregator::new();

    // Establish baseline: 5 runs of ~100 bridges
    for i in 0..5 {
        let mut t = YieldTelemetry::new(format!("t{i}"));
        t.record_source(SourceYieldMetrics {
            source_id: "s1".to_string(),
            bridges_fetched: 100,
            bridges_after_quality: 90,
            bridges_after_dedup: 85,
            latency_ms: 200.0,
            success: true,
            error: None,
        });
        t.set_exported(85);
        agg.analyze(&mut t);
    }

    // Inject anomaly: sudden drop to 10 bridges
    let mut anomaly_t = YieldTelemetry::new("t_anomaly");
    anomaly_t.record_source(SourceYieldMetrics {
        source_id: "s1".to_string(),
        bridges_fetched: 10,
        bridges_after_quality: 8,
        bridges_after_dedup: 5,
        latency_ms: 200.0,
        success: true,
        error: None,
    });
    anomaly_t.set_exported(5);
    agg.analyze(&mut anomaly_t);

    let has_anomaly = !anomaly_t.anomalies.is_empty();
    let has_volume_change = anomaly_t.change_reasons.iter().any(|r| {
        matches!(r, crate::yield_telemetry::YieldChangeReason::UpstreamVolumeChange { .. })
    });

    if has_anomaly && has_volume_change {
        InjectedTestResult::pass(
            "telemetry_anomaly_detection",
            format!("Anomaly detected: {:?}", anomaly_t.anomalies),
            json!({"anomalies": anomaly_t.anomalies, "rolling_avg": agg.rolling_average()}),
        )
    } else {
        InjectedTestResult::fail(
            "telemetry_anomaly_detection",
            format!("Expected anomaly; got anomalies={}, volume_change={}", anomaly_t.anomalies.len(), has_volume_change),
            json!({"anomalies": anomaly_t.anomalies}),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_injected_tests_pass() {
        let results = run_all_injected_tests();
        let failed: Vec<&InjectedTestResult> = results.iter().filter(|r| !r.passed).collect();
        assert!(
            failed.is_empty(),
            "Injected failure tests failed: {:?}",
            failed.iter().map(|r| &r.test_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_report_all_passed() {
        let report = test_report();
        assert_eq!(report["all_passed"], true);
        assert_eq!(report["failed"], 0);
    }

    #[test]
    fn corrupted_payload_does_not_crash() {
        let result = test_corrupted_payload_handling();
        assert!(result.passed, "corrupted payload test failed: {}", result.description);
    }

    #[test]
    fn timeout_does_not_crash() {
        let result = test_timeout_handling();
        assert!(result.passed, "timeout test failed: {}", result.description);
    }

    #[test]
    fn invalid_signatures_do_not_crash() {
        let result = test_invalid_bridge_signatures();
        assert!(result.passed, "invalid signatures test failed: {}", result.description);
    }

    #[test]
    fn circuit_breaker_trips_correctly() {
        let result = test_source_outage_circuit_breaker();
        assert!(result.passed, "circuit breaker test failed: {}", result.description);
    }

    #[test]
    fn circuit_breaker_recovers() {
        let result = test_circuit_breaker_trip_and_recovery();
        assert!(result.passed, "circuit breaker recovery test failed: {}", result.description);
    }

    #[test]
    fn telemetry_detects_anomalies() {
        let result = test_telemetry_anomaly_detection();
        assert!(result.passed, "telemetry anomaly test failed: {}", result.description);
    }

    #[test]
    fn dedup_handles_mixed_sources() {
        let result = test_dedup_under_mixed_sources();
        assert!(result.passed, "dedup mixed sources test failed: {}", result.description);
    }

    #[test]
    fn censorship_fusion_promotes_unblocked() {
        let result = test_censorship_fusion_under_outage();
        assert!(result.passed, "censorship fusion test failed: {}", result.description);
    }
}

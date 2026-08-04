//! Self-Describing Yield Telemetry (Phase 3 — Feature 4)
//!
//! Emits structured, contextual telemetry tracking real-time source yield
//! shifts, drop reasons, dynamic ceiling recalculations, and anomaly flags.
//!
//! Every run's `bridges_api.json` carries a `yield_telemetry` audit trail
//! explaining why the count went up or down run-over-run.
//!
//! # Design
//!
//! The [`YieldTelemetry`] struct captures a single pipeline run's metrics.
//! The [`TelemetryAggregator`] tracks run-over-run deltas and flags anomalies.

use std::collections::BTreeMap;
use serde_json::{json, Value};

/// Reason for a yield change between runs.
#[derive(Debug, Clone, PartialEq)]
pub enum YieldChangeReason {
    /// Upstream source returned more/fewer bridges.
    UpstreamVolumeChange { source: String, delta: i64 },
    /// A source was unavailable this run.
    SourceOutage { source: String },
    /// A previously failing source recovered.
    SourceRecovery { source: String },
    /// Quality gate filtered more/fewer candidates.
    QualityGateChange { previous_min: f64, current_min: f64 },
    /// Dynamic ceiling was recalculated.
    CeilingRecalculated { previous: usize, current: usize },
    /// Deduplication removed duplicates.
    DeduplicationApplied { duplicates_removed: usize },
    /// Censorship level changed, affecting scoring.
    CensorshipLevelChange { previous: i64, current: i64 },
    /// Anomalous yield detected (statistical outlier).
    AnomalyDetected { description: String },
}

impl YieldChangeReason {
    /// Convert to JSON.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::UpstreamVolumeChange { source, delta } => json!({
                "type": "upstream_volume_change",
                "source": source,
                "delta": delta,
            }),
            Self::SourceOutage { source } => json!({
                "type": "source_outage",
                "source": source,
            }),
            Self::SourceRecovery { source } => json!({
                "type": "source_recovery",
                "source": source,
            }),
            Self::QualityGateChange { previous_min, current_min } => json!({
                "type": "quality_gate_change",
                "previous_min": previous_min,
                "current_min": current_min,
            }),
            Self::CeilingRecalculated { previous, current } => json!({
                "type": "ceiling_recalculated",
                "previous": previous,
                "current": current,
            }),
            Self::DeduplicationApplied { duplicates_removed } => json!({
                "type": "deduplication_applied",
                "duplicates_removed": duplicates_removed,
            }),
            Self::CensorshipLevelChange { previous, current } => json!({
                "type": "censorship_level_change",
                "previous": previous,
                "current": current,
            }),
            Self::AnomalyDetected { description } => json!({
                "type": "anomaly_detected",
                "description": description,
            }),
        }
    }
}

/// Per-source yield metrics for a single run.
#[derive(Debug, Clone)]
pub struct SourceYieldMetrics {
    pub source_id: String,
    pub bridges_fetched: usize,
    pub bridges_after_quality: usize,
    pub bridges_after_dedup: usize,
    pub latency_ms: f64,
    pub success: bool,
    pub error: Option<String>,
}

impl SourceYieldMetrics {
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "bridges_fetched": self.bridges_fetched,
            "bridges_after_quality": self.bridges_after_quality,
            "bridges_after_dedup": self.bridges_after_dedup,
            "latency_ms": self.latency_ms,
            "success": self.success,
            "error": self.error,
        })
    }
}

/// Complete yield telemetry for a single pipeline run.
#[derive(Debug, Clone)]
pub struct YieldTelemetry {
    /// Timestamp of this run (ISO 8601).
    pub timestamp: String,
    /// Total bridges before any filtering.
    pub raw_count: usize,
    /// Bridges after quality gate filtering.
    pub quality_filtered_count: usize,
    /// Bridges after deduplication.
    pub dedup_count: usize,
    /// Final exported bridge count.
    pub exported_count: usize,
    /// Dynamic ceiling applied (None if not capped).
    pub ceiling: Option<usize>,
    /// Per-source metrics.
    pub source_metrics: Vec<SourceYieldMetrics>,
    /// Reasons for yield changes (populated by aggregator).
    pub change_reasons: Vec<YieldChangeReason>,
    /// Anomaly flags.
    pub anomalies: Vec<String>,
}

impl YieldTelemetry {
    /// Create a new empty telemetry record.
    #[must_use]
    pub fn new(timestamp: impl Into<String>) -> Self {
        Self {
            timestamp: timestamp.into(),
            raw_count: 0,
            quality_filtered_count: 0,
            dedup_count: 0,
            exported_count: 0,
            ceiling: None,
            source_metrics: Vec::new(),
            change_reasons: Vec::new(),
            anomalies: Vec::new(),
        }
    }

    /// Record raw bridge count from a source.
    pub fn record_source(&mut self, metrics: SourceYieldMetrics) {
        self.raw_count += metrics.bridges_fetched;
        self.source_metrics.push(metrics);
    }

    /// Set quality-filtered count.
    pub fn set_quality_filtered(&mut self, count: usize) {
        self.quality_filtered_count = count;
    }

    /// Set dedup count.
    pub fn set_dedup(&mut self, count: usize) {
        self.dedup_count = count;
    }

    /// Set exported count.
    pub fn set_exported(&mut self, count: usize) {
        self.exported_count = count;
    }

    /// Set dynamic ceiling.
    pub fn set_ceiling(&mut self, ceiling: usize) {
        self.ceiling = Some(ceiling);
    }

    /// Add a change reason.
    pub fn add_reason(&mut self, reason: YieldChangeReason) {
        self.change_reasons.push(reason);
    }

    /// Add an anomaly flag.
    pub fn add_anomaly(&mut self, description: impl Into<String>) {
        self.anomalies.push(description.into());
    }

    /// Convert to JSON for embedding in bridges_api.json.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "timestamp": self.timestamp,
            "raw_count": self.raw_count,
            "quality_filtered_count": self.quality_filtered_count,
            "dedup_count": self.dedup_count,
            "exported_count": self.exported_count,
            "ceiling": self.ceiling,
            "source_metrics": self.source_metrics.iter().map(|m| m.to_json()).collect::<Vec<_>>(),
            "change_reasons": self.change_reasons.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
            "anomalies": self.anomalies,
            "summary": self.summary(),
        })
    }

    /// Generate human-readable summary.
    #[must_use]
    pub fn summary(&self) -> Value {
        let successful_sources = self.source_metrics.iter().filter(|m| m.success).count();
        let failed_sources = self.source_metrics.iter().filter(|m| !m.success).count();
        let total_sources = self.source_metrics.len();
        let dedup_ratio = if self.raw_count > 0 {
            let removed = (self.raw_count - self.dedup_count) as f64;
            (removed / self.raw_count as f64 * 100.0).round() / 100.0
        } else {
            0.0
        };

        json!({
            "total_sources": total_sources,
            "successful_sources": successful_sources,
            "failed_sources": failed_sources,
            "dedup_ratio_percent": dedup_ratio,
            "quality_pass_ratio": if self.raw_count > 0 {
                (self.quality_filtered_count as f64 / self.raw_count as f64 * 100.0).round() / 100.0
            } else { 0.0 },
            "ceiling_applied": self.ceiling.is_some(),
            "anomaly_count": self.anomalies.len(),
        })
    }
}

/// Aggregator that tracks run-over-run deltas and flags anomalies.
#[derive(Debug, Clone)]
pub struct TelemetryAggregator {
    /// History of previous run counts per source.
    previous_source_counts: BTreeMap<String, usize>,
    /// History of previous total exported count.
    previous_exported: usize,
    /// Rolling average of exported counts (for anomaly detection).
    rolling_avg: f64,
    /// Number of runs tracked.
    run_count: u64,
}

impl TelemetryAggregator {
    /// Create a new aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            previous_source_counts: BTreeMap::new(),
            previous_exported: 0,
            rolling_avg: 0.0,
            run_count: 0,
        }
    }

    /// Analyze a telemetry record against previous runs, populating
    /// `change_reasons` and `anomalies`.
    pub fn analyze(&mut self, telemetry: &mut YieldTelemetry) {
        // Detect source outages and recoveries
        let mut current_sources: BTreeMap<String, usize> = BTreeMap::new();
        let mut new_reasons: Vec<YieldChangeReason> = Vec::new();
        for metrics in &telemetry.source_metrics {
            current_sources.insert(metrics.source_id.clone(), metrics.bridges_fetched);

            if !metrics.success {
                if self.previous_source_counts.contains_key(&metrics.source_id) {
                    new_reasons.push(YieldChangeReason::SourceOutage {
                        source: metrics.source_id.clone(),
                    });
                }
            } else if let Some(&prev) = self.previous_source_counts.get(&metrics.source_id) {
                if prev == 0 && metrics.bridges_fetched > 0 {
                    new_reasons.push(YieldChangeReason::SourceRecovery {
                        source: metrics.source_id.clone(),
                    });
                } else if metrics.bridges_fetched as i64 != prev as i64 {
                    let delta = metrics.bridges_fetched as i64 - prev as i64;
                    new_reasons.push(YieldChangeReason::UpstreamVolumeChange {
                        source: metrics.source_id.clone(),
                        delta,
                    });
                }
            }
        }
        for reason in new_reasons {
            telemetry.add_reason(reason);
        }

        // Detect anomalies (exported count > 2x or < 0.5x rolling average)
        if self.run_count > 2 && self.rolling_avg > 0.0 {
            let ratio = telemetry.exported_count as f64 / self.rolling_avg;
            if ratio > 2.0 {
                telemetry.add_anomaly(format!(
                    "Yield spike: {} bridges ({:.1}x rolling average of {:.0})",
                    telemetry.exported_count, ratio, self.rolling_avg
                ));
                telemetry.add_reason(YieldChangeReason::AnomalyDetected {
                    description: format!("Yield spike: {:.1}x average", ratio),
                });
            } else if ratio < 0.5 {
                telemetry.add_anomaly(format!(
                    "Yield drop: {} bridges ({:.1}x rolling average of {:.0})",
                    telemetry.exported_count, ratio, self.rolling_avg
                ));
                telemetry.add_reason(YieldChangeReason::AnomalyDetected {
                    description: format!("Yield drop: {:.1}x average", ratio),
                });
            }
        }

        // Update rolling average
        self.run_count += 1;
        let alpha = 2.0 / (self.run_count as f64 + 1.0);
        self.rolling_avg =
            alpha * telemetry.exported_count as f64 + (1.0 - alpha) * self.rolling_avg;

        // Update previous counts
        self.previous_source_counts = current_sources;
        self.previous_exported = telemetry.exported_count;
    }

    /// Get current rolling average.
    #[must_use]
    pub fn rolling_average(&self) -> f64 {
        self.rolling_avg
    }

    /// Get run count.
    #[must_use]
    pub fn run_count(&self) -> u64 {
        self.run_count
    }
}

impl Default for TelemetryAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_new_has_zero_counts() {
        let t = YieldTelemetry::new("2026-08-04T12:00:00Z");
        assert_eq!(t.raw_count, 0);
        assert_eq!(t.exported_count, 0);
        assert!(t.source_metrics.is_empty());
    }

    #[test]
    fn record_source_accumulates_raw_count() {
        let mut t = YieldTelemetry::new("2026-08-04T12:00:00Z");
        t.record_source(SourceYieldMetrics {
            source_id: "s1".to_string(),
            bridges_fetched: 50,
            bridges_after_quality: 40,
            bridges_after_dedup: 35,
            latency_ms: 200.0,
            success: true,
            error: None,
        });
        t.record_source(SourceYieldMetrics {
            source_id: "s2".to_string(),
            bridges_fetched: 30,
            bridges_after_quality: 25,
            bridges_after_dedup: 20,
            latency_ms: 300.0,
            success: true,
            error: None,
        });
        assert_eq!(t.raw_count, 80);
    }

    #[test]
    fn to_json_includes_all_fields() {
        let mut t = YieldTelemetry::new("2026-08-04T12:00:00Z");
        t.record_source(SourceYieldMetrics {
            source_id: "s1".to_string(),
            bridges_fetched: 50,
            bridges_after_quality: 40,
            bridges_after_dedup: 35,
            latency_ms: 200.0,
            success: true,
            error: None,
        });
        t.set_quality_filtered(40);
        t.set_dedup(35);
        t.set_exported(35);
        t.set_ceiling(10000);
        t.add_reason(YieldChangeReason::UpstreamVolumeChange {
            source: "s1".to_string(),
            delta: 10,
        });

        let json = t.to_json();
        assert_eq!(json["raw_count"], 50);
        assert_eq!(json["exported_count"], 35);
        assert_eq!(json["ceiling"], 10000);
        assert!(json["change_reasons"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn aggregator_detects_source_outage() {
        let mut agg = TelemetryAggregator::new();

        // First run: source available
        let mut t1 = YieldTelemetry::new("t1");
        t1.record_source(SourceYieldMetrics {
            source_id: "s1".to_string(),
            bridges_fetched: 50,
            bridges_after_quality: 40,
            bridges_after_dedup: 35,
            latency_ms: 200.0,
            success: true,
            error: None,
        });
        t1.set_exported(35);
        agg.analyze(&mut t1);

        // Second run: source fails
        let mut t2 = YieldTelemetry::new("t2");
        t2.record_source(SourceYieldMetrics {
            source_id: "s1".to_string(),
            bridges_fetched: 0,
            bridges_after_quality: 0,
            bridges_after_dedup: 0,
            latency_ms: 0.0,
            success: false,
            error: Some("timeout".to_string()),
        });
        t2.set_exported(0);
        agg.analyze(&mut t2);

        assert!(t2.change_reasons.iter().any(|r| matches!(
            r,
            YieldChangeReason::SourceOutage { source } if source == "s1"
        )));
    }

    #[test]
    fn aggregator_detects_volume_change() {
        let mut agg = TelemetryAggregator::new();

        let mut t1 = YieldTelemetry::new("t1");
        t1.record_source(SourceYieldMetrics {
            source_id: "s1".to_string(),
            bridges_fetched: 50,
            bridges_after_quality: 40,
            bridges_after_dedup: 35,
            latency_ms: 200.0,
            success: true,
            error: None,
        });
        t1.set_exported(35);
        agg.analyze(&mut t1);

        let mut t2 = YieldTelemetry::new("t2");
        t2.record_source(SourceYieldMetrics {
            source_id: "s1".to_string(),
            bridges_fetched: 80,
            bridges_after_quality: 70,
            bridges_after_dedup: 65,
            latency_ms: 200.0,
            success: true,
            error: None,
        });
        t2.set_exported(65);
        agg.analyze(&mut t2);

        assert!(t2.change_reasons.iter().any(|r| matches!(
            r,
            YieldChangeReason::UpstreamVolumeChange { source, delta }
                if source == "s1" && *delta == 30
        )));
    }

    #[test]
    fn aggregator_rolling_average() {
        let mut agg = TelemetryAggregator::new();

        for i in 0..5 {
            let mut t = YieldTelemetry::new(format!("t{i}"));
            t.set_exported(100);
            agg.analyze(&mut t);
        }

        // After 5 runs of 100, rolling avg should be ~100
        assert!((agg.rolling_average() - 100.0).abs() < 5.0);
    }

    #[test]
    fn change_reason_to_json() {
        let reason = YieldChangeReason::SourceOutage {
            source: "bridges.torproject.org".to_string(),
        };
        let json = reason.to_json();
        assert_eq!(json["type"], "source_outage");
        assert_eq!(json["source"], "bridges.torproject.org");
    }

    #[test]
    fn summary_correct() {
        let mut t = YieldTelemetry::new("t1");
        t.record_source(SourceYieldMetrics {
            source_id: "s1".to_string(),
            bridges_fetched: 100,
            bridges_after_quality: 80,
            bridges_after_dedup: 70,
            latency_ms: 200.0,
            success: true,
            error: None,
        });
        t.record_source(SourceYieldMetrics {
            source_id: "s2".to_string(),
            bridges_fetched: 0,
            bridges_after_quality: 0,
            bridges_after_dedup: 0,
            latency_ms: 0.0,
            success: false,
            error: Some("timeout".to_string()),
        });
        t.set_exported(70);

        let summary = t.summary();
        assert_eq!(summary["total_sources"], 2);
        assert_eq!(summary["successful_sources"], 1);
        assert_eq!(summary["failed_sources"], 1);
    }
}

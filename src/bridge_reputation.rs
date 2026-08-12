//! Bridge Reputation Engine (§4 of the 15-point spec).
//!
//! Maintains rolling statistics windows (1h, 24h, 7d, 30d) per bridge and
//! generates long-term reliability metrics. Recent performance is weighted
//! higher than stale observations.
//!
//! Tracks per bridge:
//!   - Success rate
//!   - Failure rate
//!   - Average latency
//!   - Bootstrap reliability (if Tor bootstrap data available)
//!   - Stability score (composite, 0-100)
//!
//! Operates on the [`crate::history::HistoryManager`] database and produces
//! complementary reputation files at `data/bridge_reputation.json`.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Map, Value};

use crate::dt_utils::{coerce_utc_dt, utc_now, DEFAULT_FALLBACK};
use crate::history::{BridgeRecord, HistoryManager};

// ─────────────────────────────────────────────────────────────────────────────
// Rolling window definitions
// ─────────────────────────────────────────────────────────────────────────────

/// The four rolling time windows for reputation analysis.
pub const WINDOWS: &[(i64, &str)] = &[
    (1, "1h"),
    (24, "24h"),
    (168, "7d"),  // 7 * 24
    (720, "30d"), // 30 * 24
];

/// Weight multiplier for recent observations vs stale ones.
/// Window weights: 1h=1.0, 24h=0.8, 7d=0.5, 30d=0.3
pub fn window_weight(hours: i64) -> f64 {
    match hours {
        1 => 1.0,
        24 => 0.8,
        168 => 0.5,
        720 => 0.3,
        _ => 0.1,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-window statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics for a single rolling window.
#[derive(Debug, Clone, Default)]
pub struct WindowStats {
    /// Number of probes attempted in this window.
    pub probes: usize,
    /// Number of successful probes.
    pub successes: usize,
    /// Number of failed probes.
    pub failures: usize,
    /// Cumulative latency (ms) for averaging.
    pub total_latency_ms: f64,
    /// Minimum latency observed (ms).
    pub min_latency_ms: Option<f64>,
    /// Maximum latency observed (ms).
    pub max_latency_ms: Option<f64>,
}

impl WindowStats {
    /// Success rate as a fraction [0, 1].
    pub fn success_rate(&self) -> f64 {
        if self.probes == 0 {
            return 0.0;
        }
        self.successes as f64 / self.probes as f64
    }

    /// Average latency in milliseconds.
    pub fn avg_latency_ms(&self) -> Option<f64> {
        if self.successes == 0 {
            return None;
        }
        Some(self.total_latency_ms / self.successes as f64)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "probes": self.probes,
            "successes": self.successes,
            "failures": self.failures,
            "success_rate": (self.success_rate() * 1000.0).round() / 10.0,
            "avg_latency_ms": self.avg_latency_ms().map(|v| (v * 100.0).round() / 100.0),
            "min_latency_ms": self.min_latency_ms.map(|v| (v * 100.0).round() / 100.0),
            "max_latency_ms": self.max_latency_ms.map(|v| (v * 100.0).round() / 100.0),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge reputation (composite, multi-window)
// ─────────────────────────────────────────────────────────────────────────────

/// Full reputation snapshot for one bridge.
#[derive(Debug, Clone, Default)]
pub struct BridgeReputation {
    /// The normalized bridge line key.
    pub bridge_key: String,
    /// Transport type.
    pub transport: String,
    /// First seen timestamp.
    pub first_seen: Option<String>,
    /// Last seen timestamp.
    pub last_seen: Option<String>,
    /// Per-window statistics, keyed by window label ("1h", "24h", "7d", "30d").
    pub windows: BTreeMap<String, WindowStats>,
    /// Composite stability score (0–100).
    pub stability_score: f64,
    /// Weighted success rate (recent windows weighted higher).
    pub weighted_success_rate: f64,
    /// Average latency across all successes.
    pub overall_avg_latency_ms: Option<f64>,
    /// Total probes across all windows.
    pub total_probes: usize,
}

impl BridgeReputation {
    /// Compute the stability score from the window data.
    ///
    /// `now` is the reference clock (injected so tests are deterministic;
    /// production callers pass `ReputationEngine.now`).
    ///
    /// Formula:
    ///   stability = weighted_success_rate * 60
    ///             + (1.0 - normalized_latency_variance) * 20
    ///             + freshness_bonus * 10
    ///             + probe_count_bonus * 10
    ///
    /// Normalized to [0, 100].
    ///
    /// A bridge with zero probe evidence gets stability 0.0 — no
    /// observations means no confidence, not a neutral positive score.
    pub fn compute_stability(&mut self, now: DateTime<Utc>) {
        if self.total_probes == 0 {
            self.weighted_success_rate = 0.0;
            self.overall_avg_latency_ms = None;
            self.stability_score = 0.0;
            return;
        }

        let mut weighted = 0.0;
        let mut total_weight = 0.0;
        let mut all_latencies: Vec<f64> = Vec::new();

        for &(hours, label) in WINDOWS {
            let w = window_weight(hours);
            if let Some(ws) = self.windows.get(label) {
                weighted += ws.success_rate() * w;
                total_weight += w;
                // Collect latencies for variance computation
                // (approximate: use average per window)
                if let Some(avg) = ws.avg_latency_ms() {
                    // Weight by number of data points
                    for _ in 0..ws.successes {
                        all_latencies.push(avg);
                    }
                }
            }
        }

        self.weighted_success_rate = if total_weight > 0.0 {
            weighted / total_weight
        } else {
            0.0
        };

        // Latency variance penalty (if we have data)
        let latency_bonus = if all_latencies.len() >= 2 {
            let mean = all_latencies.iter().sum::<f64>() / all_latencies.len() as f64;
            let variance = all_latencies
                .iter()
                .map(|l| (l - mean).powi(2))
                .sum::<f64>()
                / all_latencies.len() as f64;
            let normalized_variance = (variance / (mean * mean).max(1.0)).min(1.0);
            (1.0 - normalized_variance) * 20.0
        } else {
            10.0 // neutral — not enough data for variance analysis
        };

        self.overall_avg_latency_ms = if all_latencies.is_empty() {
            None
        } else {
            Some(all_latencies.iter().sum::<f64>() / all_latencies.len() as f64)
        };

        // Freshness bonus: bridges seen in the last 24h get a bonus.
        // Uses the injected `now` so behaviour is deterministic in tests.
        let freshness_bonus = if let Some(ref last) = self.last_seen {
            let dt = coerce_utc_dt(Some(last), DEFAULT_FALLBACK);
            let age_hours = (now - dt).num_seconds() as f64 / 3600.0;
            if age_hours <= 24.0 {
                10.0
            } else if age_hours <= 168.0 {
                5.0
            } else {
                0.0
            }
        } else {
            0.0
        };

        // Probe count bonus — more data = more reliable assessment
        let probe_bonus = if self.total_probes >= 50 {
            10.0
        } else if self.total_probes >= 10 {
            5.0
        } else if self.total_probes >= 3 {
            2.0
        } else {
            0.0
        };

        self.stability_score =
            (self.weighted_success_rate * 60.0 + latency_bonus + freshness_bonus + probe_bonus)
                .clamp(0.0, 100.0);
    }

    pub fn to_json(&self) -> Value {
        let windows_json: Map<String, Value> = self
            .windows
            .iter()
            .map(|(k, v)| (k.clone(), v.to_json()))
            .collect();
        json!({
            "bridge_key": self.bridge_key,
            "transport": self.transport,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "windows": Value::Object(windows_json),
            "stability_score": (self.stability_score * 100.0).round() / 100.0,
            "weighted_success_rate": (self.weighted_success_rate * 1000.0).round() / 1000.0,
            "overall_avg_latency_ms": self.overall_avg_latency_ms.map(|v| (v * 100.0).round() / 100.0),
            "total_probes": self.total_probes,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reputation engine
// ─────────────────────────────────────────────────────────────────────────────

/// The reputation engine computes rolling statistics for all bridges in the
/// history database and generates per-bridge [`BridgeReputation`] snapshots.
pub struct ReputationEngine {
    now: DateTime<Utc>,
}

impl ReputationEngine {
    /// Construct with a specific clock (injectable for testing).
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { now }
    }

    /// Production constructor — uses `chrono::Utc::now()`.
    pub fn with_defaults() -> Self {
        Self::new(utc_now())
    }

    /// Compute reputation for a single bridge record over all time windows.
    ///
    /// `probe_history` is a list of (timestamp, success, latency_ms) tuples
    /// for each probe attempt against this bridge. The engine buckets these
    /// into the four rolling windows relative to `self.now`.
    pub fn compute_reputation(
        &self,
        record: &BridgeRecord,
        probe_history: &[(DateTime<Utc>, bool, Option<f64>)],
    ) -> BridgeReputation {
        let mut rep = BridgeReputation {
            bridge_key: HistoryManager::normalize_key(&record.raw),
            transport: record.transport.clone(),
            first_seen: Some(record.first_seen.clone()),
            last_seen: Some(record.last_seen.clone()),
            ..Default::default()
        };

        for &(hours, label) in WINDOWS {
            let cutoff = self.now - Duration::hours(hours);
            let window_probes: Vec<&(DateTime<Utc>, bool, Option<f64>)> = probe_history
                .iter()
                .filter(|(ts, _, _)| *ts >= cutoff)
                .collect();

            let mut ws = WindowStats {
                probes: window_probes.len(),
                ..Default::default()
            };
            for (_, success, latency) in window_probes {
                if *success {
                    ws.successes += 1;
                    if let Some(lat) = latency {
                        ws.total_latency_ms += lat;
                        ws.min_latency_ms =
                            Some(ws.min_latency_ms.map(|m| m.min(*lat)).unwrap_or(*lat));
                        ws.max_latency_ms =
                            Some(ws.max_latency_ms.map(|m| m.max(*lat)).unwrap_or(*lat));
                    }
                } else {
                    ws.failures += 1;
                }
            }
            rep.total_probes += ws.probes;
            rep.windows.insert(label.to_string(), ws);
        }

        rep.compute_stability(self.now);
        rep
    }

    /// Build reputation from a simple test_pass and latency (for when we
    /// only have the current `BridgeRecord` and no detailed history).
    /// This is a minimal fallback that puts the current test result into
    /// the 1h window.
    pub fn compute_from_record(&self, record: &BridgeRecord) -> BridgeReputation {
        // Build a minimal probe history from the record's test fields.
        let mut history: Vec<(DateTime<Utc>, bool, Option<f64>)> = Vec::new();
        if let Some(ref test_time) = record.test_time {
            if let Some(passed) = record.test_pass {
                let dt = coerce_utc_dt(Some(test_time), DEFAULT_FALLBACK);
                history.push((dt, passed, record.latency_ms.map(|l| l as f64)));
            }
        }
        // Note: last_seen alone carries no probe result, so it is not
        // added as a probe event (only test_time/test_pass do). It is
        // available on the record for freshness calculations downstream.
        self.compute_reputation(record, &history)
    }

    /// Compute reputations for all bridges in a history manager.
    /// Returns a map of bridge_key → BridgeReputation.
    pub fn compute_all(&self, history: &HistoryManager) -> BTreeMap<String, BridgeReputation> {
        let mut results = BTreeMap::new();
        for (key, record) in history.get_all() {
            let rep = self.compute_from_record(&record);
            results.insert(key, rep);
        }
        results
    }

    /// Generate a summary JSON report for the entire bridge pool.
    pub fn summary_report(reputations: &BTreeMap<String, BridgeReputation>) -> Value {
        if reputations.is_empty() {
            return json!({
                "generated_at": utc_now().to_rfc3339(),
                "total_bridges": 0,
                "message": "no reputation data available",
            });
        }

        let total = reputations.len();
        let mut stability_sum = 0.0;
        let mut by_transport: BTreeMap<String, (usize, f64)> = BTreeMap::new();
        let mut top_stable: Vec<&BridgeReputation> = reputations.values().collect();

        for rep in reputations.values() {
            stability_sum += rep.stability_score;
            let entry = by_transport
                .entry(rep.transport.clone())
                .or_insert((0, 0.0));
            entry.0 += 1;
            entry.1 += rep.stability_score;
        }

        // Sort by stability descending, take top 25
        top_stable.sort_by(|a, b| {
            b.stability_score
                .partial_cmp(&a.stability_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let top_25: Vec<Value> = top_stable.iter().take(25).map(|r| r.to_json()).collect();

        let transport_summary: Map<String, Value> = by_transport
            .iter()
            .map(|(t, (count, sum))| {
                (
                    t.clone(),
                    json!({
                        "count": count,
                        "avg_stability": (sum / *count as f64 * 100.0).round() / 100.0,
                    }),
                )
            })
            .collect();

        json!({
            "generated_at": utc_now().to_rfc3339(),
            "total_bridges": total,
            "avg_stability": (stability_sum / total as f64 * 100.0).round() / 100.0,
            "by_transport": Value::Object(transport_summary),
            "top_25_by_stability": top_25,
        })
    }

    /// Write reputation data to `data/bridge_reputation.json`.
    pub fn export(
        reputations: &BTreeMap<String, BridgeReputation>,
        output_path: &Path,
    ) -> Result<(), std::io::Error> {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let summary = Self::summary_report(reputations);
        let text = serde_json::to_string_pretty(&summary).map_err(std::io::Error::other)?;
        std::fs::write(output_path, text)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-28T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn window_weight_decreases_with_age() {
        assert_eq!(window_weight(1), 1.0);
        assert_eq!(window_weight(24), 0.8);
        assert_eq!(window_weight(168), 0.5);
        assert_eq!(window_weight(720), 0.3);
        assert_eq!(window_weight(999), 0.1);
    }

    #[test]
    fn empty_probe_history_yields_zero_stability() {
        let engine = ReputationEngine::new(fixed_now());
        let record = BridgeRecord {
            raw: "obfs4 1.2.3.4:443".to_string(),
            transport: "obfs4".to_string(),
            first_seen: "2026-06-27T12:00:00+00:00".to_string(),
            last_seen: "2026-06-28T12:00:00+00:00".to_string(),
            test_pass: None,
            test_time: None,
            latency_ms: None,
            score: 0,
        };
        let rep = engine.compute_reputation(&record, &[]);
        assert_eq!(rep.total_probes, 0);
        assert!(rep.stability_score < 1.0);
        assert_eq!(rep.weighted_success_rate, 0.0);
    }

    #[test]
    fn perfect_probe_history_yields_high_stability() {
        let engine = ReputationEngine::new(fixed_now());
        let record = BridgeRecord {
            raw: "obfs4 1.2.3.4:443".to_string(),
            transport: "obfs4".to_string(),
            first_seen: "2026-06-27T12:00:00+00:00".to_string(),
            last_seen: "2026-06-28T12:00:00+00:00".to_string(),
            test_pass: Some(true),
            test_time: Some("2026-06-28T12:00:00+00:00".to_string()),
            latency_ms: Some(50),
            score: 80,
        };
        // Recent successful probes with low latency
        let now = fixed_now();
        let history: Vec<_> = (0..20)
            .map(|i| {
                (
                    now - Duration::minutes(i * 15),
                    true,
                    Some(50.0 + (i as f64)),
                )
            })
            .collect();
        let rep = engine.compute_reputation(&record, &history);
        assert!(rep.total_probes > 0);
        assert!(rep.stability_score > 50.0);
        assert!((rep.weighted_success_rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn mixed_probe_history_reduces_stability() {
        let engine = ReputationEngine::new(fixed_now());
        let record = BridgeRecord {
            raw: "obfs4 1.2.3.4:443".to_string(),
            transport: "obfs4".to_string(),
            first_seen: "2026-06-27T12:00:00+00:00".to_string(),
            last_seen: "2026-06-28T12:00:00+00:00".to_string(),
            test_pass: None,
            test_time: None,
            latency_ms: None,
            score: 0,
        };
        let now = fixed_now();
        let history: Vec<_> = vec![
            (now - Duration::minutes(30), true, Some(100.0)),
            (now - Duration::minutes(25), false, None),
            (now - Duration::minutes(20), true, Some(120.0)),
            (now - Duration::minutes(15), false, None),
            (now - Duration::minutes(10), true, Some(90.0)),
        ];
        let rep = engine.compute_reputation(&record, &history);
        assert!((rep.weighted_success_rate - 0.6).abs() < 0.01);
        assert!(rep.stability_score > 20.0);
        assert!(rep.stability_score < 80.0);
    }

    #[test]
    fn compute_from_record_uses_test_fields() {
        let engine = ReputationEngine::new(fixed_now());
        let record = BridgeRecord {
            raw: "obfs4 1.2.3.4:443".to_string(),
            transport: "obfs4".to_string(),
            first_seen: "2026-06-27T12:00:00+00:00".to_string(),
            last_seen: "2026-06-28T12:00:00+00:00".to_string(),
            test_pass: Some(true),
            test_time: Some("2026-06-28T11:00:00+00:00".to_string()),
            latency_ms: Some(42),
            score: 75,
        };
        let rep = engine.compute_from_record(&record);
        assert_eq!(rep.transport, "obfs4");
        // Single probe in the 1h window (within 1 hour of now=12:00)
        if let Some(ws) = rep.windows.get("1h") {
            assert_eq!(ws.probes, 1);
            assert_eq!(ws.successes, 1);
        }
    }

    #[test]
    fn summary_report_with_no_data_shows_message() {
        let report = ReputationEngine::summary_report(&BTreeMap::new());
        assert_eq!(report["total_bridges"], 0);
        assert!(report["message"]
            .as_str()
            .unwrap()
            .contains("no reputation data"));
    }

    #[test]
    fn summary_report_computes_averages() {
        let mut reps = BTreeMap::new();
        for i in 0..5 {
            let mut rep = BridgeReputation {
                bridge_key: format!("bridge_{i}"),
                transport: "obfs4".to_string(),
                total_probes: 10,
                ..Default::default()
            };
            rep.stability_score = 50.0 + (i as f64) * 10.0;
            reps.insert(format!("key_{i}"), rep);
        }
        let report = ReputationEngine::summary_report(&reps);
        assert_eq!(report["total_bridges"], 5);
        // avg = (50+60+70+80+90)/5 = 70
        let avg = report["avg_stability"].as_f64().unwrap();
        assert!((avg - 70.0).abs() < 1.0);
    }
}

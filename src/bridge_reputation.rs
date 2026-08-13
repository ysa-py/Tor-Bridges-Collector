//! Bridge Reputation Engine (§4 of the 15-point spec).
//!
//! Maintains rolling statistics windows (1h, 6h, 24h, 7d, 30d, 90d) per bridge and
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

/// The six rolling time windows for reputation analysis.
pub const WINDOWS: &[(i64, &str)] = &[
    (1, "1h"),
    (6, "6h"),
    (24, "24h"),
    (168, "7d"),   // 7 * 24
    (720, "30d"),  // 30 * 24
    (2160, "90d"), // 90 * 24
];

/// Weight multiplier for recent observations vs stale ones.
/// Window weights: 1h=1.0, 6h=0.9, 24h=0.8, 7d=0.5, 30d=0.3, 90d=0.2
pub fn window_weight(hours: i64) -> f64 {
    match hours {
        1 => 1.0,
        6 => 0.9,
        24 => 0.8,
        168 => 0.5,
        720 => 0.3,
        2160 => 0.2,
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
    /// Per-window statistics, keyed by window label ("1h", "6h", "24h", "7d", "30d", "90d").
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
    /// into the six rolling windows relative to `self.now`.
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
    ///
    /// This is the live producer path: each bridge's stored multi-probe log
    /// (via [`HistoryManager::probe_history`]) is fed into the six-window
    /// aggregation, replacing the previous single-record synthesis. Bridges
    /// with no stored probe history fall back to [`Self::compute_from_record`]
    /// so single-record-only data (and records persisted before the
    /// multi-probe feature) still yields a reputation instead of an empty one.
    pub fn compute_all(&self, history: &HistoryManager) -> BTreeMap<String, BridgeReputation> {
        let mut results = BTreeMap::new();
        for (key, record) in history.get_all() {
            let probes = history.probe_history(&record.raw);
            let rep = if probes.is_empty() {
                self.compute_from_record(&record)
            } else {
                let probe_history: Vec<(DateTime<Utc>, bool, Option<f64>)> = probes
                    .iter()
                    .map(|p| {
                        (
                            coerce_utc_dt(Some(&p.timestamp), DEFAULT_FALLBACK),
                            p.passed,
                            p.latency_ms.map(|l| l as f64),
                        )
                    })
                    .collect();
                self.compute_reputation(&record, &probe_history)
            };
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
    use std::collections::VecDeque;

    fn fixed_now() -> DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-28T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn temp_manager(now: DateTime<Utc>) -> HistoryManager {
        let dir = std::env::temp_dir().join(format!("rep_hist_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            now,
        )
        .unwrap()
    }

    #[test]
    fn window_weight_decreases_with_age() {
        assert_eq!(window_weight(1), 1.0);
        assert_eq!(window_weight(6), 0.9);
        assert_eq!(window_weight(24), 0.8);
        assert_eq!(window_weight(168), 0.5);
        assert_eq!(window_weight(720), 0.3);
        assert_eq!(window_weight(2160), 0.2);
        assert_eq!(window_weight(999), 0.1);
    }

    #[test]
    fn six_hour_and_ninety_day_windows_bucket_by_age() {
        let now = fixed_now();
        let engine = ReputationEngine::new(now);
        let record = BridgeRecord {
            raw: "obfs4 1.2.3.4:443".to_string(),
            transport: "obfs4".to_string(),
            first_seen: "2026-03-20T12:00:00+00:00".to_string(),
            last_seen: "2026-06-28T12:00:00+00:00".to_string(),
            test_pass: Some(true),
            test_time: Some("2026-06-28T12:00:00+00:00".to_string()),
            latency_ms: Some(50),
            score: 80,
            probes: VecDeque::new(),
        };
        // Fixture: three probes at known ages relative to `now`:
        //   - 30 minutes old -> inside 1h, 6h, 24h, 7d, 30d, 90d
        //   - 5 hours old    -> inside 6h, 24h, 7d, 30d, 90d (NOT 1h)
        //   - 40 days old    -> inside 90d only (NOT 30d or shorter)
        let history: Vec<(DateTime<Utc>, bool, Option<f64>)> = vec![
            (now - Duration::minutes(30), true, Some(50.0)),
            (now - Duration::hours(5), true, Some(60.0)),
            (now - Duration::days(40), false, None),
        ];
        let rep = engine.compute_reputation(&record, &history);

        // Known expected bucket counts per window.
        let expected: &[(&str, usize)] = &[
            ("1h", 1),
            ("6h", 2),
            ("24h", 2),
            ("7d", 2),
            ("30d", 2),
            ("90d", 3),
        ];
        for &(label, probes) in expected {
            let ws = rep.windows.get(label).unwrap();
            assert_eq!(ws.probes, probes, "window {label} probe count");
        }
        // Only the 90d window sees the failed 40-day probe.
        assert_eq!(rep.windows.get("90d").unwrap().failures, 1);
        assert_eq!(rep.windows.get("90d").unwrap().successes, 2);
        assert_eq!(rep.windows.get("6h").unwrap().failures, 0);
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
            probes: VecDeque::new(),
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
            probes: VecDeque::new(),
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
            probes: VecDeque::new(),
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
            probes: VecDeque::new(),
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

    #[test]
    fn exact_fixture_yields_known_window_stats_and_stability() {
        let now = fixed_now();
        let engine = ReputationEngine::new(now);
        let record = BridgeRecord {
            raw: "obfs4 9.9.9.9:443".to_string(),
            transport: "obfs4".to_string(),
            first_seen: "2026-06-27T12:00:00+00:00".to_string(),
            last_seen: "2026-06-28T11:30:00+00:00".to_string(), // 30 min before now
            test_pass: Some(true),
            test_time: Some("2026-06-28T11:30:00+00:00".to_string()),
            latency_ms: Some(200),
            score: 80,
            probes: VecDeque::new(),
        };

        // Fixture: 6 probes all within the last 30 minutes, so every rolling
        // window sees the identical set: 4 successes @ 200.0 ms, 2 failures.
        let history: Vec<(DateTime<Utc>, bool, Option<f64>)> = vec![
            (now - Duration::minutes(5), true, Some(200.0)),
            (now - Duration::minutes(10), true, Some(200.0)),
            (now - Duration::minutes(15), true, Some(200.0)),
            (now - Duration::minutes(20), true, Some(200.0)),
            (now - Duration::minutes(25), false, None),
            (now - Duration::minutes(30), false, None),
        ];
        let rep = engine.compute_reputation(&record, &history);

        // Every window sees all 6 probes: 4 success, 2 failure, flat 200.0 ms.
        for &(label, probes, successes, failures) in &[
            ("1h", 6, 4, 2),
            ("6h", 6, 4, 2),
            ("24h", 6, 4, 2),
            ("7d", 6, 4, 2),
            ("30d", 6, 4, 2),
            ("90d", 6, 4, 2),
        ] {
            let ws = rep.windows.get(label).expect("window present");
            assert_eq!(ws.probes, probes, "{label} probe count");
            assert_eq!(ws.successes, successes, "{label} successes");
            assert_eq!(ws.failures, failures, "{label} failures");
            assert_eq!(ws.min_latency_ms, Some(200.0), "{label} min latency");
            assert_eq!(ws.max_latency_ms, Some(200.0), "{label} max latency");
            assert_eq!(ws.avg_latency_ms(), Some(200.0), "{label} avg latency");
        }

        // Composite stability for this fixture, by hand:
        //   success rate 2/3 in every window -> weighted rate 2/3
        //   flat latency -> variance 0 -> latency bonus 20.0
        //   last_seen 30 min old (<= 24h) -> freshness bonus 10.0
        //   36 total probes (>= 10) -> probe bonus 5.0
        //   stability = (2/3)*60 + 20 + 10 + 5 = 75.0
        assert_eq!(rep.total_probes, 36);
        assert!((rep.weighted_success_rate - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(rep.overall_avg_latency_ms, Some(200.0));
        assert!((rep.stability_score - 75.0).abs() < 1e-9);

        // JSON surface pins the rounded rendering of the same values.
        let json = rep.to_json();
        assert_eq!(json["total_probes"], 36);
        assert_eq!(json["stability_score"], 75.0);
        let one_h = &json["windows"]["1h"];
        assert_eq!(one_h["probes"], 6);
        assert_eq!(one_h["successes"], 4);
        assert_eq!(one_h["success_rate"], 66.7);
        assert_eq!(one_h["avg_latency_ms"], 200.0);
        assert_eq!(one_h["min_latency_ms"], 200.0);
        assert_eq!(one_h["max_latency_ms"], 200.0);
    }

    #[test]
    fn compute_all_aggregates_stored_probe_history_per_window() {
        let now = fixed_now();
        let mut mgr = temp_manager(now);
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        // Stored multi-probe history across ages, matching the known bucket
        // fixture: 30m (pass 50ms), 5h (pass 60ms), 40d (fail).
        mgr.record_probe_at(
            "obfs4 1.2.3.4:443",
            now - Duration::minutes(30),
            true,
            Some(50),
        );
        mgr.record_probe_at(
            "obfs4 1.2.3.4:443",
            now - Duration::hours(5),
            true,
            Some(60),
        );
        mgr.record_probe_at("obfs4 1.2.3.4:443", now - Duration::days(40), false, None);

        let engine = ReputationEngine::new(now);
        let reps = engine.compute_all(&mgr);
        let rep = reps
            .get("obfs4 1.2.3.4:443")
            .expect("bridge has reputation");
        // Real per-window aggregation from the STORED log. Single-record
        // synthesis would put exactly one probe in the 1h window only.
        let expected: &[(&str, usize)] = &[
            ("1h", 1),
            ("6h", 2),
            ("24h", 2),
            ("7d", 2),
            ("30d", 2),
            ("90d", 3),
        ];
        for &(label, probes) in expected {
            let ws = rep.windows.get(label).unwrap();
            assert_eq!(ws.probes, probes, "window {label} probe count");
        }
        assert_eq!(rep.windows.get("90d").unwrap().failures, 1);
        assert_eq!(rep.windows.get("6h").unwrap().failures, 0);
        assert_eq!(rep.total_probes, 12); // 1+2+2+2+2+3
    }

    #[test]
    fn compute_all_exact_fixture_via_stored_history() {
        let now = fixed_now();
        let mut mgr = temp_manager(now);
        mgr.add_bridge("obfs4 9.9.9.9:443", "obfs4");
        // 6 probes all within the last 30 minutes: 4 successes @ 200ms, 2 fails.
        let probes: &[(i64, bool, Option<i64>)] = &[
            (5, true, Some(200)),
            (10, true, Some(200)),
            (15, true, Some(200)),
            (20, true, Some(200)),
            (25, false, None),
            (30, false, None),
        ];
        for &(mins, passed, lat) in probes {
            mgr.record_probe_at(
                "obfs4 9.9.9.9:443",
                now - Duration::minutes(mins),
                passed,
                lat,
            );
        }
        let engine = ReputationEngine::new(now);
        let reps = engine.compute_all(&mgr);
        let rep = reps
            .get("obfs4 9.9.9.9:443")
            .expect("bridge has reputation");
        // Identical hand-derived values to the direct-tuple fixture: every
        // window sees 6 probes (4 ok / 2 fail), stability 75.0.
        for &(label, probes, successes, failures) in &[
            ("1h", 6, 4, 2),
            ("6h", 6, 4, 2),
            ("24h", 6, 4, 2),
            ("7d", 6, 4, 2),
            ("30d", 6, 4, 2),
            ("90d", 6, 4, 2),
        ] {
            let ws = rep.windows.get(label).expect("window present");
            assert_eq!(ws.probes, probes, "{label} probe count");
            assert_eq!(ws.successes, successes, "{label} successes");
            assert_eq!(ws.failures, failures, "{label} failures");
            assert_eq!(ws.min_latency_ms, Some(200.0), "{label} min latency");
            assert_eq!(ws.max_latency_ms, Some(200.0), "{label} max latency");
        }
        assert_eq!(rep.total_probes, 36);
        assert!((rep.stability_score - 75.0).abs() < 1e-9);
    }

    #[test]
    fn compute_all_falls_back_to_single_record_without_probe_history() {
        let now = fixed_now();
        // Simulate a legacy on-disk record (no probes) via a JSON file so the
        // manager loads it exactly as pre-feature data would.
        let dir = std::env::temp_dir().join(format!("rep_legacy_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("hist.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "obfs4 1.2.3.4:443": {
                    "raw": "obfs4 1.2.3.4:443",
                    "transport": "obfs4",
                    "first_seen": "2026-06-27T12:00:00+00:00",
                    "last_seen": "2026-06-28T11:00:00+00:00",
                    "test_pass": true,
                    "test_time": "2026-06-28T11:00:00+00:00",
                    "latency_ms": 42,
                    "score": 75,
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let mgr =
            HistoryManager::new(&path, &dir.join("bridge"), &dir.join("export"), now).unwrap();
        let engine = ReputationEngine::new(now);
        let reps = engine.compute_all(&mgr);
        let rep = reps
            .get("obfs4 1.2.3.4:443")
            .expect("legacy bridge gets a reputation");
        // Fallback synthesis: the single test_time probe (exactly 1h old) is
        // within all six windows, so each window counts 1 probe/success and
        // `total_probes` — the sum across windows — is 6, not 1.
        assert_eq!(rep.windows.get("1h").unwrap().probes, 1);
        assert_eq!(rep.windows.get("1h").unwrap().successes, 1);
        assert_eq!(rep.total_probes, 6);
        assert!(rep.stability_score > 0.0);
    }
}

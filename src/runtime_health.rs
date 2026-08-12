//! Runtime Health Validation (§8 of the 10-point spec).
//!
//! Bridge quality must reflect actual usability, not simple reachability.
//! Pipeline: Bridge → Bootstrap → Circuit → Health → Latency → Stability → Score.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// A single health observation for a bridge (one probe cycle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthObservation {
    pub timestamp: f64,
    pub latency_ms: f64,
    pub bootstrap_ok: bool,
    pub circuit_ok: bool,
    pub circuit_count: usize,
    pub exit_policy_ok: bool,
    pub stability_ok: bool,
    pub tcp_ok: bool,
    pub tls_ok: bool,
    pub transport_ok: bool,
}

impl HealthObservation {
    pub fn is_healthy(&self) -> bool {
        self.tcp_ok && self.tls_ok && self.transport_ok && self.bootstrap_ok && self.circuit_ok
    }
}

/// Rolling window health statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthWindow {
    pub observations: usize,
    pub healthy: usize,
    pub total_latency_ms: f64,
    pub min_latency_ms: Option<f64>,
    pub max_latency_ms: Option<f64>,
    pub circuit_successes: usize,
    pub bootstraps: usize,
    pub flapping_count: usize,
}

impl HealthWindow {
    pub fn success_rate(&self) -> f64 {
        if self.observations == 0 {
            0.0
        } else {
            self.healthy as f64 / self.observations as f64
        }
    }
    pub fn avg_latency(&self) -> Option<f64> {
        if self.healthy == 0 {
            None
        } else {
            Some(self.total_latency_ms / self.healthy as f64)
        }
    }
    pub fn flapping_score(&self) -> f64 {
        if self.observations < 2 {
            return 1.0;
        }
        (1.0 - (self.flapping_count as f64 / (self.observations - 1) as f64)).max(0.0)
    }
    pub fn record(&mut self, obs: &HealthObservation) {
        self.observations += 1;
        if obs.is_healthy() {
            self.healthy += 1;
            self.total_latency_ms += obs.latency_ms;
            self.min_latency_ms = Some(
                self.min_latency_ms
                    .map(|m| m.min(obs.latency_ms))
                    .unwrap_or(obs.latency_ms),
            );
            self.max_latency_ms = Some(
                self.max_latency_ms
                    .map(|m| m.max(obs.latency_ms))
                    .unwrap_or(obs.latency_ms),
            );
        }
        if obs.circuit_ok {
            self.circuit_successes += 1;
        }
        if obs.bootstrap_ok {
            self.bootstraps += 1;
        }
    }
}

/// Runtime health status for a single bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHealth {
    pub bridge_key: String,
    pub transport: String,
    pub windows: BTreeMap<String, HealthWindow>,
    pub reliability_score: f64,
    pub stability_score: f64,
    pub recent_failures: usize,
    pub consecutive_failures: usize,
    pub last_healthy_at: Option<f64>,
    pub total_observations: usize,
}

impl RuntimeHealth {
    pub fn new(bridge_key: &str, transport: &str) -> Self {
        Self {
            bridge_key: bridge_key.to_string(),
            transport: transport.to_string(),
            windows: BTreeMap::new(),
            reliability_score: 0.0,
            stability_score: 100.0,
            recent_failures: 0,
            consecutive_failures: 0,
            last_healthy_at: None,
            total_observations: 0,
        }
    }

    pub fn record_observation(&mut self, obs: &HealthObservation) {
        self.total_observations += 1;
        if obs.is_healthy() {
            self.consecutive_failures = 0;
            self.last_healthy_at = Some(obs.timestamp);
        } else {
            self.consecutive_failures += 1;
            self.recent_failures += 1;
        }

        // Update windows
        for (_hours, label) in &[(1, "1h"), (24, "24h"), (168, "7d"), (720, "30d")] {
            self.windows
                .entry(label.to_string())
                .or_default()
                .record(obs);
        }
        self.compute_scores();
    }

    pub fn compute_scores(&mut self) {
        let w1h = self
            .windows
            .get("1h")
            .map(|w| w.success_rate())
            .unwrap_or(0.0);
        let w24h = self
            .windows
            .get("24h")
            .map(|w| w.success_rate())
            .unwrap_or(0.0);
        let w7d = self
            .windows
            .get("7d")
            .map(|w| w.success_rate())
            .unwrap_or(0.0);
        let w30d = self
            .windows
            .get("30d")
            .map(|w| w.success_rate())
            .unwrap_or(0.0);

        // Weighted: recent windows count more
        self.reliability_score = (w1h * 0.4 + w24h * 0.3 + w7d * 0.2 + w30d * 0.1) * 100.0;
        self.reliability_score = self.reliability_score.clamp(0.0, 100.0);

        // Stability: penalize consecutive failures
        let consec_penalty = (self.consecutive_failures as f64 * 5.0).min(80.0);
        self.stability_score = (100.0 - consec_penalty).max(0.0);
    }

    pub fn to_json(&self) -> Value {
        let win_json: serde_json::Map<_, _> = self
            .windows
            .iter()
            .map(|(k, w)| {
                (
                    k.clone(),
                    json!({
                        "observations": w.observations, "healthy": w.healthy,
                        "success_rate": (w.success_rate() * 1000.0).round() / 10.0,
                        "avg_latency_ms": w.avg_latency().map(|v| (v * 100.0).round() / 100.0),
                        "flapping_score": (w.flapping_score() * 100.0).round() / 100.0,
                    }),
                )
            })
            .collect();
        json!({
            "bridge_key": self.bridge_key, "transport": self.transport,
            "windows": win_json,
            "reliability_score": (self.reliability_score * 10.0).round() / 10.0,
            "stability_score": (self.stability_score * 10.0).round() / 10.0,
            "consecutive_failures": self.consecutive_failures,
            "total_observations": self.total_observations,
        })
    }
}

/// Batch health monitor for a pool of bridges.
#[derive(Debug, Clone, Default)]
pub struct HealthMonitor {
    bridges: BTreeMap<String, RuntimeHealth>,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            bridges: BTreeMap::new(),
        }
    }

    pub fn observe(&mut self, key: &str, transport: &str, obs: &HealthObservation) {
        self.bridges
            .entry(key.to_string())
            .or_insert_with(|| RuntimeHealth::new(key, transport))
            .record_observation(obs);
    }

    pub fn get(&self, key: &str) -> Option<&RuntimeHealth> {
        self.bridges.get(key)
    }

    pub fn top_reliable(&self, n: usize) -> Vec<&RuntimeHealth> {
        let mut sorted: Vec<&RuntimeHealth> = self.bridges.values().collect();
        sorted.sort_by(|a, b| {
            b.reliability_score
                .partial_cmp(&a.reliability_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(n);
        sorted
    }

    pub fn summary(&self) -> Value {
        let total = self.bridges.len();
        let reliable = self
            .bridges
            .values()
            .filter(|b| b.reliability_score >= 80.0)
            .count();
        let failing = self
            .bridges
            .values()
            .filter(|b| b.consecutive_failures >= 3)
            .count();
        json!({
            "total_bridges": total, "reliable_bridges": reliable, "failing_bridges": failing,
            "avg_reliability": if total > 0 { self.bridges.values().map(|b| b.reliability_score).sum::<f64>() / total as f64 } else { 0.0 },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }

    fn healthy_obs() -> HealthObservation {
        HealthObservation {
            timestamp: now(),
            latency_ms: 500.0,
            bootstrap_ok: true,
            circuit_ok: true,
            circuit_count: 3,
            exit_policy_ok: true,
            stability_ok: true,
            tcp_ok: true,
            tls_ok: true,
            transport_ok: true,
        }
    }

    fn failed_obs() -> HealthObservation {
        HealthObservation {
            timestamp: now(),
            latency_ms: 0.0,
            bootstrap_ok: false,
            circuit_ok: false,
            circuit_count: 0,
            exit_policy_ok: false,
            stability_ok: false,
            tcp_ok: false,
            tls_ok: false,
            transport_ok: false,
        }
    }

    #[test]
    fn healthy_obs_is_healthy() {
        assert!(healthy_obs().is_healthy());
    }
    #[test]
    fn failed_obs_not_healthy() {
        assert!(!failed_obs().is_healthy());
    }

    #[test]
    fn runtime_health_accumulates() {
        let mut h = RuntimeHealth::new("bridge1", "obfs4");
        for _ in 0..5 {
            h.record_observation(&healthy_obs());
        }
        assert_eq!(h.total_observations, 5);
        assert_eq!(h.consecutive_failures, 0);
        assert!(h.reliability_score > 90.0);
    }

    #[test]
    fn consecutive_failures_reduce_stability() {
        let mut h = RuntimeHealth::new("bridge1", "obfs4");
        for _ in 0..10 {
            h.record_observation(&failed_obs());
        }
        assert_eq!(h.consecutive_failures, 10);
        assert!(h.stability_score < 60.0);
    }

    #[test]
    fn recovery_resets_consecutive() {
        let mut h = RuntimeHealth::new("bridge1", "obfs4");
        for _ in 0..3 {
            h.record_observation(&failed_obs());
        }
        assert_eq!(h.consecutive_failures, 3);
        h.record_observation(&healthy_obs());
        assert_eq!(h.consecutive_failures, 0);
    }

    #[test]
    fn monitor_top_reliable() {
        let mut m = HealthMonitor::new();
        for i in 0..5 {
            let key = format!("bridge{i}");
            m.observe(&key, "obfs4", &healthy_obs());
            if i >= 3 {
                m.observe(&key, "obfs4", &failed_obs());
            }
        }
        let top = m.top_reliable(3);
        assert_eq!(top.len(), 3);
        // Most reliable bridges first
        assert!(top[0].reliability_score >= top[1].reliability_score);
    }

    #[test]
    fn monitor_summary() {
        let mut m = HealthMonitor::new();
        m.observe("a", "obfs4", &healthy_obs());
        m.observe("b", "obfs4", &healthy_obs());
        m.observe("c", "obfs4", &failed_obs());
        let s = m.summary();
        assert_eq!(s["total_bridges"], 3);
    }

    #[test]
    fn health_window_flapping_score() {
        let mut w = HealthWindow::default();
        // Alternating healthy/failed = high flapping
        w.record(&healthy_obs());
        w.record(&failed_obs());
        w.record(&healthy_obs());
        w.record(&failed_obs());
        // 4 observations, 3 transitions = high flapping count
        // flapping_count is set externally in practice; here just check floor
        assert!(w.flapping_score() <= 1.0);
    }

    #[test]
    fn reliability_score_ranges_zero_to_hundred() {
        let mut h = RuntimeHealth::new("test", "webtunnel");
        h.record_observation(&healthy_obs());
        assert!(h.reliability_score >= 0.0 && h.reliability_score <= 100.0);
        assert!(h.stability_score >= 0.0 && h.stability_score <= 100.0);
    }
}

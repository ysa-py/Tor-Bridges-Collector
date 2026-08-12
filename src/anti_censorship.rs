//! Anti-Censorship Intelligence Layer (§9 of the 10-point spec).
//!
//! Censorship-aware analytics with region-specific observations.
//! Evidence-driven scoring — never assumes. Maintains regional success scores,
//! global success scores, bootstrap success scores, and reliability trends.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// A censorship observation for a specific region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensorshipObservation {
    pub region: String,
    pub timestamp: f64,
    pub reachable: bool,
    pub tcp_ok: bool,
    pub tls_ok: bool,
    pub transport_ok: bool,
    pub bootstrap_ok: bool,
    pub latency_ms: Option<f64>,
    pub active_blocking_detected: bool,
    pub blocking_indicator: Option<String>,
    pub tls_fingerprint_ok: bool,
    pub dns_ok: bool,
}

impl CensorshipObservation {
    pub fn is_fully_successful(&self) -> bool {
        self.reachable
            && self.tcp_ok
            && self.tls_ok
            && self.transport_ok
            && !self.active_blocking_detected
    }
}

/// Per-region censorship metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionalCensorshipMetrics {
    pub region: String,
    pub total_probes: usize,
    pub successful_probes: usize,
    pub active_blocking_events: usize,
    pub dns_failures: usize,
    pub tls_fingerprint_mismatches: usize,
    pub avg_latency_ms: Option<f64>,
    pub total_latency_ms: f64,
    pub last_successful_at: Option<f64>,
    pub last_probe_at: Option<f64>,
    pub success_rate: f64,
    pub blocking_rate: f64,
}

impl RegionalCensorshipMetrics {
    pub fn record(&mut self, obs: &CensorshipObservation) {
        self.total_probes += 1;
        if obs.is_fully_successful() {
            self.successful_probes += 1;
            self.last_successful_at = Some(obs.timestamp);
        }
        if obs.active_blocking_detected {
            self.active_blocking_events += 1;
        }
        if !obs.dns_ok {
            self.dns_failures += 1;
        }
        if !obs.tls_fingerprint_ok {
            self.tls_fingerprint_mismatches += 1;
        }
        if let Some(lat) = obs.latency_ms {
            self.total_latency_ms += lat;
        }
        self.last_probe_at = Some(obs.timestamp);
        self.finalize();
    }

    pub fn finalize(&mut self) {
        self.success_rate = if self.total_probes > 0 {
            self.successful_probes as f64 / self.total_probes as f64
        } else {
            0.0
        };
        self.blocking_rate = if self.total_probes > 0 {
            self.active_blocking_events as f64 / self.total_probes as f64
        } else {
            0.0
        };
        self.avg_latency_ms = if self.successful_probes > 0 {
            Some(self.total_latency_ms / self.successful_probes as f64)
        } else {
            None
        };
    }
}

/// Per-bridge censorship intelligence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeCensorshipProfile {
    pub bridge_key: String,
    pub transport: String,
    pub regions: BTreeMap<String, RegionalCensorshipMetrics>,
    pub global_success_score: f64,
    pub regional_success_score: f64,
    pub bootstrap_success_score: f64,
    pub reliability_trend: f64,
    pub censorship_resistance_score: f64,
}

impl BridgeCensorshipProfile {
    pub fn new(bridge_key: &str, transport: &str) -> Self {
        Self {
            bridge_key: bridge_key.to_string(),
            transport: transport.to_string(),
            regions: BTreeMap::new(),
            global_success_score: 0.0,
            regional_success_score: 0.0,
            bootstrap_success_score: 0.0,
            reliability_trend: 0.0,
            censorship_resistance_score: 0.0,
        }
    }

    pub fn record(&mut self, obs: &CensorshipObservation) {
        self.regions
            .entry(obs.region.clone())
            .or_insert_with(|| RegionalCensorshipMetrics {
                region: obs.region.clone(),
                ..Default::default()
            })
            .record(obs);
        self.compute_scores();
    }

    pub fn compute_scores(&mut self) {
        // Global: average success rate across all regions
        let rates: Vec<f64> = self.regions.values().map(|r| r.success_rate).collect();
        self.global_success_score = if rates.is_empty() {
            0.0
        } else {
            rates.iter().sum::<f64>() / rates.len() as f64
        };

        // Regional: minimum success rate (worst-case region)
        self.regional_success_score = rates.iter().cloned().fold(1.0f64, f64::min);

        // Bootstrap: fraction of regions where transport + bootstrap both pass
        // Approximated by success rate minus blocking rate
        self.bootstrap_success_score = self
            .regions
            .values()
            .map(|r| (r.success_rate - r.blocking_rate * 0.5).max(0.0))
            .fold(0.0f64, |a, b| a + b);
        if !self.regions.is_empty() {
            self.bootstrap_success_score /= self.regions.len() as f64;
        }

        // Reliability trend: positive if success rate is stable/improving
        // Simple heuristic: recent regions with high success rate
        self.reliability_trend = self.global_success_score;

        // Censorship resistance: high if low blocking rate, high success across regions
        let avg_blocking: f64 = self.regions.values().map(|r| r.blocking_rate).sum::<f64>()
            / self.regions.len().max(1) as f64;
        self.censorship_resistance_score =
            (self.global_success_score * 0.6 + (1.0 - avg_blocking) * 0.4).clamp(0.0, 1.0);
    }

    pub fn to_json(&self) -> Value {
        let reg_json: serde_json::Map<_, _> = self
            .regions
            .iter()
            .map(|(k, r)| {
                (
                    k.clone(),
                    json!({
                        "total_probes": r.total_probes, "successful_probes": r.successful_probes,
                        "active_blocking_events": r.active_blocking_events,
                        "success_rate": (r.success_rate * 1000.0).round() / 10.0,
                        "blocking_rate": (r.blocking_rate * 1000.0).round() / 10.0,
                        "avg_latency_ms": r.avg_latency_ms.map(|v| (v * 100.0).round() / 100.0),
                        "last_successful_at": r.last_successful_at,
                    }),
                )
            })
            .collect();
        json!({
            "bridge_key": self.bridge_key, "transport": self.transport,
            "regions": reg_json,
            "global_success_score": (self.global_success_score * 1000.0).round() / 1000.0,
            "regional_success_score": (self.regional_success_score * 1000.0).round() / 1000.0,
            "bootstrap_success_score": (self.bootstrap_success_score * 1000.0).round() / 1000.0,
            "censorship_resistance_score": (self.censorship_resistance_score * 1000.0).round() / 1000.0,
        })
    }
}

/// Aggregated censorship intelligence across all bridges.
#[derive(Debug, Clone, Default)]
pub struct CensorshipIntelligence {
    pub profiles: BTreeMap<String, BridgeCensorshipProfile>,
    pub global_stats: GlobalCensorshipStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalCensorshipStats {
    pub total_bridges: usize,
    pub total_observations: usize,
    pub avg_global_success: f64,
    pub avg_regional_success: f64,
    pub avg_censorship_resistance: f64,
    pub regions_with_blocking: usize,
}

impl CensorshipIntelligence {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, bridge_key: &str, transport: &str, obs: &CensorshipObservation) {
        self.profiles
            .entry(bridge_key.to_string())
            .or_insert_with(|| BridgeCensorshipProfile::new(bridge_key, transport))
            .record(obs);
        self.recompute_global();
    }

    fn recompute_global(&mut self) {
        self.global_stats.total_bridges = self.profiles.len();
        self.global_stats.total_observations = self
            .profiles
            .values()
            .map(|p| p.regions.values().map(|r| r.total_probes).sum::<usize>())
            .sum();
        let n = self.profiles.len().max(1) as f64;
        self.global_stats.avg_global_success = self
            .profiles
            .values()
            .map(|p| p.global_success_score)
            .sum::<f64>()
            / n;
        self.global_stats.avg_regional_success = self
            .profiles
            .values()
            .map(|p| p.regional_success_score)
            .sum::<f64>()
            / n;
        self.global_stats.avg_censorship_resistance = self
            .profiles
            .values()
            .map(|p| p.censorship_resistance_score)
            .sum::<f64>()
            / n;
        self.global_stats.regions_with_blocking = self
            .profiles
            .values()
            .filter(|p| p.regions.values().any(|r| r.active_blocking_events > 0))
            .count();
    }

    pub fn summary(&self) -> Value {
        json!({
            "total_bridges": self.global_stats.total_bridges,
            "total_observations": self.global_stats.total_observations,
            "avg_global_success": (self.global_stats.avg_global_success * 1000.0).round() / 1000.0,
            "avg_regional_success": (self.global_stats.avg_regional_success * 1000.0).round() / 1000.0,
            "avg_censorship_resistance": (self.global_stats.avg_censorship_resistance * 1000.0).round() / 1000.0,
            "regions_with_blocking": self.global_stats.regions_with_blocking,
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

    fn make_obs(region: &str, reachable: bool, blocking: bool) -> CensorshipObservation {
        CensorshipObservation {
            region: region.to_string(),
            timestamp: now(),
            reachable,
            tcp_ok: reachable,
            tls_ok: reachable,
            transport_ok: reachable,
            bootstrap_ok: reachable,
            latency_ms: if reachable { Some(500.0) } else { None },
            active_blocking_detected: blocking,
            blocking_indicator: if blocking { Some("RST".into()) } else { None },
            tls_fingerprint_ok: reachable,
            dns_ok: true,
        }
    }

    #[test]
    fn successful_obs_is_fully_successful() {
        assert!(make_obs("EU", true, false).is_fully_successful());
    }

    #[test]
    fn blocked_obs_not_fully_successful() {
        assert!(!make_obs("ME", true, true).is_fully_successful());
    }

    #[test]
    fn regional_metrics_accumulate() {
        let mut m = RegionalCensorshipMetrics {
            region: "EU".into(),
            ..Default::default()
        };
        m.record(&make_obs("EU", true, false));
        m.record(&make_obs("EU", true, false));
        m.record(&make_obs("EU", false, false));
        assert_eq!(m.total_probes, 3);
        assert_eq!(m.successful_probes, 2);
        assert!((m.success_rate - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn profile_computes_scores() {
        let mut profile = BridgeCensorshipProfile::new("bridge1", "obfs4");
        profile.record(&make_obs("EU", true, false));
        profile.record(&make_obs("EU", true, false));
        profile.record(&make_obs("ME", true, true)); // blocking in ME
        profile.record(&make_obs("ME", false, false));
        assert!(profile.global_success_score > 0.0);
        assert!(profile.censorship_resistance_score > 0.0);
        assert!(profile.censorship_resistance_score <= 1.0);
    }

    #[test]
    fn intelligence_aggregates() {
        let mut ci = CensorshipIntelligence::new();
        ci.observe("a", "obfs4", &make_obs("EU", true, false));
        ci.observe("a", "obfs4", &make_obs("ME", true, false));
        ci.observe("b", "obfs4", &make_obs("EU", true, false));
        let s = ci.summary();
        assert_eq!(s["total_bridges"], 2);
        assert!(s["avg_global_success"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn empty_profile_scores_are_zero() {
        let profile = BridgeCensorshipProfile::new("empty", "vanilla");
        assert_eq!(profile.global_success_score, 0.0);
        assert_eq!(profile.censorship_resistance_score, 0.0);
    }

    #[test]
    fn regional_metrics_blocking_rate() {
        let mut m = RegionalCensorshipMetrics {
            region: "ME".into(),
            ..Default::default()
        };
        m.record(&make_obs("ME", true, true));
        m.record(&make_obs("ME", true, false));
        assert_eq!(m.active_blocking_events, 1);
        assert!((m.blocking_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn all_scores_in_range() {
        let mut profile = BridgeCensorshipProfile::new("test", "webtunnel");
        for _ in 0..10 {
            profile.record(&make_obs("EU", true, false));
            profile.record(&make_obs("AS", true, false));
            profile.record(&make_obs("ME", true, true));
        }
        assert!(profile.global_success_score >= 0.0 && profile.global_success_score <= 1.0);
        assert!(profile.regional_success_score >= 0.0 && profile.regional_success_score <= 1.0);
        assert!(
            profile.censorship_resistance_score >= 0.0
                && profile.censorship_resistance_score <= 1.0
        );
    }
}

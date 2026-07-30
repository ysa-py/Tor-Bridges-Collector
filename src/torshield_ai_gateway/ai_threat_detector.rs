// Parity port of `torshield_ai_gateway/ai_threat_detector.py` — the
// network-free statistical DPI threat-level detector.
//
// The scoring in `assess_threat_level` is pure arithmetic over the sliding
// window of observations, so it is reproduced with exact float semantics. The
// only non-deterministic Python inputs are wall-clock timestamps
// (`time.time()`), which affect solely the stored `timestamp` and the
// `last_assessment_age_s` field of `get_assessment` — neither participates in
// the threat computation. Those are therefore excluded from differential
// comparison and documented in `MIGRATION_NOTES.md`.

use std::collections::{BTreeMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// AI-inferred DPI threat level based on provider response patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    /// The Python `Enum` value string.
    pub fn value(&self) -> &'static str {
        match self {
            ThreatLevel::None => "none",
            ThreatLevel::Low => "low",
            ThreatLevel::Medium => "medium",
            ThreatLevel::High => "high",
            ThreatLevel::Critical => "critical",
        }
    }
}

/// Signature weights, matching `IRAN_DPI_SIGNATURES[...]["weight"]`.
pub const WEIGHT_ASYMMETRIC_FAILURES: f64 = 0.4;
pub const WEIGHT_LATENCY_SPIKE: f64 = 0.25;
pub const WEIGHT_SELECTIVE_TIMEOUT: f64 = 0.25;
pub const WEIGHT_DNS_FAILURE: f64 = 0.1;

/// Single observation of a provider's response behavior.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderObservation {
    pub provider: String,
    pub timestamp: f64,
    pub latency_ms: f64,
    pub success: bool,
    pub http_status: Option<i64>,
    pub error_type: Option<String>,
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Statistical DPI threat detector (no external network calls).
#[derive(Debug, Clone)]
pub struct AIThreatDetector {
    window_size: usize,
    observations: VecDeque<ProviderObservation>,
    baseline_latency: BTreeMap<String, f64>,
    threat_level: ThreatLevel,
    confidence: f64,
    last_assessment: f64,
}

impl Default for AIThreatDetector {
    fn default() -> Self {
        Self::new(20)
    }
}

impl AIThreatDetector {
    /// Mirrors `AIThreatDetector(window_size=20)`.
    #[must_use]
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            observations: VecDeque::new(),
            baseline_latency: BTreeMap::new(),
            threat_level: ThreatLevel::None,
            confidence: 0.0,
            last_assessment: 0.0,
        }
    }

    /// Record a provider response observation for threat analysis.
    pub fn record(
        &mut self,
        provider: &str,
        latency_ms: f64,
        success: bool,
        http_status: Option<i64>,
        error_type: Option<&str>,
    ) {
        let obs = ProviderObservation {
            provider: provider.to_string(),
            timestamp: now_secs(),
            latency_ms,
            success,
            http_status,
            error_type: error_type.map(str::to_string),
        };
        self.observations.push_back(obs);
        // deque(maxlen=window_size): drop oldest once capacity is exceeded.
        while self.window_size > 0 && self.observations.len() > self.window_size {
            self.observations.pop_front();
        }

        if success && latency_ms > 0.0 {
            let current = *self.baseline_latency.get(provider).unwrap_or(&latency_ms);
            self.baseline_latency
                .insert(provider.to_string(), current * 0.8 + latency_ms * 0.2);
        }

        if self.observations.len() >= 3 {
            self.assess_threat_level();
        }
    }

    /// Statistical inference of DPI threat level from observations.
    pub fn assess_threat_level(&mut self) {
        if self.observations.is_empty() {
            return;
        }
        let obs: Vec<&ProviderObservation> = self.observations.iter().collect();
        let mut score = 0.0_f64;

        // Signal 1: Asymmetric failures (CF works, non-CF fails).
        let cf_obs: Vec<&&ProviderObservation> = obs
            .iter()
            .filter(|o| o.provider.contains("cloudflare"))
            .collect();
        let non_cf_obs: Vec<&&ProviderObservation> = obs
            .iter()
            .filter(|o| o.provider == "cerebras" || o.provider == "portkey")
            .collect();

        if !cf_obs.is_empty() && !non_cf_obs.is_empty() {
            let cf_success_rate =
                cf_obs.iter().filter(|o| o.success).count() as f64 / cf_obs.len() as f64;
            let non_cf_success_rate =
                non_cf_obs.iter().filter(|o| o.success).count() as f64 / non_cf_obs.len() as f64;
            let asymmetry = cf_success_rate - non_cf_success_rate;
            if asymmetry > 0.5 {
                score += WEIGHT_ASYMMETRIC_FAILURES * asymmetry * 2.0;
            }
        }

        // Signal 2: Latency spikes.
        let mut latency_spikes = 0_usize;
        for o in &obs {
            let baseline = *self.baseline_latency.get(&o.provider).unwrap_or(&1000.0);
            if baseline > 0.0 && o.latency_ms > baseline * 3.0 {
                latency_spikes += 1;
            }
        }
        if !obs.is_empty() {
            let spike_rate = latency_spikes as f64 / obs.len() as f64;
            score += WEIGHT_LATENCY_SPIKE * spike_rate;
        }

        // Signal 3: Selective timeouts on Iran-blocked providers.
        let timeout_obs = obs.iter().filter(|o| {
            o.error_type
                .as_ref()
                .is_some_and(|e| e.to_lowercase().contains("timeout"))
                && (o.provider == "cerebras" || o.provider == "portkey")
        });
        let timeout_count = timeout_obs.count();
        if !non_cf_obs.is_empty() {
            let timeout_rate = timeout_count as f64 / (non_cf_obs.len().max(1)) as f64;
            if timeout_rate > 0.3 {
                score += WEIGHT_SELECTIVE_TIMEOUT * timeout_rate;
            }
        }

        // Signal 4: DNS failures.
        let dns_failures = obs
            .iter()
            .filter(|o| {
                o.error_type
                    .as_ref()
                    .is_some_and(|e| e.to_lowercase().contains("dns"))
            })
            .count();
        if !obs.is_empty() {
            let dns_rate = dns_failures as f64 / obs.len() as f64;
            score += WEIGHT_DNS_FAILURE * dns_rate;
        }

        // Map score to threat level.
        self.confidence = score.min(1.0);
        self.threat_level = if score < 0.15 {
            ThreatLevel::None
        } else if score < 0.30 {
            ThreatLevel::Low
        } else if score < 0.50 {
            ThreatLevel::Medium
        } else if score < 0.75 {
            ThreatLevel::High
        } else {
            ThreatLevel::Critical
        };

        self.last_assessment = now_secs();
    }

    /// Current inferred DPI threat level.
    pub fn threat_level(&self) -> ThreatLevel {
        self.threat_level
    }

    /// Confidence score (0.0-1.0) of the current threat assessment (unrounded).
    pub fn confidence(&self) -> f64 {
        self.confidence
    }

    /// Number of observations currently in the window.
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Per-provider baseline latencies (EMA).
    pub fn baseline_latencies(&self) -> &BTreeMap<String, f64> {
        &self.baseline_latency
    }

    /// Age in seconds since the last assessment (0.0 if never assessed here).
    pub fn last_assessment_age_s(&self) -> f64 {
        if self.last_assessment == 0.0 {
            now_secs()
        } else {
            now_secs() - self.last_assessment
        }
    }
}

/// Round to 3 decimals with Python `round()`-compatible half-to-even behaviour.
///
/// Implemented without `f64::round_ties_even` (stable only since Rust 1.77) to
/// respect the crate's pinned MSRV of 1.75. Inputs here are non-negative
/// (confidence, elapsed seconds), so a `floor`-based tie-to-even suffices.
fn round3(x: f64) -> f64 {
    let scaled = x * 1000.0;
    let floor = scaled.floor();
    let diff = scaled - floor;
    // Round up on >0.5, or on an exact tie when the floor is odd (ties-to-even).
    let round_up = diff > 0.5 || (diff == 0.5 && (floor as i64) % 2 != 0);
    let rounded = if round_up { floor + 1.0 } else { floor };
    rounded / 1000.0
}

impl AIThreatDetector {
    /// Comprehensive assessment map for logging/monitoring. Mirrors
    /// `get_assessment()`. The `last_assessment_age_s` value is time-dependent.
    pub fn get_assessment(&self) -> serde_json::Value {
        serde_json::json!({
            "threat_level": self.threat_level.value(),
            "confidence": round3(self.confidence),
            "observation_count": self.observations.len(),
            "baseline_latencies": self.baseline_latency,
            "last_assessment_age_s": round3(self.last_assessment_age_s()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_none_and_needs_three_obs() {
        let mut d = AIThreatDetector::new(20);
        d.record("cloudflare-1", 100.0, true, Some(200), None);
        d.record("cerebras", 100.0, true, Some(200), None);
        assert_eq!(d.threat_level(), ThreatLevel::None);
        assert_eq!(d.observation_count(), 2);
    }

    #[test]
    fn asymmetric_failures_raise_threat() {
        let mut d = AIThreatDetector::new(20);
        d.record("cloudflare-1", 100.0, true, Some(200), None);
        d.record("cloudflare-2", 100.0, true, Some(200), None);
        d.record("cerebras", 100.0, false, None, Some("timeout"));
        d.record("portkey", 100.0, false, None, Some("timeout"));
        assert!(d.confidence() > 0.0);
        assert_ne!(d.threat_level(), ThreatLevel::None);
    }

    #[test]
    fn window_size_caps_observations() {
        let mut d = AIThreatDetector::new(3);
        for _ in 0..10 {
            d.record("cloudflare-1", 100.0, true, Some(200), None);
        }
        assert_eq!(d.observation_count(), 3);
    }
}

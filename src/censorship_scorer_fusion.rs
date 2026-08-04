//! OONI + Censorship Monitor Fusion Scoring (Phase 3 — Feature 2)
//!
//! Integrates live OONI telemetry and censorship monitor metrics into
//! `smart_iran_scorer` and pipeline scoring algorithms. Normalizes and
//! fuses external blocking signals into bridge quality weights.
//!
//! # Design
//!
//! The [`CensorshipFusionScorer`] takes:
//! - OONI measurement data (from `ooni_correlator.rs`)
//! - Censorship state (from `censorship_monitor.rs`)
//! - Bridge scores (from `smart_iran_scorer.rs`)
//!
//! And produces adjusted scores that favor bridges most likely to survive
//! current Iranian network conditions.

use std::collections::BTreeMap;
use serde_json::{json, Map, Value};

/// Weights for fusing different censorship signals into bridge scores.
#[derive(Debug, Clone)]
pub struct FusionWeights {
    /// Weight for OONI blocking factor (0.0–1.0).
    pub ooni_weight: f64,
    /// Weight for censorship level (0.0–1.0).
    pub censorship_weight: f64,
    /// Weight for transport-specific survival rate (0.0–1.0).
    pub transport_survival_weight: f64,
    /// Weight for historical reliability (0.0–1.0).
    pub reliability_weight: f64,
}

impl Default for FusionWeights {
    fn default() -> Self {
        Self {
            ooni_weight: 0.30,
            censorship_weight: 0.25,
            transport_survival_weight: 0.25,
            reliability_weight: 0.20,
        }
    }
}

/// Censorship fusion scorer that adjusts bridge scores based on
/// real-time censorship conditions.
#[derive(Debug, Clone)]
pub struct CensorshipFusionScorer {
    weights: FusionWeights,
    /// Current censorship level (1–5, from censorship_monitor).
    censorship_level: i64,
    /// OONI blocking factors per transport type.
    ooni_factors: BTreeMap<String, f64>,
    /// Transport survival rates (from historical data).
    transport_survival: BTreeMap<String, f64>,
}

impl CensorshipFusionScorer {
    /// Create a new scorer with default weights.
    #[must_use]
    pub fn new() -> Self {
        Self {
            weights: FusionWeights::default(),
            censorship_level: 1,
            ooni_factors: BTreeMap::new(),
            transport_survival: default_transport_survival(),
        }
    }

    /// Create with custom weights.
    #[must_use]
    pub fn with_weights(weights: FusionWeights) -> Self {
        Self {
            weights,
            censorship_level: 1,
            ooni_factors: BTreeMap::new(),
            transport_survival: default_transport_survival(),
        }
    }

    /// Set current censorship level (1–5).
    pub fn set_censorship_level(&mut self, level: i64) {
        self.censorship_level = level.clamp(1, 5);
    }

    /// Set OONI blocking factor for a transport type.
    /// Factor is 0.0 (not blocked) to 1.0 (fully blocked).
    pub fn set_ooni_factor(&mut self, transport: &str, factor: f64) {
        self.ooni_factors.insert(transport.to_string(), factor.clamp(0.0, 1.0));
    }

    /// Set transport survival rate (0.0–1.0).
    pub fn set_transport_survival(&mut self, transport: &str, rate: f64) {
        self.transport_survival.insert(transport.to_string(), rate.clamp(0.0, 1.0));
    }

    /// Compute censorship adjustment factor for a transport type.
    /// Returns a multiplier (0.0–2.0) where:
    /// - 0.0 = transport is fully blocked, avoid
    /// - 1.0 = neutral
    /// - 2.0 = transport is highly effective under current conditions
    #[must_use]
    pub fn transport_adjustment(&self, transport: &str) -> f64 {
        // OONI component: lower blocking = better
        let ooni_factor = self.ooni_factors.get(transport).copied().unwrap_or(0.5);
        let ooni_score = 1.0 - ooni_factor; // Invert: 0 blocked → 1.0 score

        // Censorship component: higher level = favor stealthier transports
        let censorship_score = self.censorship_transport_score(transport);

        // Survival component: historical reliability
        let survival_score = self.transport_survival.get(transport).copied().unwrap_or(0.5);

        // Reliability component: base reliability (simplified)
        let reliability_score = 0.7;

        // Weighted fusion
        let fused = self.weights.ooni_weight * ooni_score
            + self.weights.censorship_weight * censorship_score
            + self.weights.transport_survival_weight * survival_score
            + self.weights.reliability_weight * reliability_score;

        // Scale to 0.0–2.0 range (1.0 = neutral)
        fused * 2.0
    }

    /// Adjust a bridge score based on censorship conditions.
    /// Returns the adjusted score.
    #[must_use]
    pub fn adjust_score(&self, base_score: f64, transport: &str) -> f64 {
        let adjustment = self.transport_adjustment(transport);
        (base_score * adjustment).max(0.0)
    }

    /// Adjust a BridgeScore record (from smart_iran_scorer).
    #[must_use]
    pub fn adjust_bridge_score(&self, score_json: &Value) -> Value {
        let mut adjusted = score_json.clone();
        let transport = score_json
            .get("transport")
            .and_then(Value::as_str)
            .unwrap_or("vanilla");
        let base_score = score_json
            .get("final_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);

        let adjusted_score = self.adjust_score(base_score, transport);
        let adjustment = self.transport_adjustment(transport);

        if let Some(obj) = adjusted.as_object_mut() {
            obj.insert("final_score".to_string(), json!(adjusted_score));
            obj.insert("censorship_adjustment".to_string(), json!(adjustment));
            obj.insert(
                "censorship_level".to_string(),
                json!(self.censorship_level),
            );
            obj.insert(
                "ooni_factor".to_string(),
                json!(self.ooni_factors.get(transport).copied().unwrap_or(0.0)),
            );
        }

        adjusted
    }

    /// Compute censorship-specific score for a transport.
    /// Higher censorship levels favor stealthier transports.
    fn censorship_transport_score(&self, transport: &str) -> f64 {
        match (self.censorship_level, transport) {
            // Level 1 (low): all transports work
            (1, _) => 0.8,
            // Level 2 (moderate): obfs4 and webtunnel preferred
            (2, "obfs4") => 0.9,
            (2, "webtunnel") => 0.95,
            (2, "snowflake") => 0.85,
            (2, "vanilla") => 0.4,
            // Level 3 (high): webtunnel and snowflake best
            (3, "webtunnel") => 0.95,
            (3, "snowflake") => 0.9,
            (3, "obfs4") => 0.7,
            (3, "conjure") => 0.85,
            (3, "vanilla") => 0.2,
            // Level 4 (severe): only stealthiest work
            (4, "webtunnel") => 0.95,
            (4, "snowflake") => 0.9,
            (4, "conjure") => 0.9,
            (4, "meek") => 0.85,
            (4, "obfs4") => 0.5,
            (4, "vanilla") => 0.1,
            // Level 5 (total blackout): experimental only
            (5, "snowflake") => 0.85,
            (5, "conjure") => 0.9,
            (5, "meek") => 0.8,
            (5, "webtunnel") => 0.7,
            (5, _) => 0.1,
            _ => 0.5,
        }
    }

    /// Get full status as JSON.
    #[must_use]
    pub fn status_json(&self) -> Value {
        let transports = ["obfs4", "webtunnel", "snowflake", "conjure", "meek", "vanilla"];
        let adjustments: BTreeMap<String, f64> = transports
            .iter()
            .map(|t| (t.to_string(), (self.transport_adjustment(t) * 1000.0).round() / 1000.0))
            .collect();

        json!({
            "censorship_level": self.censorship_level,
            "ooni_factors": self.ooni_factors,
            "transport_survival": self.transport_survival,
            "transport_adjustments": adjustments,
            "weights": {
                "ooni": self.weights.ooni_weight,
                "censorship": self.weights.censorship_weight,
                "transport_survival": self.weights.transport_survival_weight,
                "reliability": self.weights.reliability_weight,
            },
        })
    }
}

impl Default for CensorshipFusionScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Default transport survival rates based on historical data.
fn default_transport_survival() -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    m.insert("obfs4".to_string(), 0.75);
    m.insert("webtunnel".to_string(), 0.90);
    m.insert("snowflake".to_string(), 0.80);
    m.insert("conjure".to_string(), 0.85);
    m.insert("meek".to_string(), 0.70);
    m.insert("vanilla".to_string(), 0.30);
    m
}

/// Apply censorship fusion scoring to a list of bridge score records.
/// Returns adjusted records with censorship metadata.
#[must_use]
pub fn apply_fusion_scoring(
    bridge_scores: &[Value],
    scorer: &CensorshipFusionScorer,
) -> Vec<Value> {
    let mut adjusted: Vec<Value> = bridge_scores
        .iter()
        .map(|s| scorer.adjust_bridge_score(s))
        .collect();

    // Re-sort by adjusted score (descending)
    adjusted.sort_by(|a, b| {
        let sa = a.get("final_score").and_then(Value::as_f64).unwrap_or(0.0);
        let sb = b.get("final_score").and_then(Value::as_f64).unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    adjusted
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scorer_neutral_adjustment() {
        let scorer = CensorshipFusionScorer::new();
        // Default censorship level 1, no OONI data → adjustment ~1.0
        let adj = scorer.transport_adjustment("obfs4");
        assert!(adj > 0.5 && adj < 2.0, "expected ~1.0, got {adj}");
    }

    #[test]
    fn high_censorship_favors_stealth() {
        let mut scorer = CensorshipFusionScorer::new();
        scorer.set_censorship_level(4);
        let webtunnel = scorer.transport_adjustment("webtunnel");
        let vanilla = scorer.transport_adjustment("vanilla");
        assert!(
            webtunnel > vanilla,
            "webtunnel ({webtunnel}) should beat vanilla ({vanilla}) at level 4"
        );
    }

    #[test]
    fn ooni_blocking_reduces_adjustment() {
        let mut scorer = CensorshipFusionScorer::new();
        scorer.set_ooni_factor("obfs4", 0.9); // 90% blocked
        let adj = scorer.transport_adjustment("obfs4");
        assert!(adj < 1.0, "expected <1.0 for 90% blocked, got {adj}");
    }

    #[test]
    fn ooni_no_blocking_increases_adjustment() {
        let mut scorer = CensorshipFusionScorer::new();
        scorer.set_ooni_factor("webtunnel", 0.0); // Not blocked
        let adj = scorer.transport_adjustment("webtunnel");
        assert!(adj > 1.0, "expected >1.0 for 0% blocked, got {adj}");
    }

    #[test]
    fn adjust_score_applies_multiplier() {
        let scorer = CensorshipFusionScorer::new();
        let adjusted = scorer.adjust_score(50.0, "webtunnel");
        assert!(adjusted > 0.0, "adjusted score should be positive");
    }

    #[test]
    fn adjust_bridge_score_adds_metadata() {
        let scorer = CensorshipFusionScorer::new();
        let bridge = json!({
            "transport": "webtunnel",
            "final_score": 80.0,
            "raw": "webtunnel 1.2.3.4:443",
        });
        let adjusted = scorer.adjust_bridge_score(&bridge);
        assert!(adjusted.get("censorship_adjustment").is_some());
        assert!(adjusted.get("censorship_level").is_some());
    }

    #[test]
    fn apply_fusion_scoring_sorts_by_adjusted() {
        let mut scorer = CensorshipFusionScorer::new();
        scorer.set_censorship_level(4);
        scorer.set_ooni_factor("vanilla", 0.95);

        let bridges = vec![
            json!({"transport": "vanilla", "final_score": 90.0}),
            json!({"transport": "webtunnel", "final_score": 80.0}),
        ];

        let adjusted = apply_fusion_scoring(&bridges, &scorer);
        // Webtunnel should rank higher after adjustment
        let t0 = adjusted[0].get("transport").and_then(Value::as_str).unwrap();
        assert_eq!(t0, "webtunnel");
    }

    #[test]
    fn status_json_includes_all_fields() {
        let mut scorer = CensorshipFusionScorer::new();
        scorer.set_censorship_level(3);
        scorer.set_ooni_factor("obfs4", 0.5);
        let status = scorer.status_json();
        assert_eq!(status["censorship_level"], 3);
        assert!(status["transport_adjustments"].is_object());
        assert!(status["weights"].is_object());
    }

    #[test]
    fn censorship_level_clamped() {
        let mut scorer = CensorshipFusionScorer::new();
        scorer.set_censorship_level(10);
        assert_eq!(scorer.censorship_level, 5);
        scorer.set_censorship_level(-1);
        assert_eq!(scorer.censorship_level, 1);
    }

    #[test]
    fn transport_survival_defaults() {
        let survival = default_transport_survival();
        assert!(survival.contains_key("obfs4"));
        assert!(survival.contains_key("webtunnel"));
        assert!(survival["webtunnel"] > survival["vanilla"]);
    }
}

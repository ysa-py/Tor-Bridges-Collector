//! Evidence Fusion Engine (§1.2 of the v42 forensic audit).
//!
//! Fuses observations from multiple independent stages (DNS, TCP, TLS,
//! transport handshake, Tor bootstrap, circuit build, regional vantage
//! points) into a single confidence score with an explicit verdict.
//!
//! ## Rules (from the spec)
//!
//! * **Single observation never equals certainty.** With fewer than
//!   `min_evidence_for_verdict` observations the verdict is always
//!   [`Verdict::Uncertain`] and the confidence is clamped to 0.6 regardless
//!   of how strong the lone observation is.
//! * **Confidence scoring is required.** Every evidence carries its own
//!   observation confidence in [0, 1], and the source carries a base weight
//!   (bootstrap/circuit evidence weighs more than raw TCP).
//! * **Temporal decay.** Each evidence is dampened by an exponential half-life
//!   in hours: `0.5^(age_hours / half_life_hours)`. Stale observations lose
//!   weight; recent observations dominate.
//! * **Bayesian-like fusion.** Evidence is combined in log-odds space with
//!   the dampened weight as an exponent, so agreeing independent observations
//!   push confidence up and disagreeing ones pull it back toward the prior.
//!   The result is clamped to `max_confidence` (default 0.95): no finite set
//!   of observations ever reaches certainty.
//!
//! The module is pure — no I/O, no network, no global state.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Independent evidence sources the pipeline can fuse. Each carries a base
/// weight reflecting how much it proves about actual usability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// DNS resolution outcome.
    Dns,
    /// TCP connect outcome.
    Tcp,
    /// TLS negotiation outcome.
    Tls,
    /// Transport-layer handshake (obfs4/WebTunnel/meek) outcome.
    Transport,
    /// Full Tor bootstrap outcome.
    Bootstrap,
    /// Circuit establishment outcome.
    Circuit,
    /// Regional vantage-point aggregation outcome.
    Regional,
}

impl EvidenceSource {
    /// Stable label for reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Transport => "transport",
            Self::Bootstrap => "bootstrap",
            Self::Circuit => "circuit",
            Self::Regional => "regional",
        }
    }

    /// Base weight in [0, 1]. Raw connectivity proves less than a full
    /// bootstrap + circuit; regional agreement proves the most.
    pub fn base_weight(&self) -> f64 {
        match self {
            Self::Dns => 0.3,
            Self::Tcp => 0.5,
            Self::Tls => 0.6,
            Self::Transport => 0.7,
            Self::Bootstrap => 0.8,
            Self::Circuit => 0.85,
            Self::Regional => 0.9,
        }
    }
}

/// A single observation to fuse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Which pipeline stage produced this observation.
    pub source: EvidenceSource,
    /// Outcome in [0, 1]: 1.0 = fully succeeded, 0.0 = definitively failed,
    /// intermediate values for partial stages.
    pub outcome: f64,
    /// Confidence in the observation itself in [0, 1].
    pub confidence: f64,
    /// Observation timestamp (Unix epoch seconds).
    pub observed_at: f64,
}

impl Evidence {
    /// Convenience constructor for a fully confident binary outcome.
    pub fn new(source: EvidenceSource, outcome: f64, observed_at: f64) -> Self {
        Self {
            source,
            outcome,
            confidence: 1.0,
            observed_at,
        }
    }
}

/// Fusion configuration. `now` is injected so the engine is fully
/// deterministic and testable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FusionConfig {
    /// Prior probability before any evidence (default 0.5 = no prior belief).
    pub prior: f64,
    /// Exponential decay half-life in hours for evidence age.
    pub half_life_hours: f64,
    /// Current time as Unix epoch seconds.
    pub now: f64,
    /// Minimum evidence count before a firm verdict is allowed.
    pub min_evidence_for_verdict: usize,
    /// Absolute ceiling for fused confidence (certainty is unreachable).
    pub max_confidence: f64,
}

impl Default for FusionConfig {
    fn default() -> Self {
        Self {
            prior: 0.5,
            half_life_hours: 24.0,
            now: 0.0,
            min_evidence_for_verdict: 2,
            max_confidence: 0.95,
        }
    }
}

/// Fused verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Confidence ≥ 0.7 with enough independent evidence.
    Healthy,
    /// Fewer than `min_evidence_for_verdict` observations, or confidence in
    /// the middle band.
    Uncertain,
    /// Confidence ≤ 0.3.
    Unhealthy,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Uncertain => "uncertain",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// Result of fusing a set of observations.
#[derive(Debug, Clone, PartialEq)]
pub struct FusionResult {
    /// Fused probability the bridge is genuinely usable, in [0, 1].
    pub confidence: f64,
    /// Verdict derived from confidence and evidence count.
    pub verdict: Verdict,
    /// Sum of decayed/weighted evidence strength; low values mean the
    /// conclusion rests on thin or stale data.
    pub effective_weight: f64,
    /// Total observations considered.
    pub evidence_count: usize,
    /// Observations younger than one half-life.
    pub fresh_evidence_count: usize,
    /// Per-source decayed contribution (posterior log-odds delta × weight).
    pub contributions: BTreeMap<String, f64>,
    /// Human-readable reasoning trail.
    pub reasoning: Vec<String>,
    /// Structured JSON report.
    pub report: Value,
}

/// Exponential temporal decay: 1.0 at age 0, halved every `half_life_hours`.
pub fn temporal_decay_weight(age_hours: f64, half_life_hours: f64) -> f64 {
    if age_hours <= 0.0 || half_life_hours <= 0.0 {
        return 1.0;
    }
    0.5_f64.powf(age_hours / half_life_hours)
}

/// Fuse all observations into a single confidence + verdict.
pub fn fuse(evidences: &[Evidence], config: &FusionConfig) -> FusionResult {
    let mut reasoning: Vec<String> = Vec::new();
    let mut total_weight = 0.0_f64;
    let mut fresh_count = 0usize;
    let mut contributions: BTreeMap<String, f64> = BTreeMap::new();

    // Prior as log-odds.
    let prior = config.prior.clamp(0.02, 0.98);
    let mut log_odds = (prior / (1.0 - prior)).ln();

    for evidence in evidences {
        let age_hours = (config.now - evidence.observed_at).max(0.0) / 3600.0;
        let decay = temporal_decay_weight(age_hours, config.half_life_hours);
        let outcome = evidence.outcome.clamp(0.02, 0.98);
        let effective = evidence.source.base_weight() * evidence.confidence.clamp(0.0, 1.0) * decay;
        total_weight += effective;
        if age_hours <= config.half_life_hours {
            fresh_count += 1;
        }
        // Log-odds update, dampened by the effective weight: a weak or stale
        // observation moves the posterior less than a fresh strong one.
        let piece = (outcome / (1.0 - outcome)).ln() * effective;
        log_odds += piece;
        contributions
            .entry(evidence.source.label().to_string())
            .and_modify(|value| *value += piece)
            .or_insert(piece);
        reasoning.push(format!(
            "{}: outcome={:.2} conf={:.2} age={:.1}h decay={:.3} Δlogodds={:+.3}",
            evidence.source.label(),
            evidence.outcome,
            evidence.confidence,
            age_hours,
            decay,
            piece
        ));
    }

    // Posterior probability from the accumulated log-odds.
    let odds = log_odds.exp();
    let mut confidence = odds / (1.0 + odds);
    let evidence_count = evidences.len();

    // Single observation never equals certainty: below the minimum evidence
    // threshold the verdict is Uncertain and confidence cannot exceed 0.6.
    let single_observation_cap = evidence_count < config.min_evidence_for_verdict;
    if single_observation_cap {
        confidence = confidence.min(0.6);
        reasoning.push(format!(
            "evidence count {} below minimum {} → verdict capped to uncertain",
            evidence_count, config.min_evidence_for_verdict
        ));
    }

    // Certainty is unreachable: hard clamp.
    confidence = confidence.min(config.max_confidence);

    let verdict = if single_observation_cap {
        Verdict::Uncertain
    } else if confidence >= 0.7 {
        Verdict::Healthy
    } else if confidence <= 0.3 {
        Verdict::Unhealthy
    } else {
        Verdict::Uncertain
    };

    reasoning.push(format!(
        "fused confidence={:.3} ({}) with {} evidence, effective weight={:.3}, fresh={}",
        confidence,
        verdict.label(),
        evidence_count,
        total_weight,
        fresh_count
    ));

    let report = json!({
        "confidence": round3(confidence),
        "verdict": verdict.label(),
        "prior": prior,
        "effective_weight": round3(total_weight),
        "evidence_count": evidence_count,
        "fresh_evidence_count": fresh_count,
        "min_evidence_for_verdict": config.min_evidence_for_verdict,
        "max_confidence": config.max_confidence,
        "half_life_hours": config.half_life_hours,
        "contributions": contributions,
    });

    FusionResult {
        confidence,
        verdict,
        effective_weight: total_weight,
        evidence_count,
        fresh_evidence_count: fresh_count,
        contributions,
        reasoning,
        report,
    }
}

/// Round to three decimals for stable reports.
fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(now: f64) -> FusionConfig {
        FusionConfig {
            now,
            ..FusionConfig::default()
        }
    }

    #[test]
    fn temporal_decay_halves_each_half_life() {
        assert!((temporal_decay_weight(0.0, 24.0) - 1.0).abs() < 1e-9);
        assert!((temporal_decay_weight(24.0, 24.0) - 0.5).abs() < 1e-9);
        assert!((temporal_decay_weight(48.0, 24.0) - 0.25).abs() < 1e-9);
        assert!((temporal_decay_weight(72.0, 24.0) - 0.125).abs() < 1e-9);
        assert!((temporal_decay_weight(-5.0, 24.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn single_observation_never_equals_certainty() {
        // A single perfect observation must not produce a firm verdict.
        let evidences = vec![Evidence::new(EvidenceSource::Circuit, 1.0, 0.0)];
        let result = fuse(&evidences, &config(0.0));
        assert_eq!(result.verdict, Verdict::Uncertain);
        assert!(result.confidence <= 0.6 + 1e-9, "confidence must be capped");
    }

    #[test]
    fn two_strong_agreeing_observations_yield_healthy() {
        let evidences = vec![
            Evidence::new(EvidenceSource::Tls, 1.0, 0.0),
            Evidence::new(EvidenceSource::Bootstrap, 1.0, 0.0),
            Evidence::new(EvidenceSource::Circuit, 1.0, 0.0),
        ];
        let result = fuse(&evidences, &config(0.0));
        assert_eq!(result.verdict, Verdict::Healthy);
        assert!(result.confidence >= 0.7);
        assert!(
            result.confidence <= 0.95 + 1e-9,
            "must respect max confidence"
        );
    }

    #[test]
    fn strong_negative_evidence_yields_unhealthy() {
        let evidences = vec![
            Evidence::new(EvidenceSource::Tcp, 0.0, 0.0),
            Evidence::new(EvidenceSource::Tls, 0.0, 0.0),
            Evidence::new(EvidenceSource::Transport, 0.0, 0.0),
        ];
        let result = fuse(&evidences, &config(0.0));
        assert_eq!(result.verdict, Verdict::Unhealthy);
        assert!(result.confidence <= 0.3);
    }

    #[test]
    fn stale_evidence_loses_weight() {
        let now = 48.0 * 3600.0; // two half-lives later
        let fresh = vec![
            Evidence::new(EvidenceSource::Circuit, 1.0, now),
            Evidence::new(EvidenceSource::Bootstrap, 1.0, now),
        ];
        let stale = vec![
            Evidence::new(EvidenceSource::Circuit, 1.0, 0.0),
            Evidence::new(EvidenceSource::Bootstrap, 1.0, 0.0),
        ];
        let fresh_result = fuse(&fresh, &config(now));
        let stale_result = fuse(&stale, &config(now));
        assert!(
            fresh_result.effective_weight > stale_result.effective_weight,
            "stale evidence must be dampened"
        );
        assert!(
            fresh_result.confidence > stale_result.confidence,
            "fresh evidence must dominate stale evidence"
        );
    }

    #[test]
    fn mixed_evidence_pulls_toward_prior() {
        // One success + one failure should land in the uncertain band, not
        // at either extreme.
        let evidences = vec![
            Evidence::new(EvidenceSource::Tcp, 1.0, 0.0),
            Evidence::new(EvidenceSource::Tls, 0.0, 0.0),
        ];
        let result = fuse(&evidences, &config(0.0));
        assert_eq!(result.verdict, Verdict::Uncertain);
        assert!(result.confidence > 0.3 && result.confidence < 0.7);
    }

    #[test]
    fn source_weights_differ_by_stage() {
        assert!(EvidenceSource::Circuit.base_weight() > EvidenceSource::Tcp.base_weight());
        assert!(EvidenceSource::Regional.base_weight() > EvidenceSource::Dns.base_weight());
    }

    #[test]
    fn empty_evidence_stays_uncertain() {
        let result = fuse(&[], &config(0.0));
        assert_eq!(result.verdict, Verdict::Uncertain);
        assert!((result.confidence - 0.5).abs() < 0.05, "prior-ish");
        assert_eq!(result.evidence_count, 0);
    }

    #[test]
    fn report_contains_audit_fields() {
        let evidences = vec![
            Evidence::new(EvidenceSource::Dns, 1.0, 0.0),
            Evidence::new(EvidenceSource::Tcp, 1.0, 0.0),
        ];
        let result = fuse(&evidences, &config(0.0));
        assert_eq!(result.report["verdict"], result.verdict.label());
        assert_eq!(result.report["evidence_count"], 2);
        assert_eq!(result.report["fresh_evidence_count"], 2);
        assert!(result.report["contributions"]["tcp"].is_number());
    }

    #[test]
    fn disagreement_never_reaches_certainty() {
        // 10 perfectly agreeing circuit observations: capped at max_confidence.
        let evidences: Vec<Evidence> = (0..10)
            .map(|_| Evidence::new(EvidenceSource::Circuit, 1.0, 0.0))
            .collect();
        let result = fuse(&evidences, &config(0.0));
        assert!(result.confidence <= 0.95 + 1e-9);
        assert_eq!(result.verdict, Verdict::Healthy);
    }

    #[test]
    fn custom_min_evidence_gate_honoured() {
        let mut cfg = config(0.0);
        cfg.min_evidence_for_verdict = 4;
        let evidences = vec![
            Evidence::new(EvidenceSource::Tls, 1.0, 0.0),
            Evidence::new(EvidenceSource::Bootstrap, 1.0, 0.0),
        ];
        let result = fuse(&evidences, &cfg);
        assert_eq!(result.verdict, Verdict::Uncertain);
    }

    #[test]
    fn confidence_field_dampens_evidence() {
        let full = vec![
            Evidence::new(EvidenceSource::Tls, 1.0, 0.0),
            Evidence::new(EvidenceSource::Bootstrap, 1.0, 0.0),
        ];
        let shaky = vec![
            Evidence {
                source: EvidenceSource::Tls,
                outcome: 1.0,
                confidence: 0.2,
                observed_at: 0.0,
            },
            Evidence {
                source: EvidenceSource::Bootstrap,
                outcome: 1.0,
                confidence: 0.2,
                observed_at: 0.0,
            },
        ];
        let full_result = fuse(&full, &config(0.0));
        let shaky_result = fuse(&shaky, &config(0.0));
        assert!(full_result.confidence > shaky_result.confidence);
    }

    #[test]
    fn verdict_labels_are_stable() {
        assert_eq!(Verdict::Healthy.label(), "healthy");
        assert_eq!(Verdict::Uncertain.label(), "uncertain");
        assert_eq!(Verdict::Unhealthy.label(), "unhealthy");
    }
}

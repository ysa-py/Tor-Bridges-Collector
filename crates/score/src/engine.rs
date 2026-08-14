//! Deterministic scoring engine (Phase 6 of the master spec).
//!
//! [`ScoreEngine`] turns a set of [`tbc_core::Observation`]s for one bridge
//! into a [`ScoredBridge`]: a validated [`tbc_core::BridgeScore`] plus a
//! transparent [`ScoreBreakdown`] of every intermediate value. The formula is
//! documented in `docs/SCORING.md` and pinned by the fixtures in
//! `tests/scoring_fixtures.rs`.
//!
//! The engine is total: for any validated configuration and any set of
//! observations it returns a score (an empty or fully-stale evidence set
//! scores 0 with tier D and confidence 0/0). No observation causes a panic.

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use tbc_core::{BridgeScore, Confidence, Observation, Tier};

use crate::config::ScoreConfig;
use crate::error::ScoreError;
use crate::evidence::{class_weight, is_blocking_verdict, observation_value, WORKING_THRESHOLD};

/// Vantage identity: two observations share a vantage when kind, country, ASN,
/// and mobile flag all match. This is the unit of "independent observation"
/// used by the k-of-n confidence.
type VantageKey = (String, Option<String>, Option<u32>, bool);

/// The per-ASN half of a [`ScoreBreakdown`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AsnBreakdown {
    /// Freshness-weighted score over this ASN's observations, before the
    /// confidence and burn multipliers.
    pub raw: f64,
    /// Final per-ASN score after confidence and burn multipliers.
    pub final_score: f64,
    /// Confidence multiplier for this ASN.
    pub confidence_multiplier: f64,
    /// Burn multiplier for this ASN.
    pub burn_factor: f64,
    /// Number of accepted observations for this ASN.
    pub observation_count: usize,
    /// Number of distinct vantages for this ASN.
    pub distinct_vantages: u32,
    /// Number of distinct working vantages for this ASN.
    pub working_vantages: u32,
}

/// Transparent intermediate values behind a [`ScoredBridge`].
///
/// Every term in `docs/SCORING.md` appears here so an operator or a test can
/// verify exactly how the final number was produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    /// `100 * working_weight / total_weight` before any multiplier.
    pub raw: f64,
    /// `agreement * coverage`.
    pub confidence_multiplier: f64,
    /// `min(1, burn_seconds / burn_horizon)`, or 1.0 when never burned.
    pub burn_factor: f64,
    /// Sum of `class_weight * decay` over accepted observations.
    pub evidence_total_weight: f64,
    /// Sum of `class_weight * decay * value` over accepted observations.
    pub evidence_working_weight: f64,
    /// Number of accepted observations.
    pub observation_count: usize,
    /// Number of distinct vantages.
    pub distinct_vantages: u32,
    /// Number of distinct working vantages.
    pub working_vantages: u32,
    /// Per-ASN breakdowns for every ASN present in accepted observations.
    pub per_asn: BTreeMap<u32, AsnBreakdown>,
}

/// A fully scored bridge: the published [`BridgeScore`] plus its breakdown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoredBridge {
    /// The bridge's canonical dedupe key.
    pub bridge_key: String,
    /// The validated score.
    pub score: BridgeScore,
    /// How the score was produced.
    pub breakdown: ScoreBreakdown,
}

/// A single accepted observation, pre-weighted for scoring.
#[derive(Debug, Clone)]
struct Weighted {
    value: f64,
    class_weight: f64,
    decay: f64,
    working: bool,
    blocking: bool,
    asn: Option<u32>,
    age_seconds: u64,
    vantage_key: VantageKey,
    measured_at: DateTime<Utc>,
}

/// Aggregated statistics over a subset of observations (global or per-ASN).
#[derive(Debug, Clone)]
struct Stats {
    raw: f64,
    final_score: f64,
    confidence_multiplier: f64,
    burn_factor: f64,
    evidence_total_weight: f64,
    evidence_working_weight: f64,
    observation_count: usize,
    distinct_vantages: u32,
    working_vantages: u32,
    first_working_at: Option<DateTime<Utc>>,
    first_blocked_at: Option<DateTime<Utc>>,
    burn_seconds: Option<u64>,
    median_lifetime_seconds: Option<u64>,
    freshness_age_seconds: u64,
}

/// The deterministic scoring engine.
pub struct ScoreEngine {
    config: ScoreConfig,
}

impl ScoreEngine {
    /// Construct an engine from a validated configuration.
    pub fn new(config: ScoreConfig) -> Result<Self, ScoreError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// The configuration this engine was built with.
    pub fn config(&self) -> &ScoreConfig {
        &self.config
    }

    /// Score one bridge from its observations.
    ///
    /// `bridge_key` is carried into the result verbatim; observations for
    /// other bridges should not be passed here (see [`ScoreEngine::score_all`]
    /// for grouping a mixed stream).
    pub fn score<'a>(
        &self,
        bridge_key: &str,
        observations: impl IntoIterator<Item = &'a Observation>,
        now: DateTime<Utc>,
    ) -> ScoredBridge {
        let weighted = self.accept(observations, now);
        self.score_weighted(bridge_key, &weighted)
    }

    /// Group a mixed observation stream by bridge key and score every bridge,
    /// returned in deterministic (lexicographic) bridge-key order.
    pub fn score_all<'a>(
        &self,
        observations: &'a [Observation],
        now: DateTime<Utc>,
    ) -> Vec<ScoredBridge> {
        let mut by_key: BTreeMap<String, Vec<&'a Observation>> = BTreeMap::new();
        for observation in observations {
            by_key
                .entry(observation.bridge_key.clone())
                .or_default()
                .push(observation);
        }
        by_key
            .into_iter()
            .map(|(key, subset)| self.score(&key, subset, now))
            .collect()
    }

    /// Filter to accepted observations and precompute value, decay, class
    /// weight, and vantage identity.
    fn accept<'a>(
        &self,
        observations: impl IntoIterator<Item = &'a Observation>,
        now: DateTime<Utc>,
    ) -> Vec<Weighted> {
        let max_age = self.config.max_observation_age_seconds;
        let half_life = self.config.freshness_half_life_seconds as f64;
        let mut accepted = Vec::new();
        for observation in observations {
            // Clamp future-dated observations to "now" rather than rewarding them.
            let age_seconds = (now - observation.measured_at).num_seconds().max(0) as u64;
            if age_seconds > max_age {
                continue;
            }
            let value = observation_value(
                observation.probe_kind,
                &observation.verdict,
                observation.bootstrap_pct,
            );
            accepted.push(Weighted {
                value,
                class_weight: class_weight(observation.probe_kind, &self.config.class_weights),
                decay: 2f64.powf(-(age_seconds as f64) / half_life),
                working: value > WORKING_THRESHOLD,
                blocking: is_blocking_verdict(&observation.verdict),
                asn: observation.vantage.asn,
                age_seconds,
                vantage_key: (
                    observation.vantage.kind.to_string(),
                    observation.vantage.country.clone(),
                    observation.vantage.asn,
                    observation.vantage.is_mobile,
                ),
                measured_at: observation.measured_at,
            });
        }
        accepted
    }

    /// Score from pre-weighted observations, assembling the public result.
    fn score_weighted(&self, bridge_key: &str, weighted: &[Weighted]) -> ScoredBridge {
        let refs: Vec<&Weighted> = weighted.iter().collect();
        let global = self.stats(&refs);
        let per_asn = self.per_asn_stats(&refs);

        let mut tier = self.config.tier_for(global.final_score);
        if ScoreConfig::is_above_c(tier) && global.working_vantages < self.config.min_confirmations
        {
            tier = Tier::C;
        }

        let score = BridgeScore {
            global: global.final_score,
            per_asn: per_asn
                .iter()
                .map(|(asn, stats)| (*asn, stats.final_score))
                .collect(),
            tier,
            confidence: Confidence {
                k: global.working_vantages,
                n: global.distinct_vantages,
            },
            first_confirmed_working_at: global.first_working_at,
            first_blocked_at: global.first_blocked_at,
            burn_seconds: global.burn_seconds,
            median_lifetime_seconds: global.median_lifetime_seconds,
            freshness_age_seconds: global.freshness_age_seconds,
        };

        let breakdown = ScoreBreakdown {
            raw: global.raw,
            confidence_multiplier: global.confidence_multiplier,
            burn_factor: global.burn_factor,
            evidence_total_weight: global.evidence_total_weight,
            evidence_working_weight: global.evidence_working_weight,
            observation_count: global.observation_count,
            distinct_vantages: global.distinct_vantages,
            working_vantages: global.working_vantages,
            per_asn: per_asn
                .into_iter()
                .map(|(asn, stats)| {
                    (
                        asn,
                        AsnBreakdown {
                            raw: stats.raw,
                            final_score: stats.final_score,
                            confidence_multiplier: stats.confidence_multiplier,
                            burn_factor: stats.burn_factor,
                            observation_count: stats.observation_count,
                            distinct_vantages: stats.distinct_vantages,
                            working_vantages: stats.working_vantages,
                        },
                    )
                })
                .collect(),
        };

        ScoredBridge {
            bridge_key: bridge_key.to_owned(),
            score,
            breakdown,
        }
    }

    /// Aggregate per-ASN statistics for every ASN present in accepted evidence.
    fn per_asn_stats(&self, items: &[&Weighted]) -> BTreeMap<u32, Stats> {
        let mut grouped: BTreeMap<u32, Vec<&Weighted>> = BTreeMap::new();
        for item in items {
            if let Some(asn) = item.asn {
                grouped.entry(asn).or_default().push(*item);
            }
        }
        grouped
            .into_iter()
            .map(|(asn, subset)| (asn, self.stats(&subset)))
            .collect()
    }

    /// Compute all statistics over a subset of accepted observations.
    fn stats(&self, items: &[&Weighted]) -> Stats {
        let mut total = 0.0f64;
        let mut working_weight = 0.0f64;
        let mut vantages: HashSet<VantageKey> = HashSet::new();
        let mut working_vantages: HashSet<VantageKey> = HashSet::new();
        let mut first_working: Option<DateTime<Utc>> = None;
        let mut blocked_times: Vec<DateTime<Utc>> = Vec::new();
        let mut freshest_age: Option<u64> = None;

        for item in items {
            let evidence = item.class_weight * item.decay;
            total += evidence;
            working_weight += evidence * item.value;
            vantages.insert(item.vantage_key.clone());
            if item.working {
                working_vantages.insert(item.vantage_key.clone());
                first_working = Some(match first_working {
                    Some(existing) => existing.min(item.measured_at),
                    None => item.measured_at,
                });
            }
            if item.blocking {
                blocked_times.push(item.measured_at);
            }
            freshest_age = Some(match freshest_age {
                Some(existing) => existing.min(item.age_seconds),
                None => item.age_seconds,
            });
        }

        let distinct_vantages = vantages.len() as u32;
        let working_count = working_vantages.len() as u32;

        // Freshness-weighted score over the evidence classes. The clamp is
        // not cosmetic: `100 * working_weight / total` can round to
        // `100.00000000000001` when the two weighted sums are equal, which
        // would otherwise violate the `0.0..=100.0` invariant.
        let raw = if total > 0.0 {
            (100.0 * working_weight / total).clamp(0.0, 100.0)
        } else {
            0.0
        };

        // k-of-n confidence: agreement (working vantages / all vantages) scaled
        // by coverage (how close distinct vantages are to the saturation point).
        let agreement = if distinct_vantages == 0 {
            0.0
        } else {
            working_count as f64 / distinct_vantages as f64
        };
        let coverage = (distinct_vantages as f64 / self.config.min_vantages as f64).min(1.0);
        let confidence_multiplier = agreement * coverage;

        // Burn rate: time from first working confirmation to first observed
        // active block, scaled by the burn horizon. Never-blocked bridges and
        // bridges blocked before any working confirmation are not penalized.
        let first_blocked_at = blocked_times.iter().copied().min();
        let burn_seconds = match (first_working, first_blocked_at) {
            (Some(working), Some(blocked)) if blocked > working => {
                Some((blocked - working).num_seconds() as u64)
            }
            _ => None,
        };
        let burn_factor = match burn_seconds {
            Some(seconds) => (seconds as f64 / self.config.burn_horizon_seconds as f64).min(1.0),
            None => 1.0,
        };

        // Median survival time: median of (block time - first working time)
        // over blocking observations strictly after the first working one.
        let median_lifetime_seconds = match first_working {
            Some(working) => {
                let mut durations: Vec<u64> = blocked_times
                    .iter()
                    .filter(|blocked| **blocked > working)
                    .map(|blocked| (*blocked - working).num_seconds() as u64)
                    .collect();
                median_u64(&mut durations)
            }
            None => None,
        };

        let final_score = (raw * confidence_multiplier * burn_factor).clamp(0.0, 100.0);

        Stats {
            raw,
            final_score,
            confidence_multiplier,
            burn_factor,
            evidence_total_weight: total,
            evidence_working_weight: working_weight,
            observation_count: items.len(),
            distinct_vantages,
            working_vantages: working_count,
            first_working_at: first_working,
            first_blocked_at,
            burn_seconds,
            median_lifetime_seconds,
            freshness_age_seconds: freshest_age.unwrap_or(0),
        }
    }
}

/// Median of whole-second durations (the list is sorted in place), rounding
/// an even-length average up to the nearest second. `None` when empty.
fn median_u64(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        Some((values[middle - 1] + values[middle]).div_ceil(2))
    } else {
        Some(values[middle])
    }
}

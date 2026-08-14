//! Typed error taxonomy for the scoring layer.
//!
//! The scoring engine is total over a validated configuration: once a
//! [`crate::ScoreConfig`] is accepted, every call to `score`/`score_all`
//! returns a [`crate::ScoredBridge`] rather than failing. The only fallible
//! operation in this crate is configuration validation, so [`ScoreError`]
//! carries precisely the ways a configuration can be rejected, classified so
//! callers can report a metric-safe failure name without parsing strings.

use thiserror::Error;

/// Errors produced while validating a scoring configuration.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ScoreError {
    /// The three evidence-class weights do not sum to 1.0.
    #[error("evidence class weights must sum to 1.0, got {sum}")]
    WeightsDoNotSum { sum: f64 },

    /// An evidence-class weight is negative.
    #[error("evidence class weight {name} must be >= 0, got {value}")]
    NegativeWeight { name: &'static str, value: f64 },

    /// Tier thresholds are not strictly decreasing (S > A > B > C).
    #[error("tier thresholds are invalid: {0}")]
    InvalidTierThresholds(&'static str),

    /// A tier threshold is outside the closed 0..=100 range.
    #[error("tier threshold {name} must be in 0..=100, got {value}")]
    TierThresholdOutOfRange { name: &'static str, value: f64 },

    /// The freshness half-life must be strictly positive.
    #[error("freshness half-life must be > 0")]
    NonPositiveHalfLife,

    /// The burn horizon must be strictly positive.
    #[error("burn horizon must be > 0")]
    NonPositiveBurnHorizon,

    /// The maximum observation age must be strictly positive.
    #[error("maximum observation age must be > 0")]
    NonPositiveMaxAge,

    /// `min_vantages` must be at least 1 (it is a division denominator).
    #[error("min vantages must be >= 1")]
    ZeroMinVantages,
}

impl ScoreError {
    /// A stable, metric-safe name for the failure class (no value data).
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::WeightsDoNotSum { .. } => "weights_do_not_sum",
            Self::NegativeWeight { .. } => "negative_weight",
            Self::InvalidTierThresholds(_) => "invalid_tier_thresholds",
            Self::TierThresholdOutOfRange { .. } => "tier_threshold_out_of_range",
            Self::NonPositiveHalfLife => "non_positive_half_life",
            Self::NonPositiveBurnHorizon => "non_positive_burn_horizon",
            Self::NonPositiveMaxAge => "non_positive_max_age",
            Self::ZeroMinVantages => "zero_min_vantages",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_are_stable_and_value_free() {
        assert_eq!(
            ScoreError::NegativeWeight {
                name: "handshake",
                value: -0.5
            }
            .kind_name(),
            "negative_weight"
        );
        assert_eq!(
            ScoreError::WeightsDoNotSum { sum: 0.7 }.kind_name(),
            "weights_do_not_sum"
        );
        assert_eq!(
            ScoreError::NonPositiveHalfLife.kind_name(),
            "non_positive_half_life"
        );
        assert_eq!(ScoreError::ZeroMinVantages.kind_name(), "zero_min_vantages");
    }
}

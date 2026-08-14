//! Scoring configuration (Phase 6): thresholds in config, not magic numbers.
//!
//! Every tunable that shapes a score lives here and serializes to/from TOML or
//! JSON (`serde`), so the scoring model can be adjusted and versioned without
//! recompiling. [`ScoreConfig::validate`] rejects any configuration that would
//! make the scoring formulas ill-defined (non-normalized weights, mis-ordered
//! tier thresholds, zero denominators).

use serde::{Deserialize, Serialize};

use tbc_core::Tier;

use crate::error::ScoreError;

/// Relative weights of the three evidence classes.
///
/// The master spec requires real-handshake success (highest weight) > TCP
/// reachability > path evidence. Weights must be non-negative and sum to 1.0.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ClassWeights {
    /// Weight of handshake-class probes (`Obfs4Handshake`, `WebTunnelUpgrade`,
    /// `TorBootstrap`).
    pub handshake: f64,
    /// Weight of TCP-class probes (`TcpConnect`, `TlsSni`).
    pub tcp: f64,
    /// Weight of path-class probes (`TcpTraceroute`).
    pub path: f64,
}

impl Default for ClassWeights {
    fn default() -> Self {
        Self {
            handshake: 0.6,
            tcp: 0.3,
            path: 0.1,
        }
    }
}

impl ClassWeights {
    /// The total weight (should be exactly 1.0 after validation).
    pub fn sum(&self) -> f64 {
        self.handshake + self.tcp + self.path
    }

    /// Validate non-negativity and normalization.
    pub fn validate(&self) -> Result<(), ScoreError> {
        for (name, value) in [
            ("handshake", self.handshake),
            ("tcp", self.tcp),
            ("path", self.path),
        ] {
            if value < 0.0 {
                return Err(ScoreError::NegativeWeight { name, value });
            }
        }
        let sum = self.sum();
        // 1e-9 tolerance absorbs the f64 error of three decimal literals.
        if (sum - 1.0).abs() > 1e-9 {
            return Err(ScoreError::WeightsDoNotSum { sum });
        }
        Ok(())
    }
}

/// Score thresholds for tier assignment. `score >= s` ⇒ tier S, and so on.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TierThresholds {
    /// Minimum final score for tier S.
    pub s: f64,
    /// Minimum final score for tier A.
    pub a: f64,
    /// Minimum final score for tier B.
    pub b: f64,
    /// Minimum final score for tier C (below this is D).
    pub c: f64,
}

impl Default for TierThresholds {
    fn default() -> Self {
        Self {
            s: 90.0,
            a: 75.0,
            b: 60.0,
            c: 40.0,
        }
    }
}

impl TierThresholds {
    /// Validate range and strict ordering.
    pub fn validate(&self) -> Result<(), ScoreError> {
        for (name, value) in [("s", self.s), ("a", self.a), ("b", self.b), ("c", self.c)] {
            if !(0.0..=100.0).contains(&value) {
                return Err(ScoreError::TierThresholdOutOfRange { name, value });
            }
        }
        if !(self.s > self.a && self.a > self.b && self.b > self.c) {
            return Err(ScoreError::InvalidTierThresholds(
                "thresholds must be strictly decreasing S > A > B > C",
            ));
        }
        Ok(())
    }
}

/// The complete, validated scoring model configuration.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScoreConfig {
    /// Per-class evidence weights.
    pub class_weights: ClassWeights,
    /// Freshness half-life in seconds: an observation this old contributes
    /// half its class weight.
    pub freshness_half_life_seconds: u64,
    /// Tier score thresholds.
    pub tier_thresholds: TierThresholds,
    /// Minimum number of distinct working vantages required to hold a tier
    /// above C ("publish nothing above tier C without minimum confirmations").
    pub min_confirmations: u32,
    /// Number of distinct vantages at which coverage credit saturates.
    pub min_vantages: u32,
    /// Burn horizon in seconds: a bridge that survived at least this long
    /// before being observed blocked receives no burn penalty.
    pub burn_horizon_seconds: u64,
    /// Observations older than this are dropped entirely (stale-evidence cap).
    pub max_observation_age_seconds: u64,
}

impl Default for ScoreConfig {
    fn default() -> Self {
        Self {
            class_weights: ClassWeights::default(),
            freshness_half_life_seconds: 21_600, // 6 hours
            tier_thresholds: TierThresholds::default(),
            min_confirmations: 2,
            min_vantages: 1,
            burn_horizon_seconds: 604_800,        // 7 days
            max_observation_age_seconds: 604_800, // 7 days
        }
    }
}

impl ScoreConfig {
    /// Validate every field, rejecting configurations the formulas cannot use.
    pub fn validate(&self) -> Result<(), ScoreError> {
        self.class_weights.validate()?;
        self.tier_thresholds.validate()?;
        if self.freshness_half_life_seconds == 0 {
            return Err(ScoreError::NonPositiveHalfLife);
        }
        if self.burn_horizon_seconds == 0 {
            return Err(ScoreError::NonPositiveBurnHorizon);
        }
        if self.max_observation_age_seconds == 0 {
            return Err(ScoreError::NonPositiveMaxAge);
        }
        if self.min_vantages == 0 {
            return Err(ScoreError::ZeroMinVantages);
        }
        Ok(())
    }

    /// Map a final score to a tier using the configured thresholds.
    pub fn tier_for(&self, score: f64) -> Tier {
        if score >= self.tier_thresholds.s {
            Tier::S
        } else if score >= self.tier_thresholds.a {
            Tier::A
        } else if score >= self.tier_thresholds.b {
            Tier::B
        } else if score >= self.tier_thresholds.c {
            Tier::C
        } else {
            Tier::D
        }
    }

    /// Whether a tier is above C (S, A, or B) and therefore subject to the
    /// minimum-confirmations publication gate.
    ///
    /// This is an explicit match rather than a `Tier` comparison because the
    /// `Ord` derived on `tbc_core::Tier` is declaration order (S < A < B < C
    /// < D), which is the opposite of tier quality.
    pub fn is_above_c(tier: Tier) -> bool {
        matches!(tier, Tier::S | Tier::A | Tier::B)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        assert!(ScoreConfig::default().validate().is_ok());
    }

    #[test]
    fn weights_must_sum_to_one() {
        let config = ScoreConfig {
            class_weights: ClassWeights {
                tcp: 0.4,
                ..ClassWeights::default()
            },
            ..ScoreConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ScoreError::WeightsDoNotSum { .. }));
    }

    #[test]
    fn weights_must_be_non_negative() {
        let config = ScoreConfig {
            class_weights: ClassWeights {
                handshake: -0.1,
                path: 0.2,
                ..ClassWeights::default()
            },
            ..ScoreConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ScoreError::NegativeWeight {
                name: "handshake",
                ..
            }
        ));
    }

    #[test]
    fn thresholds_must_be_strictly_decreasing() {
        let config = ScoreConfig {
            tier_thresholds: TierThresholds {
                b: 40.0, // equals the default C threshold: B == C
                ..TierThresholds::default()
            },
            ..ScoreConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ScoreError::InvalidTierThresholds(_)));
    }

    #[test]
    fn thresholds_must_be_in_range() {
        let config = ScoreConfig {
            tier_thresholds: TierThresholds {
                s: 101.0,
                ..TierThresholds::default()
            },
            ..ScoreConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ScoreError::TierThresholdOutOfRange { name: "s", .. }
        ));
    }

    #[test]
    fn zero_denominators_are_rejected() {
        let config = ScoreConfig {
            min_vantages: 0,
            ..ScoreConfig::default()
        };
        assert_eq!(config.validate().unwrap_err(), ScoreError::ZeroMinVantages);

        let config = ScoreConfig {
            freshness_half_life_seconds: 0,
            ..ScoreConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            ScoreError::NonPositiveHalfLife
        );

        let config = ScoreConfig {
            burn_horizon_seconds: 0,
            ..ScoreConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            ScoreError::NonPositiveBurnHorizon
        );

        let config = ScoreConfig {
            max_observation_age_seconds: 0,
            ..ScoreConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            ScoreError::NonPositiveMaxAge
        );
    }

    #[test]
    fn tier_mapping_is_monotonic_and_threshold_exact() {
        let config = ScoreConfig::default();
        assert_eq!(config.tier_for(90.0), Tier::S);
        assert_eq!(config.tier_for(89.9), Tier::A);
        assert_eq!(config.tier_for(75.0), Tier::A);
        assert_eq!(config.tier_for(60.0), Tier::B);
        assert_eq!(config.tier_for(40.0), Tier::C);
        assert_eq!(config.tier_for(39.9), Tier::D);
        assert_eq!(config.tier_for(0.0), Tier::D);
    }

    #[test]
    fn above_c_is_exactly_s_a_b() {
        assert!(ScoreConfig::is_above_c(Tier::S));
        assert!(ScoreConfig::is_above_c(Tier::A));
        assert!(ScoreConfig::is_above_c(Tier::B));
        assert!(!ScoreConfig::is_above_c(Tier::C));
        assert!(!ScoreConfig::is_above_c(Tier::D));
    }

    #[test]
    fn config_serde_round_trips() {
        let config = ScoreConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: ScoreConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, decoded);
    }
}

//! Configurable k-anonymity threshold.
//!
//! The minimum batch size `k` is exposed as configuration — never hardcoded
//! into the aggregation logic. The default `k = 5` matches the existing
//! `tbc-agent` spec (`AgentConfig::default().k_anonymity_threshold = 5`); no
//! `tbc-core` constant overrides it.

use serde::{Deserialize, Serialize};

use crate::error::KAnonymityError;

/// k-anonymity configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KAnonymityConfig {
    /// Minimum number of reports that must be held before a batch is emitted.
    ///
    /// Must be at least 1. A report submitted to a batcher configured with
    /// threshold `k` is withheld until `k` reports are held, then the whole
    /// batch of `k` is released.
    pub k: usize,
}

impl Default for KAnonymityConfig {
    /// `k = 5`, matching `tbc-agent`'s `k_anonymity_threshold` default.
    fn default() -> Self {
        Self { k: 5 }
    }
}

impl KAnonymityConfig {
    /// Reject a threshold the aggregation logic cannot honor.
    pub fn validate(&self) -> Result<(), KAnonymityError> {
        if self.k == 0 {
            return Err(KAnonymityError::ZeroThreshold { k: self.k });
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_k_matches_the_agent_spec() {
        assert_eq!(KAnonymityConfig::default().k, 5);
    }

    #[test]
    fn validates_and_rejects_zero() {
        assert!(KAnonymityConfig { k: 1 }.validate().is_ok());
        assert!(KAnonymityConfig { k: 5 }.validate().is_ok());
        let error = KAnonymityConfig { k: 0 }.validate().unwrap_err();
        assert_eq!(error, KAnonymityError::ZeroThreshold { k: 0 });
    }

    #[test]
    fn config_serde_round_trips() {
        let config = KAnonymityConfig { k: 3 };
        let json = serde_json::to_string(&config).unwrap();
        let decoded: KAnonymityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, decoded);
    }
}

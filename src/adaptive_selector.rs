use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdaptiveSelectorError {
    #[error("Adaptive selector failed")]
    Failure,
}

pub struct AdaptiveSelectorConfig {
    pub enabled: bool,
}

pub struct AdaptiveBridgeSelector {
    pub config: AdaptiveSelectorConfig,
}

impl AdaptiveBridgeSelector {
    pub fn new(enabled: bool) -> Self {
        Self {
            config: AdaptiveSelectorConfig { enabled },
        }
    }

    pub fn select(&self, items: &[(String, Value)]) -> Result<Vec<(String, Value)>, AdaptiveSelectorError> {
        Ok(items.to_vec())
    }
}

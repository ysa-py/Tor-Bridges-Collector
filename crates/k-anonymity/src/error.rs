//! Typed error taxonomy for k-anonymity enforcement.

use thiserror::Error;

/// All failure modes of the k-anonymity batcher.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KAnonymityError {
    /// The configured threshold is below the minimum meaningful value.
    #[error("k-anonymity threshold must be at least 1 (got {k})")]
    ZeroThreshold { k: usize },
}

impl KAnonymityError {
    /// A stable, metric-safe classifier for observability.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ZeroThreshold { .. } => "zero_threshold",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn kind_name_is_stable() {
        assert_eq!(
            KAnonymityError::ZeroThreshold { k: 0 }.kind_name(),
            "zero_threshold"
        );
    }

    #[test]
    fn display_reports_the_offending_threshold() {
        let message = KAnonymityError::ZeroThreshold { k: 0 }.to_string();
        assert!(message.contains("at least 1"));
        assert!(message.contains("0"));
    }
}

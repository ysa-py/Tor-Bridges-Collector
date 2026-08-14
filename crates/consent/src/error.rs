//! Typed error taxonomy for the consent gate.

use thiserror::Error;

/// All failure modes of the consent flow.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConsentError {
    /// A protected operation was attempted before consent was recorded.
    #[error("consent has not been recorded")]
    NotGranted,

    /// The consent prompt received an answer other than an explicit yes/no.
    #[error("unrecognized consent response {0:?} (answer yes or no)")]
    InvalidInput(String),
}

impl ConsentError {
    /// A stable, metric-safe classifier for observability.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::NotGranted => "consent_required",
            Self::InvalidInput(_) => "invalid_consent_input",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_are_stable() {
        assert_eq!(ConsentError::NotGranted.kind_name(), "consent_required");
        assert_eq!(
            ConsentError::InvalidInput("maybe".to_owned()).kind_name(),
            "invalid_consent_input"
        );
    }

    #[test]
    fn display_messages_are_actionable() {
        assert_eq!(
            ConsentError::NotGranted.to_string(),
            "consent has not been recorded"
        );
        assert!(ConsentError::InvalidInput("maybe".to_owned())
            .to_string()
            .contains("yes or no"));
    }
}

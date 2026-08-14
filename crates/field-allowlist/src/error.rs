//! Typed, classified errors for the field-allowlist ingestion boundary.

use thiserror::Error;

/// Every way the allowlist boundary can reject a payload.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FieldAllowlistError {
    /// The payload is neither a JSON object nor an array of objects.
    #[error("report payload must be a JSON object or an array of JSON objects")]
    InvalidPayload,
    /// A field outside the five-field allowlist was present. The report is
    /// rejected — the offending field is never silently dropped.
    #[error("report contains a field outside the allowlist: {name:?}")]
    DisallowedField { name: String },
    /// `source` is not one of the two Phase-4/Phase-5 source tags.
    #[error("unknown source tag {0:?} (allowed: phase4_ci_runner, phase5_volunteer)")]
    UnknownSourceTag(String),
    /// `rtt_bucket` is not one of the coarse bucket names.
    #[error(
        "invalid RTT bucket value {0:?} (allowed: rtt_0_50, rtt_50_150, rtt_150_400, \
         rtt_400_1000, rtt_1000_plus, rtt_unknown)"
    )]
    InvalidRttBucket(String),
    /// `asn_class` is not one of the coarse classes.
    #[error("invalid ASN class value {0:?} (allowed: small, medium, large, unknown)")]
    InvalidAsnClass(String),
    /// `outcome` is not `success` or `failure`.
    #[error("invalid outcome value {0:?} (allowed: success, failure)")]
    InvalidOutcome(String),
    /// `token` is not exactly 32 lowercase hex digits.
    #[error("malformed one-time token: {0:?}")]
    MalformedToken(String),
    /// The one-time token has already been consumed by an earlier report.
    #[error("one-time token reuse rejected: {0:?}")]
    ReusedToken(String),
    /// The payload failed JSON parsing or the typed deserialization backstop
    /// (for example a missing required field).
    #[error("invalid report JSON: {0}")]
    Json(String),
}

impl From<serde_json::Error> for FieldAllowlistError {
    /// Convert a serde failure, preserving the message for diagnosis.
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl FieldAllowlistError {
    /// A stable, metric-safe classifier.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::InvalidPayload => "invalid_payload",
            Self::DisallowedField { .. } => "disallowed_field",
            Self::UnknownSourceTag(_) => "unknown_source_tag",
            Self::InvalidRttBucket(_) => "invalid_rtt_bucket",
            Self::InvalidAsnClass(_) => "invalid_asn_class",
            Self::InvalidOutcome(_) => "invalid_outcome",
            Self::MalformedToken(_) => "malformed_token",
            Self::ReusedToken(_) => "reused_token",
            Self::Json(_) => "invalid_json",
        }
    }
}

/// Free function form of [`FieldAllowlistError::kind_name`].
pub fn kind_name(error: &FieldAllowlistError) -> &'static str {
    error.kind_name()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_are_stable() {
        let cases = [
            (FieldAllowlistError::InvalidPayload, "invalid_payload"),
            (
                FieldAllowlistError::DisallowedField {
                    name: "ip".to_owned(),
                },
                "disallowed_field",
            ),
            (
                FieldAllowlistError::UnknownSourceTag("x".to_owned()),
                "unknown_source_tag",
            ),
            (
                FieldAllowlistError::InvalidRttBucket("rtt_37".to_owned()),
                "invalid_rtt_bucket",
            ),
            (
                FieldAllowlistError::InvalidAsnClass("giant".to_owned()),
                "invalid_asn_class",
            ),
            (
                FieldAllowlistError::InvalidOutcome("maybe".to_owned()),
                "invalid_outcome",
            ),
            (
                FieldAllowlistError::MalformedToken("short".to_owned()),
                "malformed_token",
            ),
            (
                FieldAllowlistError::ReusedToken("t".to_owned()),
                "reused_token",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.kind_name(), expected);
        }
    }

    #[test]
    fn display_names_the_offending_field() {
        let message = FieldAllowlistError::DisallowedField {
            name: "asn".to_owned(),
        }
        .to_string();
        assert!(message.contains("asn"));
    }

    #[test]
    fn display_lists_the_allowed_source_tags() {
        let message = FieldAllowlistError::UnknownSourceTag("phase3_runner".to_owned()).to_string();
        assert!(message.contains("phase5_volunteer"));
        assert!(message.contains("phase4_ci_runner"));
    }
}

//! The ingestion boundary: everything that is *not* in the allowlist is
//! rejected here, before any downstream logic can see the payload.
//!
//! The check is two-layered and both layers must pass:
//!
//! 1. An explicit key scan over the JSON object reports
//!    [`FieldAllowlistError::DisallowedField`] with the exact offending name
//!    (an exact IP, exact ASN, raw timestamp, evidence string, …).
//! 2. A typed deserialization into [`AllowlistedReport`]
//!    (`#[serde(deny_unknown_fields)]` + enum value domains) as the compiled
//!    backstop, which also rejects off-domain values and missing fields.

use serde_json::Value;

use crate::error::FieldAllowlistError;
use crate::model::AllowlistedReport;
use crate::token::Token;

/// The complete, closed field set of the Phase-5 report contract.
pub const ALLOWED_FIELDS: [&str; 5] = ["outcome", "rtt_bucket", "asn_class", "token", "source"];

/// Parse and allowlist-check one report from a JSON string.
pub fn parse_report(input: &str) -> Result<AllowlistedReport, FieldAllowlistError> {
    let value: Value = serde_json::from_str(input)?;
    parse_report_value(value)
}

/// Allowlist-check one report from an already-parsed JSON value.
pub fn parse_report_value(value: Value) -> Result<AllowlistedReport, FieldAllowlistError> {
    let object = value
        .as_object()
        .ok_or(FieldAllowlistError::InvalidPayload)?;

    // Layer 1 — explicit field allowlist. The error names the exact
    // non-allowlisted field; it is never silently dropped.
    for key in object.keys() {
        if !ALLOWED_FIELDS.contains(&key.as_str()) {
            return Err(FieldAllowlistError::DisallowedField { name: key.clone() });
        }
    }

    // Layer 1b — explicit value-domain checks, so off-domain values are
    // classified instead of surfacing as a generic serde error.
    check_value_domains(object)?;

    // Layer 2 — the typed contract (deny_unknown_fields + enum + token
    // validation) as the compiled backstop.
    let report: AllowlistedReport = serde_json::from_value(Value::Object(object.clone()))?;
    Ok(report)
}

/// Reject field values that are not in the documented domain. The typed
/// deserialization backstop would reject them anyway; this classifies them.
fn check_value_domains(object: &serde_json::Map<String, Value>) -> Result<(), FieldAllowlistError> {
    if let Some(value) = object.get("outcome") {
        let raw = value
            .as_str()
            .ok_or_else(|| FieldAllowlistError::InvalidOutcome(value.to_string()))?;
        if !matches!(raw, "success" | "failure") {
            return Err(FieldAllowlistError::InvalidOutcome(raw.to_owned()));
        }
    }
    if let Some(value) = object.get("rtt_bucket") {
        let raw = value
            .as_str()
            .ok_or_else(|| FieldAllowlistError::InvalidRttBucket(value.to_string()))?;
        if !matches!(
            raw,
            "rtt_0_50"
                | "rtt_50_150"
                | "rtt_150_400"
                | "rtt_400_1000"
                | "rtt_1000_plus"
                | "rtt_unknown"
        ) {
            return Err(FieldAllowlistError::InvalidRttBucket(raw.to_owned()));
        }
    }
    if let Some(value) = object.get("asn_class") {
        let raw = value
            .as_str()
            .ok_or_else(|| FieldAllowlistError::InvalidAsnClass(value.to_string()))?;
        if !matches!(raw, "small" | "medium" | "large" | "unknown") {
            return Err(FieldAllowlistError::InvalidAsnClass(raw.to_owned()));
        }
    }
    if let Some(value) = object.get("source") {
        let raw = value
            .as_str()
            .ok_or_else(|| FieldAllowlistError::UnknownSourceTag(value.to_string()))?;
        if !matches!(raw, "phase4_ci_runner" | "phase5_volunteer") {
            return Err(FieldAllowlistError::UnknownSourceTag(raw.to_owned()));
        }
    }
    if let Some(value) = object.get("token") {
        let raw = value
            .as_str()
            .ok_or_else(|| FieldAllowlistError::MalformedToken(value.to_string()))?;
        if !Token::is_valid(raw) {
            return Err(FieldAllowlistError::MalformedToken(raw.to_owned()));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_report() -> serde_json::Value {
        json!({
            "outcome": "success",
            "rtt_bucket": "rtt_50_150",
            "asn_class": "large",
            "token": "0123456789abcdef0123456789abcdef",
            "source": "phase5_volunteer",
        })
    }

    #[test]
    fn allowlisted_report_passes_the_boundary() {
        let report = parse_report_value(valid_report()).unwrap();
        assert_eq!(report.source.tag(), "phase5_volunteer");
    }

    #[test]
    fn phase4_source_tag_is_also_allowlisted() {
        let mut raw = valid_report();
        raw["source"] = json!("phase4_ci_runner");
        let report = parse_report_value(raw).unwrap();
        assert_eq!(report.source.tag(), "phase4_ci_runner");
    }

    #[test]
    fn exact_ip_is_rejected_and_named() {
        let mut raw = valid_report();
        raw["ip"] = json!("95.216.217.25");
        let error = parse_report_value(raw).unwrap_err();
        assert_eq!(
            error,
            FieldAllowlistError::DisallowedField {
                name: "ip".to_owned()
            }
        );
    }

    #[test]
    fn exact_asn_is_rejected_and_named() {
        let mut raw = valid_report();
        raw["asn"] = json!(24940);
        let error = parse_report_value(raw).unwrap_err();
        assert_eq!(
            error,
            FieldAllowlistError::DisallowedField {
                name: "asn".to_owned()
            }
        );
    }

    #[test]
    fn raw_timestamp_is_rejected_and_named() {
        let mut raw = valid_report();
        raw["recorded_at"] = json!("2026-08-14T15:00:00Z");
        let error = parse_report_value(raw).unwrap_err();
        assert_eq!(
            error,
            FieldAllowlistError::DisallowedField {
                name: "recorded_at".to_owned()
            }
        );
    }

    #[test]
    fn evidence_and_measurement_references_are_rejected() {
        for forbidden in ["evidence", "measurement_ref", "rtt_ms", "target_ip"] {
            let mut raw = valid_report();
            raw[forbidden] = json!("anything");
            let error = parse_report_value(raw).unwrap_err();
            assert_eq!(
                error,
                FieldAllowlistError::DisallowedField {
                    name: forbidden.to_owned()
                }
            );
        }
    }

    #[test]
    fn unknown_source_tag_is_classified() {
        let mut raw = valid_report();
        raw["source"] = json!("phase3_runner");
        let error = parse_report_value(raw).unwrap_err();
        assert_eq!(
            error,
            FieldAllowlistError::UnknownSourceTag("phase3_runner".to_owned())
        );
    }

    #[test]
    fn invalid_rtt_bucket_value_is_classified() {
        let mut raw = valid_report();
        raw["rtt_bucket"] = json!("rtt_37");
        let error = parse_report_value(raw).unwrap_err();
        assert_eq!(
            error,
            FieldAllowlistError::InvalidRttBucket("rtt_37".to_owned())
        );
    }

    #[test]
    fn invalid_asn_class_value_is_classified() {
        let mut raw = valid_report();
        raw["asn_class"] = json!("giant");
        let error = parse_report_value(raw).unwrap_err();
        assert_eq!(
            error,
            FieldAllowlistError::InvalidAsnClass("giant".to_owned())
        );
    }

    #[test]
    fn invalid_outcome_value_is_classified() {
        let mut raw = valid_report();
        raw["outcome"] = json!("maybe");
        let error = parse_report_value(raw).unwrap_err();
        assert_eq!(
            error,
            FieldAllowlistError::InvalidOutcome("maybe".to_owned())
        );
    }

    #[test]
    fn malformed_token_is_classified() {
        let mut raw = valid_report();
        raw["token"] = json!("not-a-token");
        let error = parse_report_value(raw).unwrap_err();
        assert_eq!(error.kind_name(), "malformed_token");
    }

    #[test]
    fn non_object_payload_is_rejected() {
        let error = parse_report_value(json!(["not", "an", "object"])).unwrap_err();
        assert_eq!(error, FieldAllowlistError::InvalidPayload);
    }

    #[test]
    fn raw_string_parse_round_trips() {
        let report = parse_report(&valid_report().to_string()).unwrap();
        assert_eq!(report.outcome, tbc_agent::Outcome::Success);
    }
}

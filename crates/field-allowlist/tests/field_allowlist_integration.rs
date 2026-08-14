//! End-to-end integration tests for the field-allowlist boundary, including
//! the adversarial raw-payload cases the Phase-2 contract demands: exact IP,
//! exact ASN, and raw timestamps must be rejected at the deserialization
//! boundary before any downstream logic can see them.

use serde_json::json;
use tbc_field_allowlist::{parse_report_value, FieldAllowlistError, Token, TokenRegistry};

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
fn a_fully_allowlisted_report_passes_and_round_trips() {
    let report = parse_report_value(valid_report()).expect("allowlisted report must be accepted");
    assert_eq!(report.source.tag(), "phase5_volunteer");
    assert_eq!(report.asn_class, tbc_agent::AsnClass::Large);

    // Serialization can only ever emit the five allowlisted fields.
    let out = serde_json::to_value(&report).unwrap();
    let mut keys: Vec<&str> = out
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["asn_class", "outcome", "rtt_bucket", "source", "token"]
    );
}

#[test]
fn raw_ip_in_the_payload_is_rejected_before_any_downstream_use() {
    let mut raw = valid_report();
    raw["ip"] = json!("95.216.217.25");
    let error = parse_report_value(raw).expect_err("raw IP must be rejected at the boundary");
    assert_eq!(
        error,
        FieldAllowlistError::DisallowedField {
            name: "ip".to_owned()
        }
    );
}

#[test]
fn raw_asn_in_the_payload_is_rejected() {
    let mut raw = valid_report();
    raw["asn"] = json!(24940);
    let error = parse_report_value(raw).expect_err("raw ASN must be rejected at the boundary");
    assert_eq!(
        error,
        FieldAllowlistError::DisallowedField {
            name: "asn".to_owned()
        }
    );
}

#[test]
fn raw_timestamp_in_the_payload_is_rejected() {
    let mut raw = valid_report();
    raw["recorded_at"] = json!("2026-08-14T15:00:00Z");
    let error = parse_report_value(raw).expect_err("raw timestamp must be rejected");
    assert_eq!(
        error,
        FieldAllowlistError::DisallowedField {
            name: "recorded_at".to_owned()
        }
    );
}

#[test]
fn raw_rtt_ms_in_the_payload_is_rejected() {
    let mut raw = valid_report();
    raw["rtt_ms"] = json!(64);
    let error = parse_report_value(raw).expect_err("raw RTT must be rejected");
    assert_eq!(
        error,
        FieldAllowlistError::DisallowedField {
            name: "rtt_ms".to_owned()
        }
    );
}

#[test]
fn a_phase4_report_is_allowlisted_with_its_source_tag() {
    let mut raw = valid_report();
    raw["source"] = json!("phase4_ci_runner");
    let report = parse_report_value(raw).expect("phase4 tag is part of the allowlist");
    assert_eq!(report.source.tag(), "phase4_ci_runner");
}

#[test]
fn an_unknown_source_tag_is_rejected() {
    let mut raw = valid_report();
    raw["source"] = json!("phase3_runner");
    let error = parse_report_value(raw).expect_err("off-domain source tag must be rejected");
    assert_eq!(
        error,
        FieldAllowlistError::UnknownSourceTag("phase3_runner".to_owned())
    );
}

#[test]
fn an_off_domain_rtt_bucket_is_rejected() {
    let mut raw = valid_report();
    raw["rtt_bucket"] = json!("rtt_37");
    let error = parse_report_value(raw).expect_err("off-domain bucket must be rejected");
    assert_eq!(
        error,
        FieldAllowlistError::InvalidRttBucket("rtt_37".to_owned())
    );
}

#[test]
fn an_off_domain_asn_class_is_rejected() {
    let mut raw = valid_report();
    raw["asn_class"] = json!("giant");
    let error = parse_report_value(raw).expect_err("off-domain class must be rejected");
    assert_eq!(
        error,
        FieldAllowlistError::InvalidAsnClass("giant".to_owned())
    );
}

#[test]
fn a_malformed_token_is_rejected() {
    let mut raw = valid_report();
    raw["token"] = json!("not-a-valid-token");
    let error = parse_report_value(raw).expect_err("malformed token must be rejected");
    assert_eq!(error.kind_name(), "malformed_token");
}

#[test]
fn a_missing_required_field_is_rejected() {
    let mut raw = valid_report();
    raw.as_object_mut().unwrap().remove("source");
    let error = parse_report_value(raw).expect_err("missing required field must be rejected");
    assert_eq!(error.kind_name(), "invalid_json");
}

#[test]
fn token_reuse_is_rejected_after_first_use() {
    let mut registry = TokenRegistry::new();
    let token = Token::from_upstream(&tbc_agent::OneTimeToken::generate()).unwrap();

    assert!(
        registry.consume(&token).is_ok(),
        "first use consumes the token"
    );
    let error = registry
        .consume(&token)
        .expect_err("a second use of the same token must be rejected");
    assert_eq!(error.kind_name(), "reused_token");
    assert!(registry.is_consumed(&token));
}

#[test]
fn two_reports_sharing_one_token_cannot_both_pass() {
    // The full path a replay attack takes: the same token in two reports.
    let mut second = valid_report();
    second["token"] = valid_report()["token"].clone();

    let first_report = parse_report_value(valid_report()).expect("first report is allowlisted");
    let second_report = parse_report_value(second).expect("second report is allowlisted");

    let mut registry = TokenRegistry::new();
    assert!(registry.consume(&first_report.token).is_ok());
    let error = registry
        .consume(&second_report.token)
        .expect_err("replayed token must be rejected");
    assert_eq!(error.kind_name(), "reused_token");
}

#[test]
fn a_real_producer_report_serializes_into_allowlisted_shape() {
    // Real integration: an actual tbc-agent AnonymizedReport (Serialize-only
    // upstream) round-trips through the allowlist boundary unchanged.
    let upstream =
        tbc_agent::AnonymizedReport::new(&tbc_core::Verdict::Reachable, Some(64), Some(197_207));
    let wire = serde_json::to_string(&upstream).unwrap();
    let report = parse_report_value(serde_json::from_str(&wire).unwrap())
        .expect("a real producer report must pass the boundary");
    assert_eq!(report.outcome, tbc_agent::Outcome::Success);
    assert_eq!(report.rtt_bucket, tbc_agent::RttBucket::Rtt50To150);
    assert_eq!(report.asn_class, tbc_agent::AsnClass::Large);
    assert_eq!(report.source, tbc_agent::ReportSource::Phase5Volunteer);
}

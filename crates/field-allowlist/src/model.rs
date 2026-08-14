//! The allowlisted report model: the *only* shape a report may take.
//!
//! The field-value domains are the real `tbc-agent` producer types, so the
//! wire contract is defined once, upstream, and enforced here at the
//! ingestion boundary. `#[serde(deny_unknown_fields)]` makes the field set a
//! compiled contract: any extra key fails deserialization instead of being
//! silently dropped.

use serde::{Deserialize, Serialize};
use tbc_agent::{AsnClass, Outcome, ReportSource, RttBucket};

use crate::token::Token;

/// A report that passed the field allowlist.
///
/// Exactly five fields, in the Phase-5 field-limited shape:
/// outcome, coarse RTT bucket, coarse ASN class, one-time token, and the
/// Phase-4/Phase-5 source tag. Nothing else can be deserialized into it, and
/// nothing else can be serialized out of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistedReport {
    /// Collapsed verdict: `success` or `failure` only.
    pub outcome: Outcome,
    /// Coarse RTT bucket — the raw millisecond value is not part of the
    /// contract and cannot be deserialized.
    pub rtt_bucket: RttBucket,
    /// Coarse ASN class — the exact ASN is not part of the contract.
    pub asn_class: AsnClass,
    /// One-time unlinkable token (validated: 32 lowercase hex digits).
    pub token: Token,
    /// Phase-4 vs Phase-5 source tag.
    pub source: ReportSource,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_model_has_exactly_the_five_allowlisted_fields() {
        // A structurally complete, allowlisted report deserializes…
        let raw = json!({
            "outcome": "success",
            "rtt_bucket": "rtt_50_150",
            "asn_class": "large",
            "token": "0123456789abcdef0123456789abcdef",
            "source": "phase5_volunteer",
        });
        let report: AllowlistedReport = serde_json::from_value(raw).unwrap();
        assert_eq!(report.outcome, Outcome::Success);
        assert_eq!(report.rtt_bucket, RttBucket::Rtt50To150);
        assert_eq!(report.asn_class, AsnClass::Large);
        assert_eq!(report.source, ReportSource::Phase5Volunteer);

        // …and serializes back to exactly those five keys — the type has no
        // place for anything else.
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
    fn deny_unknown_fields_rejects_an_extra_key() {
        let raw = json!({
            "outcome": "success",
            "rtt_bucket": "rtt_50_150",
            "asn_class": "large",
            "token": "0123456789abcdef0123456789abcdef",
            "source": "phase5_volunteer",
            "ip": "95.216.217.25",
        });
        let error = serde_json::from_value::<AllowlistedReport>(raw).unwrap_err();
        assert!(error.to_string().contains("unknown field `ip`"));
    }

    #[test]
    fn off_domain_field_values_are_rejected_by_the_typed_backstop() {
        let raw = json!({
            "outcome": "success",
            "rtt_bucket": "rtt_37",
            "asn_class": "large",
            "token": "0123456789abcdef0123456789abcdef",
            "source": "phase5_volunteer",
        });
        assert!(serde_json::from_value::<AllowlistedReport>(raw).is_err());
    }
}

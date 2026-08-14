//! The field-limited Phase-5 anonymized report.
//!
//! This is the only data the volunteer agent emits upstream. It is derived
//! from a raw measurement but drops everything fingerprintable: no raw RTT,
//! no full ASN or IP, no evidence strings, no measurement identifiers. What
//! remains is an outcome, a coarse RTT bucket, a coarse ASN class, a fresh
//! one-time unlinkable token, and the Phase-4/Phase-5 source tag that keeps
//! volunteer verdicts from ever being merged with CI-runner verdicts without
//! an explicit marker.

use serde::{Deserialize, Serialize};
use tbc_core::Verdict;

use crate::protocol::ProbeResponse;

/// Who produced a verdict. Phase 5 verdicts come from volunteer in-country
/// agents; Phase 4 verdicts come from CI runners. The tag must be present on
/// every report so the two can never be merged by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSource {
    /// A volunteer in-country agent (Phase 5).
    Phase5Volunteer,
    /// A CI-runner probe (Phase 4) — never produced by this binary, but part
    /// of the shared schema so the two classes stay explicitly separated.
    Phase4CiRunner,
}

impl ReportSource {
    /// The wire tag for this source class.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Phase5Volunteer => "phase5_volunteer",
            Self::Phase4CiRunner => "phase4_ci_runner",
        }
    }
}

/// Success or failure — the full verdict taxonomy is deliberately collapsed
/// so no per-bridge fingerprint leaves the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
}

impl Outcome {
    /// A probe is a success only if the target was reached.
    pub fn from_verdict(verdict: &Verdict) -> Self {
        if matches!(verdict, Verdict::Reachable) {
            Self::Success
        } else {
            Self::Failure
        }
    }

    /// Map a verdict token from a [`ProbeResponse`].
    pub fn from_verdict_token(token: &str) -> Self {
        if token == "reachable" {
            Self::Success
        } else {
            Self::Failure
        }
    }
}

/// A coarse round-trip-time bucket. Raw RTT is never emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RttBucket {
    #[serde(rename = "rtt_0_50")]
    Rtt0To50,
    #[serde(rename = "rtt_50_150")]
    Rtt50To150,
    #[serde(rename = "rtt_150_400")]
    Rtt150To400,
    #[serde(rename = "rtt_400_1000")]
    Rtt400To1000,
    #[serde(rename = "rtt_1000_plus")]
    Rtt1000Plus,
    #[serde(rename = "rtt_unknown")]
    Unknown,
}

impl RttBucket {
    /// Bucket a raw RTT in milliseconds.
    pub fn from_rtt_ms(rtt_ms: Option<u64>) -> Self {
        match rtt_ms {
            None => Self::Unknown,
            Some(ms) if ms <= 50 => Self::Rtt0To50,
            Some(ms) if ms <= 150 => Self::Rtt50To150,
            Some(ms) if ms <= 400 => Self::Rtt150To400,
            Some(ms) if ms <= 1000 => Self::Rtt400To1000,
            Some(_) => Self::Rtt1000Plus,
        }
    }
}

/// A coarse autonomous-system class. The exact ASN (and any IP) is never
/// emitted; only this magnitude class leaves the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsnClass {
    Small,
    Medium,
    Large,
    Unknown,
}

impl AsnClass {
    /// Coarsen an ASN (or its absence) into a class.
    pub fn from_asn(asn: Option<u32>) -> Self {
        match asn {
            None => Self::Unknown,
            Some(asn) if asn < 1_000 => Self::Small,
            Some(asn) if asn < 10_000 => Self::Medium,
            Some(_) => Self::Large,
        }
    }
}

/// A fresh, one-time, unlinkable token. It is random, carries no identifier
/// of the volunteer, and is never reused across reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct OneTimeToken(String);

impl OneTimeToken {
    /// Generate a new 128-bit random token, hex-encoded.
    pub fn generate() -> Self {
        use rand::Rng;
        let bytes: [u8; 16] = rand::thread_rng().gen();
        Self(hex(&bytes))
    }

    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The anonymized, field-limited report emitted upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnonymizedReport {
    /// Success or failure only.
    pub outcome: Outcome,
    /// Coarse RTT bucket, never the raw millisecond value.
    pub rtt_bucket: RttBucket,
    /// Coarse ASN class, never the full ASN or IP.
    pub asn_class: AsnClass,
    /// One-time unlinkable token.
    pub token: OneTimeToken,
    /// Phase-4 vs Phase-5 source tag.
    pub source: ReportSource,
}

impl AnonymizedReport {
    /// Build an anonymized report from a raw verdict and RTT, taking the
    /// coarse ASN class from an optional known ASN.
    pub fn new(verdict: &Verdict, rtt_ms: Option<u64>, asn: Option<u32>) -> Self {
        Self {
            outcome: Outcome::from_verdict(verdict),
            rtt_bucket: RttBucket::from_rtt_ms(rtt_ms),
            asn_class: AsnClass::from_asn(asn),
            token: OneTimeToken::generate(),
            source: ReportSource::Phase5Volunteer,
        }
    }

    /// Build an anonymized report from a raw probe response. The agent reports
    /// [`AsnClass::Unknown`] when it has no ASN for the target.
    pub fn from_probe_response(response: &ProbeResponse, asn: Option<u32>) -> Self {
        Self {
            outcome: Outcome::from_verdict_token(&response.verdict),
            rtt_bucket: RttBucket::from_rtt_ms(response.rtt_ms),
            asn_class: AsnClass::from_asn(asn),
            token: OneTimeToken::generate(),
            source: ReportSource::Phase5Volunteer,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rtt_is_bucketed_not_emitted_raw() {
        assert_eq!(RttBucket::from_rtt_ms(Some(50)), RttBucket::Rtt0To50);
        assert_eq!(RttBucket::from_rtt_ms(Some(64)), RttBucket::Rtt50To150);
        assert_eq!(RttBucket::from_rtt_ms(Some(400)), RttBucket::Rtt150To400);
        assert_eq!(RttBucket::from_rtt_ms(Some(1000)), RttBucket::Rtt400To1000);
        assert_eq!(RttBucket::from_rtt_ms(Some(1001)), RttBucket::Rtt1000Plus);
        assert_eq!(RttBucket::from_rtt_ms(None), RttBucket::Unknown);
    }

    #[test]
    fn asn_is_classed_not_emitted_raw() {
        assert_eq!(AsnClass::from_asn(Some(512)), AsnClass::Small);
        assert_eq!(AsnClass::from_asn(Some(5_000)), AsnClass::Medium);
        assert_eq!(AsnClass::from_asn(Some(197_207)), AsnClass::Large);
        assert_eq!(AsnClass::from_asn(None), AsnClass::Unknown);
    }

    #[test]
    fn tokens_are_one_time_and_unlinkable() {
        let a = OneTimeToken::generate();
        let b = OneTimeToken::generate();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 32);
        assert!(a.as_str().bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn enums_deserialize_from_their_exact_wire_values() {
        // The field-allowlist boundary deserializes these producer types; the
        // wire contract is defined here, so this round-trip pins it.
        let source: ReportSource = serde_json::from_str("\"phase5_volunteer\"").unwrap();
        assert_eq!(source, ReportSource::Phase5Volunteer);
        let source: ReportSource = serde_json::from_str("\"phase4_ci_runner\"").unwrap();
        assert_eq!(source, ReportSource::Phase4CiRunner);
        assert!(serde_json::from_str::<ReportSource>("\"phase3_runner\"").is_err());

        let outcome: Outcome = serde_json::from_str("\"success\"").unwrap();
        assert_eq!(outcome, Outcome::Success);
        assert!(serde_json::from_str::<Outcome>("\"maybe\"").is_err());

        let bucket: RttBucket = serde_json::from_str("\"rtt_150_400\"").unwrap();
        assert_eq!(bucket, RttBucket::Rtt150To400);
        assert!(serde_json::from_str::<RttBucket>("\"rtt_37\"").is_err());

        let class: AsnClass = serde_json::from_str("\"small\"").unwrap();
        assert_eq!(class, AsnClass::Small);
        assert!(serde_json::from_str::<AsnClass>("\"giant\"").is_err());
    }

    #[test]
    fn reports_carry_the_phase5_source_tag() {
        let report = AnonymizedReport::new(&Verdict::Reachable, Some(10), None);
        assert_eq!(report.source, ReportSource::Phase5Volunteer);
        assert_eq!(report.source.tag(), "phase5_volunteer");
        assert_eq!(ReportSource::Phase4CiRunner.tag(), "phase4_ci_runner");
        assert_ne!(report.source, ReportSource::Phase4CiRunner);
    }

    #[test]
    fn report_serializes_only_the_allowlisted_fields() {
        let report = AnonymizedReport::new(&Verdict::Reachable, Some(64), Some(197_207));
        let json = serde_json::to_value(&report).unwrap();
        let object = json.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["asn_class", "outcome", "rtt_bucket", "source", "token"]
        );
        assert_eq!(object["outcome"], "success");
        assert_eq!(object["rtt_bucket"], "rtt_50_150");
        assert_eq!(object["asn_class"], "large");
        assert_eq!(object["source"], "phase5_volunteer");
        // Nothing fingerprintable may leak through: no raw RTT, ASN, IP,
        // evidence, or measurement identifier.
        for forbidden in ["rtt_ms", "asn", "ip", "evidence", "measurement_ref"] {
            assert!(object.get(forbidden).is_none(), "leaked {forbidden}");
        }
    }

    #[test]
    fn from_probe_response_collapses_to_success_or_failure() {
        let reachable = ProbeResponse {
            verdict: "reachable".to_owned(),
            rtt_ms: Some(10),
            error_class: None,
            evidence: None,
            measurement_ref: "agent-0".to_owned(),
            http_status: None,
        };
        let report = AnonymizedReport::from_probe_response(&reachable, None);
        assert_eq!(report.outcome, Outcome::Success);
        assert_eq!(report.rtt_bucket, RttBucket::Rtt0To50);
        assert_eq!(report.asn_class, AsnClass::Unknown);

        let refused = ProbeResponse {
            verdict: "refused".to_owned(),
            rtt_ms: None,
            error_class: Some("connection_refused".to_owned()),
            evidence: Some("connection refused".to_owned()),
            measurement_ref: "agent-1".to_owned(),
            http_status: None,
        };
        let report = AnonymizedReport::from_probe_response(&refused, None);
        assert_eq!(report.outcome, Outcome::Failure);
    }
}

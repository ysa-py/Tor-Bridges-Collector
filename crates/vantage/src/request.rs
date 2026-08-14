//! The measurement request/result model and its mapping into the core
//! observation model.

use chrono::{DateTime, Utc};

use tbc_core::{EvasionProfile, Observation, ProbeKind, Vantage, Verdict};

/// A request to observe one bridge target from a vantage point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurementRequest {
    /// The bridge target (IP literal or DNS name), without a port.
    pub target: String,
    /// The bridge TCP port (informational for ping-style platforms).
    pub port: u16,
    /// The probe kind the request is asking the platform to approximate.
    pub probe_kind: ProbeKind,
    /// Preferred measurement country, if the platform supports selection.
    pub country: Option<String>,
    /// Preferred probe ASN, if the platform supports selection.
    pub asn: Option<u32>,
}

/// The outcome of one vantage measurement, normalized across platforms.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeResult {
    /// The normalized verdict.
    pub verdict: Verdict,
    /// Round-trip time in milliseconds, if the platform measured one.
    pub rtt_ms: Option<u64>,
    /// A classified error code, if the verdict is not reachable.
    pub error_class: Option<String>,
    /// Raw, unredacted platform evidence.
    pub raw_evidence: Option<String>,
    /// The platform's measurement identifier.
    pub measurement_ref: String,
    /// When the measurement was taken.
    pub measured_at: DateTime<Utc>,
}

/// Convert a normalized [`ProbeResult`] into an [`Observation`], attaching
/// the bridge key, the vantage metadata, and the probe kind.
pub fn to_observation(
    result: &ProbeResult,
    bridge_key: &str,
    vantage: Vantage,
    probe_kind: ProbeKind,
) -> Observation {
    Observation {
        bridge_key: bridge_key.to_owned(),
        vantage,
        probe_kind,
        evasion_profile: EvasionProfile::None,
        verdict: result.verdict.clone(),
        rtt_ms: result.rtt_ms,
        bootstrap_pct: None,
        error_class: result.error_class.clone(),
        raw_evidence: result.raw_evidence.clone(),
        measured_at: result.measured_at,
        measurement_ref: Some(result.measurement_ref.clone()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tbc_core::VantageKind;

    #[test]
    fn to_observation_maps_all_fields() {
        let result = ProbeResult {
            verdict: Verdict::Reachable,
            rtt_ms: Some(64),
            error_class: None,
            raw_evidence: Some("64 bytes from 1.2.3.4".to_owned()),
            measurement_ref: "gp-123".to_owned(),
            measured_at: DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let vantage = Vantage {
            kind: VantageKind::Globalping,
            country: Some("IR".to_owned()),
            asn: None,
            as_name: None,
            is_mobile: false,
        };
        let observation = to_observation(
            &result,
            "obfs4|1.2.3.4|443||",
            vantage.clone(),
            ProbeKind::TcpConnect,
        );
        assert_eq!(observation.bridge_key, "obfs4|1.2.3.4|443||");
        assert_eq!(observation.vantage, vantage);
        assert_eq!(observation.probe_kind, ProbeKind::TcpConnect);
        assert_eq!(observation.verdict, Verdict::Reachable);
        assert_eq!(observation.rtt_ms, Some(64));
        assert_eq!(observation.measurement_ref.as_deref(), Some("gp-123"));
    }
}

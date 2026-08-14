//! Probe outcomes and their mapping into the core observation model.
//!
//! A single attempt yields either a [`ProbeDetail`] (success) or a
//! [`ProbeError`]; the [`crate::Prober`] folds retries into one
//! [`ProbeOutcome`] per bridge, and [`to_observation`] turns a
//! [`BridgeProbeResult`] into a [`tbc_core::Observation`] for the store and
//! scoring crates.

use chrono::{DateTime, Utc};

use tbc_core::{Observation, ProbeKind, TransportKind, Vantage, Verdict};

use crate::error::ProbeError;

/// Details of a successful (reachable) probe attempt.
#[derive(Debug, Clone)]
pub struct ProbeDetail {
    /// Human-readable, metric-safe evidence of what was verified.
    pub evidence: Option<String>,
    /// Round-trip time in milliseconds, if measured.
    pub rtt_ms: Option<u64>,
}

/// The final, retry-folded outcome for one bridge.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    /// The probe verdict.
    pub verdict: Verdict,
    /// Round-trip time in milliseconds, if the bridge was reached.
    pub rtt_ms: Option<u64>,
    /// A classified error code, if the probe did not reach the bridge.
    pub error_class: Option<String>,
    /// Human-readable evidence of the verdict.
    pub evidence: Option<String>,
}

impl ProbeOutcome {
    /// Build a reachable outcome from a successful attempt.
    pub fn reachable(detail: ProbeDetail) -> Self {
        Self {
            verdict: Verdict::Reachable,
            rtt_ms: detail.rtt_ms,
            error_class: None,
            evidence: detail.evidence,
        }
    }

    /// Build an outcome from a classified failure.
    pub fn from_error(error: &ProbeError) -> Self {
        Self {
            verdict: error.verdict(),
            rtt_ms: None,
            error_class: Some(error.kind_name().to_owned()),
            evidence: Some(error.to_string()),
        }
    }
}

/// The outcome of probing one bridge.
#[derive(Debug, Clone)]
pub struct BridgeProbeResult {
    /// The canonical dedupe key of the measured bridge.
    pub bridge_key: String,
    /// The measured transport family.
    pub transport: TransportKind,
    /// The final outcome.
    pub outcome: ProbeOutcome,
    /// How many probe attempts were actually performed.
    pub attempts: u32,
}

/// A whole-run probe summary, including quota-budget accounting.
#[derive(Debug, Clone, Default)]
pub struct ProbeReport {
    /// Per-bridge results, in input order.
    pub results: Vec<BridgeProbeResult>,
    /// Whether the per-run bridge budget was exhausted before all inputs ran.
    pub budget_exhausted: bool,
    /// How many inputs were skipped due to the budget.
    pub skipped: usize,
}

/// The [`ProbeKind`] that best describes the probe run for a transport.
pub fn probe_kind_for(transport: &TransportKind) -> ProbeKind {
    match transport {
        TransportKind::Obfs4 => ProbeKind::Obfs4Handshake,
        TransportKind::WebTunnel => ProbeKind::WebTunnelUpgrade,
        TransportKind::Vanilla | TransportKind::Snowflake | TransportKind::Meek => {
            ProbeKind::TcpConnect
        }
        TransportKind::Conjure | TransportKind::Other(_) => ProbeKind::TcpConnect,
    }
}

/// Convert a probe result into an [`Observation`], deriving the probe kind
/// from the measured transport.
pub fn to_observation(
    result: &BridgeProbeResult,
    vantage: Vantage,
    measured_at: DateTime<Utc>,
    measurement_ref: Option<String>,
) -> Observation {
    Observation {
        bridge_key: result.bridge_key.clone(),
        vantage,
        probe_kind: probe_kind_for(&result.transport),
        evasion_profile: tbc_core::EvasionProfile::None,
        verdict: result.outcome.verdict.clone(),
        rtt_ms: result.outcome.rtt_ms,
        bootstrap_pct: None,
        error_class: result.outcome.error_class.clone(),
        raw_evidence: result.outcome.evidence.clone(),
        measured_at,
        measurement_ref,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tbc_core::{VantageKind, Verdict};

    fn outcome() -> ProbeOutcome {
        ProbeOutcome {
            verdict: Verdict::Reachable,
            rtt_ms: Some(120),
            error_class: None,
            evidence: Some("vanilla: VERSIONS + NETINFO handshake completed".to_owned()),
        }
    }

    fn result() -> BridgeProbeResult {
        BridgeProbeResult {
            bridge_key: "vanilla|1.2.3.4|9001||".to_owned(),
            transport: TransportKind::Vanilla,
            outcome: outcome(),
            attempts: 1,
        }
    }

    #[test]
    fn reachable_outcome_has_no_error_class() {
        let outcome = ProbeOutcome::reachable(ProbeDetail {
            evidence: Some("ok".to_owned()),
            rtt_ms: Some(10),
        });
        assert_eq!(outcome.verdict, Verdict::Reachable);
        assert_eq!(outcome.rtt_ms, Some(10));
        assert!(outcome.error_class.is_none());
    }

    #[test]
    fn error_outcome_carries_classified_code() {
        let outcome = ProbeOutcome::from_error(&ProbeError::Refused);
        assert_eq!(outcome.verdict, Verdict::Refused);
        assert_eq!(outcome.error_class.as_deref(), Some("connection_refused"));
        assert!(outcome.evidence.is_some());
    }

    #[test]
    fn probe_kind_maps_transports() {
        assert_eq!(
            probe_kind_for(&TransportKind::Obfs4),
            ProbeKind::Obfs4Handshake
        );
        assert_eq!(
            probe_kind_for(&TransportKind::WebTunnel),
            ProbeKind::WebTunnelUpgrade
        );
        assert_eq!(
            probe_kind_for(&TransportKind::Vanilla),
            ProbeKind::TcpConnect
        );
    }

    #[test]
    fn to_observation_maps_all_fields() {
        let vantage = Vantage {
            kind: VantageKind::Runner,
            country: Some("DE".to_owned()),
            asn: Some(24_981),
            as_name: Some("TEST".to_owned()),
            is_mobile: false,
        };
        let measured_at = DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let observation = to_observation(
            &result(),
            vantage.clone(),
            measured_at,
            Some("probe-1".to_owned()),
        );
        assert_eq!(observation.bridge_key, "vanilla|1.2.3.4|9001||");
        assert_eq!(observation.probe_kind, ProbeKind::TcpConnect);
        assert_eq!(observation.verdict, Verdict::Reachable);
        assert_eq!(observation.rtt_ms, Some(120));
        assert_eq!(observation.vantage, vantage);
        assert_eq!(observation.measurement_ref.as_deref(), Some("probe-1"));
        assert_eq!(observation.measured_at, measured_at);
    }
}

//! Verdict valuation and evidence classification.
//!
//! These are the only places where a raw [`tbc_core::Verdict`] is turned into a
//! numeric value or a probe is mapped to an evidence class, so the scoring
//! formula in [`crate::engine`] stays a single, documented transformation.

use tbc_core::{ProbeKind, Verdict};

use crate::config::ClassWeights;

/// Values strictly above this threshold count as "the bridge worked from this
/// vantage point". [`tbc_core::Verdict::Inconclusive`] (0.5) is deliberately
/// *at* the threshold, not above it: inconclusive evidence must never count as
/// a working confirmation.
pub const WORKING_THRESHOLD: f64 = 0.5;

/// The contribution of a verdict to the working score, in `0.0..=1.0`.
///
/// | Verdict | Value | Rationale |
/// |---|---|---|
/// | `Reachable` | 1.0 | Full success |
/// | `TlsAlert` | 0.2 | TLS was reached but intercepted/misconfigured |
/// | `HttpError { code < 500 }` | 0.4 | Front reached, upgrade/request rejected |
/// | `Inconclusive` | 0.5 | No signal either way |
/// | `HttpError { code >= 500 }` | 0.0 | Server-side failure |
/// | everything else | 0.0 | Refused, timeout, RST, auth fail, DNS fail, blocked |
pub fn verdict_value(verdict: &Verdict) -> f64 {
    match verdict {
        Verdict::Reachable => 1.0,
        Verdict::TlsAlert => 0.2,
        Verdict::HttpError { code } if *code < 500 => 0.4,
        Verdict::HttpError { .. } => 0.0,
        Verdict::Inconclusive => 0.5,
        Verdict::Refused
        | Verdict::Timeout
        | Verdict::ResetInjected
        | Verdict::HandshakeAuthFail
        | Verdict::DnsFailure
        | Verdict::Blocked { .. } => 0.0,
    }
}

/// The value of a single observation.
///
/// A `TorBootstrap` probe carries ground-truth progression: when
/// `bootstrap_pct` is present it *is* the value (clamped to `0.0..=1.0`),
/// regardless of the coarse verdict. Otherwise the verdict value applies.
pub fn observation_value(
    probe_kind: ProbeKind,
    verdict: &Verdict,
    bootstrap_pct: Option<u8>,
) -> f64 {
    if probe_kind == ProbeKind::TorBootstrap {
        if let Some(pct) = bootstrap_pct {
            return (pct as f64 / 100.0).clamp(0.0, 1.0);
        }
    }
    verdict_value(verdict)
}

/// The evidence-class weight of a probe kind.
///
/// Handshake-class (highest) > TCP-class > path-class, per the master spec.
pub fn class_weight(probe_kind: ProbeKind, weights: &ClassWeights) -> f64 {
    match probe_kind {
        ProbeKind::Obfs4Handshake | ProbeKind::WebTunnelUpgrade | ProbeKind::TorBootstrap => {
            weights.handshake
        }
        ProbeKind::TcpConnect | ProbeKind::TlsSni => weights.tcp,
        ProbeKind::TcpTraceroute => weights.path,
    }
}

/// Whether a verdict is active-blocking evidence (`Blocked` or an injected
/// RST), as opposed to "offline" evidence (`Refused`, `Timeout`).
///
/// Only active-blocking verdicts feed the burn-rate penalty, so an offline
/// bridge is never mistaken for a burned one.
pub fn is_blocking_verdict(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Blocked { .. } | Verdict::ResetInjected)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn verdict_values_match_the_documented_table() {
        assert_eq!(verdict_value(&Verdict::Reachable), 1.0);
        assert_eq!(verdict_value(&Verdict::TlsAlert), 0.2);
        assert_eq!(verdict_value(&Verdict::HttpError { code: 403 }), 0.4);
        assert_eq!(verdict_value(&Verdict::HttpError { code: 500 }), 0.0);
        assert_eq!(verdict_value(&Verdict::Inconclusive), 0.5);
        assert_eq!(verdict_value(&Verdict::Refused), 0.0);
        assert_eq!(verdict_value(&Verdict::Timeout), 0.0);
        assert_eq!(verdict_value(&Verdict::ResetInjected), 0.0);
        assert_eq!(verdict_value(&Verdict::HandshakeAuthFail), 0.0);
        assert_eq!(verdict_value(&Verdict::DnsFailure), 0.0);
        assert_eq!(
            verdict_value(&Verdict::Blocked {
                evidence: "SYN drop".to_owned()
            }),
            0.0
        );
    }

    #[test]
    fn bootstrap_pct_is_ground_truth() {
        assert_eq!(
            observation_value(ProbeKind::TorBootstrap, &Verdict::Reachable, Some(80)),
            0.8
        );
        // u8 can exceed 100; clamp to 1.0.
        assert_eq!(
            observation_value(ProbeKind::TorBootstrap, &Verdict::Reachable, Some(200)),
            1.0
        );
        // Missing pct falls back to the verdict value.
        assert_eq!(
            observation_value(ProbeKind::TorBootstrap, &Verdict::Reachable, None),
            1.0
        );
        assert_eq!(
            observation_value(ProbeKind::TorBootstrap, &Verdict::Inconclusive, None),
            0.5
        );
        // Non-bootstrap probes ignore the pct field.
        assert_eq!(
            observation_value(ProbeKind::Obfs4Handshake, &Verdict::Reachable, Some(80)),
            1.0
        );
    }

    #[test]
    fn probe_kinds_map_to_classes() {
        let weights = ClassWeights::default();
        assert_eq!(
            class_weight(ProbeKind::Obfs4Handshake, &weights),
            weights.handshake
        );
        assert_eq!(
            class_weight(ProbeKind::WebTunnelUpgrade, &weights),
            weights.handshake
        );
        assert_eq!(
            class_weight(ProbeKind::TorBootstrap, &weights),
            weights.handshake
        );
        assert_eq!(class_weight(ProbeKind::TcpConnect, &weights), weights.tcp);
        assert_eq!(class_weight(ProbeKind::TlsSni, &weights), weights.tcp);
        assert_eq!(
            class_weight(ProbeKind::TcpTraceroute, &weights),
            weights.path
        );
    }

    #[test]
    fn only_active_blocking_verdicts_are_blocking() {
        assert!(is_blocking_verdict(&Verdict::Blocked {
            evidence: "x".to_owned()
        }));
        assert!(is_blocking_verdict(&Verdict::ResetInjected));
        assert!(!is_blocking_verdict(&Verdict::Refused));
        assert!(!is_blocking_verdict(&Verdict::Timeout));
        assert!(!is_blocking_verdict(&Verdict::Reachable));
    }
}

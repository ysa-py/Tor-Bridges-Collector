//! Property-based tests for the scoring engine.
//!
//! The strategies build arbitrary observation streams (including stale ones
//! that the engine must drop) and assert the invariants that must hold for
//! *every* input: scores in range, k <= n, deterministic output, and
//! monotonic tier mapping.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;
use tbc_core::{EvasionProfile, Observation, ProbeKind, Tier, Vantage, VantageKind, Verdict};
use tbc_score::{ScoreConfig, ScoreEngine};

fn base_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn probe_strategy() -> impl Strategy<Value = ProbeKind> {
    prop_oneof![
        Just(ProbeKind::TcpConnect),
        Just(ProbeKind::Obfs4Handshake),
        Just(ProbeKind::WebTunnelUpgrade),
        Just(ProbeKind::TorBootstrap),
        Just(ProbeKind::TlsSni),
        Just(ProbeKind::TcpTraceroute),
    ]
}

fn verdict_strategy() -> impl Strategy<Value = Verdict> {
    prop_oneof![
        Just(Verdict::Reachable),
        Just(Verdict::Refused),
        Just(Verdict::Timeout),
        Just(Verdict::ResetInjected),
        Just(Verdict::TlsAlert),
        Just(Verdict::HandshakeAuthFail),
        Just(Verdict::HttpError { code: 403 }),
        Just(Verdict::HttpError { code: 503 }),
        Just(Verdict::DnsFailure),
        Just(Verdict::Blocked {
            evidence: "r".into()
        }),
        Just(Verdict::Inconclusive),
    ]
}

fn observation_strategy() -> impl Strategy<Value = Observation> {
    let base = base_time();
    (
        probe_strategy(),
        verdict_strategy(),
        // Age up to 10 days, straddling the 7-day stale-evidence cap.
        0u64..=864_000,
        // Bootstrap percentage (may exceed 100 to exercise clamping).
        0u8..=200,
        // A small ASN pool so per-ASN groups form.
        1u32..=4,
        prop_oneof![Just(false), Just(true)],
        prop_oneof![Just(false), Just(true)],
    )
        .prop_map(
            move |(probe, verdict, age, pct, asn, is_mobile, has_pct)| Observation {
                bridge_key: "K".to_owned(),
                vantage: Vantage {
                    kind: VantageKind::Other("test".to_owned()),
                    country: None,
                    asn: Some(asn),
                    as_name: None,
                    is_mobile,
                },
                probe_kind: probe,
                evasion_profile: EvasionProfile::None,
                verdict,
                rtt_ms: None,
                bootstrap_pct: if has_pct { Some(pct) } else { None },
                error_class: None,
                raw_evidence: None,
                measured_at: base - Duration::seconds(age as i64),
                measurement_ref: None,
            },
        )
}

fn observations_strategy() -> impl Strategy<Value = Vec<Observation>> {
    prop::collection::vec(observation_strategy(), 0..24)
}

fn tier_rank(tier: Tier) -> u8 {
    match tier {
        Tier::S => 4,
        Tier::A => 3,
        Tier::B => 2,
        Tier::C => 1,
        Tier::D => 0,
    }
}

proptest! {
    #[test]
    fn scores_are_in_range_for_any_evidence(
        observations in observations_strategy()
    ) {
        let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
        let scored = engine.score("K", &observations, base_time());

        prop_assert!((0.0..=100.0).contains(&scored.score.global));
        prop_assert!((0.0..=100.0).contains(&scored.breakdown.raw));
        prop_assert!((0.0..=1.0).contains(&scored.breakdown.confidence_multiplier));
        prop_assert!((0.0..=1.0).contains(&scored.breakdown.burn_factor));
        for value in scored.score.per_asn.values() {
            prop_assert!((0.0..=100.0).contains(value));
        }
    }

    #[test]
    fn confidence_is_consistent_for_any_evidence(
        observations in observations_strategy()
    ) {
        let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
        let scored = engine.score("K", &observations, base_time());

        prop_assert!(scored.score.confidence.k <= scored.score.confidence.n);
        prop_assert!(scored.breakdown.working_vantages <= scored.breakdown.distinct_vantages);
        // Per-ASN maps only contain ASNs from the 1..=4 pool.
        for asn in scored.score.per_asn.keys() {
            prop_assert!((1..=4).contains(asn));
        }
    }

    #[test]
    fn scoring_is_deterministic(
        observations in observations_strategy()
    ) {
        let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
        let first = engine.score("K", &observations, base_time());
        let second = engine.score("K", &observations, base_time());
        prop_assert_eq!(first, second);
    }
}

#[test]
fn tier_mapping_is_monotonic() {
    let config = ScoreConfig::default();
    for left in 0..=100u32 {
        for right in 0..=100u32 {
            let left_f = left as f64;
            let right_f = right as f64;
            if left_f >= right_f {
                assert!(tier_rank(config.tier_for(left_f)) >= tier_rank(config.tier_for(right_f)));
            }
        }
    }
}

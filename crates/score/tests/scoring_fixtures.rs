//! Fixture tests for the scoring engine.
//!
//! Examples A/B/C are the worked examples from `docs/SCORING.md`; the expected
//! numbers here are computed independently from that document, not derived
//! from the engine, so a formula change that drifts from the documentation
//! fails these tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use tbc_core::{EvasionProfile, Observation, ProbeKind, Tier, Vantage, VantageKind, Verdict};
use tbc_score::{ScoreConfig, ScoreEngine, ScoredBridge};

fn t0() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn vantage(kind: VantageKind, country: &str, asn: u32, is_mobile: bool) -> Vantage {
    Vantage {
        kind,
        country: Some(country.to_owned()),
        asn: Some(asn),
        as_name: None,
        is_mobile,
    }
}

fn obs(
    bridge_key: &str,
    at: DateTime<Utc>,
    probe: ProbeKind,
    verdict: Verdict,
    vantage: Vantage,
) -> Observation {
    Observation {
        bridge_key: bridge_key.to_owned(),
        vantage,
        probe_kind: probe,
        evasion_profile: EvasionProfile::None,
        verdict,
        rtt_ms: None,
        bootstrap_pct: None,
        error_class: None,
        raw_evidence: None,
        measured_at: at,
        measurement_ref: None,
    }
}

#[test]
fn example_a_ideal_bridge_scores_perfect() {
    let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
    let now = t0();
    let observations = vec![
        obs(
            "K",
            now,
            ProbeKind::Obfs4Handshake,
            Verdict::Reachable,
            vantage(VantageKind::Runner, "DE", 1, false),
        ),
        obs(
            "K",
            now,
            ProbeKind::TcpConnect,
            Verdict::Reachable,
            vantage(VantageKind::Globalping, "US", 2, false),
        ),
        obs(
            "K",
            now,
            ProbeKind::TcpTraceroute,
            Verdict::Reachable,
            vantage(VantageKind::RipeAtlas, "NL", 3, false),
        ),
    ];
    let scored = engine.score("K", &observations, now);

    assert_eq!(scored.score.global, 100.0);
    assert_eq!(scored.score.tier, Tier::S);
    assert_eq!(scored.score.confidence.k, 3);
    assert_eq!(scored.score.confidence.n, 3);
    assert!(scored.score.burn_seconds.is_none());
    assert!(scored.score.median_lifetime_seconds.is_none());
    assert_eq!(scored.breakdown.raw, 100.0);
    assert_eq!(scored.breakdown.confidence_multiplier, 1.0);
    assert_eq!(scored.breakdown.burn_factor, 1.0);
    assert_eq!(scored.breakdown.observation_count, 3);
}

#[test]
fn example_b_freshness_decay_and_confidence() {
    let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
    let now = t0();
    let half_life = Duration::seconds(21_600);
    let observations = vec![
        obs(
            "K",
            now,
            ProbeKind::Obfs4Handshake,
            Verdict::Reachable,
            vantage(VantageKind::Runner, "DE", 1, false),
        ),
        obs(
            "K",
            now - half_life,
            ProbeKind::TcpConnect,
            Verdict::Timeout,
            vantage(VantageKind::Ooni, "IR", 197_207, true),
        ),
        obs(
            "K",
            now - half_life - half_life,
            ProbeKind::TcpTraceroute,
            Verdict::Reachable,
            vantage(VantageKind::Globalping, "US", 2, false),
        ),
    ];
    let scored = engine.score("K", &observations, now);

    // raw = 100 * 0.625 / 0.775 = 2500/31
    assert!((scored.breakdown.raw - 80.645_161_290_322_58).abs() < 1e-9);
    assert!((scored.breakdown.confidence_multiplier - (2.0 / 3.0)).abs() < 1e-9);
    // final = (2500/31) * (2/3) = 5000/93
    assert!((scored.score.global - (5000.0 / 93.0)).abs() < 1e-9);
    assert_eq!(scored.score.tier, Tier::C);
    assert_eq!(scored.score.confidence.k, 2);
    assert_eq!(scored.score.confidence.n, 3);
}

#[test]
fn example_c_burn_penalty_and_per_asn() {
    let config = ScoreConfig {
        freshness_half_life_seconds: 86_400,
        burn_horizon_seconds: 86_400,
        ..ScoreConfig::default()
    };
    let engine = ScoreEngine::new(config).unwrap();

    let now = t0();
    let working_at = now - Duration::seconds(43_200);
    let observations = vec![
        obs(
            "K",
            working_at,
            ProbeKind::Obfs4Handshake,
            Verdict::Reachable,
            vantage(VantageKind::Runner, "DE", 1, false),
        ),
        obs(
            "K",
            now,
            ProbeKind::Obfs4Handshake,
            Verdict::Blocked {
                evidence: "SYN drop after ClientHello".to_owned(),
            },
            vantage(VantageKind::Ooni, "IR", 197_207, true),
        ),
    ];
    let scored = engine.score("K", &observations, now);

    // decay = 2^(-0.5); raw = 100 * (sqrt(2) - 1) = 41.421356...
    assert!((scored.breakdown.raw - 41.421_356_237_309_51).abs() < 1e-6);
    assert_eq!(scored.breakdown.confidence_multiplier, 0.5);
    assert_eq!(scored.breakdown.burn_factor, 0.5);
    // final = 41.421356... * 0.5 * 0.5 = 10.355339...
    assert!((scored.score.global - 10.355_339_059_327_377).abs() < 1e-6);
    assert_eq!(scored.score.tier, Tier::D);
    assert_eq!(scored.score.burn_seconds, Some(43_200));
    assert_eq!(scored.score.median_lifetime_seconds, Some(43_200));
    assert_eq!(scored.score.first_confirmed_working_at, Some(working_at));
    assert_eq!(scored.score.first_blocked_at, Some(now));

    // Outside vantage works (asn 1 -> 100); Iranian vantage is blocked
    // (asn 197207 -> 0). Same bridge, opposite per-ASN verdicts.
    assert_eq!(scored.score.per_asn.get(&1).copied(), Some(100.0));
    assert_eq!(scored.score.per_asn.get(&197_207).copied(), Some(0.0));
}

#[test]
fn empty_evidence_scores_zero_with_no_confidence() {
    let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
    let scored = engine.score("K", std::iter::empty::<&Observation>(), t0());

    assert_eq!(scored.score.global, 0.0);
    assert_eq!(scored.score.tier, Tier::D);
    assert_eq!(scored.score.confidence.k, 0);
    assert_eq!(scored.score.confidence.n, 0);
    assert_eq!(scored.breakdown.raw, 0.0);
    assert_eq!(scored.breakdown.confidence_multiplier, 0.0);
    assert_eq!(scored.breakdown.observation_count, 0);
}

#[test]
fn stale_observations_are_dropped_entirely() {
    let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
    let now = t0();
    // Default max age is 7 days; this observation is 8 days old.
    let stale = obs(
        "K",
        now - Duration::seconds(8 * 24 * 60 * 60),
        ProbeKind::Obfs4Handshake,
        Verdict::Reachable,
        vantage(VantageKind::Runner, "DE", 1, false),
    );
    let scored = engine.score("K", &[stale], now);

    assert_eq!(scored.breakdown.observation_count, 0);
    assert_eq!(scored.score.global, 0.0);
    assert_eq!(scored.score.tier, Tier::D);
}

#[test]
fn minimum_confirmations_clamp_tier_above_c() {
    let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
    let now = t0();
    // Perfect handshake evidence, but from a single vantage point.
    let observations = [obs(
        "K",
        now,
        ProbeKind::Obfs4Handshake,
        Verdict::Reachable,
        vantage(VantageKind::Runner, "DE", 1, false),
    )];
    let scored = engine.score("K", &observations, now);

    // raw and final are still perfect...
    assert_eq!(scored.breakdown.raw, 100.0);
    assert_eq!(scored.score.global, 100.0);
    // ...but one confirmation is not enough to publish above tier C.
    assert_eq!(scored.score.tier, Tier::C);
    assert_eq!(scored.score.confidence.k, 1);
    assert_eq!(scored.score.confidence.n, 1);
}

#[test]
fn bootstrap_percentage_is_used_as_ground_truth() {
    let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
    let now = t0();
    let mut bootstrapped = obs(
        "K",
        now,
        ProbeKind::TorBootstrap,
        Verdict::Reachable,
        vantage(VantageKind::Runner, "DE", 1, false),
    );
    bootstrapped.bootstrap_pct = Some(80);
    let scored = engine.score("K", &[bootstrapped], now);

    assert_eq!(scored.breakdown.raw, 80.0);
    assert_eq!(scored.score.global, 80.0);
    // 80 maps to tier A, but a single working vantage is below the
    // minimum-confirmations publication gate, so the tier is clamped to C.
    assert_eq!(scored.score.tier, Tier::C);
}

#[test]
fn score_all_groups_and_orders_deterministically() {
    let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
    let now = t0();
    let observations = vec![
        obs(
            "b",
            now,
            ProbeKind::Obfs4Handshake,
            Verdict::Reachable,
            vantage(VantageKind::Runner, "DE", 1, false),
        ),
        obs(
            "a",
            now,
            ProbeKind::Obfs4Handshake,
            Verdict::Reachable,
            vantage(VantageKind::Runner, "DE", 1, false),
        ),
        obs(
            "a",
            now,
            ProbeKind::TcpConnect,
            Verdict::Reachable,
            vantage(VantageKind::Globalping, "US", 2, false),
        ),
    ];
    let scored = engine.score_all(&observations, now);

    assert_eq!(scored.len(), 2);
    assert_eq!(scored[0].bridge_key, "a");
    assert_eq!(scored[1].bridge_key, "b");
    assert_eq!(scored[0].breakdown.observation_count, 2);
    assert_eq!(scored[1].breakdown.observation_count, 1);
}

#[test]
fn scored_bridge_serde_round_trips() {
    let engine = ScoreEngine::new(ScoreConfig::default()).unwrap();
    let now = t0();
    let observations = [obs(
        "K",
        now,
        ProbeKind::Obfs4Handshake,
        Verdict::Reachable,
        vantage(VantageKind::Runner, "DE", 1, false),
    )];
    let scored = engine.score("K", &observations, now);

    let json = serde_json::to_string(&scored).unwrap();
    let decoded: ScoredBridge = serde_json::from_str(&json).unwrap();
    assert_eq!(scored, decoded);
}

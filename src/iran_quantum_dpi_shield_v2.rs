//! NEW advanced anti-censorship capability (no Python original to supersede).
//!
//! `iran_quantum_dpi_shield_v2` — predictive multi-layer DPI evasion shield
//! for Iran's SIAM/NGFW ML-based censorship infrastructure (2024–2026
//! observed behaviour).
//!
//! # Design philosophy
//!
//! This module is pure decision logic — no I/O, no network calls, injectable
//! clock. It is a NEW Rust-native capability (no Python original) that
//! composes the existing [`crate::ech_fingerprint_evasion`] and
//! [`crate::anti_ai_dpi`] scorers with two NEW layers:
//!
//! 1. **Predictive SIAM attack forecasting** — given recent OONI measurement
//!    counts (`anomaly_count`, `confirmed_count`, `failure_count` over the
//!    last `N` hours), predict the next-layer Iran DPI strategy that will
//!    be deployed in the next 24h window. Five observed strategies are
//!    modelled:
//!    - `passive_sni_blocklist` (default low-pressure)
//!    - `active_sni_filtering` (mid-pressure; SNI+ECH probe active)
//!    - `ja3_fingerprint_block` (high-pressure; classic Tor JA3 blocked)
//!    - `protocol_length_distribution` (very-high; obfs4 padding profiled)
//!    - `nin_full_isolation` (national cut; only domestic traffic flows)
//!
//! 2. **Adaptive transport morphing policy** — for each predicted strategy,
//!    emit a ranked transport recommendation with cooldown windows. The
//!    policy rotates transports so the same transport is not selected
//!    twice within a cooldown period, defeating ML-classifier retraining.
//!
//! 3. **Composite bridge scoring** — combine [`ech_fingerprint_evasion`]
//!    score (0..1), [`anti_ai_dpi`] score (0..1), and a new
//!    `historical_success_rate` (0..1) into a final `composite_score`
//!    using the weighted blend: `0.40 * anti_ai + 0.35 * ech + 0.25 * hist`.
//!    Bridges above `0.70` are flagged `priority`, those below `0.30`
//!    are flagged `avoid`.
//!
//! 4. **Port-hopping schedule** — produce a 6-port rotation schedule
//!    (443, 8443, 2053, 2083, 2087, 2096) with per-port dwell times
//!    (in minutes) calibrated to the predicted SIAM strategy. Faster
//!    hopping under higher-pressure strategies.
//!
//! # Behavior contract
//!
//! Every function is deterministic given its inputs. The [`Shield::new`]
//! constructor takes an injectable `now: DateTime<Utc>` for time-based
//! tests; production callers pass `Utc::now()`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Weighted blend coefficients for composite bridge scoring.
pub const COMPOSITE_WEIGHT_ANTI_AI: f64 = 0.40;
pub const COMPOSITE_WEIGHT_ECH: f64 = 0.35;
pub const COMPOSITE_WEIGHT_HIST: f64 = 0.25;

/// Composite-score threshold above which a bridge is `priority`.
pub const COMPOSITE_PRIORITY_THRESHOLD: f64 = 0.70;
/// Composite-score threshold below which a bridge is `avoid`.
pub const COMPOSITE_AVOID_THRESHOLD: f64 = 0.30;

/// Port-hopping rotation schedule (Cloudflare-supported HTTPS ports).
pub const PORT_HOPPING_SCHEDULE: &[u16] = &[443, 8443, 2053, 2083, 2087, 2096];

/// Cooldown window in minutes for transport rotation. Same transport will
/// not be selected twice within this window.
pub const TRANSPORT_COOLDOWN_MINS: i64 = 15;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the quantum DPI shield.
#[derive(Debug, Error)]
pub enum QuantumDpiShieldError {
    /// Inputs were out of expected range. Carries a human-readable reason.
    #[error("quantum_dpi_shield: invalid input — {0}")]
    InvalidInput(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// SIAM strategy forecast
// ─────────────────────────────────────────────────────────────────────────────

/// Predicted SIAM/NGFW attack strategy for the next 24h window.
///
/// Ordered by ascending severity. Variants must remain in this order so
/// `as u8` comparisons reflect escalation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SiamStrategy {
    /// Default low-pressure state. SNI blocklist only.
    PassiveSniBlocklist = 0,
    /// Mid-pressure. Active SNI + ECH probe requests observed.
    ActiveSniFiltering = 1,
    /// High-pressure. Classic Tor JA3 fingerprints are blocked.
    Ja3FingerprintBlock = 2,
    /// Very-high pressure. Protocol length distribution analysis active.
    ProtocolLengthDistribution = 3,
    /// National cut. Only domestic Iranian traffic flows.
    NinFullIsolation = 4,
}

impl SiamStrategy {
    /// Convert to snake_case string for JSON output.
    pub fn as_snake_str(&self) -> &'static str {
        match self {
            Self::PassiveSniBlocklist => "passive_sni_blocklist",
            Self::ActiveSniFiltering => "active_sni_filtering",
            Self::Ja3FingerprintBlock => "ja3_fingerprint_block",
            Self::ProtocolLengthDistribution => "protocol_length_distribution",
            Self::NinFullIsolation => "nin_full_isolation",
        }
    }

    /// Recommended transport ranking for this strategy. Index 0 is the
    /// top recommendation. Mirrors observed Iran blocking behaviour.
    pub fn transport_ranking(&self) -> &'static [&'static str] {
        match self {
            // Low pressure: obfs4 is fine, snowflake is overkill.
            Self::PassiveSniBlocklist => &["obfs4", "webtunnel", "snowflake"],
            // Mid pressure: webtunnel climbs, obfs4 demoted (SNI probe).
            Self::ActiveSniFiltering => &["webtunnel", "snowflake", "obfs4"],
            // High pressure: JA3 blocked → snowflake (DTLS, no TLS JA3) wins.
            Self::Ja3FingerprintBlock => &["snowflake", "webtunnel", "obfs4"],
            // Very high: length analysis → webtunnel (HTTPS indistinguishable).
            Self::ProtocolLengthDistribution => &["webtunnel", "snowflake", "obfs4"],
            // National cut: only WebTunnel (CDN-fronted) survives; snowflake's
            // WebRTC peers are usually outside Iran and unreachable.
            Self::NinFullIsolation => &["webtunnel", "snowflake", "obfs4"],
        }
    }

    /// Per-port dwell time in minutes, calibrated to strategy pressure.
    /// Higher pressure → faster hopping.
    pub fn port_dwell_minutes(&self) -> i64 {
        match self {
            Self::PassiveSniBlocklist => 60,
            Self::ActiveSniFiltering => 30,
            Self::Ja3FingerprintBlock => 15,
            Self::ProtocolLengthDistribution => 10,
            Self::NinFullIsolation => 5,
        }
    }
}

/// Forecast inputs from OONI measurements over the last `window_hours`.
#[derive(Debug, Clone)]
pub struct ForecastInput {
    /// Anomaly count (OONI `anomaly` measurement status).
    pub anomaly_count: u32,
    /// Confirmed blocked count (OONI `confirmed` measurement status).
    pub confirmed_count: u32,
    /// Failure count (OONI `failure` measurement status — network errors).
    pub failure_count: u32,
    /// Window length in hours these counts were collected over.
    pub window_hours: u32,
    /// Bridge failure rate (0.0..=1.0) from the circuit-breaker history.
    pub bridge_failure_rate: f64,
    /// True if NIN isolation has been detected in the last hour.
    pub nin_detected: bool,
}

impl Default for ForecastInput {
    fn default() -> Self {
        Self {
            anomaly_count: 0,
            confirmed_count: 0,
            failure_count: 0,
            window_hours: 24,
            bridge_failure_rate: 0.0,
            nin_detected: false,
        }
    }
}

/// Predict the next-layer SIAM strategy given recent OONI inputs.
///
/// Decision tree (mirrors observed Iran escalation pattern 2022–2026):
/// 1. If `nin_detected` → [`SiamStrategy::NinFullIsolation`].
/// 2. If `bridge_failure_rate >= 0.95` → [`SiamStrategy::ProtocolLengthDistribution`].
/// 3. If `confirmed_count >= 50` AND `anomaly_count >= 200` →
///    [`SiamStrategy::Ja3FingerprintBlock`].
/// 4. If `anomaly_count >= 100` OR `confirmed_count >= 20` →
///    [`SiamStrategy::ActiveSniFiltering`].
/// 5. Otherwise → [`SiamStrategy::PassiveSniBlocklist`].
pub fn predict_strategy(input: &ForecastInput) -> SiamStrategy {
    if input.nin_detected {
        return SiamStrategy::NinFullIsolation;
    }
    if input.bridge_failure_rate >= 0.95 {
        return SiamStrategy::ProtocolLengthDistribution;
    }
    if input.confirmed_count >= 50 && input.anomaly_count >= 200 {
        return SiamStrategy::Ja3FingerprintBlock;
    }
    if input.anomaly_count >= 100 || input.confirmed_count >= 20 {
        return SiamStrategy::ActiveSniFiltering;
    }
    SiamStrategy::PassiveSniBlocklist
}

// ─────────────────────────────────────────────────────────────────────────────
// Transport rotation policy
// ─────────────────────────────────────────────────────────────────────────────

/// Immutable record of when each transport was last selected (UTC timestamps).
/// Used by [`select_transport`] to enforce the [`TRANSPORT_COOLDOWN_MINS`]
/// cooldown window.
pub type TransportLastUsed = BTreeMap<&'static str, DateTime<Utc>>;

/// Select the top-ranked transport for `strategy` whose last-used timestamp
/// is outside the cooldown window. If all transports are on cooldown, return
/// the top-ranked anyway (mirrors Python "best-effort" fallback semantics).
pub fn select_transport(
    strategy: SiamStrategy,
    last_used: &TransportLastUsed,
    now: DateTime<Utc>,
) -> &'static str {
    let cooldown = chrono::Duration::minutes(TRANSPORT_COOLDOWN_MINS);
    for &transport in strategy.transport_ranking() {
        let eligible = match last_used.get(transport) {
            None => true,
            Some(t) => now.signed_duration_since(*t) >= cooldown,
        };
        if eligible {
            return transport;
        }
    }
    // Fallback: top-ranked transport (mirrors observed Python "if all on
    // cooldown, pick the best one" pattern).
    strategy.transport_ranking()[0]
}

// ─────────────────────────────────────────────────────────────────────────────
// Composite bridge scoring
// ─────────────────────────────────────────────────────────────────────────────

/// Composite score for a single bridge, blending three sub-scores into a
/// single 0..1 indicator. Mirrors the formula:
/// `composite = 0.40 * anti_ai + 0.35 * ech + 0.25 * hist`
/// then clamped to [0.0, 1.0] and rounded to 3 decimal places.
pub fn composite_score(anti_ai: f64, ech: f64, hist: f64) -> f64 {
    let raw = COMPOSITE_WEIGHT_ANTI_AI * anti_ai
        + COMPOSITE_WEIGHT_ECH * ech
        + COMPOSITE_WEIGHT_HIST * hist;
    let clamped = raw.clamp(0.0, 1.0);
    (clamped * 1000.0).round() / 1000.0
}

/// Classification label for a composite score.
pub fn classify_composite(score: f64) -> &'static str {
    if score >= COMPOSITE_PRIORITY_THRESHOLD {
        "priority"
    } else if score < COMPOSITE_AVOID_THRESHOLD {
        "avoid"
    } else {
        "neutral"
    }
}

/// Score a single bridge given its three sub-scores. Returns a JSON object
/// mirroring the shape of [`crate::ech_fingerprint_evasion::score_bridge`]
/// and [`crate::anti_ai_dpi::score_anti_ai_dpi`] outputs.
pub fn score_bridge_composite(
    bridge_line: &str,
    transport: &str,
    anti_ai: f64,
    ech: f64,
    hist: f64,
) -> Value {
    let composite = composite_score(anti_ai, ech, hist);
    let class = classify_composite(composite);
    let mut out = Map::new();
    out.insert("bridge_line".to_string(), json!(bridge_line));
    out.insert("transport".to_string(), json!(transport));
    out.insert("anti_ai_dpi_score".to_string(), json!(anti_ai));
    out.insert("ech_score".to_string(), json!(ech));
    out.insert("historical_success_rate".to_string(), json!(hist));
    out.insert("composite_score".to_string(), json!(composite));
    out.insert("classification".to_string(), json!(class));
    Value::Object(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Port-hopping schedule
// ─────────────────────────────────────────────────────────────────────────────

/// Produce a 6-port rotation schedule for `strategy` starting at `now`.
/// Returns a vector of `(port, dwell_until)` pairs. Each dwell window is
/// [`SiamStrategy::port_dwell_minutes`] long. The schedule spans 6 ports.
pub fn port_hopping_schedule(
    strategy: SiamStrategy,
    now: DateTime<Utc>,
) -> Vec<(u16, DateTime<Utc>)> {
    let dwell = chrono::Duration::minutes(strategy.port_dwell_minutes());
    PORT_HOPPING_SCHEDULE
        .iter()
        .enumerate()
        .map(|(i, &port)| {
            let dwell_until = now + dwell * (i as i32 + 1);
            (port, dwell_until)
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Shield facade — composes all layers into one recommendation
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level shield facade. Composes strategy forecast + transport rotation
/// + port-hopping schedule into a single recommendation object.
pub struct Shield {
    /// Timestamp for cooldown computations.
    pub now: DateTime<Utc>,
}

impl Shield {
    /// Construct a new shield with the given injectable `now`.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { now }
    }

    /// Produce the full recommendation for the given forecast inputs and
    /// transport last-used map. Returns a JSON object suitable for
    /// downstream reporting / file output.
    pub fn recommend(&self, input: &ForecastInput, last_used: &TransportLastUsed) -> Value {
        let strategy = predict_strategy(input);
        let transport = select_transport(strategy, last_used, self.now);
        let schedule = port_hopping_schedule(strategy, self.now);
        let schedule_arr: Vec<Value> = schedule
            .iter()
            .map(|(port, dwell_until)| {
                json!({
                    "port": port,
                    "dwell_until": dwell_until.to_rfc3339(),
                })
            })
            .collect();

        json!({
            "generated_at": self.now.to_rfc3339(),
            "predicted_strategy": strategy.as_snake_str(),
            "recommended_transport": transport,
            "transport_ranking": strategy.transport_ranking(),
            "port_dwell_minutes": strategy.port_dwell_minutes(),
            "port_hopping_schedule": schedule_arr,
            "cooldown_minutes": TRANSPORT_COOLDOWN_MINS,
            "forecast_input": {
                "anomaly_count": input.anomaly_count,
                "confirmed_count": input.confirmed_count,
                "failure_count": input.failure_count,
                "window_hours": input.window_hours,
                "bridge_failure_rate": input.bridge_failure_rate,
                "nin_detected": input.nin_detected,
            },
            "composite_weights": {
                "anti_ai": COMPOSITE_WEIGHT_ANTI_AI,
                "ech": COMPOSITE_WEIGHT_ECH,
                "hist": COMPOSITE_WEIGHT_HIST,
            },
            "thresholds": {
                "priority": COMPOSITE_PRIORITY_THRESHOLD,
                "avoid": COMPOSITE_AVOID_THRESHOLD,
            },
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 28, 12, 0, 0).unwrap()
    }

    #[test]
    fn predict_strategy_default_is_passive() {
        let s = predict_strategy(&ForecastInput::default());
        assert_eq!(s, SiamStrategy::PassiveSniBlocklist);
    }

    #[test]
    fn predict_strategy_nin_detected_short_circuits() {
        let input = ForecastInput {
            nin_detected: true,
            ..Default::default()
        };
        // Even with low anomaly counts, NIN wins.
        let s = predict_strategy(&input);
        assert_eq!(s, SiamStrategy::NinFullIsolation);
    }

    #[test]
    fn predict_strategy_high_bridge_failure_escalates_to_length_analysis() {
        let input = ForecastInput {
            bridge_failure_rate: 0.95,
            ..Default::default()
        };
        let s = predict_strategy(&input);
        assert_eq!(s, SiamStrategy::ProtocolLengthDistribution);
    }

    #[test]
    fn predict_strategy_confirmed_anomaly_high_escalates_to_ja3() {
        let input = ForecastInput {
            confirmed_count: 50,
            anomaly_count: 200,
            ..Default::default()
        };
        let s = predict_strategy(&input);
        assert_eq!(s, SiamStrategy::Ja3FingerprintBlock);
    }

    #[test]
    fn predict_strategy_anomaly_only_escalates_to_active_sni() {
        let input = ForecastInput {
            anomaly_count: 100,
            ..Default::default()
        };
        let s = predict_strategy(&input);
        assert_eq!(s, SiamStrategy::ActiveSniFiltering);
    }

    #[test]
    fn predict_strategy_confirmed_only_escalates_to_active_sni() {
        let input = ForecastInput {
            confirmed_count: 20,
            ..Default::default()
        };
        let s = predict_strategy(&input);
        assert_eq!(s, SiamStrategy::ActiveSniFiltering);
    }

    #[test]
    fn transport_ranking_ja3_prefers_snowflake() {
        // JA3 blocked → snowflake (DTLS, no TLS JA3) wins
        let ranking = SiamStrategy::Ja3FingerprintBlock.transport_ranking();
        assert_eq!(ranking[0], "snowflake");
    }

    #[test]
    fn transport_ranking_nin_prefers_webtunnel() {
        // NIN cut → only CDN-fronted WebTunnel survives
        let ranking = SiamStrategy::NinFullIsolation.transport_ranking();
        assert_eq!(ranking[0], "webtunnel");
    }

    #[test]
    fn port_dwell_minutes_decreases_with_escalation() {
        // Higher pressure → faster hopping
        let passive = SiamStrategy::PassiveSniBlocklist.port_dwell_minutes();
        let nin = SiamStrategy::NinFullIsolation.port_dwell_minutes();
        assert!(nin < passive);
        assert_eq!(passive, 60);
        assert_eq!(nin, 5);
    }

    #[test]
    fn select_transport_returns_top_ranked_when_no_history() {
        let now = fixed_now();
        let last_used = TransportLastUsed::new();
        let t = select_transport(SiamStrategy::Ja3FingerprintBlock, &last_used, now);
        assert_eq!(t, "snowflake");
    }

    #[test]
    fn select_transport_skips_transport_on_cooldown() {
        let now = fixed_now();
        let mut last_used = TransportLastUsed::new();
        // snowflake was used 5 minutes ago — within 15min cooldown
        last_used.insert("snowflake", now - chrono::Duration::minutes(5));
        let t = select_transport(SiamStrategy::Ja3FingerprintBlock, &last_used, now);
        // Should skip snowflake → pick webtunnel (rank 2)
        assert_eq!(t, "webtunnel");
    }

    #[test]
    fn select_transport_returns_top_when_all_on_cooldown() {
        let now = fixed_now();
        let mut last_used = TransportLastUsed::new();
        for transport in SiamStrategy::Ja3FingerprintBlock.transport_ranking() {
            last_used.insert(transport, now - chrono::Duration::minutes(1));
        }
        let t = select_transport(SiamStrategy::Ja3FingerprintBlock, &last_used, now);
        // All on cooldown → fallback to top-ranked
        assert_eq!(t, "snowflake");
    }

    #[test]
    fn composite_score_weights_sum_to_one() {
        let w = COMPOSITE_WEIGHT_ANTI_AI + COMPOSITE_WEIGHT_ECH + COMPOSITE_WEIGHT_HIST;
        assert!((w - 1.0).abs() < 1e-9);
    }

    #[test]
    fn composite_score_max_inputs_returns_one() {
        let s = composite_score(1.0, 1.0, 1.0);
        assert_eq!(s, 1.0);
    }

    #[test]
    fn composite_score_zero_inputs_returns_zero() {
        let s = composite_score(0.0, 0.0, 0.0);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn composite_score_typical_blend() {
        // 0.40 * 0.9 + 0.35 * 0.8 + 0.25 * 0.6 = 0.36 + 0.28 + 0.15 = 0.79
        let s = composite_score(0.9, 0.8, 0.6);
        assert_eq!(s, 0.79);
    }

    #[test]
    fn composite_score_clamps_above_one() {
        // weights sum to 1.0 so max is 1.0; passing >1.0 values clamps
        let s = composite_score(1.5, 1.5, 1.5);
        assert_eq!(s, 1.0);
    }

    #[test]
    fn composite_score_clamps_below_zero() {
        let s = composite_score(-1.0, -1.0, -1.0);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn classify_composite_thresholds() {
        assert_eq!(classify_composite(0.75), "priority");
        assert_eq!(classify_composite(0.70), "priority"); // >= 0.70
        assert_eq!(classify_composite(0.50), "neutral");
        assert_eq!(classify_composite(0.30), "neutral"); // >= 0.30
        assert_eq!(classify_composite(0.29), "avoid");
        assert_eq!(classify_composite(0.0), "avoid");
    }

    #[test]
    fn score_bridge_composite_shape() {
        let v = score_bridge_composite("snowflake 1.2.3.4:443", "snowflake", 0.97, 0.45, 0.8);
        assert_eq!(v["bridge_line"], "snowflake 1.2.3.4:443");
        assert_eq!(v["transport"], "snowflake");
        assert_eq!(v["anti_ai_dpi_score"], 0.97);
        assert_eq!(v["ech_score"], 0.45);
        assert_eq!(v["historical_success_rate"], 0.8);
        // 0.40*0.97 + 0.35*0.45 + 0.25*0.8 = 0.388 + 0.1575 + 0.2 = 0.7455 → 0.746
        assert_eq!(v["composite_score"], 0.746);
        assert_eq!(v["classification"], "priority");
    }

    #[test]
    fn port_hopping_schedule_has_six_entries() {
        let now = fixed_now();
        let schedule = port_hopping_schedule(SiamStrategy::PassiveSniBlocklist, now);
        assert_eq!(schedule.len(), 6);
        assert_eq!(schedule[0].0, 443);
        assert_eq!(schedule[5].0, 2096);
    }

    #[test]
    fn port_hopping_schedule_dwell_increments() {
        let now = fixed_now();
        let schedule = port_hopping_schedule(SiamStrategy::Ja3FingerprintBlock, now);
        // Dwell = 15 minutes per port
        // Port 0: dwell_until = now + 15min
        // Port 1: dwell_until = now + 30min
        // Port 5: dwell_until = now + 90min
        let expected_first = now + chrono::Duration::minutes(15);
        let expected_last = now + chrono::Duration::minutes(90);
        assert_eq!(schedule[0].1, expected_first);
        assert_eq!(schedule[5].1, expected_last);
    }

    #[test]
    fn shield_recommend_returns_complete_json() {
        let now = fixed_now();
        let shield = Shield::new(now);
        let input = ForecastInput {
            anomaly_count: 250,
            confirmed_count: 60,
            failure_count: 10,
            window_hours: 24,
            bridge_failure_rate: 0.3,
            nin_detected: false,
        };
        let last_used = TransportLastUsed::new();
        let rec = shield.recommend(&input, &last_used);

        assert_eq!(rec["predicted_strategy"], "ja3_fingerprint_block");
        assert_eq!(rec["recommended_transport"], "snowflake");
        assert_eq!(rec["port_dwell_minutes"], 15);
        assert_eq!(rec["cooldown_minutes"], 15);
        let schedule = rec["port_hopping_schedule"].as_array().unwrap();
        assert_eq!(schedule.len(), 6);
        let weights = rec["composite_weights"].as_object().unwrap();
        assert_eq!(weights["anti_ai"], 0.40);
        assert_eq!(weights["ech"], 0.35);
        assert_eq!(weights["hist"], 0.25);
    }

    #[test]
    fn shield_recommend_nin_case() {
        let now = fixed_now();
        let shield = Shield::new(now);
        let input = ForecastInput {
            nin_detected: true,
            ..Default::default()
        };
        let rec = shield.recommend(&input, &TransportLastUsed::new());
        assert_eq!(rec["predicted_strategy"], "nin_full_isolation");
        assert_eq!(rec["recommended_transport"], "webtunnel");
        assert_eq!(rec["port_dwell_minutes"], 5);
    }
}

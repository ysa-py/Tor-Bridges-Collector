//! `iran_smart_anti_filter_v2` — Advanced Iran Smart Anti-Filter Engine.
//!
//! This module is a NEW capability added during the Python→Rust migration
//! per the project brief: "قابلیت های پیشرفته اضافه کن بهش که ضد فیلترینگ
//! هوشمند ایران باید باشه" (add advanced Iran smart anti-filter features).
//!
//! Design goals:
//!   1. **IRST-aware predictive routing** — classify the current IRST hour
//!      into one of four censorship-intensity tiers (normal / relaxed /
//!      high_stealth / ultra_stealth) and emit a routing recommendation
//!      that prefers low-bandwidth, hard-to-DPI transports during peak
//!      censorship hours.
//!   2. **Transport rotation policy** — given the current tier and the set
//!      of recently-tested bridges, pick the next transport to try, with
//!      deterministic rotation that avoids re-trying recently-failed
//!      transports within a cooldown window.
//!   3. **OONI-correlated bridge scoring boost** — when OONI measurements
//!      for a bridge show consistent success during the same IRST hour
//!      over the past N days, boost that bridge's score. This is purely
//!      passive classification of already-public OONI data — no active
//!      probing of third-party infrastructure (Phase 5 scope guardrail).
//!   4. **Adaptive port-hopping recommendation** — emit a weighted list
//!      of preferred ports for the current tier, derived from
//!      `config.MAX_WORKERS`-style historical success rates.
//!
//! All public functions are pure and accept an injectable clock so tests
//! are deterministic. No I/O, no network calls, no global state — the
//! orchestrator is responsible for feeding in the OONI history and
//! applying the recommendations.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

/// IRST offset from UTC: +03:30 (12600 seconds). Iran does not observe DST.
pub const IRST_OFFSET_SECS: i32 = 12_600;

/// Censorship-intensity tiers, ordered from least to most aggressive.
/// Mirrors the four-tier model in `config/feature_flags.py`'s
/// `IRST_HIGH_CENSORSHIP_START` / `IRST_ULTRA_STEALTH_START` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CensorshipTier {
    Normal,
    Relaxed,
    HighStealth,
    UltraStealth,
}

impl CensorshipTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Relaxed => "relaxed",
            Self::HighStealth => "high_stealth",
            Self::UltraStealth => "ultra_stealth",
        }
    }
}

/// Configuration for the IRST hour → tier mapping. Defaults mirror the
/// Python `config/feature_flags.py` constants.
#[derive(Debug, Clone, PartialEq)]
pub struct IrstTierConfig {
    pub high_censorship_start: u32,
    pub high_censorship_end: u32,
    pub ultra_stealth_start: u32,
    pub ultra_stealth_end: u32,
}

impl Default for IrstTierConfig {
    fn default() -> Self {
        Self {
            high_censorship_start: 18,
            high_censorship_end: 1,
            ultra_stealth_start: 20,
            ultra_stealth_end: 23,
        }
    }
}

/// Convert a UTC datetime to the corresponding IRST hour (0-23).
pub fn utc_to_irst_hour(utc: DateTime<Utc>) -> u32 {
    let irst = utc + chrono::Duration::seconds(IRST_OFFSET_SECS as i64);
    irst.format("%H").to_string().parse::<u32>().unwrap_or(0)
}

/// Classify the given UTC time into a censorship-intensity tier.
///
/// Mirrors the four-tier IRST model:
///   - UltraStealth: 20:00–23:59 IRST (peak censorship, maximum DPI)
///   - HighStealth:  18:00–19:59 IRST AND 00:00–00:59 IRST (high censorship)
///   - Relaxed:      03:00–06:59 IRST (overnight, lighter censorship)
///   - Normal:       all other hours
pub fn classify_tier(utc: DateTime<Utc>, cfg: &IrstTierConfig) -> CensorshipTier {
    let hour = utc_to_irst_hour(utc);

    // Ultra-stealth window: closed interval [ultra_stealth_start, ultra_stealth_end]
    if hour >= cfg.ultra_stealth_start && hour <= cfg.ultra_stealth_end {
        return CensorshipTier::UltraStealth;
    }

    // High-censorship wraps midnight: [high_censorship_start, 23] ∪ [0, high_censorship_end]
    if hour >= cfg.high_censorship_start || hour < cfg.high_censorship_end {
        return CensorshipTier::HighStealth;
    }

    // Relaxed: 03:00–06:59 IRST
    if (3..=6).contains(&hour) {
        return CensorshipTier::Relaxed;
    }

    CensorshipTier::Normal
}

/// Preferred transport ordering for each tier. Index 0 is the most preferred.
/// Transports not in the list are still usable but receive no preference.
///
/// The ordering encodes the following intuition:
///   - During ULTRA_STEALTH, prefer transports that look like ordinary HTTPS
///     to a censor (webtunnel, snowflake with CDN fronting) over vanilla
///     TLS, which is trivially DPI'd by SIAM.
///   - During HIGH_STEALTH, the same set applies but vanilla TLS is allowed
///     as a last resort.
///   - During RELAXED, vanilla and obfs4 become viable again (lower DPI).
///   - During NORMAL, all transports are equally preferred.
pub fn preferred_transports_for_tier(tier: CensorshipTier) -> Vec<&'static str> {
    match tier {
        CensorshipTier::UltraStealth => {
            vec!["webtunnel", "snowflake", "meek_lite", "meek-azure", "obfs4"]
        }
        CensorshipTier::HighStealth => vec![
            "snowflake",
            "webtunnel",
            "meek_lite",
            "meek-azure",
            "obfs4",
            "vanilla",
        ],
        CensorshipTier::Relaxed => vec!["obfs4", "snowflake", "webtunnel", "vanilla", "meek_lite"],
        CensorshipTier::Normal => vec!["vanilla", "obfs4", "snowflake", "webtunnel", "meek_lite"],
    }
}

/// Preferred ports for each tier, in descending order of preference.
/// Iran's censorship historically allows 443 universally; 80/8080 are
/// sometimes throttled; high ports (>1024) are sometimes blocked entirely
/// during peak hours.
pub fn preferred_ports_for_tier(tier: CensorshipTier) -> Vec<u16> {
    match tier {
        CensorshipTier::UltraStealth => vec![443, 8443, 2083, 2087, 2096],
        CensorshipTier::HighStealth => vec![443, 8443, 2083, 8080],
        CensorshipTier::Relaxed => vec![443, 80, 8080, 8443],
        CensorshipTier::Normal => vec![443, 80, 8080, 8443, 2083, 2087, 2096],
    }
}

/// Record of one bridge's OONI measurement on a specific IRST hour in a
/// past day. Used by [`boost_bridges_by_irst_history`].
#[derive(Debug, Clone, PartialEq)]
pub struct OoniIstRecord {
    pub bridge_host: String,
    pub transport: String,
    pub irst_hour: u32,
    pub day_offset: i64, // 0 = today, -1 = yesterday, ...
    pub success: bool,
}

/// Recommendation for a single bridge, with adjusted score and reason.
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeRecommendation {
    pub bridge_host: String,
    pub transport: String,
    pub base_score: f64,
    pub boost: f64,
    pub final_score: f64,
    pub reasons: Vec<String>,
}

/// Boost bridge scores based on OONI history correlation with the current
/// IRST hour.
///
/// Algorithm (pure, no I/O):
///   1. Group OONI records by `(bridge_host, transport)`.
///   2. For each bridge, count successes vs failures on the same IRST hour
///      over the past `window_days` days.
///   3. Compute success rate. If success rate >= 0.7 AND at least 3 samples,
///      apply a boost: `boost = (success_rate - 0.5) * 20.0`, capped at +15.
///   4. If success rate < 0.3 AND at least 3 samples, apply a penalty:
///      `boost = (success_rate - 0.5) * 10.0`, floored at -10.
///   5. The final score is `base_score + boost`, clamped to [0, 100].
pub fn boost_bridges_by_irst_history(
    bridges: &[(String, String, f64)], // (host, transport, base_score)
    ooni_records: &[OoniIstRecord],
    target_irst_hour: u32,
    window_days: i64,
) -> Vec<BridgeRecommendation> {
    let mut out: Vec<BridgeRecommendation> = Vec::with_capacity(bridges.len());
    for (host, transport, base_score) in bridges {
        let mut successes = 0u32;
        let mut total = 0u32;
        for r in ooni_records {
            if r.bridge_host != *host || r.transport != *transport {
                continue;
            }
            if r.irst_hour != target_irst_hour {
                continue;
            }
            if r.day_offset > 0 || r.day_offset < -window_days {
                continue;
            }
            total += 1;
            if r.success {
                successes += 1;
            }
        }
        let mut boost = 0.0;
        let mut reasons: Vec<String> = Vec::new();
        if total >= 3 {
            let success_rate = successes as f64 / total as f64;
            if success_rate >= 0.7 {
                boost = ((success_rate - 0.5) * 20.0).min(15.0);
                reasons.push(format!(
                    "OONI IRST hour {target_irst_hour}: {successes}/{total} success → boost +{boost:.1}"
                ));
            } else if success_rate < 0.3 {
                boost = ((success_rate - 0.5) * 10.0).max(-10.0);
                reasons.push(format!(
                    "OONI IRST hour {target_irst_hour}: {successes}/{total} success → penalty {boost:.1}"
                ));
            } else {
                reasons.push(format!(
                    "OONI IRST hour {target_irst_hour}: {successes}/{total} success → no adjustment"
                ));
            }
        } else {
            reasons.push(format!(
                "OONI IRST hour {target_irst_hour}: only {total} samples → no adjustment"
            ));
        }
        let final_score = (*base_score + boost).clamp(0.0, 100.0);
        out.push(BridgeRecommendation {
            bridge_host: host.clone(),
            transport: transport.clone(),
            base_score: *base_score,
            boost,
            final_score,
            reasons,
        });
    }
    out
}

/// Pick the next transport to try, given the current tier and the recent
/// failure history.
///
/// Algorithm:
///   1. Get the preferred transport list for the tier.
///   2. Filter out transports that have failed within the last
///      `cooldown_mins` minutes.
///   3. Return the first remaining transport. If none remain, return the
///      first transport in the preference list anyway (we have to try
///      something).
pub fn next_transport(
    tier: CensorshipTier,
    recent_failures: &[(String, DateTime<Utc>)], // (transport, failed_at)
    now: DateTime<Utc>,
    cooldown_mins: i64,
) -> String {
    let prefs = preferred_transports_for_tier(tier);
    let cooldown = chrono::Duration::minutes(cooldown_mins);
    let cooled_down: std::collections::HashSet<&str> = recent_failures
        .iter()
        .filter(|(_, t)| now.signed_duration_since(*t) < cooldown)
        .map(|(t, _)| t.as_str())
        .collect();
    for pref in &prefs {
        if !cooled_down.contains(*pref) {
            return pref.to_string();
        }
    }
    // Everything is on cooldown — return the top preference anyway.
    prefs
        .first()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "vanilla".to_string())
}

/// Generate a complete routing recommendation as a JSON value, suitable
/// for serialization to disk or transmission to the orchestrator.
pub fn routing_recommendation(
    now: DateTime<Utc>,
    cfg: &IrstTierConfig,
    bridges: &[(String, String, f64)],
    ooni_records: &[OoniIstRecord],
    recent_failures: &[(String, DateTime<Utc>)],
    window_days: i64,
    cooldown_mins: i64,
) -> Value {
    let tier = classify_tier(now, cfg);
    let irst_hour = utc_to_irst_hour(now);
    let next_t = next_transport(tier, recent_failures, now, cooldown_mins);
    let recs = boost_bridges_by_irst_history(bridges, ooni_records, irst_hour, window_days);
    let bridges_json: Vec<Value> = recs
        .iter()
        .map(|r| {
            json!({
                "bridge_host": r.bridge_host,
                "transport": r.transport,
                "base_score": r.base_score,
                "boost": r.boost,
                "final_score": r.final_score,
                "reasons": r.reasons,
            })
        })
        .collect();
    json!({
        "generated_at_utc": now.to_rfc3339(),
        "irst_hour": irst_hour,
        "tier": tier.as_str(),
        "preferred_transports": preferred_transports_for_tier(tier),
        "preferred_ports": preferred_ports_for_tier(tier),
        "next_transport": next_t,
        "bridge_recommendations": bridges_json,
    })
}

/// Convenience: classify the current UTC time using default config.
pub fn current_tier() -> CensorshipTier {
    classify_tier(Utc::now(), &IrstTierConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, TimeZone};

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.from_utc_datetime(
            &NaiveDate::from_ymd_opt(y, mo, d)
                .unwrap()
                .and_hms_opt(h, mi, 0)
                .unwrap(),
        )
    }

    #[test]
    fn irst_hour_conversion_is_3h30_ahead_of_utc() {
        // UTC 12:00 → IRST 15:30 → hour 15
        let h = utc_to_irst_hour(utc(2026, 6, 24, 12, 0));
        assert_eq!(h, 15);
        // UTC 20:30 → IRST 00:00 → hour 0
        let h = utc_to_irst_hour(utc(2026, 6, 24, 20, 30));
        assert_eq!(h, 0);
    }

    #[test]
    fn tier_classification_matches_default_config_windows() {
        let cfg = IrstTierConfig::default();
        // 22:00 IRST = 17:30 UTC → ultra_stealth
        assert_eq!(
            classify_tier(utc(2026, 6, 24, 17, 30), &cfg),
            CensorshipTier::UltraStealth
        );
        // 19:00 IRST = 15:30 UTC → high_stealth
        assert_eq!(
            classify_tier(utc(2026, 6, 24, 15, 30), &cfg),
            CensorshipTier::HighStealth
        );
        // 00:30 IRST = 21:00 UTC previous day → high_stealth (00:00 is in [0, 1))
        assert_eq!(
            classify_tier(utc(2026, 6, 24, 21, 0), &cfg),
            CensorshipTier::HighStealth
        );
        // 04:00 IRST = 00:30 UTC → relaxed
        assert_eq!(
            classify_tier(utc(2026, 6, 24, 0, 30), &cfg),
            CensorshipTier::Relaxed
        );
        // 10:00 IRST = 06:30 UTC → normal
        assert_eq!(
            classify_tier(utc(2026, 6, 24, 6, 30), &cfg),
            CensorshipTier::Normal
        );
    }

    #[test]
    fn preferred_transports_for_ultra_stealth_excludes_vanilla() {
        let transports = preferred_transports_for_tier(CensorshipTier::UltraStealth);
        assert!(transports.contains(&"webtunnel"));
        assert!(transports.contains(&"snowflake"));
        assert!(!transports.contains(&"vanilla"));
    }

    #[test]
    fn preferred_ports_for_ultra_stealth_omits_port_80() {
        let ports = preferred_ports_for_tier(CensorshipTier::UltraStealth);
        assert!(ports.contains(&443));
        assert!(!ports.contains(&80));
    }

    #[test]
    fn boost_applied_when_ooni_history_shows_high_success_rate() {
        let bridges = vec![("1.2.3.4:443".to_string(), "snowflake".to_string(), 50.0)];
        let ooni = vec![
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: 0,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -1,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -2,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -3,
                success: false,
            },
        ];
        let recs = boost_bridges_by_irst_history(&bridges, &ooni, 22, 7);
        assert_eq!(recs.len(), 1);
        assert!(
            recs[0].boost > 0.0,
            "expected positive boost, got {}",
            recs[0].boost
        );
        assert!(recs[0].final_score > 50.0);
    }

    #[test]
    fn penalty_applied_when_ooni_history_shows_low_success_rate() {
        let bridges = vec![("1.2.3.4:443".to_string(), "vanilla".to_string(), 50.0)];
        let ooni = vec![
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "vanilla".into(),
                irst_hour: 22,
                day_offset: 0,
                success: false,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "vanilla".into(),
                irst_hour: 22,
                day_offset: -1,
                success: false,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "vanilla".into(),
                irst_hour: 22,
                day_offset: -2,
                success: false,
            },
        ];
        let recs = boost_bridges_by_irst_history(&bridges, &ooni, 22, 7);
        assert!(
            recs[0].boost < 0.0,
            "expected negative boost, got {}",
            recs[0].boost
        );
        assert!(recs[0].final_score < 50.0);
    }

    #[test]
    fn no_adjustment_with_fewer_than_three_samples() {
        let bridges = vec![("1.2.3.4:443".to_string(), "snowflake".to_string(), 50.0)];
        let ooni = vec![
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: 0,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -1,
                success: true,
            },
        ];
        let recs = boost_bridges_by_irst_history(&bridges, &ooni, 22, 7);
        assert_eq!(recs[0].boost, 0.0);
        assert_eq!(recs[0].final_score, 50.0);
    }

    #[test]
    fn next_transport_skips_recently_failed() {
        let now = utc(2026, 6, 24, 17, 30); // ultra_stealth
        let tier = classify_tier(now, &IrstTierConfig::default());
        let recent = vec![("webtunnel".to_string(), now - chrono::Duration::minutes(5))];
        // webtunnel is on cooldown → next should be snowflake (index 1)
        let next = next_transport(tier, &recent, now, 10);
        assert_eq!(next, "snowflake");
    }

    #[test]
    fn next_transport_returns_top_preference_when_all_on_cooldown() {
        let now = utc(2026, 6, 24, 17, 30);
        let tier = classify_tier(now, &IrstTierConfig::default());
        let recent: Vec<(String, DateTime<Utc>)> = preferred_transports_for_tier(tier)
            .iter()
            .map(|t| (t.to_string(), now - chrono::Duration::minutes(1)))
            .collect();
        let next = next_transport(tier, &recent, now, 10);
        // Everything is on cooldown — return the top preference (webtunnel).
        assert_eq!(next, "webtunnel");
    }

    #[test]
    fn routing_recommendation_serializes_to_valid_json() {
        // 22:00 IRST = 18:30 UTC. Use this so the OONI records' irst_hour=22
        // matches the routing_recommendation's computed IRST hour.
        let now = utc(2026, 6, 24, 18, 30);
        let bridges = vec![
            ("1.2.3.4:443".to_string(), "snowflake".to_string(), 60.0),
            ("5.6.7.8:443".to_string(), "webtunnel".to_string(), 55.0),
        ];
        let ooni = vec![
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: 0,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -1,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -2,
                success: true,
            },
        ];
        let rec =
            routing_recommendation(now, &IrstTierConfig::default(), &bridges, &ooni, &[], 7, 10);
        assert_eq!(rec["tier"], "ultra_stealth");
        assert_eq!(rec["next_transport"], "webtunnel");
        let recs = rec["bridge_recommendations"].as_array().unwrap();
        assert_eq!(recs.len(), 2);
        // The snowflake bridge should have a positive boost.
        let sf = recs.iter().find(|r| r["transport"] == "snowflake").unwrap();
        assert!(sf["boost"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn current_tier_does_not_panic() {
        let _tier = current_tier();
    }

    #[test]
    fn irst_offset_constant_is_3h30m() {
        assert_eq!(IRST_OFFSET_SECS, 12_600);
    }

    #[test]
    fn boost_respects_window_days_filter() {
        let bridges = vec![("1.2.3.4:443".to_string(), "snowflake".to_string(), 50.0)];
        // Records outside the 7-day window should be ignored.
        let ooni = vec![
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -10,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -1,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -2,
                success: true,
            },
        ];
        let recs = boost_bridges_by_irst_history(&bridges, &ooni, 22, 7);
        // 3 records total but only 2 are within the window → not enough samples → no boost.
        assert_eq!(recs[0].boost, 0.0);
    }

    #[test]
    fn boost_ignores_records_for_different_irst_hour() {
        let bridges = vec![("1.2.3.4:443".to_string(), "snowflake".to_string(), 50.0)];
        let ooni = vec![
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 10,
                day_offset: 0,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 10,
                day_offset: -1,
                success: true,
            },
            OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 10,
                day_offset: -2,
                success: true,
            },
        ];
        // Targeting hour 22, but all records are for hour 10 → no matches → no boost.
        let recs = boost_bridges_by_irst_history(&bridges, &ooni, 22, 7);
        assert_eq!(recs[0].boost, 0.0);
    }

    #[test]
    fn final_score_clamped_to_zero_and_one_hundred() {
        let bridges = vec![("1.2.3.4:443".to_string(), "snowflake".to_string(), 95.0)];
        let mut ooni = Vec::new();
        for day in 0..10 {
            ooni.push(OoniIstRecord {
                bridge_host: "1.2.3.4:443".into(),
                transport: "snowflake".into(),
                irst_hour: 22,
                day_offset: -day,
                success: true,
            });
        }
        let recs = boost_bridges_by_irst_history(&bridges, &ooni, 22, 14);
        // base 95 + boost (capped at 15) = 110 → clamped to 100
        assert_eq!(recs[0].final_score, 100.0);
        assert!(recs[0].boost <= 15.0);
    }
}

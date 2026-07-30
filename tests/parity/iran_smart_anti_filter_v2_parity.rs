#![allow(warnings)]
// Tests for the NEW `src/iran_smart_anti_filter_v2.rs` module.
//
// This module is a new capability added during the migration — there is
// no Python original to parity-test against. The tests below exercise the
// public API surface and document the expected behavior. The library
// crate's internal `#[cfg(test)] mod tests` block also covers the same
// surface; this file mirrors the convention used by every other ported
// module so the test-runner inventory stays uniform.

use chrono::{NaiveDate, TimeZone, Utc};

use torshield_ir_ultra::iran_smart_anti_filter_v2::{
    boost_bridges_by_irst_history, classify_tier, current_tier, next_transport,
    preferred_ports_for_tier, preferred_transports_for_tier, routing_recommendation,
    CensorshipTier, IrstTierConfig, OoniIstRecord, IRST_OFFSET_SECS,
};

fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> chrono::DateTime<Utc> {
    Utc.from_utc_datetime(
        &NaiveDate::from_ymd_opt(y, mo, d)
            .unwrap()
            .and_hms_opt(h, mi, 0)
            .unwrap(),
    )
}

#[test]
fn irst_offset_is_3h30m() {
    assert_eq!(IRST_OFFSET_SECS, 12_600);
}

#[test]
fn tier_classification_smoke() {
    let cfg = IrstTierConfig::default();
    // 22:00 IRST = 18:30 UTC → ultra_stealth
    assert_eq!(
        classify_tier(utc(2026, 6, 24, 18, 30), &cfg),
        CensorshipTier::UltraStealth
    );
    // 10:00 IRST = 06:30 UTC → normal
    assert_eq!(
        classify_tier(utc(2026, 6, 24, 6, 30), &cfg),
        CensorshipTier::Normal
    );
}

#[test]
fn preferred_transports_exclude_vanilla_in_ultra_stealth() {
    let t = preferred_transports_for_tier(CensorshipTier::UltraStealth);
    assert!(!t.contains(&"vanilla"));
}

#[test]
fn preferred_ports_omit_80_in_ultra_stealth() {
    let p = preferred_ports_for_tier(CensorshipTier::UltraStealth);
    assert!(!p.contains(&80));
}

#[test]
fn boost_high_success_rate() {
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
    ];
    let recs = boost_bridges_by_irst_history(&bridges, &ooni, 22, 7);
    assert!(recs[0].boost > 0.0);
}

#[test]
fn penalty_low_success_rate() {
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
    assert!(recs[0].boost < 0.0);
}

#[test]
fn next_transport_skips_recent_failure() {
    let now = utc(2026, 6, 24, 18, 30); // ultra_stealth
    let tier = classify_tier(now, &IrstTierConfig::default());
    let recent = vec![("webtunnel".to_string(), now - chrono::Duration::minutes(5))];
    let next = next_transport(tier, &recent, now, 10);
    assert_eq!(next, "snowflake");
}

#[test]
fn routing_recommendation_returns_valid_json() {
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
    let rec = routing_recommendation(now, &IrstTierConfig::default(), &bridges, &ooni, &[], 7, 10);
    assert_eq!(rec["tier"], "ultra_stealth");
    assert!(rec["bridge_recommendations"].is_array());
}

#[test]
fn current_tier_does_not_panic() {
    let _ = current_tier();
}

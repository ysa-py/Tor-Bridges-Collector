//! Parity test for `iran_advanced_dpi_evasion` Rust module.
//!
//! This module has no Python original — it's a NEW capability added during
//! the migration. Tests verify correctness and internal consistency rather
//! than binary parity with a Python oracle.

use std::collections::{BTreeMap, BTreeSet};

use torshield_ir_ultra::iran_advanced_dpi_evasion::*;

#[test]
fn tls_profile_rotation_is_deterministic() {
    let seen = BTreeSet::new();
    let p1 = select_tls_profile(BROWSER_TLS_PROFILES, 10, &seen);
    let p2 = select_tls_profile(BROWSER_TLS_PROFILES, 10, &seen);
    assert_eq!(p1.unwrap().name, p2.unwrap().name);
}

#[test]
fn tls_profile_different_hours_give_different_profiles() {
    let seen = BTreeSet::new();
    let p0 = select_tls_profile(BROWSER_TLS_PROFILES, 0, &seen).unwrap().name.to_string();
    let p1 = select_tls_profile(BROWSER_TLS_PROFILES, 1, &seen).unwrap().name.to_string();
    // 0 % 4 = 0 (chrome_120), 1 % 4 = 1 (firefox_120)
    assert_ne!(p0, p1);
}

#[test]
fn cdn_fronting_arvan_is_most_reliable_in_iran() {
    let best = CDN_FRONTING_DOMAINS.iter().max_by(|a, b| {
        a.iran_reliability.partial_cmp(&b.iran_reliability).unwrap()
    }).unwrap();
    assert_eq!(best.provider, "Arvan Cloud");
}

#[test]
fn multi_path_primary_route_is_webtunnel() {
    assert_eq!(MULTI_PATH_ROUTES[0].name, "primary_tls");
    assert_eq!(MULTI_PATH_ROUTES[0].transport, "webtunnel");
}

#[test]
fn generate_evasion_strategy_includes_explanation() {
    let strategy = generate_evasion_strategy(
        "test 1.2.3.4:443",
        "obfs4",
        1,
        10,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
        false,
        false,
        0,
    );
    assert!(!strategy.explanation.is_empty(),
        "expected at least one explanation item, got {}",
        strategy.explanation.len()
    );
}

#[test]
fn anti_censorship_report_has_configuration() {
    let now = chrono::Utc::now();
    let report = generate_anti_censorship_report(&now, &[], 0, 12, 5);
    assert!(report.get("configuration").is_some());
    let config = report["configuration"].as_object().unwrap();
    assert!(config.contains_key("available_tls_profiles"));
    assert!(config.contains_key("available_cdn_domains"));
    assert!(config.contains_key("available_routes"));
}

#[test]
fn all_routes_have_valid_transports() {
    let valid_transports = ["webtunnel", "hysteria2", "snowflake", "obfs4", "meek_lite"];
    for route in MULTI_PATH_ROUTES {
        assert!(
            valid_transports.contains(&route.transport),
            "Route {} has invalid transport: {}",
            route.name,
            route.transport
        );
    }
}

#[test]
fn tcp_fragmentation_min_size_is_64() {
    assert_eq!(TCP_FRAGMENT_SIZES[0], 64);
    assert_eq!(TCP_FRAGMENT_SIZES[TCP_FRAGMENT_SIZES.len() - 1], 1460);
}

#[test]
fn morph_protocols_have_valid_ranges() {
    for p in MORPH_PROTOCOLS {
        assert!(p.padding_min <= p.padding_max);
        assert!(p.packet_size_mean > 0.0);
        assert!(p.packet_size_std > 0.0);
    }
}

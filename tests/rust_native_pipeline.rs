//! End-to-end contracts for the Rust-native Iran intelligence pipeline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use chrono::{TimeZone, Utc};
use serde_json::{json, Map, Value};
use torshield_ir_ultra::anti_ai_dpi;
use torshield_ir_ultra::ech_fingerprint_evasion::{self, NoProbe};
use torshield_ir_ultra::iran_advanced_dpi_evasion::{generate_evasion_strategy, MULTI_PATH_ROUTES};
use torshield_ir_ultra::iran_quantum_dpi_shield_v2::{ForecastInput, Shield, TransportLastUsed};
use torshield_ir_ultra::iran_smart_anti_filter_v2::{routing_recommendation, IrstTierConfig};
use torshield_ir_ultra::results_writer::write_result_files;
use torshield_ir_ultra::smart_iran_scorer::SmartIranScorer;

fn sandbox(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "torshield-rust-native-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("sandbox must be creatable");
    path
}

fn read_json(path: &std::path::Path) -> Value {
    let body = std::fs::read_to_string(path).expect("generated JSON must be readable");
    serde_json::from_str(&body).expect("generated document must be valid JSON")
}

#[test]
fn offline_dpi_pipelines_generate_ranked_reports_and_exports() {
    let root = sandbox("dpi");
    let input = root.join("bridges.json");
    let anti_report = root.join("anti-ai.json");
    let anti_export = root.join("anti-ai.txt");
    let ech_report = root.join("ech.json");
    let ech_export = root.join("ech.txt");
    let bridges = json!([
        "snowflake 1.2.3.10:443 FINGERPRINT fronts=www.google.com",
        "obfs4 1.2.3.7:443 FINGERPRINT cert=abc iat-mode=2",
        "1.2.3.9:9001 FINGERPRINT"
    ]);
    std::fs::write(&input, serde_json::to_vec_pretty(&bridges).unwrap()).unwrap();

    anti_ai_dpi::run_pipeline(&input, &anti_report, &anti_export).unwrap();
    ech_fingerprint_evasion::run_pipeline(&input, &ech_report, &ech_export, &NoProbe).unwrap();

    let anti = read_json(&anti_report);
    let ech = read_json(&ech_report);
    assert_eq!(anti["anti_ai_dpi_results"].as_array().unwrap().len(), 3);
    assert_eq!(ech["bridges"].as_array().unwrap().len(), 3);
    assert!(anti["anti_ai_dpi_results"][0]["anti_ai_dpi_score"].is_number());
    assert!(ech["bridges"][0]["iran_dpi_evasion_score"].is_number());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn adaptive_iran_engines_compose_without_an_external_client() {
    let now = Utc.with_ymd_and_hms(2026, 7, 30, 17, 30, 0).unwrap();
    let records: Vec<Map<String, Value>> = vec![
        Map::from_iter([
            (
                "raw".to_string(),
                json!("snowflake 1.2.3.10:443 FINGERPRINT fronts=www.google.com"),
            ),
            ("test_pass".to_string(), json!(true)),
        ]),
        Map::from_iter([
            (
                "raw".to_string(),
                json!("obfs4 1.2.3.7:443 FINGERPRINT cert=abc iat-mode=2"),
            ),
            ("test_pass".to_string(), json!(true)),
        ]),
    ];
    let scorer = SmartIranScorer::new(5, false, 35.0, 70.0);
    let ranked = scorer.score_all(&records);
    assert_eq!(ranked.len(), 2);
    assert!(ranked[0].final_score >= ranked[1].final_score);

    let routing_bridges: Vec<(String, String, f64)> = ranked
        .iter()
        .map(|score| {
            (
                score.bridge_id.to_string(),
                score.transport.clone(),
                score.final_score,
            )
        })
        .collect();
    let routing = routing_recommendation(
        now,
        &IrstTierConfig::default(),
        &routing_bridges,
        &[],
        &[],
        14,
        15,
    );
    assert!(routing["next_transport"].is_string());
    assert!(routing["preferred_ports"]
        .as_array()
        .unwrap()
        .contains(&json!(443)));

    let shield = Shield::new(now);
    let recommendation = shield.recommend(
        &ForecastInput {
            anomaly_count: 250,
            confirmed_count: 60,
            failure_count: 20,
            window_hours: 24,
            bridge_failure_rate: 0.4,
            nin_detected: false,
        },
        &TransportLastUsed::new(),
    );
    assert_eq!(
        recommendation["predicted_strategy"],
        "ja3_fingerprint_block"
    );
    assert!(recommendation["recommended_transport"].is_string());

    let strategy = generate_evasion_strategy(
        &ranked[0].raw,
        &ranked[0].transport,
        5,
        21,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
        false,
        false,
        42,
    );
    assert!(strategy.use_ech);
    assert!(strategy.quic_preferred);
    assert_eq!(strategy.route_priority.len(), MULTI_PATH_ROUTES.len());
}

#[test]
fn result_writer_preserves_all_bridge_output_capabilities() {
    let root = sandbox("writer");
    let records = vec![
        json!({
            "line": "obfs4 1.2.3.7:443 FINGERPRINT cert=abc iat-mode=2",
            "transport": "obfs4",
            "iran_status": "iran_likely_working",
            "tcp_reachable": true
        }),
        json!({
            "line": "webtunnel 203.0.113.2:443 FINGERPRINT url=https://cdn.example/path",
            "transport": "webtunnel",
            "iran_status": "iran_unknown",
            "tcp_reachable": true
        }),
    ];
    let stats = write_result_files(&root, &records).unwrap();
    assert_eq!(stats["iran_likely_working_obfs4.txt"], 1);
    assert_eq!(stats["iran_likely_working_webtunnel.txt"], 1);
    assert!(root.join("iran_likely_working_all.txt").is_file());
    assert!(root.join("tested_global_obfs4.txt").is_file());

    let _ = std::fs::remove_dir_all(root);
}

/// Regression contract for the NIN cut-pack empty-webtunnel defect:
/// URL-only WebTunnel bridges (the domain-fronted form BridgeDB publishes)
/// reach the results stage with an empty `host`, `tcp_reachable: false`,
/// and `iran_status: tcp_unreachable` because raw TCP cannot dial a bridge
/// that has no routable IP. The results stage must reclassify them from
/// the line's `url=` front domain so the WebTunnel special-case promotes
/// them into `iran_likely_working_webtunnel.txt` instead of leaving every
/// webtunnel tested/working projection empty.
#[test]
fn url_only_webtunnel_tcp_unreachable_is_promoted_to_working() {
    let root = sandbox("url-only-webtunnel");
    let records = vec![
        json!({
            "line": "webtunnel 68674E54A17AEB1C9ADE878BBBB46C6975DD3105 url=https://vika7.space/83c1327ea78e32b5d151e872ca123f7858aec2e1 ver=0.0.4",
            "transport": "webtunnel",
            "host": "",
            "iran_status": "tcp_unreachable",
            "tcp_reachable": false
        }),
        json!({
            // RFC 3849 documentation-prefix IPv6 placeholder: BridgeDB emits
            // these into webtunnel_ipv6 lines as anti-enumeration decoys.
            // They carry a literal placeholder endpoint and must NOT be
            // reclassified as working domain-front bridges.
            "line": "webtunnel [2001:db8:1218:1de7:3a91:22cc:8d7f:197c]:443 DF343521735ABE129910A998817B3A93AA2390FE url=https://coellen.xyz ver=0.0.3",
            "transport": "webtunnel",
            "host": "2001:db8:1218:1de7:3a91:22cc:8d7f:197c",
            "iran_status": "tcp_unreachable",
            "tcp_reachable": false
        }),
    ];
    let stats = write_result_files(&root, &records).unwrap();

    let wt = std::fs::read_to_string(root.join("iran_likely_working_webtunnel.txt"))
        .expect("webtunnel working file written");
    assert!(
        wt.contains("vika7.space"),
        "URL-only webtunnel must be promoted into iran_likely_working_webtunnel.txt, got: {wt:?}"
    );
    assert!(
        !wt.contains("2001:db8"),
        "documentation-prefix IPv6 placeholder must not be promoted, got: {wt:?}"
    );
    assert_eq!(
        stats["iran_likely_working_webtunnel.txt"], 1,
        "exactly one URL-only webtunnel promoted"
    );

    let _ = std::fs::remove_dir_all(root);
}

//! Offline contract tests for the public bridge and Telegram publication set.

use std::path::PathBuf;

use chrono::{TimeZone, Utc};
use serde_json::json;
use torshield_ir_ultra::bridge_publication::{
    publish_at, verify_publication, PublishOptions, REQUIRED_FILES,
};

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "torshield-publication-{name}-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(path.join("bridge")).unwrap();
    path
}

fn options(root: &std::path::Path) -> PublishOptions {
    PublishOptions {
        bridge_dir: root.join("bridge"),
        readme_path: root.join("README.md"),
        repo_url: "https://raw.example.invalid/org/repo/refs/heads/main".to_string(),
        recent_hours: 72,
        run_floor: None,
        relay_available: None,
    }
}

fn write_fixture(root: &std::path::Path) {
    let bridge = root.join("bridge");
    let now = "2026-08-01T23:30:00Z";
    let observed_at = "2026-08-01T23:55:00Z";
    let history = json!({
        "obfs4 1.2.3.10:443 FINGERPRINT cert=test iat-mode=0": {
            "raw": "obfs4 1.2.3.10:443 FINGERPRINT cert=test iat-mode=0",
            "transport": "obfs4",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"cloudflare_worker", "colo":"FRA"}, "probe_type":"obfs4-handshake", "observed_at":observed_at},
            "score": 88.0,
            "test_pass": false
        },
        "webtunnel 1.2.3.20:443 FINGERPRINT url=https://cdn.example.invalid/": {
            "raw": "webtunnel 1.2.3.20:443 FINGERPRINT url=https://cdn.example.invalid/",
            "transport": "webtunnel",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"cloudflare_worker", "colo":"FRA"}, "probe_type":"websocket-101", "observed_at":observed_at},
            "score": 91.0,
            "test_pass": false
        },
        "snowflake capability": {
            "raw": "snowflake 1.2.3.3:1 FINGERPRINT url=https://snowflake.example.invalid/",
            "transport": "snowflake",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"cloudflare_worker", "colo":"FRA"}, "probe_type":"snowflake-handshake", "observed_at":observed_at},
            "score": 95.0,
            "test_pass": false
        },
        "vanilla [2001:4860:4860::8844]:443 FINGERPRINT": {
            "raw": "[2001:4860:4860::8844]:443 FINGERPRINT",
            "transport": "vanilla",
            "ip_version": "ipv6",
            "first_seen": now,
            "last_seen": now,
            "score": 55.0,
            "test_pass": false
        },
        "conjure 1.2.3.9:443": {
            "raw": "conjure 1.2.3.9:443 FINGERPRINT",
            "transport": "conjure",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"cloudflare_worker", "colo":"FRA"}, "probe_type":"conjure-registration", "observed_at":observed_at},
            "score": 70.0,
            "test_pass": true
        },
        "meek-azure 1.2.3.10:443": {
            "raw": "meek-azure 1.2.3.10:443 FINGERPRINT",
            "transport": "meek-azure",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"cloudflare_worker", "colo":"FRA"}, "probe_type":"meek-post", "observed_at":observed_at},
            "score": 70.0,
            "test_pass": true
        }
    });
    let results = json!({
        "bridges": [
            {
                "line": "obfs4 1.2.3.10:443 FINGERPRINT cert=test iat-mode=0",
                "transport": "obfs4",
                "tcp_reachable": true,
                "transport_capable": false,
                "iran_status": "iran_unknown",
                "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"cloudflare_worker", "colo":"FRA"}, "probe_type":"obfs4-handshake", "observed_at":observed_at},
                "composite_score": 0.8
            },
            {
                "line": "webtunnel 1.2.3.20:443 FINGERPRINT url=https://cdn.example.invalid/",
                "transport": "webtunnel",
                "tcp_reachable": true,
                "transport_capable": false,
                "iran_status": "iran_unknown",
                "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"cloudflare_worker", "colo":"FRA"}, "probe_type":"websocket-101", "observed_at":observed_at},
                "composite_score": 0.9
            },
            {
                "line": "snowflake 1.2.3.3:1 FINGERPRINT url=https://snowflake.example.invalid/",
                "transport": "snowflake",
                "tcp_reachable": false,
                "transport_capable": true,
                "iran_status": "iran_unknown",
                "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"cloudflare_worker", "colo":"FRA"}, "probe_type":"snowflake-handshake", "observed_at":observed_at},
                "composite_score": 0.55
            },
            {
                "line": "[2001:4860:4860::8844]:443 FINGERPRINT",
                "transport": "vanilla",
                "tcp_reachable": false,
                "transport_capable": false,
                "iran_status": "iran_likely_blocked",
                "iran_assessment": {"status":"iran_likely_blocked", "source":"ooni_measurements_api", "checked":true, "vantage":{"type":"ooni_probe", "country":"IR"}, "queried_at":"2026-08-01T23:30:00Z", "measurement_at":"2026-08-01T23:30:00Z", "measurement_window_days":7},
                "composite_score": 0.0
            }
        ]
    });
    std::fs::write(
        bridge.join("bridge_history.json"),
        serde_json::to_string_pretty(&history).unwrap(),
    )
    .unwrap();
    std::fs::write(
        bridge.join("iran_results.json"),
        serde_json::to_string_pretty(&results).unwrap(),
    )
    .unwrap();
}

#[test]
fn publisher_rebuilds_every_required_file_and_verified_archive() {
    let root = scratch("complete");
    write_fixture(&root);
    let options = options(&root);
    let canonical_inputs = [
        (
            "bridge_history.json",
            std::fs::read(options.bridge_dir.join("bridge_history.json")).unwrap(),
        ),
        (
            "iran_results.json",
            std::fs::read(options.bridge_dir.join("iran_results.json")).unwrap(),
        ),
    ];
    std::fs::write(options.bridge_dir.join("obsolete-output.txt"), "stale\n").unwrap();
    std::fs::create_dir_all(options.bridge_dir.join("old-output")).unwrap();
    std::fs::write(options.bridge_dir.join("old-output/old.txt"), "stale\n").unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap();
    let report = publish_at(&options, now).unwrap();

    assert_eq!(report.archive_entries, REQUIRED_FILES.len() - 1);
    assert_eq!(report.history_records, 6);
    assert_eq!(report.probe_records, 4);
    for name in REQUIRED_FILES {
        assert!(
            options.bridge_dir.join(name).is_file(),
            "publisher missed required file {name}"
        );
    }
    assert!(options.readme_path.is_file());
    assert!(std::fs::read_to_string(&options.readme_path)
        .unwrap()
        .contains("Telegram dual persistence"));
    assert!(!options.bridge_dir.join("obsolete-output.txt").exists());
    assert!(!options.bridge_dir.join("old-output").exists());
    assert!(options.bridge_dir.join("bridge_history.json").is_file());
    assert!(options.bridge_dir.join("iran_results.json").is_file());
    for (name, original) in &canonical_inputs {
        assert_eq!(
            std::fs::read(options.bridge_dir.join(name))
                .unwrap()
                .as_slice(),
            original.as_slice(),
            "publisher must preserve canonical input bytes in {name}"
        );
    }

    const USER_REQUESTED_FILES: &[&str] = &[
        "bridge_history.json",
        "bridge_list_for_testing.json",
        "bridge_scores.json",
        "iran_results.json",
        "telegram_manifest.json",
        "conjure_ipv4_ipv6_all.txt",
        "conjure_72h_ipv4.txt",
        "conjure_72h_ipv6.txt",
        "conjure_72h.txt",
        "conjure_tested.txt",
        "iran_blocked_ipv4_ipv6_all.txt",
        "iran_likely_working_ipv4_ipv6_all.txt",
        "iran_likely_working_nin.txt",
        "iran_likely_working_obfs4.txt",
        "iran_likely_working_snowflake.txt",
        "iran_likely_working_vanilla.txt",
        "iran_likely_working_webtunnel.txt",
        "meek-azure_all.txt",
        "meek-azure_72h.txt",
        "meek-azure_tested.txt",
        "meek_lite_ipv4_ipv6_all.txt",
        "meek_lite_ipv4.txt",
        "meek_lite_72h_ipv4.txt",
        "meek_lite_72h_ipv6.txt",
        "meek_lite_ipv6.txt",
        "meek_lite_ipv6_tested.txt",
        "meek_lite_tested.txt",
        "obfs4_ipv4_ipv6_all.txt",
        "obfs4_tested.txt",
        "obfs4_72h_ipv4.txt",
        "obfs4_72h_ipv6.txt",
        "obfs4_ipv4_tested.txt",
        "obfs4_ipv6_tested.txt",
        "snowflak_ipv4_ipv6_all.txt",
        "snowflake_tested.txt",
        "snowflake_ipv6_tested",
        "snowflake_ipv6.txt",
        "snowflake_72h_ipv4.txt",
        "snowflake_72h_ipv6.txt",
        "tested_global_obfs4.txt",
        "tested_global_vanilla.txt",
        "tested_global_webtunnel.txt",
        "vanilla_ipv4_ipv6_all.txt",
        "vanilla_tested.txt",
        "vanilla_72h.txt",
        "vanilla_72h_ipv6.txt",
        "vanilla_ipv4.txt",
        "vanilla_ipv4_72h.txt",
        "vanilla_ipv4_tested.txt",
        "vanilla_ipv6.txt",
        "vanilla_ipv6_72h.txt",
        "vanilla_ipv6_tested.txt",
        "webtunnel_ipv4_ipv6_all.txt",
        "webtunnel_tested.txt",
        "webtunnel_ipv4.txt",
        "webtunnel_ipv4_tested.txt",
        "webtunnel_ipv6_tested.txt",
        "webtunnel_ipv6.txt",
        "webtunnel_72h.txt",
        "webtunnel_72h_ipv4.txt",
        "webtunnel_72h_ipv6.txt",
        "tor_bridges.zip",
    ];
    for name in USER_REQUESTED_FILES {
        assert!(
            REQUIRED_FILES.contains(name),
            "missing contract entry for {name}"
        );
        assert!(
            options.bridge_dir.join(*name).is_file(),
            "missing output {name}"
        );
    }

    assert_eq!(
        std::fs::read_to_string(options.bridge_dir.join("obfs4_72h_ipv6.txt")).unwrap(),
        std::fs::read_to_string(options.bridge_dir.join("obfs4_ipv6_72h.txt")).unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(options.bridge_dir.join("webtunnel_72h_ipv6.txt")).unwrap(),
        std::fs::read_to_string(options.bridge_dir.join("webtunnel_ipv6_72h.txt")).unwrap()
    );
    let read = |name: &str| std::fs::read_to_string(options.bridge_dir.join(name)).unwrap();
    assert!(read("conjure_72h_ipv4.txt").contains("conjure 1.2.3.9:443"));
    assert!(read("conjure_72h_ipv6.txt").trim().is_empty());
    assert!(read("conjure_72h.txt").contains("conjure 1.2.3.9:443"));
    assert!(read("conjure_tested.txt").contains("conjure 1.2.3.9:443"));
    assert!(read("obfs4_72h_ipv4.txt").contains("obfs4 1.2.3.10:443"));
    assert!(read("obfs4_72h_ipv6.txt").trim().is_empty());
    assert!(read("obfs4_ipv4_tested.txt").contains("obfs4 1.2.3.10:443"));
    assert!(read("obfs4_ipv6_tested.txt").trim().is_empty());
    assert!(read("snowflake_72h_ipv4.txt").contains("snowflake 1.2.3.3:1"));
    assert!(read("snowflake_72h_ipv6.txt").trim().is_empty());
    assert!(read("snowflake_tested.txt").contains("snowflake 1.2.3.3:1"));
    assert!(read("snowflake_ipv6_tested").trim().is_empty());
    assert!(read("vanilla_ipv6.txt").contains("[2001:4860:4860::8844]:443"));
    assert!(read("vanilla_ipv6_tested.txt").trim().is_empty());
    assert_eq!(
        read("iran_likely_working_all.txt"),
        read("iran_likely_working_ipv4_ipv6_all.txt")
    );
    assert_eq!(
        read("iran_blocked.txt"),
        read("iran_blocked_ipv4_ipv6_all.txt")
    );
    assert_eq!(
        read("snowflak_ipv4_ipv6_all.txt"),
        read("snowflake_ipv4_ipv6_all.txt")
    );
    assert_eq!(
        read("snowflake_ipv6_tested"),
        read("snowflake_ipv6_tested.txt")
    );

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(options.bridge_dir.join("telegram_manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["schema_version"], 3);
    assert_eq!(manifest["required_files_present"], true);
    assert_eq!(
        manifest["required_files"].as_array().unwrap().len(),
        REQUIRED_FILES.len()
    );
    assert_eq!(
        manifest["required_files"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>(),
        REQUIRED_FILES.to_vec()
    );
    assert_eq!(
        manifest["archive"]["entry_count"],
        json!(REQUIRED_FILES.len() - 1)
    );

    verify_publication(&options).unwrap();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verifier_rejects_archive_or_manifest_drift() {
    let root = scratch("tamper");
    write_fixture(&root);
    let options = options(&root);
    publish_at(&options, Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap()).unwrap();

    std::fs::write(options.bridge_dir.join("obfs4.txt"), "tampered\n").unwrap();
    let error = verify_publication(&options).unwrap_err().to_string();
    assert!(error.contains("manifest SHA-256 mismatch"));
    let _ = std::fs::remove_dir_all(root);
}

/// The transport probe legitimately rewrites the endpoint portion of a
/// webtunnel line (front-domain → resolved `IP:PORT`), so the canonical
/// history record and the probe record may disagree on everything except the
/// 40-hex fingerprint. The evidence join must fall back to the fingerprint so
/// the evidence-gated `webtunnel_tested.txt` projection fills instead of
/// silently staying empty.
#[test]
fn fingerprint_join_upgrades_history_records_with_rewritten_lines() {
    let root = scratch("fingerprint-join");
    let bridge = root.join("bridge");
    let now = "2026-08-01T23:30:00Z";
    let observed_at = "2026-08-01T23:55:00Z";
    let fp = "68674E54A17AEB1C9ADE878BBBB46C6975DD3105";
    // History keeps the originally collected form (placeholder endpoint as
    // collected from a mirror).
    let history_line = format!("webtunnel 198.51.100.7:443 {fp} url=https://front.example/t");
    let history = json!({
        "webtunnel placeholder form": {
            "raw": history_line,
            "transport": "webtunnel",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "tcp_reachable": true,
            "score": 0.7
        }
    });
    // The probe record carries the front-resolved endpoint form with the SAME
    // fingerprint plus a typed S2 observation.
    let probe_line = format!("webtunnel 104.21.60.225:443 {fp} url=https://front.example/t");
    let results = json!({
        "bridges": [
            {
                "line": probe_line,
                "transport": "webtunnel",
                "tcp_reachable": true,
                "iran_status": "iran_unknown",
                "verification": {"status":"connected", "stage":"S2", "vantage":{"type":"github_actions_runner", "region":null}, "probe_type":"websocket-101", "observed_at":observed_at},
                "composite_score": 0.9
            }
        ]
    });
    std::fs::write(
        bridge.join("bridge_history.json"),
        serde_json::to_string_pretty(&history).unwrap(),
    )
    .unwrap();
    std::fs::write(
        bridge.join("iran_results.json"),
        serde_json::to_string_pretty(&results).unwrap(),
    )
    .unwrap();

    let options = options(&root);
    publish_at(&options, Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap()).unwrap();

    let tested = std::fs::read_to_string(bridge.join("webtunnel_tested.txt")).unwrap();
    assert!(
        tested.contains(fp),
        "webtunnel_tested.txt must carry the fingerprint-joined verified bridge, got: {tested:?}"
    );
    let tested_global =
        std::fs::read_to_string(bridge.join("tested_global_webtunnel.txt")).unwrap();
    assert!(tested_global.contains(fp));
    let _ = std::fs::remove_dir_all(root);
}

/// Issue #257 root cause 3: BridgeDB substitutes RFC 3849 documentation-
/// prefix endpoints (`[2001:db8:…]:PORT`) for webtunnel bridges, and the
/// collected record is classified `ip_version: "ipv6"` from that synthetic
/// literal. The transport front probe resolves the REAL endpoint from
/// `url=` (typically an IPv4 CDN address). The publisher must adopt the
/// resolved dialable form in ALL projections and reclassify the IP family
/// from the real endpoint (v42 §C); otherwise the strict reserved-endpoint
/// filter empties every webtunnel family file on each run and the
/// publication guard keeps restoring grandfathered bytes.
#[test]
fn resolved_placeholder_endpoint_publishes_real_endpoint_and_family() {
    let root = scratch("webtunnel-resolved");
    let bridge = root.join("bridge");
    let now = "2026-08-01T23:30:00Z";
    let observed_at = "2026-08-01T23:55:00Z";
    let fp = "68674E54A17AEB1C9ADE878BBBB46C6975DD3105";
    let placeholder_line = format!(
        "webtunnel [2001:db8:1218:1de7:3a91:22cc:8d7f:197c]:443 {fp} url=https://front.example/t"
    );
    let resolved_line = format!("webtunnel 172.67.201.245:443 {fp} url=https://front.example/t");
    let history = json!({
        "webtunnel placeholder form": {
            "raw": placeholder_line,
            "transport": "webtunnel",
            "ip_version": "ipv6",
            "first_seen": now,
            "last_seen": now,
            "score": 0.45
        }
    });
    let results = json!({
        "bridges": [
            {
                "line": resolved_line,
                "transport": "webtunnel",
                "tcp_reachable": true,
                "iran_status": "iran_unknown",
                "verification": {"status":"connected", "stage":"S1", "vantage":{"type":"github_actions_runner", "region":null}, "probe_type":"websocket-front-check", "observed_at":observed_at},
                "composite_score": 0.45
            }
        ]
    });
    std::fs::write(
        bridge.join("bridge_history.json"),
        serde_json::to_string_pretty(&history).unwrap(),
    )
    .unwrap();
    std::fs::write(
        bridge.join("iran_results.json"),
        serde_json::to_string_pretty(&results).unwrap(),
    )
    .unwrap();

    let options = options(&root);
    publish_at(&options, Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap()).unwrap();

    let ipv4 = std::fs::read_to_string(bridge.join("webtunnel_ipv4.txt")).unwrap();
    assert!(
        ipv4.contains("172.67.201.245:443"),
        "resolved webtunnel endpoint must publish in the IPv4 family file, got: {ipv4:?}"
    );
    let all = std::fs::read_to_string(bridge.join("webtunnel_ipv4_ipv6_all.txt")).unwrap();
    assert!(all.contains("172.67.201.245:443"));
    let ipv6 = std::fs::read_to_string(bridge.join("webtunnel_ipv6.txt")).unwrap();
    assert!(
        !ipv6.contains("172.67.201.245:443") && !ipv6.contains("2001:db8"),
        "resolved IPv4 endpoint must not publish in the IPv6 family file, got: {ipv6:?}"
    );
    let testing = std::fs::read_to_string(bridge.join("bridge_list_for_testing.json")).unwrap();
    assert!(
        testing.contains("172.67.201.245:443"),
        "the probing list must carry the dialable resolved form, got: {testing:?}"
    );
    // Canonical history keeps the originally collected placeholder form.
    let history_after = std::fs::read_to_string(bridge.join("bridge_history.json")).unwrap();
    assert!(history_after.contains("2001:db8"));
    assert!(!history_after.contains("172.67.201.245"));
    let _ = std::fs::remove_dir_all(root);
}

/// A placeholder-raw webtunnel whose front probe produced no resolved
/// endpoint stays out of every consumer file (strict reserved-endpoint
/// filter); it remains in the canonical history for probing and census.
/// This is the honest zero-yield state — it must not be "fixed" by
/// publishing undialable placeholder endpoints.
#[test]
fn unresolved_placeholder_endpoint_stays_out_of_consumer_files() {
    let root = scratch("webtunnel-unresolved");
    let bridge = root.join("bridge");
    let now = "2026-08-01T23:30:00Z";
    let observed_at = "2026-08-01T23:55:00Z";
    let fp = "68674E54A17AEB1C9ADE878BBBB46C6975DD3105";
    let placeholder_line = format!(
        "webtunnel [2001:db8:1218:1de7:3a91:22cc:8d7f:197c]:443 {fp} url=https://front.example/t"
    );
    let history = json!({
        "webtunnel placeholder form": {
            "raw": placeholder_line.clone(),
            "transport": "webtunnel",
            "ip_version": "ipv6",
            "first_seen": now,
            "last_seen": now,
            "score": 0.45
        }
    });
    let results = json!({
        "bridges": [
            {
                "line": placeholder_line,
                "transport": "webtunnel",
                "tcp_reachable": false,
                "iran_status": "iran_unknown",
                "verification": {"status":"error", "stage":"S0", "vantage":{"type":"github_actions_runner", "region":null}, "probe_type":"tcp", "error_class":"tcp_connect_error", "observed_at":observed_at},
                "composite_score": 0.0
            }
        ]
    });
    std::fs::write(
        bridge.join("bridge_history.json"),
        serde_json::to_string_pretty(&history).unwrap(),
    )
    .unwrap();
    std::fs::write(
        bridge.join("iran_results.json"),
        serde_json::to_string_pretty(&results).unwrap(),
    )
    .unwrap();

    let options = options(&root);
    publish_at(&options, Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap()).unwrap();

    for name in [
        "webtunnel_ipv4_ipv6_all.txt",
        "webtunnel_ipv4.txt",
        "webtunnel_ipv6.txt",
        "webtunnel_72h_ipv6.txt",
    ] {
        let body = std::fs::read_to_string(bridge.join(name)).unwrap();
        assert!(
            !body.contains("2001:db8") && !body.contains(fp),
            "{name} must not publish undialable placeholder endpoints, got: {body:?}"
        );
    }
    let history_after = std::fs::read_to_string(bridge.join("bridge_history.json")).unwrap();
    assert!(
        history_after.contains("2001:db8"),
        "the canonical history must retain the placeholder record for probing and census"
    );
    let _ = std::fs::remove_dir_all(root);
}

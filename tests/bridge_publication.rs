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
    }
}

fn write_fixture(root: &std::path::Path) {
    let bridge = root.join("bridge");
    let now = "2026-08-01T23:30:00Z";
    let history = json!({
        "obfs4 198.51.100.10:443 FINGERPRINT cert=test iat-mode=0": {
            "raw": "obfs4 198.51.100.10:443 FINGERPRINT cert=test iat-mode=0",
            "transport": "obfs4",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "score": 88.0,
            "test_pass": false
        },
        "webtunnel 203.0.113.20:443 FINGERPRINT url=https://cdn.example.invalid/": {
            "raw": "webtunnel 203.0.113.20:443 FINGERPRINT url=https://cdn.example.invalid/",
            "transport": "webtunnel",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "score": 91.0,
            "test_pass": false
        },
        "snowflake capability": {
            "raw": "snowflake 192.0.2.3:1 FINGERPRINT url=https://snowflake.example.invalid/",
            "transport": "snowflake",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "score": 95.0,
            "test_pass": false
        },
        "vanilla [2001:db8::4]:443 FINGERPRINT": {
            "raw": "[2001:db8::4]:443 FINGERPRINT",
            "transport": "vanilla",
            "ip_version": "ipv6",
            "first_seen": now,
            "last_seen": now,
            "score": 55.0,
            "test_pass": false
        },
        "conjure 192.0.2.9:443": {
            "raw": "conjure 192.0.2.9:443 FINGERPRINT",
            "transport": "conjure",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "score": 70.0,
            "test_pass": true
        },
        "meek-azure 192.0.2.10:443": {
            "raw": "meek-azure 192.0.2.10:443 FINGERPRINT",
            "transport": "meek-azure",
            "ip_version": "ipv4",
            "first_seen": now,
            "last_seen": now,
            "score": 70.0,
            "test_pass": true
        }
    });
    let results = json!({
        "bridges": [
            {
                "line": "obfs4 198.51.100.10:443 FINGERPRINT cert=test iat-mode=0",
                "transport": "obfs4",
                "tcp_reachable": true,
                "transport_capable": false,
                "iran_status": "iran_unknown",
                "composite_score": 0.8
            },
            {
                "line": "webtunnel 203.0.113.20:443 FINGERPRINT url=https://cdn.example.invalid/",
                "transport": "webtunnel",
                "tcp_reachable": true,
                "transport_capable": false,
                "iran_status": "iran_unknown",
                "composite_score": 0.9
            },
            {
                "line": "snowflake 192.0.2.3:1 FINGERPRINT url=https://snowflake.example.invalid/",
                "transport": "snowflake",
                "tcp_reachable": false,
                "transport_capable": true,
                "iran_status": "iran_unknown",
                "composite_score": 0.55
            },
            {
                "line": "[2001:db8::4]:443 FINGERPRINT",
                "transport": "vanilla",
                "tcp_reachable": false,
                "transport_capable": false,
                "iran_status": "iran_likely_blocked",
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

    assert_eq!(
        std::fs::read_to_string(options.bridge_dir.join("obfs4_72h_ipv6.txt")).unwrap(),
        std::fs::read_to_string(options.bridge_dir.join("obfs4_ipv6_72h.txt")).unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(options.bridge_dir.join("webtunnel_72h_ipv6.txt")).unwrap(),
        std::fs::read_to_string(options.bridge_dir.join("webtunnel_ipv6_72h.txt")).unwrap()
    );

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(options.bridge_dir.join("telegram_manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["schema_version"], 2);
    assert_eq!(manifest["required_files_present"], true);
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

//! End-to-end tests for the deterministic publisher.
//!
//! These tests exercise the real rendering, snapshot, archive, manifest, and
//! atomic-write code paths against in-memory inputs and a scratch directory.
//! No network is used.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::Read;

use chrono::{DateTime, Utc};
use proptest::prelude::*;
use tbc_core::{BridgeLine, BridgeScore, Confidence, Tier};
use tbc_publish::{
    is_safe_name, render_text_list, sha256_hex, Publication, PublicationEntry, PublishConfig,
    PublishError, Publisher, SNAPSHOT_FILE,
};

fn t0() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn bridge(raw: &str) -> BridgeLine {
    BridgeLine::parse(raw, t0()).unwrap()
}

fn entry(name: &str, raw: &str) -> PublicationEntry {
    PublicationEntry {
        name: name.to_owned(),
        bridge: bridge(raw),
        score: None,
    }
}

fn scored_entry(name: &str, raw: &str, global: f64, tier: Tier) -> PublicationEntry {
    PublicationEntry {
        name: name.to_owned(),
        bridge: bridge(raw),
        score: Some(BridgeScore {
            global,
            per_asn: BTreeMap::new(),
            tier,
            confidence: Confidence::new(2, 2).unwrap(),
            first_confirmed_working_at: None,
            first_blocked_at: None,
            burn_seconds: None,
            median_lifetime_seconds: None,
            freshness_age_seconds: 60,
        }),
    }
}

fn publication() -> Publication {
    Publication {
        schema_version: 1,
        generated_at: t0(),
        entries: vec![
            scored_entry("obfs4.txt", "1.2.3.4:9001", 95.0, Tier::S),
            entry("obfs4.txt", "5.6.7.8:9002"),
            entry("webtunnel.txt", "9.10.11.12:9003"),
        ],
    }
}

#[test]
fn build_is_deterministic() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    let first = publisher.build(&publication()).unwrap();
    let second = publisher.build(&publication()).unwrap();
    assert_eq!(first, second);
}

#[test]
fn text_lists_are_grouped_sorted_and_deduplicated() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    let mut pubn = publication();
    // The same bridge twice in the same list must collapse to one line.
    pubn.entries.push(entry("obfs4.txt", "1.2.3.4:9001"));
    let bundle = publisher.build(&pubn).unwrap();

    let obfs4 = String::from_utf8(bundle.files["obfs4.txt"].clone()).unwrap();
    assert_eq!(obfs4, "1.2.3.4:9001\n5.6.7.8:9002\n");
    let webtunnel = String::from_utf8(bundle.files["webtunnel.txt"].clone()).unwrap();
    assert_eq!(webtunnel, "9.10.11.12:9003\n");
}

#[test]
fn snapshot_records_each_unique_bridge_once() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    let mut pubn = publication();
    // A bridge present in two list files still appears once in the snapshot.
    pubn.entries.push(entry("obfs4_ipv6.txt", "1.2.3.4:9001"));
    let bundle = publisher.build(&pubn).unwrap();

    let snapshot_json = String::from_utf8(bundle.files[SNAPSHOT_FILE].clone()).unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot_json).unwrap();
    assert_eq!(snapshot["schema_version"], 1);
    assert_eq!(snapshot["bridge_count"], 3);
    assert_eq!(snapshot["bridges"].as_array().unwrap().len(), 3);
    // Snapshot records are ordered by canonical key (host order here).
    assert_eq!(snapshot["bridges"][0]["line"]["host"], "1.2.3.4");
    assert_eq!(snapshot["bridges"][2]["line"]["host"], "9.10.11.12");
}

#[test]
fn archive_contains_every_bundle_file() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    let bundle = publisher.build(&publication()).unwrap();

    let reader = std::io::Cursor::new(bundle.archive.clone());
    let mut zip_archive = zip::ZipArchive::new(reader).unwrap();
    let mut names: Vec<String> = zip_archive.file_names().map(str::to_owned).collect();
    names.sort();
    let mut expected: Vec<String> = bundle.files.keys().cloned().collect();
    expected.sort();
    assert_eq!(names, expected);

    for (name, bytes) in &bundle.files {
        let mut entry = zip_archive.by_name(name).unwrap();
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents).unwrap();
        assert_eq!(&contents, bytes);
    }
}

#[test]
fn manifest_hashes_match_archive_and_contents() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    let bundle = publisher.build(&publication()).unwrap();

    assert_eq!(bundle.manifest.archive_sha256, bundle.archive_sha256);
    assert_eq!(bundle.manifest.entry_count, bundle.files.len());
    for file in &bundle.manifest.files {
        assert_eq!(file.sha256, sha256_hex(&bundle.files[&file.path]));
        assert_eq!(file.size as usize, bundle.files[&file.path].len());
    }
}

#[test]
fn zip_is_byte_reproducible_with_fixed_timestamp() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    let first = publisher.build(&publication()).unwrap();
    let second = publisher.build(&publication()).unwrap();
    assert_eq!(first.archive, second.archive);
    assert_eq!(first.archive_sha256, second.archive_sha256);
}

#[test]
fn invalid_and_reserved_names_are_rejected() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    for bad in [
        "",
        "../evil.txt",
        "a/b.txt",
        ".hidden",
        SNAPSHOT_FILE,
        "tor_bridges.zip",
        "manifest.json",
    ] {
        let pubn = Publication {
            schema_version: 1,
            generated_at: t0(),
            entries: vec![entry(bad, "1.2.3.4:9001")],
        };
        let error = publisher.build(&pubn).unwrap_err();
        assert!(
            matches!(error, PublishError::InvalidEntryName { .. }),
            "{bad:?} should be an InvalidEntryName, got {error:?}"
        );
    }
}

#[test]
fn empty_publication_is_rejected() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    let pubn = Publication {
        schema_version: 1,
        generated_at: t0(),
        entries: vec![],
    };
    let error = publisher.build(&pubn).unwrap_err();
    assert!(matches!(error, PublishError::EmptyPublication));
}

#[test]
fn config_rejects_colliding_reserved_names() {
    let config = PublishConfig {
        archive_name: "snapshot.json".to_owned(),
        ..PublishConfig::default()
    };
    assert!(Publisher::new(config).is_err());
}

#[test]
fn write_produces_all_files_atomically_without_temp_leftovers() {
    let publisher = Publisher::new(PublishConfig::default()).unwrap();
    let dir = std::env::temp_dir().join(format!("tbc-publish-write-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let mut expected = vec![
        "obfs4.txt".to_owned(),
        "webtunnel.txt".to_owned(),
        SNAPSHOT_FILE.to_owned(),
        "tor_bridges.zip".to_owned(),
        "manifest.json".to_owned(),
    ];
    expected.sort();

    let report = publisher.write(&publication(), &dir).unwrap();
    assert_eq!(report.written, expected);

    for name in &report.written {
        assert!(dir.join(name).is_file(), "missing {name}");
    }
    assert_no_temp_leftovers(&dir);

    // A second write replaces contents cleanly and leaves no temp files.
    let report2 = publisher.write(&publication(), &dir).unwrap();
    assert_eq!(report2.written, expected);
    assert_no_temp_leftovers(&dir);

    std::fs::remove_dir_all(&dir).unwrap();
}

fn assert_no_temp_leftovers(dir: &std::path::Path) {
    let leftovers: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
}

proptest! {
    #[test]
    fn rendered_lists_are_sorted_deduped_and_terminated(
        lines in proptest::collection::vec("[a-z ]{0,16}", 0..32)
    ) {
        let rendered = render_text_list(lines.iter().map(String::as_str), true);

        let mut expected: Vec<&str> = lines
            .iter()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect();
        expected.sort_unstable();
        expected.dedup();
        let mut joined = expected.join("\n");
        if !joined.is_empty() {
            joined.push('\n');
        }
        prop_assert_eq!(rendered, joined);
    }

    #[test]
    fn every_safe_name_of_safe_chars_is_accepted(
        name in "[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}"
    ) {
        prop_assert!(is_safe_name(&name));
    }
}

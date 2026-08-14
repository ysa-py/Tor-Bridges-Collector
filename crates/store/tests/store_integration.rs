//! Integration tests for the SQLite store: migrations, upserts, dedupe,
//! deterministic snapshot export, and atomic writes.
//!
//! These tests run against a real SQLite database (in-memory and file-backed)
//! with the full migration set applied, so they exercise every query path the
//! store exposes rather than a mocked schema.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use tempfile::tempdir;

use tbc_core::{
    BridgeLine, BridgeScore, Confidence, EvasionProfile, Observation, ProbeKind, Tier,
    TransportKind, Vantage, VantageKind, Verdict,
};
use tbc_store::{Snapshot, Store, StoreError};

fn rfc3339(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

fn fp() -> &'static str {
    "0123456789ABCDEF0123456789ABCDEF01234567"
}

/// 52 zero bytes encoded as 70 unpadded base64 characters.
fn cert52() -> String {
    "A".repeat(70)
}

fn obfs4_line(ip: &str) -> String {
    format!("obfs4 {ip}:443 {} cert={} iat-mode=0", fp(), cert52())
}

fn vanilla_line(ip: &str) -> String {
    format!("{ip}:9001 {}", fp())
}

fn observation(bridge_key: &str, measurement_ref: Option<&str>, at: DateTime<Utc>) -> Observation {
    Observation {
        bridge_key: bridge_key.to_owned(),
        vantage: Vantage {
            kind: VantageKind::Ooni,
            country: Some("IR".to_owned()),
            asn: Some(197_207),
            as_name: Some("MCCI".to_owned()),
            is_mobile: true,
        },
        probe_kind: ProbeKind::Obfs4Handshake,
        evasion_profile: EvasionProfile::Fragment { n: 2, delay: 30 },
        verdict: Verdict::Blocked {
            evidence: "SYN drop after ClientHello".to_owned(),
        },
        rtt_ms: Some(210),
        bootstrap_pct: None,
        error_class: Some("reset_injected".to_owned()),
        raw_evidence: None,
        measured_at: at,
        measurement_ref: measurement_ref.map(str::to_owned),
    }
}

fn sample_score() -> BridgeScore {
    let mut per_asn = BTreeMap::new();
    per_asn.insert(197_207u32, 88.5);
    BridgeScore {
        global: 90.0,
        per_asn,
        tier: Tier::A,
        confidence: Confidence::new(3, 4).unwrap(),
        first_confirmed_working_at: Some(rfc3339("2026-08-10T00:00:00+00:00")),
        first_blocked_at: None,
        burn_seconds: None,
        median_lifetime_seconds: Some(86_400),
        freshness_age_seconds: 3_600,
    }
}

#[tokio::test]
async fn migrations_apply_and_store_starts_empty() {
    let store = Store::open_in_memory().await.unwrap();
    assert_eq!(store.count_bridges().await.unwrap(), 0);
    assert_eq!(store.count_observations().await.unwrap(), 0);
    assert_eq!(store.count_scores().await.unwrap(), 0);
}

#[tokio::test]
async fn bridge_upsert_and_read_round_trips() {
    let store = Store::open_in_memory().await.unwrap();
    let bridge =
        BridgeLine::parse(&obfs4_line("1.2.3.4"), rfc3339("2026-08-13T00:00:00+00:00")).unwrap();
    store.upsert_bridge(&bridge).await.unwrap();

    let records = store.list_bridges().await.unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.canonical_key, bridge.canonical_key());
    assert_eq!(record.bridge.transport, TransportKind::Obfs4);
    assert_eq!(record.bridge.host, "1.2.3.4");
    assert_eq!(record.bridge.port, 443);
    assert_eq!(record.bridge.fingerprint.as_deref(), Some(fp()));
    assert_eq!(
        record.bridge.params.cert.as_deref(),
        Some(cert52().as_str())
    );

    let fetched = store.get_bridge(&bridge.canonical_key()).await.unwrap();
    assert_eq!(fetched, records[0]);
}

#[tokio::test]
async fn bridge_upsert_merges_sources_and_widens_time_window() {
    let store = Store::open_in_memory().await.unwrap();
    let first = rfc3339("2026-08-13T00:00:00+00:00");
    let later = rfc3339("2026-08-14T00:00:00+00:00");

    let mut a = BridgeLine::parse(&obfs4_line("5.6.7.8"), first).unwrap();
    a.add_source("bridgedb");
    store.upsert_bridge(&a).await.unwrap();

    let mut b = BridgeLine::parse(&obfs4_line("5.6.7.8"), later).unwrap();
    b.add_source("delta");
    b.add_source("bridgedb");
    store.upsert_bridge(&b).await.unwrap();

    let records = store.list_bridges().await.unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.bridge.first_seen, first);
    assert_eq!(record.bridge.last_seen, later);
    assert_eq!(record.bridge.sources.len(), 2);
    assert!(record.bridge.sources.contains("bridgedb"));
    assert!(record.bridge.sources.contains("delta"));
}

#[tokio::test]
async fn get_bridge_missing_returns_not_found() {
    let store = Store::open_in_memory().await.unwrap();
    let error = store.get_bridge("obfs4|1.2.3.4|443||").await.unwrap_err();
    assert!(matches!(error, StoreError::NotFound(_)));
}

#[tokio::test]
async fn list_by_transport_filters() {
    let store = Store::open_in_memory().await.unwrap();
    let now = rfc3339("2026-08-13T00:00:00+00:00");
    let obfs4 = BridgeLine::parse(&obfs4_line("1.2.3.4"), now).unwrap();
    let vanilla = BridgeLine::parse(&vanilla_line("9.9.9.9"), now).unwrap();
    store.upsert_bridge(&obfs4).await.unwrap();
    store.upsert_bridge(&vanilla).await.unwrap();

    let obfs4_only = store
        .list_bridges_by_transport(&TransportKind::Obfs4)
        .await
        .unwrap();
    assert_eq!(obfs4_only.len(), 1);
    assert_eq!(obfs4_only[0].bridge.transport, TransportKind::Obfs4);

    let vanilla_only = store
        .list_bridges_by_transport(&TransportKind::Vanilla)
        .await
        .unwrap();
    assert_eq!(vanilla_only.len(), 1);
    assert_eq!(vanilla_only[0].bridge.transport, TransportKind::Vanilla);
}

#[tokio::test]
async fn observation_dedupes_by_measurement_ref() {
    let store = Store::open_in_memory().await.unwrap();
    let key = "obfs4|1.2.3.4|443|FINGER|";
    let at = rfc3339("2026-08-13T00:00:00+00:00");

    let first = observation(key, Some("atlas-123"), at);
    assert!(store.upsert_observation(&first).await.unwrap());
    let duplicate = observation(key, Some("atlas-123"), at);
    assert!(!store.upsert_observation(&duplicate).await.unwrap());
    assert_eq!(store.count_observations().await.unwrap(), 1);

    // A distinct external measurement id inserts.
    let second = observation(key, Some("atlas-124"), at);
    assert!(store.upsert_observation(&second).await.unwrap());
    assert_eq!(store.count_observations().await.unwrap(), 2);

    // Without a measurement ref there is no dedupe key, so both rows are kept.
    let no_ref = observation(key, None, at);
    assert!(store.upsert_observation(&no_ref).await.unwrap());
    assert!(store.upsert_observation(&no_ref).await.unwrap());
    assert_eq!(store.count_observations().await.unwrap(), 4);
}

#[tokio::test]
async fn observation_round_trips_all_fields() {
    let store = Store::open_in_memory().await.unwrap();
    let key = "obfs4|1.2.3.4|443|FINGER|";
    let at = rfc3339("2026-08-13T00:00:00+00:00");
    let expected = observation(key, Some("globalping-1"), at);
    store.upsert_observation(&expected).await.unwrap();

    let list = store.list_observations().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0], expected);

    let since_early = store.list_observations_since(0).await.unwrap();
    assert_eq!(since_early.len(), 1);
    let since_late = store
        .list_observations_since(at.timestamp() + 1)
        .await
        .unwrap();
    assert!(since_late.is_empty());
}

#[tokio::test]
async fn score_upsert_round_trips_and_validates() {
    let store = Store::open_in_memory().await.unwrap();
    let key = "obfs4|1.2.3.4|443|FINGER|";
    let score = sample_score();
    store.upsert_score(key, &score).await.unwrap();
    let fetched = store.get_score(key).await.unwrap();
    assert_eq!(fetched, score);

    let mut invalid = sample_score();
    invalid.global = 101.0;
    let error = store.upsert_score(key, &invalid).await.unwrap_err();
    assert!(matches!(error, StoreError::Core(_)));
}

#[tokio::test]
async fn snapshot_is_deterministic_and_round_trips() {
    let store = Store::open_in_memory().await.unwrap();
    let now = rfc3339("2026-08-13T00:00:00+00:00");
    let bridge = BridgeLine::parse(&obfs4_line("1.2.3.4"), now).unwrap();
    store.upsert_bridge(&bridge).await.unwrap();
    store
        .upsert_observation(&observation(&bridge.canonical_key(), Some("atlas-1"), now))
        .await
        .unwrap();
    store
        .upsert_score(&bridge.canonical_key(), &sample_score())
        .await
        .unwrap();

    let generated = rfc3339("2026-08-13T12:00:00+00:00");
    let bytes_a = store.export_snapshot(generated).await.unwrap();
    let bytes_b = store.export_snapshot(generated).await.unwrap();
    assert_eq!(bytes_a, bytes_b);

    let snapshot = Snapshot::from_json_slice(&bytes_a).unwrap();
    assert_eq!(snapshot.schema_version, 1);
    assert_eq!(snapshot.bridge_count, 1);
    assert_eq!(snapshot.observation_count, 1);
    assert_eq!(snapshot.score_count, 1);
    assert_eq!(snapshot.bridges[0].canonical_key(), bridge.canonical_key());
    assert_eq!(snapshot.scores[0].bridge_key, bridge.canonical_key());
}

#[tokio::test]
async fn export_snapshot_to_writes_atomically() {
    let dir = tempdir().unwrap();
    let store = Store::open_in_memory().await.unwrap();
    let now = rfc3339("2026-08-13T00:00:00+00:00");
    let bridge = BridgeLine::parse(&obfs4_line("1.2.3.4"), now).unwrap();
    store.upsert_bridge(&bridge).await.unwrap();

    let target = dir.path().join("all.json");
    store.export_snapshot_to(&target, now).await.unwrap();

    // No temp files may remain next to the final artifact.
    let entries = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(entries, vec!["all.json".to_owned()]);

    let bytes = std::fs::read(&target).unwrap();
    let snapshot = Snapshot::from_json_slice(&bytes).unwrap();
    assert_eq!(snapshot.bridge_count, 1);
}

#[tokio::test]
async fn file_backed_store_persists_across_reopen() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("tbc.sqlite");
    let url = format!("sqlite:{}", db_path.display());

    let bridge =
        BridgeLine::parse(&obfs4_line("1.2.3.4"), rfc3339("2026-08-13T00:00:00+00:00")).unwrap();

    {
        let store = Store::connect(&url).await.unwrap();
        store.upsert_bridge(&bridge).await.unwrap();
    }

    // Reopening re-applies (idempotent) migrations and must see the data.
    let store = Store::connect(&url).await.unwrap();
    assert_eq!(store.count_bridges().await.unwrap(), 1);
    let records = store.list_bridges().await.unwrap();
    assert_eq!(records[0].bridge.canonical_key(), bridge.canonical_key());
}

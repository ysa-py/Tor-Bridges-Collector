//! SQLite-backed persistence for bridges, observations, and scores.
//!
//! Queries are runtime-checked against the SQLite schema and every query path
//! is exercised by the integration test suite (`tests/store_integration.rs`),
//! which applies every migration and verifies round-trips, deduplication,
//! ordering, and error handling against a real database. Column reads and
//! writes are typed via [`sqlx::FromRow`], so schema/type drift surfaces as a
//! test failure rather than a silent null or truncation.

use std::collections::BTreeSet;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::FromRow;

use tbc_core::{
    BridgeLine, BridgeScore, EvasionProfile, Observation, ProbeKind, TransportKind, Vantage,
    Verdict,
};

use crate::error::StoreError;
use crate::snapshot::{ScoredBridge, Snapshot};

/// Embedded, versioned schema migrations (see `migrations/`).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// The shared column list for observation reads (kept in one place so the
/// select lists cannot drift between query methods).
const OBSERVATION_COLUMNS: &str = "bridge_key, vantage_kind, country, asn, as_name, is_mobile, \
     probe_kind, evasion_profile, verdict, rtt_ms, bootstrap_pct, error_class, raw_evidence, \
     measured_at, measurement_ref";

/// A row of the `bridges` table (only the columns read back into Rust; the
/// denormalized `transport`/`host`/`port`/`fingerprint`/epoch columns remain
/// in the schema for SQL-side filtering and indexing).
#[derive(Debug, Clone, FromRow)]
struct BridgeRow {
    canonical_key: String,
    data: String,
    first_seen: String,
    last_seen: String,
}

/// A row of the `observations` table.
#[derive(Debug, Clone, FromRow)]
struct ObservationRow {
    bridge_key: String,
    vantage_kind: String,
    country: Option<String>,
    asn: Option<i64>,
    as_name: Option<String>,
    is_mobile: i64,
    probe_kind: String,
    evasion_profile: String,
    verdict: String,
    rtt_ms: Option<i64>,
    bootstrap_pct: Option<i64>,
    error_class: Option<String>,
    raw_evidence: Option<String>,
    measured_at: String,
    measurement_ref: Option<String>,
}

/// A bridge as persisted: its canonical key plus the fully reconstructed line.
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeRecord {
    /// The canonical dedupe key used as the primary key.
    pub canonical_key: String,
    /// The reconstructed bridge line, with merged timestamps and all sources.
    pub bridge: BridgeLine,
}

/// A persistent SQLite store. Cheap to clone (it wraps a connection pool).
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Connect to (creating if necessary) the SQLite database at `url` and
    /// apply any pending migrations.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    /// Open a private in-memory database for tests and short-lived runs.
    ///
    /// The pool is constrained to a single connection so every query observes
    /// the same in-memory database (SQLite's `:memory:` is per-connection).
    pub async fn open_in_memory() -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(":memory:")
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    // ── Bridges ────────────────────────────────────────────────────────────

    /// Insert a bridge, or merge it into the existing row with the same
    /// canonical key: the earliest `first_seen` and latest `last_seen` win,
    /// and sources accumulate (history is never deleted).
    pub async fn upsert_bridge(&self, bridge: &BridgeLine) -> Result<(), StoreError> {
        let key = bridge.canonical_key();
        let payload = serialize_bridge_payload(bridge)?;
        let transport = bridge.transport.to_string();
        let fingerprint = bridge.fingerprint.clone();
        let first_seen = bridge.first_seen.to_rfc3339();
        let last_seen = bridge.last_seen.to_rfc3339();

        let mut transaction = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO bridges
                 (canonical_key, transport, host, port, fingerprint, data,
                  first_seen, last_seen, first_seen_epoch, last_seen_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(canonical_key) DO UPDATE SET
                 transport = excluded.transport,
                 host = excluded.host,
                 port = excluded.port,
                 fingerprint = excluded.fingerprint,
                 data = excluded.data,
                 first_seen = CASE
                     WHEN bridges.first_seen_epoch <= excluded.first_seen_epoch
                         THEN bridges.first_seen ELSE excluded.first_seen END,
                 last_seen = CASE
                     WHEN bridges.last_seen_epoch >= excluded.last_seen_epoch
                         THEN bridges.last_seen ELSE excluded.last_seen END,
                 first_seen_epoch = MIN(bridges.first_seen_epoch, excluded.first_seen_epoch),
                 last_seen_epoch = MAX(bridges.last_seen_epoch, excluded.last_seen_epoch)",
        )
        .bind(&key)
        .bind(&transport)
        .bind(&bridge.host)
        .bind(i64::from(bridge.port))
        .bind(&fingerprint)
        .bind(&payload)
        .bind(&first_seen)
        .bind(&last_seen)
        .bind(bridge.first_seen.timestamp())
        .bind(bridge.last_seen.timestamp())
        .execute(&mut *transaction)
        .await?;

        for source in &bridge.sources {
            sqlx::query(
                "INSERT OR IGNORE INTO bridge_sources (canonical_key, source) VALUES (?1, ?2)",
            )
            .bind(&key)
            .bind(source)
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    /// Fetch one bridge by canonical key.
    pub async fn get_bridge(&self, key: &str) -> Result<BridgeRecord, StoreError> {
        let row = sqlx::query_as::<_, BridgeRow>(
            "SELECT canonical_key, data, first_seen, last_seen
             FROM bridges WHERE canonical_key = ?1",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;

        let row = row.ok_or_else(|| StoreError::NotFound(key.to_owned()))?;
        let sources = self.load_sources(&row.canonical_key).await?;
        bridge_record(row, sources)
    }

    /// List every bridge, ordered by canonical key for stable diffs.
    pub async fn list_bridges(&self) -> Result<Vec<BridgeRecord>, StoreError> {
        let rows = sqlx::query_as::<_, BridgeRow>(
            "SELECT canonical_key, data, first_seen, last_seen
             FROM bridges ORDER BY canonical_key",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let sources = self.load_sources(&row.canonical_key).await?;
            records.push(bridge_record(row, sources)?);
        }
        Ok(records)
    }

    /// List bridges of a single transport family.
    pub async fn list_bridges_by_transport(
        &self,
        transport: &TransportKind,
    ) -> Result<Vec<BridgeRecord>, StoreError> {
        let token = transport.to_string();
        let rows = sqlx::query_as::<_, BridgeRow>(
            "SELECT canonical_key, data, first_seen, last_seen
             FROM bridges WHERE transport = ?1 ORDER BY canonical_key",
        )
        .bind(&token)
        .fetch_all(&self.pool)
        .await?;

        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let sources = self.load_sources(&row.canonical_key).await?;
            records.push(bridge_record(row, sources)?);
        }
        Ok(records)
    }

    /// Number of distinct bridges currently stored.
    pub async fn count_bridges(&self) -> Result<i64, StoreError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bridges")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    // ── Observations ───────────────────────────────────────────────────────

    /// Insert an observation, deduplicating on `(bridge_key, measurement_ref)`.
    ///
    /// Returns `true` if the row was inserted and `false` if an identical
    /// external measurement was already present (the insert was ignored).
    pub async fn upsert_observation(&self, observation: &Observation) -> Result<bool, StoreError> {
        let probe_kind = serde_json::to_string(&observation.probe_kind)?;
        let evasion_profile = serde_json::to_string(&observation.evasion_profile)?;
        let verdict = serde_json::to_string(&observation.verdict)?;

        let result = sqlx::query(
            "INSERT OR IGNORE INTO observations
                 (bridge_key, vantage_kind, country, asn, as_name, is_mobile,
                  probe_kind, evasion_profile, verdict, rtt_ms, bootstrap_pct,
                  error_class, raw_evidence, measured_at, measured_at_epoch, measurement_ref)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )
        .bind(&observation.bridge_key)
        .bind(observation.vantage.kind.to_string())
        .bind(&observation.vantage.country)
        .bind(observation.vantage.asn.map(i64::from))
        .bind(&observation.vantage.as_name)
        .bind(i64::from(observation.vantage.is_mobile))
        .bind(&probe_kind)
        .bind(&evasion_profile)
        .bind(&verdict)
        .bind(observation.rtt_ms.map(|value| value as i64))
        .bind(observation.bootstrap_pct.map(i64::from))
        .bind(&observation.error_class)
        .bind(&observation.raw_evidence)
        .bind(observation.measured_at.to_rfc3339())
        .bind(observation.measured_at.timestamp())
        .bind(&observation.measurement_ref)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    /// List every observation, ordered for stable, deterministic exports.
    pub async fn list_observations(&self) -> Result<Vec<Observation>, StoreError> {
        let sql = format!(
            "SELECT {OBSERVATION_COLUMNS} FROM observations
             ORDER BY bridge_key, measured_at_epoch, measurement_ref, id"
        );
        let rows = sqlx::query_as::<_, ObservationRow>(&sql)
            .fetch_all(&self.pool)
            .await?;
        observations_from_rows(rows)
    }

    /// List observations for one bridge, oldest first.
    pub async fn list_observations_for_bridge(
        &self,
        bridge_key: &str,
    ) -> Result<Vec<Observation>, StoreError> {
        let sql = format!(
            "SELECT {OBSERVATION_COLUMNS} FROM observations WHERE bridge_key = ?1
             ORDER BY measured_at_epoch, measurement_ref, id"
        );
        let rows = sqlx::query_as::<_, ObservationRow>(&sql)
            .bind(bridge_key)
            .fetch_all(&self.pool)
            .await?;
        observations_from_rows(rows)
    }

    /// List observations measured at or after `epoch` (unix seconds).
    pub async fn list_observations_since(
        &self,
        epoch: i64,
    ) -> Result<Vec<Observation>, StoreError> {
        let sql = format!(
            "SELECT {OBSERVATION_COLUMNS} FROM observations WHERE measured_at_epoch >= ?1
             ORDER BY bridge_key, measured_at_epoch, measurement_ref, id"
        );
        let rows = sqlx::query_as::<_, ObservationRow>(&sql)
            .bind(epoch)
            .fetch_all(&self.pool)
            .await?;
        observations_from_rows(rows)
    }

    /// Number of observations currently stored.
    pub async fn count_observations(&self) -> Result<i64, StoreError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM observations")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    // ── Scores ─────────────────────────────────────────────────────────────

    /// Insert or replace a score for `key` after validating its ranges.
    pub async fn upsert_score(&self, key: &str, score: &BridgeScore) -> Result<(), StoreError> {
        score.validate().map_err(StoreError::Core)?;
        let per_asn = serde_json::to_string(&score.per_asn)?;
        let tier = serde_json::to_string(&score.tier)?;
        let payload = serde_json::to_string(score)?;

        sqlx::query(
            "INSERT INTO scores
                 (bridge_key, global_score, per_asn, tier, k, n,
                  first_confirmed_working_at, first_blocked_at, burn_seconds,
                  median_lifetime_seconds, freshness_age_seconds, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(bridge_key) DO UPDATE SET
                 global_score = excluded.global_score,
                 per_asn = excluded.per_asn,
                 tier = excluded.tier,
                 k = excluded.k,
                 n = excluded.n,
                 first_confirmed_working_at = excluded.first_confirmed_working_at,
                 first_blocked_at = excluded.first_blocked_at,
                 burn_seconds = excluded.burn_seconds,
                 median_lifetime_seconds = excluded.median_lifetime_seconds,
                 freshness_age_seconds = excluded.freshness_age_seconds,
                 data = excluded.data",
        )
        .bind(key)
        .bind(score.global)
        .bind(&per_asn)
        .bind(&tier)
        .bind(i64::from(score.confidence.k))
        .bind(i64::from(score.confidence.n))
        .bind(score.first_confirmed_working_at.map(|t| t.to_rfc3339()))
        .bind(score.first_blocked_at.map(|t| t.to_rfc3339()))
        .bind(score.burn_seconds.map(|value| value as i64))
        .bind(score.median_lifetime_seconds.map(|value| value as i64))
        .bind(score.freshness_age_seconds as i64)
        .bind(&payload)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch the stored score for `key`.
    pub async fn get_score(&self, key: &str) -> Result<BridgeScore, StoreError> {
        let payload =
            sqlx::query_scalar::<_, String>("SELECT data FROM scores WHERE bridge_key = ?1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| StoreError::NotFound(key.to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    /// List every score as `(bridge_key, score)`, ordered by bridge key.
    pub async fn list_scores(&self) -> Result<Vec<(String, BridgeScore)>, StoreError> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT bridge_key, data FROM scores ORDER BY bridge_key",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut scores = Vec::with_capacity(rows.len());
        for (key, payload) in rows {
            scores.push((key, serde_json::from_str(&payload)?));
        }
        Ok(scores)
    }

    /// Number of scores currently stored.
    pub async fn count_scores(&self) -> Result<i64, StoreError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scores")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    // ── Snapshots ──────────────────────────────────────────────────────────

    /// Build a deterministic snapshot of everything in the store.
    pub async fn build_snapshot(
        &self,
        generated_at: DateTime<Utc>,
    ) -> Result<Snapshot, StoreError> {
        let bridges = self
            .list_bridges()
            .await?
            .into_iter()
            .map(|record| record.bridge)
            .collect::<Vec<_>>();
        let observations = self.list_observations().await?;
        let scores = self
            .list_scores()
            .await?
            .into_iter()
            .map(|(bridge_key, score)| ScoredBridge { bridge_key, score })
            .collect::<Vec<_>>();
        Snapshot::new(generated_at, bridges, observations, scores)
    }

    /// Serialize a deterministic snapshot to pretty JSON bytes.
    pub async fn export_snapshot(
        &self,
        generated_at: DateTime<Utc>,
    ) -> Result<Vec<u8>, StoreError> {
        self.build_snapshot(generated_at).await?.to_json()
    }

    /// Write a snapshot to `path` atomically (temp file + rename).
    pub async fn export_snapshot_to(
        &self,
        path: &std::path::Path,
        generated_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let bytes = self.export_snapshot(generated_at).await?;
        crate::snapshot::write_atomic(path, &bytes)
    }

    /// Load the accumulated source set for one bridge, sorted.
    async fn load_sources(&self, key: &str) -> Result<BTreeSet<String>, StoreError> {
        let sources = sqlx::query_scalar::<_, String>(
            "SELECT source FROM bridge_sources WHERE canonical_key = ?1 ORDER BY source",
        )
        .bind(key)
        .fetch_all(&self.pool)
        .await?;
        Ok(sources.into_iter().collect())
    }
}

/// Serialize a bridge for the `data` column, excluding the source set (which
/// is stored relationally and merged back on read).
fn serialize_bridge_payload(bridge: &BridgeLine) -> Result<String, StoreError> {
    let mut payload = bridge.clone();
    payload.sources.clear();
    Ok(serde_json::to_string(&payload)?)
}

/// Parse an RFC 3339 string (as written by `to_rfc3339`) back into UTC.
fn parse_utc(value: &str) -> Result<DateTime<Utc>, StoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|error| StoreError::InvalidTimestamp(error.to_string()))
}

/// Reconstruct a [`BridgeRecord`] from a row plus its source set, applying the
/// merged `first_seen`/`last_seen` columns (which may differ from the
/// serialized payload's timestamps after a merge).
fn bridge_record(row: BridgeRow, sources: BTreeSet<String>) -> Result<BridgeRecord, StoreError> {
    let mut bridge: BridgeLine = serde_json::from_str(&row.data)?;
    bridge.first_seen = parse_utc(&row.first_seen)?;
    bridge.last_seen = parse_utc(&row.last_seen)?;
    bridge.sources = sources;
    Ok(BridgeRecord {
        canonical_key: row.canonical_key,
        bridge,
    })
}

/// Deserialize observation rows back into the typed model.
fn observations_from_rows(rows: Vec<ObservationRow>) -> Result<Vec<Observation>, StoreError> {
    rows.into_iter()
        .map(ObservationRow::into_observation)
        .collect()
}

impl ObservationRow {
    fn into_observation(self) -> Result<Observation, StoreError> {
        let vantage = Vantage {
            kind: self.vantage_kind.parse().map_err(StoreError::Core)?,
            country: self.country,
            asn: self.asn.map(|value| value as u32),
            as_name: self.as_name,
            is_mobile: self.is_mobile != 0,
        };
        let probe_kind: ProbeKind = serde_json::from_str(&self.probe_kind)?;
        let evasion_profile: EvasionProfile = serde_json::from_str(&self.evasion_profile)?;
        let verdict: Verdict = serde_json::from_str(&self.verdict)?;
        let measured_at = parse_utc(&self.measured_at)?;

        Ok(Observation {
            bridge_key: self.bridge_key,
            vantage,
            probe_kind,
            evasion_profile,
            verdict,
            rtt_ms: self.rtt_ms.map(|value| value as u64),
            bootstrap_pct: self.bootstrap_pct.map(|value| value as u8),
            error_class: self.error_class,
            raw_evidence: self.raw_evidence,
            measured_at,
            measurement_ref: self.measurement_ref,
        })
    }
}

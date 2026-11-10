//! SQLite-backed persistence for bridges, observations, and scores.
//!
//! The store wraps a single `rusqlite` connection (bundled SQLite >= 3.54, the
//! RUSTSEC-2026-0459 fix) behind a mutex. Every statement is short and local,
//! so the async methods keep the original `async fn` signatures while running
//! the query inline under the lock. Queries are runtime-checked against the
//! schema and every query path is exercised by the integration test suite
//! (`tests/store_integration.rs`), which applies every migration and verifies
//! round-trips, deduplication, ordering, and error handling against a real
//! database, so schema/type drift surfaces as a test failure rather than a
//! silent null or truncation.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row};

use tbc_core::{
    BridgeLine, BridgeScore, EvasionProfile, Observation, ProbeKind, TransportKind, Vantage,
    Verdict,
};

use crate::error::StoreError;
use crate::snapshot::{ScoredBridge, Snapshot};

/// Embedded, versioned schema migrations (see `migrations/`), applied in order
/// and tracked with SQLite's `PRAGMA user_version`.
const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../migrations/0001_init.sql"))];

/// The shared column list for observation reads (kept in one place so the
/// select lists cannot drift between query methods).
const OBSERVATION_COLUMNS: &str = "bridge_key, vantage_kind, country, asn, as_name, is_mobile, \
     probe_kind, evasion_profile, verdict, rtt_ms, bootstrap_pct, error_class, raw_evidence, \
     measured_at, measurement_ref";

/// A row of the `bridges` table (only the columns read back into Rust; the
/// denormalized `transport`/`host`/`port`/`fingerprint`/epoch columns remain
/// in the schema for SQL-side filtering and indexing).
#[derive(Debug, Clone)]
struct BridgeRow {
    canonical_key: String,
    data: String,
    first_seen: String,
    last_seen: String,
}

impl BridgeRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            canonical_key: row.get(0)?,
            data: row.get(1)?,
            first_seen: row.get(2)?,
            last_seen: row.get(3)?,
        })
    }
}

/// A row of the `observations` table.
#[derive(Debug, Clone)]
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

impl ObservationRow {
    /// Column order must match [`OBSERVATION_COLUMNS`].
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            bridge_key: row.get(0)?,
            vantage_kind: row.get(1)?,
            country: row.get(2)?,
            asn: row.get(3)?,
            as_name: row.get(4)?,
            is_mobile: row.get(5)?,
            probe_kind: row.get(6)?,
            evasion_profile: row.get(7)?,
            verdict: row.get(8)?,
            rtt_ms: row.get(9)?,
            bootstrap_pct: row.get(10)?,
            error_class: row.get(11)?,
            raw_evidence: row.get(12)?,
            measured_at: row.get(13)?,
            measurement_ref: row.get(14)?,
        })
    }
}

/// A bridge as persisted: its canonical key plus the fully reconstructed line.
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeRecord {
    /// The canonical dedupe key used as the primary key.
    pub canonical_key: String,
    /// The reconstructed bridge line, with merged timestamps and all sources.
    pub bridge: BridgeLine,
}

/// A persistent SQLite store. Cheap to clone (it shares one connection).
#[derive(Debug, Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

/// Resolve a `sqlite:` / `sqlite://` URL (query string ignored) to a file
/// path, or `None` for an in-memory database.
fn path_from_url(url: &str) -> Option<PathBuf> {
    let rest = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .unwrap_or(url);
    let rest = rest.split('?').next().unwrap_or(rest);
    if rest.is_empty() || rest == ":memory:" {
        None
    } else {
        Some(PathBuf::from(rest))
    }
}

/// Apply connection pragmas and any pending migrations.
fn initialize(conn: &mut Connection, file_backed: bool) -> Result<(), StoreError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    if file_backed {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
    }
    migrate(conn)
}

/// Bring the schema to the latest version.
///
/// Databases created by the previous sqlx-based store carry their applied
/// versions in `_sqlx_migrations`; those are adopted into `user_version`
/// instead of re-running DDL, so existing data keeps working.
fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let mut current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current == 0 {
        let legacy_table: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master
                            WHERE type = 'table' AND name = '_sqlx_migrations')",
            [],
            |row| row.get(0),
        )?;
        if legacy_table {
            current = conn.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success = 1",
                [],
                |row| row.get(0),
            )?;
            conn.pragma_update(None, "user_version", current)?;
        }
    }

    for (version, sql) in MIGRATIONS {
        if *version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)
            .map_err(|error| StoreError::Migration(format!("version {version}: {error}")))?;
        tx.pragma_update(None, "user_version", *version)?;
        tx.commit()?;
    }
    Ok(())
}

impl Store {
    /// Connect to (creating if necessary) the SQLite database at `url`
    /// (`sqlite:path`, `sqlite://path`, or `sqlite::memory:`) and apply any
    /// pending migrations.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        match path_from_url(url) {
            Some(path) => {
                let mut conn = Connection::open(path)?;
                initialize(&mut conn, true)?;
                Ok(Self::from_connection(conn))
            }
            None => Self::open_in_memory().await,
        }
    }

    /// Open a private in-memory database for tests and short-lived runs.
    ///
    /// The store owns a single connection, so every query observes the same
    /// in-memory database (SQLite's `:memory:` is per-connection).
    pub async fn open_in_memory() -> Result<Self, StoreError> {
        let mut conn = Connection::open_in_memory()?;
        initialize(&mut conn, false)?;
        Ok(Self::from_connection(conn))
    }

    fn from_connection(conn: Connection) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Lock the connection. A poisoned lock only means another thread
    /// panicked mid-statement; SQLite rolled that statement back, so the
    /// connection is still safe to use.
    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ── Bridges ────────────────────────────────────────────────────────────

    /// Insert a bridge, or merge it into the existing row with the same
    /// canonical key: the earliest `first_seen` and latest `last_seen` win,
    /// and sources accumulate (history is never deleted).
    pub async fn upsert_bridge(&self, bridge: &BridgeLine) -> Result<(), StoreError> {
        let key = bridge.canonical_key();
        let payload = serialize_bridge_payload(bridge)?;
        let transport = bridge.transport.to_string();
        let first_seen = bridge.first_seen.to_rfc3339();
        let last_seen = bridge.last_seen.to_rfc3339();

        let mut conn = self.conn();
        let tx = conn.transaction()?;

        tx.execute(
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
            params![
                key,
                transport,
                bridge.host,
                i64::from(bridge.port),
                bridge.fingerprint,
                payload,
                first_seen,
                last_seen,
                bridge.first_seen.timestamp(),
                bridge.last_seen.timestamp(),
            ],
        )?;

        for source in &bridge.sources {
            tx.execute(
                "INSERT OR IGNORE INTO bridge_sources (canonical_key, source) VALUES (?1, ?2)",
                params![key, source],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Fetch one bridge by canonical key.
    pub async fn get_bridge(&self, key: &str) -> Result<BridgeRecord, StoreError> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT canonical_key, data, first_seen, last_seen
                 FROM bridges WHERE canonical_key = ?1",
                params![key],
                BridgeRow::from_row,
            )
            .optional()?;

        let row = row.ok_or_else(|| StoreError::NotFound(key.to_owned()))?;
        let sources = load_sources(&conn, &row.canonical_key)?;
        bridge_record(row, sources)
    }

    /// List every bridge, ordered by canonical key for stable diffs.
    pub async fn list_bridges(&self) -> Result<Vec<BridgeRecord>, StoreError> {
        let conn = self.conn();
        query_bridge_records(
            &conn,
            "SELECT canonical_key, data, first_seen, last_seen
             FROM bridges ORDER BY canonical_key",
            params![],
        )
    }

    /// List bridges of a single transport family.
    pub async fn list_bridges_by_transport(
        &self,
        transport: &TransportKind,
    ) -> Result<Vec<BridgeRecord>, StoreError> {
        let token = transport.to_string();
        let conn = self.conn();
        query_bridge_records(
            &conn,
            "SELECT canonical_key, data, first_seen, last_seen
             FROM bridges WHERE transport = ?1 ORDER BY canonical_key",
            params![token],
        )
    }

    /// Number of distinct bridges currently stored.
    pub async fn count_bridges(&self) -> Result<i64, StoreError> {
        count_rows(&self.conn(), "SELECT COUNT(*) FROM bridges")
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

        let changed = self.conn().execute(
            "INSERT OR IGNORE INTO observations
                 (bridge_key, vantage_kind, country, asn, as_name, is_mobile,
                  probe_kind, evasion_profile, verdict, rtt_ms, bootstrap_pct,
                  error_class, raw_evidence, measured_at, measured_at_epoch, measurement_ref)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                observation.bridge_key,
                observation.vantage.kind.to_string(),
                observation.vantage.country,
                observation.vantage.asn.map(i64::from),
                observation.vantage.as_name,
                i64::from(observation.vantage.is_mobile),
                probe_kind,
                evasion_profile,
                verdict,
                observation.rtt_ms.map(|value| value as i64),
                observation.bootstrap_pct.map(i64::from),
                observation.error_class,
                observation.raw_evidence,
                observation.measured_at.to_rfc3339(),
                observation.measured_at.timestamp(),
                observation.measurement_ref,
            ],
        )?;

        Ok(changed == 1)
    }

    /// List every observation, ordered for stable, deterministic exports.
    pub async fn list_observations(&self) -> Result<Vec<Observation>, StoreError> {
        let sql = format!(
            "SELECT {OBSERVATION_COLUMNS} FROM observations
             ORDER BY bridge_key, measured_at_epoch, measurement_ref, id"
        );
        query_observations(&self.conn(), &sql, params![])
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
        query_observations(&self.conn(), &sql, params![bridge_key])
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
        query_observations(&self.conn(), &sql, params![epoch])
    }

    /// Number of observations currently stored.
    pub async fn count_observations(&self) -> Result<i64, StoreError> {
        count_rows(&self.conn(), "SELECT COUNT(*) FROM observations")
    }

    // ── Scores ─────────────────────────────────────────────────────────────

    /// Insert or replace a score for `key` after validating its ranges.
    pub async fn upsert_score(&self, key: &str, score: &BridgeScore) -> Result<(), StoreError> {
        score.validate().map_err(StoreError::Core)?;
        let per_asn = serde_json::to_string(&score.per_asn)?;
        let tier = serde_json::to_string(&score.tier)?;
        let payload = serde_json::to_string(score)?;

        self.conn().execute(
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
            params![
                key,
                score.global,
                per_asn,
                tier,
                i64::from(score.confidence.k),
                i64::from(score.confidence.n),
                score.first_confirmed_working_at.map(|t| t.to_rfc3339()),
                score.first_blocked_at.map(|t| t.to_rfc3339()),
                score.burn_seconds.map(|value| value as i64),
                score.median_lifetime_seconds.map(|value| value as i64),
                score.freshness_age_seconds as i64,
                payload,
            ],
        )?;
        Ok(())
    }

    /// Fetch the stored score for `key`.
    pub async fn get_score(&self, key: &str) -> Result<BridgeScore, StoreError> {
        let payload: String = self
            .conn()
            .query_row(
                "SELECT data FROM scores WHERE bridge_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(key.to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    /// List every score as `(bridge_key, score)`, ordered by bridge key.
    pub async fn list_scores(&self) -> Result<Vec<(String, BridgeScore)>, StoreError> {
        let rows: Vec<(String, String)> = {
            let conn = self.conn();
            let mut statement =
                conn.prepare("SELECT bridge_key, data FROM scores ORDER BY bridge_key")?;
            let mapped = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };

        let mut scores = Vec::with_capacity(rows.len());
        for (key, payload) in rows {
            scores.push((key, serde_json::from_str(&payload)?));
        }
        Ok(scores)
    }

    /// Number of scores currently stored.
    pub async fn count_scores(&self) -> Result<i64, StoreError> {
        count_rows(&self.conn(), "SELECT COUNT(*) FROM scores")
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
}

/// Run a `SELECT COUNT(*)`-style query.
fn count_rows(conn: &Connection, sql: &str) -> Result<i64, StoreError> {
    Ok(conn.query_row(sql, [], |row| row.get::<_, i64>(0))?)
}

/// Load the accumulated source set for one bridge, sorted.
fn load_sources(conn: &Connection, key: &str) -> Result<BTreeSet<String>, StoreError> {
    let mut statement =
        conn.prepare("SELECT source FROM bridge_sources WHERE canonical_key = ?1 ORDER BY source")?;
    let sources = statement
        .query_map(params![key], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(sources)
}

/// Run a bridge SELECT and rebuild each row with its source set.
fn query_bridge_records(
    conn: &Connection,
    sql: &str,
    query_params: impl rusqlite::Params,
) -> Result<Vec<BridgeRecord>, StoreError> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement
        .query_map(query_params, BridgeRow::from_row)?
        .collect::<Result<Vec<_>, _>>()?;

    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let sources = load_sources(conn, &row.canonical_key)?;
        records.push(bridge_record(row, sources)?);
    }
    Ok(records)
}

/// Run an observation SELECT (using [`OBSERVATION_COLUMNS`]) and decode rows.
fn query_observations(
    conn: &Connection,
    sql: &str,
    query_params: impl rusqlite::Params,
) -> Result<Vec<Observation>, StoreError> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement
        .query_map(query_params, ObservationRow::from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    observations_from_rows(rows)
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

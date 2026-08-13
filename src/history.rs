//! Parity port of `core/history.py`.
//!
//! Manages the on-disk bridge history database (bridge_history.json).
//! Stores first-seen date, last-seen date, test results, and Iran scores
//! for every bridge seen across all collection runs.
//!
//! All time-based logic uses `chrono::Utc::now()` (or an injectable clock)
//! for parity with the Python original's `utc_now()` / `utc_now_iso()`.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::dt_utils::{coerce_utc_dt, utc_now, DEFAULT_FALLBACK};

/// Typed errors for history-database operations.
#[derive(Debug)]
pub enum HistoryError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    Serialize {
        source: serde_json::Error,
    },
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "history io error at {}: {}", path.display(), source)
            }
            Self::Parse { path, source } => {
                write!(f, "history parse error at {}: {}", path.display(), source)
            }
            Self::Serialize { source } => write!(f, "history serialize error: {source}"),
        }
    }
}

impl std::error::Error for HistoryError {}

/// A single timestamped probe observation against a bridge.
///
/// This is the unit of the multi-probe history retained per bridge. The
/// timestamp is an ISO-8601 string (matching the record timestamps so the
/// on-disk JSON stays textually consistent); consumers parse it with the
/// crate's `coerce_utc_dt` helper.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeRecord {
    pub timestamp: String,
    pub passed: bool,
    pub latency_ms: Option<i64>,
}

impl ProbeRecord {
    /// Convert to a JSON object for persistence.
    pub fn to_json(&self) -> Value {
        json!({
            "timestamp": self.timestamp,
            "passed": self.passed,
            "latency_ms": self.latency_ms,
        })
    }

    /// Parse from a JSON object. Returns `None` if the value is not an
    /// object or lacks a `timestamp` string.
    pub fn from_json(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let timestamp = obj.get("timestamp").and_then(Value::as_str)?;
        Some(Self {
            timestamp: timestamp.to_string(),
            passed: obj.get("passed").and_then(Value::as_bool).unwrap_or(false),
            latency_ms: obj.get("latency_ms").and_then(Value::as_i64),
        })
    }
}

/// One bridge's history record. Mirrors the Python dict shape:
/// `{raw, transport, first_seen, last_seen, test_pass, test_time, latency_ms, score}`,
/// extended with a bounded, timestamped multi-probe log (`probes`) that the
/// six-window reputation engine consumes.
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeRecord {
    pub raw: String,
    pub transport: String,
    pub first_seen: String,
    pub last_seen: String,
    pub test_pass: Option<bool>,
    pub test_time: Option<String>,
    pub latency_ms: Option<i64>,
    pub score: i64,
    /// Bounded, timestamped probe log (newest last). Retained under the
    /// policy documented on [`HistoryManager::MAX_PROBES_PER_BRIDGE`].
    pub probes: VecDeque<ProbeRecord>,
}

impl BridgeRecord {
    /// Convert to a JSON object matching the Python dict shape plus the
    /// bounded `probes` log.
    pub fn to_json(&self) -> Value {
        json!({
            "raw": self.raw,
            "transport": self.transport,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "test_pass": self.test_pass,
            "test_time": self.test_time,
            "latency_ms": self.latency_ms,
            "score": self.score,
            "probes": self.probes.iter().map(ProbeRecord::to_json).collect::<Vec<_>>(),
        })
    }

    /// Parse from a JSON object. Returns `None` if the value is not an object.
    ///
    /// Backward compatible: records persisted before the multi-probe history
    /// feature (no `probes` key) load with an empty probe log.
    pub fn from_json(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let probes = obj
            .get("probes")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(ProbeRecord::from_json)
                    .collect::<VecDeque<_>>()
            })
            .unwrap_or_default();
        Some(Self {
            raw: obj
                .get("raw")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            transport: obj
                .get("transport")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            first_seen: obj
                .get("first_seen")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            last_seen: obj
                .get("last_seen")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            test_pass: obj.get("test_pass").and_then(Value::as_bool),
            test_time: obj
                .get("test_time")
                .and_then(Value::as_str)
                .map(|s| s.to_string()),
            latency_ms: obj.get("latency_ms").and_then(Value::as_i64),
            score: obj.get("score").and_then(Value::as_i64).unwrap_or(0),
            probes,
        })
    }
}

/// Mirror of Python's `HistoryManager`. State is a `BTreeMap<String, BridgeRecord>`.
///
/// `now` is injectable so tests can use a fixed clock. Production callers
/// should pass `chrono::Utc::now()` (or use [`HistoryManager::new`]).
pub struct HistoryManager {
    db: BTreeMap<String, BridgeRecord>,
    history_file: PathBuf,
    #[allow(dead_code)]
    bridge_dir: PathBuf,
    #[allow(dead_code)]
    export_dir: PathBuf,
    now: DateTime<Utc>,
}

impl HistoryManager {
    /// Number of probe observations retained per bridge (upper bound).
    ///
    /// Retention policy: a bridge keeps at most this many probe events, and
    /// only events newer than [`HistoryManager::PROBE_RETENTION_DAYS`]. 2,160
    /// bounds the worst case at one probe per hour across the full 90-day
    /// reputation window, keeping `bridge_history.json` bounded regardless of
    /// collection frequency.
    pub const MAX_PROBES_PER_BRIDGE: usize = 2160;

    /// Probe events older than this many days are pruned on write. Matches
    /// the widest reputation window (90d) so retained history always covers
    /// what the six-window engine can aggregate.
    pub const PROBE_RETENTION_DAYS: i64 = 90;

    /// Construct a new manager pointing at the given history file. Creates
    /// `bridge_dir` and `export_dir` if they don't exist (mirrors Python's
    /// `os.makedirs(..., exist_ok=True)` in `__init__`). Loads existing
    /// history from disk; on parse error, starts fresh (mirrors Python's
    /// broad `except Exception` swallow + log warning).
    pub fn new(
        history_file: &Path,
        bridge_dir: &Path,
        export_dir: &Path,
        now: DateTime<Utc>,
    ) -> Result<Self, HistoryError> {
        std::fs::create_dir_all(bridge_dir).map_err(|source| HistoryError::Io {
            path: bridge_dir.to_path_buf(),
            source,
        })?;
        std::fs::create_dir_all(export_dir).map_err(|source| HistoryError::Io {
            path: export_dir.to_path_buf(),
            source,
        })?;

        let mut mgr = Self {
            db: BTreeMap::new(),
            history_file: history_file.to_path_buf(),
            bridge_dir: bridge_dir.to_path_buf(),
            export_dir: export_dir.to_path_buf(),
            now,
        };
        mgr.load()?;
        Ok(mgr)
    }

    /// Production constructor — uses `chrono::Utc::now()` and the default
    /// paths from `config.py` (`bridge/`, `export/`, `bridge/bridge_history.json`).
    pub fn with_defaults() -> Result<Self, HistoryError> {
        Self::new(
            Path::new("bridge/bridge_history.json"),
            Path::new("bridge"),
            Path::new("export"),
            utc_now(),
        )
    }

    /// Mirror of Python's `_load`. On any error, logs a warning and starts
    /// fresh (does NOT propagate the error).
    pub fn load(&mut self) -> Result<(), HistoryError> {
        if !self.history_file.exists() {
            return Ok(());
        }
        let text =
            std::fs::read_to_string(&self.history_file).map_err(|source| HistoryError::Io {
                path: self.history_file.clone(),
                source,
            })?;
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(obj)) => {
                for (key, val) in obj.iter() {
                    if let Some(rec) = BridgeRecord::from_json(val) {
                        self.db.insert(key.clone(), rec);
                    }
                }
                tracing::info!("Loaded {} bridges from history.", self.db.len());
                Ok(())
            }
            Ok(_) => {
                tracing::warn!("History file is not a JSON object — starting fresh.");
                Ok(())
            }
            Err(source) => {
                tracing::warn!("Could not load history: {source}. Starting fresh.");
                // Mirror Python: don't propagate, just start fresh.
                Ok(())
            }
        }
    }

    /// Mirror of Python's `save`. Writes the database to disk with
    /// `indent=2, ensure_ascii=False`. Errors are propagated.
    pub fn save(&self) -> Result<(), HistoryError> {
        let mut obj = serde_json::Map::new();
        for (k, v) in &self.db {
            obj.insert(k.clone(), v.to_json());
        }
        let serialized = serde_json::to_string_pretty(&Value::Object(obj))
            .map_err(|source| HistoryError::Serialize { source })?;
        std::fs::write(&self.history_file, serialized).map_err(|source| HistoryError::Io {
            path: self.history_file.clone(),
            source,
        })?;
        tracing::debug!("History saved ({} entries).", self.db.len());
        Ok(())
    }

    /// Mirror of Python's `_normalize_key`. Strips leading whitespace and
    /// a leading `"Bridge "` prefix, then lowercases.
    pub fn normalize_key(line: &str) -> String {
        let mut s = line.trim().to_string();
        if s.starts_with("Bridge ") {
            s = s[7..].to_string();
        }
        s.to_ascii_lowercase()
    }

    /// Mirror of Python's `add_bridge`. Registers a bridge as newly seen
    /// (or updates `last_seen` and `raw` if already present).
    pub fn add_bridge(&mut self, line: &str, transport: &str) {
        let key = Self::normalize_key(line);
        if key.is_empty() {
            return;
        }
        let now_iso = self.now_iso();
        let raw = line.trim().to_string();
        match self.db.get_mut(&key) {
            Some(rec) => {
                rec.last_seen = now_iso;
                rec.raw = raw;
            }
            None => {
                self.db.insert(
                    key,
                    BridgeRecord {
                        raw,
                        transport: transport.to_string(),
                        first_seen: now_iso.clone(),
                        last_seen: now_iso,
                        test_pass: None,
                        test_time: None,
                        latency_ms: None,
                        score: 0,
                        probes: VecDeque::new(),
                    },
                );
            }
        }
    }

    /// Mirror of Python's `update_test`. Records the result of a
    /// connectivity test. No-op if the bridge is not in the database.
    ///
    /// Behavior is additive: the single-record fields (`test_pass`,
    /// `test_time`, `latency_ms`) are updated exactly as before, and the
    /// observation is also appended to the bridge's bounded multi-probe log
    /// (stamped with the manager's clock), so existing single-record callers
    /// are unaffected while the reputation engine gains a real producer.
    pub fn update_test(&mut self, line: &str, passed: bool, latency_ms: Option<i64>) {
        let key = Self::normalize_key(line);
        let now_iso = self.now_iso();
        if let Some(rec) = self.db.get_mut(&key) {
            rec.test_pass = Some(passed);
            rec.test_time = Some(now_iso.clone());
            if let Some(lat) = latency_ms {
                rec.latency_ms = Some(lat);
            }
            rec.probes.push_back(ProbeRecord {
                timestamp: now_iso,
                passed,
                latency_ms,
            });
            prune_probes(rec, self.now);
        }
    }

    /// Record a probe observation at an explicit timestamp, appending it to
    /// the bridge's bounded probe log. This timestamp-explicit form exists
    /// for replay/import and deterministic tests; production callers record
    /// via [`Self::update_test`] (stamped with the manager's clock). It does
    /// NOT touch the single-record `test_pass`/`test_time`/`latency_ms`
    /// fields — replayed observations are history, not the latest result.
    /// No-op if the bridge is not in the database.
    pub fn record_probe_at(
        &mut self,
        line: &str,
        timestamp: DateTime<Utc>,
        passed: bool,
        latency_ms: Option<i64>,
    ) {
        let key = Self::normalize_key(line);
        if let Some(rec) = self.db.get_mut(&key) {
            rec.probes.push_back(ProbeRecord {
                timestamp: fmt_iso(timestamp),
                passed,
                latency_ms,
            });
            prune_probes(rec, self.now);
        }
    }

    /// Return the bounded probe log for a bridge (newest last), or an empty
    /// vector if the bridge is unknown. This is the multi-probe input the
    /// six-window reputation engine aggregates.
    pub fn probe_history(&self, line: &str) -> Vec<ProbeRecord> {
        let key = Self::normalize_key(line);
        self.db
            .get(&key)
            .map(|rec| rec.probes.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Enforce the probe log's invariants after an append: chronological order
/// (oldest first, "newest last"), the [`HistoryManager::PROBE_RETENTION_DAYS`]
/// age cutoff, and the [`HistoryManager::MAX_PROBES_PER_BRIDGE`] bound (which
/// drops the oldest events first). Ordering matters: callers may replay or
/// import observations out of chronological order via
/// [`HistoryManager::record_probe_at`], and the bound loop below relies on the
/// log being sorted so it drops the genuinely oldest events.
///
/// Timestamps are always [`fmt_iso`]-formatted UTC with a fixed `+00:00` offset
/// and a single fractional-second convention, so lexicographic comparison of the
/// timestamp strings equals chronological comparison.
fn prune_probes(rec: &mut BridgeRecord, now: DateTime<Utc>) {
    rec.probes
        .make_contiguous()
        .sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let cutoff = now - chrono::Duration::days(HistoryManager::PROBE_RETENTION_DAYS);
    rec.probes.retain(|p| {
        let dt = coerce_utc_dt(Some(&p.timestamp), DEFAULT_FALLBACK);
        dt > cutoff
    });
    while rec.probes.len() > HistoryManager::MAX_PROBES_PER_BRIDGE {
        rec.probes.pop_front();
    }
}

impl HistoryManager {
    /// Mirror of Python's `update_score`. No-op if the bridge is not in
    /// the database.
    pub fn update_score(&mut self, line: &str, score: i64) {
        let key = Self::normalize_key(line);
        if let Some(rec) = self.db.get_mut(&key) {
            rec.score = score;
        }
    }

    /// Mirror of Python's `get_all`. Returns a snapshot of all records.
    pub fn get_all(&self) -> Vec<(String, BridgeRecord)> {
        self.db
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Mirror of Python's `get_by_transport`. Case-insensitive transport match.
    pub fn get_by_transport(&self, transport: &str) -> Vec<BridgeRecord> {
        let t = transport.to_ascii_lowercase();
        self.db
            .values()
            .filter(|v| v.transport.to_ascii_lowercase() == t)
            .cloned()
            .collect()
    }

    /// Mirror of Python's `get_recent`. Returns records whose `first_seen`
    /// is within the last `hours` hours.
    pub fn get_recent(&self, hours: i64) -> Vec<BridgeRecord> {
        let cutoff = self.now - chrono::Duration::hours(hours);
        self.db
            .values()
            .filter(|v| {
                let dt = coerce_utc_dt(Some(&v.first_seen), DEFAULT_FALLBACK);
                dt > cutoff
            })
            .cloned()
            .collect()
    }

    /// Mirror of Python's `get_tested`. Returns records where `test_pass`
    /// equals `passed`.
    pub fn get_tested(&self, passed: bool) -> Vec<BridgeRecord> {
        self.db
            .values()
            .filter(|v| v.test_pass == Some(passed))
            .cloned()
            .collect()
    }

    /// Mirror of Python's `get_stats`. Returns a summary dict.
    pub fn get_stats(&self) -> Value {
        let total = self.db.len() as i64;
        let tested = self.db.values().filter(|v| v.test_pass.is_some()).count() as i64;
        let passing = self
            .db
            .values()
            .filter(|v| v.test_pass == Some(true))
            .count() as i64;
        let mut by_transport: BTreeMap<String, i64> = BTreeMap::new();
        for v in self.db.values() {
            *by_transport.entry(v.transport.clone()).or_insert(0) += 1;
        }
        json!({
            "total": total,
            "tested": tested,
            "passing": passing,
            "by_transport": by_transport,
            "updated": self.now_iso(),
        })
    }

    /// Mirror of Python's `purge_old`. Removes entries whose `last_seen`
    /// is older than `days` days. Returns the number of removed entries.
    pub fn purge_old(&mut self, days: i64) -> usize {
        let cutoff = self.now - chrono::Duration::days(days);
        let before = self.db.len();
        self.db.retain(|_, v| {
            let dt = coerce_utc_dt(
                Some(if v.last_seen.is_empty() {
                    "2000-01-01"
                } else {
                    &v.last_seen
                }),
                DEFAULT_FALLBACK,
            );
            dt > cutoff
        });
        let removed = before - self.db.len();
        if removed > 0 {
            tracing::info!("Purged {removed} stale bridges (older than {days} days).");
        }
        removed
    }

    /// Internal helper: ISO timestamp for the current `self.now`.
    fn now_iso(&self) -> String {
        fmt_iso(self.now)
    }
}

/// Format a `DateTime<Utc>` exactly like Python's `datetime.now(UTC).isoformat()`:
/// a literal `+00:00` offset (NOT `Z`), and the fractional-seconds part present
/// only when microseconds are nonzero (then 6 digits). `chrono`'s
/// `to_rfc3339_opts(Micros, true)` diverges on both counts (`...000000Z`),
/// which would break byte-for-byte parity of every persisted timestamp
/// (first_seen / last_seen / test_time / updated / probe timestamps).
fn fmt_iso(dt: DateTime<Utc>) -> String {
    if dt.timestamp_subsec_micros() == 0 {
        dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        dt.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> DateTime<Utc> {
        // 2026-06-28T12:00:00Z
        chrono::DateTime::parse_from_rfc3339("2026-06-28T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn normalize_key_strips_bridge_prefix_and_lowercases() {
        assert_eq!(
            HistoryManager::normalize_key("  Bridge OBFS4 1.2.3.4:443  "),
            "obfs4 1.2.3.4:443"
        );
        assert_eq!(
            HistoryManager::normalize_key("obfs4 1.2.3.4:443"),
            "obfs4 1.2.3.4:443"
        );
        assert_eq!(HistoryManager::normalize_key(""), "");
    }

    #[test]
    fn add_bridge_inserts_new_record_with_correct_fields() {
        let dir = std::env::temp_dir().join(format!("history_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443 cert=abc", "obfs4");
        let all = mgr.get_all();
        assert_eq!(all.len(), 1);
        let (_, rec) = &all[0];
        assert_eq!(rec.transport, "obfs4");
        assert_eq!(rec.score, 0);
        assert!(rec.test_pass.is_none());
        assert!(!rec.first_seen.is_empty());
    }

    #[test]
    fn add_bridge_updates_existing_record() {
        let dir = std::env::temp_dir().join(format!("history_test2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        mgr.add_bridge("OBFS4 1.2.3.4:443", "obfs4"); // same key after normalization
        let all = mgr.get_all();
        assert_eq!(all.len(), 1); // deduplicated
    }

    #[test]
    fn update_test_records_pass_and_latency() {
        let dir = std::env::temp_dir().join(format!("history_test3_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        mgr.update_test("obfs4 1.2.3.4:443", true, Some(42));
        let tested = mgr.get_tested(true);
        assert_eq!(tested.len(), 1);
        assert_eq!(tested[0].latency_ms, Some(42));
    }

    #[test]
    fn update_score_sets_score() {
        let dir = std::env::temp_dir().join(format!("history_test4_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        mgr.update_score("obfs4 1.2.3.4:443", 75);
        let all = mgr.get_all();
        assert_eq!(all[0].1.score, 75);
    }

    #[test]
    fn get_by_transport_filters_case_insensitive() {
        let dir = std::env::temp_dir().join(format!("history_test5_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        mgr.add_bridge("snowflake 5.6.7.8:1", "snowflake");
        assert_eq!(mgr.get_by_transport("OBFS4").len(), 1);
        assert_eq!(mgr.get_by_transport("snowflake").len(), 1);
        assert_eq!(mgr.get_by_transport("vanilla").len(), 0);
    }

    #[test]
    fn purge_old_removes_stale_entries() {
        let dir = std::env::temp_dir().join(format!("history_test6_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        // Add a bridge, then rewind its last_seen to 100 days ago.
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        let key = HistoryManager::normalize_key("obfs4 1.2.3.4:443");
        let old = fixed_now() - chrono::Duration::days(100);
        if let Some(rec) = mgr.db.get_mut(&key) {
            rec.last_seen = old.to_rfc3339();
        }
        let removed = mgr.purge_old(30);
        assert_eq!(removed, 1);
        assert_eq!(mgr.get_all().len(), 0);
    }

    #[test]
    fn save_and_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("history_test7_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("hist.json");
        {
            let mut mgr =
                HistoryManager::new(&path, &dir.join("bridge"), &dir.join("export"), fixed_now())
                    .unwrap();
            mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
            mgr.update_test("obfs4 1.2.3.4:443", true, Some(50));
            mgr.update_score("obfs4 1.2.3.4:443", 80);
            mgr.save().unwrap();
        }
        // Re-load
        let mgr2 =
            HistoryManager::new(&path, &dir.join("bridge"), &dir.join("export"), fixed_now())
                .unwrap();
        let all = mgr2.get_all();
        assert_eq!(all.len(), 1);
        let (_, rec) = &all[0];
        assert_eq!(rec.score, 80);
        assert_eq!(rec.test_pass, Some(true));
        assert_eq!(rec.latency_ms, Some(50));
    }

    #[test]
    fn update_test_appends_probe_and_keeps_single_record_fields() {
        let dir = std::env::temp_dir().join(format!("history_probe1_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        mgr.update_test("obfs4 1.2.3.4:443", true, Some(50));
        mgr.update_test("obfs4 1.2.3.4:443", false, Some(90));

        // Single-record fields hold the LATEST result (unchanged behavior).
        let all = mgr.get_all();
        assert_eq!(all.len(), 1);
        let (_, rec) = &all[0];
        assert_eq!(rec.test_pass, Some(false));
        assert_eq!(rec.latency_ms, Some(90));
        // Multi-probe log retains BOTH observations (additive).
        let probes = mgr.probe_history("obfs4 1.2.3.4:443");
        assert_eq!(probes.len(), 2);
        assert!(probes[0].passed);
        assert_eq!(probes[0].latency_ms, Some(50));
        assert!(!probes[1].passed);
        assert_eq!(probes[1].latency_ms, Some(90));
    }

    #[test]
    fn probe_history_bounded_by_max_probes_drops_oldest() {
        let dir = std::env::temp_dir().join(format!("history_probe2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let now = fixed_now();
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            now,
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        let overflow = HistoryManager::MAX_PROBES_PER_BRIDGE + 10;
        for i in 0..overflow {
            mgr.record_probe_at(
                "obfs4 1.2.3.4:443",
                now - chrono::Duration::minutes((overflow - i) as i64),
                true,
                Some(i as i64),
            );
        }
        let probes = mgr.probe_history("obfs4 1.2.3.4:443");
        assert_eq!(probes.len(), HistoryManager::MAX_PROBES_PER_BRIDGE);
        // Oldest 10 dropped: first retained probe is the 11th recorded.
        assert_eq!(probes[0].latency_ms, Some(10));
        // Newest retained.
        assert_eq!(
            probes.last().unwrap().latency_ms,
            Some((overflow - 1) as i64)
        );
    }

    #[test]
    fn probe_history_pruned_by_retention_days() {
        let dir = std::env::temp_dir().join(format!("history_probe3_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let now = fixed_now();
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            now,
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        // A 100-day-old probe is beyond PROBE_RETENTION_DAYS = 90.
        mgr.record_probe_at(
            "obfs4 1.2.3.4:443",
            now - chrono::Duration::days(100),
            true,
            Some(10),
        );
        // A fresh probe triggers the prune on write.
        mgr.update_test("obfs4 1.2.3.4:443", true, Some(20));
        let probes = mgr.probe_history("obfs4 1.2.3.4:443");
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].latency_ms, Some(20));
        assert!(probes[0].timestamp.contains("2026-06-28"));
    }

    #[test]
    fn save_load_round_trips_probe_history() {
        let dir = std::env::temp_dir().join(format!("history_probe4_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("hist.json");
        {
            let mut mgr =
                HistoryManager::new(&path, &dir.join("bridge"), &dir.join("export"), fixed_now())
                    .unwrap();
            mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
            mgr.update_test("obfs4 1.2.3.4:443", true, Some(50));
            mgr.record_probe_at(
                "obfs4 1.2.3.4:443",
                fixed_now() - chrono::Duration::hours(2),
                false,
                None,
            );
            mgr.save().unwrap();
        }
        let mgr2 =
            HistoryManager::new(&path, &dir.join("bridge"), &dir.join("export"), fixed_now())
                .unwrap();
        let probes = mgr2.probe_history("obfs4 1.2.3.4:443");
        assert_eq!(probes.len(), 2);
        assert!(!probes[0].passed);
        assert_eq!(probes[0].latency_ms, None);
        assert!(probes[1].passed);
        assert_eq!(probes[1].latency_ms, Some(50));
    }

    #[test]
    fn from_json_without_probes_defaults_empty_log() {
        // Records persisted before the multi-probe feature have no `probes`
        // key; they must load with an empty log (backward compatible with
        // the existing on-disk bridge_history.json).
        let legacy = json!({
            "raw": "obfs4 1.2.3.4:443",
            "transport": "obfs4",
            "first_seen": "2026-06-01T12:00:00+00:00",
            "last_seen": "2026-06-28T12:00:00+00:00",
            "test_pass": true,
            "test_time": "2026-06-28T11:00:00+00:00",
            "latency_ms": 42,
            "score": 80,
        });
        let rec = BridgeRecord::from_json(&legacy).expect("legacy record parses");
        assert_eq!(rec.probes.len(), 0);
        assert_eq!(rec.test_pass, Some(true));
        assert_eq!(rec.score, 80);

        // And a record WITH probes round-trips through to_json/from_json.
        let with_probes = json!({
            "raw": "obfs4 9.9.9.9:443",
            "transport": "obfs4",
            "first_seen": "2026-06-01T12:00:00+00:00",
            "last_seen": "2026-06-28T12:00:00+00:00",
            "test_pass": null,
            "test_time": null,
            "latency_ms": null,
            "score": 0,
            "probes": [
                {"timestamp": "2026-06-28T11:00:00+00:00", "passed": true, "latency_ms": 42},
                {"timestamp": "2026-06-28T11:30:00+00:00", "passed": false, "latency_ms": null},
            ],
        });
        let rec2 = BridgeRecord::from_json(&with_probes).expect("probe record parses");
        assert_eq!(rec2.probes.len(), 2);
        assert!(!rec2.probes[1].passed);
        // Round-trip back to JSON preserves the log.
        let back = rec2.to_json();
        assert_eq!(back["probes"].as_array().unwrap().len(), 2);
        let rec3 = BridgeRecord::from_json(&back).expect("round-trip parses");
        assert_eq!(rec3.probes, rec2.probes);
    }

    #[test]
    fn get_stats_returns_correct_counts() {
        let dir = std::env::temp_dir().join(format!("history_test8_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        mgr.add_bridge("obfs4 1.2.3.4:443", "obfs4");
        mgr.add_bridge("snowflake 5.6.7.8:1", "snowflake");
        mgr.add_bridge("vanilla 9.10.11.12:9001", "vanilla");
        mgr.update_test("obfs4 1.2.3.4:443", true, None);
        mgr.update_test("snowflake 5.6.7.8:1", false, None);
        let stats = mgr.get_stats();
        assert_eq!(stats["total"], 3);
        assert_eq!(stats["tested"], 2);
        assert_eq!(stats["passing"], 1);
    }
}

//! Parity port of `core/formatter.py`.
//!
//! Multi-format bridge file exporter. Generates the following outputs
//! from the history database:
//!
//! ```text
//! bridge/
//!   <transport>.txt              All-time archive per transport (IPv4)
//!   <transport>_ipv6.txt         All-time archive per transport (IPv6)
//!   <transport>_72h.txt          Last RECENT_HOURS window (IPv4)
//!   <transport>_72h_ipv6.txt     Last RECENT_HOURS window (IPv6)
//!   <transport>_tested.txt       Connectivity-verified (IPv4)
//!   <transport>_ipv6_tested.txt  Connectivity-verified (IPv6)
//!   bridge_scores.json           Full scores database
//!   tor_bridges.zip              ZIP archive for Telegram distribution
//!
//! export/
//!   iran_pack.txt                Top-N highest-scored bridges for Iran
//!   iran_cut_pack.txt            Best bridges for NIN internet-cut scenarios
//!   bridges_api.json             Machine-readable JSON API
//! ```
//!
//! ## `score_reasons`/`recommended_priority`: always-default, not a capability loss
//!
//! `_export_json_api` reads `v.get("score_reasons", [])` and
//! `v.get("recommended_priority")` from each history record.
//! [`crate::history::BridgeRecord`] does not model either field. Traced
//! this to source rather than assuming it's fine: `core/history.py`'s
//! *only* three write paths into its persisted `self._db` — `add_bridge`
//! (sets exactly `raw`, `transport`, `first_seen`, `last_seen`,
//! `test_pass`, `test_time`, `latency_ms`, `score`), `update_test`, and
//! `update_score` — never set either field. `core/scorer.py`'s `score()`
//! method does compute and attach both to *its own local copy* of a
//! record, but that mutated copy is never round-tripped back through
//! `HistoryManager`'s narrow, typed update methods, so it never reaches
//! persisted storage. This means `v.get("score_reasons", [])` /
//! `v.get("recommended_priority")` evaluate to their defaults (`[]` /
//! `None`) for *every* record `HistoryManager.get_all()` can ever
//! actually return in the current, unmodified system — this port emits
//! those same defaults unconditionally, which is not an approximation
//! but the actual value for every real input.
//!
//! Separately, and worth flagging for completeness: `BridgeRecord`'s
//! fixed 8-field shape means `history.rs` would *also* silently discard
//! these two fields if a hand-edited `history.json` file ever did
//! contain them (unlike `config.py`'s load-time coercion, an external
//! JSON file isn't a provable-by-construction guarantee the way
//! `core/history.py`'s own write paths are). This is a pre-existing
//! structural property of `history.rs` from a prior session, not
//! something introduced here, and fixing it — giving `BridgeRecord` a
//! catch-all extra-fields bag — is out of scope for porting
//! `formatter.py` itself.
//!
//! ## Directory-listing order: fixed for determinism, like `iran_anti_siam.rs`
//!
//! `_build_zip` iterates `os.listdir(self._bd)` to decide which `.txt`
//! files go into the ZIP archive and in what order — Python's
//! `os.listdir()` order is OS/filesystem-dependent and unspecified, so
//! even Python's own output isn't guaranteed reproducible run-to-run.
//! Following the same fix already established this migration for
//! `iran_anti_siam.rs::load_bridges_txt`, [`build_zip`] sorts directory
//! entries by filename before iterating, for deterministic Rust output.
//! Parity tests compare the *set* of files placed in each ZIP folder
//! category, not byte-exact archive ordering, since Python's own
//! ordering has no single ground truth to match.
//!
//! ## `_save_line`'s unused `transport` parameter: dropped, not preserved
//!
//! Python's `_save_line(raw: str, transport: str) -> str` never
//! references `transport` in its body (confirmed by full read of the
//! function). Since this is a private module-level helper with no
//! external callers depending on its exact arity, [`save_line`] drops
//! the parameter rather than carrying a dead one forward — not a
//! capability loss, since the parameter provably had zero effect on any
//! output in the original either.

//! ## `history.rs`'s `BTreeMap` vs. Python's insertion-ordered `dict`: tie-break divergence
//!
//! `history.rs`'s `HistoryManager` stores records in a `BTreeMap<String,
//! BridgeRecord>` (a prior-session design choice, not introduced here),
//! which iterates in **key-sorted** order. `core/history.py`'s
//! `HistoryManager._db` is a plain `dict`, which — Python 3.7+ — iterates
//! in **insertion** order. `get_all()` on both sides just returns/iterates
//! that underlying structure, so this difference is directly observable
//! from this module.
//!
//! This is invisible whenever every record being compared has a distinct
//! sort key (score, or the `(transport_rank, score)` pair `top_for_iran`/
//! `iran_cut_pack` use) — the stable sort produces the same result either
//! way. It becomes observable only when **two or more records tie** on
//! every field the sort orders by: `_export_json_api`'s per-transport
//! `sort_by_key(|e| Reverse(score))` and `IranScorer::top_for_iran`/
//! `iran_cut_pack`'s stable sorts all preserve *pre-sort* order for ties,
//! and that pre-sort order is `get_all()`'s order — key-sorted here,
//! insertion-ordered in Python. A tie plus a normalized-key insertion
//! order that isn't already alphabetical (e.g. inserting a `192.0.2.1`
//! bridge before a `[2001:db8::42]`-hosted one — `'1' < '['` in ASCII, so
//! the *second*-inserted record's key sorts first) is enough to trigger a
//! different tie-break order between the two implementations.
//!
//! Fixing this would mean changing `history.rs`'s storage type (an
//! unrelated module from a prior session, with its own established
//! tests) or threading an insertion-order-preserving structure through
//! this module's own history access — both out of scope for porting
//! `formatter.py` itself. Flagged here rather than silently worked
//! around: this module's own tests avoid asserting a specific tie-break
//! order for genuinely-tied records (using either distinct scores, or an
//! explicit, separate test that documents the divergence rather than
//! hiding it — see `formatter_parity.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use zip::write::FileOptions;
use zip::ZipWriter;

use crate::config::Config;
use crate::dt_utils::coerce_utc_dt;
use crate::history::{BridgeRecord, HistoryManager};
use crate::scorer::IranScorer;
use crate::tester::extract_endpoint;

/// Mirrors `TRANSPORT_FILENAMES`. A `Vec` of pairs rather than a
/// `BTreeMap`/`HashMap` because Python's `dict` preserves insertion
/// order and this is iterated (not just looked up) in
/// `_export_standard_files`, determining the order `stats` keys are
/// populated in — though since the final `stats` output is itself a
/// `dict`/JSON-object (unordered for comparison purposes, per
/// `serde_json::Value`'s `PartialEq`), this only matters for iteration
/// determinism, not for any observable output ordering.
pub const TRANSPORT_FILENAMES: [(&str, &str); 5] = [
    ("obfs4", "obfs4"),
    ("webtunnel", "webtunnel"),
    ("vanilla", "vanilla"),
    ("snowflake", "snowflake"),
    ("meek_lite", "meek_lite"),
];

#[derive(Debug, thiserror::Error)]
pub enum FormatterError {
    #[error("I/O error on `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
}

fn io_err(path: &Path, source: std::io::Error) -> FormatterError {
    FormatterError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Mirrors `_save_line`. See the module-level doc comment for why the
/// always-unused `transport` parameter is dropped.
fn save_line(raw: &str) -> String {
    let line = raw.trim();
    line.strip_prefix("Bridge ").unwrap_or(line).to_string()
}

/// Mirrors `_is_ipv6`.
fn is_ipv6(record: &BridgeRecord) -> bool {
    let (host, _, _) = extract_endpoint(&record.raw);
    host.map(|h| h.contains(':')).unwrap_or(false)
}

/// Mirrors `_write(path, lines)`: dedup + sort, and never overwrite an
/// existing non-empty file with empty content. `BTreeSet` gives dedup
/// and sort in one step, matching Python's `sorted(set(...))`.
fn write_bridge_file(path: &Path, lines: &[String]) -> Result<(), FormatterError> {
    let clean: BTreeSet<String> = lines
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    if clean.is_empty() {
        // GUARD: never replace an existing non-empty file with empty content.
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > 0 {
                return Ok(());
            }
        }
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| io_err(path, e))?;
        }
    }
    let mut body = String::new();
    for line in &clean {
        body.push_str(line);
        body.push('\n');
    }
    std::fs::write(path, body).map_err(|e| io_err(path, e))
}

/// Holds a scored, Iran-aware view of the bridge history. Mirrors
/// `BridgeFormatter`.
pub struct BridgeFormatter {
    scorer: IranScorer,
}

impl BridgeFormatter {
    /// Mirrors `BridgeFormatter.__init__`, which constructs `IranScorer()`
    /// — whose own `__init__` auto-loads `data/transport_weights.json`.
    /// `IranScorer::new`/`with_defaults` in this port do *not* auto-load
    /// (see `scorer.rs`'s own doc comments), so this constructor calls
    /// `load_transport_scores` explicitly to reproduce the same
    /// observable behavior.
    #[must_use]
    pub fn new(now: DateTime<Utc>, transport_weights_path: &Path) -> Self {
        let mut scorer = IranScorer::new(now);
        scorer.load_transport_scores(transport_weights_path);
        Self { scorer }
    }

    /// Mirrors `_export_standard_files`. Returns the per-file bridge
    /// counts used by `update_readme` and folded into `export_all`'s
    /// stats.
    fn export_standard_files(
        &self,
        history: &HistoryManager,
        bridge_dir: &Path,
        recent_hours: i64,
        now: DateTime<Utc>,
    ) -> Result<BTreeMap<String, i64>, FormatterError> {
        let db: Vec<BridgeRecord> = history.get_all().into_iter().map(|(_, r)| r).collect();
        let cutoff = now - chrono::Duration::hours(recent_hours);
        let mut stats: BTreeMap<String, i64> = BTreeMap::new();

        for (transport, fname) in TRANSPORT_FILENAMES {
            let records: Vec<&BridgeRecord> =
                db.iter().filter(|v| v.transport == transport).collect();

            let ipv4: Vec<String> = records
                .iter()
                .filter(|r| !is_ipv6(r) && !r.raw.is_empty())
                .map(|r| save_line(&r.raw))
                .collect();
            let ipv6: Vec<String> = records
                .iter()
                .filter(|r| is_ipv6(r) && !r.raw.is_empty())
                .map(|r| save_line(&r.raw))
                .collect();

            let ipv4_72h: Vec<String> = records
                .iter()
                .filter(|r| {
                    !is_ipv6(r)
                        && !r.raw.is_empty()
                        && coerce_utc_dt(Some(&r.first_seen), "2000-01-01") > cutoff
                })
                .map(|r| save_line(&r.raw))
                .collect();
            let ipv6_72h: Vec<String> = records
                .iter()
                .filter(|r| {
                    is_ipv6(r)
                        && !r.raw.is_empty()
                        && coerce_utc_dt(Some(&r.first_seen), "2000-01-01") > cutoff
                })
                .map(|r| save_line(&r.raw))
                .collect();

            let ipv4_tested: Vec<String> = records
                .iter()
                .filter(|r| !is_ipv6(r) && !r.raw.is_empty() && r.test_pass == Some(true))
                .map(|r| save_line(&r.raw))
                .collect();
            let ipv6_tested: Vec<String> = records
                .iter()
                .filter(|r| is_ipv6(r) && !r.raw.is_empty() && r.test_pass == Some(true))
                .map(|r| save_line(&r.raw))
                .collect();

            write_bridge_file(&bridge_dir.join(format!("{fname}.txt")), &ipv4)?;
            write_bridge_file(&bridge_dir.join(format!("{fname}_ipv6.txt")), &ipv6)?;
            write_bridge_file(
                &bridge_dir.join(format!("{fname}_{recent_hours}h.txt")),
                &ipv4_72h,
            )?;
            write_bridge_file(
                &bridge_dir.join(format!("{fname}_{recent_hours}h_ipv6.txt")),
                &ipv6_72h,
            )?;
            write_bridge_file(
                &bridge_dir.join(format!("{fname}_tested.txt")),
                &ipv4_tested,
            )?;
            write_bridge_file(
                &bridge_dir.join(format!("{fname}_ipv6_tested.txt")),
                &ipv6_tested,
            )?;

            stats.insert(format!("{fname}.txt"), ipv4.len() as i64);
            stats.insert(format!("{fname}_ipv6.txt"), ipv6.len() as i64);
            stats.insert(
                format!("{fname}_{recent_hours}h.txt"),
                ipv4_72h.len() as i64,
            );
            stats.insert(
                format!("{fname}_{recent_hours}h_ipv6.txt"),
                ipv6_72h.len() as i64,
            );
            stats.insert(format!("{fname}_tested.txt"), ipv4_tested.len() as i64);
            stats.insert(format!("{fname}_ipv6_tested.txt"), ipv6_tested.len() as i64);
        }

        Ok(stats)
    }

    /// Mirrors `_export_iran_packs`. Unlike `_export_standard_files`,
    /// these two files are written directly — no dedup, no sort, no
    /// non-empty-file preservation guard — preserving the scorer's own
    /// output order exactly.
    fn export_iran_packs(
        &self,
        history: &HistoryManager,
        export_dir: &Path,
        now: DateTime<Utc>,
    ) -> Result<(), FormatterError> {
        let db: Vec<Value> = history
            .get_all()
            .into_iter()
            .map(|(_, r)| r.to_json())
            .collect();
        std::fs::create_dir_all(export_dir).map_err(|e| io_err(export_dir, e))?;

        // Dynamic yield: compute ceiling from config instead of hardcoded 100.
        // This scales with the actual database size, bounded only by the
        // circuit-breaker ceiling from config.
        let ceiling = crate::config::Config::from_env()
            .map(|cfg| crate::config::compute_dynamic_ceiling(db.len(), &cfg))
            .unwrap_or(100);
        let top = self.scorer.top_for_iran(&db, ceiling, 0);
        let lines: Vec<String> = top
            .iter()
            .filter_map(|r| {
                let raw = r.get("raw").and_then(Value::as_str).unwrap_or("");
                if raw.is_empty() {
                    None
                } else {
                    Some(save_line(raw))
                }
            })
            .collect();
        let iran_pack_path = export_dir.join("iran_pack.txt");
        {
            let mut body = String::new();
            body.push_str("# Tor Bridge Iran Pack — sorted by Iran effectiveness score\n");
            body.push_str(&format!(
                "# Generated: {}\n",
                now.format("%Y-%m-%d %H:%M UTC")
            ));
            body.push_str(
                "# Usage: paste lines below into Tor Browser → Settings → Connection → Bridges\n\n",
            );
            for line in &lines {
                if !line.is_empty() {
                    body.push_str(line);
                    body.push('\n');
                }
            }
            std::fs::write(&iran_pack_path, body).map_err(|e| io_err(&iran_pack_path, e))?;
        }

        let cut_pack = self.scorer.iran_cut_pack(&db);
        let cut_lines: Vec<String> = cut_pack
            .iter()
            .filter_map(|r| {
                let raw = r.get("raw").and_then(Value::as_str).unwrap_or("");
                if raw.is_empty() {
                    None
                } else {
                    Some(save_line(raw))
                }
            })
            .collect();
        let iran_cut_pack_path = export_dir.join("iran_cut_pack.txt");
        {
            let mut body = String::new();
            body.push_str("# Bridges for Iranian Internet Cut (شبکه ملی)\n");
            body.push_str(
                "# These bridges are most likely to work when international internet is blocked.\n",
            );
            body.push_str("# Priority: Snowflake > WebTunnel (CDN) > obfs4 port 443\n\n");
            for line in &cut_lines {
                if !line.is_empty() {
                    body.push_str(line);
                    body.push('\n');
                }
            }
            std::fs::write(&iran_cut_pack_path, body)
                .map_err(|e| io_err(&iran_cut_pack_path, e))?;
        }

        Ok(())
    }

    /// Mirrors `_export_json_api`. See the module-level doc comment for
    /// why `score_reasons`/`recommended_priority` are always their
    /// Python defaults.
    fn export_json_api(
        &self,
        history: &HistoryManager,
        export_dir: &Path,
        now: DateTime<Utc>,
    ) -> Result<(), FormatterError> {
        let db = history.get_all();
        let mut by_transport: BTreeMap<String, Vec<Value>> = BTreeMap::new();

        for (_, v) in &db {
            let t = if v.transport.is_empty() {
                "unknown".to_string()
            } else {
                v.transport.clone()
            };
            let entry = json!({
                "line": save_line(&v.raw),
                "score": v.score,
                "tested": v.test_pass,
                "first_seen": v.first_seen,
                "last_seen": v.last_seen,
                "latency_ms": v.latency_ms,
                "score_reasons": Value::Array(vec![]),
                "recommended_priority": Value::Null,
            });
            by_transport.entry(t).or_default().push(entry);
        }

        for entries in by_transport.values_mut() {
            // Python: `.sort(key=lambda x: x["score"], reverse=True)` — stable.
            entries.sort_by_key(|e| {
                std::cmp::Reverse(e.get("score").and_then(Value::as_i64).unwrap_or(0))
            });
        }

        let bridges_value: Map<String, Value> = by_transport
            .into_iter()
            .map(|(k, v)| (k, Value::Array(v)))
            .collect();
        let api = json!({
            "schema": "1.0",
            "updated": now.to_rfc3339(),
            "bridges": Value::Object(bridges_value),
        });

        let path = export_dir.join("bridges_api.json");
        let text = serde_json::to_string_pretty(&api).expect("api serializes");
        std::fs::write(&path, text).map_err(|e| io_err(&path, e))
    }

    /// Mirrors `_save_scores_db`.
    fn save_scores_db(
        &self,
        history: &HistoryManager,
        bridge_dir: &Path,
    ) -> Result<(), FormatterError> {
        let db = history.get_all();
        let scores: Map<String, Value> = db
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    json!({"score": v.score, "transport": v.transport}),
                )
            })
            .collect();
        let path = bridge_dir.join("bridge_scores.json");
        let text = serde_json::to_string_pretty(&Value::Object(scores)).expect("scores serialize");
        std::fs::write(&path, text).map_err(|e| io_err(&path, e))
    }

    /// Mirrors `_build_zip`. See the module-level doc comment for the
    /// directory-listing-order determinism fix.
    fn build_zip(
        &self,
        bridge_dir: &Path,
        export_dir: &Path,
        recent_hours: i64,
    ) -> Result<PathBuf, FormatterError> {
        let entries = std::fs::read_dir(bridge_dir).map_err(|e| io_err(bridge_dir, e))?;
        let mut names: Vec<std::ffi::OsString> = entries
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        names.sort();

        for name in &names {
            if name.to_string_lossy().ends_with(".zip") {
                let _ = std::fs::remove_file(bridge_dir.join(name));
            }
        }

        let zip_path = bridge_dir.join("tor_bridges.zip");
        let file = std::fs::File::create(&zip_path).map_err(|e| io_err(&zip_path, e))?;
        let mut zf = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let root = "Tor Bridges";

        // Re-list post-deletion, still sorted, matching Python's second
        // independent `os.listdir()` call in the same function.
        let entries2 = std::fs::read_dir(bridge_dir).map_err(|e| io_err(bridge_dir, e))?;
        let mut names2: Vec<std::ffi::OsString> = entries2
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        names2.sort();

        let hours_marker = format!("_{recent_hours}h");
        for name in &names2 {
            let fname = name.to_string_lossy().to_string();
            if !fname.ends_with(".txt") {
                continue;
            }
            let fpath = bridge_dir.join(&fname);
            let folder = if fname.contains("_tested") {
                format!("{root}/Tested (Verified)")
            } else if fname.contains(&hours_marker) {
                format!("{root}/Fresh (Last {recent_hours}h)")
            } else {
                format!("{root}/Full Archive")
            };
            let bytes = std::fs::read(&fpath).map_err(|e| io_err(&fpath, e))?;
            zf.start_file(format!("{folder}/{fname}"), options)?;
            zf.write_all(&bytes).map_err(|e| io_err(&fpath, e))?;
        }

        for ef in ["iran_pack.txt", "iran_cut_pack.txt"] {
            let ep = export_dir.join(ef);
            if ep.exists() {
                let bytes = std::fs::read(&ep).map_err(|e| io_err(&ep, e))?;
                zf.start_file(format!("{root}/Iran Optimized/{ef}"), options)?;
                zf.write_all(&bytes).map_err(|e| io_err(&ep, e))?;
            }
        }

        zf.finish()?;
        Ok(zip_path)
    }

    /// Mirrors `export_all`. Returns a JSON object: the per-file `i64`
    /// stats from `_export_standard_files`, plus a `"__zip_path__"`
    /// string entry — matching Python's single `dict[str, Any]` mixing
    /// int and string values.
    pub fn export_all(
        &self,
        history: &HistoryManager,
        cfg: &Config,
        now: DateTime<Utc>,
    ) -> Result<Value, FormatterError> {
        let bridge_dir = Path::new(&cfg.bridge_dir);
        let export_dir = Path::new(&cfg.export_dir);

        let stats = self.export_standard_files(history, bridge_dir, cfg.recent_hours, now)?;
        self.export_iran_packs(history, export_dir, now)?;
        self.export_json_api(history, export_dir, now)?;
        self.save_scores_db(history, bridge_dir)?;
        let zip_path = self.build_zip(bridge_dir, export_dir, cfg.recent_hours)?;

        let mut out: Map<String, Value> = stats.into_iter().map(|(k, v)| (k, json!(v))).collect();
        out.insert(
            "__zip_path__".to_string(),
            json!(zip_path.display().to_string()),
        );
        Ok(Value::Object(out))
    }

    /// Mirrors `update_readme`, with the README path and `now` as
    /// explicit parameters for testability. See [`update_readme`] for
    /// the production entry point using the same hard-coded `"README.md"`
    /// path the Python original uses.
    pub fn update_readme_with_path(
        &self,
        stats: &Value,
        readme_path: &Path,
        cfg: &Config,
        now: DateTime<Utc>,
    ) -> Result<(), FormatterError> {
        let ts = now.format("%Y-%m-%d %H:%M UTC").to_string();
        let rh = cfg.recent_hours;
        let repo = &cfg.repo_url;

        let link = |f: &str| format!("[{f}]({repo}/bridge/{f})");
        let cnt = |key: &str| -> String {
            let v = stats.get(key).and_then(Value::as_i64).unwrap_or(0);
            format!("**{v}**")
        };

        let content = format!(
            r#"# 🌐 Tor Bridges Ultra Collector

> Auto-collected, tested, and Iran-scored Tor bridges.<br>
> GitHub Actions runs every hour — fresh bridges always available.<br>
> **Last update:** `{ts}`

## ⚠️ Notes for Iran Users

- **Internet cut (شبکه ملی):** Use `export/iran_cut_pack.txt` — contains Snowflake and WebTunnel bridges that survive NIN.
- **Normal censorship:** Use `export/iran_pack.txt` — top-ranked obfs4/WebTunnel bridges for Iran's DPI.
- **Port 443 bridges** are prioritised — Iran almost never blocks HTTPS.
- **IPv4 is more stable** than IPv6 inside Iran.

## ✅ Tested & Active (Recommended)

| Transport | IPv4 Tested | Count |
| :--- | :--- | :--- |
| **obfs4** | {obfs4_tested_link} | {obfs4_tested_cnt} |
| **WebTunnel** | {webtunnel_tested_link} | {webtunnel_tested_cnt} |
| **Snowflake** | {snowflake_tested_link} | {snowflake_tested_cnt} |
| **Vanilla** | {vanilla_tested_link} | {vanilla_tested_cnt} |
| **meek-lite** | {meek_lite_tested_link} | {meek_lite_tested_cnt} |

## 🕐 Fresh Bridges (Last {rh}h)

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | {obfs4_rh_link} | {obfs4_rh_cnt} | {obfs4_rh_ipv6_link} | {obfs4_rh_ipv6_cnt} |
| **WebTunnel** | {webtunnel_rh_link} | {webtunnel_rh_cnt} | {webtunnel_rh_ipv6_link} | {webtunnel_rh_ipv6_cnt} |
| **Vanilla** | {vanilla_rh_link} | {vanilla_rh_cnt} | {vanilla_rh_ipv6_link} | {vanilla_rh_ipv6_cnt} |

## 📦 Full Archive

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | {obfs4_link} | {obfs4_cnt} | {obfs4_ipv6_link} | {obfs4_ipv6_cnt} |
| **WebTunnel** | {webtunnel_link} | {webtunnel_cnt} | {webtunnel_ipv6_link} | {webtunnel_ipv6_cnt} |
| **Snowflake** | {snowflake_link} | {snowflake_cnt} | — | — |
| **Vanilla** | {vanilla_link} | {vanilla_cnt} | {vanilla_ipv6_link} | {vanilla_ipv6_cnt} |
| **meek-lite** | {meek_lite_link} | {meek_lite_cnt} | — | — |

## 🇮🇷 Iran Optimised Packs

| Pack | Description |
| :--- | :--- |
| [iran_pack.txt]({repo}/export/iran_pack.txt) | Top 100 bridges ranked by Iran effectiveness score |
| [iran_cut_pack.txt]({repo}/export/iran_cut_pack.txt) | Bridges for internet cut / شبکه ملی scenarios |
| [bridges_api.json]({repo}/export/bridges_api.json) | Machine-readable JSON API |

## 📡 Transport Guide for Iran

| Transport | Anti-DPI | Works during cut | Speed | Recommended |
| :--- | :--- | :--- | :--- | :--- |
| Snowflake | ⭐⭐⭐⭐⭐ | ✅ | Medium | **Yes** |
| WebTunnel | ⭐⭐⭐⭐⭐ | ✅ (CDN) | Fast | **Yes** |
| obfs4 | ⭐⭐⭐⭐ | ❌ | Fast | **Yes** |
| meek-lite | ⭐⭐⭐⭐ | ✅ (Azure) | Slow | Fallback |
| Vanilla | ⭐ | ❌ | Fast | No |

## Disclaimer

For educational and archival purposes. Use bridges responsibly.
"#,
            ts = ts,
            repo = repo,
            rh = rh,
            obfs4_tested_link = link("obfs4_tested.txt"),
            obfs4_tested_cnt = cnt("obfs4_tested.txt"),
            webtunnel_tested_link = link("webtunnel_tested.txt"),
            webtunnel_tested_cnt = cnt("webtunnel_tested.txt"),
            snowflake_tested_link = link("snowflake_tested.txt"),
            snowflake_tested_cnt = cnt("snowflake_tested.txt"),
            vanilla_tested_link = link("vanilla_tested.txt"),
            vanilla_tested_cnt = cnt("vanilla_tested.txt"),
            meek_lite_tested_link = link("meek_lite_tested.txt"),
            meek_lite_tested_cnt = cnt("meek_lite_tested.txt"),
            obfs4_rh_link = link(&format!("obfs4_{rh}h.txt")),
            obfs4_rh_cnt = cnt(&format!("obfs4_{rh}h.txt")),
            obfs4_rh_ipv6_link = link(&format!("obfs4_{rh}h_ipv6.txt")),
            obfs4_rh_ipv6_cnt = cnt(&format!("obfs4_{rh}h_ipv6.txt")),
            webtunnel_rh_link = link(&format!("webtunnel_{rh}h.txt")),
            webtunnel_rh_cnt = cnt(&format!("webtunnel_{rh}h.txt")),
            webtunnel_rh_ipv6_link = link(&format!("webtunnel_{rh}h_ipv6.txt")),
            webtunnel_rh_ipv6_cnt = cnt(&format!("webtunnel_{rh}h_ipv6.txt")),
            vanilla_rh_link = link(&format!("vanilla_{rh}h.txt")),
            vanilla_rh_cnt = cnt(&format!("vanilla_{rh}h.txt")),
            vanilla_rh_ipv6_link = link(&format!("vanilla_{rh}h_ipv6.txt")),
            vanilla_rh_ipv6_cnt = cnt(&format!("vanilla_{rh}h_ipv6.txt")),
            obfs4_link = link("obfs4.txt"),
            obfs4_cnt = cnt("obfs4.txt"),
            obfs4_ipv6_link = link("obfs4_ipv6.txt"),
            obfs4_ipv6_cnt = cnt("obfs4_ipv6.txt"),
            webtunnel_link = link("webtunnel.txt"),
            webtunnel_cnt = cnt("webtunnel.txt"),
            webtunnel_ipv6_link = link("webtunnel_ipv6.txt"),
            webtunnel_ipv6_cnt = cnt("webtunnel_ipv6.txt"),
            snowflake_link = link("snowflake.txt"),
            snowflake_cnt = cnt("snowflake.txt"),
            vanilla_link = link("vanilla.txt"),
            vanilla_cnt = cnt("vanilla.txt"),
            vanilla_ipv6_link = link("vanilla_ipv6.txt"),
            vanilla_ipv6_cnt = cnt("vanilla_ipv6.txt"),
            meek_lite_link = link("meek_lite.txt"),
            meek_lite_cnt = cnt("meek_lite.txt"),
        );

        std::fs::write(readme_path, content).map_err(|e| io_err(readme_path, e))
    }

    /// Mirrors the zero-argument `update_readme(stats)` entry point,
    /// using the same hard-coded `"README.md"` path the Python original
    /// uses.
    pub fn update_readme(
        &self,
        stats: &Value,
        cfg: &Config,
        now: DateTime<Utc>,
    ) -> Result<(), FormatterError> {
        self.update_readme_with_path(stats, Path::new("README.md"), cfg, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap()
    }

    fn test_formatter(now: DateTime<Utc>) -> BridgeFormatter {
        BridgeFormatter::new(now, Path::new("/nonexistent/transport_weights.json"))
    }

    #[test]
    fn save_line_strips_bridge_prefix_and_whitespace() {
        assert_eq!(
            save_line("  Bridge obfs4 1.2.3.4:443 ABC  "),
            "obfs4 1.2.3.4:443 ABC"
        );
        assert_eq!(save_line("obfs4 1.2.3.4:443 ABC"), "obfs4 1.2.3.4:443 ABC");
        assert_eq!(save_line(""), "");
    }

    #[test]
    fn write_bridge_file_dedups_and_sorts() {
        let tmp = std::env::temp_dir().join(format!("fmt_write_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("out.txt");

        write_bridge_file(
            &path,
            &[
                "b".to_string(),
                "a".to_string(),
                "b".to_string(),
                "  ".to_string(),
            ],
        )
        .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "a\nb\n");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn write_bridge_file_preserves_nonempty_file_on_empty_export() {
        let tmp = std::env::temp_dir().join(format!("fmt_preserve_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("out.txt");
        std::fs::write(&path, "existing\n").unwrap();

        write_bridge_file(&path, &[]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            content, "existing\n",
            "non-empty file must survive an empty export"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn write_bridge_file_creates_empty_file_when_none_exists() {
        let tmp = std::env::temp_dir().join(format!("fmt_createempty_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("out.txt");

        write_bridge_file(&path, &[]).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn export_json_api_always_defaults_score_reasons_and_priority() {
        let tmp = std::env::temp_dir().join(format!("fmt_jsonapi_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let export_dir = tmp.join("export");
        let bridge_dir = tmp.join("bridge");
        std::fs::create_dir_all(&export_dir).unwrap();
        std::fs::create_dir_all(&bridge_dir).unwrap();

        let mut history = HistoryManager::new(
            &tmp.join("history.json"),
            &bridge_dir,
            &export_dir,
            fixed_now(),
        )
        .unwrap();
        history.add_bridge("obfs4 1.2.3.4:443 ABC", "obfs4");

        let formatter = test_formatter(fixed_now());
        formatter
            .export_json_api(&history, &export_dir, fixed_now())
            .unwrap();

        let api: Value = serde_json::from_str(
            &std::fs::read_to_string(export_dir.join("bridges_api.json")).unwrap(),
        )
        .unwrap();
        let entry = &api["bridges"]["obfs4"][0];
        assert_eq!(entry["score_reasons"], json!([]));
        assert_eq!(entry["recommended_priority"], Value::Null);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn export_all_writes_zip_with_all_categories() {
        let tmp = std::env::temp_dir().join(format!("fmt_full_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let bridge_dir = tmp.join("bridge");
        let export_dir = tmp.join("export");
        std::fs::create_dir_all(&bridge_dir).unwrap();
        std::fs::create_dir_all(&export_dir).unwrap();

        let mut history = HistoryManager::new(
            &tmp.join("history.json"),
            &bridge_dir,
            &export_dir,
            fixed_now(),
        )
        .unwrap();
        history.add_bridge("obfs4 1.2.3.4:443 ABC", "obfs4");
        history.update_score("obfs4 1.2.3.4:443 ABC", 80);
        history.update_test("obfs4 1.2.3.4:443 ABC", true, Some(50));

        let mut cfg = crate::config::from_env_map(&crate::config::EnvMap::new()).unwrap();
        cfg.bridge_dir = bridge_dir.display().to_string();
        cfg.export_dir = export_dir.display().to_string();

        let formatter = test_formatter(fixed_now());
        let stats = formatter.export_all(&history, &cfg, fixed_now()).unwrap();

        assert_eq!(stats["obfs4_tested.txt"], json!(1));
        assert!(bridge_dir.join("tor_bridges.zip").exists());
        assert!(bridge_dir.join("bridge_scores.json").exists());
        assert!(export_dir.join("iran_pack.txt").exists());
        assert!(export_dir.join("iran_cut_pack.txt").exists());
        assert!(export_dir.join("bridges_api.json").exists());

        let zip_file = std::fs::File::open(bridge_dir.join("tor_bridges.zip")).unwrap();
        let mut archive = zip::ZipArchive::new(zip_file).unwrap();
        let mut names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        names.sort();
        assert!(names.iter().any(|n| n.contains("Tested (Verified)")));
        assert!(names.iter().any(|n| n.contains("Full Archive")));
        assert!(names.iter().any(|n| n.contains("Iran Optimized")));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn update_readme_renders_counts_and_links() {
        let tmp = std::env::temp_dir().join(format!("fmt_readme_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let readme_path = tmp.join("README.md");

        let cfg = crate::config::from_env_map(&crate::config::EnvMap::new()).unwrap();
        let formatter = test_formatter(fixed_now());
        let stats = json!({"obfs4_tested.txt": 5});

        formatter
            .update_readme_with_path(&stats, &readme_path, &cfg, fixed_now())
            .unwrap();
        let content = std::fs::read_to_string(&readme_path).unwrap();
        assert!(content.contains("**5**"));
        assert!(content.contains("Tor Bridges Ultra Collector"));
        assert!(content.contains(&cfg.repo_url));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

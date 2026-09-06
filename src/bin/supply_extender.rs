//! Extended low-supply bridge-source draws + per-run supply diagnostics.
//!
//! Additive enrichment stage: requests additional, bounded, legitimately
//! available BridgeDB HTML draws (including the snowflake pages the core
//! target list omits) and additional single-transport MOAT draws, then merges
//! everything into `bridge_history.json` through the exact same validation and
//! deduplication pipeline the core scrapers use.
//!
//! The run also writes two NEW diagnostics files under `data/`:
//!
//! * `data/supply_diagnostics.json` — per-source/per-transport pull counts
//!   and the history-count delta caused by this stage;
//! * `data/supply_diagnostics_history.json` — append-only per-run history
//!   (capped) so supply growth can be tracked over time.
//!
//! No existing scraper, filter, prober, output file, or workflow step is
//! modified by this binary.  When the `network` feature is disabled the
//! binary still runs: it writes diagnostics (all counters zero) and exits
//! cleanly, mirroring the core `scraper` binary's offline behaviour.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};

use torshield_ir_ultra::scraper::{
    load_history, merge_raw_into_history, prune_history, save_history, DEFAULT_BRIDGE_DIR,
};
use torshield_ir_ultra::supply_extension::{
    count_added_lines, diagnostics_payload, fetch_html_supply, fetch_moat_supply,
    history_family_counts, SourceLines, SupplyConfig, NOTICE_FOCUS_FAMILIES,
};

/// New diagnostics snapshot written by every run (never overwrites an
/// existing pipeline output — this filename is new).
const DIAGNOSTICS_FILE: &str = "data/supply_diagnostics.json";

/// Append-only per-run history of the diagnostics snapshot (new file too).
const DIAGNOSTICS_HISTORY_FILE: &str = "data/supply_diagnostics_history.json";

/// Maximum number of per-run records kept in the append-only history file.
const DIAGNOSTICS_HISTORY_CAP: usize = 500;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = SupplyConfig::from_env();

    let bridge_dir = Path::new(DEFAULT_BRIDGE_DIR);
    let history_path = bridge_dir.join("bridge_history.json");
    let mut history = load_history(&history_path)?;
    let before = history_family_counts(&history);

    // The extended draws are network-backed and therefore live behind the
    // same `network` feature gate the core scraper uses for its fetchers.
    // Without the feature the stage degrades to a pure diagnostics pass.
    #[cfg(feature = "network")]
    let fetched: Vec<SourceLines> = {
        let client = torshield_ir_ultra::scraper::ReqwestHttpFetch::new(Duration::from_secs(30));
        let mut fetched = Vec::new();
        fetched.extend(fetch_html_supply(&client, config.html_draws));
        fetched.extend(fetch_moat_supply(&client, config.moat_rounds));
        fetched
    };

    #[cfg(not(feature = "network"))]
    let fetched: Vec<SourceLines> = Vec::new();

    let mut lines: Vec<(String, String, String)> = Vec::new();
    for group in &fetched {
        lines.extend(group.lines.iter().cloned());
    }
    let added = count_added_lines(&history, &lines);
    let total_added: usize = added.values().sum();

    // Merge through the canonical history writer: same key normalisation and
    // deduplication as every other source; `last_seen` refreshes keep known
    // healthy candidates hot instead of duplicating them.
    if !lines.is_empty() {
        merge_raw_into_history(&mut history, &lines)?;
    }
    let pruned = prune_history(&mut history)?;
    save_history(&history, &history_path)?;
    let after = history_family_counts(&history);

    let payload = diagnostics_payload(
        &config,
        &fetched,
        &before,
        &after,
        &added,
        Utc::now().to_rfc3339(),
    );
    write_outputs(&payload, &config, &after, total_added);

    println!(
        "supply_extender: config html_draws={} moat_rounds={} sources={} fetched_lines={} \
         new_history_records={} pruned={}",
        config.html_draws,
        config.moat_rounds,
        fetched.len(),
        lines.len(),
        total_added,
        pruned,
    );
    Ok(())
}

/// Best-effort writers for the two NEW diagnostics files.  Failures are
/// logged, never fatal — the supply stage must stay non-blocking for the
/// pipeline exactly like the other enrichment sources.
fn write_outputs(
    payload: &Value,
    config: &SupplyConfig,
    after: &BTreeMap<String, usize>,
    total_added: usize,
) {
    if let Err(err) = fs::create_dir_all("data") {
        tracing::warn!(
            "supply diagnostics: could not create data directory: {}",
            err
        );
        return;
    }

    match serde_json::to_vec_pretty(payload) {
        Ok(buf) => {
            if let Err(err) = fs::write(DIAGNOSTICS_FILE, buf) {
                tracing::warn!(
                    "supply diagnostics: could not write {}: {}",
                    DIAGNOSTICS_FILE,
                    err
                );
            }
        }
        Err(err) => tracing::warn!("supply diagnostics: could not serialize snapshot: {}", err),
    }

    append_history_record(payload, after, total_added);
    emit_step_summary(payload, config, total_added);
    emit_workflow_notices(after);
}

/// Append one per-run record to the history file, keeping at most
/// [`DIAGNOSTICS_HISTORY_CAP`] records.
fn append_history_record(payload: &Value, after: &BTreeMap<String, usize>, total_added: usize) {
    let mut records: Vec<Value> = match fs::read_to_string(DIAGNOSTICS_HISTORY_FILE) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| Vec::new()),
        Err(_) => Vec::new(),
    };
    let record = json!({
        "generated_at": payload.get("generated_at"),
        "config": payload.get("config"),
        "added_by_extended_sources": total_added,
        "history_family_counts_after": after,
    });
    records.push(record);
    if records.len() > DIAGNOSTICS_HISTORY_CAP {
        let overflow = records.len() - DIAGNOSTICS_HISTORY_CAP;
        records.drain(..overflow);
    }
    match serde_json::to_vec_pretty(&json!({ "runs": records })) {
        Ok(buf) => {
            if let Err(err) = fs::write(DIAGNOSTICS_HISTORY_FILE, buf) {
                tracing::warn!(
                    "supply diagnostics: could not write {DIAGNOSTICS_HISTORY_FILE}: {err}"
                );
            }
        }
        Err(err) => tracing::warn!("supply diagnostics: could not serialize history: {err}"),
    }
}

/// Append a compact markdown summary to `$GITHUB_STEP_SUMMARY` when running
/// inside GitHub Actions (best effort; ignored elsewhere).  The summary is
/// rendered on the job page, which keeps the AFTER counts visible even when
/// log archives are unavailable.
fn emit_step_summary(payload: &Value, config: &SupplyConfig, total_added: usize) {
    let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let counts = payload
        .get("history_family_counts")
        .and_then(Value::as_object);
    let Some(counts) = counts else {
        return;
    };
    let mut rows =
        String::from("| transport family | before | after | added |\n|---|---|---|---|\n");
    let before = counts.get("before").and_then(Value::as_object);
    let after = counts.get("after").and_then(Value::as_object);
    let added = counts
        .get("added_by_extended_sources")
        .and_then(Value::as_object);
    let mut families: Vec<&String> = Vec::new();
    for map in [before, after, added].into_iter().flatten() {
        for key in map.keys() {
            if !families.contains(&key) {
                families.push(key);
            }
        }
    }
    families.sort();
    for family in families {
        let get = |map: Option<&serde_json::Map<String, Value>>| -> u64 {
            map.and_then(|m| m.get(family))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        };
        rows.push_str(&format!(
            "| {family} | {} | {} | {} |\n",
            get(before),
            get(after),
            get(added),
        ));
    }
    let summary = format!(
        "### Supply diagnostics (extended low-supply sources)\n\n\
         config: html extra draws = {draws}, moat single-transport rounds = {rounds}; \
         new history records added this run = {added}\n\n{rows}",
        draws = config.html_draws,
        rounds = config.moat_rounds,
        added = total_added,
    );
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&summary_path)
    {
        use std::io::Write;
        let _ = file.write_all(summary.as_bytes());
    }
}

/// Emit one `::notice` workflow annotation per focus transport family so the
/// AFTER history counts are readable on the run page without log access.
fn emit_workflow_notices(after: &BTreeMap<String, usize>) {
    for family in NOTICE_FOCUS_FAMILIES {
        let count = after.get(*family).copied().unwrap_or(0);
        println!("::notice title=SUPPLY_DIAG::{family}::history_count_after={count}");
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("supply_extender: {error}");
        std::process::exit(1);
    }
}

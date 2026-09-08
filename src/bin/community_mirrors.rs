//! Community mirror expansion entry point (additive, advisory by default).
//!
//! Fetches curated `bridge/<transport>.txt` projections from additional
//! public community mirrors (GitHub contents API), validates every line
//! through the exact same format + non-routable-endpoint gates the core
//! pipeline applies, and reports per-mirror yield to
//! `data/community_mirrors_report.json` plus GitHub Actions notices.
//!
//! Merging into `bridge_history.json` happens ONLY when
//! `COMMUNITY_MIRRORS_MERGE=true`; the default is advisory-only so the
//! source's real yield is proven across runs before it can influence the
//! candidate pool. Disable the module entirely with `COMMUNITY_MIRRORS=none`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use torshield_ir_ultra::scraper::{
    load_history, merge_raw_into_history, prune_history, save_history,
};
use torshield_ir_ultra::sources_community_mirrors::{
    build_report, count_new_lines, fetch_mirror, merge_enabled_from_env, mirrors_from_env,
    MirrorOutcome, REPORT_FILE,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mirrors = mirrors_from_env();
    let merge_enabled = merge_enabled_from_env();

    if mirrors.is_empty() {
        println!("community_mirrors: disabled (COMMUNITY_MIRRORS=none or empty list)");
        let report = build_report(&[], merge_enabled, &BTreeMap::new());
        write_report(&report)?;
        return Ok(());
    }

    // The fetches are network-backed and therefore live behind the same
    // `network` feature gate the core scraper uses. Without the feature the
    // stage degrades to an empty advisory report.
    #[cfg(feature = "network")]
    let outcomes: Vec<MirrorOutcome> = {
        let client = torshield_ir_ultra::scraper::ReqwestHttpFetch::new(Duration::from_secs(30));
        mirrors
            .iter()
            .map(|repo| fetch_mirror(&client, repo))
            .collect()
    };
    #[cfg(not(feature = "network"))]
    let outcomes: Vec<MirrorOutcome> = Vec::new();

    let mut added: BTreeMap<String, usize> = BTreeMap::new();
    if merge_enabled && !outcomes.is_empty() {
        let bridge_dir = Path::new("bridge");
        let history_path = bridge_dir.join("bridge_history.json");
        let mut history = load_history(&history_path)?;
        let mut lines: Vec<(String, String, String)> = Vec::new();
        for outcome in &outcomes {
            lines.extend(outcome.lines.iter().cloned());
        }
        added = count_new_lines(&history, &lines);
        merge_raw_into_history(&mut history, &lines)?;
        let pruned = prune_history(&mut history)?;
        save_history(&history, &history_path)?;
        println!(
            "community_mirrors: merged validated lines into history (pruned {pruned} stale records)"
        );
    }

    let report = build_report(&outcomes, merge_enabled, &added);
    for outcome in &outcomes {
        let valid: usize = outcome.files.iter().map(|file| file.valid_lines).sum();
        let fetched: usize = outcome.files.iter().map(|file| file.fetched_lines).sum();
        println!(
            "::notice title=COMMUNITY_MIRRORS::{} fetched={} valid={} (merge={})",
            outcome.repo, fetched, valid, merge_enabled
        );
    }
    write_report(&report)?;
    Ok(())
}

fn write_report(report: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let output = Path::new(REPORT_FILE);
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut body = serde_json::to_vec_pretty(report)?;
    body.push(b'\n');
    std::fs::write(output, body)?;
    println!("community_mirrors: report written to {}", output.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("community_mirrors: {error}");
        std::process::exit(1);
    }
}

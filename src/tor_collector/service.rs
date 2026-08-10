//! End-to-end collector orchestration and atomic/dry-run publication.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{Timelike, Utc};
use serde_json::{json, Value};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::config::{fronted_defaults, CollectorConfig, ListSpec, Transport};
use super::fetch::{deduplicate, SourceFetcher};
use super::parsing::{clean_output_line, is_valid_bridge_line};
use super::readme::{
    build_zip, existing_zip_entries, render_readme, telegram_caption, upload_telegram, ListStats,
    StatsMap,
};
use super::storage::HistoryStore;
use super::tester::{Obfs4Verification, ProbeEngine, ProbeResult};

/// Summary returned by a collector run for CLI and integration diagnostics.
#[derive(Clone, Debug, Default)]
pub struct RunSummary {
    /// Number of staged paths whose on-disk bytes would change/did change.
    pub changed_files: usize,
    /// Whether the execution was dry-run only.
    pub dry_run: bool,
    /// Pooled and fronted list counts used by README/Telegram rendering.
    pub stats: StatsMap,
    /// Number of active history entries after retention cleanup.
    pub history_entries: usize,
}

/// Results of one transport/IP list after its probes complete.  Acquisition
/// and list probing are kept separate so every list can be tested concurrently
/// without allowing parallel tasks to mutate the shared history/publication
/// state.
struct ListOutcome {
    transport: Transport,
    ipv6: bool,
    archive: Vec<String>,
    source_lines: Vec<String>,
    results: Vec<ProbeResult>,
    tested: Vec<String>,
}

/// Unified OnionHop/vip collection service.
#[derive(Clone)]
pub struct CollectorService {
    config: CollectorConfig,
    fetcher: SourceFetcher,
    tester: ProbeEngine,
}

impl CollectorService {
    /// Construct a fully async collector. Building the HTTP client is the only
    /// fallible setup step and does not perform network I/O.
    pub fn new(config: CollectorConfig) -> Result<Self> {
        let fetcher = SourceFetcher::new(config.clone())?;
        let tester = ProbeEngine::new(config.clone());
        Ok(Self {
            config,
            fetcher,
            tester,
        })
    }

    /// Run collection, testing, reporting, ZIP creation, and optional Telegram
    /// upload. Individual upstream/probe failures are logged and skipped;
    /// filesystem publication errors are returned to the caller.
    ///
    /// A configurable `STAGE_DEADLINE_SECS` wraps the entire operation so a
    /// stuck source can never consume the full CI job budget.  When the deadline
    /// fires, the collector writes whatever partial data is available rather
    /// than failing hard.
    pub async fn run(&self) -> Result<RunSummary> {
        let deadline = Duration::from_secs(self.config.stage_deadline_secs);
        match timeout(deadline, self.run_inner()).await {
            Ok(Ok(summary)) => Ok(summary),
            Ok(Err(error)) => Err(error),
            Err(_elapsed) => {
                log(&format!(
                    "STAGE_DEADLINE of {}s reached; writing partial data before exiting",
                    self.config.stage_deadline_secs
                ));
                // Write whatever we managed to collect
                let staged = self.flush_partial().await?;
                let changed = publish_staged(&staged, self.config.dry_run)?;
                log(&format!(
                    "Graceful deadline exit: {changed} file(s) written from partial collection"
                ));
                Ok(RunSummary {
                    changed_files: changed,
                    dry_run: self.config.dry_run,
                    stats: StatsMap::new(),
                    history_entries: 0,
                })
            }
        }
    }

    /// Inner run implementation without deadline wrapping.
    async fn run_inner(&self) -> Result<RunSummary> {
        let now = Utc::now();
        log("Starting unified Tor bridge collection run...");
        let (mut history, history_writable) = match HistoryStore::load(&self.config.history_path) {
            Ok(history) => (history, true),
            Err(error) => {
                log(&format!(
                    "WARNING: history could not be safely loaded ({error}); retaining existing history file unchanged"
                ));
                (HistoryStore::default(), false)
            }
        };
        let mut staged = BTreeMap::new();
        let mut stats = StatsMap::new();

        // Acquire every transport/IP source concurrently. The previous nested
        // loops fetched six pooled lists and six fronted lists serially; with
        // three retries and a blackholed mirror that could consume most of the
        // job budget before probing even began.
        let mut acquisition_tasks = JoinSet::new();
        for transport in Transport::POOLED.into_iter().chain(Transport::FRONTED) {
            for ipv6 in [false, true] {
                let fetcher = self.fetcher.clone();
                acquisition_tasks.spawn(async move {
                    let (bridgedb, community) = tokio::join!(
                        fetcher.fetch_bridgedb(transport, ipv6),
                        fetcher.fetch_community_sources(transport, ipv6),
                    );
                    (transport, ipv6, bridgedb, community)
                });
            }
        }

        let mut acquired = Vec::new();
        while let Some(joined) = acquisition_tasks.join_next().await {
            match joined {
                Ok(item) => acquired.push(item),
                Err(error) => log(&format!("WARNING: source acquisition task failed: {error}")),
            }
        }

        // Convert the acquired source results into independent list jobs. The
        // old implementation probed these lists one after another, so an
        // adaptive/unbounded pool of slow endpoints could exhaust Stage 0b's
        // 12-minute budget even though acquisition itself was concurrent.
        let mut list_inputs = Vec::new();
        for (transport, ipv6, bridgedb, community) in acquired {
            let fetched = bridgedb.unwrap_or_else(|error| {
                log(&format!(
                    "WARNING: BridgeDB {transport} ipv6={ipv6} unavailable: {error}"
                ));
                Vec::new()
            });
            let seeded = community.unwrap_or_else(|error| {
                log(&format!(
                    "WARNING: community source {transport} ipv6={ipv6} unavailable: {error}"
                ));
                Vec::new()
            });
            let defaults =
                if transport.is_fronted() && fetched.is_empty() && seeded.is_empty() && !ipv6 {
                    fronted_defaults(transport)
                        .iter()
                        .map(|line| clean_output_line(line))
                        .filter(|line| is_valid_bridge_line(line))
                        .collect()
                } else {
                    Vec::new()
                };
            list_inputs.push((transport, ipv6, fetched, seeded));
            if !defaults.is_empty() {
                list_inputs.push((transport, false, Vec::new(), defaults));
            }
        }

        // Each worker receives a read-only snapshot for health-aware ordering.
        // Outcomes are merged below in stable transport order, which keeps
        // publication deterministic while allowing all protocol probes to
        // share the ProbeEngine's adaptive concurrency state.
        let history_snapshot = history.clone();
        let mut list_tasks = JoinSet::new();
        for (transport, ipv6, fetched, seeded) in list_inputs {
            let service = self.clone();
            let list_history = history_snapshot.clone();
            list_tasks.spawn(async move {
                service
                    .collect_list(transport, ipv6, fetched, seeded, list_history)
                    .await
            });
        }

        let mut outcomes = Vec::new();
        while let Some(joined) = list_tasks.join_next().await {
            match joined {
                Ok(Ok(Some(outcome))) => outcomes.push(outcome),
                Ok(Ok(None)) => {}
                Ok(Err(error)) => return Err(error),
                Err(error) => return Err(error.into()),
            }
        }
        outcomes.sort_by(|left, right| {
            left.transport
                .cmp(&right.transport)
                .then_with(|| left.ipv6.cmp(&right.ipv6))
        });

        for outcome in outcomes {
            for line in &outcome.source_lines {
                history.observe_discovered(line, outcome.transport, outcome.ipv6, now);
            }
            for result in &outcome.results {
                history.record_probe(
                    &result.line,
                    outcome.transport,
                    outcome.ipv6,
                    result.reachable,
                    result.latency_ms,
                    now,
                );
            }

            let spec = ListSpec {
                transport: outcome.transport,
                ipv6: outcome.ipv6,
            };
            let archive_path = self.config.bridge_dir.join(spec.archive_name());
            let recent = outcome
                .archive
                .iter()
                .filter(|line| history.is_recent(line, self.config.recent_hours, now))
                .cloned()
                .collect::<Vec<_>>();
            stage_lines(&mut staged, archive_path, &outcome.archive);
            stage_lines(
                &mut staged,
                self.config.bridge_dir.join(spec.recent_name()),
                &recent,
            );
            stage_lines(
                &mut staged,
                self.config.bridge_dir.join(spec.tested_name()),
                &outcome.tested,
            );
            stats.insert(
                spec.archive_name(),
                ListStats {
                    archive: outcome.archive.len(),
                    recent: recent.len(),
                    tested: outcome.tested.len(),
                },
            );
            log(&format!(
                "{} ipv6={}: archive={} fresh72h={} tested={} candidates={}",
                outcome.transport,
                outcome.ipv6,
                outcome.archive.len(),
                recent.len(),
                outcome.tested.len(),
                outcome.results.len(),
            ));
        }

        let purged = history.cleanup(self.config.history_retention_days, now);
        if purged > 0 {
            log(&format!(
                "Removed {purged} history entries older than {} days",
                self.config.history_retention_days
            ));
        }
        if history_writable {
            staged.insert(self.config.history_path.clone(), history.to_bytes()?);
        }

        staged.insert(
            self.config.readme_path.clone(),
            render_readme(&self.config, &stats, now).into_bytes(),
        );

        let mut zip_entries = existing_zip_entries(&self.config.bridge_dir)?;
        for (path, bytes) in &staged {
            if path.parent() == Some(self.config.bridge_dir.as_path()) {
                if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                    if name.ends_with(".txt") {
                        zip_entries.insert(name.to_owned(), bytes.clone());
                    }
                }
            }
        }
        let zip_bytes = build_zip(&zip_entries)?;
        staged.insert(self.config.zip_path.clone(), zip_bytes.clone());

        if let Some(path) = &self.config.metrics_output {
            staged.insert(path.clone(), self.tester.metrics().render().into_bytes());
        }
        if !self.config.dry_run {
            write_yield_dashboard(&self.config, &stats, history.len())?;
        }

        let changed_files = publish_staged(&staged, self.config.dry_run)?;
        if self.config.dry_run {
            log(&format!(
                "DRY RUN complete: {changed_files} file(s) would change; no output was written"
            ));
        } else {
            log(&format!(
                "Published {changed_files} changed file(s) atomically"
            ));
        }

        if !self.config.dry_run && self.config.telegram_triggered_at(now.hour()) {
            match upload_telegram(&self.config, zip_bytes, telegram_caption(&stats)).await {
                Ok(()) => log("Telegram upload successful: tor_bridges.zip"),
                Err(error) => log(&format!("WARNING: Telegram upload skipped/failed: {error}")),
            }
        } else if self.config.dry_run {
            log("Telegram upload skipped in dry-run mode");
        }

        log("Unified collector run complete.");
        Ok(RunSummary {
            changed_files,
            dry_run: self.config.dry_run,
            stats,
            history_entries: history.len(),
        })
    }

    /// When the stage deadline fires mid-collection, flush whatever output
    /// files we have partially staged so downstream CI stages have
    /// last-known-good data instead of nothing.
    async fn flush_partial(&self) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
        let mut staged = BTreeMap::new();
        // Re-read all existing archive files from disk so we can
        // republish them unchanged alongside any partial results.
        for transport in Transport::POOLED.into_iter().chain(Transport::FRONTED) {
            for ipv6 in [false, true] {
                let spec = ListSpec { transport, ipv6 };
                let archive_path = self.config.bridge_dir.join(spec.archive_name());
                if let Ok(existing) = read_existing_archive(&archive_path) {
                    if !existing.is_empty() {
                        stage_lines(&mut staged, archive_path, &existing);
                    }
                }
            }
        }
        log(&format!(
            "Flushed {} existing archive files as partial-deadline fallback",
            staged.len()
        ));
        Ok(staged)
    }

    async fn collect_list(
        &self,
        transport: Transport,
        ipv6: bool,
        fetched: Vec<String>,
        seeded: Vec<String>,
        history: HistoryStore,
    ) -> Result<Option<ListOutcome>> {
        let spec = ListSpec { transport, ipv6 };
        let archive_path = self.config.bridge_dir.join(spec.archive_name());
        let existing = match read_existing_archive(&archive_path) {
            Ok(lines) => lines,
            Err(error) => {
                log(&format!(
                    "WARNING: unable to read {} ({error}); leaving this archive untouched",
                    archive_path.display()
                ));
                return Ok(None);
            }
        };
        let source_lines = deduplicate(
            fetched
                .into_iter()
                .chain(seeded)
                .map(|line| clean_output_line(&line))
                .filter(|line| is_valid_bridge_line(line))
                .collect(),
        );
        let archive = deduplicate(
            existing
                .into_iter()
                .chain(source_lines.iter().cloned())
                .collect(),
        );
        if archive.is_empty() {
            // This is the zero-byte/empty-upstream guard: no archive, recent,
            // or tested file is touched when there is nothing trustworthy to
            // publish, so a transient source failure cannot erase old output.
            log(&format!(
                "WARNING: {transport} ipv6={ipv6} has no usable source or existing lines; retaining prior files"
            ));
            return Ok(None);
        }

        let mut candidates = archive.clone();
        candidates.sort_by(|left, right| {
            history
                .health_score(right)
                .partial_cmp(&history.health_score(left))
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.cmp(right))
        });
        // A zero ceiling is the default adaptive mode: never discard source
        // lines merely because they arrived after an old fixed top-N limit.
        // Operators can still set a positive ceiling as an explicit safety
        // valve for constrained runners.
        if self.config.max_test_per_list > 0 {
            candidates.truncate(self.config.max_test_per_list);
        }
        let results = self.tester.test_many(candidates, transport, ipv6).await;
        let mut tested = successful_lines(&results);
        if transport == Transport::Obfs4 && !ipv6 && !tested.is_empty() {
            let verification = self.tester.verify_obfs4_handshakes(&tested).await;
            tested =
                apply_obfs4_policy(tested, verification, self.config.obfs4_verify_min_fraction);
        }

        Ok(Some(ListOutcome {
            transport,
            ipv6,
            archive,
            source_lines,
            results,
            tested,
        }))
    }
}

fn successful_lines(results: &[ProbeResult]) -> Vec<String> {
    deduplicate(
        results
            .iter()
            .filter(|result| result.reachable)
            .map(|result| result.line.clone())
            .collect(),
    )
}

fn apply_obfs4_policy(
    tcp_reachable: Vec<String>,
    verification: Obfs4Verification,
    minimum_fraction: f64,
) -> Vec<String> {
    if !verification.ran {
        // No harness means transport-level verification was not attempted. A
        // TCP prefilter remains useful for the archive, but it is explicitly
        // labelled as unverified rather than silently reported as a success.
        log(&format!(
            "WARNING: obfs4 verify unavailable for {} TCP candidates: {}; retaining TCP set as unverified",
            tcp_reachable.len(),
            verification.diagnostic
        ));
        return tcp_reachable;
    }
    let threshold = ((verification.attempted as f64) * minimum_fraction).ceil() as usize;
    let threshold = threshold.max(1);
    if verification.verified.len() < threshold {
        // Never convert a failed real handshake into a successful-looking
        // tested line. This was the source of the misleading 0/255 fallback
        // signal in the incident run.
        log(&format!(
            "ERROR: obfs4 verify only {}/{} handshakes (minimum {threshold}); publishing verified subset only",
            verification.verified.len(),
            verification.attempted
        ));
    } else {
        log(&format!(
            "obfs4 verify: {}/{} completed an obfs4 SOCKS handshake",
            verification.verified.len(),
            verification.attempted
        ));
    }
    deduplicate(verification.verified)
}

fn read_existing_archive(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("unable to read archive {}", path.display()))?;
    Ok(deduplicate(
        text.lines()
            .map(clean_output_line)
            .filter(|line| is_valid_bridge_line(line))
            .collect(),
    ))
}

fn stage_lines(staged: &mut BTreeMap<PathBuf, Vec<u8>>, path: PathBuf, lines: &[String]) {
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    staged.insert(path, content.into_bytes());
}

fn publish_staged(staged: &BTreeMap<PathBuf, Vec<u8>>, dry_run: bool) -> Result<usize> {
    let mut changed: usize = 0;
    for (index, (path, bytes)) in staged.iter().enumerate() {
        let is_changed =
            std::fs::read(path).map_or(true, |current| current.as_slice() != bytes.as_slice());
        if !is_changed {
            continue;
        }
        changed = changed.saturating_add(1);
        if dry_run {
            println!(
                "[{}] DRY RUN would update {} ({} bytes)",
                timestamp(),
                path.display(),
                bytes.len()
            );
            continue;
        }
        write_atomic(path, bytes, index)?;
    }
    Ok(changed)
}

fn write_atomic(path: &Path, bytes: &[u8], index: usize) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("unable to create {}", parent.display()))?;
        }
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("collector-output");
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}-{index}", std::process::id()));
    std::fs::write(&temporary, bytes)
        .with_context(|| format!("unable to write temporary output {}", temporary.display()))?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(anyhow::Error::from(error))
            .with_context(|| format!("unable to publish {}", path.display()));
    }
    Ok(())
}

fn write_yield_dashboard(
    config: &CollectorConfig,
    stats: &StatsMap,
    history_entries: usize,
) -> Result<()> {
    let mut transports = serde_json::Map::new();
    for transport in Transport::POOLED.into_iter().chain(Transport::FRONTED) {
        let ipv4 = stats
            .get(&format!("{}.txt", transport.file_name()))
            .copied()
            .unwrap_or_default();
        let ipv6 = stats
            .get(&format!("{}_ipv6.txt", transport.file_name()))
            .copied()
            .unwrap_or_default();
        transports.insert(
            transport.file_name().to_string(),
            json!({
                "archive_ipv4": ipv4.archive,
                "archive_ipv6": ipv6.archive,
                "fresh_ipv4": ipv4.recent,
                "fresh_ipv6": ipv6.recent,
                "tested_ipv4": ipv4.tested,
                "tested_ipv6": ipv6.tested,
                "dynamic_pool": config.max_test_per_list == 0,
            }),
        );
    }
    let generated_at = Utc::now().to_rfc3339();
    let data_dir = PathBuf::from("data");
    let trend_path = data_dir.join("collector_yield_history.json");
    let mut trend_history = fs::read_to_string(&trend_path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut trends = serde_json::Map::new();
    for (transport, current) in &transports {
        let mut previous = Vec::new();
        for snapshot in trend_history.iter().rev().take(7) {
            if let Some(value) = snapshot
                .get("transports")
                .and_then(|items| items.get(transport))
                .and_then(|item| {
                    Some(item.get("archive_ipv4")?.as_u64()? + item.get("archive_ipv6")?.as_u64()?)
                })
            {
                previous.push(value as f64);
            }
        }
        let average = if previous.is_empty() {
            0.0
        } else {
            previous.iter().sum::<f64>() / previous.len() as f64
        };
        let current_count = current
            .get("archive_ipv4")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            + current
                .get("archive_ipv6")
                .and_then(Value::as_u64)
                .unwrap_or(0);
        trends.insert(
            transport.clone(),
            json!({
                "current_archive_count": current_count,
                "trailing_7_run_average": average,
                "below_trailing_7_run_average": !previous.is_empty() && (current_count as f64) < average,
            }),
        );
    }
    let snapshot = json!({"generated_at": generated_at.clone(), "transports": transports.clone()});
    trend_history.push(snapshot);
    if trend_history.len() > 90 {
        let drop_count = trend_history.len() - 90;
        trend_history.drain(0..drop_count);
    }
    let report = json!({
        "schema_version": 1,
        "generated_at": generated_at,
        "engine": "torshield-rust-adaptive-collector-v2",
        "history_entries": history_entries,
        "max_workers": config.max_workers,
        "max_test_per_list": config.max_test_per_list,
        "dynamic_pool_mode": config.max_test_per_list == 0,
        "transports": transports,
        "trends": trends,
        "failsafe_telemetry": "data/failsafe_activations.json",
    });
    fs::create_dir_all(&data_dir).context("unable to create data dashboard directory")?;
    let mut trend_bytes = serde_json::to_vec_pretty(&Value::Array(trend_history))?;
    trend_bytes.push(b'\n');
    fs::write(&trend_path, trend_bytes)?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    let temporary = data_dir.join(format!(
        ".collector_yield_report.tmp-{}",
        std::process::id()
    ));
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, data_dir.join("collector_yield_report.json"))?;

    let mut summary = String::from("# Adaptive collector yield\n\n");
    summary.push_str("| Transport | IPv4 archive | IPv6 archive | IPv4 tested | IPv6 tested |\n|---|---:|---:|---:|---:|\n");
    for transport in Transport::POOLED.into_iter().chain(Transport::FRONTED) {
        let ipv4 = stats
            .get(&format!("{}.txt", transport.file_name()))
            .copied()
            .unwrap_or_default();
        let ipv6 = stats
            .get(&format!("{}_ipv6.txt", transport.file_name()))
            .copied()
            .unwrap_or_default();
        summary.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            transport.file_name(),
            ipv4.archive,
            ipv6.archive,
            ipv4.tested,
            ipv6.tested
        ));
    }
    fs::write(data_dir.join("collector_yield_summary.md"), summary)?;
    Ok(())
}

/// Print timestamps on stdout to retain compatibility with existing CI log
/// scraping, while structured `tracing` events are emitted by subcomponents.
pub fn log(message: &str) {
    println!("[{}] {message}", timestamp());
    tracing::info!(message = %message);
}

fn timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn test_config() -> CollectorConfig {
        let bridge_dir = PathBuf::from("bridge");
        CollectorConfig {
            bridge_dir: bridge_dir.clone(),
            readme_path: PathBuf::from("README.md"),
            history_path: bridge_dir.join("bridge_history.json"),
            zip_path: bridge_dir.join("tor_bridges.zip"),
            bridgedb_base_url: "https://example.invalid".to_owned(),
            delta_raw_base_url: "https://example.invalid".to_owned(),
            raw_repo_url: "https://example.invalid".to_owned(),
            connect_timeout_secs: 1,
            obfs4_handshake_timeout_secs: 1,
            max_retries: 1,
            max_workers: 8,
            min_workers: 2,
            max_test_per_list: 10,
            recent_hours: 72,
            history_retention_days: 30,
            obfs4_verify_min_fraction: 0.2,
            front_failure_threshold: 2,
            front_cooldown_secs: 1,
            fetch_retries: 1,
            per_source_timeout_secs: 15,
            source_circuit_breaker_failures: 5,
            source_circuit_breaker_reset_secs: 600,
            stage_deadline_secs: 660,
            retained_fallback_dir: bridge_dir,
            metrics_output: None,
            dry_run: true,
            verbose: false,
            telegram_bot_token: None,
            telegram_chat_id: None,
            telegram_upload: false,
            github_actions: false,
        }
    }

    #[test]
    fn obfs4_policy_preserves_tcp_set_when_harness_is_unavailable() {
        let lines = vec!["obfs4 1.2.3.4:443 FINGER cert=x".to_owned()];
        let output = apply_obfs4_policy(
            lines.clone(),
            Obfs4Verification {
                ran: false,
                diagnostic: "missing".to_owned(),
                ..Obfs4Verification::default()
            },
            0.2,
        );
        assert_eq!(output, lines);
    }

    #[test]
    fn obfs4_policy_does_not_mask_failed_real_handshakes() {
        let lines = vec![
            "obfs4 1.2.3.4:443 FINGER cert=x".to_owned(),
            "obfs4 5.6.7.8:443 FINGER cert=x".to_owned(),
        ];
        let output = apply_obfs4_policy(
            lines,
            Obfs4Verification {
                verified: Vec::new(),
                unparseable: Vec::new(),
                attempted: 2,
                failed: 2,
                ran: true,
                diagnostic: "ran".to_owned(),
            },
            0.2,
        );
        assert!(
            output.is_empty(),
            "failed handshakes must not be published as tested"
        );
    }

    #[test]
    fn stage_lines_writes_clean_newline_terminated_output() {
        let mut staged = BTreeMap::new();
        stage_lines(
            &mut staged,
            PathBuf::from("bridge/vanilla.txt"),
            &["1.2.3.4:443 FINGER".to_owned()],
        );
        assert_eq!(
            staged.get(&PathBuf::from("bridge/vanilla.txt")),
            Some(&b"1.2.3.4:443 FINGER\n".to_vec())
        );
    }
}

//! `handshake_probe` — runner-side transport handshake verification.
//!
//! This binary closes the S2+ evidence gap that left every `*_tested.txt`,
//! `tested_global_*.txt`, and `iran_likely_working_*.txt` projection
//! permanently empty: the pipeline collected TCP-level (S1) evidence only,
//! while the publication contract gates those files on typed, positive S2+
//! protocol observations from a recognized vantage (`src/evidence_stamp.rs`).
//!
//! The binary drives the `tbc-prober` handshake engine (`crates/prober`)
//! against the current candidate pool and emits flat verification records in
//! the exact schema `evidence_stamp::merge_relay_results_at` already consumes
//! from `data/pt_results.json`, so the existing `pipeline --stage results`
//! merge path picks them up without any schema change:
//!
//! ```json
//! {"line":"Bridge ...","status":"connected","stage":"S3",
//!  "probe_type":"tor-handshake","vantage":{"type":"github_actions_runner"},
//!  "rtt_ms":42,"observed_at":"...","detail":"...","error_class":null,
//!  "source":"handshake-probe"}
//! ```
//!
//! ## Honest stage mapping (never fabricates a stronger stage)
//!
//! | Transport  | Verified exchange                                   | Stage | probe_type        |
//! |------------|------------------------------------------------------|-------|-------------------|
//! | vanilla    | tor-spec `VERSIONS` + `NETINFO` link-cell exchange   | S3    | `tor-handshake`   |
//! | obfs4      | framing handshake, server `M_S`/`MAC_S` verified     | S3    | `obfs4-framing`   |
//! | webtunnel  | RFC 6455 upgrade + `Sec-WebSocket-Accept` verified   | S2    | `websocket-101`   |
//! | meek       | domain-fronted POST envelope parsed                  | S2    | `meek-envelope`   |
//! | snowflake  | broker rendezvous response parsed                    | S2    | `snowflake-broker`|
//!
//! Failures keep their neutral S0/S1 stages (`timeout`, `refused`, `error`,
//! `inconclusive`); a failed handshake never becomes a positive observation,
//! exactly like the relay path. The obfs4 probe completes the framing
//! handshake but deliberately does not verify the ntor `AUTH` tag (see the
//! honest boundary in `crates/prober/src/lib.rs`), so it is stamped S3, not
//! S4. No S4 evidence is ever emitted by this binary.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use serde_json::{json, Value};
use tbc_core::{BridgeLine, SystemClock, TransportKind};
use tbc_prober::{ProbeConfig, Prober};

/// Upper bound on the candidate pool ingested from `--input`, guarding the
/// parser against pathological files.
const MAX_INPUT_LINES: usize = 20_000;

#[derive(Debug, clap::Parser)]
#[command(
    name = "handshake_probe",
    about = "Runner-side transport handshake verification (typed S2+/S3 evidence)"
)]
struct Args {
    /// Candidate source: `bridge/iran_results.json` (object with `bridges`,
    /// honoring per-bridge `tcp_reachable`/`composite_score` priority), a JSON
    /// array of bridge lines, or a plain newline-delimited list.
    #[arg(long, default_value = "bridge/iran_results.json")]
    input: PathBuf,
    /// Where the typed observation records are written (JSON array).
    #[arg(long, default_value = "data/handshake_results.json")]
    output: PathBuf,
    /// Existing relay-schema file the records are appended into (deduplicated
    /// by line + stage + observed_at). Typically `data/pt_results.json`, which
    /// `pipeline --stage results` merges into the published evidence.
    #[arg(long)]
    merge_into: Option<PathBuf>,
    /// Maximum bridges to probe this invocation (quota guard).
    #[arg(long, default_value_t = 300)]
    max_bridges: usize,
    /// Concurrent handshake probes.
    #[arg(long, default_value_t = 24)]
    workers: usize,
    /// Per-operation connect/read/write timeout in seconds.
    #[arg(long, default_value_t = 8)]
    timeout_secs: u64,
    /// Wall-clock budget for the whole invocation in seconds.
    #[arg(long, default_value_t = 480)]
    budget_seconds: u64,
}

/// A candidate selected for probing, ordered by publication value.
struct Candidate {
    line: String,
    /// S1-reachable candidates first: a TCP-verified endpoint is the most
    /// likely to complete a transport handshake within the run budget.
    tcp_reachable: bool,
    score: f64,
    /// Canonical transport family of the parsed line (issue #257 follow-up:
    /// drives stratified selection so every supported family gets S2+
    /// coverage within the run quota instead of the largest family absorbing
    /// the whole budget).
    transport: TransportKind,
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(summary) => {
            let by_transport = summary
                .selected_by_transport
                .iter()
                .map(|(transport, count)| format!("{transport}={count}"))
                .collect::<Vec<_>>()
                .join(",");
            eprintln!(
                "handshake-probe: connected={} reachable_s1={} failed={} skipped_unsupported={} parse_errors={} selected={} selected_by_transport=[{by_transport}]",
                summary.connected,
                summary.reachable_s1,
                summary.failed,
                summary.skipped_unsupported,
                summary.parse_errors,
                summary.selected,
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::from(1)
        }
    }
}

struct RunSummary {
    connected: usize,
    reachable_s1: usize,
    failed: usize,
    skipped_unsupported: usize,
    parse_errors: usize,
    selected: usize,
    /// Per-family selected counts, printed for run observability so the
    /// stratified quota is auditable from the CI log alone.
    selected_by_transport: std::collections::BTreeMap<String, usize>,
}

fn run(args: Args) -> Result<RunSummary, String> {
    let raw = std::fs::read_to_string(&args.input)
        .map_err(|error| format!("read {}: {error}", args.input.display()))?;
    let (candidates, parse_errors, skipped_unsupported) = select_candidates(&raw);
    // Stratified quota: round-robin across transport families (reachable-first
    // within each family) so the fixed bridge quota buys evidence for EVERY
    // supported family. The previous reachable-first global take let the
    // largest family (obfs4) absorb the whole budget, which left vanilla,
    // webtunnel, snowflake, and meek with zero S2+ observations and their
    // evidence-gated *_tested.txt projections permanently empty.
    let selected: Vec<Candidate> = stratify_candidates(candidates, args.max_bridges);
    let mut selected_by_transport: BTreeMap<String, usize> = BTreeMap::new();
    for candidate in &selected {
        *selected_by_transport
            .entry(candidate.transport.to_string())
            .or_insert(0) += 1;
    }
    let selected_count = selected.len();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| format!("build tokio runtime: {error}"))?;
    let records = runtime.block_on(probe_all(
        selected,
        args.timeout_secs,
        args.workers,
        args.budget_seconds,
    ))?;

    let connected = records
        .iter()
        .filter(|record| record["status"] == "connected" && record["stage"] != "S1")
        .count();
    let reachable_s1 = records
        .iter()
        .filter(|record| record["status"] == "connected" && record["stage"] == "S1")
        .count();
    let failed = records.len() - connected - reachable_s1;

    write_json_array(&args.output, &records)?;
    if let Some(merge_path) = args.merge_into.as_ref() {
        merge_into(merge_path, &records)?;
    }

    Ok(RunSummary {
        connected,
        reachable_s1,
        failed,
        skipped_unsupported,
        parse_errors,
        selected: selected_count,
        selected_by_transport,
    })
}

/// Interleave per-transport sorted groups into one quota-bounded list.
///
/// Each group keeps its own publication-value order (S1-reachable first, then
/// descending score). One candidate is taken from each family per rotation in
/// a deterministic (alphabetical) family order, so families present in the
/// input always receive proportional representation and no family can be
/// starved below one rotation slot by a larger family. Deterministic: equal
/// inputs produce equal outputs.
fn stratify_candidates(candidates: Vec<Candidate>, quota: usize) -> Vec<Candidate> {
    let mut groups: BTreeMap<String, std::collections::VecDeque<Candidate>> = BTreeMap::new();
    for candidate in candidates {
        groups
            .entry(candidate.transport.to_string())
            .or_default()
            .push_back(candidate);
    }
    for queue in groups.values_mut() {
        let mut group: Vec<Candidate> = queue.drain(..).collect();
        group.sort_by(|a, b| {
            b.tcp_reachable.cmp(&a.tcp_reachable).then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });
        *queue = group.into();
    }
    let mut selected = Vec::with_capacity(quota);
    while selected.len() < quota && !groups.is_empty() {
        let mut progressed = false;
        let mut next: BTreeMap<String, std::collections::VecDeque<Candidate>> = BTreeMap::new();
        for (name, mut queue) in groups {
            if selected.len() < quota {
                if let Some(candidate) = queue.pop_front() {
                    selected.push(candidate);
                    progressed = true;
                }
            }
            if !queue.is_empty() {
                next.insert(name, queue);
            }
        }
        groups = next;
        if !progressed {
            break;
        }
    }
    selected
}

/// Parse the input into ordered candidates plus honest accounting of what was
/// skipped. Ordering: S1 TCP-reachable first, then by descending composite
/// score, so the budget buys the most publication-relevant evidence first.
fn select_candidates(raw: &str) -> (Vec<Candidate>, usize, usize) {
    let mut parse_errors = 0_usize;
    let mut skipped_unsupported = 0_usize;
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();

    for (line, tcp_reachable, score) in iter_input(raw) {
        if candidates.len() >= MAX_INPUT_LINES {
            break;
        }
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() || trimmed.starts_with('#') || !seen.insert(trimmed.clone()) {
            continue;
        }
        let now = chrono::Utc::now();
        let Ok(bridge) = BridgeLine::parse(&trimmed, now) else {
            parse_errors += 1;
            continue;
        };
        if !matches!(
            bridge.transport,
            TransportKind::Obfs4
                | TransportKind::Vanilla
                | TransportKind::WebTunnel
                | TransportKind::Meek
                | TransportKind::Snowflake
        ) {
            // Conjure and other transports have no handshake probe; record the
            // skip instead of silently dropping them.
            skipped_unsupported += 1;
            continue;
        }
        candidates.push(Candidate {
            line: trimmed,
            tcp_reachable,
            score,
            transport: bridge.transport,
        });
    }

    candidates.sort_by(|a, b| {
        b.tcp_reachable.cmp(&a.tcp_reachable).then(
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    (candidates, parse_errors, skipped_unsupported)
}

/// Yield `(line, tcp_reachable, score)` triples from any accepted input shape.
fn iter_input(raw: &str) -> Vec<(String, bool, f64)> {
    if let Ok(Value::Object(object)) = serde_json::from_str::<Value>(raw) {
        if let Some(Value::Array(bridges)) = object.get("bridges") {
            return bridges
                .iter()
                .filter_map(|bridge| {
                    let line = bridge.get("line").and_then(Value::as_str)?;
                    let tcp = bridge
                        .get("tcp_reachable")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let score = bridge
                        .get("composite_score")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    Some((line.to_string(), tcp, score))
                })
                .collect();
        }
    }
    if let Ok(Value::Array(lines)) = serde_json::from_str::<Value>(raw) {
        return lines
            .iter()
            .filter_map(Value::as_str)
            .map(|line| (line.to_string(), false, 0.0))
            .collect();
    }
    raw.lines()
        .map(|line| (line.to_string(), false, 0.0))
        .collect()
}

/// Probe the selected candidates concurrently under a hard wall-clock budget.
async fn probe_all(
    candidates: Vec<Candidate>,
    timeout_secs: u64,
    workers: usize,
    budget_seconds: u64,
) -> Result<Vec<Value>, String> {
    let deadline = Instant::now() + Duration::from_secs(budget_seconds);
    let config = ProbeConfig {
        connect_timeout: Duration::from_secs(timeout_secs),
        read_timeout: Duration::from_secs(timeout_secs),
        write_timeout: Duration::from_secs(timeout_secs),
        max_attempts: 1,
        backoff_base: Duration::from_millis(100),
        backoff_max: Duration::from_secs(1),
        max_bridges_per_run: candidates.len().max(1),
    };
    let prober = Arc::new(
        Prober::new(config, Arc::new(SystemClock))
            .map_err(|error| format!("invalid probe config: {error}"))?,
    );
    let semaphore = Arc::new(tokio::sync::Semaphore::new(workers.max(1)));
    let mut join_set = tokio::task::JoinSet::new();

    for candidate in candidates {
        if Instant::now() >= deadline {
            break;
        }
        let permit = Arc::clone(&semaphore);
        let prober = Arc::clone(&prober);
        let line = candidate.line;
        join_set.spawn(async move {
            let _permit = permit.acquire().await;
            let now = chrono::Utc::now();
            let parsed = BridgeLine::parse(&line, now);
            let record = match parsed {
                Ok(bridge) => {
                    let result = prober.probe_bridge(&bridge).await;
                    outcome_record(&line, &bridge.transport.to_string(), &result.outcome)
                }
                Err(_) => record(
                    &line,
                    "inconclusive",
                    "S0",
                    "none",
                    0.0,
                    "bridge line no longer parses; skipped by handshake probe",
                    Some("parse"),
                ),
            };
            (line, record)
        });
    }

    let mut records = Vec::new();
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok((_, record)) => records.push(record),
            Err(error) => eprintln!("handshake-probe: task failed: {error}"),
        }
    }
    Ok(records)
}

/// Map a typed [`tbc_prober::ProbeOutcome`] onto the flat relay-schema record
/// with the honest stage table from the module docs. A reachable outcome is
/// positive evidence of the transport handshake listed in the outcome's own
/// evidence string; everything else stays a neutral, negative-or-inconclusive
/// observation.
fn outcome_record(line: &str, transport: &str, outcome: &tbc_prober::ProbeOutcome) -> Value {
    match outcome.verdict {
        tbc_core::Verdict::Reachable => {
            let (stage, probe_type) = positive_stage(transport);
            let rtt = outcome.rtt_ms.map(|ms| ms as f64).unwrap_or(0.0);
            record(
                line,
                "connected",
                stage,
                probe_type,
                rtt,
                outcome
                    .evidence
                    .as_deref()
                    .unwrap_or("transport handshake verified"),
                None,
            )
        }
        tbc_core::Verdict::Refused => failure_record(line, transport, outcome, "refused"),
        tbc_core::Verdict::Timeout => failure_record(line, transport, outcome, "timeout"),
        tbc_core::Verdict::DnsFailure => failure_record(line, transport, outcome, "error"),
        tbc_core::Verdict::Inconclusive => failure_record(line, transport, outcome, "inconclusive"),
        // Reset-injected, TLS alert, handshake-auth failures, HTTP errors, and
        // explicit blocks are observed refusals; they stay typed and negative,
        // never silently neutral, mirroring the relay mapping.
        _ => failure_record(line, transport, outcome, "error"),
    }
}

/// The honest `(stage, probe_type)` for a verified handshake per transport.
fn positive_stage(transport: &str) -> (&'static str, &'static str) {
    match transport {
        "vanilla" => ("S3", "tor-handshake"),
        "obfs4" => ("S3", "obfs4-framing"),
        "webtunnel" => ("S2", "websocket-101"),
        "meek" => ("S2", "meek-envelope"),
        "snowflake" => ("S2", "snowflake-broker"),
        _ => ("S1", "transport-check"),
    }
}

fn failure_record(
    line: &str,
    transport: &str,
    outcome: &tbc_prober::ProbeOutcome,
    status: &str,
) -> Value {
    // Failed handshakes stay at S0 (observed attempt before any positive
    // connection stage); the evidence string records what actually happened.
    let error_class = outcome.error_class.clone().unwrap_or_default();
    record(
        line,
        status,
        "S0",
        "none",
        0.0,
        outcome
            .evidence
            .as_deref()
            .unwrap_or("handshake not completed"),
        Some(&format!("{transport}:{error_class}")),
    )
}

#[allow(clippy::too_many_arguments)]
fn record(
    line: &str,
    status: &str,
    stage: &str,
    probe_type: &str,
    rtt_ms: f64,
    detail: &str,
    error_class: Option<&str>,
) -> Value {
    json!({
        "line": line,
        "status": status,
        "stage": stage,
        "probe_type": probe_type,
        "vantage": {"type": "github_actions_runner", "region": null},
        "rtt_ms": rtt_ms,
        "observed_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "detail": detail,
        "error_class": error_class,
        "source": "handshake-probe",
    })
}

/// Write a JSON array file atomically (tmp + rename), creating parents.
fn write_json_array(path: &PathBuf, records: &[Value]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(records)
        .map_err(|error| format!("serialize records: {error}"))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = std::fs::File::create(&tmp)
            .map_err(|error| format!("create {}: {error}", tmp.display()))?;
        file.write_all(body.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|error| format!("write {}: {error}", tmp.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|error| format!("rename {}: {error}", path.display()))
}

/// Append records into an existing relay-schema file, deduplicating on
/// (line, stage, observed_at). Missing target files start from an empty array.
fn merge_into(path: &PathBuf, records: &[Value]) -> Result<(), String> {
    let mut existing: Vec<Value> = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .and_then(|value: Value| value.as_array().cloned())
        .unwrap_or_default();
    let mut seen: BTreeSet<String> = existing.iter().map(record_dedup_key).collect();
    for record in records {
        let key = record_dedup_key(record);
        if seen.insert(key) {
            existing.push(record.clone());
        }
    }
    write_json_array(path, &existing)
}

fn record_dedup_key(record: &Value) -> String {
    format!(
        "{}|{}|{}",
        record.get("line").and_then(Value::as_str).unwrap_or(""),
        record.get("stage").and_then(Value::as_str).unwrap_or(""),
        record
            .get("observed_at")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn positive_stage_mapping_is_honest_per_transport() {
        assert_eq!(positive_stage("vanilla"), ("S3", "tor-handshake"));
        assert_eq!(positive_stage("obfs4"), ("S3", "obfs4-framing"));
        assert_eq!(positive_stage("webtunnel"), ("S2", "websocket-101"));
        assert_eq!(positive_stage("meek"), ("S2", "meek-envelope"));
        assert_eq!(positive_stage("snowflake"), ("S2", "snowflake-broker"));
        assert_eq!(positive_stage("conjure"), ("S1", "transport-check"));
    }

    #[test]
    fn reachable_outcome_stamps_connected_with_transport_stage() {
        let outcome = tbc_prober::ProbeOutcome::reachable(tbc_prober::ProbeDetail {
            evidence: Some("VERSIONS/NETINFO link-cell exchange verified".to_owned()),
            rtt_ms: Some(42),
        });
        let record = outcome_record("Bridge 192.0.2.1:443 A", "vanilla", &outcome);
        assert_eq!(record["status"], "connected");
        assert_eq!(record["stage"], "S3");
        assert_eq!(record["probe_type"], "tor-handshake");
        assert_eq!(record["vantage"]["type"], "github_actions_runner");
        assert_eq!(record["source"], "handshake-probe");
        assert_eq!(record["rtt_ms"], 42.0);
        assert!(record["error_class"].is_null());
    }

    #[test]
    fn timeout_outcome_stays_neutral_s0_and_never_becomes_positive() {
        let outcome = tbc_prober::ProbeOutcome::from_error(&tbc_prober::ProbeError::Timeout {
            phase: "connect",
        });
        let record = outcome_record("Bridge 192.0.2.1:443 A", "obfs4", &outcome);
        assert_eq!(record["status"], "timeout");
        assert_eq!(record["stage"], "S0");
        assert_eq!(record["probe_type"], "none");
        assert!(record["error_class"].is_string());
    }

    #[test]
    fn iran_results_input_orders_tcp_reachable_and_dedupes() {
        let raw = serde_json::json!({
            "bridges": [
                {"line": "Bridge 192.0.2.10:443 A", "tcp_reachable": false, "composite_score": 0.9},
                {"line": "Bridge 192.0.2.11:443 B", "tcp_reachable": true, "composite_score": 0.2},
                {"line": "Bridge 192.0.2.12:443 C", "tcp_reachable": true, "composite_score": 0.7},
                {"line": "Bridge 192.0.2.11:443 B", "tcp_reachable": true, "composite_score": 0.2}
            ]
        })
        .to_string();
        let (candidates, parse_errors, skipped) = select_candidates(&raw);
        assert_eq!(parse_errors, 0);
        assert_eq!(skipped, 0);
        let lines: Vec<&str> = candidates.iter().map(|c| c.line.as_str()).collect();
        assert_eq!(
            lines,
            vec![
                "Bridge 192.0.2.12:443 C",
                "Bridge 192.0.2.11:443 B",
                "Bridge 192.0.2.10:443 A"
            ]
        );
    }

    #[test]
    fn unsupported_transports_are_counted_not_silently_dropped() {
        let raw = serde_json::json!({
            "bridges": [
                {"line": "conjure 192.0.2.5:443 AAAA", "tcp_reachable": true, "composite_score": 1.0},
                {"line": "Bridge 192.0.2.9:443 B", "tcp_reachable": true, "composite_score": 0.5}
            ]
        })
        .to_string();
        let (candidates, _, skipped) = select_candidates(&raw);
        assert_eq!(skipped, 1);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].line, "Bridge 192.0.2.9:443 B");
    }

    fn candidate(line: &str, transport: &str, reachable: bool, score: f64) -> Candidate {
        Candidate {
            line: line.to_owned(),
            tcp_reachable: reachable,
            score,
            transport: transport.parse().unwrap(),
        }
    }

    // Regression (issue #257 follow-up): the fixed bridge quota must be spread
    // across transport families. Previously a reachable-first global take let
    // obfs4 (the largest family) absorb the entire quota, leaving vanilla and
    // webtunnel with zero S2+ observations and permanently empty *_tested.txt
    // projections.
    #[test]
    fn stratified_selection_gives_every_family_quota_slots() {
        let mut candidates = Vec::new();
        for index in 0..10 {
            candidates.push(candidate(
                &format!("obfs4 192.0.2.{index}:443 A"),
                "obfs4",
                true,
                1.0,
            ));
        }
        for index in 0..10 {
            candidates.push(candidate(
                &format!("vanilla 192.0.2.{index}:443 A"),
                "vanilla",
                true,
                0.9,
            ));
        }
        candidates.push(candidate(
            "webtunnel 192.0.2.200:443 A",
            "webtunnel",
            true,
            0.8,
        ));
        candidates.push(candidate(
            "webtunnel 192.0.2.201:443 B",
            "webtunnel",
            false,
            0.8,
        ));
        candidates.push(candidate(
            "snowflake 192.0.2.210:443 A",
            "snowflake",
            true,
            0.7,
        ));

        let selected = stratify_candidates(candidates, 6);
        let lines: Vec<&str> = selected.iter().map(|c| c.line.as_str()).collect();
        assert_eq!(
            lines,
            vec![
                "obfs4 192.0.2.0:443 A",
                "snowflake 192.0.2.210:443 A",
                "vanilla 192.0.2.0:443 A",
                "webtunnel 192.0.2.200:443 A",
                "obfs4 192.0.2.1:443 A",
                "vanilla 192.0.2.1:443 A",
            ]
        );
    }

    #[test]
    fn stratified_selection_within_family_is_reachable_first_then_score() {
        let candidates = vec![
            candidate("obfs4 192.0.2.2:443 C", "obfs4", false, 0.99),
            candidate("obfs4 192.0.2.1:443 B", "obfs4", true, 0.10),
            candidate("obfs4 192.0.2.0:443 A", "obfs4", true, 0.50),
        ];
        let selected = stratify_candidates(candidates, 10);
        let lines: Vec<&str> = selected.iter().map(|c| c.line.as_str()).collect();
        assert_eq!(
            lines,
            vec![
                "obfs4 192.0.2.0:443 A",
                "obfs4 192.0.2.1:443 B",
                "obfs4 192.0.2.2:443 C",
            ]
        );
    }

    #[test]
    fn stratified_selection_is_deterministic_and_quota_bounded() {
        let build = || {
            let mut candidates = Vec::new();
            for index in 0..5 {
                candidates.push(candidate(
                    &format!("obfs4 192.0.2.{index}:443 A"),
                    "obfs4",
                    true,
                    1.0,
                ));
                candidates.push(candidate(
                    &format!("vanilla 192.0.2.{index}:443 A"),
                    "vanilla",
                    false,
                    1.0,
                ));
            }
            candidates
        };
        let first = stratify_candidates(build(), 4);
        let second = stratify_candidates(build(), 4);
        let first_lines: Vec<&str> = first.iter().map(|c| c.line.as_str()).collect();
        let second_lines: Vec<&str> = second.iter().map(|c| c.line.as_str()).collect();
        assert_eq!(first_lines, second_lines);
        assert_eq!(first.len(), 4);
    }

    #[test]
    fn merge_into_dedupes_on_line_stage_observed_at() {
        let dir = std::env::temp_dir().join(format!("handshake-probe-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("pt_results.json");
        std::fs::write(&target, "[]\n").unwrap();
        let records = vec![record(
            "Bridge 192.0.2.1:443 A",
            "connected",
            "S3",
            "tor-handshake",
            12.0,
            "ok",
            None,
        )];
        merge_into(&target, &records).unwrap();
        merge_into(&target, &records).unwrap();
        let merged: Value =
            serde_json::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        assert_eq!(merged.as_array().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}

//! Advanced, fully-automated WebTunnel supply expansion (strictly additive).
//!
//! WebTunnel is the pipeline's smallest usable pool, and the earlier
//! extended-supply stage (Stage 1x, [`crate::supply_extension`] +
//! [`crate::supply_extension_v2`]) proved via live CI traces that the
//! canonical MOAT request-parameter space is already exhausted: the only
//! legitimately different MOAT payload fields BridgeDB/rdsys parses are
//! `transports` and `unblocked`, and both variants are already drawn every
//! run. The official distributor picture (rdsys, the BridgeDB successor
//! that serves bridges.torproject.org since 2024) distributes webtunnel
//! through the HTTPS web endpoint and the moat settings endpoint only.
//!
//! This module therefore automates the *remaining* legitimate growth levers
//! and makes every run's webtunnel supply status transparent:
//!
//! 1. **Bounded extra WebTunnel HTML draws** (new source label
//!    `webtunnel_html_rotation`): the two canonical
//!    `bridges.torproject.org/bridges?transport=webtunnel[&ipv6=yes]`
//!    pages are re-drawn `WEBTUNNEL_EXTRA_DRAWS` times per run (default 1,
//!    clamp `0..=4`), paced and merged through the exact existing pipeline
//!    (`merge_raw_into_history` + validation). BridgeDB rotates per-request
//!    answers, so repeated bounded draws over the pipeline's 3-hour cadence
//!    are the only remaining honest way to sample new webtunnel subsets.
//!    `0` disables the extra draws entirely.
//! 2. **Automatic canonical documentation audit** (on by default,
//!    `WEBTUNNEL_DOCS_AUDIT`): each run fetches the official Tor Project
//!    rdsys / webtunnel documentation pages and scans them for distributor
//!    mechanism tokens (moat, https, email, telegram, gettor, ...). The
//!    audit result is recorded in the report; if a *new* canonical
//!    mechanism ever appears upstream it will show up in the audit instead
//!    of being silently missed. Fetches are best-effort and never fatal.
//! 3. **Relay probe history sidecar** (`data/webtunnel_probe_history.json`,
//!    append-only, capped): every run records what the Stage 4 probe relay
//!    observed per transport and per host from `data/pt_results.json`
//!    (which itself is re-generated every run, so every webtunnel front is
//!    automatically re-probed on the 3-hour schedule — a temporarily down
//!    front is retried every run, never permanently written off after one
//!    failure). The sidecar makes the retry cadence and per-host results
//!    visible and auditable across runs.
//! 4. **Advanced diagnostics**: the job's step summary is *extended* with
//!    per-channel rows for this module (`webtunnel_html_rotation`), the
//!    webtunnel family before/after/added table, the relay per-transport
//!    totals, and the docs audit table. `data/supply_diagnostics.json` from
//!    Stage 1x is never modified.
//!
//! # Guarantees (identical to the v1/v2 supply modules)
//!
//! * Nothing here removes, disables, or weakens an existing source,
//!   scraper, parser, filter, prober, test, or safety check.
//! * Every fetched line is parsed by [`crate::scraper::parse_bridgelines_html`]
//!   (same validation and reserved-endpoint / documentation-IP gate as the
//!   core scrapers) and merged only through
//!   [`crate::scraper::merge_raw_into_history`].
//! * Request volume is bounded (`WEBTUNNEL_EXTRA_DRAWS` clamped `0..=4` of
//!   two canonical pages = at most 8 requests per run) and paced with the
//!   same jittered pause as the other supply modules. Non-2xx and
//!   unparsable responses degrade to counted zero-line results, never
//!   pipeline failures. Docs-audit fetches are best-effort.

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use serde_json::{json, Value};

use crate::scraper::{
    load_history, merge_raw_into_history, normalize_for_history, parse_bridgelines_html,
    prune_history, save_history, HttpFetch, DEFAULT_BRIDGE_DIR,
};
use crate::supply_extension::{
    count_added_lines, history_family_counts, pace_request, SourceLines,
};

/// Request timeout used by every fetch in this module (mirrors the core
/// scrapers and the v1/v2 supply modules).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// New diagnostics report written by every run (new file; never overwrites
/// an existing pipeline output).
const REPORT_FILE: &str = "data/webtunnel_supply_report.json";

/// Append-only per-run probe-history sidecar (new file too).
const PROBE_HISTORY_FILE: &str = "data/webtunnel_probe_history.json";

/// Maximum number of per-run records kept in the probe-history sidecar.
const PROBE_HISTORY_CAP: usize = 300;

/// Stable source label for this module's extra HTML draws. Deliberately
/// distinct from the Stage 1x labels (`bridgedb_html_rotation`,
/// `bridgedb_html_snowflake`) so the diagnostics table shows exactly which
/// module contributed what.
pub const SOURCE_WEBTUNNEL_HTML_ROTATION: &str = "webtunnel_html_rotation";

/// The two canonical WebTunnel pages served by bridges.torproject.org
/// (rdsys HTTPS distributor). `ip_version` mirrors the file-stem/family
/// convention used everywhere else in the pipeline.
pub const WEBTUNNEL_HTML_TARGETS: &[(&str, &str, &str)] = &[
    (
        "https://bridges.torproject.org/bridges?transport=webtunnel",
        "webtunnel",
        "ipv4",
    ),
    (
        "https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes",
        "webtunnel",
        "ipv6",
    ),
];

/// Official Tor Project documentation endpoints audited every run for
/// distributor mechanism tokens. All are public project pages; each fetch
/// is best-effort and non-fatal (a failed fetch is recorded in the audit
/// output, it never fails the pipeline).
pub const DOC_AUDIT_TARGETS: &[(&str, &str)] = &[
    (
        "rdsys-readme",
        "https://gitlab.torproject.org/tpo/anti-censorship/rdsys/-/raw/main/README.md",
    ),
    (
        "rdsys-distributor-config",
        "https://gitlab.torproject.org/tpo/anti-censorship/rdsys/-/raw/main/config/rdsys.yaml",
    ),
    (
        "webtunnel-project-readme",
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/-/raw/main/README.md",
    ),
    (
        "bridges-torproject-home",
        "https://bridges.torproject.org/",
    ),
];

/// Mechanism tokens the docs audit scans for. The known canonical
/// distribution mechanisms today are moat (builtin/settings endpoints) and
/// the HTTPS web endpoint; email and telegram exist upstream but are
/// captcha-gated / community-run and out of scope for this pipeline (same
/// constraint as `docs/SUPPLY_EXPANSION.md`).
pub const MECHANISM_TOKENS: &[&str] = &[
    "moat",
    "https",
    "email",
    "telegram",
    "gettor",
    "distributor",
    "webtunnel",
];

/// Bounded per-run tuning for this module.
///
/// * `webtunnel_draws` — extra draws of the two canonical WebTunnel pages
///   (default `1`, clamped `0..=MAX_WEBTUNNEL_DRAWS`).
/// * `docs_audit` — whether the canonical documentation audit runs
///   (default `true`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct WebtunnelAdvConfig {
    pub webtunnel_draws: usize,
    pub docs_audit: bool,
}

impl WebtunnelAdvConfig {
    pub const DEFAULT_WEBTUNNEL_DRAWS: usize = 1;
    pub const MAX_WEBTUNNEL_DRAWS: usize = 4;

    /// Read the per-run configuration from the environment.
    ///
    /// * `WEBTUNNEL_EXTRA_DRAWS` — extra draws of the canonical WebTunnel
    ///   pages (clamped to `0..=4`; `0` disables this module's fetching).
    /// * `WEBTUNNEL_DOCS_AUDIT` — `0`/`false` disables the docs audit.
    ///
    /// Unset, non-numeric, or out-of-range values fall back to the default.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            webtunnel_draws: parse_bounded(
                std::env::var("WEBTUNNEL_EXTRA_DRAWS").ok().as_deref(),
                Self::DEFAULT_WEBTUNNEL_DRAWS,
                Self::MAX_WEBTUNNEL_DRAWS,
            ),
            docs_audit: parse_bool_value(
                std::env::var("WEBTUNNEL_DOCS_AUDIT").ok().as_deref(),
                true,
            ),
        }
    }
}

/// Parse a bounded non-negative integer configuration value.
fn parse_bounded(raw: Option<&str>, default: usize, max: usize) -> usize {
    match raw {
        Some(value) => value.trim().parse::<usize>().unwrap_or(default).min(max),
        None => default,
    }
}

/// Parse a boolean configuration value: `0`/`false`/`no` (any case)
/// disables, anything else keeps `default` (so an unset var stays enabled).
fn parse_bool_value(raw: Option<&str>, default: bool) -> bool {
    match raw {
        Some(value) => {
            let value = value.trim().to_ascii_lowercase();
            !(value == "0" || value == "false" || value == "no")
        }
        None => default,
    }
}

/// Assemble the per-run draw plan: `draws` rounds over the two canonical
/// WebTunnel pages. `draws` is clamped to
/// [`WebtunnelAdvConfig::MAX_WEBTUNNEL_DRAWS`].
#[must_use]
pub fn webtunnel_html_plan(draws: usize) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut plan = Vec::new();
    for _ in 0..draws.min(WebtunnelAdvConfig::MAX_WEBTUNNEL_DRAWS) {
        plan.extend_from_slice(WEBTUNNEL_HTML_TARGETS);
    }
    plan
}

/// Fetch the extra WebTunnel HTML draws.
///
/// Requests each URL from [`webtunnel_html_plan`] with the same jittered
/// pacing as the v1/v2 supply modules and parses every response with
/// [`parse_bridgelines_html`] — the identical validation chain as the core
/// scraper. Per-URL failures are counted, logged, and skipped.
pub fn fetch_webtunnel_html(client: &dyn HttpFetch, draws: usize) -> SourceLines {
    let plan = webtunnel_html_plan(draws);
    let mut group = SourceLines {
        source: SOURCE_WEBTUNNEL_HTML_ROTATION,
        requests: 0,
        responses_ok: 0,
        lines: Vec::new(),
    };
    for (index, &(url, transport, ip_version)) in plan.iter().enumerate() {
        if index > 0 {
            pace_request();
        }
        group.requests += 1;
        match client.get(url, REQUEST_TIMEOUT) {
            Ok(resp) if (200..300).contains(&resp.status) => {
                group.responses_ok += 1;
                let parsed = parse_bridgelines_html(&resp.text);
                tracing::info!(
                    source = group.source,
                    url,
                    parsed_lines = parsed.len(),
                    "advanced WebTunnel HTML draw"
                );
                for line in parsed {
                    group
                        .lines
                        .push((line, transport.to_string(), ip_version.to_string()));
                }
            }
            Ok(resp) => {
                tracing::warn!(
                    source = group.source,
                    url,
                    status = resp.status,
                    "advanced WebTunnel HTML draw returned non-2xx"
                );
            }
            Err(err) => {
                tracing::warn!(
                    source = group.source,
                    url,
                    error = %err,
                    "advanced WebTunnel HTML draw failed"
                );
            }
        }
    }
    group
}

/// Scan a document body for known distributor mechanism tokens.
///
/// Returns the sorted list of tokens present in `text` (each occurrence
/// counted once per document). Pure string scan over official docs; used by
/// the canonical-mechanism audit.
#[must_use]
pub fn scan_mechanism_tokens(text: &str) -> Vec<String> {
    let lowered = text.to_ascii_lowercase();
    let mut found: Vec<String> = MECHANISM_TOKENS
        .iter()
        .filter(|token| lowered.contains(&token.to_ascii_lowercase()))
        .map(|token| (*token).to_string())
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Fetch and scan the official documentation endpoints.
///
/// Best-effort: every entry records `status` and the tokens found (or the
/// fetch error). A fetch failure is recorded, never fatal.
pub fn audit_canonical_docs(client: &dyn HttpFetch) -> Vec<Value> {
    let mut entries = Vec::new();
    for (label, url) in DOC_AUDIT_TARGETS {
        match client.get(url, REQUEST_TIMEOUT) {
            Ok(resp) if (200..300).contains(&resp.status) => {
                let tokens = scan_mechanism_tokens(&resp.text);
                entries.push(json!({
                    "doc": label,
                    "url": url,
                    "status": resp.status,
                    "bytes": resp.text.len(),
                    "mechanism_tokens": tokens,
                }));
                tracing::info!(
                    doc = label,
                    bytes = resp.text.len(),
                    tokens = ?tokens,
                    "canonical docs audit OK"
                );
            }
            Ok(resp) => {
                entries.push(json!({
                    "doc": label,
                    "url": url,
                    "status": resp.status,
                    "error": "non-2xx",
                }));
                tracing::warn!(doc = label, status = resp.status, "docs audit non-2xx");
            }
            Err(err) => {
                entries.push(json!({
                    "doc": label,
                    "url": url,
                    "error": err.to_string(),
                }));
                tracing::warn!(doc = label, error = %err, "docs audit fetch failed");
            }
        }
    }
    entries
}

/// Read `data/pt_results.json` (written by Stage 4) into a vector of JSON
/// entries. Missing/invalid files degrade to an empty vector.
#[must_use]
pub fn read_pt_results() -> Vec<Value> {
    match fs::read_to_string("data/pt_results.json") {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Summarise relay probe observations per transport and per host.
///
/// Each result entry is expected to carry `transport`, `success`, `host`,
/// and `port` (the schema written by probe-relay and merged by
/// `scripts/probe_relay.sh`). The summary is purely diagnostic.
#[must_use]
pub fn summarize_pt_results(results: &[Value]) -> Value {
    let mut by_transport: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
    let mut by_host: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
    for entry in results {
        let Some(transport) = entry.get("transport").and_then(Value::as_str) else {
            continue;
        };
        let Some(host) = entry.get("host").and_then(Value::as_str) else {
            continue;
        };
        let success = entry
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let transport_key = transport.to_string();
        let counter = by_transport
            .entry(transport_key.clone())
            .or_insert_with(BTreeMap::new);
        *counter.entry("attempted").or_insert(0) += 1;
        if success {
            *counter.entry("success").or_insert(0) += 1;
        }
        let host_key = format!("{transport_key}|{host}");
        let host_counter = by_host.entry(host_key).or_insert_with(BTreeMap::new);
        *host_counter.entry("attempted").or_insert(0) += 1;
        if success {
            *host_counter.entry("success").or_insert(0) += 1;
        }
    }
    json!({
        "by_transport": by_transport,
        "by_host": by_host,
        "entries": results.len(),
    })
}

/// Load the append-only probe-history sidecar (`{ "runs": [...] }`),
/// returning an empty document when the file is missing or unparsable.
#[must_use]
pub fn load_probe_history() -> Value {
    match fs::read_to_string(PROBE_HISTORY_FILE) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| json!({ "runs": [] })),
        Err(_) => json!({ "runs": [] }),
    }
}

/// Append one per-run record to the probe-history sidecar, keeping at most
/// [`PROBE_HISTORY_CAP`] records. Best-effort: failures are logged, never
/// fatal.
pub fn push_probe_history_record(record: Value) {
    let mut history = load_probe_history();
    let mut runs: Vec<Value> = match history.get_mut("runs").and_then(Value::as_array_mut) {
        Some(runs) => std::mem::take(runs),
        None => Vec::new(),
    };
    runs.push(record);
    if runs.len() > PROBE_HISTORY_CAP {
        let overflow = runs.len() - PROBE_HISTORY_CAP;
        runs.drain(..overflow);
    }
    match serde_json::to_vec_pretty(&json!({ "runs": runs })) {
        Ok(buf) => {
            if let Err(err) = fs::write(PROBE_HISTORY_FILE, buf) {
                tracing::warn!("webtunnel probe history: could not write: {err}");
            }
        }
        Err(err) => tracing::warn!("webtunnel probe history: could not serialize: {err}"),
    }
}

/// Write the per-run diagnostics report (new file, best-effort).
pub fn write_report(payload: &Value) {
    if let Err(err) = fs::create_dir_all("data") {
        tracing::warn!("webtunnel supply: could not create data directory: {err}");
        return;
    }
    match serde_json::to_vec_pretty(payload) {
        Ok(buf) => {
            if let Err(err) = fs::write(REPORT_FILE, buf) {
                tracing::warn!("webtunnel supply: could not write {REPORT_FILE}: {err}");
            }
        }
        Err(err) => tracing::warn!("webtunnel supply: could not serialize report: {err}"),
    }
}

/// Append the module's markdown section to `$GITHUB_STEP_SUMMARY` when
/// running inside GitHub Actions (best-effort; ignored elsewhere). This
/// *extends* the job's existing supply-diagnostics summary from Stage 1x
/// with a new per-channel table — it never replaces or edits that table.
pub fn emit_step_summary(
    config: &WebtunnelAdvConfig,
    html: &SourceLines,
    before: &BTreeMap<String, usize>,
    after: &BTreeMap<String, usize>,
    added: &BTreeMap<String, usize>,
    relay: &Value,
    docs_audit: &[Value],
) {
    let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let get = |map: &BTreeMap<String, usize>, family: &str| -> u64 {
        u64::try_from(map.get(family).copied().unwrap_or(0)).unwrap_or(u64::MAX)
    };
    let mut rows = String::from("### WebTunnel supply automation (advanced module, additive)\n\n");
    rows.push_str(&format!(
        "config: webtunnel html extra draws = {}, docs audit = {};\n",
        config.webtunnel_draws, config.docs_audit
    ));
    rows.push_str("new history records added by this module's draws = ");
    let module_added: usize = added.values().sum();
    rows.push_str(&format!("{module_added}\n\n"));
    rows.push_str(
        "| channel | requests | responses_ok | fetched_lines | added_records |\n\
         |---|---|---|---|---|\n",
    );
    rows.push_str(&format!(
        "| {source} | {requests} | {ok} | {fetched} | {added_records} |\n",
        source = html.source,
        requests = html.requests,
        ok = html.responses_ok,
        fetched = html.lines.len(),
        added_records = added.values().sum::<usize>(),
    ));
    rows.push_str("\n| webtunnel family | before | after | added |\n|---|---|---|---|\n");
    for family in ["webtunnel", "webtunnel_ipv6"] {
        rows.push_str(&format!(
            "| {family} | {b} | {a} | {d} |\n",
            b = get(before, family),
            a = get(after, family),
            d = get(added, family),
        ));
    }
    if let Some(by_transport) = relay.get("by_transport").and_then(Value::as_object) {
        if !by_transport.is_empty() {
            rows.push_str("\n| relay transport | attempted | success |\n|---|---|---|\n");
            for (transport, counters) in by_transport {
                let attempted = counters
                    .get("attempted")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let success = counters.get("success").and_then(Value::as_u64).unwrap_or(0);
                rows.push_str(&format!("| {transport} | {attempted} | {success} |\n"));
            }
        }
    }
    if !docs_audit.is_empty() {
        rows.push_str("\n| docs audit | status | mechanism tokens |\n|---|---|---|\n");
        for entry in docs_audit {
            let doc = entry.get("doc").and_then(Value::as_str).unwrap_or("?");
            let status = entry.get("status").and_then(Value::as_u64).unwrap_or(0);
            let error = entry.get("error").and_then(Value::as_str).unwrap_or("");
            let tokens = entry
                .get("mechanism_tokens")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_else(|| error.to_string());
            rows.push_str(&format!("| {doc} | {status} | {tokens} |\n"));
        }
    }
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(summary_path)
    {
        use std::io::Write;
        let _ = file.write_all(rows.as_bytes());
    }
}

/// Emit `::notice` workflow annotations for this module's headline numbers
/// so they are visible on the run page without log access.
pub fn emit_workflow_notices(
    after: &BTreeMap<String, usize>,
    html: &SourceLines,
    added_total: usize,
) {
    for family in ["webtunnel", "webtunnel_ipv6"] {
        let count = after.get(family).copied().unwrap_or(0);
        println!("::notice title=WEBTUNNEL_SUPPLY::{family}::history_count_after={count}");
    }
    println!(
        "::notice title=WEBTUNNEL_SUPPLY::webtunnel_html_rotation::fetched_lines={} added_records={}",
        html.lines.len(),
        added_total
    );
}

/// Core driver shared by the binary: load history, optionally fetch the
/// extra WebTunnel draws and the docs audit, merge through the canonical
/// pipeline, and emit all diagnostics.
///
/// `network_available` mirrors the binary's `#[cfg(feature = "network")]`
/// gate so the offline path (all counters zero) stays testable.
pub fn run_advanced_supply(
    network_available: bool,
    client: Option<&dyn HttpFetch>,
    generated_at: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = WebtunnelAdvConfig::from_env();

    let history_path = std::path::Path::new(DEFAULT_BRIDGE_DIR).join("bridge_history.json");
    let mut history = load_history(&history_path)?;
    let before = history_family_counts(&history);

    let (html, docs_audit) = if network_available {
        let client = client.expect("network_available implies a client");
        let html = fetch_webtunnel_html(client, config.webtunnel_draws);
        let docs_audit = if config.docs_audit {
            audit_canonical_docs(client)
        } else {
            Vec::new()
        };
        (html, docs_audit)
    } else {
        let html = SourceLines {
            source: SOURCE_WEBTUNNEL_HTML_ROTATION,
            requests: 0,
            responses_ok: 0,
            lines: Vec::new(),
        };
        (html, Vec::new())
    };

    let added = count_added_lines(&history, &html.lines);
    let added_total: usize = added.values().sum();

    // Per-line audit trace (additive diagnostics), mirroring the
    // supply_extender trace so fetched/new is auditable line-by-line.
    for (line, transport, ip_version) in &html.lines {
        let key = normalize_for_history(line, transport);
        let known = history
            .as_object()
            .is_some_and(|object| object.contains_key(&key));
        println!(
            "webtunnel_supply_advanced trace: source={} transport={} ip_version={} known={} line={}",
            html.source, transport, ip_version, known, line,
        );
    }

    // Merge through the canonical history writer (same validation,
    // deduplication, and last_seen refresh as every other source).
    let pruned = if html.lines.is_empty() {
        0
    } else {
        merge_raw_into_history(&mut history, &html.lines)?;
        prune_history(&mut history)?
    };
    save_history(&history, &history_path)?;
    let after = history_family_counts(&history);

    let relay = summarize_pt_results(&read_pt_results());

    let payload = json!({
        "generated_at": generated_at,
        "config": {
            "webtunnel_html_draws": config.webtunnel_draws,
            "docs_audit": config.docs_audit,
        },
        "sources": [{
            "source": html.source,
            "requests": html.requests,
            "responses_ok": html.responses_ok,
            "fetched_lines": html.lines.len(),
            "added_records": added_total,
        }],
        "webtunnel_family_counts": {
            "before": family_counts_to_json(&before, &["webtunnel", "webtunnel_ipv6"]),
            "after": family_counts_to_json(&after, &["webtunnel", "webtunnel_ipv6"]),
            "added_by_webtunnel_source": family_counts_to_json(&added, &["webtunnel", "webtunnel_ipv6"]),
        },
        "relay_observations": relay,
        "docs_audit": docs_audit,
    });

    write_report(&payload);
    let generated_at_value = payload.get("generated_at").cloned().unwrap_or(Value::Null);
    let config_value = payload.get("config").cloned().unwrap_or(Value::Null);
    let relay_transport_value = relay.get("by_transport").cloned().unwrap_or(Value::Null);
    push_probe_history_record(json!({
        "generated_at": generated_at_value,
        "config": config_value,
        "webtunnel_html_fetched_lines": html.lines.len(),
        "webtunnel_html_added_records": added_total,
        "relay_per_transport": relay_transport_value,
    }));
    emit_step_summary(&config, &html, &before, &after, &added, &relay, &docs_audit);
    emit_workflow_notices(&after, &html, added_total);

    println!(
        "webtunnel_supply_advanced: config draws={} docs_audit={} fetched_lines={} new_history_records={} pruned={}",
        config.webtunnel_draws,
        config.docs_audit,
        html.lines.len(),
        added_total,
        pruned,
    );
    Ok(())
}

/// Render a counts map as a JSON object, restricted to `families`.
fn family_counts_to_json(counts: &BTreeMap<String, usize>, families: &[&str]) -> Value {
    let mut map = serde_json::Map::new();
    for family in families {
        if let Some(count) = counts.get(*family) {
            map.insert((*family).to_string(), json!(count));
        }
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bounded_clamps_and_defaults() {
        assert_eq!(parse_bounded(None, 1, 4), 1);
        assert_eq!(parse_bounded(Some(""), 1, 4), 1);
        assert_eq!(parse_bounded(Some("0"), 1, 4), 0);
        assert_eq!(parse_bounded(Some("99"), 1, 4), 4);
        assert_eq!(parse_bounded(Some("abc"), 1, 4), 1);
    }

    #[test]
    fn parse_bool_value_disables_on_false_like() {
        assert!(parse_bool_value(None, true));
        assert!(parse_bool_value(Some("1"), true));
        assert!(!parse_bool_value(Some("0"), true));
        assert!(!parse_bool_value(Some("false"), true));
        assert!(!parse_bool_value(Some("no"), true));
    }

    #[test]
    fn webtunnel_html_plan_is_bounded_draws_of_two_pages() {
        let plan = webtunnel_html_plan(2);
        assert_eq!(plan.len(), 2 * WEBTUNNEL_HTML_TARGETS.len());
        let zero = webtunnel_html_plan(0);
        assert!(zero.is_empty());
        let huge = webtunnel_html_plan(WebtunnelAdvConfig::MAX_WEBTUNNEL_DRAWS + 10);
        assert_eq!(
            huge.len(),
            WebtunnelAdvConfig::MAX_WEBTUNNEL_DRAWS * WEBTUNNEL_HTML_TARGETS.len()
        );
    }

    #[test]
    fn scan_mechanism_tokens_finds_known_tokens_only() {
        let text = "rdsys distributors: moat, https and email. webtunnel resources.";
        let found = scan_mechanism_tokens(text);
        assert!(found.contains(&"moat".to_string()));
        assert!(found.contains(&"https".to_string()));
        assert!(found.contains(&"webtunnel".to_string()));
        assert!(!found.contains(&"gettor".to_string()));
        let none = scan_mechanism_tokens("no tokens here");
        assert!(none.is_empty());
    }

    #[test]
    fn summarize_pt_results_groups_by_transport_and_host() {
        let results = vec![
            json!({"transport": "webtunnel", "host": "cdn-a.example", "port": 443, "success": true}),
            json!({"transport": "webtunnel", "host": "cdn-a.example", "port": 443, "success": false}),
            json!({"transport": "webtunnel", "host": "cdn-b.example", "port": 443, "success": true}),
            json!({"transport": "snowflake", "host": "sf.example", "port": 443, "success": false}),
        ];
        let summary = summarize_pt_results(&results);
        assert_eq!(summary.get("entries").and_then(Value::as_u64), Some(4));
        let wt = summary.pointer("/by_transport/webtunnel").unwrap();
        assert_eq!(wt.get("attempted").and_then(Value::as_u64), Some(3));
        assert_eq!(wt.get("success").and_then(Value::as_u64), Some(2));
        let host_a = summary.pointer("/by_host/webtunnel|cdn-a.example").unwrap();
        assert_eq!(host_a.get("attempted").and_then(Value::as_u64), Some(2));
    }

    #[test]
    fn family_counts_to_json_restricts_families() {
        let mut counts = BTreeMap::new();
        counts.insert("webtunnel".to_string(), 4usize);
        counts.insert("obfs4".to_string(), 10usize);
        let value = family_counts_to_json(&counts, &["webtunnel"]);
        assert_eq!(value.pointer("/webtunnel").and_then(Value::as_u64), Some(4));
        assert!(value.get("obfs4").is_none());
    }
}

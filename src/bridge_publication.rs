//! Deterministic publication of the `bridge/` distribution contract.
//!
//! This module is deliberately separate from collection and probing.  A
//! collector may fail to reach an optional upstream, and a probe may report no
//! reachable endpoints from a particular runner, but neither condition should
//! leave consumers with a half-written bridge directory or a Telegram archive
//! that differs from the repository payload.
//!
//! The publisher therefore has four responsibilities:
//!
//! 1. rebuild every public text projection from the canonical history and the
//!    latest probe report;
//! 2. validate the JSON inputs and the complete output inventory;
//! 3. build one deterministic ZIP payload used both for repository consumers
//!    and for Telegram delivery; and
//! 4. verify that every archive member is byte-identical to its `bridge/`
//!    counterpart before reporting success.
//!
//! It never represents a runner-side TCP observation as proof of reachability
//! from Iran.  `iran_likely_working_*` is an advisory ranking name retained for
//! compatibility with existing clients; the README and manifest describe the
//! evidence scope explicitly.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};
use zip::write::FileOptions;

use crate::static_bridges;

/// Every file promised to downstream bridge consumers.
///
/// Keep this inventory in one Rust constant rather than duplicating it in a
/// shell script, workflow, and Telegram uploader.  `tor_bridges.zip` cannot
/// contain itself; all other entries are embedded under `bridge/` in the ZIP.
pub const REQUIRED_FILES: &[&str] = &[
    "bridge_history.json",
    "bridge_list_for_testing.json",
    "bridge_scores.json",
    "conjure.txt",
    "conjure_72h.txt",
    "conjure_tested.txt",
    "iran_blocked.txt",
    "iran_likely_working_all.txt",
    "iran_likely_working_nin.txt",
    "iran_likely_working_obfs4.txt",
    "iran_likely_working_snowflake.txt",
    "iran_likely_working_vanilla.txt",
    "iran_likely_working_webtunnel.txt",
    "iran_results.json",
    "meek-azure.txt",
    "meek-azure_72h.txt",
    "meek-azure_tested.txt",
    "meek_lite.txt",
    "meek_lite_72h.txt",
    "meek_lite_72h_ipv6.txt",
    "meek_lite_ipv6.txt",
    "meek_lite_ipv6_tested.txt",
    "meek_lite_tested.txt",
    "obfs4.txt",
    "obfs4_72h.txt",
    "obfs4_72h_ipv6.txt",
    "obfs4_ipv6.txt",
    "obfs4_ipv6_72h.txt",
    "obfs4_ipv6_tested.txt",
    "obfs4_tested.txt",
    "snowflake.txt",
    "snowflake_72h.txt",
    "snowflake_72h_ipv6.txt",
    "snowflake_ipv6.txt",
    "snowflake_ipv6_tested.txt",
    "snowflake_tested.txt",
    "telegram_manifest.json",
    "tested_global_obfs4.txt",
    "tested_global_vanilla.txt",
    "tested_global_webtunnel.txt",
    "tor_bridges.zip",
    "vanilla.txt",
    "vanilla_72h.txt",
    "vanilla_72h_ipv6.txt",
    "vanilla_ipv6.txt",
    "vanilla_ipv6_72h.txt",
    "vanilla_ipv6_tested.txt",
    "vanilla_tested.txt",
    "webtunnel.txt",
    "webtunnel_72h.txt",
    "webtunnel_72h_ipv6.txt",
    "webtunnel_ipv6.txt",
    "webtunnel_ipv6_72h.txt",
    "webtunnel_ipv6_tested.txt",
    "webtunnel_tested.txt",
];

const JSON_FILES: &[&str] = &[
    "bridge_history.json",
    "bridge_list_for_testing.json",
    "bridge_scores.json",
    "iran_results.json",
    "telegram_manifest.json",
];

// These are the Iran-specific projections retained in the public contract.
// meek-lite remains fully published in its own transport family but has no
// historical `iran_likely_working_meek_lite.txt` consumer file.
const IRAN_TRANSPORTS: &[&str] = &["obfs4", "webtunnel", "vanilla", "snowflake"];
const GLOBAL_TRANSPORTS: &[&str] = &["obfs4", "webtunnel", "vanilla"];

/// Inputs to a single publish operation.
#[derive(Debug, Clone)]
pub struct PublishOptions {
    /// Directory containing the public bridge data.
    pub bridge_dir: PathBuf,
    /// README rendered from the same inventory and counts as the ZIP.
    pub readme_path: PathBuf,
    /// Raw GitHub URL prefix, without a trailing slash.
    pub repo_url: String,
    /// Freshness window used by `*_72h*` projections.
    pub recent_hours: i64,
}

impl Default for PublishOptions {
    fn default() -> Self {
        Self {
            bridge_dir: PathBuf::from("bridge"),
            readme_path: PathBuf::from("README.md"),
            repo_url:
                "https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main"
                    .to_string(),
            recent_hours: 72,
        }
    }
}

/// Useful publication facts for CLI output, workflow summaries, and tests.
#[derive(Debug, Clone)]
pub struct PublicationReport {
    pub generated_at: DateTime<Utc>,
    pub history_records: usize,
    pub probe_records: usize,
    pub file_counts: BTreeMap<String, usize>,
    pub archive_path: PathBuf,
    pub archive_sha256: String,
    pub archive_entries: usize,
}

#[derive(Debug, Clone)]
struct Candidate {
    raw: String,
    transport: String,
    ipv6: bool,
    fresh: bool,
    tested: bool,
    score: f64,
}

#[derive(Debug, Clone)]
struct ProbeRecord {
    line: String,
    transport: String,
    tcp_reachable: bool,
    transport_capable: bool,
    iran_status: String,
    score: f64,
}

#[derive(Serialize)]
struct ManifestFile {
    name: String,
    raw_url: String,
    size_bytes: u64,
    non_empty_lines: Option<usize>,
    sha256: String,
}

#[derive(Serialize)]
struct ArchiveDescription {
    name: String,
    layout: String,
    entry_count: usize,
    excludes_self: bool,
    verification: String,
}

#[derive(Serialize)]
struct Manifest {
    schema_version: u8,
    generated_at: String,
    producer: String,
    evidence_scope: String,
    bridge_directory: String,
    required_files: Vec<String>,
    required_files_present: bool,
    missing_required_files: Vec<String>,
    /// Hashes for non-self-referential payload files.  The manifest and ZIP
    /// intentionally do not hash themselves, avoiding stale recursive hashes.
    files: Vec<ManifestFile>,
    archive: ArchiveDescription,
    summary: BTreeMap<String, usize>,
}

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

fn bridge_key(line: &str) -> String {
    line.trim()
        .strip_prefix("Bridge ")
        .unwrap_or(line.trim())
        .to_ascii_lowercase()
}

fn normalise_transport(raw: &str, declared: Option<&str>) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    let first = lower.split_whitespace().next().unwrap_or_default();
    // Prefer an explicit first-token transport: URL-bearing meek lines would
    // otherwise be misclassified as WebTunnel by generic URL detection.
    match first {
        "obfs4" | "webtunnel" | "vanilla" | "snowflake" | "meek_lite" | "meek-lite"
        | "meek-azure" | "conjure" => {
            return if first == "meek-lite" {
                "meek_lite".to_string()
            } else {
                first.to_string()
            };
        }
        _ => {}
    }

    let declared = declared.unwrap_or_default().trim().to_ascii_lowercase();
    if !declared.is_empty() {
        return match declared.as_str() {
            "meek-lite" => "meek_lite".to_string(),
            value => value.to_string(),
        };
    }
    if lower.contains("snowflake") {
        "snowflake".to_string()
    } else if lower.contains("webtunnel") {
        "webtunnel".to_string()
    } else if lower.contains("obfs4") {
        "obfs4".to_string()
    } else if lower.contains("meek") {
        "meek_lite".to_string()
    } else {
        "vanilla".to_string()
    }
}

fn record_is_ipv6(record: &Map<String, Value>, raw: &str) -> bool {
    if record.get("ip_version").and_then(Value::as_str) == Some("ipv6") {
        return true;
    }
    // Tor bridge IPv6 endpoints use the bracketed `[host]:port` syntax.
    raw.contains('[') && raw.contains("]:")
}

fn record_is_fresh(record: &Map<String, Value>, cutoff: DateTime<Utc>) -> bool {
    // `last_seen` means this bridge was observed in the current window.  It is
    // more useful than `first_seen` for a live collector, while malformed
    // timestamps are conservatively not labelled fresh.
    for field in ["last_seen", "first_seen"] {
        if let Some(value) = record.get(field).and_then(Value::as_str) {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
                return parsed.with_timezone(&Utc) >= cutoff;
            }
        }
    }
    false
}

fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let body = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&body)?)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid(format!("output has no valid file name: {}", path.display())))?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn write_json_atomic(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut body = serde_json::to_string_pretty(value)?;
    body.push('\n');
    write_atomic(path, body.as_bytes())
}

fn write_lines(
    path: &Path,
    lines: impl IntoIterator<Item = String>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let clean: BTreeSet<String> = lines
        .into_iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    let mut body = clean.iter().cloned().collect::<Vec<_>>().join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    write_atomic(path, body.as_bytes())?;
    Ok(clean.len())
}

fn extract_probe_records(root: &Value) -> Result<Vec<ProbeRecord>, Box<dyn std::error::Error>> {
    let records = root
        .get("bridges")
        .and_then(Value::as_array)
        .or_else(|| root.as_array())
        .ok_or_else(|| {
            invalid("iran_results.json must be an object with a bridges array or a JSON array")
        })?;

    let mut result = Vec::with_capacity(records.len());
    for record in records {
        let Some(object) = record.as_object() else {
            continue;
        };
        let line = object
            .get("line")
            .or_else(|| object.get("bridge"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        if line.is_empty() {
            continue;
        }
        let status = object
            .get("iran_status")
            .and_then(Value::as_str)
            .unwrap_or("iran_unknown")
            .to_string();
        let probe_status = object
            .get("probe_status")
            .or_else(|| object.get("status"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let tcp_reachable = object
            .get("tcp_reachable")
            .and_then(Value::as_bool)
            .unwrap_or(matches!(probe_status, "reachable" | "quic_reachable"));
        let transport_capable = object
            .get("transport_capable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let transport = normalise_transport(&line, object.get("transport").and_then(Value::as_str));
        let score = object
            .get("composite_score")
            .or_else(|| object.get("score"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        result.push(ProbeRecord {
            line,
            transport,
            tcp_reachable,
            transport_capable,
            iran_status: status,
            score,
        });
    }
    Ok(result)
}

fn candidates_from_history(
    history: &Value,
    probes: &[ProbeRecord],
    cutoff: DateTime<Utc>,
) -> Result<Vec<Candidate>, Box<dyn std::error::Error>> {
    let object = history
        .as_object()
        .ok_or_else(|| invalid("bridge_history.json must be a JSON object"))?;
    let probe_by_line: BTreeMap<String, &ProbeRecord> = probes
        .iter()
        .map(|probe| (bridge_key(&probe.line), probe))
        .collect();
    let mut candidates = Vec::with_capacity(object.len());

    for (key, value) in object {
        let Some(record) = value.as_object() else {
            continue;
        };
        let raw = record
            .get("raw")
            .and_then(Value::as_str)
            .unwrap_or(key)
            .trim()
            .to_string();
        if raw.is_empty() {
            continue;
        }
        let probe = probe_by_line.get(&bridge_key(&raw)).copied();
        // Probe evidence recorded in history may use either the legacy
        // single-record `test_pass` field (history.rs schema) or the live
        // collector's per-record observation fields written by
        // tor_collector/storage.rs: `tcp_reachable` (the latest protocol
        // probe result, including front-domain TLS/WebSocket checks) and the
        // additive `probe_successes` counter. URL-only WebTunnel lines have
        // no raw TCP endpoint and are never probed by the Go iran_tester, so
        // without honouring these history fields their `*_tested.txt`
        // projections would stay empty even though the collector recorded
        // successful front-domain probes.
        let legacy_test_pass = record
            .get("test_pass")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let history_tcp_ok = record
            .get("tcp_reachable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let history_probe_successes = record
            .get("probe_successes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let history_test = legacy_test_pass || history_tcp_ok || history_probe_successes > 0;
        let tested = probe
            .map(|entry| entry.tcp_reachable || entry.transport_capable)
            .unwrap_or(history_test);
        let score = probe
            .map(|entry| entry.score)
            .or_else(|| record.get("score").and_then(Value::as_f64))
            .unwrap_or(0.0);
        candidates.push(Candidate {
            transport: normalise_transport(&raw, record.get("transport").and_then(Value::as_str)),
            ipv6: record_is_ipv6(record, &raw),
            fresh: record_is_fresh(record, cutoff),
            raw,
            tested,
            score,
        });
    }
    Ok(candidates)
}

fn ensure_testing_list(
    path: &Path,
    candidates: &[Candidate],
) -> Result<usize, Box<dyn std::error::Error>> {
    let expected: BTreeSet<String> = candidates
        .iter()
        .map(|candidate| candidate.raw.clone())
        .collect();
    let existing = if path.is_file() {
        read_json(path).ok().and_then(|value| {
            value.as_array().map(|array| {
                array
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect::<BTreeSet<_>>()
            })
        })
    } else {
        None
    };

    // Preserve adaptive-selector ordering when the existing list is complete.
    if existing.as_ref() == Some(&expected) {
        return Ok(expected.len());
    }
    let values: Vec<Value> = expected.into_iter().map(Value::String).collect();
    write_json_atomic(path, &Value::Array(values))?;
    Ok(candidates.len())
}

fn write_scores(path: &Path, candidates: &[Candidate]) -> Result<(), Box<dyn std::error::Error>> {
    let scores: Map<String, Value> = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.raw.clone(),
                json!({
                    "score": candidate.score,
                    "transport": candidate.transport,
                }),
            )
        })
        .collect();
    write_json_atomic(path, &Value::Object(scores))
}

fn record_publication_fallback(
    bridge_dir: &Path,
    file_name: &str,
    transport: &str,
    line_count: usize,
    reason: &str,
) {
    let root = bridge_dir.parent().unwrap_or_else(|| Path::new("."));
    let path = root.join("data/failsafe_activations.json");
    let mut document = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({"activations": []}));
    let Some(object) = document.as_object_mut() else {
        return;
    };
    let list = object
        .entry("activations")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(items) = list.as_array_mut() {
        items.push(json!({
            "timestamp": Utc::now().to_rfc3339(),
            "file": file_name,
            "transport": transport,
            "lines": line_count,
            "reason": reason,
            "producer": "bridge_publication",
        }));
        if items.len() > 500 {
            let drop_count = items.len() - 500;
            items.drain(0..drop_count);
        }
    }
    object.insert(
        "generated_at".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_ok() {
            if let Ok(bytes) = serde_json::to_vec_pretty(&document) {
                let _ = fs::write(&path, bytes);
            }
        }
    }
}

fn family_lines(
    candidates: &[Candidate],
    transport: &str,
    ipv6: bool,
    fresh: bool,
    tested: bool,
) -> Vec<String> {
    candidates
        .iter()
        .filter(|candidate| candidate.transport == transport)
        .filter(|candidate| candidate.ipv6 == ipv6)
        .filter(|candidate| !fresh || candidate.fresh)
        .filter(|candidate| !tested || candidate.tested)
        .map(|candidate| candidate.raw.clone())
        .collect()
}

fn write_transport_family(
    bridge_dir: &Path,
    candidates: &[Candidate],
    transport: &str,
    stem: &str,
    with_ipv6: bool,
    counts: &mut BTreeMap<String, usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    // When live collection produces no candidates, use compiled-in static
    // lines only when they contain a valid client endpoint. WebTunnel's
    // bundled metadata is URL-only, so its empty projections remain empty
    // until a source supplies a literal IP:PORT or [IPv6]:PORT.
    let fallback = || -> Vec<String> {
        static_bridges::fallback_lines(transport)
            .into_iter()
            .map(str::to_string)
            .collect()
    };

    let standard = [
        (format!("{stem}.txt"), false, false, false),
        (format!("{stem}_72h.txt"), false, true, false),
        (format!("{stem}_tested.txt"), false, false, true),
    ];
    for (name, ipv6, fresh, tested) in standard {
        let mut lines = family_lines(candidates, transport, ipv6, fresh, tested);
        if lines.is_empty() {
            let fallback_lines = fallback();
            record_publication_fallback(
                bridge_dir,
                &name,
                transport,
                fallback_lines.len(),
                "empty_transport_projection",
            );
            lines = fallback_lines;
        }
        let count = write_lines(&bridge_dir.join(&name), lines)?;
        counts.insert(name, count);
    }

    if with_ipv6 {
        let ipv6_outputs = [
            (format!("{stem}_ipv6.txt"), false, false),
            (format!("{stem}_72h_ipv6.txt"), true, false),
            (format!("{stem}_ipv6_tested.txt"), false, true),
        ];
        for (name, fresh, tested) in ipv6_outputs {
            let mut lines = family_lines(candidates, transport, true, fresh, tested);
            if lines.is_empty() {
                let fallback_lines = fallback();
                record_publication_fallback(
                    bridge_dir,
                    &name,
                    transport,
                    fallback_lines.len(),
                    "empty_transport_ipv6_projection",
                );
                lines = fallback_lines;
            }
            let count = write_lines(&bridge_dir.join(&name), lines)?;
            counts.insert(name, count);
        }

        // Older clients use this reversed spelling.  Keep it byte-identical
        // to the canonical *_72h_ipv6 form rather than dropping compatibility.
        if matches!(stem, "obfs4" | "vanilla" | "webtunnel") {
            let alias = format!("{stem}_ipv6_72h.txt");
            let mut lines = family_lines(candidates, transport, true, true, false);
            if lines.is_empty() {
                let fallback_lines = fallback();
                record_publication_fallback(
                    bridge_dir,
                    &alias,
                    transport,
                    fallback_lines.len(),
                    "empty_transport_ipv6_alias",
                );
                lines = fallback_lines;
            }
            let count = write_lines(&bridge_dir.join(&alias), lines)?;
            counts.insert(alias, count);
        }
    }
    Ok(())
}

fn is_likely_working(probe: &ProbeRecord) -> bool {
    matches!(
        probe.iran_status.as_str(),
        "iran_likely_working" | "iran_unknown"
    ) && (probe.tcp_reachable || probe.transport_capable)
}

fn is_blocked(probe: &ProbeRecord) -> bool {
    matches!(
        probe.iran_status.as_str(),
        "iran_likely_blocked" | "iran_frequently_blocked" | "iran_asn_blocked"
    )
}

fn write_iran_projections(
    bridge_dir: &Path,
    candidates: &[Candidate],
    probes: &[ProbeRecord],
    counts: &mut BTreeMap<String, usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidate_by_line: BTreeMap<String, &Candidate> = candidates
        .iter()
        .map(|candidate| (bridge_key(&candidate.raw), candidate))
        .collect();
    let mut working: BTreeMap<String, Vec<(f64, String)>> = IRAN_TRANSPORTS
        .iter()
        .map(|transport| ((*transport).to_string(), Vec::new()))
        .collect();
    let mut global: BTreeMap<String, Vec<(f64, String)>> = GLOBAL_TRANSPORTS
        .iter()
        .map(|transport| ((*transport).to_string(), Vec::new()))
        .collect();
    let mut blocked = Vec::new();

    for probe in probes {
        let candidate = candidate_by_line.get(&bridge_key(&probe.line)).copied();
        let transport = candidate
            .map(|entry| entry.transport.clone())
            .unwrap_or_else(|| probe.transport.clone());
        let score = if probe.score != 0.0 {
            probe.score
        } else {
            candidate.map(|entry| entry.score).unwrap_or(0.0)
        };
        if is_likely_working(probe) {
            if let Some(lines) = working.get_mut(&transport) {
                lines.push((score, probe.line.clone()));
            }
        }
        if probe.tcp_reachable {
            if let Some(lines) = global.get_mut(&transport) {
                lines.push((score, probe.line.clone()));
            }
        }
        if is_blocked(probe) {
            blocked.push(probe.line.clone());
        }
    }

    let mut all_working = Vec::new();
    let mut nin = Vec::new();
    for transport in IRAN_TRANSPORTS {
        let mut entries = working.remove(*transport).unwrap_or_default();
        // Score first, then line; the text writer does a final deterministic
        // dedup/sort so consumers never receive duplicate bridge lines.
        entries.sort_by(|left, right| {
            right
                .0
                .total_cmp(&left.0)
                .then_with(|| left.1.cmp(&right.1))
        });
        let mut lines: Vec<String> = entries.into_iter().map(|(_, line)| line).collect();
        // With no probe evidence, use a compiled-in fallback only when it is
        // a complete client line. URL-only WebTunnel metadata is deliberately
        // not emitted as a bridge and therefore remains empty here.
        if lines.is_empty() {
            let fallback_lines = static_bridges::fallback_lines(transport)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>();
            record_publication_fallback(
                bridge_dir,
                &format!("iran_likely_working_{transport}.txt"),
                transport,
                fallback_lines.len(),
                "empty_iran_working_projection",
            );
            lines = fallback_lines;
        }
        if matches!(*transport, "snowflake" | "webtunnel" | "meek_lite") {
            nin.extend(lines.iter().cloned());
        }
        all_working.extend(lines.iter().cloned());
        let name = format!("iran_likely_working_{transport}.txt");
        let count = write_lines(&bridge_dir.join(&name), lines)?;
        counts.insert(name, count);
    }

    // If no NIN-appropriate transport has evidence in this run, provide the
    // working set rather than manufacturing a special NIN claim. If even the
    // working set is empty, use the NIN-appropriate static fallback.
    if nin.is_empty() {
        nin.extend(all_working.iter().cloned());
    }
    if nin.is_empty() {
        nin.extend(
            static_bridges::fallback_lines("snowflake")
                .into_iter()
                .chain(static_bridges::fallback_lines("webtunnel"))
                .map(str::to_string),
        );
        record_publication_fallback(
            bridge_dir,
            "iran_likely_working_nin.txt",
            "aggregate",
            nin.len(),
            "no_nin_evidence",
        );
    }
    if all_working.is_empty() {
        all_working = static_bridges::fallback_all()
            .into_iter()
            .map(str::to_string)
            .collect();
        record_publication_fallback(
            bridge_dir,
            "iran_likely_working_all.txt",
            "aggregate",
            all_working.len(),
            "no_iran_working_evidence",
        );
    }
    let all_count = write_lines(&bridge_dir.join("iran_likely_working_all.txt"), all_working)?;
    counts.insert("iran_likely_working_all.txt".to_string(), all_count);
    let nin_count = write_lines(&bridge_dir.join("iran_likely_working_nin.txt"), nin)?;
    counts.insert("iran_likely_working_nin.txt".to_string(), nin_count);
    let blocked_count = write_lines(&bridge_dir.join("iran_blocked.txt"), blocked)?;
    counts.insert("iran_blocked.txt".to_string(), blocked_count);

    for transport in GLOBAL_TRANSPORTS {
        let mut entries = global.remove(*transport).unwrap_or_default();
        entries.sort_by(|left, right| {
            right
                .0
                .total_cmp(&left.0)
                .then_with(|| left.1.cmp(&right.1))
        });
        let mut lines: Vec<String> = entries.into_iter().map(|(_, line)| line).collect();
        // Apply the same validated-fallback policy to global tested
        // projections; URL-only WebTunnel metadata is not emitted.
        if lines.is_empty() {
            let fallback_lines = static_bridges::fallback_lines(transport)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>();
            record_publication_fallback(
                bridge_dir,
                &format!("tested_global_{transport}.txt"),
                transport,
                fallback_lines.len(),
                "empty_global_tested_projection",
            );
            lines = fallback_lines;
        }
        let name = format!("tested_global_{transport}.txt");
        let count = write_lines(&bridge_dir.join(&name), lines)?;
        counts.insert(name, count);
    }
    Ok(())
}

fn required_missing(bridge_dir: &Path) -> Vec<String> {
    REQUIRED_FILES
        .iter()
        .filter(|name| !bridge_dir.join(name).is_file())
        .map(|name| (*name).to_string())
        .collect()
}

fn count_non_empty_lines(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|body| body.lines().filter(|line| !line.trim().is_empty()).count())
        .unwrap_or(0)
}

fn sha256_bytes(data: &[u8]) -> String {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Kept local so publication integrity does not depend on a system binary
    // or a new cryptographic dependency in this already pinned workspace.
    let constants: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut padded = data.to_vec();
    let bit_len = (padded.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut hash = H0;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).take(16).enumerate() {
            words[index] =
                u32::from_be_bytes(bytes.try_into().expect("SHA-256 word has four bytes"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        );
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary_one = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(constants[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary_two = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary_one);
            d = c;
            c = b;
            b = a;
            a = temporary_one.wrapping_add(temporary_two);
        }
        for (slot, value) in hash.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    hash.iter().map(|word| format!("{word:08x}")).collect()
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sha256_bytes(&fs::read(path)?))
}

fn payload_files() -> Vec<&'static str> {
    REQUIRED_FILES
        .iter()
        .copied()
        .filter(|name| *name != "tor_bridges.zip" && *name != "telegram_manifest.json")
        .collect()
}

fn write_manifest(
    options: &PublishOptions,
    generated_at: DateTime<Utc>,
    counts: &BTreeMap<String, usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bridge_dir = &options.bridge_dir;
    let missing_before_manifest: Vec<String> = REQUIRED_FILES
        .iter()
        .filter(|name| **name != "telegram_manifest.json" && **name != "tor_bridges.zip")
        .filter(|name| !bridge_dir.join(name).is_file())
        .map(|name| (*name).to_string())
        .collect();
    if !missing_before_manifest.is_empty() {
        return Err(invalid(format!(
            "cannot publish incomplete bridge inventory: {}",
            missing_before_manifest.join(", ")
        )));
    }

    let mut files: Vec<ManifestFile> = payload_files()
        .into_iter()
        .map(|name| {
            let path = bridge_dir.join(name);
            Ok(ManifestFile {
                name: name.to_string(),
                raw_url: format!("{}/bridge/{name}", options.repo_url.trim_end_matches('/')),
                size_bytes: path.metadata()?.len(),
                non_empty_lines: name.ends_with(".txt").then(|| count_non_empty_lines(&path)),
                sha256: sha256_file(&path)?,
            })
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;
    files.sort_by(|left, right| left.name.cmp(&right.name));

    let archive_entries = payload_files().len() + 1; // + telegram_manifest.json
    let manifest = Manifest {
        schema_version: 2,
        generated_at: generated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        producer: "torshield-ir-rust-publication-v2".to_string(),
        evidence_scope: "TCP observations are made from the CI runner. Iran labels are advisory rankings derived from recorded evidence and transport capability; they are not a guarantee of reachability from Iran."
            .to_string(),
        bridge_directory: bridge_dir.display().to_string(),
        required_files: REQUIRED_FILES.iter().map(|name| (*name).to_string()).collect(),
        required_files_present: true,
        missing_required_files: Vec::new(),
        files,
        archive: ArchiveDescription {
            name: "tor_bridges.zip".to_string(),
            layout: "bridge/<filename>".to_string(),
            entry_count: archive_entries,
            excludes_self: true,
            verification: "Each non-self-referential payload file is SHA-256 recorded above; the publisher byte-compares every ZIP entry before delivery."
                .to_string(),
        },
        summary: counts.clone(),
    };
    let value = serde_json::to_value(manifest)?;
    write_json_atomic(&bridge_dir.join("telegram_manifest.json"), &value)
}

fn build_archive(bridge_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let archive_path = bridge_dir.join("tor_bridges.zip");
    let temporary = bridge_dir.join(format!(".tor_bridges.{}.tmp", std::process::id()));
    let file = File::create(&temporary)?;
    let mut archive = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    // Include the manifest snapshot and every payload file.  A ZIP cannot
    // include itself, which is stated in its manifest rather than hidden.
    let mut names: Vec<&str> = REQUIRED_FILES
        .iter()
        .copied()
        .filter(|name| *name != "tor_bridges.zip")
        .collect();
    names.sort_unstable();
    for name in names {
        let path = bridge_dir.join(name);
        if !path.is_file() {
            return Err(invalid(format!(
                "missing archive input: {}",
                path.display()
            )));
        }
        archive.start_file(format!("bridge/{name}"), options)?;
        archive.write_all(&fs::read(path)?)?;
    }
    archive.finish()?;
    fs::rename(temporary, &archive_path)?;
    Ok(archive_path)
}

fn render_readme(
    options: &PublishOptions,
    report: &PublicationReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = options.repo_url.trim_end_matches('/');
    let link = |name: &str| format!("[{name}]({url}/bridge/{name})");
    let count = |name: &str| report.file_counts.get(name).copied().unwrap_or(0);
    let required_list = REQUIRED_FILES
        .iter()
        .map(|name| format!("- {}\n", link(name)))
        .collect::<String>();
    let body = format!(
        r#"# 🛡️ TorShield-IR — Rust-native Tor Bridge Intelligence

> Automated collection, runner-side reachability probing, Iran-aware ranking, and dual publication for `bridge/` and Telegram.
>
> **Last publication:** `{published}` · **Archive payload SHA-256:** `{archive_sha256}`

## Quick use for Iran

1. Start with {working_all} for the current advisory working set.
2. Prefer {working_obfs4} under ordinary DPI and {working_snowflake} / {working_webtunnel} when a CDN/WebRTC route is appropriate.
3. During a national-internet-cut scenario, try {working_nin}; it is a prioritized *advisory* set, not a connectivity guarantee.
4. Import the selected lines in Tor Browser: **Settings → Connection → Bridges → Add a Bridge Manually**.

## Current publication snapshot

| Output | Entries | Purpose |
| --- | ---: | --- |
| {working_all} | `{all_count}` | Evidence-backed advisory set across transports |
| {working_obfs4} | `{obfs4_count}` | obfs4-oriented fallback for conventional DPI |
| {working_webtunnel} | `{webtunnel_count}` | WebTunnel candidates |
| {working_snowflake} | `{snowflake_count}` | Snowflake capability candidates |
| {working_nin} | `{nin_count}` | NIN/cut-mode priority candidates |
| {blocked} | `{blocked_count}` | Observations classified as blocked |
| {archive} | `{archive_entries}` files | Same verified payload used for Telegram delivery |
| {manifest} | — | SHA-256 inventory, evidence scope, and archive contract |

## What the automation actually does

The GitHub Actions workflow is Rust-native and runs a bounded, reproducible pipeline:

1. Collects from built-in fallback bridges and, when available, Tor Project/MOAT sources.
2. Runs bounded concurrent TCP reachability probes from the GitHub runner. A TCP success is clearly recorded as a **runner-side observation**, not a claim that the endpoint works in Iran.
3. Applies the existing Rust DPI, NIN, transport-rotation, and Iran scoring components to produce advisory output sets.
4. Rebuilds **every required file** in `bridge/`, writes a deterministic ZIP, validates JSON/text inputs, and byte-compares every archive entry to its repository counterpart.
5. Uses that exact ZIP for Telegram upload when explicitly enabled and configured, then commits the same verified `bridge/` payload and this README.

## Autonomous diagnostics and dynamic yield

The Rust whole-run self-healing engine audits every retained job-log line for swallowed errors, empty/short source responses, MOAT schema failures, rate limits, handshake failures, stale caches, artifact mismatches, skipped toolchains, and static FAILSAFE use. It emits affected-stage retry plans and records idempotent safe repairs without fabricating bridge data.

BridgeDB query variants, MOAT top-level/settings schemas, and redundant community mirrors are merged with adaptive concurrency. `MAX_TEST_PER_LIST=0` tests the complete deduplicated source pool; a positive value is an explicit safety ceiling. See `data/collector_yield_report.json`, `data/collector_yield_summary.md`, `data/collector_yield_history.json`, and `data/failsafe_activations.json` for per-transport yield trends and fallback telemetry. Stage 8q installs and verifies its pinned Zig toolchain instead of silently skipping.

## Machine-readable changelog and per-entry test evidence

Every successful publication appends a timestamped entry to
`data/publication_changelog.json` (schema version, ISO-8601 UTC run time, the
verified archive SHA-256, per-file entry counts, and evidence tier/result
counts). Each entry in `bridge/iran_results.json` is stamped with `tested_at`
(the run timestamp), `test_tier` (`tier_2_pt_handshake` / `tier_1_tcp` /
`untested`), and `test_result` (`tested_working` / `tested_failing` /
`untested (rate-limited)`) derived from the recorded probe observations; the
run-level `evidence` block summarises the stamping pass. Tiers and results are
per-observation — they record *how* an endpoint was tested, never an assertion
of Iranian reachability.

## Telegram dual persistence

Telegram delivery uses a bot token and distributes a bridge inventory outside GitHub, so it requires explicit configuration; once configured it is fully automatic.

- Set repository secrets `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`; delivery is then ON by default for schedule, push, and manual runs.
- Opt out per run by selecting **false** in **Run workflow**, or repo-wide with the `TELEGRAM_AUTO_UPLOAD=false` repository variable. Pull-request runs never deliver (preview only).
- The publisher builds and verifies one `tor_bridges.zip`; GitHub and Telegram consume that exact file. Cross-service commits cannot be literally atomic, so an upload failure stops the workflow before the repository commit step whenever possible.

## Evidence and safety notes

- `*_tested.txt` means the latest pipeline recorded a successful TCP observation or a transport-capability check where raw TCP is not meaningful (for example Snowflake). It does **not** prove a full Tor circuit or Iranian reachability.
- `iran_likely_working_*` and anti-DPI scores are decision aids, not guarantees. Censorship conditions vary by ISP, region, time, and Tor Browser version.
- The AI/DPI-labelled reports in `data/` are deterministic scoring/telemetry analyses. They are not a promise that an AI system can defeat filtering or DPI.
- Never place personal credentials in bridge files, commit messages, workflow inputs, or Telegram captions.

## Complete `bridge/` contract

<details>
<summary>Show all {required_count} required files refreshed by the publisher</summary>

{required_list}</details>

## Local verification

```bash
# Full Rust test suite (including offline publication contract tests)
cargo test --workspace --all-targets

# Rebuild the bridge distribution package without Telegram delivery
cargo run --release --bin sync_bridge_outputs -- \
  --bridge-dir bridge \
  --repo-url "{url}" \
  --readme README.md

# Verify an existing publication without changing it
cargo run --release --bin sync_bridge_outputs -- \
  --bridge-dir bridge \
  --verify-only
```

The authoritative machine-readable inventory is {manifest}. Consumers should validate its SHA-256 entries after downloading bridge files.
"#,
        published = report
            .generated_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        archive_sha256 = report.archive_sha256,
        working_all = link("iran_likely_working_all.txt"),
        working_obfs4 = link("iran_likely_working_obfs4.txt"),
        working_webtunnel = link("iran_likely_working_webtunnel.txt"),
        working_snowflake = link("iran_likely_working_snowflake.txt"),
        working_nin = link("iran_likely_working_nin.txt"),
        blocked = link("iran_blocked.txt"),
        archive = link("tor_bridges.zip"),
        manifest = link("telegram_manifest.json"),
        all_count = count("iran_likely_working_all.txt"),
        obfs4_count = count("iran_likely_working_obfs4.txt"),
        webtunnel_count = count("iran_likely_working_webtunnel.txt"),
        snowflake_count = count("iran_likely_working_snowflake.txt"),
        nin_count = count("iran_likely_working_nin.txt"),
        blocked_count = count("iran_blocked.txt"),
        archive_entries = report.archive_entries,
        required_count = REQUIRED_FILES.len(),
        required_list = required_list,
        url = url,
    );
    write_atomic(&options.readme_path, body.as_bytes())
}

/// Rebuild and verify the complete public bridge distribution.
///
/// `publish_at` accepts a clock for deterministic tests. Production callers
/// should use [`publish`].
pub fn publish_at(
    options: &PublishOptions,
    now: DateTime<Utc>,
) -> Result<PublicationReport, Box<dyn std::error::Error>> {
    if options.recent_hours <= 0 {
        return Err(invalid("recent_hours must be positive"));
    }
    fs::create_dir_all(&options.bridge_dir)?;
    let history_path = options.bridge_dir.join("bridge_history.json");
    let results_path = options.bridge_dir.join("iran_results.json");
    if !history_path.is_file() {
        return Err(invalid(format!(
            "missing canonical history: {}",
            history_path.display()
        )));
    }
    if !results_path.is_file() {
        return Err(invalid(format!(
            "missing current probe report: {}",
            results_path.display()
        )));
    }

    let history = read_json(&history_path)?;
    let results = read_json(&results_path)?;
    let probes = extract_probe_records(&results)?;
    let candidates = candidates_from_history(
        &history,
        &probes,
        now - Duration::hours(options.recent_hours),
    )?;

    let mut counts = BTreeMap::new();
    let testing_count = ensure_testing_list(
        &options.bridge_dir.join("bridge_list_for_testing.json"),
        &candidates,
    )?;
    counts.insert("bridge_list_for_testing.json".to_string(), testing_count);
    write_scores(&options.bridge_dir.join("bridge_scores.json"), &candidates)?;
    counts.insert("bridge_scores.json".to_string(), candidates.len());

    write_transport_family(
        &options.bridge_dir,
        &candidates,
        "conjure",
        "conjure",
        false,
        &mut counts,
    )?;
    write_transport_family(
        &options.bridge_dir,
        &candidates,
        "meek-azure",
        "meek-azure",
        false,
        &mut counts,
    )?;
    for (transport, stem) in [
        ("obfs4", "obfs4"),
        ("snowflake", "snowflake"),
        ("vanilla", "vanilla"),
        ("webtunnel", "webtunnel"),
        ("meek_lite", "meek_lite"),
    ] {
        write_transport_family(
            &options.bridge_dir,
            &candidates,
            transport,
            stem,
            true,
            &mut counts,
        )?;
    }
    write_iran_projections(&options.bridge_dir, &candidates, &probes, &mut counts)?;

    // `bridge_history.json` and `iran_results.json` are canonical inputs but
    // are still represented in the summary so the manifest makes their use
    // explicit.
    counts.insert("bridge_history.json".to_string(), candidates.len());
    counts.insert("iran_results.json".to_string(), probes.len());
    write_manifest(options, now, &counts)?;
    let archive_path = build_archive(&options.bridge_dir)?;

    let missing = required_missing(&options.bridge_dir);
    if !missing.is_empty() {
        return Err(invalid(format!(
            "publication missing required files after build: {}",
            missing.join(", ")
        )));
    }
    let archive_sha256 = sha256_file(&archive_path)?;
    let archive_entries = REQUIRED_FILES.len() - 1;
    let report = PublicationReport {
        generated_at: now,
        history_records: candidates.len(),
        probe_records: probes.len(),
        file_counts: counts,
        archive_path,
        archive_sha256,
        archive_entries,
    };
    verify_publication(options)?;
    render_readme(options, &report)?;
    Ok(report)
}

/// Rebuild a publication using the current UTC time.
pub fn publish(options: &PublishOptions) -> Result<PublicationReport, Box<dyn std::error::Error>> {
    publish_at(options, Utc::now())
}

/// Verify an existing publication without changing any user-facing file.
pub fn verify_publication(options: &PublishOptions) -> Result<(), Box<dyn std::error::Error>> {
    let missing = required_missing(&options.bridge_dir);
    if !missing.is_empty() {
        return Err(invalid(format!(
            "missing required bridge files: {}",
            missing.join(", ")
        )));
    }

    for name in JSON_FILES {
        let path = options.bridge_dir.join(name);
        let value = read_json(&path)?;
        if *name == "bridge_history.json" && !value.is_object() {
            return Err(invalid("bridge_history.json must be an object"));
        }
        if *name == "bridge_list_for_testing.json" && !value.is_array() {
            return Err(invalid("bridge_list_for_testing.json must be an array"));
        }
        if *name == "bridge_scores.json" && !value.is_object() {
            return Err(invalid("bridge_scores.json must be an object"));
        }
    }

    for name in REQUIRED_FILES.iter().filter(|name| name.ends_with(".txt")) {
        let body = fs::read_to_string(options.bridge_dir.join(name))?;
        if body.contains('\0') {
            return Err(invalid(format!("text output contains NUL byte: {name}")));
        }
    }

    let manifest = read_json(&options.bridge_dir.join("telegram_manifest.json"))?;
    if manifest
        .get("required_files_present")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid(
            "telegram_manifest.json does not attest a complete inventory",
        ));
    }
    let file_entries = manifest
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("telegram_manifest.json files must be an array"))?;
    let hashes: BTreeMap<&str, &str> = file_entries
        .iter()
        .filter_map(|entry| Some((entry.get("name")?.as_str()?, entry.get("sha256")?.as_str()?)))
        .collect();
    for name in payload_files() {
        let expected = hashes
            .get(name)
            .ok_or_else(|| invalid(format!("manifest does not hash payload file: {name}")))?;
        let actual = sha256_file(&options.bridge_dir.join(name))?;
        if actual != *expected {
            return Err(invalid(format!("manifest SHA-256 mismatch for {name}")));
        }
    }

    let archive_path = options.bridge_dir.join("tor_bridges.zip");
    let archive_file = File::open(&archive_path)?;
    let mut archive = zip::ZipArchive::new(archive_file)?;
    for name in REQUIRED_FILES
        .iter()
        .filter(|name| **name != "tor_bridges.zip")
    {
        let mut entry = archive
            .by_name(&format!("bridge/{name}"))
            .map_err(|_| invalid(format!("archive is missing bridge/{name}")))?;
        let mut archived = Vec::new();
        entry.read_to_end(&mut archived)?;
        let local = fs::read(options.bridge_dir.join(name))?;
        if archived != local {
            return Err(invalid(format!("archive content mismatch for {name}")));
        }
    }
    if archive.len() != REQUIRED_FILES.len() - 1 {
        return Err(invalid(format!(
            "archive entry count mismatch: expected {}, got {}",
            REQUIRED_FILES.len() - 1,
            archive.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn sha256_matches_the_standard_test_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn normalise_transport_keeps_meek_before_generic_url_detection() {
        assert_eq!(
            normalise_transport("meek_lite 192.0.2.1:80 url=https://example.test", None),
            "meek_lite"
        );
        assert_eq!(
            normalise_transport("conjure 192.0.2.2:443", Some("vanilla")),
            "conjure"
        );
    }

    #[test]
    fn recent_timestamp_is_evaluated_from_last_seen() {
        let now = Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap();
        let record = serde_json::json!({
            "first_seen": "2020-01-01T00:00:00Z",
            "last_seen": "2026-08-01T23:00:00Z",
        });
        assert!(record_is_fresh(
            record.as_object().unwrap(),
            now - Duration::hours(72)
        ));
    }

    #[test]
    fn write_transport_family_falls_back_to_static_lines_when_empty() {
        let dir = std::env::temp_dir().join(format!("pub_fb_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let mut counts = BTreeMap::new();
        // No candidates at all -> every obfs4 projection must be populated
        // from the static fallback, never truncated to 0 bytes.
        write_transport_family(&bridge_dir, &[], "obfs4", "obfs4", true, &mut counts)
            .expect("write family");
        for name in [
            "obfs4.txt",
            "obfs4_72h.txt",
            "obfs4_ipv6.txt",
            "obfs4_72h_ipv6.txt",
            "obfs4_ipv6_72h.txt",
            "obfs4_ipv6_tested.txt",
            "obfs4_tested.txt",
        ] {
            let body = std::fs::read_to_string(bridge_dir.join(name)).expect("file");
            assert!(body.lines().count() > 0, "{name} must not be empty");
            assert_eq!(
                *counts.get(name).expect("counted"),
                body.lines().count(),
                "{name} count mismatch"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_transport_family_populates_conjure_and_meek_azure() {
        let dir = std::env::temp_dir().join(format!("pub_fb2_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let mut counts = BTreeMap::new();
        write_transport_family(&bridge_dir, &[], "conjure", "conjure", false, &mut counts)
            .expect("write conjure");
        write_transport_family(
            &bridge_dir,
            &[],
            "meek-azure",
            "meek-azure",
            false,
            &mut counts,
        )
        .expect("write meek-azure");
        for name in [
            "conjure.txt",
            "conjure_72h.txt",
            "conjure_tested.txt",
            "meek-azure.txt",
            "meek-azure_72h.txt",
            "meek-azure_tested.txt",
        ] {
            let body = std::fs::read_to_string(bridge_dir.join(name)).expect("file");
            assert!(body.lines().count() > 0, "{name} must not be empty");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_tcp_evidence_marks_url_only_webtunnel_tested() {
        // Regression: the live collector (tor_collector/storage.rs) records
        // protocol-probe outcomes as `tcp_reachable` + `probe_successes` on
        // history records. Domain-fronted URL-only WebTunnel bridges have no
        // literal endpoint for the Go tester, so publication must honour
        // these fields (not only the legacy `test_pass`) when deciding the
        // `*_tested.txt` projections — otherwise
        // webtunnel_tested.txt stayed empty even though the collector
        // recorded successful front-domain probes.
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(72);
        let raw = "webtunnel 68674E54A17AEB1C9ADE878BBBB46C6975DD3105 url=https://vika7.space/x ver=0.0.4";
        let history = serde_json::json!({
            "key1": {
                "raw": raw,
                "transport": "webtunnel",
                "ip_version": "ipv4",
                "last_seen": chrono::Utc::now().to_rfc3339(),
                "tcp_reachable": true,
                "probe_successes": 25,
                "probe_failures": 0
            },
            "key2": {
                "raw": "webtunnel FFFFFFFFFFFFFFFFFFFFFFFFFFFF url=https://offline.example ver=0.0.3",
                "transport": "webtunnel",
                "ip_version": "ipv4",
                "last_seen": chrono::Utc::now().to_rfc3339(),
                "tcp_reachable": false,
                "probe_successes": 0,
                "probe_failures": 25
            }
        });
        let candidates =
            candidates_from_history(history.as_object().unwrap(), &[], cutoff).expect("candidates");
        let tested: Vec<&str> = candidates
            .iter()
            .filter(|candidate| candidate.tested)
            .map(|candidate| candidate.raw.as_str())
            .collect();
        assert_eq!(tested, vec![raw], "only the reachable front-domain webtunnel is tested");

        // Legacy `test_pass` schema still works unchanged.
        let legacy = serde_json::json!({
            "k": {
                "raw": "obfs4 192.0.2.1:443 cert=x iat-mode=2",
                "transport": "obfs4",
                "ip_version": "ipv4",
                "last_seen": chrono::Utc::now().to_rfc3339(),
                "test_pass": true
            }
        });
        let legacy_candidates =
            candidates_from_history(legacy.as_object().unwrap(), &[], cutoff).expect("legacy");
        assert!(legacy_candidates
            .iter()
            .any(|candidate| candidate.tested && candidate.transport == "obfs4"));
    }

    #[test]
    fn iran_projections_fall_back_to_static_lines_when_no_evidence() {
        let dir = std::env::temp_dir().join(format!("pub_iran_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let mut counts = BTreeMap::new();
        // Empty candidates AND empty probes -> projections use validated
        // static fallbacks where available. WebTunnel remains empty because
        // its bundled metadata has no direct client endpoint; blocked stays
        // empty because there is no evidence.
        write_iran_projections(&bridge_dir, &[], &[], &mut counts).expect("write projections");
        for name in [
            "iran_likely_working_obfs4.txt",
            "iran_likely_working_vanilla.txt",
            "iran_likely_working_snowflake.txt",
            "iran_likely_working_all.txt",
            "iran_likely_working_nin.txt",
            "tested_global_obfs4.txt",
            "tested_global_vanilla.txt",
        ] {
            let body = std::fs::read_to_string(bridge_dir.join(name)).expect("file");
            assert!(body.lines().count() > 0, "{name} must not be empty");
        }
        for name in [
            "iran_likely_working_webtunnel.txt",
            "tested_global_webtunnel.txt",
        ] {
            let body = std::fs::read_to_string(bridge_dir.join(name)).expect("file");
            assert!(
                body.trim().is_empty(),
                "{name} must not contain URL-only WebTunnel metadata"
            );
        }
        let blocked = std::fs::read_to_string(bridge_dir.join("iran_blocked.txt")).expect("file");
        assert!(
            blocked.is_empty(),
            "iran_blocked.txt stays empty without evidence"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

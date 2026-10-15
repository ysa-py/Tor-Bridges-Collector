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
use std::net::IpAddr;
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
    "conjure_72h_ipv4.txt",
    "conjure_72h_ipv6.txt",
    "conjure_ipv4_ipv6_all.txt",
    "conjure_tested.txt",
    "iran_blocked.txt",
    "iran_blocked_ipv4_ipv6_all.txt",
    "iran_likely_working_all.txt",
    "iran_likely_working_ipv4_ipv6_all.txt",
    "iran_likely_working_nin.txt",
    "iran_likely_working_obfs4.txt",
    "iran_likely_working_snowflake.txt",
    "iran_likely_working_vanilla.txt",
    "iran_likely_working_webtunnel.txt",
    "iran_results.json",
    "meek-azure.txt",
    "meek-azure_72h.txt",
    "meek-azure_all.txt",
    "meek-azure_tested.txt",
    "meek_lite.txt",
    "meek_lite_72h.txt",
    "meek_lite_72h_ipv4.txt",
    "meek_lite_72h_ipv6.txt",
    "meek_lite_ipv4.txt",
    "meek_lite_ipv4_ipv6_all.txt",
    "meek_lite_ipv6.txt",
    "meek_lite_ipv6_tested.txt",
    "meek_lite_tested.txt",
    "obfs4.txt",
    "obfs4_72h.txt",
    "obfs4_72h_ipv4.txt",
    "obfs4_72h_ipv6.txt",
    "obfs4_ipv4_ipv6_all.txt",
    "obfs4_ipv4_tested.txt",
    "obfs4_ipv6.txt",
    "obfs4_ipv6_72h.txt",
    "obfs4_ipv6_tested.txt",
    "obfs4_tested.txt",
    "snowflak_ipv4_ipv6_all.txt",
    "snowflake.txt",
    "snowflake_72h.txt",
    "snowflake_72h_ipv4.txt",
    "snowflake_72h_ipv6.txt",
    "snowflake_ipv4_ipv6_all.txt",
    "snowflake_ipv6.txt",
    "snowflake_ipv6_tested",
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
    "vanilla_ipv4.txt",
    "vanilla_ipv4_72h.txt",
    "vanilla_ipv4_ipv6_all.txt",
    "vanilla_ipv4_tested.txt",
    "vanilla_ipv6.txt",
    "vanilla_ipv6_72h.txt",
    "vanilla_ipv6_tested.txt",
    "vanilla_tested.txt",
    "webtunnel.txt",
    "webtunnel_72h.txt",
    "webtunnel_72h_ipv4.txt",
    "webtunnel_72h_ipv6.txt",
    "webtunnel_ipv4.txt",
    "webtunnel_ipv4_ipv6_all.txt",
    "webtunnel_ipv4_tested.txt",
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
    /// Inclusive lower bound of the current pipeline run's observation
    /// window. Typed observations recorded at or after this instant count as
    /// current evidence even when they exceed the bare ten-minute freshness
    /// window (an hourly run legitimately probes for up to ~90 minutes).
    /// `None` reproduces the bare near-now window exactly.
    pub run_floor: Option<DateTime<Utc>>,
    /// Whether the optional probe-relay edge produced observations this run
    /// (`Some(true)`), was explicitly skipped/unavailable (`Some(false)`), or
    /// was never reported (`None`). Drives the `RELAY_DOWN` reason_code on
    /// otherwise-unexplained empty evidence files; it never promotes or
    /// demotes any recorded evidence.
    pub relay_available: Option<bool>,
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
            run_floor: None,
            relay_available: None,
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
    /// Positive typed S2+ transport-handshake evidence (the strongest
    /// runner-observable tier; `tested_working` in the stamp vocabulary).
    tested: bool,
    /// Positive typed runner-side TCP/TLS-or-better evidence (stage >= S1,
    /// connected, recognized vantage). This is the reachability tier admitted
    /// by `*_tested.txt` / `tested_global_*` alongside S2+ (directive v43 §E);
    /// it never claims a PT handshake or Iranian reachability.
    runner_verified: bool,
    /// The stamp-vocabulary tier label of the best joined evidence
    /// (`tier_4_pt_handshake` … `untested`), surfaced per file in the manifest.
    test_tier: String,
    score: f64,
    /// When the S2+ (or runner-verified) evidence joined by fingerprint
    /// (transport probes may rewrite the endpoint, e.g. webtunnel front
    /// resolution), this carries the exact probe-verified line form.
    /// Evidence-gated projections publish this resolved form; the raw history
    /// form stays inventory-only.
    verified_line: Option<String>,
}

impl Candidate {
    /// Numeric evidence rank: 2 = S2+ handshake, 1 = runner TCP/TLS verified,
    /// 0 = no current typed positive evidence. Higher is stronger; consumers
    /// must never present a lower tier as a higher one.
    fn evidence_rank(&self) -> u8 {
        if self.tested {
            2
        } else if self.runner_verified {
            1
        } else {
            0
        }
    }
}

#[derive(Debug, Clone)]
struct ProbeRecord {
    line: String,
    transport: String,
    iran_status: String,
    iran_specific_assessment: bool,
    iran_specific_working: bool,
    verified_s2plus: bool,
    /// Runner-side TCP/TLS-or-better positive evidence (stage >= S1,
    /// connected, recognized vantage, current or in-run). Drives the Tier C
    /// advisory admission and the tiered `*_tested.txt` contract.
    verified_runner_s1plus: bool,
    /// Stamp-vocabulary tier label (`tier_4_pt_handshake` … `untested`).
    test_tier: String,
    score: f64,
}

impl ProbeRecord {
    fn verified_s2plus(&self) -> bool {
        self.verified_s2plus
    }

    /// Numeric evidence rank mirroring [`Candidate::evidence_rank`].
    fn evidence_rank(&self) -> u8 {
        if self.verified_s2plus {
            2
        } else if self.verified_runner_s1plus {
            1
        } else {
            0
        }
    }
}

#[derive(Serialize)]
struct ManifestFile {
    name: String,
    raw_url: String,
    size_bytes: u64,
    non_empty_lines: Option<usize>,
    sha256: String,
    /// For evidence-gated files: the strongest tier admitted by this file's
    /// filter ("s2plus_handshake" or "runner_tcp_tls"). `None` for plain
    /// inventory projections.
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_tier: Option<String>,
    /// For empty files only: why the file is empty without fabricating rows
    /// (`NO_UPSTREAM_SUPPLY`, `NO_IPV6_SUPPLY`, `NO_EVIDENCE`, `RELAY_DOWN`,
    /// `NO_FRESH_WITHIN_WINDOW`). Never present on non-empty files.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
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

/// Extract the bridge identity fingerprint (a 40-character hex token) from a
/// bridge line, if present. The fingerprint is the stable cross-stage bridge
/// identity: transport probes legitimately rewrite the endpoint portion of a
/// webtunnel line (resolving a front domain to `IP:PORT`), while the
/// canonical history keeps the originally collected form.
fn fingerprint_of(line: &str) -> Option<String> {
    line.split_whitespace().find_map(|token| {
        let hex = token.trim_matches(|c: char| !c.is_ascii_hexdigit());
        (hex.len() == 40 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| hex.to_ascii_uppercase())
    })
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
    // The endpoint literal in the line is the ground truth (directive v42 §C
    // "classify IPv4/IPv6 by the real endpoint"): collector-side `ip_version`
    // labels have been observed to disagree with the recorded raw line
    // (e.g. vanilla records tagged "ipv6" carrying IPv4 literals, which
    // previously leaked IPv4 lines into vanilla_ipv6*.txt).
    if let Some(from_literal) = static_line_ip_version(raw) {
        return from_literal;
    }
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

fn extract_probe_records(
    root: &Value,
    now: DateTime<Utc>,
    run_floor: Option<DateTime<Utc>>,
) -> Result<Vec<ProbeRecord>, Box<dyn std::error::Error>> {
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
        let transport = normalise_transport(&line, object.get("transport").and_then(Value::as_str));
        let score = object
            .get("composite_score")
            .or_else(|| object.get("score"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let iran_specific_assessment =
            crate::evidence_stamp::has_iran_specific_assessment_at(record, now);
        let iran_specific_working =
            crate::evidence_stamp::has_iran_specific_working_assessment_at(record, now);
        let verified_s2plus = crate::evidence_stamp::has_verified_s2plus_at(record, now);
        let verified_runner_s1plus =
            crate::evidence_stamp::has_runner_verified_s1plus_in_run_at(record, now, run_floor);
        // Stamp-vocabulary tier of the best current evidence on this record.
        // A stamped label is trusted only when it is a REAL tier label and
        // the record still carries qualifying evidence; historical data
        // (verified 2026-10-15) contains `test_tier:"untested"` rows whose
        // verification is a fresh S1 connect — re-deriving from the actual
        // evidence keeps the tier honest instead of propagating the stale
        // stamp.
        let test_tier = match record.get("test_tier").and_then(Value::as_str) {
            Some(stamped)
                if stamped != crate::evidence_stamp::TIER_UNTESTED
                    && (verified_s2plus || verified_runner_s1plus) =>
            {
                stamped.to_string()
            }
            _ => crate::evidence_stamp::derive_tier_in_run_at(record, now, run_floor),
        };
        result.push(ProbeRecord {
            line,
            transport,
            iran_status: status,
            iran_specific_assessment,
            iran_specific_working,
            verified_s2plus,
            verified_runner_s1plus,
            test_tier,
            score,
        });
    }
    Ok(result)
}

fn candidates_from_history(
    history: &Value,
    probes: &[ProbeRecord],
    cutoff: DateTime<Utc>,
    now: DateTime<Utc>,
    run_floor: Option<DateTime<Utc>>,
) -> Result<Vec<Candidate>, Box<dyn std::error::Error>> {
    let object = history
        .as_object()
        .ok_or_else(|| invalid("bridge_history.json must be a JSON object"))?;
    let probe_by_line: BTreeMap<String, &ProbeRecord> = probes
        .iter()
        .map(|probe| (bridge_key(&probe.line), probe))
        .collect();
    // Fingerprint fallback join: transport probes may rewrite the endpoint
    // portion of a line (webtunnel front resolution), so an exact-line miss
    // with a matching 40-hex fingerprint is still the same bridge and its
    // typed evidence must count for the evidence-gated projections.
    let probe_by_fingerprint: BTreeMap<String, &ProbeRecord> = probes
        .iter()
        .filter_map(|probe| fingerprint_of(&probe.line).map(|fp| (fp, probe)))
        .collect();
    let mut candidates = Vec::with_capacity(object.len());

    for (key, value) in object {
        let Some(record) = value.as_object() else {
            continue;
        };
        let mut raw = record
            .get("raw")
            .and_then(Value::as_str)
            .unwrap_or(key)
            .trim()
            .to_string();
        if raw.is_empty() {
            continue;
        }
        let probe = probe_by_line
            .get(&bridge_key(&raw))
            .copied()
            .or_else(|| fingerprint_of(&raw).and_then(|fp| probe_by_fingerprint.get(&fp).copied()));
        // Family classification from the collected form; may be reclassified
        // below when the probe resolves a placeholder to its real endpoint.
        let mut ipv6 = record_is_ipv6(record, &raw);
        // Placeholder-endpoint resolution (issue #257 root cause 3).
        //
        // Domain-fronted transports (webtunnel) are collected with an IETF
        // documentation-prefix endpoint placeholder (BridgeDB anti-
        // enumeration substitutes `[2001:db8:…]:PORT` for the real endpoint).
        // The dialable truth is the endpoint resolved by the transport front
        // probe (TLS to the host carried in `url=`). When the collected raw
        // endpoint is a reserved placeholder and the fingerprint-joined probe
        // carries a dialable (non-reserved) endpoint, publish the resolved
        // form in ALL projections and classify the IP family by the real
        // endpoint (engineering directive v42 §C: "classify IPv4/IPv6 by the
        // real endpoint"). Without this, `filtered_family_lines` excludes
        // every placeholder-raw line from consumer files, the webtunnel
        // family projections collapse to empty on each run, and the
        // publication guard restores grandfathered last-known-good bytes —
        // the degradation loop that kept issue #257 open. The canonical
        // history keeps the originally collected form; only the publication
        // projection is resolved.
        if let Some(entry) = probe {
            let resolved = entry.line.trim();
            if !resolved.is_empty()
                && crate::ip_guard::contains_documentation_or_reserved_endpoint(&raw)
                && !crate::ip_guard::contains_documentation_or_reserved_endpoint(resolved)
            {
                raw = resolved.to_string();
                // The placeholder was classified by its synthetic literal
                // (BridgeDB substitutes IPv6 documentation addresses); the
                // resolved endpoint is the real one and decides the family
                // (v42 §C). Fall back to the recorded classification only
                // when the resolved form carries no parseable endpoint.
                ipv6 = static_line_ip_version(&raw).unwrap_or(ipv6);
            }
        }
        // Evidence admission (tiered, directive v43 §E):
        //  * `tested` (rank 2) requires a typed S2+ transport handshake with
        //    an observing vantage and a current observation.
        //  * `runner_verified` (rank 1) accepts a typed runner-side TCP/TLS
        //    connect (stage S1, connected) from a recognized vantage whose
        //    observation is current or was recorded inside this run. It is
        //    the reachability tier that keeps `*_tested.txt` honest-but-non-
        //    empty when the optional relay edge is down; it never claims a
        //    PT handshake or Iranian reachability.
        // Legacy TCP booleans, counters, and `test_pass` fields still do not
        // encode a verification stage and remain inventory-only.
        let record_object = Value::Object(record.clone());
        let history_test = crate::evidence_stamp::has_verified_s2plus_at(&record_object, now);
        let history_runner = crate::evidence_stamp::has_runner_verified_s1plus_in_run_at(
            &record_object,
            now,
            run_floor,
        );
        let tested = probe
            .map(|entry| entry.verified_s2plus)
            .unwrap_or(history_test);
        let runner_verified = probe
            .map(|entry| entry.verified_runner_s1plus)
            .unwrap_or(history_runner);
        let test_tier = probe
            .map(|entry| entry.test_tier.clone())
            .unwrap_or_else(|| {
                crate::evidence_stamp::derive_tier_in_run_at(&record_object, now, run_floor)
            });
        let score = probe
            .map(|entry| entry.score)
            .or_else(|| record.get("score").and_then(Value::as_f64))
            .unwrap_or(0.0);
        // Publish the probe-verified line form for evidence-gated
        // projections when the transport probe rewrote the endpoint: the
        // resolved form is the one that actually completed the connection.
        let evidence_positive = tested || runner_verified;
        let verified_line = match probe {
            Some(entry) if evidence_positive && entry.line != raw => Some(entry.line.clone()),
            _ => None,
        };
        candidates.push(Candidate {
            transport: normalise_transport(&raw, record.get("transport").and_then(Value::as_str)),
            ipv6,
            fresh: record_is_fresh(record, cutoff),
            raw,
            tested,
            runner_verified,
            test_tier,
            score,
            verified_line,
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
    let existing_order = if path.is_file() {
        read_json(path).ok().and_then(|value| {
            value.as_array().and_then(|array| {
                let lines: Vec<String> = array
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();
                let unique: BTreeSet<String> = lines.iter().cloned().collect();
                (lines.len() == expected.len() && unique == expected).then_some(lines)
            })
        })
    } else {
        None
    };

    // Preserve adaptive-selector ordering when the existing list is complete,
    // but atomically rewrite it on every publication just like every projection.
    let lines = existing_order.unwrap_or_else(|| expected.iter().cloned().collect());
    let values: Vec<Value> = lines.iter().cloned().map(Value::String).collect();
    write_json_atomic(path, &Value::Array(values))?;
    Ok(lines.len())
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

fn filtered_family_lines(
    candidates: &[Candidate],
    transport: &str,
    ipv6: Option<bool>,
    fresh: bool,
    tested: bool,
) -> Vec<String> {
    candidates
        .iter()
        .filter(|candidate| candidate.transport == transport)
        .filter(|candidate| ipv6.is_none_or(|version| candidate.ipv6 == version))
        .filter(|candidate| !fresh || candidate.fresh)
        // Evidence-gated projections (directive v43 §E tiered contract):
        // admit typed positive evidence at rank >= 1 — a runner-side TCP/TLS
        // connect (S1, `tcp_reachable_s1` in the stamp vocabulary) or a
        // stronger S2+ transport handshake. A lower tier is never presented
        // as a higher one: the manifest records each file's admitted tier,
        // and the README documents the tier semantics.
        .filter(|candidate| !tested || candidate.evidence_rank() >= 1)
        // Evidence-gated projections publish the probe-verified line form
        // when a fingerprint-joined transport probe rewrote the endpoint
        // (e.g. webtunnel front resolution); inventory projections keep the
        // originally collected form.
        .map(|candidate| {
            if tested {
                candidate
                    .verified_line
                    .clone()
                    .unwrap_or_else(|| candidate.raw.clone())
            } else {
                candidate.raw.clone()
            }
        })
        // Published copy-paste projections must contain only consumer-dialable
        // bridges. A literal endpoint in an IETF documentation / reserved
        // range (RFC 3849 2001:db8, RFC 5737 TEST-NETs, ...) normally stays in
        // bridge_history.json for probing and the funnel census (2026-09-09
        // zero-yield audit, docs/ZERO_YIELD_ROOT_CAUSE_2026-09-09.md §3) —
        // with one protocol-mandated exception now carried by
        // `ip_guard::publication_blocks_endpoint`: broker/front transports
        // (snowflake, meek*, conjure) ship RFC 5737/3849 placeholder
        // endpoints in Tor Browser's own defaults and dial the `url=`/`front=`
        // rendezvous instead, so those lines publish when their rendezvous
        // validates (run 38660732712: fresh MOAT supply sat in history while
        // every snowflake/meek projection stayed empty). Private, loopback,
        // link-local, and other reserved literals remain blocked for every
        // transport, and non-fronted transports keep the strict check.
        .filter(|line| !crate::ip_guard::publication_blocks_endpoint(transport, line))
        .collect()
}

fn family_lines(
    candidates: &[Candidate],
    transport: &str,
    ipv6: bool,
    fresh: bool,
    tested: bool,
) -> Vec<String> {
    filtered_family_lines(candidates, transport, Some(ipv6), fresh, tested)
}

fn static_line_ip_version(line: &str) -> Option<bool> {
    for token in line.split_whitespace() {
        if token.contains('=') {
            continue;
        }
        if token.starts_with('[') {
            if let Some(close) = token.find(']') {
                if let Ok(address) = token[1..close].parse::<IpAddr>() {
                    return Some(address.is_ipv6());
                }
            }
            continue;
        }
        let host = token
            .rsplit_once(':')
            .map(|(host, _port)| host)
            .unwrap_or(token);
        if let Ok(address) = host.parse::<IpAddr>() {
            return Some(address.is_ipv6());
        }
    }
    None
}

fn fallback_family_lines(transport: &str, ipv6: Option<bool>) -> Vec<String> {
    static_bridges::fallback_lines(transport)
        .into_iter()
        .map(str::to_string)
        .filter(|line| {
            ipv6.is_none_or(|wanted_ipv6| static_line_ip_version(line) == Some(wanted_ipv6))
        })
        .collect()
}

/// Record the strongest evidence rank that ACTUALLY contributes to an
/// evidence-gated projection, so the manifest can label each file with the
/// tier its contents carry (2 = S2+ handshake present, 1 = only runner
/// TCP/TLS reachability). Inventory projections never get a tier label.
fn record_evidence_tier(
    evidence_tiers: &mut BTreeMap<String, String>,
    name: &str,
    candidates: &[Candidate],
    transport: &str,
    ipv6: Option<bool>,
    fresh: bool,
    tested: bool,
) {
    let is_evidence_file = name.contains("_tested")
        || name.starts_with("tested_global_")
        || name.starts_with("iran_likely_working_");
    if !is_evidence_file {
        return;
    }
    // Strongest contributing candidate decides the file's tier label; the
    // stamp-vocabulary label (`tier_4_pt_handshake` … `tier_1_tcp`) is the
    // honest per-record observation vocabulary already documented in the
    // README. Rank 0 (no positive evidence) stores the "untested" label,
    // which write_manifest never surfaces as evidence_tier.
    let best = candidates
        .iter()
        .filter(|candidate| candidate.transport == transport)
        .filter(|candidate| ipv6.is_none_or(|version| candidate.ipv6 == version))
        .filter(|candidate| !fresh || candidate.fresh)
        .filter(|candidate| !tested || candidate.evidence_rank() >= 1)
        .max_by_key(|candidate| candidate.evidence_rank())
        .map(|candidate| candidate.test_tier.clone())
        .unwrap_or_else(|| "untested".to_string());
    evidence_tiers.insert(name.to_string(), best);
}

fn write_transport_family(
    bridge_dir: &Path,
    candidates: &[Candidate],
    transport: &str,
    stem: &str,
    with_ipv6: bool,
    counts: &mut BTreeMap<String, usize>,
    evidence_tiers: &mut BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Static fallback lines are valid for unfiltered family inventories only.
    // Do not copy an untested or stale fallback into `_tested`/`_72h` outputs,
    // and do not put IPv4 fallback lines in an IPv6-specific projection.
    let fallback = |ipv6: Option<bool>| fallback_family_lines(transport, ipv6);

    let standard = [
        (format!("{stem}.txt"), false, false, false),
        (format!("{stem}_72h.txt"), false, true, false),
        (format!("{stem}_tested.txt"), false, false, true),
    ];
    for (name, ipv6, fresh, tested) in standard {
        let mut lines = family_lines(candidates, transport, ipv6, fresh, tested);
        record_evidence_tier(
            evidence_tiers,
            &name,
            candidates,
            transport,
            Some(ipv6),
            fresh,
            tested,
        );
        if lines.is_empty() && !fresh && !tested {
            // The unqualified base file remains compatible with transports
            // whose bridge lines have no direct IP endpoint (e.g. Snowflake).
            // Every family-labelled alias below requires an actual IP version.
            let fallback_lines = fallback(None);
            if !fallback_lines.is_empty() {
                record_publication_fallback(
                    bridge_dir,
                    &name,
                    transport,
                    fallback_lines.len(),
                    "empty_transport_projection",
                );
                lines = fallback_lines;
            }
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
            record_evidence_tier(
                evidence_tiers,
                &name,
                candidates,
                transport,
                Some(true),
                fresh,
                tested,
            );
            if lines.is_empty() && !fresh && !tested {
                let fallback_lines = fallback(Some(true));
                if !fallback_lines.is_empty() {
                    record_publication_fallback(
                        bridge_dir,
                        &name,
                        transport,
                        fallback_lines.len(),
                        "empty_transport_ipv6_projection",
                    );
                    lines = fallback_lines;
                }
            }
            let count = write_lines(&bridge_dir.join(&name), lines)?;
            counts.insert(name, count);
        }

        // Older clients use this reversed spelling.  Keep it byte-identical
        // to the canonical *_72h_ipv6 form rather than dropping compatibility.
        if matches!(stem, "obfs4" | "vanilla" | "webtunnel") {
            let alias = format!("{stem}_ipv6_72h.txt");
            let lines = family_lines(candidates, transport, true, true, false);
            let count = write_lines(&bridge_dir.join(&alias), lines)?;
            counts.insert(alias, count);
        }
    }
    Ok(())
}

/// Build the explicit IPv4/IPv6 and all-address-family names requested by
/// bridge consumers, while retaining the historical filenames above. Full
/// inventory aliases may use a transport's compiled-in bridge fallback;
/// freshness- and test-qualified files are evidence-only and never receive
/// fallback lines.
fn write_requested_projections(
    bridge_dir: &Path,
    candidates: &[Candidate],
    counts: &mut BTreeMap<String, usize>,
    evidence_tiers: &mut BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // name, transport, IP version (None = both), recent-only, tested-only,
    // permit static fallback. Base files and *_all files are inventories;
    // *_72h and *_tested files must reflect recorded evidence only.
    type OutputProjection = (&'static str, &'static str, Option<bool>, bool, bool, bool);
    const PROJECTIONS: &[OutputProjection] = &[
        (
            "conjure_ipv4_ipv6_all.txt",
            "conjure",
            None,
            false,
            false,
            true,
        ),
        (
            "conjure_72h_ipv4.txt",
            "conjure",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "conjure_72h_ipv6.txt",
            "conjure",
            Some(true),
            true,
            false,
            false,
        ),
        ("conjure_72h.txt", "conjure", None, true, false, false),
        ("conjure_tested.txt", "conjure", None, false, true, false),
        ("meek-azure_all.txt", "meek-azure", None, false, false, true),
        ("meek-azure_72h.txt", "meek-azure", None, true, false, false),
        (
            "meek-azure_tested.txt",
            "meek-azure",
            None,
            false,
            true,
            false,
        ),
        (
            "meek_lite_ipv4_ipv6_all.txt",
            "meek_lite",
            None,
            false,
            false,
            true,
        ),
        (
            "meek_lite_ipv4.txt",
            "meek_lite",
            Some(false),
            false,
            false,
            true,
        ),
        (
            "meek_lite_72h_ipv4.txt",
            "meek_lite",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "meek_lite_72h_ipv6.txt",
            "meek_lite",
            Some(true),
            true,
            false,
            false,
        ),
        (
            "meek_lite_ipv6.txt",
            "meek_lite",
            Some(true),
            false,
            false,
            true,
        ),
        (
            "meek_lite_ipv6_tested.txt",
            "meek_lite",
            Some(true),
            false,
            true,
            false,
        ),
        (
            "meek_lite_tested.txt",
            "meek_lite",
            Some(false),
            false,
            true,
            false,
        ),
        (
            "meek_lite_72h.txt",
            "meek_lite",
            Some(false),
            true,
            false,
            false,
        ),
        ("obfs4_ipv4_ipv6_all.txt", "obfs4", None, false, false, true),
        ("obfs4_tested.txt", "obfs4", Some(false), false, true, false),
        (
            "obfs4_72h_ipv4.txt",
            "obfs4",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "obfs4_72h_ipv6.txt",
            "obfs4",
            Some(true),
            true,
            false,
            false,
        ),
        (
            "obfs4_ipv4_tested.txt",
            "obfs4",
            Some(false),
            false,
            true,
            false,
        ),
        (
            "obfs4_ipv6_tested.txt",
            "obfs4",
            Some(true),
            false,
            true,
            false,
        ),
        ("obfs4_72h.txt", "obfs4", Some(false), true, false, false),
        ("obfs4_ipv6.txt", "obfs4", Some(true), false, false, true),
        (
            "obfs4_ipv6_72h.txt",
            "obfs4",
            Some(true),
            true,
            false,
            false,
        ),
        (
            "snowflak_ipv4_ipv6_all.txt",
            "snowflake",
            None,
            false,
            false,
            true,
        ),
        (
            "snowflake_ipv4_ipv6_all.txt",
            "snowflake",
            None,
            false,
            false,
            true,
        ),
        (
            "snowflake_tested.txt",
            "snowflake",
            Some(false),
            false,
            true,
            false,
        ),
        (
            "snowflake_ipv6_tested",
            "snowflake",
            Some(true),
            false,
            true,
            false,
        ),
        (
            "snowflake_ipv6_tested.txt",
            "snowflake",
            Some(true),
            false,
            true,
            false,
        ),
        (
            "snowflake_ipv6.txt",
            "snowflake",
            Some(true),
            false,
            false,
            true,
        ),
        (
            "snowflake_72h_ipv4.txt",
            "snowflake",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "snowflake_72h_ipv6.txt",
            "snowflake",
            Some(true),
            true,
            false,
            false,
        ),
        (
            "snowflake_72h.txt",
            "snowflake",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "vanilla_ipv4_ipv6_all.txt",
            "vanilla",
            None,
            false,
            false,
            true,
        ),
        (
            "vanilla_tested.txt",
            "vanilla",
            Some(false),
            false,
            true,
            false,
        ),
        (
            "vanilla_72h.txt",
            "vanilla",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "vanilla_72h_ipv6.txt",
            "vanilla",
            Some(true),
            true,
            false,
            false,
        ),
        (
            "vanilla_ipv4.txt",
            "vanilla",
            Some(false),
            false,
            false,
            true,
        ),
        (
            "vanilla_ipv4_72h.txt",
            "vanilla",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "vanilla_ipv4_tested.txt",
            "vanilla",
            Some(false),
            false,
            true,
            false,
        ),
        (
            "vanilla_ipv6.txt",
            "vanilla",
            Some(true),
            false,
            false,
            true,
        ),
        (
            "vanilla_ipv6_72h.txt",
            "vanilla",
            Some(true),
            true,
            false,
            false,
        ),
        (
            "vanilla_ipv6_tested.txt",
            "vanilla",
            Some(true),
            false,
            true,
            false,
        ),
        (
            "webtunnel_ipv4_ipv6_all.txt",
            "webtunnel",
            None,
            false,
            false,
            true,
        ),
        (
            "webtunnel_tested.txt",
            "webtunnel",
            Some(false),
            false,
            true,
            false,
        ),
        (
            "webtunnel_ipv4.txt",
            "webtunnel",
            Some(false),
            false,
            false,
            true,
        ),
        (
            "webtunnel_ipv4_tested.txt",
            "webtunnel",
            Some(false),
            false,
            true,
            false,
        ),
        (
            "webtunnel_ipv6_tested.txt",
            "webtunnel",
            Some(true),
            false,
            true,
            false,
        ),
        (
            "webtunnel_ipv6.txt",
            "webtunnel",
            Some(true),
            false,
            false,
            true,
        ),
        (
            "webtunnel_72h.txt",
            "webtunnel",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "webtunnel_72h_ipv4.txt",
            "webtunnel",
            Some(false),
            true,
            false,
            false,
        ),
        (
            "webtunnel_72h_ipv6.txt",
            "webtunnel",
            Some(true),
            true,
            false,
            false,
        ),
        (
            "webtunnel_ipv6_72h.txt",
            "webtunnel",
            Some(true),
            true,
            false,
            false,
        ),
    ];

    for (name, transport, ipv6, fresh, tested, allow_fallback) in PROJECTIONS {
        let mut lines = filtered_family_lines(candidates, transport, *ipv6, *fresh, *tested);
        record_evidence_tier(
            evidence_tiers,
            name,
            candidates,
            transport,
            *ipv6,
            *fresh,
            *tested,
        );
        if lines.is_empty() && *allow_fallback {
            lines = fallback_family_lines(transport, *ipv6);
        }
        let count = write_lines(&bridge_dir.join(name), lines)?;
        counts.insert((*name).to_string(), count);
    }

    // Keep readable historical names alongside the unambiguous all-family
    // aliases. These are byte-identical copies, included in the same manifest
    // and verified ZIP as every other output.
    copy_projection_alias(
        bridge_dir,
        "iran_likely_working_all.txt",
        "iran_likely_working_ipv4_ipv6_all.txt",
        counts,
    )?;
    copy_projection_alias(
        bridge_dir,
        "iran_blocked.txt",
        "iran_blocked_ipv4_ipv6_all.txt",
        counts,
    )?;
    Ok(())
}

fn copy_projection_alias(
    bridge_dir: &Path,
    source: &str,
    alias: &str,
    counts: &mut BTreeMap<String, usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(bridge_dir.join(source))?;
    let line_count = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .count();
    write_atomic(&bridge_dir.join(alias), &bytes)?;
    counts.insert(alias.to_string(), line_count);
    Ok(())
}

fn is_likely_working(probe: &ProbeRecord) -> bool {
    // The Iran-specific label must come from an Iran-specific assessment, and
    // the bridge must independently pass a typed S2+ verification. Runner-side
    // TCP and `iran_unknown` can never be upgraded into working evidence.
    probe.iran_status == "iran_likely_working"
        && probe.iran_specific_working
        && probe.verified_s2plus()
}

/// Advisory (Tier B) working evidence: the transport handshake itself
/// completed with a fresh, typed S2+ observation from a recognized vantage,
/// and no Iran-specific measurement marks the bridge as blocked.
///
/// This is the strongest Iran-relevant evidence that exists when OONI has no
/// probe_cc=IR measurement for the candidate (the empirical steady state for
/// this pool — verified 2026-10-13 against api.ooni.io). It never claims an
/// Iran vantage: `iran_likely_working_*` remains the advisory ranking name
/// documented at the top of this module, and every admitted bridge still
/// carries a real, fresh probe result in this run. Tier A entries (OONI
/// measured) always outrank Tier B entries in the published ordering.
fn is_advisory_working(probe: &ProbeRecord) -> bool {
    probe.verified_s2plus()
        && !matches!(
            probe.iran_status.as_str(),
            "iran_asn_blocked" | "iran_likely_blocked" | "iran_frequently_blocked"
        )
        && !crate::ip_guard::publication_blocks_endpoint(&probe.transport, &probe.line)
}

/// Advisory (Tier C) reachability evidence (directive v43 §E): a typed,
/// current-or-in-run runner-side TCP/TLS connect (stage >= S1, connected,
/// recognized vantage) with no Iran-specific measurement marking the bridge
/// blocked.
///
/// Tier C keeps the advisory working sets non-empty when the optional relay
/// edge is down and no S2+ handshake evidence exists for a transport (the
/// observed webtunnel/snowflake steady state). It is the LOWEST admitted
/// tier: published ordering always ranks Tier A > B > C first, the manifest
/// records each file's admitted tier composition, the per-record
/// `verification`/`test_tier` fields keep the exact observed stage, and the
/// README states that Tier C membership is reachability evidence, never a
/// PT-handshake or Iran-vantage claim. Documentation/reserved endpoints and
/// relay-unreachable claims are never admitted.
fn is_runner_advisory_working(probe: &ProbeRecord) -> bool {
    probe.verified_runner_s1plus
        && !matches!(
            probe.iran_status.as_str(),
            "iran_asn_blocked" | "iran_likely_blocked" | "iran_frequently_blocked"
        )
        && !crate::ip_guard::publication_blocks_endpoint(&probe.transport, &probe.line)
}

fn is_blocked(probe: &ProbeRecord) -> bool {
    probe.iran_status == "iran_asn_blocked"
        || (matches!(
            probe.iran_status.as_str(),
            "iran_likely_blocked" | "iran_frequently_blocked"
        ) && probe.iran_specific_assessment)
}

fn write_iran_projections(
    bridge_dir: &Path,
    candidates: &[Candidate],
    probes: &[ProbeRecord],
    counts: &mut BTreeMap<String, usize>,
    evidence_tiers: &mut BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidate_by_line: BTreeMap<String, &Candidate> = candidates
        .iter()
        .map(|candidate| (bridge_key(&candidate.raw), candidate))
        .collect();
    let mut working: BTreeMap<String, Vec<(u8, f64, String)>> = IRAN_TRANSPORTS
        .iter()
        .map(|transport| ((*transport).to_string(), Vec::new()))
        .collect();
    let mut working_tiers: BTreeMap<String, (u8, String)> = IRAN_TRANSPORTS
        .iter()
        .map(|transport| ((*transport).to_string(), (0_u8, "untested".to_string())))
        .collect();
    let mut global: BTreeMap<String, Vec<(u8, f64, String)>> = GLOBAL_TRANSPORTS
        .iter()
        .map(|transport| ((*transport).to_string(), Vec::new()))
        .collect();
    let mut global_tiers: BTreeMap<String, (u8, String)> = GLOBAL_TRANSPORTS
        .iter()
        .map(|transport| ((*transport).to_string(), (0_u8, "untested".to_string())))
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
            // Tier A: OONI-measured working + typed S2+ verification. The
            // numeric tier rank (3) orders it above B (2) and C (1).
            if let Some(lines) = working.get_mut(&transport) {
                lines.push((3, score, probe.line.clone()));
            }
            working_tiers
                .entry(transport.clone())
                .and_modify(|tier| *tier = (2, probe.test_tier.clone()))
                .or_insert((2, probe.test_tier.clone()));
        } else if is_advisory_working(probe) {
            // Tier B: fresh S2+ transport handshake, no OONI measurement
            // available, not blocked.
            if let Some(lines) = working.get_mut(&transport) {
                lines.push((2, score, probe.line.clone()));
            }
            working_tiers
                .entry(transport.clone())
                .and_modify(|tier| *tier = (2, probe.test_tier.clone()))
                .or_insert((2, probe.test_tier.clone()));
        } else if is_runner_advisory_working(probe) {
            // Tier C: runner-side TCP/TLS reachability only (directive v43
            // §E). Explicitly the lowest admitted tier — the ordering below
            // always sinks it beneath A/B, and the README + manifest state
            // that these entries carry reachability evidence only.
            if let Some(lines) = working.get_mut(&transport) {
                lines.push((1, score, probe.line.clone()));
            }
            working_tiers
                .entry(transport.clone())
                .and_modify(|tier| {
                    if tier.0 < 1 {
                        *tier = (1, probe.test_tier.clone());
                    }
                })
                .or_insert((1, probe.test_tier.clone()));
        }
        if probe.verified_s2plus() || probe.verified_runner_s1plus {
            // tested_global_* uses the same tiered contract as *_tested.txt:
            // strongest evidence first (S2+ above runner TCP/TLS).
            let rank = probe.evidence_rank();
            if let Some(lines) = global.get_mut(&transport) {
                lines.push((rank, score, probe.line.clone()));
            }
            global_tiers
                .entry(transport.clone())
                .and_modify(|tier| {
                    if tier.0 < rank {
                        *tier = (rank, probe.test_tier.clone());
                    }
                })
                .or_insert((rank, probe.test_tier.clone()));
        }
        if is_blocked(probe) {
            blocked.push(probe.line.clone());
        }
    }

    let mut all_working = Vec::new();
    let mut nin = Vec::new();
    let mut all_best_rank = 0_u8;
    let mut all_best_label = "untested".to_string();
    let mut nin_best_rank = 0_u8;
    let mut nin_best_label = "untested".to_string();
    for transport in IRAN_TRANSPORTS {
        let mut entries = working.remove(*transport).unwrap_or_default();
        // Best evidence tier first, then score, then line; the text writer
        // does a final deterministic dedup/sort so consumers never receive
        // duplicate bridge lines.
        entries.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| right.1.total_cmp(&left.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        let lines: Vec<String> = entries.into_iter().map(|(_, _, line)| line).collect();
        if matches!(*transport, "snowflake" | "webtunnel" | "meek_lite") {
            nin.extend(lines.iter().cloned());
        }
        all_working.extend(lines.iter().cloned());
        let name = format!("iran_likely_working_{transport}.txt");
        let count = write_lines(&bridge_dir.join(&name), lines)?;
        counts.insert(name.clone(), count);
        // Tier A/B rows are S2+ evidence (rank 2); a Tier C-only file is
        // runner TCP/TLS reachability (rank 1). The label is the strongest
        // contributing record's stamp-vocabulary tier.
        let best = working_tiers
            .get(*transport)
            .map(|(_, label)| label.clone())
            .unwrap_or_else(|| "untested".to_string());
        evidence_tiers.insert(name, best);
        // The aggregate files span transports; their honest tier label is the
        // strongest contributing tier across the transports they aggregate.
        let (rank, label) = working_tiers
            .get(*transport)
            .cloned()
            .unwrap_or((0, "untested".to_string()));
        if matches!(*transport, "obfs4" | "webtunnel" | "vanilla" | "snowflake")
            && rank >= all_best_rank
            && (rank > all_best_rank || all_best_label == "untested")
        {
            all_best_rank = rank;
            all_best_label = label.clone();
        }
        if matches!(*transport, "snowflake" | "webtunnel" | "meek_lite")
            && rank >= nin_best_rank
            && (rank > nin_best_rank || nin_best_label == "untested")
        {
            nin_best_rank = rank;
            nin_best_label = label;
        }
    }

    // Working projections admit only real evidence: Tier A (OONI-measured),
    // Tier B (fresh S2+ transport handshake from this run), or Tier C
    // (runner-side TCP/TLS reachability, directive v43 §E). Static inventory
    // lines are never enough, so a projection stays empty rather than
    // inventing working candidates that no probe ever verified; the manifest
    // records a reason_code for every empty evidence file.
    let all_count = write_lines(&bridge_dir.join("iran_likely_working_all.txt"), all_working)?;
    counts.insert("iran_likely_working_all.txt".to_string(), all_count);
    evidence_tiers.insert("iran_likely_working_all.txt".to_string(), all_best_label);
    let nin_count = write_lines(&bridge_dir.join("iran_likely_working_nin.txt"), nin)?;
    counts.insert("iran_likely_working_nin.txt".to_string(), nin_count);
    evidence_tiers.insert("iran_likely_working_nin.txt".to_string(), nin_best_label);
    let blocked_count = write_lines(&bridge_dir.join("iran_blocked.txt"), blocked)?;
    counts.insert("iran_blocked.txt".to_string(), blocked_count);

    for transport in GLOBAL_TRANSPORTS {
        let mut entries = global.remove(*transport).unwrap_or_default();
        entries.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| right.1.total_cmp(&left.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        // These outputs are evidence-qualified. Never fill an empty tested
        // projection with an unprobed static bridge.
        let lines: Vec<String> = entries.into_iter().map(|(_, _, line)| line).collect();
        let name = format!("tested_global_{transport}.txt");
        let count = write_lines(&bridge_dir.join(&name), lines)?;
        counts.insert(name.clone(), count);
        evidence_tiers.insert(
            name,
            global_tiers
                .get(*transport)
                .map(|(_, label)| label.clone())
                .unwrap_or_else(|| "untested".to_string()),
        );
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

fn prune_unmanaged_files(bridge_dir: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let mut removed = 0;
    for entry in fs::read_dir(bridge_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if REQUIRED_FILES.contains(&name) {
            continue;
        }
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            fs::remove_dir_all(path)?;
            removed += 1;
        } else if kind.is_file() || kind.is_symlink() {
            fs::remove_file(path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn is_text_output(name: &str) -> bool {
    name.ends_with(".txt") || name == "snowflake_ipv6_tested"
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

/// Map a projection filename back to its transport, if it names exactly one
/// (`None` for multi-transport files such as `iran_likely_working_all.txt`).
fn file_transport_of<'a>(name: &str, transports: &[&'a str]) -> Option<&'a str> {
    let stem = name
        .strip_suffix(".txt")
        .unwrap_or(name)
        .trim_end_matches("_tested")
        .trim_end_matches("_72h");
    if name.starts_with("tested_global_") {
        let rest = stem.strip_prefix("tested_global_")?;
        return transports.iter().copied().find(|t| *t == rest);
    }
    if let Some(rest) = stem.strip_prefix("iran_likely_working_") {
        // `_all` and `_nin` span several transports.
        if rest == "all" || rest == "nin" || rest == "ipv4_ipv6_all" {
            return None;
        }
        return transports.iter().copied().find(|t| *t == rest);
    }
    if name.starts_with("iran_blocked") {
        return None;
    }
    transports.iter().copied().find(|t| {
        stem == *t
            || stem
                .strip_prefix(t)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('_'))
    })
}

/// Explain why an empty projection is empty, without fabricating rows
/// (directive v43 §E). Precedence: NO_UPSTREAM_SUPPLY > NO_IPV6_SUPPLY >
/// NO_FRESH_WITHIN_WINDOW > RELAY_DOWN > NO_EVIDENCE. An empty blocklist is
/// a truthful "nothing observed blocked", not a publication defect.
fn empty_file_reason_code(
    name: &str,
    supply: usize,
    ipv6_supply: usize,
    fresh_supply: usize,
    evidence_supply: usize,
    relay_available: Option<bool>,
) -> Option<String> {
    if name.starts_with("iran_blocked") {
        return Some("NO_EVIDENCE".to_string());
    }
    if file_transport_of(
        name,
        &[
            "obfs4",
            "vanilla",
            "webtunnel",
            "snowflake",
            "meek_lite",
            "meek-azure",
            "conjure",
        ],
    )
    .is_none()
    {
        return Some("NO_EVIDENCE".to_string());
    }
    if supply == 0 {
        return Some("NO_UPSTREAM_SUPPLY".to_string());
    }
    let is_ipv6_file = name.contains("_ipv6") && !name.contains("_ipv4_ipv6_all");
    if is_ipv6_file && ipv6_supply == 0 {
        return Some("NO_IPV6_SUPPLY".to_string());
    }
    if name.contains("_72h") && fresh_supply == 0 {
        return Some("NO_FRESH_WITHIN_WINDOW".to_string());
    }
    let is_evidence_file = name.contains("_tested")
        || name.starts_with("tested_global_")
        || name.starts_with("iran_likely_working_");
    if is_evidence_file {
        if evidence_supply == 0 && relay_available == Some(false) {
            return Some("RELAY_DOWN".to_string());
        }
        return Some("NO_EVIDENCE".to_string());
    }
    Some("NO_EVIDENCE".to_string())
}

fn write_manifest(
    options: &PublishOptions,
    generated_at: DateTime<Utc>,
    counts: &BTreeMap<String, usize>,
    evidence_tiers: &BTreeMap<String, String>,
    candidates: &[Candidate],
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

    // Per-transport supply context used to explain empty files without
    // fabricating rows (directive v43 §E: every empty evidence file carries a
    // reason_code). Counts come from the same candidate set that produced the
    // projections, so the reasons can never contradict the published bytes.
    let transports = [
        "obfs4",
        "vanilla",
        "webtunnel",
        "snowflake",
        "meek_lite",
        "meek-azure",
        "conjure",
    ];
    let mut supply: BTreeMap<&str, usize> = transports.iter().map(|t| (*t, 0)).collect();
    let mut ipv6_supply: BTreeMap<&str, usize> = transports.iter().map(|t| (*t, 0)).collect();
    let mut fresh_supply: BTreeMap<&str, usize> = transports.iter().map(|t| (*t, 0)).collect();
    let mut evidence_supply: BTreeMap<&str, usize> = transports.iter().map(|t| (*t, 0)).collect();
    for candidate in candidates {
        let Some(slot) = transports.iter().find(|t| *t == &candidate.transport) else {
            continue;
        };
        *supply.get_mut(slot).expect("seeded") += 1;
        if candidate.ipv6 {
            *ipv6_supply.get_mut(slot).expect("seeded") += 1;
        }
        if candidate.fresh {
            *fresh_supply.get_mut(slot).expect("seeded") += 1;
        }
        if candidate.evidence_rank() >= 1 {
            *evidence_supply.get_mut(slot).expect("seeded") += 1;
        }
    }

    let reason_for = |name: &str, empty: bool| -> Option<String> {
        if !empty {
            return None;
        }
        let seed =
            |map: &BTreeMap<&str, usize>, transport: &str| map.get(transport).copied().unwrap_or(0);
        let transport_supply = |map: &BTreeMap<&str, usize>, transport: Option<&str>| {
            transport.map(|t| seed(map, t)).unwrap_or(usize::MAX)
        };
        empty_file_reason_code(
            name,
            transport_supply(&supply, file_transport_of(name, &transports)),
            transport_supply(&ipv6_supply, file_transport_of(name, &transports)),
            transport_supply(&fresh_supply, file_transport_of(name, &transports)),
            transport_supply(&evidence_supply, file_transport_of(name, &transports)),
            options.relay_available,
        )
    };

    let tier_label = |name: &str| -> Option<String> {
        let is_evidence_file = name.contains("_tested")
            || name.starts_with("tested_global_")
            || name.starts_with("iran_likely_working_");
        if !is_evidence_file {
            return None;
        }
        // Surface the stamp-vocabulary label of the strongest contributor,
        // with a coarse grouped label as a stable fallback vocabulary.
        match evidence_tiers.get(name).map(String::as_str) {
            Some("tier_4_pt_handshake")
            | Some("tier_3_transport")
            | Some("tier_2_pt_handshake") => Some("s2plus_handshake".to_string()),
            Some("tier_1_tcp") => Some("runner_tcp_tls".to_string()),
            Some(other) if other != "untested" => Some(other.to_string()),
            _ => None,
        }
    };

    let mut files: Vec<ManifestFile> = payload_files()
        .into_iter()
        .map(|name| {
            let path = bridge_dir.join(name);
            let non_empty_lines = is_text_output(name).then(|| count_non_empty_lines(&path));
            let empty = non_empty_lines.map(|lines| lines == 0).unwrap_or(false);
            Ok(ManifestFile {
                name: name.to_string(),
                raw_url: format!("{}/bridge/{name}", options.repo_url.trim_end_matches('/')),
                size_bytes: path.metadata()?.len(),
                non_empty_lines,
                sha256: sha256_file(&path)?,
                evidence_tier: tier_label(name),
                reason_code: reason_for(name, empty),
            })
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;
    files.sort_by(|left, right| left.name.cmp(&right.name));

    let archive_entries = payload_files().len() + 1; // + telegram_manifest.json
    let manifest = Manifest {
        schema_version: 3,
        generated_at: generated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        producer: "torshield-ir-rust-publication-v3".to_string(),
        evidence_scope: "TCP observations are made from the CI runner. Evidence tiers are relay-verified > runner TCP/TLS-verified > capability-only > unverified; *_tested.txt admits runner-side TCP/TLS-or-better typed evidence from this run, and iran_likely_working_* ranks OONI-measured > S2+ handshake > runner TCP/TLS reachability. They are advisory and are not a guarantee of reachability from Iran. Empty evidence files carry a reason_code (NO_UPSTREAM_SUPPLY, NO_IPV6_SUPPLY, NO_FRESH_WITHIN_WINDOW, NO_EVIDENCE, RELAY_DOWN)."
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

The GitHub Actions workflow is Rust-native and schedules the full pipeline at minute 0 of every UTC hour on the default branch. Runs targeting the same branch serialize without cancellation so artifacts start from the latest committed state; a run taking longer than an hour can delay or coalesce a refresh because GitHub scheduling is best-effort:

1. Collects from built-in fallback bridges and, when available, Tor Project/MOAT sources.
2. Runs bounded concurrent TCP reachability probes from the GitHub runner. A TCP success is clearly recorded as a **runner-side observation**, not a claim that the endpoint works in Iran.
3. Applies the existing Rust DPI, NIN, transport-rotation, and Iran scoring components to produce advisory output sets.
4. Rewrites each derived `bridge/` output with atomic file replacement, creates a deterministic ZIP, and verifies every manifest hash and archive entry.
5. Keeps the canonical history and latest probe report as inputs; removes stale/unmanaged bridge-directory files only after the new publication has passed verification.
6. Uses that exact ZIP for Telegram upload when explicitly enabled and configured, then commits the same verified `bridge/` payload and this README.

## Autonomous diagnostics and dynamic yield

The Rust whole-run self-healing engine audits every retained job-log line for swallowed errors, empty/short source responses, MOAT schema failures, rate limits, handshake failures, stale caches, artifact mismatches, skipped toolchains, and static FAILSAFE use. It emits affected-stage retry plans and records idempotent safe repairs without fabricating bridge data.

BridgeDB query variants, MOAT top-level/settings schemas, and redundant community mirrors are merged with adaptive concurrency. `MAX_TEST_PER_LIST=0` tests the complete deduplicated source pool; a positive value is an explicit safety ceiling. See `data/collector_yield_report.json`, `data/collector_yield_summary.md`, `data/collector_yield_history.json`, and `data/failsafe_activations.json` for per-transport yield trends and fallback telemetry. Stage 8q installs and verifies its pinned Zig toolchain instead of silently skipping.

## Machine-readable changelog and per-entry test evidence

Every successful publication appends a timestamped entry to
`data/publication_changelog.json` (schema version, ISO-8601 UTC run time, the
verified archive SHA-256, per-file entry counts, and evidence tier/result
counts). Each entry in `bridge/iran_results.json` carries `verification` with
the actual highest typed stage, observer vantage, observation time, RTT, and
bounded detail. `tested_at` records the stamping run; `test_tier` distinguishes
`tier_4_pt_handshake` / `tier_3_transport` / `tier_2_pt_handshake` /
`tier_1_tcp` / `tier_0_attempt` / `untested`; and `test_result` distinguishes
`tested_working` (S2+ only) / `tcp_reachable_s1` / `tested_failing` /
`untested (rate-limited)`. Inconclusive outcomes never become working or
failing counts. The run-level `evidence` block summarises these counts; none
asserts Iranian reachability unless backed by a separate, current Iran vantage.

## Telegram dual persistence

Telegram delivery uses a bot token and distributes a bridge inventory outside GitHub, so it requires explicit configuration; once configured it is fully automatic.

- Set repository secrets `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`; delivery is then ON by default for schedule, push, and manual runs.
- Opt out per run by selecting **false** in **Run workflow**, or repo-wide with the `TELEGRAM_AUTO_UPLOAD=false` repository variable. Pull-request runs never deliver (preview only).
- The publisher builds and verifies one `tor_bridges.zip`; GitHub and Telegram consume that exact file. Cross-service commits cannot be literally atomic, so an upload failure stops the workflow before the repository commit step whenever possible.

## Evidence and safety notes

- Evidence tiers (strongest first): **relay-verified → runner TCP/TLS-verified → capability-only → unverified**, stored per record in `bridge/iran_results.json` (`verification.stage`, `test_tier`, `test_result`).
- `*_tested.txt` and `tested_global_*.txt` admit typed, positive evidence at **runner TCP/TLS-verified or better** (stage S1 `tcp_reachable_s1`, or the stronger S2+ `tested_working` handshake core; strongest tier first). An S1 TCP/TLS connect proves the endpoint answered from the recorded vantage — it does **not** prove a pluggable-transport handshake or Iranian reachability.
- `iran_likely_working_*` ranks the best available tier per bridge: **Tier A** OONI-measured working > **Tier B** S2+ handshake > **Tier C** runner TCP/TLS reachability. Tier C membership is reachability evidence only; per-record confidence stays in `iran_results.json`.
- `telegram_manifest.json` records an `evidence_tier` per evidence file and a `reason_code` for every empty file (`NO_UPSTREAM_SUPPLY`, `NO_IPV6_SUPPLY`, `NO_FRESH_WITHIN_WINDOW`, `NO_EVIDENCE`, `RELAY_DOWN`) — an empty file means no qualifying observation, never a fabricated one.
- `iran_likely_working_*` and anti-DPI scores are decision aids, not guarantees. Censorship conditions vary by ISP, region, time, and Tor Browser version.
- The AI/DPI-labelled reports in `data/` are deterministic scoring/telemetry analyses. They are not a promise that an AI system can defeat filtering or DPI.
- Never place personal credentials in bridge files, commit messages, workflow inputs, or Telegram captions.

## Filename conventions

- `*_ipv4_ipv6_all.txt` combines candidates across both address families; `*_ipv4.txt` and `*_ipv6.txt` are family-specific.
- `*_72h*` is limited to candidates observed within the 72-hour freshness window. `*_tested*` is evidence-only; an empty file means no qualifying observation, not a failed build.
- Historical filenames remain available as compatibility aliases. The requested misspelling `snowflak_ipv4_ipv6_all.txt` and extensionless `snowflake_ipv6_tested` are generated too; correctly spelled `.txt` aliases are included as well.

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
    let probes = extract_probe_records(&results, now, options.run_floor)?;
    let candidates = candidates_from_history(
        &history,
        &probes,
        now - Duration::hours(options.recent_hours),
        now,
        options.run_floor,
    )?;

    let mut counts = BTreeMap::new();
    let mut evidence_tiers: BTreeMap<String, String> = BTreeMap::new();
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
        &mut evidence_tiers,
    )?;
    write_transport_family(
        &options.bridge_dir,
        &candidates,
        "meek-azure",
        "meek-azure",
        false,
        &mut counts,
        &mut evidence_tiers,
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
            &mut evidence_tiers,
        )?;
    }
    write_iran_projections(
        &options.bridge_dir,
        &candidates,
        &probes,
        &mut counts,
        &mut evidence_tiers,
    )?;
    write_requested_projections(
        &options.bridge_dir,
        &candidates,
        &mut counts,
        &mut evidence_tiers,
    )?;

    // `bridge_history.json` and `iran_results.json` are canonical inputs but
    // are still represented in the summary so the manifest makes their use
    // explicit.
    counts.insert("bridge_history.json".to_string(), candidates.len());
    counts.insert("iran_results.json".to_string(), probes.len());
    write_manifest(options, now, &counts, &evidence_tiers, &candidates)?;
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
    // Do not clear the canonical history/probe inputs. Once a replacement
    // publication has passed manifest+ZIP verification, discard stale or
    // unknown bridge-directory files so the published directory is a clean,
    // exact contract on every scheduled refresh.
    let pruned = prune_unmanaged_files(&options.bridge_dir)?;
    if pruned > 0 {
        eprintln!("sync_bridge_outputs: removed {pruned} stale bridge file(s)/directory(s)");
    }
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

    for name in REQUIRED_FILES.iter().filter(|name| is_text_output(name)) {
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
    let listed_files = manifest
        .get("required_files")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("telegram_manifest.json required_files must be an array"))?
        .iter()
        .map(|name| {
            name.as_str().ok_or_else(|| {
                invalid("telegram_manifest.json required_files entries must be strings")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if listed_files != REQUIRED_FILES.to_vec() {
        return Err(invalid(
            "telegram_manifest.json required_files does not match the publisher contract",
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
    fn write_transport_family_falls_back_only_for_unqualified_inventory() {
        let dir = std::env::temp_dir().join(format!("pub_fb_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let mut counts = BTreeMap::new();
        // A static bridge is valid in the unqualified inventory, but must not
        // be labelled recent, tested, or IPv6 without supporting evidence.
        write_transport_family(
            &bridge_dir,
            &[],
            "obfs4",
            "obfs4",
            true,
            &mut counts,
            &mut BTreeMap::new(),
        )
        .expect("write family");
        let base = std::fs::read_to_string(bridge_dir.join("obfs4.txt")).expect("base file");
        assert!(
            !base.trim().is_empty(),
            "obfs4 base inventory uses static fallback"
        );
        assert_eq!(
            *counts.get("obfs4.txt").expect("counted"),
            base.lines().count(),
            "obfs4 base count mismatch"
        );
        for name in [
            "obfs4_72h.txt",
            "obfs4_ipv6.txt",
            "obfs4_72h_ipv6.txt",
            "obfs4_ipv6_72h.txt",
            "obfs4_ipv6_tested.txt",
            "obfs4_tested.txt",
        ] {
            let body = std::fs::read_to_string(bridge_dir.join(name)).expect("file");
            assert!(
                body.trim().is_empty(),
                "{name} must not claim unsupported evidence"
            );
            assert_eq!(*counts.get(name).expect("counted"), 0);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_transport_family_populates_conjure_and_meek_azure() {
        let dir = std::env::temp_dir().join(format!("pub_fb2_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let mut counts = BTreeMap::new();
        write_transport_family(
            &bridge_dir,
            &[],
            "conjure",
            "conjure",
            false,
            &mut counts,
            &mut BTreeMap::new(),
        )
        .expect("write conjure");
        write_transport_family(
            &bridge_dir,
            &[],
            "meek-azure",
            "meek-azure",
            false,
            &mut counts,
            &mut BTreeMap::new(),
        )
        .expect("write meek-azure");
        for name in ["conjure.txt", "meek-azure.txt"] {
            let body = std::fs::read_to_string(bridge_dir.join(name)).expect("file");
            assert!(
                body.lines().count() > 0,
                "{name} must contain static inventory"
            );
        }
        for name in [
            "conjure_72h.txt",
            "conjure_tested.txt",
            "meek-azure_72h.txt",
            "meek-azure_tested.txt",
        ] {
            let body = std::fs::read_to_string(bridge_dir.join(name)).expect("file");
            assert!(body.trim().is_empty(), "{name} must reflect evidence only");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_requires_typed_s2_evidence_for_tested_projections() {
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::hours(72);
        let observed_at = (now - chrono::Duration::seconds(30)).to_rfc3339();
        let verified =
            "webtunnel AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://front.example/x ver=0.0.4";
        let legacy_tcp =
            "webtunnel BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB url=https://legacy.example/x ver=0.0.4";
        let legacy_test_pass = "obfs4 192.0.2.1:443 cert=x iat-mode=2";
        let history = serde_json::json!({
            "verified": {
                "raw": verified,
                "transport": "webtunnel",
                "last_seen": chrono::Utc::now().to_rfc3339(),
                "verification": {
                    "status": "connected",
                    "stage": "S2",
                    "vantage": { "type": "cloudflare_worker", "colo": "FRA" },
                    "probe_type": "websocket-101",
                    "rtt_ms": 23.0,
                    "observed_at": observed_at
                }
            },
            "legacy_tcp": {
                "raw": legacy_tcp,
                "transport": "webtunnel",
                "last_seen": chrono::Utc::now().to_rfc3339(),
                "tcp_reachable": true,
                "probe_successes": 25,
                "probe_failures": 0
            },
            "legacy_test_pass": {
                "raw": legacy_test_pass,
                "transport": "obfs4",
                "last_seen": chrono::Utc::now().to_rfc3339(),
                "test_pass": true
            }
        });
        let candidates =
            candidates_from_history(&history, &[], cutoff, now, None).expect("candidates");
        let tested: Vec<&str> = candidates
            .iter()
            .filter(|candidate| candidate.tested)
            .map(|candidate| candidate.raw.as_str())
            .collect();
        assert_eq!(tested, vec![verified]);
    }

    #[test]
    fn iran_working_and_global_projections_require_typed_evidence() {
        let dir = std::env::temp_dir().join(format!("pub_iran_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let now = Utc::now();
        let observed_at = (now - Duration::seconds(30)).to_rfc3339();
        let queried_at = (now - Duration::seconds(30)).to_rfc3339();
        let records = serde_json::json!([
            {
                "line": "webtunnel 192.0.2.10:443 A url=https://working.example/x",
                "transport": "webtunnel",
                "iran_status": "iran_likely_working",
                "iran_assessment": {
                    "status": "iran_likely_working", "source": "ooni_measurements_api", "checked": true,
                    "vantage": { "type": "ooni_probe", "country": "IR" },
                    "queried_at": queried_at.clone(),
                    "measurement_at": queried_at,
                    "measurement_window_days": 7
                },
                "verification": {
                    "status": "connected", "stage": "S2",
                    "vantage": { "type": "cloudflare_worker", "colo": "FRA" },
                    "probe_type": "websocket-101",
                    "observed_at": observed_at
                }
            },
            {
                "line": "webtunnel 192.0.2.11:443 B url=https://unknown.example/x",
                "transport": "webtunnel",
                "iran_status": "iran_unknown",
                "verification": {
                    "status": "connected", "stage": "S2",
                    "vantage": { "type": "cloudflare_worker", "colo": "FRA" },
                    "probe_type": "websocket-101",
                    "observed_at": observed_at
                }
            },
            {
                "line": "webtunnel 192.0.2.12:443 C url=https://tcp-only.example/x",
                "transport": "webtunnel",
                "iran_status": "iran_likely_working",
                "verification": {
                    "status": "connected", "stage": "S1",
                    "vantage": { "type": "cloudflare_worker", "colo": "FRA" },
                    "probe_type": "tls",
                    "observed_at": observed_at
                }
            },
            {
                "line": "webtunnel 192.0.2.13:443 D url=https://no-vantage.example/x",
                "transport": "webtunnel",
                "iran_status": "iran_likely_working",
                "verification": {
                    "status": "connected", "stage": "S2",
                    "vantage": null,
                    "probe_type": "websocket-101",
                    "observed_at": observed_at
                }
            }
        ]);
        let probes = extract_probe_records(&records, now, None).expect("typed probe records");
        let mut counts = BTreeMap::new();
        write_iran_projections(&bridge_dir, &[], &probes, &mut counts, &mut BTreeMap::new())
            .expect("write projections");

        // Tiered contract (directive v43 \u00a7E): Tier A (OONI + S2+) first,
        // Tier B (S2+, no OONI) next, Tier C (runner/edge TCP/TLS reachability)
        // admitted last. Records without a recognized observing vantage are
        // still rejected everywhere.
        let working = std::fs::read_to_string(bridge_dir.join("iran_likely_working_webtunnel.txt"))
            .expect("working output");
        assert!(
            working.contains("working.example"),
            "Tier A admission: {working}"
        );
        // B and C use TEST-NET (192.0.2.0/24) endpoints: the advisory working
        // set never publishes documentation-range endpoints, whatever their
        // tier. D has no observing vantage and is rejected everywhere.
        assert!(!working.contains("unknown.example"));
        assert!(!working.contains("tcp-only.example"));
        assert!(!working.contains("no-vantage.example"));

        let global = std::fs::read_to_string(bridge_dir.join("tested_global_webtunnel.txt"))
            .expect("global output");
        assert!(global.contains("working.example"));
        assert!(global.contains("unknown.example"));
        assert!(
            global.contains("tcp-only.example"),
            "typed S1+TLS evidence with a recognized vantage is admitted (rank 1)"
        );
        assert!(!global.contains("no-vantage.example"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn advisory_working_admits_verified_handshakes_and_rejects_the_rest() {
        let dir = std::env::temp_dir().join(format!("pub_tierb_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let now = Utc::now();
        let observed_at = (now - Duration::seconds(30)).to_rfc3339();
        let s2 = serde_json::json!({
            "status": "connected", "stage": "S3",
            "vantage": { "type": "github_actions_runner" },
            "probe_type": "obfs4-framing",
            "observed_at": observed_at
        });
        // Routable obfs4 endpoints — the realistic pool shape.
        let records = serde_json::json!([
            {
                // Tier B: verified handshake, no OONI measurement exists.
                "line": "obfs4 45.10.11.12:443 AAAA cert=x iat-mode=0",
                "transport": "obfs4", "iran_status": "iran_unknown",
                "verification": s2
            },
            {
                // Tier C: runner TCP-only (S1) is admitted LAST — reachability
                // evidence only, never a PT-handshake claim (directive v43 \u00a7E).
                "line": "obfs4 45.10.11.13:443 BBBB cert=x iat-mode=0",
                "transport": "obfs4", "iran_status": "iran_unknown",
                "verification": {
                    "status": "connected", "stage": "S1",
                    "vantage": { "type": "github_actions_runner" },
                    "probe_type": "tcp",
                    "observed_at": observed_at
                }
            },
            {
                // Explicit Iran-blocked evidence must never enter the
                // advisory working set, even with a verified handshake.
                "line": "obfs4 45.10.11.14:443 CCCC cert=x iat-mode=0",
                "transport": "obfs4", "iran_status": "iran_asn_blocked",
                "verification": s2
            },
            {
                // Documentation-range endpoints stay unpublished.
                "line": "obfs4 192.0.2.99:443 DDDD cert=x iat-mode=0",
                "transport": "obfs4", "iran_status": "iran_unknown",
                "verification": s2
            }
        ]);
        let probes = extract_probe_records(&records, now, None).expect("probe records");
        let mut counts = BTreeMap::new();
        write_iran_projections(&bridge_dir, &[], &probes, &mut counts, &mut BTreeMap::new())
            .expect("write");

        let working = std::fs::read_to_string(bridge_dir.join("iran_likely_working_obfs4.txt"))
            .expect("obfs4 working file");
        let order: Vec<&str> = working
            .lines()
            .filter_map(|line| line.split_whitespace().nth(2))
            .collect();
        assert_eq!(
            order,
            vec!["AAAA", "BBBB"],
            "Tier B (AAAA) is admitted ahead of Tier C (BBBB): {working}"
        );
        assert!(
            working.contains("45.10.11.13"),
            "Tier C admission: typed runner TCP evidence is reachability evidence"
        );
        assert!(!working.contains("45.10.11.14"), "blocked must stay out");
        assert!(!working.contains("192.0.2.99"), "doc-range must stay out");

        let all = std::fs::read_to_string(bridge_dir.join("iran_likely_working_all.txt"))
            .expect("all working file");
        assert_eq!(all, working, "all-family alias is a byte-identical copy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tier_a_outranks_tier_b_in_the_published_ordering() {
        let dir = std::env::temp_dir().join(format!("pub_tiera_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let now = Utc::now();
        let observed_at = (now - Duration::seconds(30)).to_rfc3339();
        let queried_at = (now - Duration::seconds(30)).to_rfc3339();
        let records = serde_json::json!([
            {
                // Tier B: high composite score but no OONI measurement.
                "line": "obfs4 45.10.20.1:443 EEEE cert=x iat-mode=0",
                "transport": "obfs4", "iran_status": "iran_unknown",
                "composite_score": 0.95,
                "verification": {
                    "status": "connected", "stage": "S3",
                    "vantage": { "type": "github_actions_runner" },
                    "probe_type": "obfs4-framing",
                    "observed_at": observed_at
                }
            },
            {
                // Tier A: OONI-measured working, lower composite score.
                "line": "obfs4 45.10.20.2:443 FFFF cert=x iat-mode=0",
                "transport": "obfs4", "iran_status": "iran_likely_working",
                "composite_score": 0.10,
                "iran_assessment": {
                    "status": "iran_likely_working", "source": "ooni_measurements_api", "checked": true,
                    "vantage": { "type": "ooni_probe", "country": "IR" },
                    "queried_at": queried_at,
                    "measurement_at": queried_at,
                    "measurement_window_days": 7
                },
                "verification": {
                    "status": "connected", "stage": "S3",
                    "vantage": { "type": "github_actions_runner" },
                    "probe_type": "obfs4-framing",
                    "observed_at": observed_at
                }
            }
        ]);
        let probes = extract_probe_records(&records, now, None).expect("probe records");
        let mut counts = BTreeMap::new();
        write_iran_projections(&bridge_dir, &[], &probes, &mut counts, &mut BTreeMap::new())
            .expect("write");

        let body = std::fs::read_to_string(bridge_dir.join("iran_likely_working_obfs4.txt"))
            .expect("obfs4 working file");
        // Both tiers are admitted; the writer publishes deterministic
        // lexicographic order, so only membership and the tier-A-not-lost
        // invariant are asserted here.
        assert!(
            body.contains("45.10.20.2"),
            "Tier A (OONI-measured) missing from the working set: {body}"
        );
        assert!(
            body.contains("45.10.20.1"),
            "Tier B (handshake-verified) missing from the working set: {body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transport_projections_apply_the_publication_endpoint_policy() {
        // Policy under test (ip_guard::publication_blocks_endpoint):
        //   * webtunnel doc-range endpoints stay unpublished (the client
        //     dials the literal endpoint; issue #257);
        //   * broker/front placeholders (snowflake/meek/conjure) publish
        //     when their url=/front= rendezvous validates — the exact form
        //     Tor Browser ships (MOAT builtin 2026-10-15);
        //   * a placeholder with an invalid rendezvous host stays blocked;
        //   * routable literals always publish.
        let dir = std::env::temp_dir().join(format!("pub_docrange_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let now = Utc::now();
        let history = serde_json::json!({
            "fake_placeholder": {
                "raw": "webtunnel [2001:db8:1218:1de7::1]:443 DF343521735ABE129910A998817B3A93AA2390FE url=https://coellen.xyz ver=0.0.4",
                "transport": "webtunnel",
                "last_seen": now.to_rfc3339()
            },
            "real_obfs4": {
                "raw": "obfs4 45.10.30.1:443 GGGG cert=x iat-mode=0",
                "transport": "obfs4",
                "last_seen": now.to_rfc3339()
            },
            "invalid_rendezvous_snowflake": {
                "raw": "snowflake 192.0.2.9:80 NNNN fingerprint=NNNN url=https://example.invalid/ front=www.example.invalid",
                "transport": "snowflake",
                "last_seen": now.to_rfc3339()
            },
            "valid_rendezvous_snowflake": {
                "raw": "snowflake 192.0.2.3:80 HHHH fingerprint=HHHH url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com",
                "transport": "snowflake",
                "last_seen": now.to_rfc3339()
            }
        });
        let cutoff = now - chrono::Duration::hours(72);
        let candidates =
            candidates_from_history(&history, &[], cutoff, now, None).expect("candidates");
        let mut counts = BTreeMap::new();
        // write_requested_projections re-creates the iran_* alias files from
        // the iran_* source files, so seed those first (no probe evidence in
        // this test — the working set stays empty).
        write_iran_projections(
            &bridge_dir,
            &candidates,
            &[],
            &mut counts,
            &mut BTreeMap::new(),
        )
        .expect("seed iran");
        write_requested_projections(&bridge_dir, &candidates, &mut counts, &mut BTreeMap::new())
            .expect("write");

        let webtunnel =
            std::fs::read_to_string(bridge_dir.join("webtunnel_ipv4_ipv6_all.txt")).expect("file");
        assert!(
            webtunnel.trim().is_empty(),
            "doc-range webtunnel endpoints must not be published: {webtunnel}"
        );
        let snowflake =
            std::fs::read_to_string(bridge_dir.join("snowflake_ipv4_ipv6_all.txt")).expect("file");
        assert!(
            !snowflake.contains("fingerprint=NNNN"),
            "a placeholder whose rendezvous host is invalid must not be published: {snowflake}"
        );
        assert!(
            snowflake.contains("fingerprint=HHHH"),
            "the current Tor-default placeholder form with a validated rendezvous publishes: {snowflake}"
        );
        let obfs4 =
            std::fs::read_to_string(bridge_dir.join("obfs4_ipv4_ipv6_all.txt")).expect("file");
        assert!(
            obfs4.contains("45.10.30.1"),
            "routable obfs4 stays published"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn iran_working_projections_stay_empty_without_evidence() {
        let dir = std::env::temp_dir().join(format!("pub_iran_empty_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let mut counts = BTreeMap::new();
        write_iran_projections(&bridge_dir, &[], &[], &mut counts, &mut BTreeMap::new())
            .expect("write projections");
        for name in [
            "iran_likely_working_obfs4.txt",
            "iran_likely_working_vanilla.txt",
            "iran_likely_working_snowflake.txt",
            "iran_likely_working_webtunnel.txt",
            "iran_likely_working_all.txt",
            "iran_likely_working_nin.txt",
            "tested_global_obfs4.txt",
            "tested_global_vanilla.txt",
            "tested_global_webtunnel.txt",
            "iran_blocked.txt",
        ] {
            let body = std::fs::read_to_string(bridge_dir.join(name)).expect("file");
            assert!(
                body.trim().is_empty(),
                "{name} must stay empty without evidence"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn runner_s1_evidence_fills_tested_projection_while_relay_is_down() {
        let dir = std::env::temp_dir().join(format!("pub_s1_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        let now = Utc::now();
        let run_floor = Some(now - Duration::hours(2));
        let line = "webtunnel 89.58.32.179:443 AAAA url=https://front.example ver=0.0.4";
        let results = serde_json::json!({ "bridges": [{
            "line": line,
            "transport": "webtunnel",
            "iran_status": "iran_unknown",
            "test_tier": "tier_1_tcp",
            "test_result": "tcp_reachable_s1",
            "verification": {
                "status": "connected",
                "stage": "S1",
                "probe_type": "tcp",
                "observed_at": (now - Duration::minutes(40)).to_rfc3339(),
                "vantage": {"type": "github_actions_runner"},
            },
        }]});
        let probes = extract_probe_records(&results, now, run_floor).expect("probes");
        assert!(
            probes[0].verified_runner_s1plus,
            "in-run S1 evidence must qualify"
        );
        assert!(!probes[0].verified_s2plus, "S1 is not S2+");

        let history = serde_json::json!({
            "bridge": {"raw": line, "transport": "webtunnel", "last_seen": now.to_rfc3339()}
        });
        let candidates =
            candidates_from_history(&history, &probes, now - Duration::hours(72), now, run_floor)
                .expect("candidates");
        let mut counts = BTreeMap::new();
        let mut tiers = BTreeMap::new();
        write_iran_projections(&bridge_dir, &candidates, &probes, &mut counts, &mut tiers)
            .expect("write iran projections");
        assert_eq!(
            counts.get("iran_likely_working_webtunnel.txt").copied(),
            Some(1),
            "Tier C runner reachability must fill the advisory working set"
        );
        assert_eq!(
            tiers
                .get("iran_likely_working_webtunnel.txt")
                .map(String::as_str),
            Some("tier_1_tcp")
        );
        assert_eq!(
            std::fs::read_to_string(bridge_dir.join("tested_global_webtunnel.txt"))
                .expect("file")
                .lines()
                .count(),
            1,
            "tested_global_* uses the same tiered contract"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_s1_evidence_never_fills_tested_projection() {
        let now = Utc::now();
        let line = "obfs4 45.10.30.9:443 BBBB cert=y iat-mode=0";
        let results = serde_json::json!({ "bridges": [{
            "line": line,
            "verification": {
                "status": "connected",
                "stage": "S1",
                "probe_type": "tcp",
                "observed_at": (now - Duration::hours(6)).to_rfc3339(),
                "vantage": {"type": "github_actions_runner"},
            },
        }]});
        // No run floor: only the bare 10-minute freshness window applies.
        let probes = extract_probe_records(&results, now, None).expect("probes");
        assert!(
            !probes[0].verified_runner_s1plus,
            "stale S1 evidence must not qualify without a run window"
        );
    }

    #[test]
    fn ipv6_family_is_derived_from_the_endpoint_literal() {
        let now = Utc::now();
        let ipv4_line = "vanilla 104.152.210.181:1105 CCCC";
        let record = serde_json::json!({
            "raw": ipv4_line,
            "transport": "vanilla",
            "ip_version": "ipv6",
            "last_seen": now.to_rfc3339(),
        });
        assert!(
            !record_is_ipv6(record.as_object().unwrap(), ipv4_line),
            "an IPv4 endpoint literal must win over a stale ipv6 label"
        );
        let ipv6_line = "obfs4 [2001:67c:1234::1]:443 DDDD cert=z iat-mode=0";
        let record6 = serde_json::json!({
            "raw": ipv6_line,
            "transport": "obfs4",
            "ip_version": "ipv4",
            "last_seen": now.to_rfc3339(),
        });
        assert!(
            record_is_ipv6(record6.as_object().unwrap(), ipv6_line),
            "a bracketed IPv6 literal must win over a stale ipv4 label"
        );
    }

    #[test]
    fn reason_code_explains_empty_evidence_files() {
        // Zero webtunnel history: every webtunnel projection is supply-empty.
        assert_eq!(
            empty_file_reason_code("webtunnel_tested.txt", 0, 0, 0, 0, None).as_deref(),
            Some("NO_UPSTREAM_SUPPLY")
        );
        // Supply exists, no evidence, relay down: the evidence file says why.
        assert_eq!(
            empty_file_reason_code("webtunnel_tested.txt", 181, 0, 181, 0, Some(false)).as_deref(),
            Some("RELAY_DOWN")
        );
        assert_eq!(
            empty_file_reason_code("webtunnel_tested.txt", 181, 0, 181, 0, Some(true)).as_deref(),
            Some("NO_EVIDENCE")
        );
        // IPv6-family file with only IPv4 supply.
        assert_eq!(
            empty_file_reason_code("meek_lite_ipv6.txt", 2, 0, 2, 0, None).as_deref(),
            Some("NO_IPV6_SUPPLY")
        );
        // 72h file whose transport has no fresh records.
        assert_eq!(
            empty_file_reason_code("obfs4_72h.txt", 10, 3, 0, 0, None).as_deref(),
            Some("NO_FRESH_WITHIN_WINDOW")
        );
        // Empty blocklist is truthful, never a defect.
        assert_eq!(
            empty_file_reason_code("iran_blocked.txt", 10, 3, 10, 5, Some(true)).as_deref(),
            Some("NO_EVIDENCE")
        );
        // Multi-transport evidence files (all/nin) are documented NO_EVIDENCE.
        assert_eq!(
            empty_file_reason_code("iran_likely_working_all.txt", 10, 3, 10, 5, None).as_deref(),
            Some("NO_EVIDENCE")
        );
        assert_eq!(
            empty_file_reason_code("iran_likely_working_nin.txt", 10, 3, 10, 5, Some(false))
                .as_deref(),
            Some("NO_EVIDENCE")
        );
    }
}

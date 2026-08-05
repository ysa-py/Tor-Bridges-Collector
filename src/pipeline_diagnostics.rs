//! Whole-run diagnostics and bounded self-healing planning.
//!
//! This module is deliberately independent from GitHub's log transport.  It
//! accepts the complete text emitted by a job (or a locally captured
//! equivalent), examines every line, and produces a deterministic JSON report
//! that can be uploaded as a CI artifact.  A green job is not considered
//! healthy when it contains a swallowed fallback, an empty source result, or a
//! skipped required stage.
//!
//! The remediation layer only describes and performs safe, idempotent local
//! repairs.  It never edits source code or handles credentials.  Network
//! retries, alternate-source selection, and stage replay are represented in a
//! machine-readable plan so a workflow can execute the affected stage rather
//! than blindly rerunning the entire pipeline.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Canonical stages used by the collector and its auxiliary reports.  The
/// parser also accepts arbitrary future stage names; this list is a coverage
/// guard for the current pipeline.
pub const REQUIRED_STAGES: &[&str] = &[
    "Stage 00",
    "Stage 0s",
    "Stage 0",
    "Stage 0b",
    "Stage 0c",
    "Stage 1",
    "Stage 2",
    "Stage 3",
    "Stage 4",
    "Stage 5",
    "Stage 6a",
    "Stage 6b",
    "Stage 7",
    "Stage 8",
    "Stage 8b",
    "Stage 8c",
    "Stage 8d",
    "Stage 8d2",
    "Stage 8e",
    "Stage 8f",
    "Stage 8g",
    "Stage 8h",
    "Stage 8i",
    "Stage 8i-smart",
    "Stage 8j",
    "Stage 8k",
    "Stage 8l",
    "Stage 8m",
    "Stage 8n",
    "Stage 8o",
    "Stage 8p",
    "Stage 8q",
    "Stage 8r",
    "Stage 9",
    "Stage 9b",
    "Stage 10",
    "Stage 11",
];

/// Anomaly category emitted by the full-log classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    HardFailure,
    NonZeroExit,
    EmptyOutput,
    ShortOutput,
    FailsafeFallback,
    Timeout,
    RateLimit,
    DnsTlsError,
    ArtifactDigestMismatch,
    StaleCache,
    SkippedStage,
    HandshakeFailure,
    SourceGap,
    MoatEmpty,
}

impl AnomalyKind {
    /// Stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HardFailure => "hard_failure",
            Self::NonZeroExit => "non_zero_exit",
            Self::EmptyOutput => "empty_output",
            Self::ShortOutput => "short_output",
            Self::FailsafeFallback => "failsafe_fallback",
            Self::Timeout => "timeout",
            Self::RateLimit => "rate_limit",
            Self::DnsTlsError => "dns_tls_error",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::StaleCache => "stale_cache",
            Self::SkippedStage => "skipped_stage",
            Self::HandshakeFailure => "handshake_failure",
            Self::SourceGap => "source_gap",
            Self::MoatEmpty => "moat_empty",
        }
    }
}

/// Severity of an event. Fallbacks and empty outputs are errors even when the
/// shell command exited zero because they are functional collection defects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Warning,
    Error,
}

/// One classified line from the input log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    pub line_number: usize,
    pub step: String,
    pub kind: AnomalyKind,
    pub severity: Severity,
    pub message: String,
    pub raw_line: String,
    pub remediation: String,
}

/// Per-kind counts make trend comparisons cheap without reparsing events.
pub type Counts = BTreeMap<String, usize>;

/// Full diagnostic report. `total_lines` proves that the complete input was
/// read, rather than a grep-selected excerpt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub schema_version: u8,
    pub generated_at: String,
    pub engine: String,
    pub input: String,
    pub total_lines: usize,
    pub stages_seen: Vec<String>,
    pub required_stages_missing: Vec<String>,
    pub events: Vec<DiagnosticEvent>,
    pub counts: Counts,
    pub errors: usize,
    pub warnings: usize,
    pub failsafe_triggers: usize,
    pub unresolved: usize,
    pub status: String,
    pub remediation_plan: Vec<RemediationAction>,
}

/// A safe action that a workflow may execute. `command` is informational and
/// never contains a token or secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub action_id: String,
    pub stage: String,
    pub kind: String,
    pub reason: String,
    pub command: String,
    pub idempotent: bool,
}

/// Result of local safe repairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairResult {
    pub action: String,
    pub path: String,
    pub changed: bool,
    pub detail: String,
}

/// Parse a complete log. The function does not stop at the first failure and
/// does not discard ordinary lines: `total_lines` is always the number of
/// input lines.
#[must_use]
pub fn analyze_log(input: &str, input_name: impl Into<String>) -> DiagnosticReport {
    let lines: Vec<&str> = input.lines().collect();
    let mut step = String::from("job");
    let mut stages = Vec::<String>::new();
    let mut events = Vec::new();

    for (index, raw) in lines.iter().enumerate() {
        if let Some(detected) = detect_step(raw) {
            step = detected;
        }
        if let Some(stage) = detect_stage(raw) {
            step = stage.clone();
            if !stages.contains(&stage) {
                stages.push(stage);
            }
        }
        if let Some((kind, severity, message)) = classify_line(raw) {
            let remediation = remediation_text(kind);
            events.push(DiagnosticEvent {
                line_number: index + 1,
                step: step.clone(),
                kind,
                severity,
                message,
                raw_line: redact_log_line(raw),
                remediation: remediation.to_string(),
            });
        }
    }

    stages.sort();
    let required_stages_missing = REQUIRED_STAGES
        .iter()
        .filter(|required| !stages.iter().any(|seen| seen.starts_with(*required)))
        .map(|stage| (*stage).to_string())
        .collect::<Vec<_>>();

    let mut counts = Counts::new();
    let mut errors = 0;
    let mut warnings = 0;
    let mut failsafe_triggers = 0;
    for event in &events {
        *counts.entry(event.kind.as_str().to_string()).or_default() += 1;
        match event.severity {
            Severity::Error => errors += 1,
            Severity::Warning => warnings += 1,
        }
        if event.kind == AnomalyKind::FailsafeFallback {
            failsafe_triggers += 1;
        }
    }

    let remediation_plan = build_remediation_plan(&events);
    let unresolved = events.len();
    let status = if errors > 0 {
        "failed"
    } else if warnings > 0 || !required_stages_missing.is_empty() {
        "degraded"
    } else {
        "healthy"
    };

    DiagnosticReport {
        schema_version: 1,
        generated_at: Utc::now().to_rfc3339(),
        engine: "torshield-rust-whole-run-diagnostics-v2".to_string(),
        input: input_name.into(),
        total_lines: lines.len(),
        stages_seen: stages,
        required_stages_missing,
        events,
        counts,
        errors,
        warnings,
        failsafe_triggers,
        unresolved,
        status: status.to_string(),
        remediation_plan,
    }
}

/// Analyze a file without loading a partial tail. Files are read as bytes and
/// decoded lossily so one malformed byte cannot hide later diagnostics.
pub fn analyze_log_file(path: &Path) -> Result<DiagnosticReport, std::io::Error> {
    let bytes = fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(analyze_log(&text, path.display().to_string()))
}

/// Serialize a report with an atomic replace. A partially written report must
/// never be mistaken for a healthy report by a later workflow step.
pub fn write_report(path: &Path, report: &DiagnosticReport) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    let temporary = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("report"),
        std::process::id()
    ));
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

/// Perform only safe, local, idempotent repairs. The function intentionally
/// does not create bridge data or invent a successful probe result.
pub fn safe_repairs(repo_root: &Path, report: &DiagnosticReport) -> Vec<RepairResult> {
    let mut results = Vec::new();
    let data = repo_root.join("data");
    if fs::create_dir_all(&data).is_ok() {
        results.push(RepairResult {
            action: "ensure_data_directory".to_string(),
            path: data.display().to_string(),
            changed: false,
            detail: "data directory is available".to_string(),
        });
    }

    // Empty JSON documents are repaired to [] only when they are clearly an
    // output document. We never overwrite non-empty or malformed JSON here.
    let bridge_dir = repo_root.join("bridge");
    if let Ok(entries) = fs::read_dir(&bridge_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(metadata) = fs::metadata(&path) else { continue };
            if metadata.len() != 0 {
                continue;
            }
            if fs::write(&path, b"[]\n").is_ok() {
                results.push(RepairResult {
                    action: "initialise_empty_json_output".to_string(),
                    path: path.display().to_string(),
                    changed: true,
                    detail: "empty output replaced with a valid JSON array".to_string(),
                });
            }
        }
    }

    if report.events.iter().any(|event| event.kind == AnomalyKind::StaleCache) {
        // Do not delete caches automatically. Removing a shared Cargo cache
        // can make a transient outage worse; emit an explicit plan instead.
        results.push(RepairResult {
            action: "cache_invalidation_deferred".to_string(),
            path: repo_root.display().to_string(),
            changed: false,
            detail: "cache invalidation is planned for the affected stage only".to_string(),
        });
    }
    results
}

/// Human-readable single-line summary for `$GITHUB_STEP_SUMMARY`.
#[must_use]
pub fn human_summary(report: &DiagnosticReport) -> String {
    format!(
        "Whole-run diagnostics: status={} lines={} errors={} warnings={} failsafe_triggers={} unresolved={} stages_missing={}",
        report.status,
        report.total_lines,
        report.errors,
        report.warnings,
        report.failsafe_triggers,
        report.unresolved,
        report.required_stages_missing.len()
    )
}

fn build_remediation_plan(events: &[DiagnosticEvent]) -> Vec<RemediationAction> {
    let mut plan = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for event in events {
        let key = format!("{}:{}", event.step, event.kind.as_str());
        if !seen.insert(key) {
            continue;
        }
        let (kind, command) = match event.kind {
            AnomalyKind::RateLimit | AnomalyKind::Timeout | AnomalyKind::DnsTlsError => (
                "retry_with_backoff",
                format!("rerun affected stage '{}' with bounded jittered retries", event.step),
            ),
            AnomalyKind::FailsafeFallback | AnomalyKind::SourceGap | AnomalyKind::MoatEmpty => (
                "alternate_source_then_replay",
                format!("refresh alternate sources and replay only '{}'", event.step),
            ),
            AnomalyKind::HandshakeFailure => (
                "revalidate_probe_toolchain",
                format!("verify obfs4proxy/lyrebird and replay only '{}'", event.step),
            ),
            AnomalyKind::SkippedStage => (
                "restore_required_toolchain",
                format!("install the required tool and replay only '{}'", event.step),
            ),
            AnomalyKind::ArtifactDigestMismatch => (
                "rebuild_artifact",
                format!("invalidate the affected artifact and rebuild '{}'", event.step),
            ),
            AnomalyKind::StaleCache => (
                "invalidate_stage_cache",
                format!("invalidate only the cache key used by '{}'", event.step),
            ),
            _ => (
                "inspect_and_replay",
                format!("replay only '{}' after remediation", event.step),
            ),
        };
        plan.push(RemediationAction {
            action_id: format!("{}-{}", event.step.replace(' ', "_"), kind),
            stage: event.step.clone(),
            kind: kind.to_string(),
            reason: event.message.clone(),
            command,
            idempotent: true,
        });
    }
    plan
}

fn remediation_text(kind: AnomalyKind) -> &'static str {
    match kind {
        AnomalyKind::FailsafeFallback => "retry alternate sources; do not count static fallback as live yield",
        AnomalyKind::HandshakeFailure => "verify the PT harness and report transport verification separately",
        AnomalyKind::MoatEmpty => "accept top-level MOAT and settings bridge_strings schemas, then retry",
        AnomalyKind::SourceGap => "try redundant sources and retain the previous non-empty archive",
        AnomalyKind::SkippedStage => "install the required toolchain and replay this stage",
        AnomalyKind::ArtifactDigestMismatch => "rebuild the affected artifact and verify its digest",
        AnomalyKind::StaleCache => "invalidate only the affected cache key and refetch dependencies",
        AnomalyKind::RateLimit | AnomalyKind::Timeout | AnomalyKind::DnsTlsError => "retry with exponential backoff and a bounded alternate endpoint",
        _ => "fail the health gate or replay the affected stage after diagnosis",
    }
}

fn classify_line(line: &str) -> Option<(AnomalyKind, Severity, String)> {
    let lower = line.to_ascii_lowercase();
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Most specific signals first. This prevents a 0/255 handshake from being
    // downgraded to a generic warning merely because the line contains one.
    if lower.contains("0/") && lower.contains("handshake")
        || lower.contains("handshake")
            && (lower.contains("only ") || lower.contains("failed") || lower.contains("minimum"))
    {
        return Some((
            AnomalyKind::HandshakeFailure,
            Severity::Error,
            trimmed.to_string(),
        ));
    }
    if lower.contains("failsafe:")
        && (lower.contains("force-populated")
            || lower.contains("fallback")
            || lower.contains("wrote "))
        || lower.contains("retaining tcp-reachable set")
    {
        return Some((
            AnomalyKind::FailsafeFallback,
            Severity::Error,
            trimmed.to_string(),
        ));
    }
    if lower.contains("moat")
        && (lower.contains("0 bridges")
            || lower.contains("no usable bridges")
            || lower.contains("empty_200")
            || lower.contains("no bridge lines"))
    {
        return Some((AnomalyKind::MoatEmpty, Severity::Error, trimmed.to_string()));
    }
    if lower.contains("no usable source")
        || lower.contains("source discovery gap")
        || lower.contains("source outage")
    {
        return Some((AnomalyKind::SourceGap, Severity::Error, trimmed.to_string()));
    }
    if lower.contains("digest mismatch")
        || lower.contains("sha256 mismatch")
        || lower.contains("hash mismatch")
    {
        return Some((
            AnomalyKind::ArtifactDigestMismatch,
            Severity::Error,
            trimmed.to_string(),
        ));
    }
    if lower.contains("cache")
        && (lower.contains("stale")
            || lower.contains("poison")
            || lower.contains("invalid")
            || lower.contains("mismatch"))
    {
        return Some((AnomalyKind::StaleCache, Severity::Warning, trimmed.to_string()));
    }
    if lower.contains("rate limit")
        || lower.contains("rate-limit")
        || lower.contains("http 429")
        || lower.contains("too many requests")
    {
        return Some((AnomalyKind::RateLimit, Severity::Warning, trimmed.to_string()));
    }
    if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("deadline exceeded")
    {
        return Some((AnomalyKind::Timeout, Severity::Error, trimmed.to_string()));
    }
    if lower.contains("dns")
        || lower.contains("tls handshake failed")
        || lower.contains("ssl error")
        || lower.contains("certificate verify")
        || lower.contains("connection refused")
    {
        return Some((AnomalyKind::DnsTlsError, Severity::Warning, trimmed.to_string()));
    }
    if lower.contains("zig not available")
        || lower.contains("skipping stage")
        || lower.contains("stage 8q") && lower.contains("skip")
    {
        return Some((
            AnomalyKind::SkippedStage,
            Severity::Error,
            trimmed.to_string(),
        ));
    }
    if lower.contains("no usable")
        || lower.contains("empty body")
        || lower.contains("no output")
        || lower.contains("0 bridges fetched")
        || lower.contains("0 bridges")
    {
        return Some((AnomalyKind::EmptyOutput, Severity::Error, trimmed.to_string()));
    }
    if lower.contains("short output")
        || lower.contains("below minimum")
        || lower.contains("too few bridges")
        || lower.contains("only 1 bridge")
        || lower.contains("only 2 bridges")
        || lower.contains("only 3 bridges")
        || lower.contains("only 4 bridges")
    {
        return Some((AnomalyKind::ShortOutput, Severity::Error, trimmed.to_string()));
    }

    if let Some(code) = parse_exit_code(&lower) {
        if code != 0 {
            return Some((
                AnomalyKind::NonZeroExit,
                Severity::Error,
                format!("{} (exit code {})", trimmed, code),
            ));
        }
    }
    if lower.contains("::error::")
        || lower.starts_with("error:")
        || lower.contains(" process completed with exit code ")
        || lower.contains("panic")
        || lower.contains("fatal:")
    {
        return Some((AnomalyKind::HardFailure, Severity::Error, trimmed.to_string()));
    }
    if lower.contains("warning")
        || lower.contains("unavailable")
        || lower.contains("fallback")
        || lower.contains("failed")
    {
        return Some((AnomalyKind::HardFailure, Severity::Warning, trimmed.to_string()));
    }
    None
}

fn parse_exit_code(line: &str) -> Option<i64> {
    for marker in ["exit code", "exit_code", "status code"] {
        let Some(start) = line.find(marker) else { continue };
        let tail = &line[start + marker.len()..];
        let digits: String = tail
            .chars()
            .skip_while(|character| !character.is_ascii_digit() && *character != '-')
            .take_while(|character| character.is_ascii_digit() || *character == '-')
            .collect();
        if !digits.is_empty() {
            if let Ok(value) = digits.parse() {
                return Some(value);
            }
        }
    }
    None
}

fn detect_step(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("##[group]Run ") {
        return Some(rest.trim().to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("Run ") {
        return Some(rest.trim().to_string());
    }
    None
}

fn detect_stage(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker = lower.find("stage ")?;
    let original = &line[marker..];
    let mut end = original.len();
    for delimiter in ['—', ':', '|'] {
        if let Some(position) = original.find(delimiter) {
            end = end.min(position);
        }
    }
    let candidate = original[..end].trim();
    if candidate.len() >= 7 && candidate[..5].eq_ignore_ascii_case("stage") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn redact_log_line(line: &str) -> String {
    // Logs should never contain secrets, but the report is an artifact and is
    // therefore defensively redacted before persistence.
    let mut output = line.to_string();
    for marker in ["Authorization: Bearer ", "x-access-token:"] {
        let lower = output.to_ascii_lowercase();
        if let Some(start) = lower.find(&marker.to_ascii_lowercase()) {
            let value_start = start + marker.len();
            let end = output[value_start..]
                .find(char::is_whitespace)
                .map_or(output.len(), |offset| value_start + offset);
            output.replace_range(value_start..end, "***");
        }
    }
    output
}

/// Convenience for dashboards and tests.
#[must_use]
pub fn report_json(report: &DiagnosticReport) -> Value {
    serde_json::to_value(report).unwrap_or_else(|_| json!({"status":"failed"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_every_line_and_classifies_silent_failures() {
        let log = "ordinary\nMOAT [builtin]: 0 bridges fetched\nobfs4 verify: only 0/255 handshakes (minimum 51); retaining TCP-reachable set\nFAILSAFE: force-populated webtunnel.txt with 4 static fallback lines\n";
        let report = analyze_log(log, "fixture");
        assert_eq!(report.total_lines, 4);
        assert_eq!(report.events.len(), 3);
        assert_eq!(report.failsafe_triggers, 1);
        assert_eq!(report.status, "failed");
        assert!(report
            .events
            .iter()
            .any(|event| event.kind == AnomalyKind::MoatEmpty));
    }

    #[test]
    fn recognizes_nonzero_exit_and_tool_skip() {
        let report = analyze_log(
            "Stage 8q — Zig ultra-fast TCP bridge pre-screener\nZig not available — skipping Stage 8q\nProcess completed with exit code 127\n",
            "fixture",
        );
        assert!(report
            .events
            .iter()
            .any(|event| event.kind == AnomalyKind::SkippedStage));
        assert!(report
            .events
            .iter()
            .any(|event| event.kind == AnomalyKind::NonZeroExit));
    }

    #[test]
    fn remediation_plan_is_deduplicated_and_secret_safe() {
        let report = analyze_log(
            "warning: HTTP 429\nwarning: HTTP 429 Authorization: Bearer secret\n",
            "fixture",
        );
        assert_eq!(report.remediation_plan.len(), 1);
        assert!(report.remediation_plan[0].command.contains("backoff"));
        assert!(!report.events[1].raw_line.contains("secret"));
    }

    #[test]
    fn healthy_log_has_no_events() {
        let report = analyze_log("Stage 1 — scraper\ncollection complete\n", "fixture");
        assert!(report.events.is_empty());
        assert_eq!(report.status, "degraded");
        assert!(!report.required_stages_missing.is_empty());
    }
}

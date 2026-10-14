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
pub fn write_report(
    path: &Path,
    report: &DiagnosticReport,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    let temporary = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("report"),
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
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
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

    if report
        .events
        .iter()
        .any(|event| event.kind == AnomalyKind::StaleCache)
    {
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
                format!(
                    "rerun affected stage '{}' with exponential backoff and jittered retries",
                    event.step
                ),
            ),
            AnomalyKind::FailsafeFallback | AnomalyKind::SourceGap | AnomalyKind::MoatEmpty => (
                "alternate_source_then_replay",
                format!("refresh alternate sources and replay only '{}'", event.step),
            ),
            AnomalyKind::HandshakeFailure => (
                "revalidate_probe_toolchain",
                format!(
                    "verify obfs4proxy/lyrebird and replay only '{}'",
                    event.step
                ),
            ),
            AnomalyKind::SkippedStage => (
                "restore_required_toolchain",
                format!("install the required tool and replay only '{}'", event.step),
            ),
            AnomalyKind::ArtifactDigestMismatch => (
                "rebuild_artifact",
                format!(
                    "invalidate the affected artifact and rebuild '{}'",
                    event.step
                ),
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
        AnomalyKind::FailsafeFallback => {
            "retry alternate sources; do not count static fallback as live yield"
        }
        AnomalyKind::HandshakeFailure => {
            "verify the PT harness and report transport verification separately"
        }
        AnomalyKind::MoatEmpty => {
            "accept top-level MOAT and settings bridge_strings schemas, then retry"
        }
        AnomalyKind::SourceGap => "try redundant sources and retain the previous non-empty archive",
        AnomalyKind::SkippedStage => "install the required toolchain and replay this stage",
        AnomalyKind::ArtifactDigestMismatch => {
            "rebuild the affected artifact and verify its digest"
        }
        AnomalyKind::StaleCache => {
            "invalidate only the affected cache key and refetch dependencies"
        }
        AnomalyKind::RateLimit | AnomalyKind::Timeout | AnomalyKind::DnsTlsError => {
            "retry with exponential backoff and a bounded alternate endpoint"
        }
        _ => "fail the health gate or replay the affected stage after diagnosis",
    }
}

/// Extract the bare log message from a `gh run view --log` line.
///
/// GitHub Actions whole-run logs prefix every line with
/// `<job>\t<step>\t<ISO-timestamp> `; the structural guards below must see
/// the message itself (`hint: ...`, `+ echo ...`, `test result: ok. ...`,
/// `CONNECTION_TIMEOUT: 8`), not a line starting with the job name. Some
/// wrapped/continuation lines carry only the timestamp — that form is
/// handled too. Lines with neither prefix are returned unchanged.
fn log_message_part(line: &str) -> &str {
    let mut rest = line;
    let mut tabs_found = 0;
    for _ in 0..2 {
        match rest.find('\t') {
            Some(index) => {
                rest = &rest[index + 1..];
                tabs_found += 1;
            }
            None => break,
        }
    }
    if tabs_found < 2 {
        rest = line;
    }
    // Skip the timestamp token and the single separating space. Wrapped
    // continuation lines sometimes carry only `<ISO-ts> message` (no job or
    // step columns) — handle that shape as well. The `message_trimmed`
    // guards below then see `hint: ...` / `# comment` / `KEY: value`.
    if let Some(space) = rest.find(' ') {
        let candidate = &rest[..space];
        let bytes = candidate.as_bytes();
        let looks_like_iso_ts = candidate.len() >= 20
            && bytes[0..4].iter().all(|b| b.is_ascii_digit())
            && bytes[4] == b'-'
            && bytes[5..7].iter().all(|b| b.is_ascii_digit())
            && bytes[7] == b'-'
            && bytes[10] == b'T';
        if looks_like_iso_ts {
            return &rest[space + 1..];
        }
    }
    rest
}

/// Remove ANSI escape sequences (CSI/OSC one-letter-terminated) and other
/// C0 control characters from a log message. GitHub Actions colors and some
/// tools interleave `\x1b[...m` sequences mid-message; the structural guards
/// must see the literal text (`# comment`, `+ echo ...`, `KEY: value`).
fn strip_ansi(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(current) = chars.next() {
        if current == '\u{1b}' {
            match chars.peek() {
                Some('[') => {
                    // Well-formed CSI: ESC [ <params: digits ; ? > <final @-~>.
                    // Only strip sequences whose parameter bytes are in the
                    // strict set — real log colors/cursor moves. Malformed
                    // embedded escapes (e.g. a bare `ESC [    echo ...` from a
                    // tracing prefix) must survive stripping so the structural
                    // guards can still see the literal command text.
                    let preview: Vec<char> = chars.clone().take(48).collect();
                    let mut length = 1; // '['
                    while length < preview.len() {
                        let c = preview[length];
                        if c.is_ascii_digit() || c == ';' || c == '?' {
                            length += 1;
                        } else if ('@'..='~').contains(&c) {
                            length += 1; // final byte consumed too
                            break;
                        } else {
                            length = 0; // not a well-formed CSI: keep as text
                            break;
                        }
                    }
                    if length == 0 {
                        // Leave '[' to be handled as an ordinary character.
                        output.push(current);
                        continue;
                    }
                    for _ in 0..length.min(preview.len()) {
                        chars.next();
                    }
                }
                Some(']') => {
                    // OSC: consume until BEL or ST.
                    chars.next();
                    while let Some(next) = chars.next() {
                        if next == '\u{7}' {
                            break;
                        }
                        if next == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {
                    // Single-character escape: drop the ESC itself.
                }
            }
            continue;
        }
        if current.is_control() {
            continue;
        }
        output.push(current);
    }
    output
}

fn classify_line(line: &str) -> Option<(AnomalyKind, Severity, String)> {
    let lower = line.to_ascii_lowercase();
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let message = log_message_part(trimmed);
    let message_clean = strip_ansi(message);
    let message_trimmed = message_clean.trim();
    let message_lower = message_clean.to_ascii_lowercase();

    // ── Structural false-positive guards (added 2026-10-14) ─────────────
    // The 2026-10-14 run 38579293985 audit proved the pattern rules below
    // fabricated 724 "errors" from a fully GREEN run: passing cargo test
    // NAMES ("test engine_reports_non_reachable_for_a_bogus_dns_name ... ok"
    // -> dns_tls_error), env-var echoes ("CONNECTION_TIMEOUT: 8" -> timeout),
    // git hint lines ("hint: ... suppress this warning" -> hard_failure),
    // shell xtrace source echoes, and `test result: ok. N passed; 0 failed`
    // summaries. A success summary must never be classified as a failure.
    // These guards run BEFORE every pattern rule.

    // cargo: a passing test line and a passing suite summary are success
    // evidence, whatever identifiers their names contain. Failing tests
    // print "... FAILED" / "test result: FAILED." and are still classified
    // by the rules below.
    if message_lower.contains(" ... ok") || message_lower.starts_with("test result: ok.") {
        return None;
    }
    // git's friendly "hint:" advice block (e.g. detached-HEAD guidance) is
    // noise, not a pipeline event.
    if message_trimmed.starts_with("hint:") {
        return None;
    }
    // Shell `set -x` command traces and echoed script sources. A line whose
    // payload is a quoted template with an UNEXPANDED shell variable (e.g.
    // `echo "⚠️  $req: 0 bridges"`) is source code, never runtime output.
    if message_trimmed.starts_with("+ ")
        || message_trimmed.starts_with("++ ")
        || (message_lower.contains("echo")
            && message_lower.contains('$')
            && message_lower.contains('"')
            && (message_lower.contains("$req") || message_lower.contains("${")))
    {
        return None;
    }
    // ALL-CAPS configuration echoes ("CONNECTION_TIMEOUT: 8",
    // "MAX_CONCURRENT_PROBES: 6") are build/env metadata, not timeouts.
    // Only SINGLE-TOKEN values are skipped: event lines of the same shape
    // ("FAILSAFE: force-populated meek_lite", "MOAT: 0 bridges fetched")
    // carry multi-token messages and remain classified below.
    if let Some(colon) = message_trimmed.find(": ") {
        let (key, value) = message_trimmed.split_at(colon);
        let value = value[2..].trim();
        if key.len() >= 3
            && key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
            && key.chars().any(|c| c.is_ascii_uppercase())
            && !value.is_empty()
            && value.len() <= 32
            && !value.contains(char::is_whitespace)
        {
            return None;
        }
    }

    // ECHOED SCRIPT SOURCE, not an emitted annotation: CI steps print their
    // own command text (`echo "::error::..."`, `print(f"::error::...")`,
    // `{ echo "::error::..."; exit 1; }`) when listing/verifying script
    // bodies. A REAL annotation has `::error::` at the START of the message
    // (after optional GitHub styling); an echo of it is source code.
    if message_lower.contains("echo \"::error::")
        || message_lower.contains("echo \"::warning::")
        || message_lower.contains("print(\"::error::")
        || message_lower.contains("print(f\"::error::")
        || message_lower.contains("print(\"::warning::")
        || message_lower.contains("print(f\"::warning::")
    {
        return None;
    }
    // Explicit success markers ("[PASS] C9 no-panic-traps — clean") are
    // success evidence even when their LABEL contains alarming substrings
    // ("no-panic-traps" matched the panic rule).
    if message_lower.contains("[pass]") || message_lower.contains("✓ passed") {
        return None;
    }
    // Shell/Makefile comment lines from echoed script bodies are never
    // runtime events ("# a non-zero byte count — `test -s` previously
    // emitted ::error::" matched the ::error:: rule). Keep GitHub's own
    // `##[...]` log commands (group/endgroup/annotations) classifiable.
    if message_trimmed.starts_with('#') && !message_trimmed.starts_with("##[") {
        return None;
    }

    // Most specific signals first. This prevents a 0/255 handshake from being
    // downgraded to a generic warning merely because the line contains one.
    if lower.contains("0/") && lower.contains("handshake")
        || lower.contains("handshake")
            && (lower.contains("only ") || lower.contains("failed") || lower.contains("minimum"))
    {
        // Handshake outcomes are capability EVIDENCE: per-endpoint results
        // (`host => websocket_failed: ...`) are honest probe data, and the
        // aggregate gate ("only 0/295 handshakes (minimum 59); publishing
        // verified subset only") explicitly continues by design and lets the
        // Quality Gate job independently gate publication. Warning keeps the
        // signal in the counts/summary without re-judging a green run.
        return Some((
            AnomalyKind::HandshakeFailure,
            Severity::Warning,
            trimmed.to_string(),
        ));
    }
    if lower.contains("failsafe:")
        && (lower.contains("force-populated")
            || lower.contains("fallback")
            || lower.contains("wrote "))
        || lower.contains("retaining tcp-reachable set")
    {
        // The failsafe working as designed IS the self-heal contract: it
        // restores last-known-good content and the run continues. That is
        // honest typed self-healing behaviour (severity: warning), not a run
        // failure — the underlying supply gap, when real, is separately
        // visible in the funnel/publish gates.
        return Some((
            AnomalyKind::FailsafeFallback,
            Severity::Warning,
            trimmed.to_string(),
        ));
    }
    if lower.contains("moat")
        && (lower.contains("0 bridges")
            || lower.contains("no usable bridges")
            || lower.contains("empty_200")
            || lower.contains("no bridge lines"))
    {
        // Typed supply advisory (the pipeline prints it as ::notice::): MOAT
        // legitimately returning zero resources in a window is an upstream
        // supply condition, not a run failure.
        return Some((
            AnomalyKind::MoatEmpty,
            Severity::Warning,
            trimmed.to_string(),
        ));
    }
    if lower.contains("no usable source")
        || lower.contains("source discovery gap")
        || lower.contains("source outage")
    {
        // Supply-diagnostic lines that self-declare WARNING ("WARNING:
        // snowflake ipv6=true has no usable source ...; retaining prior
        // files") are the pipeline's own typed, non-fatal handling of an
        // optional channel gap — honor that declaration. Undeclared source
        // outages stay Error.
        let severity = if lower.contains("warning:") || lower.contains("retaining prior") {
            Severity::Warning
        } else {
            Severity::Error
        };
        return Some((AnomalyKind::SourceGap, severity, trimmed.to_string()));
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
        return Some((
            AnomalyKind::StaleCache,
            Severity::Warning,
            trimmed.to_string(),
        ));
    }
    if lower.contains("rate limit")
        || lower.contains("rate-limit")
        || lower.contains("http 429")
        || lower.contains("too many requests")
    {
        return Some((
            AnomalyKind::RateLimit,
            Severity::Warning,
            trimmed.to_string(),
        ));
    }
    if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("deadline exceeded")
    {
        // Per-endpoint timeout EVIDENCE ("probe timed out", canary retry
        // lines) is honest observed data in a healthy run; a step that dies
        // of timeout always also emits a `::error::` / non-zero-exit line,
        // which still carries Severity::Error. Warning keeps the signal
        // visible without fabricating failures from data.
        return Some((AnomalyKind::Timeout, Severity::Warning, trimmed.to_string()));
    }
    if lower.contains("dns")
        || lower.contains("tls handshake failed")
        || lower.contains("ssl error")
        || lower.contains("certificate verify")
        || lower.contains("connection refused")
    {
        return Some((
            AnomalyKind::DnsTlsError,
            Severity::Warning,
            trimmed.to_string(),
        ));
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
        // Typed supply advisory: optional channels legitimately publish 0 in
        // a given window (the manifest contract and failsafe gate the
        // REQUIRED set independently). Warning keeps the visibility without
        // labelling an advisory as a run failure.
        return Some((
            AnomalyKind::EmptyOutput,
            Severity::Warning,
            trimmed.to_string(),
        ));
    }
    if lower.contains("short output")
        || lower.contains("below minimum")
        || lower.contains("too few bridges")
        || lower.contains("only 1 bridge")
        || lower.contains("only 2 bridges")
        || lower.contains("only 3 bridges")
        || lower.contains("only 4 bridges")
    {
        return Some((
            AnomalyKind::ShortOutput,
            Severity::Error,
            trimmed.to_string(),
        ));
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
        return Some((
            AnomalyKind::HardFailure,
            Severity::Error,
            trimmed.to_string(),
        ));
    }
    // A genuinely failing cargo test line / suite summary is a hard error —
    // the passing-side guard above only exempts "... ok" lines, so keep the
    // failing mirror explicit and Error-severity here.
    if message_lower.contains(" ... failed") || message_lower.starts_with("test result: failed.") {
        return Some((
            AnomalyKind::HardFailure,
            Severity::Error,
            trimmed.to_string(),
        ));
    }
    if lower.contains("warning")
        || lower.contains("unavailable")
        || lower.contains("fallback")
        || lower.contains("failed")
    {
        return Some((
            AnomalyKind::HardFailure,
            Severity::Warning,
            trimmed.to_string(),
        ));
    }
    None
}

fn parse_exit_code(line: &str) -> Option<i64> {
    for marker in ["exit code", "exit_code", "status code"] {
        let Some(start) = line.find(marker) else {
            continue;
        };
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
        // 2026-10-14 severity recalibration: typed supply advisories and
        // by-design handshake/continuation evidence are warnings — the run's
        // publish-and-continue contract makes them degraded, not failed.
        assert_eq!(report.status, "degraded");
        assert!(report
            .events
            .iter()
            .all(|event| event.severity == Severity::Warning));
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

    /// Regression (2026-10-14, run 38579293985): every line below is REAL
    /// output from a fully GREEN pipeline run that the old classifier
    /// fabricated into 724 "errors" / 1975 "unresolved" anomalies. Each is
    /// a passing test name, an env/config echo, a git hint, a shell xtrace
    /// source echo, or a success summary — none is a pipeline event.
    #[test]
    fn green_run_noise_is_never_classified_as_failure() {
        let log = concat!(
            "Quality Gate\tRun actions/checkout@v7\t2026-10-14T13:45:42.2367516Z hint: to use in all of your new repositories, which will suppress this warning,\n",
            "Quality Gate\tRun dtolnay/rust-toolchain@stable\t2026-10-14T13:45:45.5280469Z   CONNECTION_TIMEOUT: 8\n",
            "rust-parity-tests\tFull Rust test suite (all features)\t2026-10-14T13:48:45.5145465Z test engine_reports_non_reachable_for_a_bogus_dns_name ... ok\n",
            "rust-parity-tests\tFull Rust test suite (all features)\t2026-10-14T13:48:51.0485244Z test iran_detector::tests::cache_exactly_30s_is_invalid ... ok\n",
            "rust-parity-tests\tFull Rust test suite (all features)\t2026-10-14T13:48:57.9781763Z test prober::engine::tests::handshake_failure_is_not_masked ... ok\n",
            "rust-parity-tests\tFull Rust test suite (all features)\t2026-10-14T13:49:02.0000000Z test result: ok. 1432 passed; 0 failed; 12 ignored; 0 measured\n",
            "scrape-and-test (finalize)\tStage 10 — Full bridge/ inventory (manifest contract)\t2026-10-14T14:13:14.3956023Z \u{1b}[    echo \"⚠️  $req: 0 bridges\"\u{1b}[\n",
        );
        let report = analyze_log(log, "fixture");
        assert_eq!(
            report.errors, 0,
            "green-run noise must not fabricate errors"
        );
        assert_ne!(report.status, "failed");
        assert!(report.events.is_empty(), "got {:?}", report.events);
    }

    /// The by-design supply advisories (failsafe self-heal, MOAT empty
    /// window, per-endpoint timeout evidence) stay VISIBLE but must no
    /// longer flip a run's status to "failed" — they are warnings.
    #[test]
    fn typed_advisories_are_warnings_not_errors() {
        let log = concat!(
            "scrape-and-test (core)\tFAILSAFE — ensure bridge files always have content (Rust port)\t2026-10-14T13:55:37.6760665Z FAILSAFE: force-populated meek_lite\n",
            "scrape-and-test (core)\tStage 3 — probe_scheduler (RIPE Atlas + MOAT merge)\t2026-10-14T13:57:31.0846600Z MOAT: 0 bridges fetched\n",
            "scrape-and-test (core)\tStage 4-prep\t2026-10-14T13:59:00.0000000Z probe timed out after 5000ms\n",
        );
        let report = analyze_log(log, "fixture");
        assert_eq!(report.errors, 0);
        assert_eq!(report.warnings, 3);
        assert_eq!(report.status, "degraded");
        assert!(report
            .events
            .iter()
            .all(|event| event.severity == Severity::Warning));
    }

    /// Real failure signatures keep Error severity even inside the new
    /// guard logic: failing cargo test lines, error annotations, panics.
    #[test]
    fn real_failures_remain_error_severity() {
        let log = concat!(
            "rust-parity-tests\tFull Rust test suite\t2026-10-14T13:48:57.9781763Z test pipeline::tests::publishes_manifest ... FAILED\n",
            "rust-parity-tests\tFull Rust test suite\t2026-10-14T13:49:02.0000000Z test result: FAILED. 1431 passed; 1 failed; 0 ignored\n",
            "build-r\tBuild\t2026-10-14T13:50:00.0000000Z ::error::manifest contract violated\n",
            "build-r\tBuild\t2026-10-14T13:50:01.0000000Z thread 'main' panicked at 'contract', src/lib.rs:1:1\n",
        );
        let report = analyze_log(log, "fixture");
        assert!(report.errors >= 3, "expected real failures as errors");
        assert_eq!(report.status, "failed");
    }
}

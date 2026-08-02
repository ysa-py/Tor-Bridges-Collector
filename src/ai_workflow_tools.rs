//! Rust ports of the last inline Python heredocs used by
//! `.github/workflows/ai_gateway_health_check.yml` and
//! `.github/workflows/ai_self_healing.yml`:
//!
//!   * `health-summary`      → `_health_summary.py` — pretty-print
//!                             `data/gateway_health_report.json` (kept
//!                             byte-compatible, including Python's
//!                             capitalised `True`/`False` bools).
//!   * `obs-report`          → `_obs_report.py` — build provider health
//!                             metrics from the gateway report, persist
//!                             `data/observability_report.json` and append
//!                             the GitHub step-summary markdown. On any
//!                             failure it writes the same degraded fallback
//!                             report the Python script wrote.
//!   * `categorize-failure`  → `_categorize.py` — classify a failed parent
//!                             workflow run from its logs (GitHub API,
//!                             `network` feature), write
//!                             `data/failure_categorization.json` and the
//!                             three `$GITHUB_OUTPUT` key/value pairs.
//!
//! The Python implementations imported `monitoring.structured_logging`;
//! that package is retired, so the metrics/analytics/report logic lives in
//! this module now (`record_failure` had no effect on workflow outputs and
//! is intentionally not reproduced).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Map, Value};

// ────────────────────────────────────────────────────────────────────────────
// health-summary
// ────────────────────────────────────────────────────────────────────────────

/// Python `str(bool)` — capitalised, unlike Rust's `Display`.
fn py_bool(v: bool) -> &'static str {
    if v {
        "True"
    } else {
        "False"
    }
}

/// Python `str(value)` for the JSON scalars interpolated by the original
/// f-strings: `None` for null, capitalised bools, plain strings as-is, and
/// the JSON rendering for anything numeric/compound.
fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(b) => py_bool(*b).to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Render the health summary lines for a parsed gateway report.
/// Returns `Err(key)` with the missing key name when a result record is not
/// shaped like the Python script required (it accessed `r["status"]` and
/// `r["provider"]` directly, turning `KeyError` into
/// `Could not parse report: '<key>'`).
pub fn render_health_summary(report: &Value) -> Result<Vec<String>, &'static str> {
    let summary = report.get("summary").cloned().unwrap_or_else(|| json!({}));
    let get_num = |key: &str| summary.get(key).and_then(Value::as_i64).unwrap_or(0);
    let version = report.get("version").and_then(Value::as_str).unwrap_or("unknown");
    let primary_ok = get_num("primary_ok");
    let total = get_num("total");
    let healthy = summary
        .get("healthy")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Python: summary.get("exit_code", "?") / summary.get("failure_reason",
    // "none") — the default only applies when the key is ABSENT; a JSON null
    // present in the report interpolates as "None", exactly like CPython.
    let exit_code = summary.get("exit_code").map(py_str).unwrap_or_else(|| "?".to_string());
    let failure_reason = summary
        .get("failure_reason")
        .map(py_str)
        .unwrap_or_else(|| "none".to_string());

    let mut lines = vec![
        format!("Version: {version}"),
        format!("Primary OK: {primary_ok}/{total}"),
        format!("Degraded: {}", get_num("degraded")),
        format!("Errors: {}", get_num("error")),
        format!("Healthy: {}", py_bool(healthy)),
        format!("Exit code: {exit_code}"),
        format!("Failure reason: {failure_reason}"),
        String::new(),
    ];
    for result in report.get("results").and_then(Value::as_array).cloned().unwrap_or_default() {
        let status = result.get("status").and_then(Value::as_str).ok_or("status")?;
        let provider = result.get("provider").and_then(Value::as_str).ok_or("provider")?;
        let marker = if status == "ok" {
            "OK"
        } else if status.contains("degraded") {
            "DG"
        } else {
            "ER"
        };
        let latency = result.get("latency_ms").and_then(Value::as_i64).unwrap_or(0);
        lines.push(format!("  [{marker}] {provider}: {status} ({latency}ms)"));
    }
    let warnings = report
        .get("env_validation")
        .and_then(|env| env.get("warnings"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !warnings.is_empty() {
        lines.push(String::new());
        lines.push("Env warnings:".to_string());
        for warning in &warnings {
            let text = warning.as_str().map(str::to_string).unwrap_or_else(|| warning.to_string());
            lines.push(format!("  - {text}"));
        }
    }
    Ok(lines)
}

/// `health-summary [path]` — default `data/gateway_health_report.json`.
pub fn health_summary(path: &Path) -> i32 {
    match fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str::<Value>(&text).map_err(|e| e.to_string()))
    {
        Ok(report) => match render_health_summary(&report) {
            Ok(lines) => {
                for line in lines {
                    println!("{line}");
                }
            }
            Err(key) => println!("Could not parse report: '{key}'"),
        },
        Err(err) => println!("Could not parse report: {err}"),
    }
    0
}

// ────────────────────────────────────────────────────────────────────────────
// obs-report
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct ProviderStats {
    pub request_count: u64,
    pub success_count: u64,
    pub total_latency_ms: f64,
}

impl ProviderStats {
    pub fn success_rate(&self) -> f64 {
        if self.request_count == 0 {
            0.0
        } else {
            self.success_count as f64 / self.request_count as f64
        }
    }

    pub fn avg_latency_ms(&self) -> f64 {
        if self.request_count == 0 {
            0.0
        } else {
            self.total_latency_ms / self.request_count as f64
        }
    }
}

/// Fold the gateway report's `results` into per-provider stats, mirroring
/// `ProviderHealthMetrics.record_request(...)` calls in the Python original.
pub fn provider_stats_from_gateway(report: &Value) -> BTreeMap<String, ProviderStats> {
    let mut stats: BTreeMap<String, ProviderStats> = BTreeMap::new();
    for result in report.get("results").and_then(Value::as_array).cloned().unwrap_or_default() {
        let provider = result
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let status = result.get("status").and_then(Value::as_str).unwrap_or("unknown");
        let latency = result.get("latency_ms").and_then(Value::as_f64).unwrap_or(0.0);
        let entry = stats.entry(provider).or_default();
        entry.request_count += 1;
        if status == "ok" {
            entry.success_count += 1;
        }
        entry.total_latency_ms += latency;
    }
    stats
}

/// Build the observability report document.
pub fn build_obs_report(stats: &BTreeMap<String, ProviderStats>) -> Value {
    let provider_stats: Map<String, Value> = stats
        .iter()
        .map(|(name, s)| {
            (
                name.clone(),
                json!({
                    "request_count": s.request_count,
                    "success_rate": s.success_rate(),
                    "avg_latency_ms": s.avg_latency_ms(),
                }),
            )
        })
        .collect();
    let all_healthy =
        !stats.is_empty() && stats.values().all(|s| s.success_count == s.request_count);
    json!({
        "overall_status": if all_healthy { "healthy" } else { "degraded" },
        "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false),
        "provider_stats": provider_stats,
    })
}

/// The exact GitHub step-summary markdown appended by the Python script.
pub fn obs_step_summary_markdown(report: &Value) -> String {
    let overall = report
        .get("overall_status")
        .and_then(Value::as_str)
        .unwrap_or("degraded")
        .to_uppercase();
    let timestamp = report.get("timestamp").and_then(Value::as_str).unwrap_or_default();
    let mut out = String::from("## Observability Report\n\n");
    out.push_str(&format!("**Overall Status:** `{overall}`\n\n"));
    out.push_str(&format!("**Timestamp:** {timestamp}\n\n"));
    out.push_str("### Provider Health\n\n");
    out.push_str("| Provider | Requests | Success Rate | Avg Latency |\n");
    out.push_str("|----------|----------|--------------|-------------|\n");
    if let Some(map) = report.get("provider_stats").and_then(Value::as_object) {
        for (name, stats) in map {
            let reqs = stats.get("request_count").and_then(Value::as_i64).unwrap_or(0);
            let rate = stats.get("success_rate").and_then(Value::as_f64).unwrap_or(0.0);
            let lat = stats.get("avg_latency_ms").and_then(Value::as_f64).unwrap_or(0.0);
            // Python: f"| {name} | {reqs} | {rate:.1%} | {lat:.0f}ms |"
            let row = format!("| {name} | {reqs} | {:.1}% | {:.0}ms |\n", rate * 100.0, lat);
            out.push_str(&row);
        }
    }
    out
}

fn write_degraded_fallback(error: &str) {
    // Exact fallback document of the Python `except` branch:
    // indent=2, sort_keys=True, trailing newline, timestamp
    // datetime.utcnow().isoformat() + "Z".
    let fallback = json!({
        "overall_status": "degraded",
        "timestamp": format!("{}Z", Utc::now().format("%Y-%m-%dT%H:%M:%S%.6f")),
        "error": error,
        "provider_stats": {},
    });
    let _ = fs::create_dir_all("data");
    let mut body = serde_json::to_string_pretty(&fallback).unwrap_or_else(|_| "{}".to_string());
    body.push('\n');
    let _ = fs::write("data/observability_report.json", body);
}

/// `obs-report` — build + persist the observability report. Pure-Rust
/// counterpart of `_obs_report.py` (never exits non-zero).
pub fn obs_report(gateway_report_path: &Path) -> i32 {
    let stats = match fs::read_to_string(gateway_report_path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(report) => provider_stats_from_gateway(&report),
            Err(err) => {
                // Same warning text as the Python `except` around json.load.
                println!("Warning: Could not parse health report: {err}");
                BTreeMap::new()
            }
        },
        Err(_) => BTreeMap::new(),
    };
    let report = build_obs_report(&stats);

    let body = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    let _ = fs::create_dir_all("data");
    if let Err(err) = fs::write("data/observability_report.json", &body) {
        println!("Observability report generation failed: {err}");
        write_degraded_fallback(&err.to_string());
        return 0;
    }
    let status = report
        .get("overall_status")
        .and_then(Value::as_str)
        .unwrap_or("degraded")
        .to_uppercase();
    println!("Observability Report: {status}");
    println!("Report saved to: data/observability_report.json");
    if let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
        if !summary_path.is_empty() {
            let markdown = obs_step_summary_markdown(&report);
            use std::io::Write as _;
            let handle = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&summary_path);
            if let Ok(mut file) = handle {
                let _ = file.write_all(markdown.as_bytes());
            }
        }
    }
    0
}

// ────────────────────────────────────────────────────────────────────────────
// categorize-failure
// ────────────────────────────────────────────────────────────────────────────

/// Fixable failure patterns, in the iteration order of the Python dict.
const FIXABLE_PATTERNS: &[(&str, &[&str])] = &[
    (
        "syntax_error",
        &[
            "SyntaxError",
            "IndentationError",
            "TabError",
            "syntax error",
            "unexpected token",
            "invalid syntax",
            "py_compile",
            "syntax check failed",
        ],
    ),
    (
        "auth_failure",
        &[
            "401",
            "403",
            "Unauthorized",
            "Forbidden",
            "invalid api key",
            "authentication failed",
            "access denied",
            "auth error",
        ],
    ),
    (
        "model_error",
        &[
            "model not found",
            "invalid model",
            "wrong response",
            "no route for URI",
            "model_error",
            "ValueError",
        ],
    ),
];

/// Transient failure patterns, in the iteration order of the Python dict.
const TRANSIENT_PATTERNS: &[(&str, &[&str])] = &[
    (
        "network_error",
        &[
            "ConnectionError",
            "TimeoutError",
            "connection refused",
            "dns resolution",
            "network unreachable",
            "ssl error",
            "502",
            "503",
            "504",
            "Bad Gateway",
        ],
    ),
    (
        "timeout",
        &[
            "timeout",
            "timed out",
            "deadline exceeded",
            "ETIMEDOUT",
            "operation timed out",
        ],
    ),
];

const FIXABLE_CATEGORIES: &[&str] = &[
    "syntax_error",
    "auth_failure",
    "model_error",
    "unknown_fixable",
];
const TRANSIENT_CATEGORIES: &[&str] = &["network_error", "timeout"];

/// Classify a failure from combined lowercase text. Transient patterns are
/// checked first, exactly as in the Python original.
pub fn categorize(combined_text_lower: &str) -> &'static str {
    for &(category, patterns) in TRANSIENT_PATTERNS {
        if patterns.iter().any(|p| combined_text_lower.contains(&p.to_lowercase())) {
            return category;
        }
    }
    for &(category, patterns) in FIXABLE_PATTERNS {
        if patterns.iter().any(|p| combined_text_lower.contains(&p.to_lowercase())) {
            return category;
        }
    }
    "unknown_fixable"
}

/// Decide `(is_fixable, should_run_autodebug)` for a category, mirroring the
/// Python branch table (every arm sets `should_run_autodebug = true`).
pub fn category_flags(category: &str) -> (bool, bool) {
    if FIXABLE_CATEGORIES.contains(&category) {
        (true, true)
    } else if TRANSIENT_CATEGORIES.contains(&category) {
        (false, true)
    } else {
        (false, true)
    }
}

fn append_github_output(pairs: &[(&str, &str)]) {
    let path = std::env::var("GITHUB_OUTPUT").unwrap_or_else(|_| "/dev/null".to_string());
    use std::io::Write as _;
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        for (key, value) in pairs {
            let _ = writeln!(file, "{key}={value}");
        }
    }
}

fn write_categorization_report(report: &Value) {
    let _ = fs::create_dir_all("data");
    let body = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());
    let _ = fs::write("data/failure_categorization.json", &body);
    println!("{body}");
}

/// Last `n` *characters* of a string (Python `text[-n:]` slices by code
/// points, not bytes).
fn tail_chars(text: &str, n: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    chars.iter().skip(chars.len().saturating_sub(n)).collect()
}

/// Fetch the parent run's logs (zip or plain text) from the GitHub API.
/// Requires the `network` feature; without it (or without the required env
/// vars) this is an empty string, matching the Python fallback.
#[cfg(feature = "network")]
fn fetch_parent_logs() -> String {
    let token = std::env::var("GH_PAT_AUTOFIX").unwrap_or_default();
    let owner = std::env::var("GH_REPO_OWNER").unwrap_or_default();
    let repo = std::env::var("GH_REPO_NAME").unwrap_or_default();
    if token.is_empty() || owner.is_empty() || repo.is_empty() {
        return String::new();
    }
    let event_path = std::env::var("GITHUB_EVENT_PATH").unwrap_or_default();
    let parent_run_id = (|| -> Option<String> {
        let text = fs::read_to_string(&event_path).ok()?;
        let event: Value = serde_json::from_str(&text).ok()?;
        event.get("workflow_run")?.get("id")?.as_i64().map(|id| id.to_string())
    })()
    .unwrap_or_default();
    if parent_run_id.is_empty() {
        return String::new();
    }
    let url = format!(
        "https://api.github.com/repos/{owner}/{repo}/actions/runs/{parent_run_id}/logs"
    );
    let result = (|| -> Result<Vec<u8>, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("torshield-ir-categorize")
            .build()
            .map_err(|e| e.to_string())?;
        let bytes = client
            .get(&url)
            .bearer_auth(&token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .and_then(|r| r.error_for_status())
            .map_err(|e| e.to_string())?
            .bytes()
            .map_err(|e| e.to_string())?
            .to_vec();
        Ok(bytes)
    })();
    match result {
        Ok(content) => {
            if content.len() >= 2 && content[0] == b'P' && content[1] == b'K' {
                let cursor = std::io::Cursor::new(content);
                match zip::ZipArchive::new(cursor) {
                    Ok(mut archive) => {
                        let mut texts = Vec::new();
                        for index in 0..archive.len() {
                            if let Ok(mut file) = archive.by_index(index) {
                                if file.name().ends_with(".txt") {
                                    let mut buf = Vec::new();
                                    use std::io::Read as _;
                                    if file.read_to_end(&mut buf).is_ok() {
                                        texts.push(String::from_utf8_lossy(&buf).into_owned());
                                    }
                                }
                            }
                        }
                        tail_chars(&texts.join("\n"), 5000)
                    }
                    Err(_) => String::new(),
                }
            } else {
                tail_chars(&String::from_utf8_lossy(&content), 5000)
            }
        }
        Err(err) => {
            println!("Could not fetch parent logs: {err}");
            String::new()
        }
    }
}

/// Without the `network` feature, log fetching is a no-op (Python behaved
/// the same when the request could not be made at all).
#[cfg(not(feature = "network"))]
fn fetch_parent_logs() -> String {
    String::new()
}

/// `categorize-failure` — full port of `_categorize.py` (never exits non-zero).
pub fn categorize_failure() -> i32 {
    let workflow_name =
        std::env::var("GITHUB_WORKFLOW").unwrap_or_else(|_| "unknown".to_string());
    let parent_conclusion =
        std::env::var("PARENT_CONCLUSION").unwrap_or_else(|_| "manual".to_string());

    if parent_conclusion != "failure" && parent_conclusion != "manual" {
        let report = json!({
            "workflow_name": workflow_name,
            "parent_conclusion": parent_conclusion,
            "failure_category": "no_failure",
            "is_fixable": false,
            "should_run_autodebug": false,
            "has_logs": false,
        });
        println!("  Parent workflow conclusion is {parent_conclusion}; no repair needed");
        append_github_output(&[
            ("category", "no_failure"),
            ("is_fixable", "false"),
            ("should_run_autodebug", "false"),
        ]);
        write_categorization_report(&report);
        return 0;
    }

    let log_content = fetch_parent_logs();
    let combined = format!("{} {}", workflow_name, log_content).to_lowercase();
    let category = categorize(&combined);
    let (is_fixable, should_run_autodebug) = category_flags(category);

    println!("  Failure Category: {category}");
    println!("  Is Fixable:       {is_fixable}");
    println!("  Workflow:         {workflow_name}");
    append_github_output(&[
        ("category", category),
        ("is_fixable", if is_fixable { "true" } else { "false" }),
        (
            "should_run_autodebug",
            if should_run_autodebug { "true" } else { "false" },
        ),
    ]);
    let report = json!({
        "workflow_name": workflow_name,
        "parent_conclusion": parent_conclusion,
        "failure_category": category,
        "is_fixable": is_fixable,
        "should_run_autodebug": should_run_autodebug,
        "has_logs": !log_content.is_empty(),
    });
    write_categorization_report(&report);
    0
}

// ────────────────────────────────────────────────────────────────────────────
// CLI
// ────────────────────────────────────────────────────────────────────────────

const USAGE: &str =
    "Usage: ai_workflow_tools <health-summary|obs-report|categorize-failure> [path]";

/// CLI entry point; returns the process exit code.
pub fn entry(args: &[String]) -> i32 {
    let Some(cmd) = args.get(1) else {
        eprintln!("{USAGE}");
        return 2;
    };
    match cmd.as_str() {
        "health-summary" => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("data/gateway_health_report.json");
            health_summary(Path::new(path))
        }
        "obs-report" => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("data/gateway_health_report.json");
            obs_report(Path::new(path))
        }
        "categorize-failure" => categorize_failure(),
        "--help" | "-h" => {
            println!("{USAGE}");
            0
        }
        other => {
            eprintln!("ai_workflow_tools: unknown subcommand '{other}'\n{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_summary_formats_like_python() {
        let report = json!({
            "version": "1.2.3",
            "summary": {
                "primary_ok": 2, "total": 3, "degraded": 1, "error": 0,
                "healthy": true, "exit_code": 0, "failure_reason": null,
            },
            "results": [
                {"provider": "cerebras", "status": "ok", "latency_ms": 42},
                {"provider": "portkey", "status": "degraded_slow", "latency_ms": 500},
                {"provider": "groq", "status": "error", "latency_ms": 0},
            ],
            "env_validation": {"warnings": ["missing key 3"]},
        });
        let lines = render_health_summary(&report).expect("rendered");
        assert_eq!(lines[0], "Version: 1.2.3");
        assert_eq!(lines[1], "Primary OK: 2/3");
        assert_eq!(lines[3], "Errors: 0");
        assert_eq!(lines[4], "Healthy: True"); // Python bool capitalisation
        assert_eq!(lines[5], "Exit code: 0");
        // Key present with JSON null -> Python interpolates "None", not the
        // absent-key default "none".
        assert_eq!(lines[6], "Failure reason: None");
        assert_eq!(lines[8], "  [OK] cerebras: ok (42ms)");
        assert_eq!(lines[9], "  [DG] portkey: degraded_slow (500ms)");
        assert_eq!(lines[10], "  [ER] groq: error (0ms)");
        assert_eq!(lines[12], "Env warnings:");
        assert_eq!(lines[13], "  - missing key 3");
    }

    #[test]
    fn health_summary_defaults_and_missing_keys() {
        let lines = render_health_summary(&json!({})).expect("rendered");
        assert_eq!(lines[0], "Version: unknown");
        assert_eq!(lines[4], "Healthy: False");
        assert_eq!(lines[5], "Exit code: ?");
        // Key absent -> Python's .get default kicks in.
        assert_eq!(lines[6], "Failure reason: none");
        let err = render_health_summary(&json!({"results": [{"provider": "x"}]}));
        assert_eq!(err, Err("status"));
    }

    #[test]
    fn provider_stats_computation() {
        let report = json!({"results": [
            {"provider": "a", "status": "ok", "latency_ms": 10},
            {"provider": "a", "status": "error", "latency_ms": 30},
            {"provider": "b", "status": "degraded", "latency_ms": 100},
        ]});
        let stats = provider_stats_from_gateway(&report);
        let a = stats.get("a").expect("provider a");
        assert_eq!(a.request_count, 2);
        assert_eq!(a.success_count, 1);
        assert!((a.success_rate() - 0.5).abs() < f64::EPSILON);
        assert!((a.avg_latency_ms() - 20.0).abs() < f64::EPSILON);
        let doc = build_obs_report(&stats);
        assert_eq!(doc["overall_status"], "degraded");
        assert!(doc["provider_stats"]["a"]["request_count"] == 2);
    }

    #[test]
    fn obs_report_all_success_is_healthy() {
        let report = json!({"results": [
            {"provider": "a", "status": "ok", "latency_ms": 10},
        ]});
        let stats = provider_stats_from_gateway(&report);
        assert_eq!(build_obs_report(&stats)["overall_status"], "healthy");
    }

    #[test]
    fn step_summary_markdown_shape() {
        let report = json!({
            "overall_status": "degraded",
            "timestamp": "2026-08-02T00:00:00+00:00",
            "provider_stats": {"a": {"request_count": 2, "success_rate": 0.5, "avg_latency_ms": 20.0}},
        });
        let md = obs_step_summary_markdown(&report);
        assert!(md.starts_with("## Observability Report\n\n**Overall Status:** `DEGRADED`"));
        assert!(md.contains("| a | 2 | 50.0% | 20ms |"));
        assert!(md.contains("| Provider | Requests | Success Rate | Avg Latency |"));
    }

    #[test]
    fn categorize_prioritises_transient_then_fixable() {
        assert_eq!(categorize("a 502 bad gateway happened"), "network_error");
        assert_eq!(categorize("operation timed out repeatedly"), "timeout");
        assert_eq!(categorize("syntaxerror on line 3"), "syntax_error");
        assert_eq!(categorize("http 403 forbidden"), "auth_failure");
        assert_eq!(categorize("model not found: x"), "model_error");
        assert_eq!(categorize("cargo fmt failed mysteriously"), "unknown_fixable");
        // Transient wins even when a fixable token is present too.
        assert_eq!(categorize("valueerror and 503"), "network_error");
    }

    #[test]
    fn category_flags_match_python_branches() {
        assert_eq!(category_flags("syntax_error"), (true, true));
        assert_eq!(category_flags("unknown_fixable"), (true, true));
        assert_eq!(category_flags("network_error"), (false, true));
        assert_eq!(category_flags("timeout"), (false, true));
        assert_eq!(category_flags("anything_else"), (false, true));
    }

    #[test]
    fn tail_chars_counts_codepoints() {
        assert_eq!(tail_chars("héllo wörld", 5), "wörld");
        assert_eq!(tail_chars("short", 10), "short");
    }
}

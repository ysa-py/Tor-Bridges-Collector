//! Parity port of `iran_anti_siam.py`.
//!
//! Iran SIAM/NGFW Anti-AI DPI full analysis pipeline. Loads bridge lines
//! from the best available source, runs the 8-layer SIAM evasion scoring
//! engine, and produces ranked output files (JSON report, PHANTOM/STEALTH
//! exports, markdown analysis).
//!
//! Behavior traced to `iran_anti_siam.py`:
//! * `load_bridges_json` — load bridge lines from a JSON file (array of
//!   strings or `{"bridges": [{"line": ...}]}` shape). Returns `[]` on any
//!   error (matching Python's broad `except Exception`).
//! * `load_bridges_txt` — load bridge lines from `*.txt` files in a directory,
//!   skipping `iran_blocked*` files, blank lines, and `#` comments. Dedupes
//!   while preserving first-occurrence order.
//! * `load_ja3_map` — load the `bridge_ja3_map` value from
//!   `data/ja3_rotation_plan.json` (or the equivalent injectable path).
//! * `load_bridges` — try `bridge_list_for_testing.json`, then
//!   `iran_results.json`, then `.txt` files; returns `[]` if all sources are
//!   empty/missing.
//! * `build_md_report` — render the Farsi/English SIAM analysis markdown.
//! * `run_pipeline` — orchestrate the full `main()` flow with injectable
//!   paths, clock, and a `score_all`-shaped callback. The Python original
//!   imports `score_all` from `core.iran_dpi_shaper`, which wasn't ported
//!   yet when this module was first written, so it was injected as a
//!   closure rather than a hard dependency. `core/iran_dpi_shaper.py` is
//!   now ported (`src/iran_dpi_shaper.rs`, Session 9) —
//!   [`real_score_all`] wires to it directly for any real (non-test)
//!   caller. `run_pipeline` stays generic over the callback rather than
//!   hardcoding `real_score_all` internally, since existing tests
//!   deliberately use fixed/mock results to validate pipeline mechanics
//!   independent of scoring correctness — see [`real_score_all`]'s own
//!   doc comment.
//!
//! Scope guardrail: the Python module only consumes already-public bridge
//! lines and JA3 rotation metadata and forwards them to the passive scoring
//! engine. It does not perform any active fingerprinting of third-party
//! infrastructure, so the port is faithful and no behavior is flagged.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors raised by the Rust `iran_anti_siam.py` parity port.
#[derive(Debug, Error)]
pub enum IranAntiSiamError {
    /// File I/O failed. The Python original swallows these inside
    /// `_load_bridges_json` / `_load_bridges_txt` / `_load_ja3_map`, but the
    /// orchestration helpers ([`run_pipeline`]) surface them as typed errors
    /// so callers can decide whether to log or retry.
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    /// JSON parse failed. Same swallowing rule as [`IranAntiSiamError::Io`].
    #[error("JSON parse error in {path}: {source}")]
    Json {
        path: String,
        source: serde_json::Error,
    },
    /// `iran_results.json`-shaped dict contained a non-dict entry inside the
    /// `bridges` array. The Python original raises an `AttributeError` that
    /// the broad `except Exception` swallows, returning `[]`. The Rust port
    /// surfaces it as a typed error internally and the public loader
    /// converts it back to an empty vector.
    #[error("invalid bridges entry in {path}: {detail}")]
    InvalidBridgesFormat { path: String, detail: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// SIAM result type (mirrors `core.iran_dpi_shaper.SIAMEvasionScore`)
// ─────────────────────────────────────────────────────────────────────────────

/// Bypass tier constants mirroring `core.iran_dpi_shaper.BypassTier`.
pub mod bypass_tier {
    pub const PHANTOM: &str = "PHANTOM";
    pub const STEALTH: &str = "STEALTH";
    pub const COVERT: &str = "COVERT";
    pub const EXPOSED: &str = "EXPOSED";
    pub const DETECTED: &str = "DETECTED";
}

/// A single SIAM scoring result, mirroring the fields of
/// `core.iran_dpi_shaper.SIAMEvasionScore` that `iran_anti_siam.py` consumes.
#[derive(Debug, Clone)]
pub struct SiamResult {
    pub bridge_line: String,
    pub transport: String,
    pub port: Option<i64>,
    pub iran_siam_score: f64,
    pub bypass_tier: String,
    pub layers_bypassed: i64,
    pub evasion_flags: Vec<String>,
    pub layer_scores: BTreeMap<String, f64>,
    pub recommendation: String,
}

impl SiamResult {
    /// Mirror of Python `result.to_dict()` (which is `dataclasses.asdict`).
    pub fn to_dict(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "bridge_line".to_string(),
            Value::String(self.bridge_line.clone()),
        );
        map.insert(
            "transport".to_string(),
            Value::String(self.transport.clone()),
        );
        map.insert(
            "port".to_string(),
            match self.port {
                Some(p) => Value::Number(serde_json::Number::from(p)),
                None => Value::Null,
            },
        );
        map.insert(
            "iran_siam_score".to_string(),
            number_from_f64(self.iran_siam_score),
        );
        map.insert(
            "bypass_tier".to_string(),
            Value::String(self.bypass_tier.clone()),
        );
        map.insert(
            "layers_bypassed".to_string(),
            Value::Number(serde_json::Number::from(self.layers_bypassed)),
        );
        map.insert(
            "evasion_flags".to_string(),
            Value::Array(
                self.evasion_flags
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "layer_scores".to_string(),
            Value::Object(Map::from_iter(
                self.layer_scores
                    .iter()
                    .map(|(k, v)| (k.clone(), number_from_f64(*v))),
            )),
        );
        map.insert(
            "recommendation".to_string(),
            Value::String(self.recommendation.clone()),
        );
        Value::Object(map)
    }
}

fn number_from_f64(f: f64) -> Value {
    match serde_json::Number::from_f64(f) {
        Some(n) => Value::Number(n),
        None => Value::Null,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Input loaders (mirror `_load_bridges_json`, `_load_bridges_txt`,
// `_load_ja3_map`, `load_bridges`)
// ─────────────────────────────────────────────────────────────────────────────

/// Load bridge lines from a JSON file. Mirrors `_load_bridges_json(path)`.
///
/// Accepts either a JSON array of bridge-line strings (filtered for truthy
/// values) or a JSON object with a `bridges` array of `{"line": ...}` dicts.
/// Returns `[]` on any error (missing file, malformed JSON, unexpected
/// schema), matching the Python broad `except Exception` swallow.
pub fn load_bridges_json(path: &Path) -> Vec<String> {
    load_bridges_json_inner(path).unwrap_or_default()
}

fn load_bridges_json_inner(path: &Path) -> Result<Vec<String>, IranAntiSiamError> {
    let text = std::fs::read_to_string(path).map_err(|source| IranAntiSiamError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let data: Value = serde_json::from_str(&text).map_err(|source| IranAntiSiamError::Json {
        path: path.display().to_string(),
        source,
    })?;
    match &data {
        Value::Array(arr) => {
            let mut out = Vec::new();
            for b in arr {
                if !is_truthy(b) {
                    continue;
                }
                out.push(python_str(b));
            }
            Ok(out)
        }
        Value::Object(obj) => {
            let bridges = match obj.get("bridges") {
                Some(Value::Array(arr)) => arr,
                _ => return Ok(Vec::new()),
            };
            let mut out = Vec::new();
            for b in bridges {
                let b_map =
                    b.as_object()
                        .ok_or_else(|| IranAntiSiamError::InvalidBridgesFormat {
                            path: path.display().to_string(),
                            detail: "bridge entry is not an object".to_string(),
                        })?;
                let line = match b_map.get("line") {
                    Some(v) => v,
                    None => continue,
                };
                if is_truthy(line) {
                    out.push(python_str(line));
                }
            }
            Ok(out)
        }
        _ => Ok(Vec::new()),
    }
}

/// Load bridge lines from `*.txt` files in `bridge_dir`. Mirrors
/// `_load_bridges_txt(bridge_dir)`.
///
/// Files whose name starts with `iran_blocked` are skipped. Within each file,
/// lines are stripped and blank/comment (`#`) lines are dropped. The combined
/// list is deduped preserving first-occurrence order.
pub fn load_bridges_txt(bridge_dir: &Path) -> Vec<String> {
    let read = match std::fs::read_dir(bridge_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    // Python glob sorts results alphabetically; sort here to match.
    let mut entries: Vec<_> = read.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    let mut lines: Vec<String> = Vec::new();
    for entry in entries {
        let path = entry.path();
        // Match `bridge_dir.glob("*.txt")`.
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.ends_with(".txt") {
            continue;
        }
        if name.starts_with("iran_blocked") {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for raw in text.lines() {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                lines.push(trimmed.to_string());
            }
        }
    }
    // Dedup preserving first-occurrence order, mirroring
    // `list(dict.fromkeys(lines))`.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines {
        if seen.insert(line.clone()) {
            out.push(line);
        }
    }
    out
}

/// Load the `bridge_ja3_map` value from `path`. Mirrors `_load_ja3_map()`
/// with the path made injectable. Returns `Value::Object(empty)` on any error
/// or missing key, matching the Python swallow-and-default behavior.
pub fn load_ja3_map(path: &Path) -> Value {
    match load_ja3_map_inner(path) {
        Ok(v) => v,
        Err(_) => Value::Object(Map::new()),
    }
}

fn load_ja3_map_inner(path: &Path) -> Result<Value, IranAntiSiamError> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let text = std::fs::read_to_string(path).map_err(|source| IranAntiSiamError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let data: Value = serde_json::from_str(&text).map_err(|source| IranAntiSiamError::Json {
        path: path.display().to_string(),
        source,
    })?;
    if let Value::Object(obj) = &data {
        if let Some(bridge_ja3_map) = obj.get("bridge_ja3_map") {
            return Ok(bridge_ja3_map.clone());
        }
    }
    Ok(Value::Object(Map::new()))
}

/// Load bridge lines from the best available source. Mirrors `load_bridges()`
/// with the bridge directory made injectable.
///
/// Tries `bridge_list_for_testing.json`, then `iran_results.json`, then
/// `*.txt` files. Returns `[]` if all sources are missing or empty.
pub fn load_bridges(bridge_dir: &Path) -> Vec<String> {
    let test_json = bridge_dir.join("bridge_list_for_testing.json");
    if test_json.exists() {
        let lines = load_bridges_json(&test_json);
        if !lines.is_empty() {
            return lines;
        }
    }
    let iran_json = bridge_dir.join("iran_results.json");
    if iran_json.exists() {
        let lines = load_bridges_json(&iran_json);
        if !lines.is_empty() {
            return lines;
        }
    }
    let lines = load_bridges_txt(bridge_dir);
    if !lines.is_empty() {
        return lines;
    }
    Vec::new()
}

// ─────────────────────────────────────────────────────────────────────────────
// Markdown report (mirror `_build_md_report`)
// ─────────────────────────────────────────────────────────────────────────────

/// Build the Farsi/English SIAM analysis markdown report. Mirrors
/// `_build_md_report(results, tier_counts, transport_counts, ts)`.
///
/// `tier_counts` is a `BTreeMap` keyed by tier name (only `.get()` is used,
/// so iteration order is irrelevant). `transport_counts` is a slice of
/// `(name, count)` tuples in **insertion order** — the Python original
/// iterates a regular `dict` (insertion-ordered) and sorts by descending
/// count with a stable sort, so ties preserve insertion order. The Rust port
/// reproduces that exact tie-break by accepting an insertion-ordered slice
/// and using `sort_by` (which is stable).
pub fn build_md_report(
    results: &[SiamResult],
    tier_counts: &BTreeMap<String, u64>,
    transport_counts: &[(String, u64)],
    ts: &str,
) -> String {
    let total = results.len();
    let phantom_n = tier_counts.get("PHANTOM").copied().unwrap_or(0);
    let stealth_n = tier_counts.get("STEALTH").copied().unwrap_or(0);
    let covert_n = tier_counts.get("COVERT").copied().unwrap_or(0);
    let exposed_n = tier_counts.get("EXPOSED").copied().unwrap_or(0);
    let detected_n = tier_counts.get("DETECTED").copied().unwrap_or(0);

    let scores: Vec<f64> = results.iter().map(|r| r.iran_siam_score).collect();
    let mean_s = if scores.is_empty() {
        0.0
    } else {
        scores.iter().sum::<f64>() / scores.len() as f64
    };
    let best_s = if scores.is_empty() {
        0.0
    } else {
        scores.iter().copied().fold(f64::NEG_INFINITY, f64::max)
    };

    let mut lines: Vec<String> = Vec::with_capacity(64);
    lines.push("# 🛡️ گزارش تحلیل SIAM ایران / Iran SIAM DPI Analysis".to_string());
    lines.push(String::new());
    lines.push(format!("> آخرین بروزرسانی: `{ts}`  "));
    lines.push(format!("> کل پل‌های تحلیل‌شده: **{total}**  "));
    lines.push(format!(
        "> میانگین امتیاز دور زدن: **{:.1}%**  ",
        mean_s * 100.0
    ));
    lines.push(format!("> بهترین امتیاز: **{:.1}%**", best_s * 100.0));
    lines.push(String::new());
    lines.push("---".to_string());
    lines.push(String::new());
    lines.push("## 📊 خلاصه لایه‌بندی SIAM / SIAM Bypass Tier Summary".to_string());
    lines.push(String::new());
    lines.push("| سطح / Tier | تعداد / Count | توضیح / Description |".to_string());
    lines.push("| :--- | :---: | :--- |".to_string());
    lines.push(format!(
        "| 👻 PHANTOM  | {phantom_n}  | کاملاً ناشناس — سیستم SIAM هیچ سیگنالی دریافت نمی‌کند |"
    ));
    lines.push(format!(
        "| 🕶️ STEALTH  | {stealth_n}  | قوی — از ۶-۷ لایه از ۸ لایه عبور می‌کند |"
    ));
    lines.push(format!(
        "| 🥷 COVERT   | {covert_n}   | متوسط — از ۴-۵ لایه عبور می‌کند |"
    ));
    lines.push(format!(
        "| ⚠️ EXPOSED  | {exposed_n}  | ضعیف — اکثر لایه‌های SIAM تشخیص می‌دهند |"
    ));
    lines.push(format!(
        "| 🚫 DETECTED | {detected_n} | بلاک می‌شود — SIAM تشخیص کامل می‌دهد |"
    ));
    lines.push(String::new());
    lines.push("---".to_string());
    lines.push(String::new());
    lines.push("## 🔬 ۸ لایه سیستم SIAM ایران / 8 Layers of Iran SIAM DPI".to_string());
    lines.push(String::new());
    lines.push("| لایه | نام | توضیح |".to_string());
    lines.push("| :--- | :--- | :--- |".to_string());
    lines.push(
        "| L1 | Packet Length Fingerprinting | CNN تحلیل هیستوگرام اندازه بسته‌ها |".to_string(),
    );
    lines.push("| L2 | IAT Timing Analysis | LSTM تحلیل فواصل زمانی بین بسته‌ها |".to_string());
    lines.push("| L3 | Flow Feature Extraction | NetFlow + گشتاورهای آماری |".to_string());
    lines.push("| L4 | JA3/JA3S Fingerprint | پایگاه داده ۵۰k اثر انگشت TLS |".to_string());
    lines.push("| L5 | Certificate + SNI | تطبیق گواهی و SNI با پایگاه داده رله Tor |".to_string());
    lines.push("| L6 | ALPN Anomaly | تشخیص ALPN نامعمول روی پورت ۴۴۳ |".to_string());
    lines.push("| L7 | Temporal Analysis | تشخیص ضربان ۱ ثانیه‌ای Tor vanilla |".to_string());
    lines.push("| L8 | AS Relationship Graph | ارتباط ASN رله با شبکه‌های CDN |".to_string());
    lines.push(String::new());
    lines.push("---".to_string());
    lines.push(String::new());
    lines.push("## 🚀 راهنمای انتخاب پل / Bridge Selection Guide".to_string());
    lines.push(String::new());
    lines.push("```".to_string());
    lines.push("شبکه ملی فعال (NIN / قطع اینترنت بین‌المللی):".to_string());
    lines.push("  → export/iran_phantom_bridges.txt  (Snowflake + WebTunnel CDN)".to_string());
    lines.push(String::new());
    lines.push("فیلترینگ معمولی SIAM:".to_string());
    lines.push("  → export/iran_stealth_bridges.txt  (obfs4 IAT-2 + meek-lite)".to_string());
    lines.push(String::new());
    lines.push("هر شرایطی / Any condition:".to_string());
    lines.push("  → bridge/iran_likely_working_all.txt".to_string());
    lines.push("```".to_string());
    lines.push(String::new());
    lines.push("---".to_string());
    lines.push(String::new());
    lines.push("## 📈 توزیع transport / Transport Distribution".to_string());
    lines.push(String::new());
    lines.push("| Transport | تعداد |".to_string());
    lines.push("| :--- | :---: |".to_string());

    // Sort by descending count, preserving insertion order for ties (Python's
    // `sorted(..., key=lambda x: -x[1])` is stable).
    let mut transport_entries: Vec<&(String, u64)> = transport_counts.iter().collect();
    // Sort by descending count, preserving insertion order for ties (Python's
    // `sorted(..., key=lambda x: -x[1])` is stable). Clippy::sort_by_key
    // suggests using key closure — but `sort_by_key` is stable, matching
    // Python's stable sort, so this is the correct replacement.
    transport_entries.sort_by_key(|&item| std::cmp::Reverse(item.1));
    for (t, c) in transport_entries {
        lines.push(format!("| {t} | {c} |"));
    }

    lines.push(String::new());
    lines.push("---".to_string());
    lines.push(String::new());
    lines.push("*تولید شده توسط iran_anti_siam.py — TorShield-IR*".to_string());
    lines.join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Main pipeline (mirror `main()` with injectable paths/clock/score_all)
// ─────────────────────────────────────────────────────────────────────────────

/// Output of a successful [`run_pipeline`] call. Contains the paths that were
/// written and the in-memory report data so tests can compare against the
/// Python original without re-reading the files.
#[derive(Debug, Clone)]
pub struct PipelineOutput {
    pub total_scored: usize,
    pub tier_summary: BTreeMap<String, u64>,
    /// Transport counts in insertion order (first occurrence wins), matching
    /// Python's regular-dict iteration order.
    pub transport_summary: Vec<(String, u64)>,
    pub results: Vec<SiamResult>,
    pub generated_at: String,
    pub wrote_phantom: bool,
    pub wrote_stealth: bool,
    pub wrote_best: bool,
    pub wrote_markdown: bool,
}

/// Run the full Iran SIAM analysis pipeline. Mirrors `main()` with all paths
/// and the clock made injectable, and `score_all` injected as a closure
/// (the Python original imports it from `core.iran_dpi_shaper`, which is out
/// of scope for this port).
///
/// Directories `data_dir`, `export_dir`, and `docs_dir` are created if
/// missing. The JSON report is written to `data_dir/iran_siam_report.json`,
/// PHANTOM/STEALTH/best exports to `export_dir/iran_{phantom,stealth,siam_best}_bridges.txt`,
/// and the markdown report to `docs_dir/iran-siam-analysis.md`.
pub fn run_pipeline<F>(
    bridge_dir: &Path,
    data_dir: &Path,
    export_dir: &Path,
    docs_dir: &Path,
    ja3_plan_path: &Path,
    now: DateTime<Utc>,
    score_all: F,
) -> Result<PipelineOutput, IranAntiSiamError>
where
    F: FnOnce(&[String], &Value) -> Vec<SiamResult>,
{
    // Ensure output dirs (mirrors `Path("data").mkdir(exist_ok=True)` etc.).
    create_dir_all(data_dir)?;
    create_dir_all(export_dir)?;
    create_dir_all(docs_dir)?;

    let bridge_lines = load_bridges(bridge_dir);
    if bridge_lines.is_empty() {
        // Mirror: write empty `{"scored": 0, "results": []}` report.
        let empty_report = serde_json::json!({"scored": 0, "results": []});
        let report_json = serde_json::to_string_pretty(&empty_report).map_err(|source| {
            IranAntiSiamError::Json {
                path: data_dir.join("iran_siam_report.json").display().to_string(),
                source,
            }
        })?;
        let out_json = data_dir.join("iran_siam_report.json");
        std::fs::write(&out_json, report_json).map_err(|source| IranAntiSiamError::Io {
            path: out_json.display().to_string(),
            source,
        })?;
        return Ok(PipelineOutput {
            total_scored: 0,
            tier_summary: BTreeMap::new(),
            transport_summary: Vec::new(),
            results: Vec::new(),
            generated_at: isoformat(now),
            wrote_phantom: false,
            wrote_stealth: false,
            wrote_best: false,
            wrote_markdown: false,
        });
    }

    let ja3_map = load_ja3_map(ja3_plan_path);
    let results = score_all(&bridge_lines, &ja3_map);

    let mut tier_summary: BTreeMap<String, u64> = BTreeMap::new();
    // Build transport_summary as an insertion-ordered vec to mirror Python's
    // regular-dict iteration order (first occurrence wins).
    let mut transport_summary: Vec<(String, u64)> = Vec::new();
    let mut transport_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in &results {
        *tier_summary.entry(r.bypass_tier.clone()).or_insert(0) += 1;
        if transport_seen.insert(r.transport.clone()) {
            transport_summary.push((r.transport.clone(), 1));
        } else if let Some(entry) = transport_summary
            .iter_mut()
            .find(|(t, _)| *t == r.transport)
        {
            entry.1 += 1;
        }
    }

    let generated_at = isoformat(now);
    // The JSON report's `transport_summary` is a dict in Python; serializing
    // the insertion-ordered vec as a JSON object would require a preserved-
    // order map. Use a BTreeMap for the JSON report (comparison is order-
    // independent) and the vec only for the markdown report.
    let transport_summary_map: BTreeMap<String, u64> = transport_summary.iter().cloned().collect();
    let report = serde_json::json!({
        "generated_at": generated_at,
        "total_scored": results.len(),
        "tier_summary": tier_summary,
        "transport_summary": transport_summary_map,
        "results": results.iter().map(|r| r.to_dict()).collect::<Vec<_>>(),
    });
    let report_json =
        serde_json::to_string_pretty(&report).map_err(|source| IranAntiSiamError::Json {
            path: data_dir.join("iran_siam_report.json").display().to_string(),
            source,
        })?;
    let out_json = data_dir.join("iran_siam_report.json");
    std::fs::write(&out_json, report_json).map_err(|source| IranAntiSiamError::Io {
        path: out_json.display().to_string(),
        source,
    })?;

    // PHANTOM export.
    let phantom_lines: Vec<&String> = results
        .iter()
        .filter(|r| r.bypass_tier == bypass_tier::PHANTOM)
        .map(|r| &r.bridge_line)
        .collect();
    let mut wrote_phantom = false;
    if !phantom_lines.is_empty() {
        let content = phantom_lines
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let p_path = export_dir.join("iran_phantom_bridges.txt");
        std::fs::write(&p_path, content).map_err(|source| IranAntiSiamError::Io {
            path: p_path.display().to_string(),
            source,
        })?;
        wrote_phantom = true;
    }

    // STEALTH export.
    let stealth_lines: Vec<&String> = results
        .iter()
        .filter(|r| r.bypass_tier == bypass_tier::STEALTH)
        .map(|r| &r.bridge_line)
        .collect();
    let mut wrote_stealth = false;
    if !stealth_lines.is_empty() {
        let content = stealth_lines
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let s_path = export_dir.join("iran_stealth_bridges.txt");
        std::fs::write(&s_path, content).map_err(|source| IranAntiSiamError::Io {
            path: s_path.display().to_string(),
            source,
        })?;
        wrote_stealth = true;
    }

    // Combined best (PHANTOM + STEALTH).
    let best_lines: Vec<&String> = phantom_lines
        .iter()
        .chain(stealth_lines.iter())
        .copied()
        .collect();
    let mut wrote_best = false;
    if !best_lines.is_empty() {
        let content = best_lines
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let b_path = export_dir.join("iran_siam_best_bridges.txt");
        std::fs::write(&b_path, content).map_err(|source| IranAntiSiamError::Io {
            path: b_path.display().to_string(),
            source,
        })?;
        wrote_best = true;
    }

    // Markdown report.
    let ts_human = now.format("%Y-%m-%d %H:%M UTC").to_string();
    let md = build_md_report(&results, &tier_summary, &transport_summary, &ts_human);
    let md_path = docs_dir.join("iran-siam-analysis.md");
    std::fs::write(&md_path, md).map_err(|source| IranAntiSiamError::Io {
        path: md_path.display().to_string(),
        source,
    })?;

    Ok(PipelineOutput {
        total_scored: results.len(),
        tier_summary,
        transport_summary,
        results,
        generated_at,
        wrote_phantom,
        wrote_stealth,
        wrote_best,
        wrote_markdown: true,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Real (non-mock) `score_all` — wires to `iran_dpi_shaper` (Session 9)
// ─────────────────────────────────────────────────────────────────────────────

/// Converts [`crate::iran_dpi_shaper::SiamEvasionScore`] to this module's own
/// [`SiamResult`]. Same fields; different concrete types (`u16`/[`BypassTier`
/// enum](crate::iran_dpi_shaper::BypassTier)/`u8` there vs. this struct's
/// `i64`/`String`/`i64`, matching what this module already declared before
/// `iran_dpi_shaper.rs` existed to produce real values for it).
fn from_dpi_shaper_score(score: crate::iran_dpi_shaper::SiamEvasionScore) -> SiamResult {
    SiamResult {
        bridge_line: score.bridge_line,
        transport: score.transport,
        port: score.port.map(i64::from),
        iran_siam_score: score.iran_siam_score,
        bypass_tier: score.bypass_tier.as_str().to_string(),
        layers_bypassed: i64::from(score.layers_bypassed),
        evasion_flags: score.evasion_flags,
        layer_scores: score
            .layer_scores
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        recommendation: score.recommendation,
    }
}

/// Real `score_all` for [`run_pipeline`], wiring to
/// `crate::iran_dpi_shaper::score_all` now that it's ported (Session 9) —
/// the Python original's own `from core.iran_dpi_shaper import score_all`,
/// which this port's own doc comment already flagged as "out of scope for
/// this port" before that module existed here.
///
/// Use this in any real (non-test) caller — e.g. a future `main.rs`, once
/// `main.py` is ported. Existing tests intentionally keep passing their own
/// fixed/mock closures to `run_pipeline` instead of this function: they
/// validate pipeline mechanics (report structure, tier/transport
/// summaries, file writing) in isolation from scoring correctness, which
/// `iran_dpi_shaper_parity.rs` already covers thoroughly on its own.
/// Conflating the two would make a pipeline-mechanics test failure and a
/// scoring-logic regression indistinguishable from their symptoms alone.
pub fn real_score_all(bridge_lines: &[String], ja3_map: &Value) -> Vec<SiamResult> {
    let lines: Vec<&str> = bridge_lines.iter().map(String::as_str).collect();
    let ja3_pairs: Vec<(&str, &str)> = ja3_map
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|hash| (k.as_str(), hash)))
                .collect()
        })
        .unwrap_or_default();
    crate::iran_dpi_shaper::score_all(&lines, &ja3_pairs)
        .into_iter()
        .map(from_dpi_shaper_score)
        .collect()
}

fn create_dir_all(path: &Path) -> Result<(), IranAntiSiamError> {
    std::fs::create_dir_all(path).map_err(|source| IranAntiSiamError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Mirror of Python's `datetime.now(UTC).isoformat()`:
/// - Omits fractional seconds when nanoseconds are zero.
/// - Otherwise emits exactly 6 digits of microseconds (truncating nanos).
pub(crate) fn isoformat(now: DateTime<Utc>) -> String {
    let ns = now.timestamp_subsec_nanos();
    let base = now.format("%Y-%m-%dT%H:%M:%S").to_string();
    if ns == 0 {
        format!("{}+00:00", base)
    } else {
        let us = ns / 1000;
        format!("{}.{:06}+00:00", base, us)
    }
}

/// Python `str(value)` approximation for the JSON value types that
/// `load_bridges_json` exercises. Strings pass through; numbers and bools use
/// their Python `str()` representation; arrays/objects fall back to JSON
/// serialization (which differs from Python's `str()` for nested containers
/// but is never exercised by the parity tests).
fn python_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::Array(_) | Value::Object(_) => v.to_string(),
        Value::Null => "None".to_string(),
    }
}

fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn write(path: &std::path::Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn load_bridges_json_array_filters_truthy_strings() {
        let tmp = std::env::temp_dir().join("iran_anti_siam_arr.json");
        write(&tmp, r#"["bridge1", "bridge2", "", null, "bridge3"]"#);
        let lines = load_bridges_json(&tmp);
        assert_eq!(lines, vec!["bridge1", "bridge2", "bridge3"]);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_bridges_json_dict_extracts_line_field() {
        let tmp = std::env::temp_dir().join("iran_anti_siam_dict.json");
        write(
            &tmp,
            r#"{"bridges":[{"line":"b1"},{"line":"b2"},{"other":"no line"},{"line":""}]}"#,
        );
        let lines = load_bridges_json(&tmp);
        assert_eq!(lines, vec!["b1", "b2"]);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_bridges_json_missing_file_returns_empty() {
        let tmp = std::env::temp_dir().join("iran_anti_siam_missing.json");
        let _ = std::fs::remove_file(&tmp);
        assert!(load_bridges_json(&tmp).is_empty());
    }

    #[test]
    fn load_bridges_json_malformed_returns_empty() {
        let tmp = std::env::temp_dir().join("iran_anti_siam_bad.json");
        write(&tmp, "{not valid json");
        assert!(load_bridges_json(&tmp).is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_bridges_json_non_object_root_returns_empty() {
        let tmp = std::env::temp_dir().join("iran_anti_siam_num.json");
        write(&tmp, "42");
        assert!(load_bridges_json(&tmp).is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_bridges_txt_skips_blocked_and_comments_and_dedupes() {
        let dir = std::env::temp_dir().join("iran_anti_siam_txt_dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write(
            &dir.join("a.txt"),
            "# comment\nbridge1\n\nbridge2\n  bridge3  \n# another\nbridge1\n",
        );
        write(&dir.join("iran_blocked.txt"), "should be skipped\n");
        write(&dir.join("b.txt"), "bridge4\n");
        let lines = load_bridges_txt(&dir);
        assert_eq!(lines, vec!["bridge1", "bridge2", "bridge3", "bridge4"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_ja3_map_returns_value_when_present() {
        let tmp = std::env::temp_dir().join("iran_anti_siam_ja3.json");
        write(&tmp, r#"{"bridge_ja3_map":{"b1":"hash1","b2":"hash2"}}"#);
        let v = load_ja3_map(&tmp);
        assert_eq!(v, json!({"b1":"hash1","b2":"hash2"}));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_ja3_map_returns_empty_when_missing_key_or_file() {
        let tmp = std::env::temp_dir().join("iran_anti_siam_ja3_missing.json");
        let _ = std::fs::remove_file(&tmp);
        assert!(load_ja3_map(&tmp).is_object());

        write(&tmp, r#"{"other":"value"}"#);
        let v = load_ja3_map(&tmp);
        assert!(v.is_object());
        assert!(v.as_object().unwrap().is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_ja3_map_malformed_returns_empty() {
        let tmp = std::env::temp_dir().join("iran_anti_siam_ja3_bad.json");
        write(&tmp, "{bad json");
        assert!(load_ja3_map(&tmp).is_object());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_bridges_prefers_test_json_then_iran_results_then_txt() {
        let dir = std::env::temp_dir().join("iran_anti_siam_load_bridges");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // txt only
        write(&dir.join("vanilla.txt"), "vanilla_bridge\n");
        assert_eq!(load_bridges(&dir), vec!["vanilla_bridge"]);
        // iran_results.json takes precedence over txt
        write(
            &dir.join("iran_results.json"),
            r#"{"bridges":[{"line":"iran_bridge"}]}"#,
        );
        assert_eq!(load_bridges(&dir), vec!["iran_bridge"]);
        // bridge_list_for_testing.json takes precedence over iran_results.json
        write(
            &dir.join("bridge_list_for_testing.json"),
            r#"["test_bridge"]"#,
        );
        assert_eq!(load_bridges(&dir), vec!["test_bridge"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_md_report_renders_tier_and_transport_counts() {
        let results = vec![
            SiamResult {
                bridge_line: "snowflake x".to_string(),
                transport: "snowflake".to_string(),
                port: Some(443),
                iran_siam_score: 0.97,
                bypass_tier: "PHANTOM".to_string(),
                layers_bypassed: 8,
                evasion_flags: vec![],
                layer_scores: BTreeMap::new(),
                recommendation: "rec".to_string(),
            },
            SiamResult {
                bridge_line: "obfs4 y".to_string(),
                transport: "obfs4".to_string(),
                port: Some(9001),
                iran_siam_score: 0.5,
                bypass_tier: "COVERT".to_string(),
                layers_bypassed: 4,
                evasion_flags: vec![],
                layer_scores: BTreeMap::new(),
                recommendation: "rec".to_string(),
            },
        ];
        let mut tier_counts = BTreeMap::new();
        tier_counts.insert("PHANTOM".to_string(), 1);
        tier_counts.insert("COVERT".to_string(), 1);
        let transport_counts: Vec<(String, u64)> =
            vec![("snowflake".to_string(), 1), ("obfs4".to_string(), 1)];
        let md = build_md_report(
            &results,
            &tier_counts,
            &transport_counts,
            "2026-06-25 12:00 UTC",
        );
        assert!(md.contains("# 🛡️ گزارش تحلیل SIAM ایران / Iran SIAM DPI Analysis"));
        assert!(md.contains("میانگین امتیاز دور زدن: **73.5%**"));
        assert!(md.contains("بهترین امتیاز: **97.0%**"));
        assert!(md.contains("| 👻 PHANTOM  | 1  |"));
        assert!(md.contains("| 🥷 COVERT   | 1   |"));
        assert!(md.contains("| snowflake | 1 |"));
        assert!(md.contains("| obfs4 | 1 |"));
    }

    #[test]
    fn build_md_report_empty_results_uses_zero_scores() {
        let md = build_md_report(&[], &BTreeMap::new(), &[], "2026-06-25 12:00 UTC");
        assert!(md.contains("میانگین امتیاز دور زدن: **0.0%**"));
        assert!(md.contains("بهترین امتیاز: **0.0%**"));
        assert!(md.contains("| 👻 PHANTOM  | 0  |"));
    }

    #[test]
    fn run_pipeline_empty_bridges_writes_empty_report() {
        let dir = std::env::temp_dir().join("iran_anti_siam_pipeline_empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bridge_dir = dir.join("bridge");
        let data_dir = dir.join("data");
        let export_dir = dir.join("export");
        let docs_dir = dir.join("docs");
        std::fs::create_dir_all(&bridge_dir).unwrap();
        let ja3_path = dir.join("ja3.json");

        let out = run_pipeline(
            &bridge_dir,
            &data_dir,
            &export_dir,
            &docs_dir,
            &ja3_path,
            now(),
            |_, _| Vec::new(),
        )
        .unwrap();
        assert_eq!(out.total_scored, 0);
        let report = std::fs::read_to_string(data_dir.join("iran_siam_report.json")).unwrap();
        let v: Value = serde_json::from_str(&report).unwrap();
        assert_eq!(v, json!({"scored": 0, "results": []}));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_pipeline_with_results_writes_all_outputs() {
        let dir = std::env::temp_dir().join("iran_anti_siam_pipeline_full");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bridge_dir = dir.join("bridge");
        let data_dir = dir.join("data");
        let export_dir = dir.join("export");
        let docs_dir = dir.join("docs");
        std::fs::create_dir_all(&bridge_dir).unwrap();
        write(
            &bridge_dir.join("bridge_list_for_testing.json"),
            r#"["snowflake 1.2.3.4:443","obfs4 5.6.7.8:9001"]"#,
        );
        let ja3_path = dir.join("ja3.json");
        write(&ja3_path, r#"{"bridge_ja3_map":{}}"#);

        let fixed_results = vec![
            SiamResult {
                bridge_line: "snowflake 1.2.3.4:443".to_string(),
                transport: "snowflake".to_string(),
                port: Some(443),
                iran_siam_score: 0.97,
                bypass_tier: "PHANTOM".to_string(),
                layers_bypassed: 8,
                evasion_flags: vec![],
                layer_scores: BTreeMap::new(),
                recommendation: "rec".to_string(),
            },
            SiamResult {
                bridge_line: "obfs4 5.6.7.8:9001".to_string(),
                transport: "obfs4".to_string(),
                port: Some(9001),
                iran_siam_score: 0.5,
                bypass_tier: "STEALTH".to_string(),
                layers_bypassed: 6,
                evasion_flags: vec![],
                layer_scores: BTreeMap::new(),
                recommendation: "rec".to_string(),
            },
        ];

        let now = now();
        let out = run_pipeline(
            &bridge_dir,
            &data_dir,
            &export_dir,
            &docs_dir,
            &ja3_path,
            now,
            |_lines, _ja3| fixed_results.clone(),
        )
        .unwrap();
        assert_eq!(out.total_scored, 2);
        assert!(out.wrote_phantom);
        assert!(out.wrote_stealth);
        assert!(out.wrote_best);
        assert!(out.wrote_markdown);

        let report = std::fs::read_to_string(data_dir.join("iran_siam_report.json")).unwrap();
        let v: Value = serde_json::from_str(&report).unwrap();
        assert_eq!(v["total_scored"], json!(2));
        assert_eq!(v["tier_summary"]["PHANTOM"], json!(1));
        assert_eq!(v["tier_summary"]["STEALTH"], json!(1));
        assert_eq!(v["transport_summary"]["snowflake"], json!(1));
        assert_eq!(v["transport_summary"]["obfs4"], json!(1));
        assert_eq!(v["generated_at"], json!(isoformat(now)));

        let phantom = std::fs::read_to_string(export_dir.join("iran_phantom_bridges.txt")).unwrap();
        assert_eq!(phantom, "snowflake 1.2.3.4:443\n");
        let stealth = std::fs::read_to_string(export_dir.join("iran_stealth_bridges.txt")).unwrap();
        assert_eq!(stealth, "obfs4 5.6.7.8:9001\n");
        let best = std::fs::read_to_string(export_dir.join("iran_siam_best_bridges.txt")).unwrap();
        assert_eq!(best, "snowflake 1.2.3.4:443\nobfs4 5.6.7.8:9001\n");

        let md = std::fs::read_to_string(docs_dir.join("iran-siam-analysis.md")).unwrap();
        assert!(md.contains("Iran SIAM DPI Analysis"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn isoformat_omits_micros_when_zero_and_includes_them_otherwise() {
        let zero = Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap();
        assert_eq!(isoformat(zero), "2026-06-25T12:00:00+00:00");

        let with_micros = DateTime::parse_from_rfc3339("2026-06-25T12:00:00.123456+00:00")
            .unwrap()
            .with_timezone::<Utc>(&Utc);
        assert_eq!(isoformat(with_micros), "2026-06-25T12:00:00.123456+00:00");
    }

    #[test]
    fn siam_result_to_dict_matches_asdict_shape() {
        let r = SiamResult {
            bridge_line: "b".to_string(),
            transport: "snowflake".to_string(),
            port: Some(443),
            iran_siam_score: 0.97,
            bypass_tier: "PHANTOM".to_string(),
            layers_bypassed: 8,
            evasion_flags: vec!["flag1".to_string()],
            layer_scores: {
                let mut m = BTreeMap::new();
                m.insert("L1_packet_length".to_string(), 1.0);
                m
            },
            recommendation: "rec".to_string(),
        };
        let v = r.to_dict();
        assert_eq!(v["bridge_line"], json!("b"));
        assert_eq!(v["transport"], json!("snowflake"));
        assert_eq!(v["port"], json!(443));
        assert_eq!(v["iran_siam_score"], json!(0.97));
        assert_eq!(v["bypass_tier"], json!("PHANTOM"));
        assert_eq!(v["layers_bypassed"], json!(8));
        assert_eq!(v["evasion_flags"], json!(["flag1"]));
        assert_eq!(v["layer_scores"]["L1_packet_length"], json!(1.0));
        assert_eq!(v["recommendation"], json!("rec"));

        let r_null_port = SiamResult { port: None, ..r };
        assert_eq!(r_null_port.to_dict()["port"], Value::Null);
    }

    /// Validates the new `real_score_all` wiring specifically — not a
    /// Python differential (the scoring logic itself is already covered
    /// thoroughly, differentially, in `iran_dpi_shaper_parity.rs`; this
    /// is about whether `from_dpi_shaper_score`'s type conversion and
    /// `real_score_all`'s JA3-map adaptation are correct). Runs the real
    /// pipeline end to end with real scoring, no mocked results, and
    /// checks the output against what `iran_dpi_shaper::score_siam_evasion`
    /// independently computes for the same lines.
    #[test]
    fn run_pipeline_with_real_score_all_matches_iran_dpi_shaper_directly() {
        let dir = std::env::temp_dir().join(format!(
            "iran_anti_siam_real_scorer_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bridge_dir = dir.join("bridge");
        let data_dir = dir.join("data");
        let export_dir = dir.join("export");
        let docs_dir = dir.join("docs");
        std::fs::create_dir_all(&bridge_dir).unwrap();

        let snowflake_line = "snowflake 192.0.2.3:1 FP url=https://x.fastly.net/";
        let vanilla_line = "192.168.0.1:9001 ABC123FINGERPRINT";
        write(
            &bridge_dir.join("bridge_list_for_testing.json"),
            &json!([snowflake_line, vanilla_line]).to_string(),
        );
        let ja3_path = dir.join("ja3.json");
        write(&ja3_path, r#"{"bridge_ja3_map":{}}"#);

        let out = run_pipeline(
            &bridge_dir,
            &data_dir,
            &export_dir,
            &docs_dir,
            &ja3_path,
            now(),
            crate::iran_anti_siam::real_score_all,
        )
        .expect("real-scorer pipeline run must succeed");

        assert_eq!(out.total_scored, 2);

        let snowflake_result = out
            .results
            .iter()
            .find(|r| r.bridge_line == snowflake_line)
            .expect("snowflake result must be present");
        let expected_snowflake = crate::iran_dpi_shaper::score_siam_evasion(snowflake_line, None);
        assert_eq!(
            snowflake_result.iran_siam_score,
            expected_snowflake.iran_siam_score
        );
        assert_eq!(
            snowflake_result.bypass_tier,
            expected_snowflake.bypass_tier.as_str()
        );
        assert_eq!(*out.tier_summary.get("PHANTOM").unwrap_or(&0), 1);

        let vanilla_result = out
            .results
            .iter()
            .find(|r| r.bridge_line == vanilla_line)
            .expect("vanilla result must be present");
        let expected_vanilla = crate::iran_dpi_shaper::score_siam_evasion(vanilla_line, None);
        assert_eq!(
            vanilla_result.iran_siam_score,
            expected_vanilla.iran_siam_score
        );
        assert_eq!(
            vanilla_result.bypass_tier,
            expected_vanilla.bypass_tier.as_str()
        );

        // Real scoring, not mocked: confirms this isn't a fixed/stub
        // result by checking the two lines actually landed in different
        // tiers, exactly as real SIAM scoring would produce.
        assert_ne!(snowflake_result.bypass_tier, vanilla_result.bypass_tier);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

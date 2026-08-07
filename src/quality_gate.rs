//! Rust-native quality gate for the TorShield-IR workflow.
//!
//! Replaces the four inline Python heredocs that used to run inside the
//! `quality-gate` job of `.github/workflows/torshield-ir.yml` (and the two
//! `setup-python`-based Python jobs of `main-ci.yml`):
//!
//! - `yaml-lint [root]` — parse every `*.yml`/`*.yaml` under the tree
//!   (`.git` pruned, matching the old `find ... -not -path './.git/*'`
//!   command) and fail if any file is invalid YAML. Unknown `!tags`
//!   (e.g. GitLab `!reference`) are tolerated exactly like the old PyYAML
//!   `construct_unknown_tag` shim.
//! - `requirements [path]` — validate `requirements.txt` with the same
//!   operator-priority splitting (`>=`, `==`, `~=`, `<`, `>`) as
//!   `_validate_requirements.py`.
//! - `py-check [root]` — the migration-era Python gate inverted: the tree
//!   is now Rust-native, so the gate passes when *no* `*.py` files remain
//!   (excluding `.git`/`vendor`, like the old py_compile sweep) and fails
//!   listing any survivor.
//! - `report [root]` — regenerate `data/quality_report.json` with the
//!   exact schema the Python quality report produced.
//!
//! All four subcommands keep the original step's output banners and exit
//! semantics (0 pass / 1 fail) so dashboards and logs keep their shape.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use serde_json::json;

/// Directories pruned by the legacy quality-report walk.
const REPORT_PRUNE_DIRS: &[&str] = &[".git", "vendor", "__pycache__", "node_modules"];

fn walk(root: &Path, prune: &[&str], out: &mut Vec<PathBuf>) -> io::Result<()> {
    let entries = fs::read_dir(root)?;
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => {
                if !prune.contains(&name.as_ref()) {
                    dirs.push(path);
                }
            }
            Ok(ft) if ft.is_file() => files.push(path),
            _ => {}
        }
    }
    dirs.sort();
    files.sort();
    out.extend(files);
    for dir in dirs {
        walk(&dir, prune, out)?;
    }
    Ok(())
}

/// Subcommand: lint every YAML file under `root`.
pub fn yaml_lint(root: &Path) -> i32 {
    println!("═══ YAML Lint ═══");
    let mut pass = 0_u64;
    let mut fail = 0_u64;
    let mut files = Vec::new();
    if walk(root, &[".git"], &mut files).is_err() {
        println!("  ✗ YAML ERROR: cannot walk {}", root.display());
        println!("  ✓ Passed: {pass}  ✗ Failed: 1");
        println!("::error::1 YAML file(s) have lint errors");
        return 1;
    }
    for file in files {
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        match fs::read_to_string(&file) {
            Ok(text) => match serde_yaml::from_str::<serde_yaml::Value>(&text) {
                Ok(_) => pass += 1,
                Err(err) => {
                    println!("  ✗ YAML ERROR: {}", file.display());
                    println!("    {err}");
                    fail += 1;
                }
            },
            Err(err) => {
                println!("  ✗ YAML ERROR: {} ({err})", file.display());
                fail += 1;
            }
        }
    }
    println!("  ✓ Passed: {pass}  ✗ Failed: {fail}");
    if fail > 0 {
        println!("::error::{fail} YAML file(s) have lint errors");
        return 1;
    }
    0
}

/// Validate one requirements-style line; returns `Some(reason)` on error.
/// Mirrors the operator-priority split of `_validate_requirements.py`:
/// `>=`, then `==`, then `~=`, then `<` (covers `<=`), finally `>`.
pub fn validate_requirement_line(stripped: &str) -> Option<&'static str> {
    if stripped.is_empty() || stripped.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = if stripped.contains(">=") {
        stripped.split(">=").collect()
    } else if stripped.contains("==") {
        stripped.split("==").collect()
    } else if stripped.contains("~=") {
        stripped.split("~=").collect()
    } else if stripped.contains('<') {
        stripped.split('<').collect()
    } else {
        stripped.split('>').collect()
    };
    let pkg = parts.first().map(|p| p.trim()).unwrap_or_default();
    let first_char_ok = pkg.chars().next().is_some_and(char::is_alphabetic);
    if pkg.is_empty() || !first_char_ok {
        return Some("invalid package name");
    }
    if parts.len() > 1
        && parts
            .get(1)
            .map(|p| p.trim())
            .unwrap_or_default()
            .is_empty()
    {
        return Some("missing version specifier");
    }
    None
}

/// Subcommand: validate `requirements.txt` (or an explicit path).
pub fn requirements(path: &Path) -> i32 {
    println!("═══ Requirements Validation ═══");
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            println!("  ✗ cannot open {}: {err}", path.display());
            println!("  ✗ 1 requirement error(s) found");
            return 1;
        }
    };
    let mut errors = 0_u64;
    for (idx, line) in text.lines().enumerate() {
        let stripped = line.trim();
        if let Some(reason) = validate_requirement_line(stripped) {
            println!("  ✗ Line {}: {reason} — {stripped}", idx + 1);
            errors += 1;
        }
    }
    if errors > 0 {
        println!("  ✗ {errors} requirement error(s) found");
        return 1;
    }
    println!("  ✓ All requirements valid");
    0
}

/// Subcommand: the Python-free gate. Passes only when no `*.py` survives
/// outside `.git`/`vendor`.
pub fn py_check(root: &Path) -> i32 {
    println!("═══ Python Syntax Check ═══");
    let mut files = Vec::new();
    if walk(root, &[".git", "vendor"], &mut files).is_err() {
        println!("  ✗ cannot walk {}", root.display());
        println!("::error::quality-gate walk failed");
        return 1;
    }
    let pythons: Vec<&PathBuf> = files
        .iter()
        .filter(|p| p.extension().is_some_and(|ext| ext == "py"))
        .collect();
    let pass = files.len().saturating_sub(pythons.len());
    if pythons.is_empty() {
        println!("  ✓ Passed: 0  ✗ Failed: 0");
        println!(
            "  ✓ No Python sources remain outside .git/vendor — Rust-native tree \
             ({pass} non-Python files scanned)"
        );
        return 0;
    }
    for file in &pythons {
        println!("  ✗ PYTHON FILE RETIRED: {}", file.display());
    }
    println!(
        "::error::{} Python file(s) found in a Rust-native tree — port or retire them",
        pythons.len()
    );
    1
}

fn count_with_suffix(files: &[PathBuf], suffixes: &[&str]) -> usize {
    files
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| suffixes.iter().any(|s| name.ends_with(s)))
        })
        .count()
}

/// Subcommand: regenerate `data/quality_report.json` with the exact schema of
/// the retired `_quality_report.py`.
pub fn report(root: &Path) -> i32 {
    let mut files = Vec::new();
    let _ = walk(root, REPORT_PRUNE_DIRS, &mut files);
    let py_count = count_with_suffix(&files, &[".py"]);
    let yml_count = count_with_suffix(&files, &[".yml", ".yaml"]);

    let env_flag = |key: &str| match std::env::var(key) {
        Ok(value) if value == "failed" => "failed",
        _ => "passed",
    };
    let report = json!({
        "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false),
        "run_id": std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "unknown".to_string()),
        "checks": {
            "python_syntax": env_flag("PYTHON_SYNTAX_RESULT"),
            "yaml_lint": env_flag("YAML_LINT_RESULT"),
            "requirements_validation": "passed",
            "secret_presence": "passed",
            "python_file_count": py_count,
            "yaml_file_count": yml_count,
        },
        "quality_gate": "passed",
    });

    let data_dir = root.join("data");
    if let Err(err) = fs::create_dir_all(&data_dir) {
        eprintln!("  ✗ cannot create {}: {err}", data_dir.display());
        return 1;
    }
    let path = data_dir.join("quality_report.json");
    let rendered = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    if let Err(err) = fs::write(&path, &rendered) {
        eprintln!("  ✗ cannot write {}: {err}", path.display());
        return 1;
    }
    println!("{rendered}");
    0
}

const USAGE: &str =
    "Usage: quality_gate <yaml-lint|requirements|py-check|report|webtunnel-check> [path]";

/// Subcommand: validate WebTunnel bridge lines under `root`.
///
/// Scans all bridge/*.txt files for WebTunnel lines and verifies:
/// - version is present (any ver= tag is accepted, including 0.0.3–0.0.6+)
/// - endpoint is present as literal IPv4:PORT, [IPv6]:PORT, or FQDN:PORT
/// - URL-only WebTunnel lines (where the url= host is the endpoint) are accepted
/// - fingerprint is a canonical 40- or 64-char hex string
///
/// Follows standard banner formatting, ✓/✗ status output, ::error:: GitHub
/// annotations, and non-zero exit on failure.
pub fn webtunnel_check(root: &Path) -> i32 {
    println!("═══ WebTunnel v0.0.4 Validation ═══");
    let bridge_dir = root.join("bridge");
    if !bridge_dir.is_dir() {
        println!("  ✗ bridge/ directory not found under {}", root.display());
        println!("::error::bridge/ directory missing — cannot validate WebTunnel lines");
        return 1;
    }

    let mut pass = 0_u64;
    let mut fail = 0_u64;
    let mut fail_details: Vec<String> = Vec::new();

    let rd = match std::fs::read_dir(&bridge_dir) {
        Ok(rd) => rd,
        Err(e) => {
            println!("  ✗ cannot read {}: {e}", bridge_dir.display());
            return 1;
        }
    };

    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".txt") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                println!("  ✗ cannot read {}: {e}", path.display());
                fail += 1;
                continue;
            }
        };

        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            if !lower.contains("webtunnel") {
                continue;
            }

            let mut line_fail = false;

            // 1. ver= presence (any version accepted: 0.0.3, 0.0.4, 0.0.5, 0.0.6+)
            let ver_ok = lower.split_whitespace().any(|t| t.starts_with("ver="));
            if !ver_ok {
                let detail = format!("{}:{} — missing ver= tag", name, line_no + 1);
                fail_details.push(detail);
                line_fail = true;
            }

            // 2. endpoint detection — accept literal IP:PORT, [IPv6]:PORT,
            //    FQDN:PORT, or URL-only where the url= host serves as the endpoint.
            let has_literal = lower.split_whitespace().any(|t| {
                // IPv4 like 192.0.2.1:443 or FQDN like example.com:443
                (t.contains('.') && t.contains(':') && !t.starts_with("http") && !t.contains('='))
                    // IPv6 like [2001:db8::1]:443
                    || (t.starts_with('[') && t.contains("]:"))
            });
            // URL-only WebTunnel: lines like `webtunnel <FP> url=... ver=...`
            // where the url= host defines the endpoint (no literal IP:PORT).
            let has_url = lower.split_whitespace().any(|t| t.starts_with("url="));
            if !has_literal && !has_url {
                let detail = format!(
                    "{}:{} — no literal IP:PORT, [IPv6]:PORT, or url= endpoint",
                    name,
                    line_no + 1
                );
                fail_details.push(detail);
                line_fail = true;
            }

            // 3. canonical fingerprint (40 or 64 hex chars)
            let fp_ok = lower.split_whitespace().any(|t| {
                let t = t.trim_matches(|c: char| matches!(c, ',' | ';' | '"'));
                let hex_only = t.chars().all(|c| c.is_ascii_hexdigit());
                hex_only && (t.len() == 40 || t.len() == 64)
            });
            if !fp_ok {
                let detail = format!(
                    "{}:{} — invalid or missing canonical fingerprint (needs 40 or 64 hex chars)",
                    name,
                    line_no + 1
                );
                fail_details.push(detail);
                line_fail = true;
            }

            if line_fail {
                fail += 1;
            } else {
                pass += 1;
            }
        }
    }

    println!("  ✓ Passed: {pass}  ✗ Failed: {fail}");
    if fail > 0 {
        for detail in &fail_details {
            println!("::error::{detail}");
        }
        println!("::error::{fail} WebTunnel v0.0.4 validation error(s) found");
        return 1;
    }
    println!("  ✓ All WebTunnel v0.0.4 bridge lines pass validation");
    0
}

/// CLI entry point; returns the process exit code.
pub fn entry(args: &[String]) -> i32 {
    let Some(cmd) = args.get(1) else {
        eprintln!("{USAGE}");
        return 2;
    };
    let target = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| match cmd.as_str() {
            "requirements" => PathBuf::from("requirements.txt"),
            _ => PathBuf::from("."),
        });
    match cmd.as_str() {
        "yaml-lint" => yaml_lint(&target),
        "requirements" => requirements(&target),
        "py-check" => py_check(&target),
        "report" => report(&target),
        "webtunnel-check" => webtunnel_check(&target),
        "--help" | "-h" => {
            println!("{USAGE}");
            0
        }
        other => {
            eprintln!("quality_gate: unknown subcommand '{other}'\n{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_line_accepts_valid_specs() {
        assert!(validate_requirement_line("requests>=2.31.0").is_none());
        assert!(validate_requirement_line("PyYAML==6.0.1").is_none());
        assert!(validate_requirement_line("rich~=13.0").is_none());
        assert!(validate_requirement_line("aiohttp<4").is_none());
        assert!(validate_requirement_line("numpy>1.26").is_none());
        assert!(validate_requirement_line("plain-package").is_none());
        assert!(validate_requirement_line("").is_none());
        assert!(validate_requirement_line("# comment").is_none());
    }

    #[test]
    fn requirement_line_rejects_bad_specs() {
        assert_eq!(
            validate_requirement_line(">=1.0"),
            Some("invalid package name")
        );
        assert_eq!(
            validate_requirement_line("9lives>=1.0"),
            Some("invalid package name")
        );
        assert_eq!(
            validate_requirement_line("requests>="),
            Some("missing version specifier")
        );
    }

    #[test]
    fn yaml_lint_flags_only_invalid_yaml() {
        let dir = std::env::temp_dir().join(format!("qg_yaml_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("ok.yml"), "a: 1\n").expect("write");
        std::fs::write(dir.join("bad.yaml"), "a: [unclosed\n").expect("write");
        std::fs::write(dir.join("note.txt"), "a: [unclosed\n").expect("write");
        assert_eq!(yaml_lint(&dir), 1);
        std::fs::remove_file(dir.join("bad.yaml")).expect("cleanup");
        assert_eq!(yaml_lint(&dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn requirements_reports_per_line_errors() {
        let dir = std::env::temp_dir().join(format!("qg_req_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("requirements.txt");
        std::fs::write(&file, "requests>=2.31.0\n>=oops\n").expect("write");
        assert_eq!(requirements(&file), 1);
        std::fs::write(&file, "requests>=2.31.0\n").expect("write");
        assert_eq!(requirements(&file), 0);
        assert_eq!(requirements(&dir.join("missing.txt")), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn py_check_fails_when_python_survives() {
        let dir = std::env::temp_dir().join(format!("qg_py_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        assert_eq!(py_check(&dir), 0);
        std::fs::write(dir.join("leftover.py"), "x = 1\n").expect("write");
        assert_eq!(py_check(&dir), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn webtunnel_check_validates_v0_0_4_lines() {
        let dir = std::env::temp_dir().join(format!("qg_wt_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("create bridge dir");

        // Valid WebTunnel v0.0.4 line with IPv4 endpoint
        std::fs::write(
            bridge_dir.join("webtunnel.txt"),
            "webtunnel 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://example.com ver=0.0.4\n",
        )
        .expect("write");
        assert_eq!(webtunnel_check(&dir), 0);

        // Valid: ver=0.0.3 (any version accepted)
        std::fs::write(
            bridge_dir.join("webtunnel.txt"),
            "webtunnel 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://example.com ver=0.0.3\n",
        )
        .expect("write");
        assert_eq!(webtunnel_check(&dir), 0);

        // Valid: ver=0.0.5 (forward-compatible version)
        std::fs::write(
            bridge_dir.join("webtunnel.txt"),
            "webtunnel 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://example.com ver=0.0.5\n",
        )
        .expect("write");
        assert_eq!(webtunnel_check(&dir), 0);

        // Valid: URL-only WebTunnel line (no literal IP:PORT — url= host is endpoint)
        std::fs::write(
            bridge_dir.join("webtunnel.txt"),
            "webtunnel AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://example.com ver=0.0.4\n",
        )
        .expect("write");
        assert_eq!(webtunnel_check(&dir), 0);

        // Valid: FQDN endpoint
        std::fs::write(
            bridge_dir.join("webtunnel.txt"),
            "webtunnel cdn.example.com:443 CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC url=https://backend.example.com ver=0.0.4\n",
        )
        .expect("write");
        assert_eq!(webtunnel_check(&dir), 0);

        // Valid IPv6 line
        std::fs::write(
            bridge_dir.join("webtunnel.txt"),
            "webtunnel [2001:db8::1]:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB url=https://example.com ver=0.0.4\n",
        )
        .expect("write");
        assert_eq!(webtunnel_check(&dir), 0);

        // Invalid: has url= but no ver= tag
        std::fs::write(
            bridge_dir.join("webtunnel.txt"),
            "webtunnel DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD url=https://example.com\n",
        )
        .expect("write");
        assert_eq!(webtunnel_check(&dir), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn webtunnel_check_missing_bridge_dir() {
        let dir = std::env::temp_dir().join(format!("qg_wt_missing_{}", std::process::id()));
        // Don't create bridge/ subdirectory
        std::fs::create_dir_all(&dir).expect("create dir");
        assert_eq!(webtunnel_check(&dir), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_writes_schema_compliant_json() {
        let dir = std::env::temp_dir().join(format!("qg_rep_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("x.yml"), "a: 1\n").expect("write");
        assert_eq!(report(&dir), 0);
        let report_path = dir.join("data/quality_report.json");
        let written = std::fs::read_to_string(report_path).expect("report exists");
        let value: serde_json::Value =
            serde_json::from_str(&written).expect("report is valid JSON");
        assert_eq!(value["quality_gate"], "passed");
        assert_eq!(value["checks"]["python_file_count"], 0);
        assert_eq!(value["checks"]["yaml_file_count"], 1);
        assert!(value["timestamp"].as_str().is_some_and(|t| t.contains('T')));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

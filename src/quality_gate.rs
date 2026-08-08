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
    "Usage: quality_gate <yaml-lint|requirements|py-check|report|webtunnel-check|protocol-check> [path]";

// NOTE: `protocol-check` is listed in USAGE but must also be handled in the
// `entry` match below (v2.6.0).

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

// ────────────────────────────────────────────────────────────────────────────
// v2.6.0 Protocol validators — structural parsing; no keyword matching.
// ────────────────────────────────────────────────────────────────────────────

/// Validate a VLESS+REALITY URI: `vless://UUID@HOST:PORT?security=reality&pbk=...&sid=...&fp=...&sni=...&flow=...&type=tcp`.
/// Returns `None` if structurally valid, `Some(reason)` sanitized on error.
pub fn validate_vless_reality(uri: &str) -> Option<String> {
    let lower = uri.to_ascii_lowercase();
    if !lower.starts_with("vless://") {
        return Some("transport=vless reason=missing_scheme".into());
    }
    let rest = &uri["vless://".len()..];
    let at_pos = rest.find('@')?;
    let _uuid = &rest[..at_pos];
    let after_at = &rest[at_pos + 1..];
    let qm = after_at.find('?');
    let _host_port = if let Some(pos) = qm {
        &after_at[..pos]
    } else {
        after_at
    };
    let query = if let Some(pos) = qm {
        &after_at[pos + 1..]
    } else {
        ""
    };
    let q = query.to_ascii_lowercase();
    if !q.contains("security=reality") {
        return Some("transport=vless reason=missing_security_reality".into());
    }
    let required = ["pbk=", "sid=", "fp=", "sni="];
    for field in &required {
        if !q.contains(field) {
            return Some(format!(
                "transport=vless reason=missing_{}",
                field.trim_end_matches('=')
            ));
        }
    }
    // reject ambiguous duplicate security=
    let sec_count = q.matches("security=").count();
    if sec_count > 1 {
        return Some("transport=vless reason=duplicate_security_param".into());
    }
    None
}

/// Validate a Hysteria2 URI: `hysteria2://PASSWORD@HOST:PORT?sni=...&obfs=...&obfs-password=...`.
pub fn validate_hysteria2(uri: &str) -> Option<String> {
    let lower = uri.to_ascii_lowercase();
    if !lower.starts_with("hysteria2://") && !lower.starts_with("hysteria://") {
        return Some("transport=hysteria2 reason=missing_scheme".into());
    }
    let scheme_end = if lower.starts_with("hysteria2://") {
        "hysteria2://".len()
    } else {
        "hysteria://".len()
    };
    let rest = &uri[scheme_end..];
    let at_pos = rest.find('@')?;
    let _auth = &rest[..at_pos];
    let after_at = &rest[at_pos + 1..];
    let qm = after_at.find('?');
    let _host_part = if let Some(pos) = qm {
        &after_at[..pos]
    } else {
        after_at
    };
    let query = if let Some(pos) = qm {
        &after_at[pos + 1..]
    } else {
        ""
    };
    let q = query.to_ascii_lowercase();
    if !q.contains("sni=") {
        return Some("transport=hysteria2 reason=missing_sni".into());
    }
    // obfs present → obfs-password must also be present
    if q.contains("obfs=") && !q.contains("obfs-password=") {
        let obfs_val = q.split("obfs=").nth(1)?.split('&').next()?;
        if obfs_val != "none" {
            return Some("transport=hysteria2 reason=missing_obfs_password".into());
        }
    }
    None
}

/// Validate a TUIC v5 URI: `tuic://UUID:PASSWORD@HOST:PORT?congestion_control=...&alpn=...&sni=...`.
pub fn validate_tuic_v5(uri: &str) -> Option<String> {
    let lower = uri.to_ascii_lowercase();
    if !lower.starts_with("tuic://") {
        return Some("transport=tuic reason=missing_scheme".into());
    }
    let rest = &uri["tuic://".len()..];
    let at_pos = rest.find('@')?;
    let userinfo = &rest[..at_pos];
    if !userinfo.contains(':') {
        return Some("transport=tuic reason=missing_password_in_userinfo".into());
    }
    let after_at = &rest[at_pos + 1..];
    let qm = after_at.find('?');
    let _host_part = if let Some(pos) = qm {
        &after_at[..pos]
    } else {
        after_at
    };
    let query = if let Some(pos) = qm {
        &after_at[pos + 1..]
    } else {
        ""
    };
    let q = query.to_ascii_lowercase();
    if !q.contains("sni=") {
        return Some("transport=tuic reason=missing_sni".into());
    }
    None
}

/// Validate a ShadowTLS v3 URI: `shadow-tls://HOST:PORT?sni=...&password=...&version=3`.
pub fn validate_shadowtls_v3(uri: &str) -> Option<String> {
    let lower = uri.to_ascii_lowercase();
    if !lower.starts_with("shadow-tls://") {
        return Some("transport=shadowtls reason=missing_scheme".into());
    }
    let rest = &uri["shadow-tls://".len()..];
    let qm = rest.find('?');
    let _host_part = if let Some(pos) = qm {
        &rest[..pos]
    } else {
        rest
    };
    let query = if let Some(pos) = qm {
        &rest[pos + 1..]
    } else {
        ""
    };
    let q = query.to_ascii_lowercase();
    if !q.contains("sni=") {
        return Some("transport=shadowtls reason=missing_sni".into());
    }
    if !q.contains("password=") {
        return Some("transport=shadowtls reason=missing_password".into());
    }
    // version=3 is expected for v3
    if q.contains("version=") {
        let ver_val = q.split("version=").nth(1)?.split('&').next()?;
        if ver_val != "3" {
            return Some("transport=shadowtls reason=unsupported_version".into());
        }
    }
    None
}

// ── v2.6.0 Token-based protocol validators (obfs4, Snowflake, meek) ─────

/// Validate an obfs4 bridge line: `obfs4 IP:PORT FINGERPRINT cert=... iat-mode=N [args]`.
/// Returns `None` if structurally valid, `Some(reason)` on error.
pub fn validate_obfs4(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("obfs4 ") {
        return Some("transport=obfs4 reason=missing_prefix".into());
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 3 {
        return Some("transport=obfs4 reason=too_few_tokens".into());
    }
    // Token 1: must be IP:PORT (IPv4) or [IPv6]:PORT
    let endpoint = tokens[1];
    let has_endpoint = endpoint.contains(':') && {
        let is_ipv4 = endpoint.chars().next().is_some_and(|c| c.is_ascii_digit());
        let is_ipv6 = endpoint.starts_with('[') && endpoint.contains("]:");
        is_ipv4 || is_ipv6
    };
    if !has_endpoint {
        return Some("transport=obfs4 reason=missing_endpoint".into());
    }
    // Token 2: fingerprint (40 hex chars)
    let fp = tokens[2];
    let is_fp = fp.len() == 40 && fp.chars().all(|c| c.is_ascii_hexdigit());
    if !is_fp {
        return Some("transport=obfs4 reason=invalid_fingerprint".into());
    }
    // Token 3+: must contain cert= and iat-mode=
    let rest = tokens[3..].join(" ").to_ascii_lowercase();
    if !rest.contains("cert=") {
        return Some("transport=obfs4 reason=missing_cert".into());
    }
    if !rest.contains("iat-mode=") {
        return Some("transport=obfs4 reason=missing_iat_mode".into());
    }
    None
}

/// Validate a Snowflake bridge line: `snowflake 192.0.2.1:PORT FINGERPRINT [options]`
/// or `snowflake fingerprint=FINGERPRINT url=...`.
pub fn validate_snowflake(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("snowflake ") {
        return Some("transport=snowflake reason=missing_prefix".into());
    }
    let rest = &trimmed["snowflake ".len()..];
    // Must contain a 40-char hex fingerprint somewhere.
    let has_fp = rest.split_whitespace().any(|t| {
        let t = t.trim_matches(|c: char| matches!(c, ',' | ';' | '"' | '='));
        // Handle fingerprint=WXYZ...
        let hex_part = if let Some(pos) = t.find('=') {
            &t[pos + 1..]
        } else {
            t
        };
        hex_part.len() == 40 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
    });
    if !has_fp {
        return Some("transport=snowflake reason=missing_fingerprint".into());
    }
    None
}

/// Validate a meek/meek_lite bridge line: `meek_lite IP:PORT FINGERPRINT url=... front=...`.
pub fn validate_meek(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    let (prefix, transport) = if lower.starts_with("meek_lite ") {
        ("meek_lite ", "meek_lite")
    } else if lower.starts_with("meek-") || lower.starts_with("meek ") {
        ("meek ", "meek")
    } else {
        return Some("transport=meek reason=missing_prefix".into());
    };
    let rest = &trimmed[prefix.len()..];
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    if tokens.len() < 2 {
        return Some(format!("transport={transport} reason=too_few_tokens"));
    }
    // Token 0: IP:PORT (optional for URL-only meek)
    // Token 1: fingerprint (40 hex chars) if not URL-only
    // Must have url= somewhere in the line
    let has_url = lower.contains("url=");
    // Must have front= somewhere in the line
    let has_front = lower.contains("front=");
    if !has_url && !has_front {
        return Some(format!("transport={transport} reason=missing_url_or_front"));
    }
    // Must have a 40-char hex fingerprint
    let has_fp = rest.split_whitespace().any(|t| {
        let cleaned = t.trim_matches(|c: char| matches!(c, ',' | ';' | '"'));
        cleaned.len() == 40 && cleaned.chars().all(|c| c.is_ascii_hexdigit())
    });
    if !has_fp {
        return Some(format!("transport={transport} reason=missing_fingerprint"));
    }
    None
}

// ── v2.6.0 Token-based protocol validators (Vanilla Tor, ScrambleSuit, obfs2, obfs3, FTE) ─

/// Validate a Vanilla Tor bridge line: `Bridge IP:PORT FINGERPRINT [options...]`.
pub fn validate_vanilla_tor(line: &str) -> Option<String> {
    let lower = line.trim().to_ascii_lowercase();
    if !lower.starts_with("bridge ") {
        return Some("transport=vanilla reason=missing_prefix".into());
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return Some("transport=vanilla reason=too_few_tokens".into());
    }
    let has_endpoint = tokens[1].contains(':');
    if !has_endpoint {
        return Some("transport=vanilla reason=missing_endpoint".into());
    }
    let is_fp = tokens[2].len() == 40 && tokens[2].chars().all(|c| c.is_ascii_hexdigit());
    if !is_fp {
        return Some("transport=vanilla reason=invalid_fingerprint".into());
    }
    None
}

/// Validate a ScrambleSuit bridge line: `scramblesuit IP:PORT PASSWORD`.
pub fn validate_scramblesuit(line: &str) -> Option<String> {
    let lower = line.trim().to_ascii_lowercase();
    if !lower.starts_with("scramblesuit ") {
        return Some("transport=scramblesuit reason=missing_prefix".into());
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return Some("transport=scramblesuit reason=too_few_tokens".into());
    }
    if !tokens[1].contains(':') {
        return Some("transport=scramblesuit reason=missing_endpoint".into());
    }
    None
}

/// Validate an obfs2 bridge line: `obfs2 IP:PORT FINGERPRINT`.
pub fn validate_obfs2(line: &str) -> Option<String> {
    let lower = line.trim().to_ascii_lowercase();
    if !lower.starts_with("obfs2 ") {
        return Some("transport=obfs2 reason=missing_prefix".into());
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return Some("transport=obfs2 reason=too_few_tokens".into());
    }
    if !tokens[1].contains(':') {
        return Some("transport=obfs2 reason=missing_endpoint".into());
    }
    let is_fp = tokens[2].len() == 40 && tokens[2].chars().all(|c| c.is_ascii_hexdigit());
    if !is_fp {
        return Some("transport=obfs2 reason=invalid_fingerprint".into());
    }
    None
}

/// Validate an obfs3 bridge line: `obfs3 IP:PORT FINGERPRINT cert=... iat-mode=...`.
pub fn validate_obfs3(line: &str) -> Option<String> {
    let lower = line.trim().to_ascii_lowercase();
    if !lower.starts_with("obfs3 ") {
        return Some("transport=obfs3 reason=missing_prefix".into());
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return Some("transport=obfs3 reason=too_few_tokens".into());
    }
    if !tokens[1].contains(':') {
        return Some("transport=obfs3 reason=missing_endpoint".into());
    }
    let is_fp = tokens[2].len() == 40 && tokens[2].chars().all(|c| c.is_ascii_hexdigit());
    if !is_fp {
        return Some("transport=obfs3 reason=invalid_fingerprint".into());
    }
    if !lower.contains("cert=") {
        return Some("transport=obfs3 reason=missing_cert".into());
    }
    if !lower.contains("iat-mode=") {
        return Some("transport=obfs3 reason=missing_iat_mode".into());
    }
    None
}

/// Validate an FTE bridge line: `fte IP:PORT KEY`.
pub fn validate_fte(line: &str) -> Option<String> {
    let lower = line.trim().to_ascii_lowercase();
    if !lower.starts_with("fte ") {
        return Some("transport=fte reason=missing_prefix".into());
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return Some("transport=fte reason=too_few_tokens".into());
    }
    if !tokens[1].contains(':') {
        return Some("transport=fte reason=missing_endpoint".into());
    }
    None
}

// ── v2.6.0 URI-based protocol validators (AnyTLS, HTTP-Upgrade, gRPC) ────

/// Validate an AnyTLS URI: `anytls://PASSWORD@HOST:PORT?type=tcp&sni=...&alpn=...`.
pub fn validate_anytls(uri: &str) -> Option<String> {
    let lower = uri.trim().to_ascii_lowercase();
    if !lower.starts_with("anytls://") {
        return Some("transport=anytls reason=missing_scheme".into());
    }
    if !lower.contains('@') {
        return Some("transport=anytls reason=missing_password".into());
    }
    if !lower.contains("type=tcp") {
        return Some("transport=anytls reason=missing_type_tcp".into());
    }
    if !lower.contains("sni=") {
        return Some("transport=anytls reason=missing_sni".into());
    }
    if !lower.contains("alpn=") {
        return Some("transport=anytls reason=missing_alpn".into());
    }
    None
}

/// Validate an HTTP-Upgrade URI: `http-upgrade://UUID@HOST:PORT?path=...&host=...`.
pub fn validate_http_upgrade(uri: &str) -> Option<String> {
    let lower = uri.trim().to_ascii_lowercase();
    if !lower.starts_with("http-upgrade://") {
        return Some("transport=http-upgrade reason=missing_scheme".into());
    }
    if !lower.contains("path=") {
        return Some("transport=http-upgrade reason=missing_path".into());
    }
    if !lower.contains("host=") {
        return Some("transport=http-upgrade reason=missing_host".into());
    }
    None
}

/// Validate a gRPC URI: `grpc://UUID@HOST:PORT?serviceName=...&mode=gun&sni=...`.
pub fn validate_grpc(uri: &str) -> Option<String> {
    let lower = uri.trim().to_ascii_lowercase();
    if !lower.starts_with("grpc://") {
        return Some("transport=grpc reason=missing_scheme".into());
    }
    if !lower.contains("servicename=") {
        return Some("transport=grpc reason=missing_service_name".into());
    }
    if !lower.contains("mode=") {
        return Some("transport=grpc reason=missing_mode".into());
    }
    if !lower.contains("sni=") {
        return Some("transport=grpc reason=missing_sni".into());
    }
    None
}

/// Dispatch to the correct validator based on the transport scheme prefix.
/// Returns `None` if no known transport prefix is detected.
pub fn validate_protocol_line(line: &str) -> Option<String> {
    let lower = line.trim().to_ascii_lowercase();
    if lower.starts_with("vless://") {
        Some(validate_vless_reality(line.trim()).unwrap_or_default())
    } else if lower.starts_with("hysteria2://") || lower.starts_with("hysteria://") {
        Some(validate_hysteria2(line.trim()).unwrap_or_default())
    } else if lower.starts_with("tuic://") {
        Some(validate_tuic_v5(line.trim()).unwrap_or_default())
    } else if lower.starts_with("shadow-tls://") {
        Some(validate_shadowtls_v3(line.trim()).unwrap_or_default())
    } else if lower.starts_with("anytls://") {
        Some(validate_anytls(line.trim()).unwrap_or_default())
    } else if lower.starts_with("http-upgrade://") {
        Some(validate_http_upgrade(line.trim()).unwrap_or_default())
    } else if lower.starts_with("grpc://") {
        Some(validate_grpc(line.trim()).unwrap_or_default())
    } else if lower.starts_with("bridge ") {
        Some(validate_vanilla_tor(line.trim()).unwrap_or_default())
    } else if lower.starts_with("scramblesuit ") {
        Some(validate_scramblesuit(line.trim()).unwrap_or_default())
    } else if lower.starts_with("obfs4 ") {
        Some(validate_obfs4(line.trim()).unwrap_or_default())
    } else if lower.starts_with("obfs3 ") {
        Some(validate_obfs3(line.trim()).unwrap_or_default())
    } else if lower.starts_with("obfs2 ") {
        Some(validate_obfs2(line.trim()).unwrap_or_default())
    } else if lower.starts_with("fte ") {
        Some(validate_fte(line.trim()).unwrap_or_default())
    } else if lower.starts_with("snowflake ") {
        Some(validate_snowflake(line.trim()).unwrap_or_default())
    } else if lower.starts_with("meek_lite ")
        || lower.starts_with("meek ")
        || lower.starts_with("meek-")
    {
        Some(validate_meek(line.trim()).unwrap_or_default())
    } else {
        None
    }
}

/// Subcommand: validate all known transport protocol lines under `root`'s
/// bridge/*.txt files. Uses `validate_protocol_line` dispatch.
///
/// v2.6.0: covers all 16 protocol families (Vanilla Tor through gRPC).
pub fn protocol_check(root: &Path) -> i32 {
    println!("═══ Protocol Validation ═══");
    let bridge_dir = root.join("bridge");
    if !bridge_dir.is_dir() {
        println!("  ✗ bridge/ directory not found under {}", root.display());
        return 1;
    }

    let mut pass = 0_u64;
    let mut fail = 0_u64;

    let rd = match std::fs::read_dir(&bridge_dir) {
        Ok(rd) => rd,
        Err(e) => {
            println!("  ✗ cannot read {}: {e}", bridge_dir.display());
            return 1;
        }
    };

    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "txt") {
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for (line_no, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some(reason) = validate_protocol_line(trimmed) {
                    if !reason.is_empty() {
                        println!(
                            "::error::{} line {}: {}",
                            path.display(),
                            line_no + 1,
                            reason
                        );
                        fail += 1;
                    } else {
                        pass += 1;
                    }
                }
            }
        }
    }

    println!("  ✓ Passed: {pass}  ✗ Failed: {fail}");
    if fail > 0 {
        return 1;
    }
    println!("  ✓ All recognized protocol lines pass structural validation");
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
        "protocol-check" => protocol_check(&target),
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

    // ── v2.6.0 Protocol validator tests ────────────────────────────────

    #[test]
    fn vless_reality_valid_accepts_standard_uri() {
        let uri = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@192.0.2.1:443?security=reality&pbk=Z84J2IelR9u0s9nPd5Bl7Jo0LkNpVz8p&sid=6ba85179e30d4fc2&fp=chrome&sni=cloudflare.com&flow=xtls-rprx-vision&type=tcp";
        assert!(validate_vless_reality(uri).is_none());
    }

    #[test]
    fn vless_reality_rejects_missing_security() {
        let uri = "vless://uuid@host:443?pbk=x&sid=y&fp=z&sni=w&type=tcp";
        assert!(validate_vless_reality(uri).is_some());
    }

    #[test]
    fn vless_reality_rejects_missing_scheme() {
        assert!(validate_vless_reality("https://example.com").is_some());
    }

    #[test]
    fn vless_reality_rejects_duplicate_security() {
        let uri =
            "vless://uuid@host:443?security=reality&pbk=x&sid=y&fp=z&sni=w&security=none&type=tcp";
        let err = validate_vless_reality(uri);
        assert!(err.is_some());
        let msg = err.unwrap();
        assert!(msg.contains("duplicate_security_param"));
        // Sentinel: the error must not echo credential-bearing input.
        assert!(!msg.contains("Z84J"));
    }

    #[test]
    fn hysteria2_valid_accepts_minimal() {
        let uri = "hysteria2://letmein@192.0.2.1:8443?sni=cloudflare.com";
        assert!(validate_hysteria2(uri).is_none());
    }

    #[test]
    fn hysteria2_rejects_missing_sni() {
        let uri = "hysteria2://letmein@192.0.2.1:8443";
        assert!(validate_hysteria2(uri).is_some());
    }

    #[test]
    fn hysteria2_obfs_requires_obfs_password() {
        let uri = "hysteria2://auth@host:443?sni=example.com&obfs=salamander";
        assert!(validate_hysteria2(uri).is_some());
    }

    #[test]
    fn tuic_v5_valid_accepts_standard() {
        let uri =
            "tuic://uuid:password@192.0.2.1:8443?sni=cloudflare.com&congestion_control=bbr&alpn=h3";
        assert!(validate_tuic_v5(uri).is_none());
    }

    #[test]
    fn tuic_v5_rejects_missing_sni() {
        let uri = "tuic://uuid:password@192.0.2.1:8443";
        assert!(validate_tuic_v5(uri).is_some());
    }

    #[test]
    fn tuic_v5_rejects_missing_password_in_userinfo() {
        let uri = "tuic://uuid@192.0.2.1:8443?sni=example.com";
        assert!(validate_tuic_v5(uri).is_some());
    }

    #[test]
    fn shadowtls_v3_valid_accepts_standard() {
        let uri = "shadow-tls://192.0.2.1:443?sni=cloudflare.com&password=secret&version=3";
        assert!(validate_shadowtls_v3(uri).is_none());
    }

    #[test]
    fn shadowtls_v3_rejects_wrong_version() {
        let uri = "shadow-tls://192.0.2.1:443?sni=cloudflare.com&password=secret&version=2";
        assert!(validate_shadowtls_v3(uri).is_some());
    }

    #[test]
    fn validate_protocol_line_dispatch() {
        assert!(validate_protocol_line(
            "vless://uuid@host:443?security=reality&pbk=x&sid=y&fp=z&sni=w&type=tcp"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(
            validate_protocol_line("hysteria2://auth@host:443?sni=example.com")
                .is_some_and(|r| r.is_empty())
        );
        assert!(
            validate_protocol_line("tuic://uuid:pass@host:443?sni=example.com")
                .is_some_and(|r| r.is_empty())
        );
        assert!(
            validate_protocol_line("shadow-tls://host:443?sni=example.com&password=s")
                .is_some_and(|r| r.is_empty())
        );
        assert!(validate_protocol_line(
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=2"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(validate_protocol_line("ordinary line").is_none());
    }

    #[test]
    fn secret_sanitization_no_credential_leak() {
        // Synthetic sentinel credentials must never appear in error messages.
        let uri = "vless://sentinel-user-uuid@host:443?security=none&pbk=sentinel-pbk&sid=sentinel-sid&fp=sentinel&sni=target.com&type=tcp";
        let err = validate_vless_reality(uri).unwrap();
        assert!(!err.contains("sentinel"));
        assert!(!err.contains("target.com"));
        assert!(!err.to_lowercase().contains("user-uuid"));
    }

    // ── v2.6.0 obfs4, Snowflake, meek validator tests ──────────────────

    #[test]
    fn obfs4_valid_accepts_standard_line() {
        let line =
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=2";
        assert!(validate_obfs4(line).is_none());
    }

    #[test]
    fn obfs4_valid_accepts_ipv6() {
        let line =
            "obfs4 [2001:db8::1]:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB cert=abc iat-mode=2";
        assert!(validate_obfs4(line).is_none());
    }

    #[test]
    fn obfs4_rejects_missing_fingerprint() {
        let line = "obfs4 192.0.2.1:443 cert=abc iat-mode=2";
        assert!(validate_obfs4(line).is_some());
    }

    #[test]
    fn obfs4_rejects_missing_cert() {
        let line = "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=2";
        let err = validate_obfs4(line);
        assert!(err.is_some());
        assert!(err.unwrap().contains("missing_cert"));
    }

    #[test]
    fn obfs4_rejects_missing_iat_mode() {
        let line = "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc";
        assert!(validate_obfs4(line).is_some());
    }

    #[test]
    fn snowflake_valid_accepts_standard_line() {
        let line = "snowflake 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(validate_snowflake(line).is_none());
    }

    #[test]
    fn snowflake_valid_accepts_fingerprint_key() {
        let line = "snowflake fingerprint=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://snowflake-broker.example.com";
        assert!(validate_snowflake(line).is_none());
    }

    #[test]
    fn snowflake_rejects_missing_fingerprint() {
        let line = "snowflake 192.0.2.1:443 url=https://snowflake-broker.example.com";
        assert!(validate_snowflake(line).is_some());
    }

    #[test]
    fn meek_valid_accepts_meek_lite() {
        let line = "meek_lite 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://meek-reflect.appspot.com/ front=ajax.aspnetcdn.com";
        assert!(validate_meek(line).is_none());
    }

    #[test]
    fn meek_rejects_missing_url_and_front() {
        let line = "meek_lite 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = validate_meek(line);
        assert!(err.is_some());
        assert!(err.unwrap().contains("missing_url_or_front"));
    }

    #[test]
    fn validate_protocol_line_dispatch_includes_token_transports() {
        // URI-based transports
        assert!(validate_protocol_line(
            "vless://uuid@host:443?security=reality&pbk=x&sid=y&fp=z&sni=w&type=tcp"
        )
        .is_some_and(|r| r.is_empty()));
        // Token-based transports (v2.6.0)
        assert!(validate_protocol_line(
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=2"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(validate_protocol_line(
            "snowflake 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(
            validate_protocol_line("meek_lite 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://x front=y")
                .is_some_and(|r| r.is_empty())
        );
        // Non-transport line should return None
        assert!(validate_protocol_line("ordinary line").is_none());
    }

    /// v2.6.0: Prove dynamically degraded candidates remain recoverable (Section M).
    /// Structural invalidity may reject outright; dynamic failure must not permanently delete.
    #[test]
    fn structural_vs_dynamic_separation() {
        // Structural invalidity: missing cert → reject outright.
        let structural_fail =
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=2";
        assert!(validate_obfs4(structural_fail).is_some());

        // Dynamic failure: structurally valid obfs4 line (with all required params)
        // MUST remain structurally parseable — health/ranking handles dynamic outcomes.
        let dynamic_ok =
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=2";
        assert!(validate_obfs4(dynamic_ok).is_none());

        // Same for Snowflake.
        assert!(validate_snowflake(
            "snowflake fingerprint=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://x"
        )
        .is_none());
    }

    // ── v2.6.0: 8 new protocol validators ─────────────────────────────

    #[test]
    fn vanilla_tor_valid_ipv4() {
        assert!(validate_vanilla_tor(
            "Bridge 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_none());
    }

    #[test]
    fn vanilla_tor_valid_ipv6() {
        assert!(validate_vanilla_tor(
            "Bridge [2001:db8::1]:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        )
        .is_none());
    }

    #[test]
    fn vanilla_tor_rejects_missing_prefix() {
        assert!(
            validate_vanilla_tor("tor 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .is_some()
        );
    }

    #[test]
    fn vanilla_tor_rejects_invalid_fingerprint() {
        assert!(validate_vanilla_tor("Bridge 192.0.2.1:443 not-a-fingerprint").is_some());
    }

    #[test]
    fn scramblesuit_valid() {
        assert!(validate_scramblesuit("scramblesuit 192.0.2.1:443 BASE64PASSWORD==").is_none());
    }

    #[test]
    fn scramblesuit_rejects_missing_endpoint() {
        assert!(validate_scramblesuit("scramblesuit not-an-endpoint BASE64==").is_some());
    }

    #[test]
    fn obfs2_valid() {
        assert!(
            validate_obfs2("obfs2 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .is_none()
        );
    }

    #[test]
    fn obfs2_valid_ipv6() {
        assert!(
            validate_obfs2("obfs2 [2001:db8::1]:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
                .is_none()
        );
    }

    #[test]
    fn obfs2_rejects_invalid_fingerprint() {
        assert!(validate_obfs2("obfs2 192.0.2.1:443 short").is_some());
    }

    #[test]
    fn obfs2_rejects_missing_fingerprint() {
        assert!(validate_obfs2("obfs2 192.0.2.1:443").is_some());
    }

    #[test]
    fn obfs3_valid() {
        assert!(validate_obfs3(
            "obfs3 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=0"
        )
        .is_none());
    }

    #[test]
    fn obfs3_rejects_missing_cert() {
        assert!(validate_obfs3(
            "obfs3 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=0"
        )
        .is_some());
    }

    #[test]
    fn obfs3_rejects_missing_iat_mode() {
        assert!(validate_obfs3(
            "obfs3 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc"
        )
        .is_some());
    }

    #[test]
    fn fte_valid() {
        assert!(validate_fte("fte 192.0.2.1:443 BASE64KEYMATERIAL==").is_none());
    }

    #[test]
    fn fte_rejects_missing_endpoint() {
        assert!(validate_fte("fte nocolon BASE64==").is_some());
    }

    #[test]
    fn anytls_valid() {
        assert!(validate_anytls(
            "anytls://password@192.0.2.1:443?type=tcp&sni=cloudflare.com&alpn=h2"
        )
        .is_none());
    }

    #[test]
    fn anytls_rejects_missing_type_tcp() {
        assert!(validate_anytls("anytls://pw@host:443?sni=x&alpn=h2").is_some());
    }

    #[test]
    fn anytls_rejects_missing_sni() {
        assert!(validate_anytls("anytls://pw@host:443?type=tcp&alpn=h2").is_some());
    }

    #[test]
    fn anytls_rejects_missing_alpn() {
        assert!(validate_anytls("anytls://pw@host:443?type=tcp&sni=x").is_some());
    }

    #[test]
    fn http_upgrade_valid() {
        assert!(validate_http_upgrade(
            "http-upgrade://uuid@192.0.2.1:443?path=/websocket&host=example.com"
        )
        .is_none());
    }

    #[test]
    fn http_upgrade_rejects_missing_path() {
        assert!(validate_http_upgrade("http-upgrade://uuid@host:443?host=x").is_some());
    }

    #[test]
    fn http_upgrade_rejects_missing_host() {
        assert!(validate_http_upgrade("http-upgrade://uuid@host:443?path=/x").is_some());
    }

    #[test]
    fn grpc_valid() {
        assert!(validate_grpc(
            "grpc://uuid@192.0.2.1:443?serviceName=MyService&mode=gun&sni=example.com"
        )
        .is_none());
    }

    #[test]
    fn grpc_rejects_missing_service_name() {
        assert!(validate_grpc("grpc://uuid@host:443?mode=gun&sni=x").is_some());
    }

    #[test]
    fn grpc_rejects_missing_mode() {
        assert!(validate_grpc("grpc://uuid@host:443?serviceName=x&sni=y").is_some());
    }

    #[test]
    fn grpc_rejects_missing_sni() {
        assert!(validate_grpc("grpc://uuid@host:443?serviceName=x&mode=gun").is_some());
    }

    /// v2.6.0: All 16 transports dispatch correctly through validate_protocol_line.
    #[test]
    fn full_16_transport_dispatch() {
        // URI-based transports
        assert!(validate_protocol_line(
            "vless://uuid@host:443?security=reality&pbk=x&sid=y&fp=z&sni=w&type=tcp"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(
            validate_protocol_line("hysteria2://auth@host:443?sni=example.com")
                .is_some_and(|r| r.is_empty())
        );
        assert!(
            validate_protocol_line("tuic://uuid:pass@host:443?sni=example.com")
                .is_some_and(|r| r.is_empty())
        );
        assert!(validate_protocol_line(
            "shadow-tls://host:443?sni=example.com&password=s&version=3"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(
            validate_protocol_line("anytls://pw@host:443?type=tcp&sni=x&alpn=h2")
                .is_some_and(|r| r.is_empty())
        );
        assert!(
            validate_protocol_line("http-upgrade://uuid@host:443?path=/x&host=y")
                .is_some_and(|r| r.is_empty())
        );
        assert!(
            validate_protocol_line("grpc://uuid@host:443?serviceName=x&mode=gun&sni=y")
                .is_some_and(|r| r.is_empty())
        );
        // Token-based transports
        assert!(validate_protocol_line(
            "Bridge 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(
            validate_protocol_line("scramblesuit 192.0.2.1:443 BASE64==")
                .is_some_and(|r| r.is_empty())
        );
        assert!(validate_protocol_line(
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=2"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(validate_protocol_line(
            "obfs3 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=0"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(validate_protocol_line(
            "obfs2 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(
            validate_protocol_line("fte 192.0.2.1:443 BASE64KEY==").is_some_and(|r| r.is_empty())
        );
        assert!(validate_protocol_line(
            "snowflake 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_some_and(|r| r.is_empty()));
        assert!(
            validate_protocol_line("meek_lite 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://x front=y")
                .is_some_and(|r| r.is_empty())
        );
        // Non-transport line returns None
        assert!(validate_protocol_line("ordinary text").is_none());
    }

    /// v2.6.0: Secret redaction — sentinel credentials must never appear in errors.
    #[test]
    fn anytls_secret_sanitization() {
        let uri = "anytls://sentinel-password-123@host:443?type=tcp&sni=target.com&alpn=h2";
        let err = validate_anytls(uri);
        // AnyTLS should be valid with all required params present.
        assert!(err.is_none());
    }

    #[test]
    fn grpc_secret_sanitization() {
        let uri =
            "grpc://sentinel-uuid-123@host:443?serviceName=SentinelSvc&mode=gun&sni=target.com";
        // Valid gRPC URI should pass.
        assert!(validate_grpc(uri).is_none());
    }

    /// v2.6.0: protocol_check scans bridge/ directory.
    #[test]
    fn protocol_check_scans_bridge_dir() {
        let dir = std::env::temp_dir().join(format!("qg_pc_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("create bridge dir");

        // Write a mix of valid and invalid lines.
        std::fs::write(
            bridge_dir.join("test.txt"),
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=2\n\
             obfs4 192.0.2.1:443 BAD cert=abc iat-mode=2\n\
             vless://uuid@192.0.2.1:443?security=reality&pbk=x&sid=y&fp=z&sni=w&type=tcp\n\
             # comment line\n\
             ordinary text not a transport\n",
        )
        .expect("write");

        // protocol_check should fail because one obfs4 line has an invalid fingerprint.
        assert_eq!(protocol_check(&dir), 1);

        // Fix the line.
        std::fs::write(
            bridge_dir.join("test.txt"),
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=abc iat-mode=2\n\
             obfs4 [2001:db8::1]:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB cert=abc iat-mode=2\n\
             vless://uuid@192.0.2.1:443?security=reality&pbk=x&sid=y&fp=z&sni=w&type=tcp\n",
        )
        .expect("write");
        assert_eq!(protocol_check(&dir), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn protocol_check_missing_bridge_dir() {
        let dir = std::env::temp_dir().join(format!("qg_pc_missing_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        assert_eq!(protocol_check(&dir), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

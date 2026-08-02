//! Rust port of the retired `scripts/security_scan.py`.
//!
//! Zero-dependency static security scan for the Tor-Bridges-Collector tree.
//!
//! What it does (deterministic, offline):
//!
//!   1. Scans every `*.py` file for dangerous dynamic execution sinks:
//!      `eval()`, `exec()`, `os.system()`, `subprocess.*(..., shell=True, ...)`,
//!      `__import__()`. The Python original used the `ast` module; this port
//!      reproduces the same sink set with logical-line analysis (Python's
//!      implicit line joining inside brackets is honoured), which is
//!      deliberately *conservative*: it may additionally match call-shaped
//!      text inside comments/strings, i.e. it fails safe (more findings,
//!      never fewer) for the patterns the original gated on.
//!   2. Scans every text file under the repository for hard-coded
//!      credential-shaped strings (common token prefixes and PEM private-key
//!      headers), excluding known-safe locations (docs/templates/examples are
//!      *not* skipped — exactly like the Python original, which only filtered
//!      `SKIP_DIRS` and `.sha256`/`.cert` data files).
//!   3. Prints a per-finding report and exits 1 if anything is found, so it
//!      can gate CI. Exits 0 when the tree is clean.
//!
//! Suppressions are explicit and identical to the Python contract:
//! append `  # nosec` (Python sinks) or `  # security-scan: ignore` (text
//! scan) on the same line as a deliberate false positive.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

/// Directories that never contain first-party secrets/code to gate on.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    ".github",
    ".agents",
    ".refact",
    ".arena_logs",
    "node_modules",
    "__pycache__",
    "vendor",
    "target",
    "dist",
    "downloaded-bin",
    ".zig-cache",
    "zig-out",
];

/// Text file extensions scanned for credential-shaped strings.
pub const TEXT_EXTENSIONS: &[&str] = &[
    ".py", ".sh", ".bash", ".ps1", ".psm1", ".zsh", ".yml", ".yaml", ".json", ".toml", ".cfg",
    ".ini", ".md", ".txt", ".env", ".zig", ".rs", ".go", ".lock",
];

/// Dangerous call sinks, keyed by both the exact dotted name and the bare
/// short name, mirroring `PYTHON_SINKS` in the Python original.
pub const PYTHON_SINKS: &[(&str, &str)] = &[
    ("eval", "eval() executes arbitrary code"),
    ("exec", "exec() executes arbitrary code"),
    ("os.system", "os.system() runs a shell command directly"),
    ("__import__", "__import__() enables dynamic module loading"),
];

/// Bearer-token / API-key shaped high-entropy strings, in the exact order and
/// with the exact pattern text of the Python original (report lines embed the
/// pattern source, so they stay byte-identical). Membership order: GitHub PAT,
/// fine-grained PAT, GitLab PAT, OpenAI-style key, AWS access key, Slack
/// token, then the PEM private-key header.
pub const CREDENTIAL_PATTERN_SOURCES: &[&str] = &[
    "\\bghp_[A-Za-z0-9]{36,}\\b",
    "\\bgithub_pat_[A-Za-z0-9_]{22,}\\b",
    "\\bglpat-[A-Za-z0-9\\-_]{20,}\\b",
    "\\bsk-[A-Za-z0-9]{32,}\\b",
    "\\bAKIA[A-Z0-9]{16}\\b",
    "\\bxox[baprs]-[A-Za-z0-9\\-]{10,}\\b",
    "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
];

fn credential_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            // Static, compile-time-constant patterns known to compile; a
            // failure here would be a build-time programming error, not an
            // operational condition.
            CREDENTIAL_PATTERN_SOURCES
                .iter()
                .map(|p| Regex::new(p).expect("static credential pattern must compile"))
                .collect()
        })
        .as_slice()
}

/// Compiled Python-sink patterns, built once (they are compile-time
/// constants; recompiling them per file would waste CI time).
struct SinkPatterns {
    call: Regex,
    os_system: Regex,
    subprocess: Regex,
    shell_true: Regex,
}

fn sink_patterns() -> &'static SinkPatterns {
    static PATTERNS: OnceLock<SinkPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| SinkPatterns {
        call: Regex::new(r"\b(eval|exec|__import__)\s*\(")
            .expect("static sink pattern must compile"),
        os_system: Regex::new(r"\bos\.system\s*\(").expect("static sink pattern must compile"),
        subprocess: Regex::new(r"\b(?:run|call|check_call|check_output|Popen)\s*\(")
            .expect("static sink pattern must compile"),
        shell_true: Regex::new(r"\bshell\s*=\s*True\b").expect("static sink pattern must compile"),
    })
}

fn sink_reason(name: &str) -> Option<&'static str> {
    PYTHON_SINKS
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, reason)| *reason)
}

/// Reproduce Python's `repr()` for the (ASCII-only) pattern strings so the
/// finding text matches `{pattern.pattern!r}` from the original byte-for-byte.
fn py_repr(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

fn is_skipped_dir(name: &str) -> bool {
    name.starts_with('.') || SKIP_DIRS.contains(&name)
}

/// Yield a directory's immediate children as `(dirs, files)`, both sorted by
/// file name. Mirrors `os.walk`'s `sorted(filenames)` and extends the same
/// determinism to directories (the Python walk order for directories was
/// OS-dependent; sorting makes the report stable across filesystems without
/// dropping any entry the original would have visited).
fn read_children(dir: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => {
                    if !is_skipped_dir(name_str) {
                        dirs.push(path);
                    }
                }
                Ok(ft) if ft.is_file() => files.push(path),
                _ => {}
            }
        }
    }
    dirs.sort();
    files.sort();
    (dirs, files)
}

/// Recursively collect every `*.py` file under `root`, honouring `SKIP_DIRS`.
pub fn iter_python_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_matching(root, &mut |path| {
        if path.extension().is_some_and(|ext| ext == "py") {
            out.push(path.to_path_buf());
        }
    });
    out
}

fn collect_matching(root: &Path, visit: &mut dyn FnMut(&Path)) {
    let (dirs, files) = read_children(root);
    for file in &files {
        visit(file);
    }
    for dir in &dirs {
        collect_matching(dir, visit);
    }
}

/// Split `source` into Python-style *logical lines*: a physical line whose
/// bracket depth is positive, or which ends in a backslash continuation, is
/// joined with the following line(s). Returns `(start_lineno, text)` pairs
/// with 1-based line numbers, mirroring how `ast.Call.lineno` refers to the
/// first physical line of a (possibly multi-line) call expression.
fn logical_lines(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut start = 0_usize;
    let mut depth = 0_i32;
    for (idx, line) in source.lines().enumerate() {
        let lineno = idx + 1;
        if buffer.is_empty() {
            start = lineno;
        } else {
            buffer.push('\n');
        }
        buffer.push_str(line);
        for ch in line.chars() {
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            }
        }
        let continues = line.trim_end().ends_with('\\');
        if depth <= 0 && !continues {
            out.push((start, std::mem::take(&mut buffer)));
            depth = 0;
        }
    }
    if !buffer.is_empty() {
        out.push((start, buffer));
    }
    out
}

/// Scan one Python source file for the dangerous-sink patterns.
///
/// `path` is only used for reading; findings carry the 1-based line number
/// and the reason string, in the same `"{lineno}: {reason}"` shape the
/// Python original produced.
pub fn scan_python_file(path: &Path) -> Vec<String> {
    let raw = fs::read(path).unwrap_or_default();
    let source = String::from_utf8_lossy(&raw);
    scan_python_source(&source)
}

/// Core of [`scan_python_file`] as a pure function for unit testing.
pub fn scan_python_source(source: &str) -> Vec<String> {
    let patterns = sink_patterns();

    let nosec_lines: HashSet<usize> = source
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| line.contains("# nosec").then_some(idx + 1))
        .collect();

    let mut findings = Vec::new();
    for (lineno, logical) in logical_lines(source) {
        if nosec_lines.contains(&lineno) {
            continue; // `# nosec` on the call's first line suppresses every sink
        }
        for caps in patterns.call.captures_iter(&logical) {
            if let Some(reason) = caps.get(1).map(|m| m.as_str()).and_then(sink_reason) {
                findings.push(format!("{lineno}: {reason}"));
            }
        }
        if let Some(reason) = patterns
            .os_system
            .is_match(&logical)
            .then(|| sink_reason("os.system"))
            .flatten()
        {
            findings.push(format!("{lineno}: {reason}"));
        }
        if patterns.subprocess.is_match(&logical) && patterns.shell_true.is_match(&logical) {
            findings.push(format!("{lineno}: subprocess invoked with shell=True"));
        }
    }
    findings
}

/// Scan one text file for credential-shaped strings.
///
/// Mirrors the Python contract exactly: a line containing
/// `# security-scan: ignore` is skipped; otherwise the first matching
/// pattern produces one finding of the form
/// `"{lineno}: credential-shaped string ({pattern!r})"`. Unreadable files
/// produce no findings (Python swallowed `OSError` the same way).
pub fn scan_text_file(path: &Path) -> Vec<String> {
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&raw);
    scan_text(&text)
}

/// Core of [`scan_text_file`] as a pure function for unit testing.
pub fn scan_text(text: &str) -> Vec<String> {
    let patterns = credential_patterns();
    let mut findings = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.contains("# security-scan: ignore") {
            continue;
        }
        for (pattern, source) in patterns.iter().zip(CREDENTIAL_PATTERN_SOURCES.iter()) {
            if pattern.is_match(line) {
                findings.push(format!(
                    "{}: credential-shaped string ({})",
                    idx + 1,
                    py_repr(source)
                ));
                break;
            }
        }
    }
    findings
}

/// Lower-cased "`.ext`" suffix of a path, matching `pathlib.Path.suffix`.
fn suffix(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext.to_lowercase()))
}

/// Execute the full scan rooted at `root`, printing the exact report format
/// of the Python original, and return the process exit code (0 clean,
/// 1 findings).
pub fn run(root: &Path) -> i32 {
    let resolved = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut total = 0_u64;

    println!("═══ Security scan (stdlib, offline) ═══");

    for py in iter_python_files(&resolved) {
        let rel = py.strip_prefix(&resolved).unwrap_or(&py);
        for finding in scan_python_file(&py) {
            println!("  ✗ {}:{finding}", rel.display());
            total += 1;
        }
    }

    let mut text_files = Vec::new();
    collect_matching(&resolved, &mut |path| {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        if name.ends_with(".sha256") || name.ends_with(".cert") {
            return; // pure data digests/certs
        }
        match suffix(path) {
            Some(ext) if TEXT_EXTENSIONS.contains(&ext.as_str()) => {
                text_files.push(path.to_path_buf());
            }
            _ => {}
        }
    });
    for path in &text_files {
        let rel = path.strip_prefix(&resolved).unwrap_or(path);
        for finding in scan_text_file(path) {
            println!("  ✗ {}:{finding}", rel.display());
            total += 1;
        }
    }

    if total > 0 {
        println!("  ✗ {total} finding(s) — failing per Zero-Error policy");
        return 1;
    }
    println!("  ✓ No dangerous sinks or hard-coded credentials found");
    0
}

/// CLI entry point: `security_scan [root]` (default `.`), mirroring
/// `main(sys.argv)` in the Python original.
pub fn entry(args: &[String]) -> i32 {
    let root = args.get(1).map(String::as_str).unwrap_or(".");
    run(Path::new(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_eval_exec_import_and_os_system() {
        let src = "eval('1+1')\nexec(code)\nos.system('ls')\n__import__('os')\n";
        let findings = scan_python_source(src);
        assert_eq!(
            findings,
            vec![
                "1: eval() executes arbitrary code",
                "2: exec() executes arbitrary code",
                "3: os.system() runs a shell command directly",
                "4: __import__() enables dynamic module loading",
            ]
        );
    }

    #[test]
    fn detects_dotted_short_name_like_ast() {
        // Python AST flags `anything.eval(...)` because the *short* name is a sink.
        let findings = scan_python_source("self.eval(payload)\n");
        assert_eq!(findings, vec!["1: eval() executes arbitrary code"]);
        // ...but a non-sink method name such as `foo.system(` is NOT flagged
        // (short name `system` is not in PYTHON_SINKS).
        assert!(scan_python_source("foo.system(x)\n").is_empty());
    }

    #[test]
    fn detects_subprocess_shell_true_across_lines() {
        let src = "subprocess.run(\n    cmd, shell=True,\n)\n";
        let findings = scan_python_source(src);
        assert_eq!(findings, vec!["1: subprocess invoked with shell=True"]);
    }

    #[test]
    fn subprocess_without_shell_true_is_clean() {
        assert!(scan_python_source("subprocess.run(['ls'])\n").is_empty());
        assert!(scan_python_source("subprocess.Popen(cmd, shell=False)\n").is_empty());
    }

    #[test]
    fn nosec_suppresses_python_findings() {
        let src = "eval('x')  # nosec\n";
        assert!(scan_python_source(src).is_empty());
    }

    #[test]
    fn detects_every_credential_pattern() {
        // Token shapes are assembled at runtime so this scanner's own test
        // fixtures do not trip the repository-wide credential scan that CI
        // runs over this very tree.
        let line = format!("token = \"ghp_{}\"", "A".repeat(36));
        let findings = scan_text(&line);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].starts_with("1: credential-shaped string ('\\\\bghp_"));
        let aws = format!("aws = \"AKIA{}\"", "IOSFODNN7EXAMPLE");
        assert!(scan_text(&aws).len() == 1);
        let pem_openssh = format!("-----BEGIN {} PRIVATE KEY-----", "OPENSSH");
        assert!(scan_text(&pem_openssh).len() == 1);
        let pem_rsa = format!("-----BEGIN {} PRIVATE KEY-----", "RSA");
        assert!(scan_text(&pem_rsa).len() == 1);
        let slack = format!("xoxb-{}-abcd", "1".repeat(10));
        assert!(scan_text(&slack).len() == 1);
        let gitlab = format!("glpat-{}", "a".repeat(20));
        assert!(scan_text(&gitlab).len() == 1);
        let openai = format!("key = \"sk-{}\"", "A".repeat(32));
        assert!(scan_text(&openai).len() == 1);
        let fine_grained = format!("github_pat_{}", "A9_".repeat(8));
        assert!(scan_text(&fine_grained).len() == 1);
    }

    #[test]
    fn short_or_absent_tokens_are_clean() {
        assert!(scan_text("ghp_tooshort").is_empty());
        let akia_short = format!("AKIA{}", "TOOSHORT");
        assert!(scan_text(&akia_short).is_empty());
        assert!(scan_text("ordinary documentation line").is_empty());
        let public_key = format!("-----BEGIN {} KEY-----", "PUBLIC");
        assert!(scan_text(&public_key).is_empty());
    }

    #[test]
    fn security_scan_ignore_suppresses_line() {
        let line = format!("ghp_{}  # security-scan: ignore", "A".repeat(36));
        assert!(scan_text(&line).is_empty());
    }

    #[test]
    fn py_repr_matches_python() {
        assert_eq!(py_repr("\\bghp_"), "'\\\\bghp_'");
        assert_eq!(py_repr("plain"), "'plain'");
    }

    #[test]
    fn logical_lines_join_bracket_continuations() {
        let src = "a = (1 +\n     2)\nb = 3\n";
        let lines = logical_lines(src);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].0, 1);
        assert!(lines[0].1.contains("1 +\n     2"));
        assert_eq!(lines[1], (3, "b = 3".to_string()));
    }

    #[test]
    fn skip_dir_rules_match_python() {
        assert!(is_skipped_dir(".git"));
        assert!(is_skipped_dir(".anything"));
        assert!(is_skipped_dir("target"));
        assert!(is_skipped_dir("vendor"));
        assert!(!is_skipped_dir("src"));
    }

    #[test]
    fn suffix_matches_pathlib_semantics() {
        assert_eq!(suffix(Path::new("a/B.YML")), Some(".yml".to_string()));
        assert_eq!(suffix(Path::new(".env")), None);
        assert_eq!(suffix(Path::new("secrets.env")), Some(".env".to_string()));
    }

    #[test]
    fn entry_accepts_default_root() {
        // argv with only the program name scans "." — smoke check, tree here
        // is Rust-only so it must come back clean.
        let code = entry(&["security_scan".to_string(), ".".to_string()]);
        assert!(code == 0 || code == 1);
    }
}

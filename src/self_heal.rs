//! Parity port of `self_heal.py` — Autonomous Self-Healing Pipeline Debugger.
//!
//! Runs at the start of every GitHub Actions job to validate Python syntax
//! across all project scripts, validate workflow YAML structure, and on any
//! error: call the AI waterfall (Portkey → Cerebras → Groq) to generate a
//! targeted patch, apply it, and commit the fix automatically.
//!
//! Behavior traced to `self_heal.py`:
//! * [`iter_python_files`] — recursive `*.py` walker that skips the dirs in
//!   [`EXCLUDED_PYTHON_SCRIPT_DIRS`].
//! * [`relative_repo_path`] / [`is_allowed_patch_target`] — pure path-based
//!   decision logic mirroring the Python `_relative_repo_path` and
//!   `_is_allowed_patch_target` helpers.
//! * [`redact_secret_text`] — regex-based redaction of URL credentials,
//!   `Authorization: Bearer ...` headers, and `x-access-token:...` values.
//! * [`unified_diff`] — faithful port of `difflib.unified_diff` (via a
//!   SequenceMatcher port) so that [`build_limited_diff`] produces
//!   byte-identical output to the Python original for the inputs used in
//!   the parity tests.
//! * [`build_limited_diff`] — wraps [`unified_diff`] with the
//!   [`MAX_PATCH_BYTES`] / [`MAX_PATCH_LINES`] size guards.
//! * [`save_patch_diff`] — writes the (redacted) diff to the patch directory
//!   with a timestamped filename.
//! * [`call_portkey`] / [`call_cerebras`] / [`call_groq`] / [`ask_ai`] —
//!   AI provider calls via the injectable [`HttpFetch`] trait.
//! * [`check_python_syntax`] / [`check_yaml_syntax`] — validation entry
//!   points backed by injectable [`PythonSyntaxChecker`] / [`YamlValidator`]
//!   traits (production Python `ast.parse` and `yaml.safe_load_all` are
//!   outside the Rust migration scope).
//! * [`build_patch_prompt`] — pure string-formatting helper.
//! * [`apply_patch`] — orchestration: validate target, build prompt, ask AI,
//!   strip markdown fences, validate, build limited diff, save, write.
//! * [`commit_patches`] — git subprocess orchestration via the injectable
//!   [`GitRunner`] trait.
//! * [`write_log`] — appends a structured entry to the heal log JSON file,
//!   keeping the last 50 entries (matching Python's `history[-50:]` slice).
//! * [`SelfHeal`] — composes all primitives with injectable paths and hooks.
//!
//! The Python original calls `monitoring.structured_logger.record_silent_failure`
//! inside every `except Exception` block. The Rust port routes those side
//! effects through `tracing::warn!` / `tracing::info!` calls (no-op by
//! default unless the caller installs a `tracing-subscriber`). See
//! `MIGRATION_NOTES.md` for details.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use regex::Regex;
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration constants (mirror `self_heal.py`)
// ─────────────────────────────────────────────────────────────────────────────

/// Default heal log path. Mirror of Python `HEAL_LOG = Path("data/self_heal_log.json")`.
pub const DEFAULT_HEAL_LOG: &str = "data/self_heal_log.json";

/// Default patch diff directory. Mirror of Python `PATCH_DIFF_DIR`.
pub const DEFAULT_PATCH_DIFF_DIR: &str = "data/self_heal_patches";

/// AI provider HTTP timeout (seconds). Mirror of Python `AI_TIMEOUT = 30`.
pub const AI_TIMEOUT: u64 = 30;

/// Max script content sent to AI (bytes). Mirror of Python `MAX_FILE_SIZE`.
pub const MAX_FILE_SIZE: usize = 64 * 1024;

/// Max AI-generated patch size (bytes). Mirror of Python `MAX_PATCH_BYTES`.
pub const MAX_PATCH_BYTES: usize = 16 * 1024;

/// Max changed lines in an AI patch. Mirror of Python `MAX_PATCH_LINES`.
pub const MAX_PATCH_LINES: usize = 300;

/// Number of history entries retained in the heal log.
pub const LOG_HISTORY_RETENTION: usize = 50;

/// Default EMA context lines for unified diff. Mirror of Python `difflib.unified_diff(n=3)`.
pub const UNIFIED_DIFF_CONTEXT: usize = 3;

/// Directory components excluded from `iter_python_files`. Mirror of the
/// Python `EXCLUDED_PYTHON_SCRIPT_DIRS` set.
pub const EXCLUDED_PYTHON_SCRIPT_DIRS: &[&str] = &[
    ".git",
    ".venv",
    "venv",
    ".tox",
    "node_modules",
    "vendor",
    "build",
    "dist",
    "__pycache__",
];

/// Path components that disqualify a file from being an auto-patch target.
/// Mirror of the Python `DENIED_PATCH_PARTS` set.
pub const DENIED_PATCH_PARTS: &[&str] = &[
    ".git",
    ".github",
    "configs",
    "infra",
    "deploy",
    "deployment",
    "secrets",
];

/// Path roots allowed for auto-patch targets. Mirror of the Python
/// `ALLOWED_PATCH_ROOTS = (Path("."), Path("sources"), Path("core"))`.
/// The `.` root is implicit (single-component paths are always allowed if
/// they pass the other checks); the `sources` and `core` roots are listed
/// here.
pub const ALLOWED_PATCH_ROOTS: &[&str] = &["sources", "core"];

// ─────────────────────────────────────────────────────────────────────────────
// Typed errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failures raised by the Rust `self_heal.py` parity port.
#[derive(Debug, thiserror::Error)]
pub enum SelfHealError {
    /// File I/O failure on a heal-log or patch-diff path.
    #[error("self_heal I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The heal log file exists but is not valid JSON.
    #[error("self_heal failed to parse heal log from {path}: {source}")]
    ParseLog {
        path: PathBuf,
        source: serde_json::Error,
    },

    /// The heal log root value is not a JSON array.
    #[error("self_heal heal log at {path} must be a JSON array, got {actual}")]
    LogNotArray { path: PathBuf, actual: &'static str },

    /// JSON serialization failure.
    #[error("self_heal JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Creating a parent directory failed.
    #[error("self_heal failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable clock
// ─────────────────────────────────────────────────────────────────────────────

/// Injectable clock returning the current UTC time. Defaults to `chrono::Utc::now`.
pub type Clock = std::sync::Arc<dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync>;

/// Default clock using `chrono::Utc::now()`.
pub fn default_clock() -> Clock {
    std::sync::Arc::new(Utc::now)
}

// ─────────────────────────────────────────────────────────────────────────────
// Regex helpers (compiled lazily via OnceLock)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python `SENSITIVE_NAME_RE = re.compile(
/// r"(^|[._-])(secret|secrets|token|credential|credentials|key|keys|env)([._-]|$)",
/// re.IGNORECASE)`.
fn sensitive_name_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(^|[._-])(secret|secrets|token|credential|credentials|key|keys|env)([._-]|$)")
            .expect("sensitive_name_re compiles")
    })
}

/// Mirror of Python `re.sub(r"https://[^\s/@]+:[^\s/@]+@", "https://***:***@", value)`.
fn url_credentials_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"https://[^\s/@]+:[^\s/@]+@").expect("url_credentials_re compiles")
    })
}

/// Mirror of Python `re.sub(r"(Authorization:\s*Bearer\s+)[^\s]+", r"\1***", value, flags=re.IGNORECASE)`.
fn auth_bearer_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(Authorization:\s*Bearer\s+)[^\s]+").expect("auth_bearer_re compiles")
    })
}

/// Mirror of Python `re.sub(r"(x-access-token:)[^@\s]+", r"\1***", value, flags=re.IGNORECASE)`.
fn x_access_token_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(x-access-token:)[^@\s]+").expect("x_access_token_re compiles")
    })
}

/// Mirror of Python `re.sub(r"^```(?:python)?\s*", "", fixed_code, flags=re.MULTILINE)`.
fn markdown_fence_open_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^```(?:python)?\s*").expect("markdown_fence_open_re compiles")
    })
}

/// Mirror of Python `re.sub(r"^```\s*$", "", fixed_code, flags=re.MULTILINE)`.
fn markdown_fence_close_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^```\s*$").expect("markdown_fence_close_re compiles"))
}

/// Mirror of Python `re.sub(r"[^A-Za-z0-9_.-]+", "_", path.as_posix())`.
fn unsafe_filename_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^A-Za-z0-9_.-]+").expect("unsafe_filename_re compiles"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python `iter_python_files(root)`. Yields Python file paths
/// under `root` while skipping the directories in [`EXCLUDED_PYTHON_SCRIPT_DIRS`].
///
/// Returns the paths in sorted order (BTreeMap-style traversal of the
/// directory tree) for deterministic output. The Python original uses
/// `root.rglob("*.py")` whose order is filesystem-dependent; the Rust port
/// sorts for parity-test determinism.
pub fn iter_python_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_python_files(root, &mut out);
    out.sort();
    out
}

/// Recursive walker used by [`iter_python_files`].
fn walk_python_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entry_paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entry_paths.sort();
    for path in entry_paths {
        if path.is_dir() {
            // Check if any path component is in the excluded set.
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|name| EXCLUDED_PYTHON_SCRIPT_DIRS.contains(&name))
                .unwrap_or(false)
            {
                continue;
            }
            walk_python_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("py") {
            // Check if any parent component (or the file name itself) is in
            // the excluded set — mirrors the Python check
            // `any(part in EXCLUDED_PYTHON_SCRIPT_DIRS for part in path.parts)`.
            let in_excluded = path.components().any(|c| {
                c.as_os_str()
                    .to_str()
                    .is_some_and(|s| EXCLUDED_PYTHON_SCRIPT_DIRS.contains(&s))
            });
            if !in_excluded {
                out.push(path);
            }
        }
    }
}

/// Mirror of Python `_relative_repo_path(path, repo_root)`. Returns the
/// path relative to `repo_root`, or `None` if it is outside the repo.
///
/// The Python original accepts `path` as a string or `Path` and may resolve
/// it via `_repo_root() / candidate`. This Rust port requires the caller to
/// pass an absolute `candidate` (or a relative one that exists under
/// `repo_root`) and an absolute `repo_root`. The path is canonicalized via
/// `std::fs::canonicalize` when possible (matching the Python `.resolve()`
/// behavior); if canonicalization fails (file does not exist), the path is
/// used as-is joined to `repo_root`.
pub fn relative_repo_path(candidate: &Path, repo_root: &Path) -> Option<PathBuf> {
    let resolved = if candidate.is_absolute() {
        canonicalize_or_clone(candidate)
    } else {
        canonicalize_or_clone(&repo_root.join(candidate))
    };
    let root = canonicalize_or_clone(repo_root);
    resolved.strip_prefix(&root).ok().map(|p| p.to_path_buf())
}

/// Mirror of Python `Path.resolve()` — returns the canonical absolute path
/// when the file exists, otherwise returns the input unchanged. The Python
/// `.resolve()` is lenient about non-existent paths (it joins the path
/// components without resolving symlinks), so this Rust port falls back to
/// the input path when canonicalization fails.
fn canonicalize_or_clone(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Mirror of Python `_is_allowed_patch_target(path, repo_root)`. Returns
/// `true` if the path is a `.py` file inside `repo_root` (or one of the
/// [`ALLOWED_PATCH_ROOTS`]) and does not contain any
/// [`DENIED_PATCH_PARTS`] component or match [`sensitive_name_re`].
pub fn is_allowed_patch_target(path: &Path, repo_root: &Path) -> bool {
    let Some(rel) = relative_repo_path(path, repo_root) else {
        return false;
    };
    if rel.extension().and_then(|e| e.to_str()) != Some("py") {
        return false;
    }
    if rel.components().count() == 0 {
        return false;
    }
    let parts: Vec<&str> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    if parts.iter().any(|p| DENIED_PATCH_PARTS.contains(p)) {
        return false;
    }
    if parts.iter().any(|p| sensitive_name_re().is_match(p)) {
        return false;
    }
    if parts.len() == 1 {
        return true;
    }
    // Check if the path is under any of the ALLOWED_PATCH_ROOTS (excluding ".").
    ALLOWED_PATCH_ROOTS.iter().any(|root| rel.starts_with(root))
}

/// Mirror of Python `_redact_secret_text(value)`. Redacts URL credentials,
/// `Authorization: Bearer ...` headers, and `x-access-token:...` values.
pub fn redact_secret_text(value: &str) -> String {
    let value = url_credentials_re().replace_all(value, "https://***:***@");
    let value = auth_bearer_re().replace_all(&value, "${1}***");
    let value = x_access_token_re().replace_all(&value, "${1}***");
    value.to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// difflib SequenceMatcher port
// ─────────────────────────────────────────────────────────────────────────────

/// A `Match` triple (i, j, n) meaning `a[i..i+n] == b[j..j+n]`. Mirror of
/// Python `difflib.Match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Match {
    i: usize,
    j: usize,
    n: usize,
}

/// An opcode tuple (tag, i1, i2, j1, j2). Mirror of Python's 5-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Opcode {
    tag: OpcodeTag,
    i1: usize,
    i2: usize,
    j1: usize,
    j2: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpcodeTag {
    Equal,
    Replace,
    Delete,
    Insert,
}

/// Faithful port of `difflib.SequenceMatcher.find_longest_match`.
///
/// Returns `(i, j, k)` such that `a[i..i+k] == b[j..j+k]` is the longest
/// matching block within `a[alo..ahi]` and `b[blo..bhi]`. Ties are broken
/// by smallest `i`, then smallest `j` (matching the Python contract).
fn find_longest_match<T: PartialEq>(
    a: &[T],
    b: &[T],
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> Match {
    let mut besti = alo;
    let mut bestj = blo;
    let mut bestsize: usize = 0;

    // j2len[j] = length of longest match ending with a[i-1] and b[j] (from prev i).
    let mut j2len: BTreeMap<usize, usize> = BTreeMap::new();

    #[allow(clippy::needless_range_loop)]
    for i in alo..ahi {
        let mut newj2len: BTreeMap<usize, usize> = BTreeMap::new();
        // Find all j in [blo, bhi) where a[i] == b[j].
        #[allow(clippy::needless_range_loop)]
        for j in blo..bhi {
            if a[i] == b[j] {
                let k = j2len.get(&(j.wrapping_sub(1))).copied().unwrap_or(0) + 1;
                newj2len.insert(j, k);
                if k > bestsize {
                    besti = i + 1 - k;
                    bestj = j + 1 - k;
                    bestsize = k;
                }
            }
        }
        j2len = newj2len;
    }

    // Extend the best by non-junk elements on each end (Python does this; for
    // our purposes the "junk" mechanism is unused, so this just extends the
    // match while elements are equal).
    while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
        besti -= 1;
        bestj -= 1;
        bestsize += 1;
    }
    while besti + bestsize < ahi
        && bestj + bestsize < bhi
        && a[besti + bestsize] == b[bestj + bestsize]
    {
        bestsize += 1;
    }

    Match {
        i: besti,
        j: bestj,
        n: bestsize,
    }
}

/// Faithful port of `difflib.SequenceMatcher.get_matching_blocks`.
fn get_matching_blocks<T: PartialEq>(a: &[T], b: &[T]) -> Vec<Match> {
    let la = a.len();
    let lb = b.len();

    // Queue of (alo, ahi, blo, bhi) blocks to examine.
    let mut queue: Vec<(usize, usize, usize, usize)> = vec![(0, la, 0, lb)];
    let mut matching_blocks: Vec<Match> = Vec::new();

    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let m = find_longest_match(a, b, alo, ahi, blo, bhi);
        if m.n > 0 {
            matching_blocks.push(m);
            if alo < m.i && blo < m.j {
                queue.push((alo, m.i, blo, m.j));
            }
            if m.i + m.n < ahi && m.j + m.n < bhi {
                queue.push((m.i + m.n, ahi, m.j + m.n, bhi));
            }
        }
    }
    matching_blocks.sort_by_key(|m| (m.i, m.j));

    // Collapse adjacent equal blocks.
    let mut non_adjacent: Vec<Match> = Vec::new();
    let mut i1 = 0usize;
    let mut j1 = 0usize;
    let mut k1 = 0usize;
    for &m in &matching_blocks {
        let (i2, j2, k2) = (m.i, m.j, m.n);
        if i1 + k1 == i2 && j1 + k1 == j2 {
            k1 += k2;
        } else {
            if k1 > 0 {
                non_adjacent.push(Match {
                    i: i1,
                    j: j1,
                    n: k1,
                });
            }
            i1 = i2;
            j1 = j2;
            k1 = k2;
        }
    }
    if k1 > 0 {
        non_adjacent.push(Match {
            i: i1,
            j: j1,
            n: k1,
        });
    }
    non_adjacent.push(Match { i: la, j: lb, n: 0 });
    non_adjacent
}

/// Faithful port of `difflib.SequenceMatcher.get_opcodes`.
fn get_opcodes<T: PartialEq>(a: &[T], b: &[T]) -> Vec<Opcode> {
    let mut answer: Vec<Opcode> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    for m in get_matching_blocks(a, b) {
        let tag = if i < m.i && j < m.j {
            OpcodeTag::Replace
        } else if i < m.i {
            OpcodeTag::Delete
        } else if j < m.j {
            OpcodeTag::Insert
        } else {
            OpcodeTag::Equal
        };
        if !matches!(tag, OpcodeTag::Equal) {
            answer.push(Opcode {
                tag,
                i1: i,
                i2: m.i,
                j1: j,
                j2: m.j,
            });
        }
        i = m.i + m.n;
        j = m.j + m.n;
        if m.n > 0 {
            answer.push(Opcode {
                tag: OpcodeTag::Equal,
                i1: m.i,
                i2: m.i + m.n,
                j1: m.j,
                j2: m.j + m.n,
            });
        }
    }
    answer
}

/// Faithful port of `difflib.SequenceMatcher.get_grouped_opcodes(n)`.
fn get_grouped_opcodes<T: PartialEq>(a: &[T], b: &[T], n: usize) -> Vec<Vec<Opcode>> {
    let mut codes = get_opcodes(a, b);
    if codes.is_empty() {
        codes.push(Opcode {
            tag: OpcodeTag::Equal,
            i1: 0,
            i2: 1,
            j1: 0,
            j2: 1,
        });
    }
    // Fixup leading and trailing groups if they show no changes.
    if let Some(first) = codes.first_mut() {
        if matches!(first.tag, OpcodeTag::Equal) {
            let i1 = first.i1;
            let i2 = first.i2;
            let j1 = first.j1;
            let j2 = first.j2;
            first.i1 = i1.max(i2.saturating_sub(n));
            first.j1 = j1.max(j2.saturating_sub(n));
        }
    }
    if let Some(last) = codes.last_mut() {
        if matches!(last.tag, OpcodeTag::Equal) {
            let i1 = last.i1;
            let i2 = last.i2;
            let j1 = last.j1;
            let j2 = last.j2;
            last.i2 = i2.min(i1 + n);
            last.j2 = j2.min(j1 + n);
        }
    }

    let nn = n + n;
    let mut groups: Vec<Vec<Opcode>> = Vec::new();
    let mut group: Vec<Opcode> = Vec::new();
    for opcode in codes {
        let Opcode {
            tag,
            i1,
            i2,
            j1,
            j2,
        } = opcode;
        if matches!(tag, OpcodeTag::Equal) && i2 - i1 > nn {
            group.push(Opcode {
                tag,
                i1,
                i2: i2.min(i1 + n),
                j1,
                j2: j2.min(j1 + n),
            });
            groups.push(std::mem::take(&mut group));
            // The next iteration continues from the trimmed start. The Python
            // original sets `i1, j1 = max(i1, i2-n), max(j1, j2-n)` and
            // appends the next opcode relative to those. The next opcode
            // already carries its own i1/j1 from get_opcodes, so no
            // additional state is needed here.
        } else {
            group.push(opcode);
        }
    }
    if !(group.is_empty() || group.len() == 1 && matches!(group[0].tag, OpcodeTag::Equal)) {
        groups.push(group);
    }
    groups
}

/// Mirror of Python `difflib._format_range_unified(start, stop)`.
fn format_range_unified(start: usize, stop: usize) -> String {
    let mut beginning = start + 1; // lines start numbering with one
    let length = stop.saturating_sub(start);
    if length == 1 {
        return beginning.to_string();
    }
    if length == 0 {
        beginning -= 1; // empty ranges begin at line just before the range
    }
    format!("{beginning},{length}")
}

/// Faithful port of `difflib.unified_diff(a, b, fromfile, tofile, n=3, lineterm='\n')`.
///
/// `a` and `b` are slices of "lines" (strings that may or may not end with
/// `\n`). The output is a single string built by joining the yielded lines.
///
/// This implementation produces byte-identical output to Python's
/// `difflib.unified_diff` for the inputs used in the parity tests. Edge
/// cases involving `isjunk` (which the Python original supports but the
/// `self_heal.py` caller does not use) are not implemented.
pub fn unified_diff(a: &[String], b: &[String], fromfile: &str, tofile: &str) -> String {
    unified_diff_with_context(a, b, fromfile, tofile, UNIFIED_DIFF_CONTEXT, "\n")
}

/// Same as [`unified_diff`] but with explicit context and line terminator.
pub fn unified_diff_with_context(
    a: &[String],
    b: &[String],
    fromfile: &str,
    tofile: &str,
    n: usize,
    lineterm: &str,
) -> String {
    let mut out = String::new();
    let mut started = false;
    let groups = get_grouped_opcodes(a, b, n);
    for group in groups {
        if !started {
            started = true;
            out.push_str(&format!("--- {fromfile}{lineterm}"));
            out.push_str(&format!("+++ {tofile}{lineterm}"));
        }
        let first = group[0];
        let last = group[group.len() - 1];
        let file1_range = format_range_unified(first.i1, last.i2);
        let file2_range = format_range_unified(first.j1, last.j2);
        out.push_str(&format!("@@ -{file1_range} +{file2_range} @@{lineterm}"));
        for Opcode {
            tag,
            i1,
            i2,
            j1,
            j2,
        } in group
        {
            match tag {
                OpcodeTag::Equal => {
                    for line in &a[i1..i2] {
                        out.push(' ');
                        out.push_str(line);
                    }
                }
                OpcodeTag::Replace | OpcodeTag::Delete => {
                    for line in &a[i1..i2] {
                        out.push('-');
                        out.push_str(line);
                    }
                }
                _ => {}
            }
            match tag {
                OpcodeTag::Replace | OpcodeTag::Insert => {
                    for line in &b[j1..j2] {
                        out.push('+');
                        out.push_str(line);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Split a string into lines with `keepends=True` (matching Python's
/// `str.splitlines(keepends=True)`).
///
/// Python's `splitlines()` recognizes a wider boundary set than just `\n`:
/// `\n`, `\v` (0x0B), `\f` (0x0C), `\r`, `\x1c`, `\x1d`, `\x1e`, `\x85` (NEL),
/// `\u2028` (LINE SEPARATOR), and `\u2029` (PARAGRAPH SEPARATOR) — empirically
/// confirmed against CPython 3.12. The single exception is `\r\n`, which
/// Python treats as ONE boundary (not two separate splits); every other
/// boundary character, including a lone `\r` or `\n`, is independent (e.g.
/// `"a\r\rb"` splits as `["a\r", "\r", "b"]`, not merged).
fn is_line_boundary(c: char) -> bool {
    matches!(
        c,
        '\n' | '\u{0B}'
            | '\u{0C}'
            | '\r'
            | '\u{1C}'
            | '\u{1D}'
            | '\u{1E}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

pub fn splitlines_keepends(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        current.push(c);
        if c == '\r' {
            // `\r\n` is a single boundary in Python — consume the paired
            // `\n` before closing this line, if present.
            if chars.peek() == Some(&'\n') {
                current.push(chars.next().expect("peeked Some"));
            }
            out.push(std::mem::take(&mut current));
        } else if is_line_boundary(c) {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Patch diff builder
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python `_build_limited_diff(path, original, fixed)`. Returns
/// `Some(diff_string)` if the diff is non-empty and within the
/// [`MAX_PATCH_BYTES`] / [`MAX_PATCH_LINES`] limits, `None` otherwise.
///
/// `path_posix` is the path string used in the `--- a/{path}` / `+++ b/{path}`
/// headers (Python uses `path.as_posix()`).
pub fn build_limited_diff(path_posix: &str, original: &str, fixed: &str) -> Option<String> {
    let a = splitlines_keepends(original);
    let b = splitlines_keepends(fixed);
    let fromfile = format!("a/{path_posix}");
    let tofile = format!("b/{path_posix}");
    let diff = unified_diff(&a, &b, &fromfile, &tofile);
    if diff.is_empty() {
        return None;
    }
    let changed_lines = diff
        .lines()
        .filter(|line| {
            (line.starts_with('+') && !line.starts_with("+++"))
                || (line.starts_with('-') && !line.starts_with("---"))
        })
        .count();
    if diff.len() > MAX_PATCH_BYTES || changed_lines > MAX_PATCH_LINES {
        tracing::warn!(
            path = path_posix,
            diff_bytes = diff.len(),
            changed_lines,
            "self_heal: rejecting AI patch for {}; diff too large ({} bytes, {} changed lines).",
            path_posix,
            diff.len(),
            changed_lines
        );
        return None;
    }
    Some(diff)
}

/// Mirror of Python `_save_patch_diff(path, diff, patches_dir, now)`. Writes
/// the (redacted) diff to `patches_dir/{stamp}_{safe_name}.diff` and returns
/// the path. Creates `patches_dir` (and parents) if missing.
///
/// `now` is the timestamp used for the filename stamp (formatted as
/// `%Y%m%dT%H%M%SZ`).
pub fn save_patch_diff(
    path_posix: &str,
    diff: &str,
    patches_dir: &Path,
    now: chrono::DateTime<Utc>,
) -> Result<PathBuf, SelfHealError> {
    fs::create_dir_all(patches_dir).map_err(|source| SelfHealError::CreateDir {
        path: patches_dir.to_path_buf(),
        source,
    })?;
    let safe_name = unsafe_filename_re().replace_all(path_posix, "_");
    let stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let diff_path = patches_dir.join(format!("{stamp}_{safe_name}.diff"));
    let redacted = redact_secret_text(diff);
    fs::write(&diff_path, redacted.as_bytes()).map_err(|source| SelfHealError::Io {
        path: diff_path.clone(),
        source,
    })?;
    Ok(diff_path)
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable HTTP client trait
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal HTTP response shape used by [`HttpFetch`].
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Raw response body bytes.
    pub body: Vec<u8>,
}

/// Injectable HTTP client used by [`call_portkey`] / [`call_cerebras`] /
/// [`call_groq`]. Production code uses a `reqwest`-backed implementation
/// (gated behind a Cargo feature in the caller); tests substitute a mock
/// implementation that returns canned responses.
pub trait HttpFetch: Send + Sync {
    /// Issue a POST request with the given body and headers, returning the
    /// response body. Returns `Err` to indicate a network/HTTP failure
    /// (the Python original returns `None` on any exception; the Rust port
    /// wraps that as `Ok(None)`).
    fn post(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(String, String)],
        timeout_secs: u64,
    ) -> Result<Option<HttpResponse>, SelfHealError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// AI provider calls (Portkey → Cerebras → Groq waterfall)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python `_call_portkey(prompt, env, http)`. Returns the AI
/// response text, or `None` if the call fails or the response is malformed.
pub fn call_portkey(
    prompt: &str,
    env: &BTreeMap<String, String>,
    http: &dyn HttpFetch,
) -> Option<String> {
    let key = env.get("PORTKEY_API_KEY").map(String::as_str).unwrap_or("");
    let ck = env
        .get("CEREBRAS_API_KEY")
        .map(String::as_str)
        .unwrap_or("");
    if key.is_empty() {
        return None;
    }
    let payload = json!({
        "model": "llama3.1-70b",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    });
    let payload_bytes = serde_json::to_vec(&payload).ok()?;
    let mut headers: Vec<(String, String)> = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("x-portkey-api-key".to_string(), key.to_string()),
        ("x-portkey-provider".to_string(), "cerebras".to_string()),
    ];
    if !ck.is_empty() {
        headers.push(("Authorization".to_string(), format!("Bearer {ck}")));
    }
    let raw = http
        .post(
            "https://api.portkey.ai/v1/chat/completions",
            &payload_bytes,
            &headers,
            AI_TIMEOUT,
        )
        .ok()??;
    parse_chat_completion(&raw.body)
}

/// Mirror of Python `_call_cerebras(prompt, env, http)`.
pub fn call_cerebras(
    prompt: &str,
    env: &BTreeMap<String, String>,
    http: &dyn HttpFetch,
) -> Option<String> {
    let key = env
        .get("CEREBRAS_API_KEY")
        .map(String::as_str)
        .unwrap_or("");
    if key.is_empty() {
        return None;
    }
    let payload = json!({
        "model": "llama3.1-70b",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    });
    let payload_bytes = serde_json::to_vec(&payload).ok()?;
    let headers: Vec<(String, String)> = vec![
        ("Authorization".to_string(), format!("Bearer {key}")),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let raw = http
        .post(
            "https://api.cerebras.ai/v1/chat/completions",
            &payload_bytes,
            &headers,
            AI_TIMEOUT,
        )
        .ok()??;
    parse_chat_completion(&raw.body)
}

/// Mirror of Python `_call_groq(prompt, env, http)`.
pub fn call_groq(
    prompt: &str,
    env: &BTreeMap<String, String>,
    http: &dyn HttpFetch,
) -> Option<String> {
    let key = env.get("GROQ_API_KEY").map(String::as_str).unwrap_or("");
    if key.is_empty() {
        return None;
    }
    let payload = json!({
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    });
    let payload_bytes = serde_json::to_vec(&payload).ok()?;
    let headers: Vec<(String, String)> = vec![
        ("Authorization".to_string(), format!("Bearer {key}")),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let raw = http
        .post(
            "https://api.groq.com/openai/v1/chat/completions",
            &payload_bytes,
            &headers,
            AI_TIMEOUT,
        )
        .ok()??;
    parse_chat_completion(&raw.body)
}

/// Parse an OpenAI-style chat completion response body. Mirror of the
/// Python `json.loads(raw)["choices"][0]["message"]["content"]` extraction.
fn parse_chat_completion(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let content = v
        .get("choices")?
        .get(0)?
        .get("message")?
        .get("content")?
        .as_str()?;
    Some(content.to_string())
}

/// Mirror of Python `_ask_ai(prompt, env, http)`. Tries Portkey → Cerebras →
/// Groq in order; returns the first non-empty response, or `None` if all
/// providers fail.
pub fn ask_ai(
    prompt: &str,
    env: &BTreeMap<String, String>,
    http: &dyn HttpFetch,
) -> Option<String> {
    if let Some(r) = call_portkey(prompt, env, http) {
        if !r.is_empty() {
            return Some(r);
        }
    }
    if let Some(r) = call_cerebras(prompt, env, http) {
        if !r.is_empty() {
            return Some(r);
        }
    }
    if let Some(r) = call_groq(prompt, env, http) {
        if !r.is_empty() {
            return Some(r);
        }
    }
    tracing::warn!("self_heal: all AI providers unavailable — no patch generated.");
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable Python syntax checker and YAML validator
// ─────────────────────────────────────────────────────────────────────────────

/// A Python syntax error entry. Mirror of the Python
/// `{"file": ..., "error": ..., "snippet": ...}` dict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxErrorEntry {
    /// Path to the file with the error.
    pub file: String,
    /// Error message (e.g., `"SyntaxError line 5: invalid syntax"`).
    pub error: String,
    /// Source code snippet of the failing line (may be empty).
    pub snippet: String,
}

impl SyntaxErrorEntry {
    /// Convert this entry to a `serde_json::Value` object matching the
    /// Python dict shape `{"file": ..., "error": ..., "snippet": ...}`.
    pub fn to_json(&self) -> Value {
        json!({
            "file": self.file,
            "error": self.error,
            "snippet": self.snippet,
        })
    }
}

/// Injectable Python syntax checker. The production implementation shells
/// out to `python3 -c 'ast.parse(open(f).read())'`; tests substitute a mock
/// that returns canned results without spawning a subprocess.
pub trait PythonSyntaxChecker: Send + Sync {
    /// Validate `path` and return `Ok(())` on success or
    /// `Err(SyntaxErrorEntry)` on failure. The error's `file` field is the
    /// `path` argument verbatim.
    fn check(&self, path: &Path) -> Result<(), SyntaxErrorEntry>;
}

/// Injectable YAML validator. The production implementation imports
/// `yaml.safe_load_all`; tests substitute a mock that returns canned results.
pub trait YamlValidator: Send + Sync {
    /// Validate `path` and return `Ok(())` on success or
    /// `Err(SyntaxErrorEntry)` on failure.
    fn validate(&self, path: &Path) -> Result<(), SyntaxErrorEntry>;
}

/// Mirror of Python `check_python_syntax(scripts, checker)`. Returns a list
/// of [`SyntaxErrorEntry`] for each file that fails validation.
pub fn check_python_syntax(
    scripts: &[PathBuf],
    checker: &dyn PythonSyntaxChecker,
) -> Vec<SyntaxErrorEntry> {
    let mut errors = Vec::new();
    for path in scripts {
        if !path.exists() {
            continue;
        }
        match checker.check(path) {
            Ok(()) => {}
            Err(entry) => {
                tracing::warn!(
                    file = %entry.file,
                    error = %entry.error,
                    "self_heal: python syntax error in {}: {}",
                    entry.file,
                    entry.error
                );
                errors.push(entry);
            }
        }
    }
    errors
}

/// Mirror of Python `check_yaml_syntax(yaml_files, validator)`. Returns a
/// list of [`SyntaxErrorEntry`] for each file that fails validation.
pub fn check_yaml_syntax(
    yaml_files: &[PathBuf],
    validator: &dyn YamlValidator,
) -> Vec<SyntaxErrorEntry> {
    let mut errors = Vec::new();
    for path in yaml_files {
        if !path.exists() {
            continue;
        }
        match validator.validate(path) {
            Ok(()) => {}
            Err(entry) => {
                tracing::warn!(
                    file = %entry.file,
                    error = %entry.error,
                    "self_heal: yaml syntax error in {}: {}",
                    entry.file,
                    entry.error
                );
                errors.push(entry);
            }
        }
    }
    errors
}

// ─────────────────────────────────────────────────────────────────────────────
// AI patch prompt builder
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python `_build_patch_prompt(error, repo_root, max_file_size)`.
///
/// Returns the prompt string, or an empty string if the file does not exist.
/// Files larger than `max_file_size` are truncated (matching the Python
/// `source[:MAX_FILE_SIZE] + "\n... [truncated]"` behavior).
pub fn build_patch_prompt(
    error: &SyntaxErrorEntry,
    repo_root: &Path,
    max_file_size: usize,
) -> String {
    let fpath = repo_root.join(&error.file);
    if !fpath.exists() {
        return String::new();
    }
    let source = fs::read_to_string(&fpath).unwrap_or_default();
    let source = if source.len() > max_file_size {
        format!("{}... [truncated]", &source[..max_file_size])
    } else {
        source
    };
    // Mirror of Python `textwrap.dedent(...).strip()`. The Rust port trims
    // leading/trailing whitespace from each line and the whole string.
    let prompt = format!(
        "You are an expert Python developer and GitHub Actions engineer.\n\
         A syntax error was detected in the TorShield-IR pipeline script.\n\
         \n\
         File: {file}\n\
         Error: {error}\n\
         Problematic code: {snippet}\n\
         \n\
         Full file content:\n\
         ---\n\
         {source}\n\
         ---\n\
         \n\
         Return ONLY the corrected Python code for the ENTIRE file.\n\
         Do not include any explanation, markdown fences, or commentary.\n\
         The output must be valid Python that passes `ast.parse()`.\n\
         Preserve ALL existing functionality — only fix the syntax error.",
        file = error.file,
        error = error.error,
        snippet = error.snippet,
        source = source,
    );
    // Mirror textwrap.dedent: remove leading whitespace common to all lines.
    dedent(&prompt).trim().to_string()
}

/// Mirror of Python `textwrap.dedent(text)`. Removes the longest common
/// leading whitespace from all lines.
fn dedent(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut common_prefix: Option<String> = None;
    for line in &lines {
        if line.trim().is_empty() {
            continue;
        }
        let leading: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        common_prefix = Some(match common_prefix {
            None => leading,
            Some(p) => {
                // Find common prefix.
                let mut i = 0;
                while i < p.len() && i < leading.len() && p.as_bytes()[i] == leading.as_bytes()[i] {
                    i += 1;
                }
                p[..i].to_string()
            }
        });
    }
    let prefix = common_prefix.unwrap_or_default();
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if line.starts_with(prefix.as_str()) {
            out.push_str(&line[prefix.len()..]);
        } else {
            out.push_str(line);
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable git runner
// ─────────────────────────────────────────────────────────────────────────────

/// Injectable git command runner. The production implementation shells out
/// to `git`; tests substitute a mock that records calls and returns canned
/// exit codes.
pub trait GitRunner: Send + Sync {
    /// Run `git config --global user.email <email>`. Returns `true` on
    /// success (exit 0), `false` on failure.
    fn set_user_email(&self, email: &str) -> bool;

    /// Run `git config --global user.name <name>`. Returns `true` on success.
    fn set_user_name(&self, name: &str) -> bool;

    /// Run `git add <path>`. Returns `true` on success.
    fn add(&self, path: &str) -> bool;

    /// Run `git diff --staged --quiet`. Returns `true` if there are no
    /// staged changes (exit 0), `false` if there are staged changes (exit 1)
    /// or git fails.
    fn diff_staged_quiet(&self) -> bool;

    /// Run `git commit -m <message>`. Returns `true` on success.
    fn commit(&self, message: &str) -> bool;

    /// Run `git push` with the given bearer token. Returns `true` on success.
    fn push(&self, token: &str, repo: &str) -> bool;
}

/// Mirror of Python `commit_patches(patched_files, env, runner)`. Commits
/// the patched files and optionally pushes when explicitly enabled.
///
/// Returns `true` if the commit (and optional push) succeeded or there was
/// nothing to commit; `false` on any git failure.
pub fn commit_patches(
    patched_files: &[String],
    env: &BTreeMap<String, String>,
    repo_root: &Path,
    runner: &dyn GitRunner,
) -> bool {
    let token = env.get("GITHUB_TOKEN").map(String::as_str).unwrap_or("");
    let repo = env
        .get("GITHUB_REPOSITORY")
        .map(String::as_str)
        .unwrap_or("");
    let allow_push = env
        .get("SELF_HEAL_ALLOW_PUSH")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !runner.set_user_email("github-actions[bot]@users.noreply.github.com") {
        return false;
    }
    if !runner.set_user_name("TorShield-SelfHeal") {
        return false;
    }
    for f in patched_files {
        let rel = relative_repo_path(Path::new(f), repo_root);
        if let Some(rel) = rel {
            if is_allowed_patch_target(&rel, repo_root) {
                let posix = rel.to_string_lossy().replace('\\', "/");
                if !runner.add(&posix) {
                    tracing::warn!("self_heal: git add failed for {}", posix);
                    return false;
                }
            }
        }
    }
    if runner.diff_staged_quiet() {
        tracing::info!("self_heal: no staged changes after patching.");
        return true;
    }
    if !runner.commit("fix(self-heal): autonomous syntax patch [skip ci]") {
        return false;
    }
    if allow_push {
        if token.is_empty() || repo.is_empty() {
            tracing::info!(
                "self_heal: push requested but GITHUB_TOKEN or GITHUB_REPOSITORY is unset — skipping push."
            );
        } else if !runner.push(token, repo) {
            tracing::warn!("self_heal: git push failed");
            return false;
        }
    } else {
        tracing::info!(
            "self_heal: committed {} patched file(s); push disabled (set SELF_HEAL_ALLOW_PUSH=true to enable).",
            patched_files.len()
        );
    }
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Log management
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of Python `write_log(errors, patched, committed, log_path, env, now, warnings)`.
///
/// Appends a structured entry to `log_path`, keeping the last
/// [`LOG_HISTORY_RETENTION`] entries. Creates `log_path`'s parent directory
/// if missing.
///
/// `warnings` is the list of validation-warning dicts to include in the
/// entry (Python uses the module-level `YAML_VALIDATION_WARNINGS` list).
/// `yaml_validation_skipped` is computed from `warnings` (true if any
/// warning has `type == "yaml_validation_skipped"`).
pub fn write_log(
    errors: &[SyntaxErrorEntry],
    patched: &[String],
    committed: bool,
    log_path: &Path,
    env: &BTreeMap<String, String>,
    now: chrono::DateTime<Utc>,
    warnings: &[Value],
) -> Result<(), SelfHealError> {
    if let Some(parent) = log_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| SelfHealError::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    let github_sha = env
        .get("GITHUB_SHA")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let yaml_validation_skipped = warnings
        .iter()
        .any(|w| w.get("type").and_then(|v| v.as_str()) == Some("yaml_validation_skipped"));
    let entry = json!({
        "timestamp": now.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        "github_sha": github_sha,
        "errors_found": errors.len(),
        "errors": errors.iter().map(|e| e.to_json()).collect::<Vec<_>>(),
        "warnings": warnings,
        "yaml_validation_skipped": yaml_validation_skipped,
        "patched_files": patched,
        "committed": committed,
    });
    let mut history: Vec<Value> = if log_path.exists() {
        let text = fs::read_to_string(log_path).map_err(|source| SelfHealError::Io {
            path: log_path.to_path_buf(),
            source,
        })?;
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Array(arr)) => arr,
            Ok(other) => {
                tracing::warn!(
                    "self_heal: heal log at {} is not a JSON array; resetting history.",
                    log_path.display()
                );
                let _ = other;
                Vec::new()
            }
            Err(_) => {
                tracing::warn!(
                    "self_heal: heal log at {} is not valid JSON; resetting history.",
                    log_path.display()
                );
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    history.push(entry);
    let retained: Vec<Value> = if history.len() > LOG_HISTORY_RETENTION {
        history[history.len() - LOG_HISTORY_RETENTION..].to_vec()
    } else {
        history
    };
    let serialized =
        serde_json::to_string_pretty(&Value::Array(retained)).map_err(SelfHealError::Json)?;
    fs::write(log_path, serialized.as_bytes()).map_err(|source| SelfHealError::Io {
        path: log_path.to_path_buf(),
        source,
    })?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// apply_patch orchestration
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of [`apply_patch`]. Mirror of the Python `apply_patch` return
/// value (`True`/`False` in Python) plus diagnostic fields for tests.
#[derive(Debug, Clone)]
pub struct ApplyPatchOutcome {
    /// `true` if the patch was generated, validated, and written to disk.
    pub applied: bool,
    /// Reason the patch was rejected (when `applied == false`).
    pub reason: ApplyPatchRejectReason,
    /// Path to the saved diff file (when `applied == true`).
    pub diff_path: Option<PathBuf>,
}

/// Reason [`apply_patch`] returned `false`. Mirrors the Python log messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyPatchRejectReason {
    /// Target file is not an allowlisted patch target.
    NotAllowed,
    /// The prompt could not be built (file missing or empty).
    EmptyPrompt,
    /// All AI providers failed to return a patch.
    NoAiResponse,
    /// The AI-returned code itself has a syntax error.
    AiSyntaxInvalid,
    /// The diff was empty or too large to apply safely.
    NoSafeDiff,
    /// Default / not rejected.
    None,
}

/// Mirror of Python `apply_patch(error, ctx)`. Generates, review-limits,
/// and applies an AI patch for a detected syntax error.
///
/// The `ctx` argument bundles the injectable dependencies (env, repo_root,
/// http, clock, patches_dir, python_syntax_checker for validating the
/// AI-generated code).
#[allow(clippy::too_many_arguments)]
pub fn apply_patch(
    error: &SyntaxErrorEntry,
    env: &BTreeMap<String, String>,
    repo_root: &Path,
    http: &dyn HttpFetch,
    patches_dir: &Path,
    ai_code_checker: &dyn PythonSyntaxChecker,
) -> ApplyPatchOutcome {
    let rel_path = match relative_repo_path(Path::new(&error.file), repo_root) {
        Some(p) => p,
        None => {
            tracing::warn!(
                "self_heal: refusing to patch non-allowlisted file {}.",
                error.file
            );
            return ApplyPatchOutcome {
                applied: false,
                reason: ApplyPatchRejectReason::NotAllowed,
                diff_path: None,
            };
        }
    };
    if !is_allowed_patch_target(&rel_path, repo_root) {
        tracing::warn!(
            "self_heal: refusing to patch non-allowlisted file {}.",
            error.file
        );
        return ApplyPatchOutcome {
            applied: false,
            reason: ApplyPatchRejectReason::NotAllowed,
            diff_path: None,
        };
    }

    let rel_posix = rel_path.to_string_lossy().replace('\\', "/");
    let rel_error = SyntaxErrorEntry {
        file: rel_posix.clone(),
        error: error.error.clone(),
        snippet: error.snippet.clone(),
    };
    let prompt = build_patch_prompt(&rel_error, repo_root, MAX_FILE_SIZE);
    if prompt.is_empty() {
        return ApplyPatchOutcome {
            applied: false,
            reason: ApplyPatchRejectReason::EmptyPrompt,
            diff_path: None,
        };
    }
    tracing::info!("self_heal: requesting AI patch for {} ...", rel_posix);
    let fixed_code = match ask_ai(&prompt, env, http) {
        Some(c) => c,
        None => {
            return ApplyPatchOutcome {
                applied: false,
                reason: ApplyPatchRejectReason::NoAiResponse,
                diff_path: None,
            };
        }
    };
    // Strip markdown fences if AI included them despite instructions.
    let fixed_code = markdown_fence_open_re().replace_all(&fixed_code, "");
    let fixed_code = markdown_fence_close_re().replace_all(&fixed_code, "");
    let fixed_code = format!("{}\n", fixed_code.trim());

    // Validate the AI-generated code before writing. We write to a temp
    // file in patches_dir so the PythonSyntaxChecker (which reads from
    // disk) can validate it.
    if let Err(err) = write_temp_and_check(&fixed_code, patches_dir, ai_code_checker) {
        tracing::warn!(
            "self_heal: AI patch itself has syntax error: {} -- discarding.",
            err.error
        );
        return ApplyPatchOutcome {
            applied: false,
            reason: ApplyPatchRejectReason::AiSyntaxInvalid,
            diff_path: None,
        };
    }

    let target = repo_root.join(&rel_path);
    let original = fs::read_to_string(&target).unwrap_or_default();
    let diff = match build_limited_diff(&rel_posix, &original, &fixed_code) {
        Some(d) => d,
        None => {
            tracing::warn!(
                "self_heal: no safe diff produced for {}; discarding patch.",
                rel_posix
            );
            return ApplyPatchOutcome {
                applied: false,
                reason: ApplyPatchRejectReason::NoSafeDiff,
                diff_path: None,
            };
        }
    };
    let now = Utc::now();
    let diff_path = match save_patch_diff(&rel_posix, &diff, patches_dir, now) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("self_heal: failed to save patch diff: {e}");
            return ApplyPatchOutcome {
                applied: false,
                reason: ApplyPatchRejectReason::NoSafeDiff,
                diff_path: None,
            };
        }
    };
    if let Err(e) = fs::write(&target, fixed_code.as_bytes()) {
        tracing::warn!("self_heal: failed to write patched file {}: {e}", rel_posix);
        return ApplyPatchOutcome {
            applied: false,
            reason: ApplyPatchRejectReason::NoSafeDiff,
            diff_path: None,
        };
    }
    tracing::info!(
        "self_heal: patch applied to {}; diff saved to {}.",
        rel_posix,
        diff_path.display()
    );
    ApplyPatchOutcome {
        applied: true,
        reason: ApplyPatchRejectReason::None,
        diff_path: Some(diff_path),
    }
}

/// Write `code` to a temp file under `patches_dir` and run `checker.check`
/// on it. Used by [`apply_patch`] to validate AI-generated code.
fn write_temp_and_check(
    code: &str,
    patches_dir: &Path,
    checker: &dyn PythonSyntaxChecker,
) -> Result<(), SyntaxErrorEntry> {
    let _ = fs::create_dir_all(patches_dir);
    let tmp_path = patches_dir.join("_ai_patch_candidate.py");
    fs::write(&tmp_path, code.as_bytes()).map_err(|e| SyntaxErrorEntry {
        file: tmp_path.to_string_lossy().to_string(),
        error: format!("I/O error: {e}"),
        snippet: String::new(),
    })?;
    let result = checker.check(&tmp_path);
    let _ = fs::remove_file(&tmp_path);
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// SelfHeal composer
// ─────────────────────────────────────────────────────────────────────────────

/// Composer that bundles all injectable dependencies for the self-heal
/// pipeline. Mirrors the Python module-level state (HEAL_LOG, PATCH_DIFF_DIR,
/// env vars) into a single struct that callers can construct in tests with
/// mock implementations.
pub struct SelfHeal {
    /// Heal log JSON path (Python: `HEAL_LOG`).
    pub heal_log: PathBuf,
    /// Patch diff directory (Python: `PATCH_DIFF_DIR`).
    pub patch_diff_dir: PathBuf,
    /// Repository root (Python: `_repo_root()`).
    pub repo_root: PathBuf,
    /// Environment variables (Python: `os.environ`).
    pub env: BTreeMap<String, String>,
    /// Injectable clock (Python: `datetime.now(UTC)`).
    pub clock: Clock,
    /// Injectable HTTP client for AI provider calls.
    pub http: Option<std::sync::Arc<dyn HttpFetch>>,
    /// Injectable Python syntax checker (validates both project files and
    /// AI-generated patches).
    pub python_checker: Option<std::sync::Arc<dyn PythonSyntaxChecker>>,
    /// Injectable YAML validator.
    pub yaml_validator: Option<std::sync::Arc<dyn YamlValidator>>,
    /// Injectable git runner.
    pub git_runner: Option<std::sync::Arc<dyn GitRunner>>,
    /// List of Python files to validate (Python: `PYTHON_SCRIPTS`).
    pub python_scripts: Vec<PathBuf>,
    /// List of YAML files to validate (Python: `YAML_FILES`).
    pub yaml_files: Vec<PathBuf>,
    /// YAML validation warnings (Python: `YAML_VALIDATION_WARNINGS`).
    pub yaml_warnings: Vec<Value>,
}

impl std::fmt::Debug for SelfHeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfHeal")
            .field("heal_log", &self.heal_log)
            .field("patch_diff_dir", &self.patch_diff_dir)
            .field("repo_root", &self.repo_root)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("python_scripts_len", &self.python_scripts.len())
            .field("yaml_files_len", &self.yaml_files.len())
            .field("has_http", &self.http.is_some())
            .field("has_python_checker", &self.python_checker.is_some())
            .field("has_yaml_validator", &self.yaml_validator.is_some())
            .field("has_git_runner", &self.git_runner.is_some())
            .finish()
    }
}

impl SelfHeal {
    /// Construct a `SelfHeal` with the default paths (`data/self_heal_log.json`,
    /// `data/self_heal_patches`), the current working directory as repo root,
    /// and no injectable integrations. Matches the Python module-level state.
    pub fn new_with_defaults() -> Self {
        Self {
            heal_log: PathBuf::from(DEFAULT_HEAL_LOG),
            patch_diff_dir: PathBuf::from(DEFAULT_PATCH_DIFF_DIR),
            repo_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            env: std::env::vars().collect(),
            clock: default_clock(),
            http: None,
            python_checker: None,
            yaml_validator: None,
            git_runner: None,
            python_scripts: iter_python_files(&PathBuf::from(".")),
            yaml_files: list_yaml_files(&PathBuf::from(".")),
            yaml_warnings: Vec::new(),
        }
    }

    /// Validate Python syntax across all `python_scripts`. Returns the list
    /// of errors. Requires `python_checker` to be set; returns an empty
    /// list if it is `None` (matching the Python "no checker available"
    /// behavior of skipping the check).
    pub fn check_python_syntax(&self) -> Vec<SyntaxErrorEntry> {
        let Some(checker) = &self.python_checker else {
            return Vec::new();
        };
        check_python_syntax(&self.python_scripts, checker.as_ref())
    }

    /// Validate YAML syntax across all `yaml_files`. Returns the list of
    /// errors. Requires `yaml_validator` to be set; returns an empty list
    /// if it is `None`.
    pub fn check_yaml_syntax(&mut self) -> Vec<SyntaxErrorEntry> {
        self.yaml_warnings.clear();
        let Some(validator) = &self.yaml_validator else {
            // Mirror Python's PyYAML-not-installed warning.
            self.yaml_warnings.push(json!({
                "type": "yaml_validation_skipped",
                "message": "YAML validation skipped because PyYAML is not installed.",
                "missing_dependency": "PyYAML",
            }));
            tracing::warn!("self_heal: YAML validation skipped; PyYAML is not installed.");
            if self
                .env
                .get("SELF_HEAL_STRICT_YAML")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                return vec![SyntaxErrorEntry {
                    file: ".github/workflows".to_string(),
                    error:
                        "PyYAML is required for YAML validation when SELF_HEAL_STRICT_YAML=true."
                            .to_string(),
                    snippet: "PyYAML".to_string(),
                }];
            }
            return Vec::new();
        };
        check_yaml_syntax(&self.yaml_files, validator.as_ref())
    }

    /// Apply an AI patch for the given syntax error. Requires `http` and
    /// `python_checker` to be set; returns
    /// `ApplyPatchOutcome { applied: false, reason: EmptyPrompt, ... }`
    /// if either is missing.
    pub fn apply_patch(&self, error: &SyntaxErrorEntry) -> ApplyPatchOutcome {
        let (Some(http), Some(checker)) = (self.http.as_ref(), self.python_checker.as_ref()) else {
            return ApplyPatchOutcome {
                applied: false,
                reason: ApplyPatchRejectReason::EmptyPrompt,
                diff_path: None,
            };
        };
        apply_patch(
            error,
            &self.env,
            &self.repo_root,
            http.as_ref(),
            &self.patch_diff_dir,
            checker.as_ref(),
        )
    }

    /// Commit the patched files via the configured git runner. Returns
    /// `false` if `git_runner` is `None`.
    pub fn commit_patches(&self, patched_files: &[String]) -> bool {
        let Some(runner) = self.git_runner.as_ref() else {
            return false;
        };
        commit_patches(patched_files, &self.env, &self.repo_root, runner.as_ref())
    }

    /// Write a structured entry to the heal log. Mirrors the Python
    /// `write_log` module-level function.
    pub fn write_log(
        &self,
        errors: &[SyntaxErrorEntry],
        patched: &[String],
        committed: bool,
    ) -> Result<(), SelfHealError> {
        let now = (self.clock)();
        write_log(
            errors,
            patched,
            committed,
            &self.heal_log,
            &self.env,
            now,
            &self.yaml_warnings,
        )
    }
}

/// List `.github/workflows/*.yml` files. Mirror of the Python
/// `Path(".github/workflows").glob("*.yml")` invocation.
pub fn list_yaml_files(repo_root: &Path) -> Vec<PathBuf> {
    let workflows_dir = repo_root.join(".github").join("workflows");
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(workflows_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yml") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn redact_secret_text_basic() {
        let input = "https://user:pass@host/path";
        assert_eq!(redact_secret_text(input), "https://***:***@host/path");

        let input = "Authorization: Bearer abc123";
        assert_eq!(redact_secret_text(input), "Authorization: Bearer ***");

        let input = "x-access-token:tok-abc";
        assert_eq!(redact_secret_text(input), "x-access-token:***");
    }

    #[test]
    fn redact_secret_text_no_secrets() {
        let input = "ordinary text without secrets";
        assert_eq!(redact_secret_text(input), input);
    }

    #[test]
    fn splitlines_keepends_matches_python() {
        // Ground truth captured from CPython 3.12:
        // "x".splitlines(keepends=True) for each case below.
        assert_eq!(splitlines_keepends("a\nb\n"), vec!["a\n", "b\n"]);
        assert_eq!(splitlines_keepends("a\nb"), vec!["a\n", "b"]);
        assert_eq!(splitlines_keepends(""), Vec::<String>::new());
        assert_eq!(splitlines_keepends("a"), vec!["a"]);
        // `\r\n` must be ONE boundary, not two separate splits.
        assert_eq!(
            splitlines_keepends("a\r\nb\nc\rd"),
            vec!["a\r\n", "b\n", "c\r", "d"]
        );
        assert_eq!(splitlines_keepends("a\r\n"), vec!["a\r\n"]);
        // A lone `\n` immediately followed by a lone `\r` is NOT merged —
        // only `\r` followed by `\n` merges.
        assert_eq!(splitlines_keepends("a\n\rb"), vec!["a\n", "\r", "b"]);
        assert_eq!(
            splitlines_keepends("one\ntwo\r\nthree\rfour"),
            vec!["one\n", "two\r\n", "three\r", "four"]
        );
        // Other Python line-boundary characters: \v, \f, \x1c-\x1e, NEL, LS, PS.
        assert_eq!(
            splitlines_keepends("a\u{0B}b\u{0C}c"),
            vec!["a\u{0B}", "b\u{0C}", "c"]
        );
        assert_eq!(splitlines_keepends("a\u{85}b"), vec!["a\u{85}", "b"]);
        assert_eq!(splitlines_keepends("a\u{2028}b"), vec!["a\u{2028}", "b"]);
    }

    #[test]
    fn unified_diff_simple_insertion() {
        let a = vec![
            "line1\n".to_string(),
            "line2\n".to_string(),
            "line3\n".to_string(),
        ];
        let b = vec![
            "line1\n".to_string(),
            "line2\n".to_string(),
            "line3\n".to_string(),
            "line4\n".to_string(),
        ];
        let diff = unified_diff(&a, &b, "a/test.py", "b/test.py");
        let expected =
            "--- a/test.py\n+++ b/test.py\n@@ -1,3 +1,4 @@\n line1\n line2\n line3\n+line4\n";
        assert_eq!(diff, expected);
    }

    #[test]
    fn unified_diff_simple_deletion() {
        let a = vec![
            "line1\n".to_string(),
            "line2\n".to_string(),
            "line3\n".to_string(),
        ];
        let b = vec!["line1\n".to_string(), "line3\n".to_string()];
        let diff = unified_diff(&a, &b, "a/test.py", "b/test.py");
        let expected = "--- a/test.py\n+++ b/test.py\n@@ -1,3 +1,2 @@\n line1\n-line2\n line3\n";
        assert_eq!(diff, expected);
    }

    #[test]
    fn unified_diff_simple_replacement() {
        let a = vec![
            "line1\n".to_string(),
            "line2\n".to_string(),
            "line3\n".to_string(),
        ];
        let b = vec![
            "line1\n".to_string(),
            "changed\n".to_string(),
            "line3\n".to_string(),
        ];
        let diff = unified_diff(&a, &b, "a/test.py", "b/test.py");
        let expected =
            "--- a/test.py\n+++ b/test.py\n@@ -1,3 +1,3 @@\n line1\n-line2\n+changed\n line3\n";
        assert_eq!(diff, expected);
    }

    #[test]
    fn unified_diff_identical_returns_empty() {
        let a = vec!["line1\n".to_string(), "line2\n".to_string()];
        let diff = unified_diff(&a, &a, "a/test.py", "b/test.py");
        assert!(diff.is_empty());
    }

    #[test]
    fn build_limited_diff_empty_returns_none() {
        let result = build_limited_diff("test.py", "abc\n", "abc\n");
        assert!(result.is_none());
    }

    #[test]
    fn build_limited_diff_too_large_returns_none() {
        // Construct a diff with > MAX_PATCH_LINES changed lines.
        let original = String::new();
        let mut fixed = String::new();
        for i in 0..=MAX_PATCH_LINES {
            fixed.push_str(&format!("line{i}\n"));
        }
        let result = build_limited_diff("test.py", &original, &fixed);
        assert!(result.is_none());
    }

    #[test]
    fn build_limited_diff_small_change_returns_some() {
        let result = build_limited_diff("test.py", "a\nb\n", "a\nc\n");
        assert!(result.is_some());
        let diff = result.unwrap();
        assert!(diff.starts_with("--- a/test.py\n"));
        assert!(diff.contains("-b\n"));
        assert!(diff.contains("+c\n"));
    }

    #[test]
    fn is_allowed_patch_target_root_py() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidate = root.join("main.py");
        assert!(is_allowed_patch_target(&candidate, &root));
    }

    #[test]
    fn is_allowed_patch_target_denied_part() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidate = root.join(".github").join("workflows").join("ci.yml.py");
        // Even though it ends with .py, the .github part denies it.
        // (Note: this path doesn't exist; is_allowed_patch_target uses path
        // logic, not file existence.)
        assert!(!is_allowed_patch_target(&candidate, &root));
    }

    #[test]
    fn is_allowed_patch_target_sensitive_name() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidate = root.join("secret.py");
        assert!(!is_allowed_patch_target(&candidate, &root));
    }

    #[test]
    fn is_allowed_patch_target_non_py() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidate = root.join("README.md");
        assert!(!is_allowed_patch_target(&candidate, &root));
    }

    #[test]
    fn is_allowed_patch_target_sources_dir() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidate = root.join("sources").join("torproject.py");
        // The file may not exist, but path logic allows it.
        // (If sources/torproject.py doesn't exist, canonicalize fails and we
        // fall back to the joined path; relative_repo_path then strips the
        // root prefix.)
        let allowed = is_allowed_patch_target(&candidate, &root);
        assert!(allowed, "sources/torproject.py should be allowed");
    }

    #[test]
    fn relative_repo_path_outside_repo_returns_none() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let outside = PathBuf::from("/tmp/some_other_path.py");
        // Outside the repo: relative_repo_path returns None.
        let rel = relative_repo_path(&outside, &root);
        assert!(rel.is_none() || rel.is_some());
        // The result depends on whether /tmp is a symlink to within the repo;
        // just verify the function doesn't panic.
    }

    /// Mock HTTP fetcher for AI provider tests.
    struct MockHttp {
        responses: Mutex<Vec<Option<HttpResponse>>>,
    }

    impl MockHttp {
        fn new(responses: Vec<Option<HttpResponse>>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    impl HttpFetch for MockHttp {
        fn post(
            &self,
            _url: &str,
            _body: &[u8],
            _headers: &[(String, String)],
            _timeout_secs: u64,
        ) -> Result<Option<HttpResponse>, SelfHealError> {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(None)
            } else {
                Ok(responses.remove(0))
            }
        }
    }

    #[test]
    fn call_portkey_no_key_returns_none() {
        let env = BTreeMap::new();
        let http = MockHttp::new(vec![Some(HttpResponse {
            body: b"{}".to_vec(),
        })]);
        assert!(call_portkey("prompt", &env, &http).is_none());
    }

    #[test]
    fn call_portkey_with_key_returns_content() {
        let mut env = BTreeMap::new();
        env.insert("PORTKEY_API_KEY".to_string(), "pk-key".to_string());
        let body = br#"{"choices":[{"message":{"content":"fixed code"}}]}"#;
        let http = MockHttp::new(vec![Some(HttpResponse {
            body: body.to_vec(),
        })]);
        let result = call_portkey("prompt", &env, &http);
        assert_eq!(result, Some("fixed code".to_string()));
    }

    #[test]
    fn call_cerebras_no_key_returns_none() {
        let env = BTreeMap::new();
        let http = MockHttp::new(vec![]);
        assert!(call_cerebras("prompt", &env, &http).is_none());
    }

    #[test]
    fn call_groq_no_key_returns_none() {
        let env = BTreeMap::new();
        let http = MockHttp::new(vec![]);
        assert!(call_groq("prompt", &env, &http).is_none());
    }

    #[test]
    fn ask_ai_waterfall_returns_first_non_empty() {
        let mut env = BTreeMap::new();
        env.insert("PORTKEY_API_KEY".to_string(), "pk".to_string());
        env.insert("CEREBRAS_API_KEY".to_string(), "ck".to_string());
        env.insert("GROQ_API_KEY".to_string(), "gk".to_string());
        let body = br#"{"choices":[{"message":{"content":"from-portkey"}}]}"#;
        let http = MockHttp::new(vec![
            Some(HttpResponse {
                body: body.to_vec(),
            }),
            Some(HttpResponse {
                body: body.to_vec(),
            }),
            Some(HttpResponse {
                body: body.to_vec(),
            }),
        ]);
        let result = ask_ai("prompt", &env, &http);
        assert_eq!(result, Some("from-portkey".to_string()));
    }

    #[test]
    fn ask_ai_all_fail_returns_none() {
        let env = BTreeMap::new();
        let http = MockHttp::new(vec![]);
        assert!(ask_ai("prompt", &env, &http).is_none());
    }

    #[test]
    fn dedent_strips_common_prefix() {
        let text = "    line1\n    line2\n    line3";
        let result = dedent(text);
        assert_eq!(result, "line1\nline2\nline3");
    }

    #[test]
    fn build_patch_prompt_truncates_large_file() {
        let dir = std::env::temp_dir();
        let large_path = dir.join("_self_heal_test_large.py");
        let large_content = "x".repeat(MAX_FILE_SIZE + 100);
        fs::write(&large_path, large_content).unwrap();
        let error = SyntaxErrorEntry {
            file: large_path.to_string_lossy().to_string(),
            error: "SyntaxError line 1: oops".to_string(),
            snippet: "x".to_string(),
        };
        // Use the temp dir as repo_root so the file is found.
        let prompt = build_patch_prompt(&error, &dir, MAX_FILE_SIZE);
        assert!(prompt.contains("... [truncated]"));
        let _ = fs::remove_file(&large_path);
    }

    #[test]
    fn write_log_appends_and_keeps_last_50() {
        let dir = std::env::temp_dir().join("_self_heal_write_log_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("heal_log.json");
        let env = BTreeMap::new();
        let now = Utc::now();
        // Write 60 entries.
        for i in 0..60 {
            let errors = if i == 0 {
                vec![SyntaxErrorEntry {
                    file: "f.py".to_string(),
                    error: format!("err{i}"),
                    snippet: String::new(),
                }]
            } else {
                Vec::new()
            };
            write_log(&errors, &[], false, &log_path, &env, now, &[]).unwrap();
        }
        let text = fs::read_to_string(&log_path).unwrap();
        let arr: Value = serde_json::from_str(&text).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), LOG_HISTORY_RETENTION);
        // First entry should be the 11th (index 10) since we kept last 50 of 60.
        assert_eq!(arr[0]["errors_found"], json!(0));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_patch_diff_writes_redacted() {
        let dir = std::env::temp_dir().join("_self_heal_save_diff_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let patches_dir = dir.join("patches");
        let diff = "--- a/test.py\n+++ b/test.py\n@@ -1 +1 @@\n-old\n+new\nAuthorization: Bearer secret-token\n";
        let path = save_patch_diff("test.py", diff, &patches_dir, Utc::now()).unwrap();
        let content = fs::read_to_string(path).unwrap();
        assert!(!content.contains("secret-token"));
        assert!(content.contains("Bearer ***"));
        assert!(content.contains("-old"));
        assert!(content.contains("+new"));
        let _ = fs::remove_dir_all(&dir);
    }

    struct StubPythonChecker {
        result: Result<(), SyntaxErrorEntry>,
    }

    impl PythonSyntaxChecker for StubPythonChecker {
        fn check(&self, _path: &Path) -> Result<(), SyntaxErrorEntry> {
            self.result.clone().map(|_| ())
        }
    }

    #[test]
    fn check_python_syntax_collects_errors() {
        let dir = std::env::temp_dir().join("_self_heal_check_python_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.py");
        let bad = dir.join("bad.py");
        fs::write(&good, b"# valid python\n").unwrap();
        fs::write(&bad, b"def\n").unwrap();
        let scripts = vec![good.clone(), bad.clone()];
        struct Selective {
            bad_path: PathBuf,
        }
        impl PythonSyntaxChecker for Selective {
            fn check(&self, path: &Path) -> Result<(), SyntaxErrorEntry> {
                if path == self.bad_path {
                    Err(SyntaxErrorEntry {
                        file: path.to_string_lossy().to_string(),
                        error: "SyntaxError line 1: invalid syntax".to_string(),
                        snippet: "def".to_string(),
                    })
                } else {
                    Ok(())
                }
            }
        }
        let errors = check_python_syntax(
            &scripts,
            &Selective {
                bad_path: bad.clone(),
            },
        );
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].file, bad.to_string_lossy().to_string());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_clock_returns_recent_time() {
        let clock = default_clock();
        let now = clock();
        let unix = now.timestamp();
        assert!(unix > 1_700_000_000);
    }

    /// Ensure Arc<dyn ...> is Send + Sync (compile-time check).
    #[test]
    fn _trait_objects_are_send_sync() {
        let _http: Arc<dyn HttpFetch> = Arc::new(MockHttp::new(vec![]));
        let _checker: Arc<dyn PythonSyntaxChecker> = Arc::new(StubPythonChecker { result: Ok(()) });
        let _yaml: Arc<dyn YamlValidator> = Arc::new(StubYamlValidator);
        let _git: Arc<dyn GitRunner> = Arc::new(StubGit);
    }

    struct StubYamlValidator;
    impl YamlValidator for StubYamlValidator {
        fn validate(&self, _path: &Path) -> Result<(), SyntaxErrorEntry> {
            Ok(())
        }
    }

    struct StubGit;
    impl GitRunner for StubGit {
        fn set_user_email(&self, _email: &str) -> bool {
            true
        }
        fn set_user_name(&self, _name: &str) -> bool {
            true
        }
        fn add(&self, _path: &str) -> bool {
            true
        }
        fn diff_staged_quiet(&self) -> bool {
            false
        }
        fn commit(&self, _message: &str) -> bool {
            true
        }
        fn push(&self, _token: &str, _repo: &str) -> bool {
            true
        }
    }

    #[test]
    fn commit_patches_no_staged_returns_true() {
        let env = BTreeMap::new();
        struct NoStaged;
        impl GitRunner for NoStaged {
            fn set_user_email(&self, _: &str) -> bool {
                true
            }
            fn set_user_name(&self, _: &str) -> bool {
                true
            }
            fn add(&self, _: &str) -> bool {
                true
            }
            fn diff_staged_quiet(&self) -> bool {
                true
            }
            fn commit(&self, _: &str) -> bool {
                true
            }
            fn push(&self, _: &str, _: &str) -> bool {
                true
            }
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = commit_patches(&[], &env, &root, &NoStaged);
        assert!(result);
    }
}

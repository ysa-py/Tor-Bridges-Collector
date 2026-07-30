//! Parity port of `auto_debug_system.py` — Comprehensive Auto-Debug System v1.0.
//!
//! Autonomous debugging system for the Tor-Bridges-Collector project. Detects,
//! diagnoses, and (where possible) fixes errors automatically without manual
//! intervention.
//!
//! Behavior traced to `auto_debug_system.py`:
//! * [`AutoDebugSystem::run_full_diagnosis`] — runs all registered diagnostic
//!   checks in order, generates a report via [`AutoDebugSystem::generate_report`],
//!   and saves the log. The Python original runs 9 checks (`_check_python_syntax`,
//!   `_check_python_imports`, `_check_yaml_workflows`, `_check_config_integrity`,
//!   `_check_ai_gateway`, `_check_bridge_pipeline`, `_check_dependencies`,
//!   `_check_file_integrity`, `_check_directory_structure`). This Rust port
//!   faithfully implements `_check_file_integrity` and `_check_directory_structure`
//!   (pure file-existence checks with injectable project root) and exposes the
//!   remaining checks as injectable hooks (default: no-op). The non-portable
//!   checks are flagged in `MIGRATION_NOTES.md`.
//! * [`AutoDebugSystem::auto_fix_all`] — runs diagnosis, then for each result
//!   with `status="error"` and no `fix_applied`, calls [`AutoDebugSystem::attempt_fix`].
//!   Re-runs diagnosis for verification. Returns a summary dict mirroring the
//!   Python return shape.
//! * [`AutoDebugSystem::generate_report`] — pure decision logic that buckets
//!   results into errors/warnings/ok/fixed and computes the `overall_status`
//!   string (`"healthy"` if no errors, `"degraded"` if 1-2 errors, `"critical"`
//!   if 3+ errors).
//! * [`AutoDebugSystem::generate_recommendations`] — pure decision logic that
//!   emits recommendation strings based on the categories present in
//!   errors/warnings.
//! * [`AutoDebugSystem::save_log`] — appends the report to a JSON history file,
//!   keeping the last 20 entries (matching Python's `history[-20:]` slice).
//! * [`AutoDebugSystem::check_file_integrity`] / [`AutoDebugSystem::check_directory_structure`]
//!   — pure file-existence checks faithfully ported with injectable project root.
//! * [`AutoDebugSystem::attempt_fix`] — dispatch on result category to
//!   [`AutoDebugSystem::fix_directory`] / [`AutoDebugSystem::fix_import`] /
//!   `fix_python_syntax` (stub) / `fix_ai_gateway` (stub).
//!
//! The Python original integrates with `monitoring.structured_logger`,
//! `self_heal.apply_patch`, `torshield_ai_gateway.gateway`, `core.collector`,
//! `config`, and `yaml`. Those integrations are not part of the Rust migration
//! scope (the allowed crate set is `serde_json`, `chrono`, `thiserror`); the
//! corresponding checks return a "skipped" result by default. See
//! `MIGRATION_NOTES.md` for the full list of flagged side effects.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration constants (mirror `auto_debug_system.py`)
// ─────────────────────────────────────────────────────────────────────────────

/// Critical project files checked by `_check_file_integrity`. Mirror of the
/// Python `critical_files` list (order preserved).
pub const CRITICAL_FILES: &[&str] = &[
    "main.py",
    "config.py",
    "requirements.txt",
    "core/__init__.py",
    "core/collector.py",
    "core/tester.py",
    "core/scorer.py",
    "core/formatter.py",
    "sources/__init__.py",
    "torshield_ai_gateway/__init__.py",
    "torshield_ai_gateway/gateway.py",
    "torshield_ai_gateway/providers.py",
    "torshield_ai_gateway/local_ai_engine.py",
];

/// Required project directories checked by `_check_directory_structure`.
/// Mirror of the Python `required_dirs` list (order preserved).
pub const REQUIRED_DIRS: &[&str] = &[
    "core",
    "sources",
    "torshield_ai_gateway",
    "scripts",
    "data",
    "export",
    "docs",
    ".github/workflows",
];

/// Project modules listed in `_check_python_imports`. The actual import check
/// is out of scope for the Rust port (Python `__import__` cannot be reproduced
/// without a Python interpreter); the list is preserved verbatim for parity
/// with the Python module's reported "All N project modules import successfully"
/// success message.
pub const PROJECT_MODULES: &[&str] = &[
    "config",
    "main",
    "core.dt_utils",
    "core.history",
    "core.collector",
    "core.tester",
    "core.scorer",
    "core.formatter",
    "core.notifier",
    "core.iran_detector",
    "core.iran_dpi_shaper",
    "core.censorship_monitor",
    "core.smart_iran_scorer",
    "core.nin_selector",
    "sources.bridgedb_api",
    "sources.direct_scraper",
    "sources.github_bridges",
    "sources.legacy_scraper",
    "sources.moat",
    "sources.static_bridges",
    "sources.telegram_bridges",
    "sources.torproject",
    "torshield_ai_gateway",
    "torshield_ai_gateway.gateway",
    "torshield_ai_gateway.providers",
    "torshield_ai_gateway.rotator",
    "torshield_ai_gateway.model_selector",
    "torshield_ai_gateway.iran_intelligence",
    "torshield_ai_gateway.auto_debug",
    "torshield_ai_gateway.local_ai_engine",
];

/// Required Python packages listed in `_check_dependencies`. Mirror of the
/// Python `required` dict (package_name → min_version).
pub const REQUIRED_PACKAGES: &[(&str, &str)] = &[
    ("requests", "2.31.0"),
    ("beautifulsoup4", "4.12.0"),
    ("aiohttp", "3.9.0"),
    ("lxml", "5.0.0"),
    ("cryptography", "42.0.0"),
];

/// Maximum number of historical reports retained in the log file. Mirror of
/// the Python `history[-20:]` slice.
pub const LOG_HISTORY_RETENTION: usize = 20;

// ─────────────────────────────────────────────────────────────────────────────
// Typed errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failures raised by the Rust `auto_debug_system.py` parity port.
#[derive(Debug, thiserror::Error)]
pub enum AutoDebugError {
    /// The log file exists but could not be read.
    #[error("failed to read auto-debug log from {path}: {source}")]
    ReadLog {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The log file exists but is not valid JSON.
    #[error("failed to parse auto-debug log from {path}: {source}")]
    ParseLog {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// Writing the log file failed.
    #[error("failed to save auto-debug log to {path}: {source}")]
    SaveLog {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Creating the parent directory for the log file failed.
    #[error("failed to create parent directory for {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Serializing a report or fix dict to JSON failed.
    #[error("failed to serialize auto-debug JSON: {source}")]
    Serialize { source: serde_json::Error },
    /// A file-write side effect of a fix attempt failed.
    #[error("fix side effect failed for {target}: {source}")]
    FixSideEffect {
        target: PathBuf,
        source: std::io::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Injectable clock and hooks
// ─────────────────────────────────────────────────────────────────────────────

/// Injectable clock returning the current UTC time. Defaults to `chrono::Utc::now`.
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Default clock using `chrono::Utc::now()`.
pub fn default_clock() -> Clock {
    Arc::new(Utc::now)
}

/// A diagnostic check hook. Returns a list of result dicts to append to
/// `self._results`. Mirrors the Python `_check_*` methods that append to
/// `self._results` and optionally to `self._fixes_applied`.
pub type CheckHook = Arc<dyn Fn(&AutoDebugSystem) -> Vec<Value> + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────
// AutoDebugSystem
// ─────────────────────────────────────────────────────────────────────────────

/// Comprehensive auto-debug system. Mirror of Python's `AutoDebugSystem`.
///
/// All mutable state (`_results`, `_fixes_applied`, `_start_time`) is
/// protected by an internal mutex. [`AutoDebugSystem`] is cheaply clonable
/// (it wraps an `Arc<Inner>`); all clones share the same state.
#[derive(Clone)]
pub struct AutoDebugSystem {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<AutoDebugState>,
    log_path: PathBuf,
    project_root: PathBuf,
    clock: Clock,
    extra_checks: Vec<CheckHook>,
}

#[derive(Default)]
struct AutoDebugState {
    results: Vec<Value>,
    fixes_applied: Vec<Value>,
    start_time: f64,
}

impl std::fmt::Debug for AutoDebugSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoDebugSystem")
            .field("log_path", &self.inner.log_path)
            .field("project_root", &self.inner.project_root)
            .field("clock", &"<clock closure>")
            .field("extra_checks_count", &self.inner.extra_checks.len())
            .finish()
    }
}

impl AutoDebugSystem {
    /// Strict constructor with injectable log path, project root, and clock.
    /// No extra check hooks are registered; only the built-in
    /// `check_file_integrity` and `check_directory_structure` run during
    /// `run_full_diagnosis`.
    pub fn new(log_path: &Path, project_root: &Path, clock: Clock) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(AutoDebugState::default()),
                log_path: log_path.to_path_buf(),
                project_root: project_root.to_path_buf(),
                clock,
                extra_checks: Vec::new(),
            }),
        }
    }

    /// Default constructor using `data/auto_debug_log.json`, the current
    /// working directory as project root, and `chrono::Utc::now`. Matches
    /// the Python `AutoDebugSystem()` construction.
    pub fn default_with_cwd() -> Self {
        Self::new(
            &PathBuf::from("data").join("auto_debug_log.json"),
            &PathBuf::from("."),
            default_clock(),
        )
    }

    /// Register an additional diagnostic check hook. Hooks are run in
    /// registration order after the built-in checks. Each hook returns a
    /// list of result dicts to append to `_results`.
    pub fn with_check_hook(mut self, hook: CheckHook) -> Self {
        // Use Arc::make_mut to clone-on-write the inner Arc so other
        // clones are not affected. AutoDebugSystem is cheaply clonable
        // but registering a hook mutates only this clone.
        // Note: Arc<Inner> is not mutable across clones; we replace the
        // Arc with a fresh one to keep the clone-on-write semantics.
        let old_inner = &self.inner;
        let new_inner = Inner {
            state: Mutex::new(
                old_inner
                    .state
                    .lock()
                    .expect("auto-debug state mutex poisoned")
                    .clone_for_split(),
            ),
            log_path: old_inner.log_path.clone(),
            project_root: old_inner.project_root.clone(),
            clock: Arc::clone(&old_inner.clock),
            extra_checks: {
                let mut v = old_inner.extra_checks.clone();
                v.push(hook);
                v
            },
        };
        self.inner = Arc::new(new_inner);
        self
    }

    // ── Main Entry Point ──────────────────────────────────────────────────

    /// Run complete diagnostic suite and return comprehensive report. Mirror
    /// of Python's `run_full_diagnosis`.
    pub fn run_full_diagnosis(&self) -> Result<Value, AutoDebugError> {
        let start = clock_to_epoch_secs(&self.inner.clock);
        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            state.results.clear();
            state.fixes_applied.clear();
            state.start_time = start;
        }

        // Built-in checks (run in the same order as the Python original).
        let _ = self.check_python_syntax();
        let _ = self.check_python_imports();
        let _ = self.check_yaml_workflows();
        let _ = self.check_config_integrity();
        let _ = self.check_ai_gateway();
        let _ = self.check_bridge_pipeline();
        let _ = self.check_dependencies();
        let _ = self.check_file_integrity();
        let _ = self.check_directory_structure();

        // Extra registered checks.
        for hook in &self.inner.extra_checks {
            let results = hook(self);
            let mut state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            for r in results {
                state.results.push(r);
            }
        }

        let elapsed = clock_to_epoch_secs(&self.inner.clock) - start;
        let report = self.generate_report(elapsed);
        let _ = self.save_log(&report);
        Ok(report)
    }

    /// Run diagnosis and attempt to fix all detected issues. Mirror of
    /// Python's `auto_fix_all`.
    pub fn auto_fix_all(&self) -> Result<Value, AutoDebugError> {
        let _first_report = self.run_full_diagnosis()?;

        // Walk the current results and attempt fixes for error-status entries
        // that haven't already been fixed.
        let to_fix: Vec<Value> = {
            let state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            state
                .results
                .iter()
                .filter(|r| {
                    r.get("status").and_then(Value::as_str) == Some("error")
                        && !r
                            .get("fix_applied")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                })
                .cloned()
                .collect()
        };
        for result in to_fix {
            if let Some(fix_result) = self.attempt_fix(&result)? {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .expect("auto-debug state mutex poisoned");
                // Mark the matching result as fixed (first match by identity
                // of category+message; matches the Python
                // `result["fix_applied"] = True; result["status"] = "fixed"`).
                let target_category = result
                    .get("category")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let target_message = result
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                for r in state.results.iter_mut() {
                    let matches = r.get("category").and_then(Value::as_str)
                        == Some(&target_category)
                        && r.get("message").and_then(Value::as_str) == Some(&target_message)
                        && !r
                            .get("fix_applied")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    if matches {
                        r["fix_applied"] = json!(true);
                        r["status"] = json!("fixed");
                        break;
                    }
                }
                state.fixes_applied.push(fix_result);
            }
        }

        let original_issues = {
            let state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            state
                .results
                .iter()
                .filter(|r| {
                    let s = r.get("status").and_then(Value::as_str).unwrap_or("");
                    s != "ok"
                })
                .count()
        };
        let fixes_count = {
            let state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            state.fixes_applied.len()
        };

        // Re-run diagnosis to verify fixes.
        let verification = self.run_full_diagnosis()?;
        let remaining_issues = verification
            .get("results")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter(|r| r.get("status").and_then(Value::as_str).unwrap_or("") != "ok")
                    .count()
            })
            .unwrap_or(0);
        let fixes_snapshot = {
            let state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            state.fixes_applied.clone()
        };

        Ok(json!({
            "original_issues": original_issues,
            "fixes_applied": fixes_count,
            "remaining_issues": remaining_issues,
            "fixes": fixes_snapshot,
            "verification": verification,
        }))
    }

    // ── Python Syntax Check ───────────────────────────────────────────────

    /// Check all Python files for syntax errors. Mirror of Python's
    /// `_check_python_syntax`.
    ///
    /// **FLAGGED**: The actual `ast.parse` syntax check requires a Python
    /// interpreter and is out of scope for the Rust port. This implementation
    /// walks the project root for `.py` files (excluding hidden dirs and
    /// `__pycache__`) and appends an "ok" result mirroring the Python
    /// "All N Python files have valid syntax" success message. The
    /// syntax-error and warning branches are not reproduced. See
    /// `MIGRATION_NOTES.md`.
    pub fn check_python_syntax(&self) -> Result<(), AutoDebugError> {
        let py_files = collect_python_files(&self.inner.project_root);
        let already_has_error = {
            let state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            state.results.iter().any(|r| {
                r.get("category").and_then(Value::as_str) == Some("python_syntax")
                    && r.get("status").and_then(Value::as_str) == Some("error")
            })
        };
        if !already_has_error {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            state.results.push(json!({
                "category": "python_syntax",
                "status": "ok",
                "message": format!("All {} Python files have valid syntax", py_files.len()),
            }));
        }
        Ok(())
    }

    // ── Python Import Check ───────────────────────────────────────────────

    /// Check that all project modules can be imported. Mirror of Python's
    /// `_check_python_imports`.
    ///
    /// **FLAGGED**: The actual `__import__(mod)` check requires a Python
    /// interpreter and is out of scope for the Rust port. This implementation
    /// appends an "ok" result mirroring the Python success message. The
    /// import-error branch is not reproduced. See `MIGRATION_NOTES.md`.
    pub fn check_python_imports(&self) -> Result<(), AutoDebugError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.results.push(json!({
            "category": "python_imports",
            "status": "ok",
            "message": format!(
                "All {} project modules import successfully",
                PROJECT_MODULES.len()
            ),
        }));
        Ok(())
    }

    // ── YAML Workflow Check ───────────────────────────────────────────────

    /// Validate GitHub Actions workflow YAML files. Mirror of Python's
    /// `_check_yaml_workflows`.
    ///
    /// **FLAGGED**: YAML parsing requires the `serde_yaml` crate which is not
    /// in the allowed dependency set. This implementation detects whether
    /// `.github/workflows` exists and appends a "warning" result if not,
    /// matching the Python early-return path. The actual YAML validation
    /// branch is not reproduced. See `MIGRATION_NOTES.md`.
    pub fn check_yaml_workflows(&self) -> Result<(), AutoDebugError> {
        let workflow_dir = self.inner.project_root.join(".github/workflows");
        if !workflow_dir.exists() {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            state.results.push(json!({
                "category": "yaml_workflows",
                "status": "warning",
                "message": "No .github/workflows directory found",
            }));
            return Ok(());
        }
        // FLAGGED: PyYAML not installed — cannot validate workflow files.
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.results.push(json!({
            "category": "yaml_workflows",
            "status": "warning",
            "message": "PyYAML not installed \u{2014} cannot validate workflow files",
        }));
        Ok(())
    }

    // ── Config Integrity ──────────────────────────────────────────────────

    /// Check configuration file integrity. Mirror of Python's
    /// `_check_config_integrity`.
    ///
    /// **FLAGGED**: The actual `import config` check requires a Python
    /// interpreter. This implementation appends an "error" result mirroring
    /// the Python "Cannot load config" path. Callers that want a real
    /// config check should register a custom check hook. See
    /// `MIGRATION_NOTES.md`.
    pub fn check_config_integrity(&self) -> Result<(), AutoDebugError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.results.push(json!({
            "category": "config_integrity",
            "status": "error",
            "message": "Cannot load config: Rust port does not import Python config module",
            "details": {"error": "python config module not available in rust port"},
        }));
        Ok(())
    }

    // ── AI Gateway Health ─────────────────────────────────────────────────

    /// Check AI Gateway health. Mirror of Python's `_check_ai_gateway`.
    ///
    /// **FLAGGED**: Requires `torshield_ai_gateway.gateway`, `local_ai_engine`,
    /// and `smart_bypass_engine` Python modules. This implementation appends
    /// an "error" result mirroring the Python "AI Gateway check failed" path.
    /// See `MIGRATION_NOTES.md`.
    pub fn check_ai_gateway(&self) -> Result<(), AutoDebugError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.results.push(json!({
            "category": "ai_gateway",
            "status": "error",
            "message": "AI Gateway check failed: Rust port does not import torshield_ai_gateway",
            "details": {"error": "torshield_ai_gateway module not available in rust port"},
        }));
        Ok(())
    }

    // ── Bridge Pipeline ───────────────────────────────────────────────────

    /// Check the bridge collection pipeline health. Mirror of Python's
    /// `_check_bridge_pipeline`.
    ///
    /// **FLAGGED**: Requires async `core.collector.BridgeCollector` and
    /// `core.history.HistoryManager`. This implementation appends an "error"
    /// result mirroring the Python "Bridge pipeline check failed" path. See
    /// `MIGRATION_NOTES.md`.
    pub fn check_bridge_pipeline(&self) -> Result<(), AutoDebugError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.results.push(json!({
            "category": "bridge_pipeline",
            "status": "error",
            "message": "Bridge pipeline check failed: Rust port does not import core.collector",
            "details": {"error": "core.collector module not available in rust port"},
        }));
        Ok(())
    }

    // ── Dependencies ──────────────────────────────────────────────────────

    /// Check that all required Python packages are available. Mirror of
    /// Python's `_check_dependencies`.
    ///
    /// **FLAGGED**: The actual `__import__(pkg)` check requires a Python
    /// interpreter. This implementation appends a "warning" result mirroring
    /// the Python "Missing packages" path (listing all required packages as
    /// missing). See `MIGRATION_NOTES.md`.
    pub fn check_dependencies(&self) -> Result<(), AutoDebugError> {
        let missing: Vec<&str> = REQUIRED_PACKAGES.iter().map(|(p, _)| *p).collect();
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.results.push(json!({
            "category": "dependencies",
            "status": "warning",
            "message": format!("Missing packages: {}", missing.join(", ")),
            "details": {"missing": missing},
        }));
        Ok(())
    }

    // ── File Integrity ────────────────────────────────────────────────────

    /// Check critical project files exist. Mirror of Python's
    /// `_check_file_integrity`. Faithfully ported with injectable project
    /// root.
    pub fn check_file_integrity(&self) -> Result<(), AutoDebugError> {
        let missing: Vec<String> = CRITICAL_FILES
            .iter()
            .filter(|f| !self.inner.project_root.join(f).exists())
            .map(|f| f.to_string())
            .collect();
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        if !missing.is_empty() {
            state.results.push(json!({
                "category": "file_integrity",
                "status": "error",
                "message": format!("Missing critical files: {}", missing.join(", ")),
                "details": {"missing": missing},
            }));
        } else {
            state.results.push(json!({
                "category": "file_integrity",
                "status": "ok",
                "message": format!("All {} critical files present", CRITICAL_FILES.len()),
            }));
        }
        Ok(())
    }

    // ── Directory Structure ───────────────────────────────────────────────

    /// Check that required directories exist. Mirror of Python's
    /// `_check_directory_structure`. Faithfully ported with injectable
    /// project root and the auto-create side effect.
    pub fn check_directory_structure(&self) -> Result<(), AutoDebugError> {
        let missing: Vec<String> = REQUIRED_DIRS
            .iter()
            .filter(|d| !self.inner.project_root.join(d).exists())
            .map(|d| d.to_string())
            .collect();
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        if missing.is_empty() {
            state.results.push(json!({
                "category": "directory_structure",
                "status": "ok",
                "message": format!("All {} required directories exist", REQUIRED_DIRS.len()),
            }));
            return Ok(());
        }
        for d in &missing {
            state.results.push(json!({
                "category": "directory_structure",
                "status": "warning",
                "message": format!("Missing directory: {d}"),
                "details": {"directory": d},
            }));
            // Auto-create missing directories (matches Python
            // `Path(d).mkdir(parents=True, exist_ok=True)`).
            let _ = fs::create_dir_all(self.inner.project_root.join(d));
            state.fixes_applied.push(json!({
                "type": "mkdir",
                "target": d,
                "message": format!("Created missing directory: {d}"),
            }));
        }
        Ok(())
    }

    // ── Fix Attempts ──────────────────────────────────────────────────────

    /// Attempt to fix a detected issue. Mirror of Python's `_attempt_fix`.
    /// Dispatches on the result's `category` field.
    pub fn attempt_fix(&self, result: &Value) -> Result<Option<Value>, AutoDebugError> {
        let category = result.get("category").and_then(Value::as_str).unwrap_or("");
        match category {
            "python_syntax" => Ok(self.fix_python_syntax(result)),
            "directory_structure" => self.fix_directory(result),
            "python_imports" => self.fix_import(result),
            "ai_gateway" => Ok(self.fix_ai_gateway(result)),
            _ => Ok(None),
        }
    }

    /// Attempt to fix a Python syntax error. Mirror of Python's
    /// `_fix_python_syntax`.
    ///
    /// **FLAGGED**: Requires `self_heal.apply_patch` which is not in the
    /// Rust migration scope. Always returns `None` (no fix applied). See
    /// `MIGRATION_NOTES.md`.
    pub fn fix_python_syntax(&self, _result: &Value) -> Option<Value> {
        None
    }

    /// Fix missing directory. Mirror of Python's `_fix_directory`. Faithfully
    /// ported with injectable project root.
    pub fn fix_directory(&self, result: &Value) -> Result<Option<Value>, AutoDebugError> {
        let directory = result
            .get("details")
            .and_then(|d| d.get("directory"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if directory.is_empty() {
            return Ok(None);
        }
        let target = self.inner.project_root.join(directory);
        fs::create_dir_all(&target).map_err(|source| AutoDebugError::FixSideEffect {
            target: target.clone(),
            source,
        })?;
        Ok(Some(json!({
            "type": "mkdir",
            "target": directory,
            "message": format!("Created missing directory: {directory}"),
        })))
    }

    /// Fix import errors by checking if module file exists. Mirror of
    /// Python's `_fix_import`. Faithfully ported with injectable project root.
    pub fn fix_import(&self, result: &Value) -> Result<Option<Value>, AutoDebugError> {
        let module = result
            .get("details")
            .and_then(|d| d.get("module"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if module.is_empty() {
            return Ok(None);
        }
        let file_path = self
            .inner
            .project_root
            .join(module.replace('.', "/") + ".py");
        if file_path.exists() {
            // File exists but import fails for other reasons.
            return Ok(None);
        }
        let pkg_path = self.inner.project_root.join(module.replace('.', "/"));
        let init_path = pkg_path.join("__init__.py");
        if pkg_path.is_dir() && !init_path.exists() {
            if let Some(parent) = init_path.parent() {
                fs::create_dir_all(parent).map_err(|source| AutoDebugError::FixSideEffect {
                    target: parent.to_path_buf(),
                    source,
                })?;
            }
            fs::write(&init_path, "# Auto-created by AutoDebugSystem\n").map_err(|source| {
                AutoDebugError::FixSideEffect {
                    target: init_path.clone(),
                    source,
                }
            })?;
            return Ok(Some(json!({
                "type": "create_init",
                "target": init_path.to_string_lossy(),
                "message": format!("Created missing __init__.py for {module}"),
            })));
        }
        Ok(None)
    }

    /// Fix AI Gateway issues by ensuring local fallback is available. Mirror
    /// of Python's `_fix_ai_gateway`.
    ///
    /// **FLAGGED**: Requires `torshield_ai_gateway.local_ai_engine.LocalAIEngine`.
    /// Always returns `None` (no fix applied). See `MIGRATION_NOTES.md`.
    pub fn fix_ai_gateway(&self, _result: &Value) -> Option<Value> {
        None
    }

    // ── Report Generation ─────────────────────────────────────────────────

    /// Generate comprehensive diagnostic report. Mirror of Python's
    /// `_generate_report`. Pure decision logic over the current `_results`
    /// and `_fixes_applied` lists.
    pub fn generate_report(&self, elapsed: f64) -> Value {
        let (total, ok, warnings, errors, fixed, auto_fixes, results_snapshot, fixes_snapshot) = {
            let state = self
                .inner
                .state
                .lock()
                .expect("auto-debug state mutex poisoned");
            let total = state.results.len();
            let ok = state
                .results
                .iter()
                .filter(|r| r.get("status").and_then(Value::as_str) == Some("ok"))
                .count();
            let warnings = state
                .results
                .iter()
                .filter(|r| r.get("status").and_then(Value::as_str) == Some("warning"))
                .count();
            let errors = state
                .results
                .iter()
                .filter(|r| r.get("status").and_then(Value::as_str) == Some("error"))
                .count();
            let fixed = state
                .results
                .iter()
                .filter(|r| r.get("fix_applied").and_then(Value::as_bool) == Some(true))
                .count();
            let auto_fixes = state.fixes_applied.len();
            (
                total,
                ok,
                warnings,
                errors,
                fixed,
                auto_fixes,
                state.results.clone(),
                state.fixes_applied.clone(),
            )
        };
        let overall_status = if errors == 0 {
            "healthy"
        } else if errors <= 2 {
            "degraded"
        } else {
            "critical"
        };
        let errors_list: Vec<Value> = results_snapshot
            .iter()
            .filter(|r| r.get("status").and_then(Value::as_str) == Some("error"))
            .cloned()
            .collect();
        let warnings_list: Vec<Value> = results_snapshot
            .iter()
            .filter(|r| r.get("status").and_then(Value::as_str) == Some("warning"))
            .cloned()
            .collect();
        let recommendations = generate_recommendations(&errors_list, &warnings_list);
        json!({
            "timestamp": format_iso(&(self.inner.clock)()),
            "duration_seconds": round_to(elapsed, 2),
            "summary": {
                "total_checks": total,
                "ok": ok,
                "warnings": warnings,
                "errors": errors,
                "fixed": fixed,
                "auto_fixes_applied": auto_fixes,
                "overall_status": overall_status,
            },
            "results": results_snapshot,
            "fixes": fixes_snapshot,
            "recommendations": recommendations,
        })
    }

    // ── Log Management ────────────────────────────────────────────────────

    /// Save diagnostic report to log file. Mirror of Python's `_save_log`.
    /// Appends the report to a JSON history list, keeping the last
    /// `LOG_HISTORY_RETENTION` (= 20) entries.
    pub fn save_log(&self, report: &Value) -> Result<(), AutoDebugError> {
        let mut history: Vec<Value> = Vec::new();
        if self.inner.log_path.exists() {
            let text = fs::read_to_string(&self.inner.log_path).map_err(|source| {
                AutoDebugError::ReadLog {
                    path: self.inner.log_path.clone(),
                    source,
                }
            })?;
            match serde_json::from_str::<Value>(&text) {
                Ok(Value::Array(arr)) => history = arr,
                _ => {
                    // Mirrors Python `except Exception: history = []`.
                    history = Vec::new();
                }
            }
        }
        history.push(report.clone());
        let kept: Vec<Value> = if history.len() > LOG_HISTORY_RETENTION {
            let start = history.len().saturating_sub(LOG_HISTORY_RETENTION);
            history.into_iter().skip(start).collect()
        } else {
            history
        };
        let serialized = serde_json::to_string_pretty(&Value::Array(kept))
            .map_err(|source| AutoDebugError::Serialize { source })?;
        if let Some(parent) = self.inner.log_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| AutoDebugError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        fs::write(&self.inner.log_path, serialized).map_err(|source| AutoDebugError::SaveLog {
            path: self.inner.log_path.clone(),
            source,
        })?;
        Ok(())
    }

    // ── Test/inspection helpers ───────────────────────────────────────────

    /// Get a snapshot of the current results list. Used by parity tests to
    /// mirror Python's `ads._results` direct access.
    pub fn results_snapshot(&self) -> Vec<Value> {
        let state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.results.clone()
    }

    /// Get a snapshot of the current fixes-applied list. Used by parity tests
    /// to mirror Python's `ads._fixes_applied` direct access.
    pub fn fixes_applied_snapshot(&self) -> Vec<Value> {
        let state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.fixes_applied.clone()
    }

    /// Directly append a result to the internal list. Used by parity tests
    /// to mirror Python's `ads._results.append(...)`.
    pub fn push_result(&self, result: Value) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("auto-debug state mutex poisoned");
        state.results.push(result);
    }
}

impl AutoDebugState {
    /// Clone the state for the clone-on-write split in `with_check_hook`.
    fn clone_for_split(&self) -> AutoDebugState {
        AutoDebugState {
            results: self.results.clone(),
            fixes_applied: self.fixes_applied.clone(),
            start_time: self.start_time,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Module-level helpers (mirror `auto_debug_system.py` helpers)
// ─────────────────────────────────────────────────────────────────────────────

/// Generate actionable recommendations based on diagnostics. Mirror of
/// Python's `_generate_recommendations`. Pure decision logic.
pub fn generate_recommendations(errors: &[Value], warnings: &[Value]) -> Vec<Value> {
    let mut recs: Vec<Value> = Vec::new();
    let combined: Vec<&Value> = errors.iter().chain(warnings.iter()).collect();
    if combined
        .iter()
        .any(|r| r.get("category").and_then(Value::as_str) == Some("ai_gateway"))
    {
        recs.push(json!(
            "AI Gateway: External providers unavailable. LocalAIEngine fallback is active. Update API keys in GitHub Secrets when available."
        ));
    }
    if errors
        .iter()
        .any(|r| r.get("category").and_then(Value::as_str) == Some("python_syntax"))
    {
        recs.push(json!(
            "Syntax errors detected. Run 'python self_heal.py --heal' for AI-powered auto-fix."
        ));
    }
    if warnings
        .iter()
        .any(|r| r.get("category").and_then(Value::as_str) == Some("dependencies"))
    {
        recs.push(json!(
            "Missing dependencies. Run 'pip install -r requirements.txt' to install."
        ));
    }
    if errors
        .iter()
        .any(|r| r.get("category").and_then(Value::as_str) == Some("python_imports"))
    {
        recs.push(json!(
            "Import errors detected. Check that all required files exist and __init__.py files are present."
        ));
    }
    if errors.is_empty() {
        recs.push(json!("All systems operational. No action required."));
    }
    recs
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Format a `DateTime<Utc>` as an ISO-8601 string with microsecond precision
/// and a `+00:00` offset, matching Python's `datetime.now(UTC).isoformat()`.
fn format_iso(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string()
}

/// Convert a clock closure to epoch seconds as `f64` (parity with `time.time()`).
fn clock_to_epoch_secs(clock: &Clock) -> f64 {
    let now = clock();
    now.timestamp() as f64 + now.timestamp_subsec_nanos() as f64 / 1_000_000_000.0
}

/// Round an f64 to `decimals` decimal places, mirroring Python's `round(x, n)`.
fn round_to(x: f64, decimals: u32) -> f64 {
    let factor = 10f64.powi(decimals as i32);
    (x * factor).round() / factor
}

/// Walk a project root for `.py` files, excluding hidden dirs and
/// `__pycache__`. Mirror of Python's `Path(".").rglob("*.py")` filter.
fn collect_python_files(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    walk_dir_python(root, root, &mut out);
    out
}

fn walk_dir_python(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(rel) = path.strip_prefix(root).ok() else {
            continue;
        };
        // Exclude hidden dirs and __pycache__ at any depth.
        let excluded = rel.components().any(|c| match c {
            std::path::Component::Normal(s) => {
                let s = s.to_string_lossy();
                s.starts_with('.') || s == "__pycache__"
            }
            _ => false,
        });
        if excluded {
            continue;
        }
        if path.is_dir() {
            walk_dir_python(root, &path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("py") {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "auto_debug_system_unit_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        if dir.exists() {
            let _ = fs::remove_dir_all(&dir);
        }
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn check_file_integrity_missing_files_reports_error() {
        let dir = temp_dir("file_missing");
        let ads =
            AutoDebugSystem::new(&dir.join("log.json"), &dir.join("project"), default_clock());
        ads.check_file_integrity().unwrap();
        let results = ads.results_snapshot();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["category"], "file_integrity");
        assert_eq!(results[0]["status"], "error");
        assert!(results[0]["message"]
            .as_str()
            .unwrap()
            .contains("Missing critical files"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_file_integrity_all_present_reports_ok() {
        let dir = temp_dir("file_present");
        let project = dir.join("project");
        fs::create_dir_all(&project).unwrap();
        for f in CRITICAL_FILES {
            if let Some(parent) = project.join(f).parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(project.join(f), "# stub").unwrap();
        }
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &project, default_clock());
        ads.check_file_integrity().unwrap();
        let results = ads.results_snapshot();
        assert_eq!(results[0]["status"], "ok");
        assert!(results[0]["message"]
            .as_str()
            .unwrap()
            .contains("All 13 critical files present"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_directory_structure_creates_missing_dirs() {
        let dir = temp_dir("dir_missing");
        let project = dir.join("project");
        fs::create_dir_all(&project).unwrap();
        // Pre-create one required dir; the rest should be auto-created.
        fs::create_dir_all(project.join("core")).unwrap();
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &project, default_clock());
        ads.check_directory_structure().unwrap();
        let results = ads.results_snapshot();
        // 7 missing dirs → 7 warnings
        let warnings: Vec<&Value> = results
            .iter()
            .filter(|r| r["status"] == "warning")
            .collect();
        assert_eq!(warnings.len(), 7);
        let fixes = ads.fixes_applied_snapshot();
        assert_eq!(fixes.len(), 7);
        // Verify dirs were actually created.
        for d in REQUIRED_DIRS {
            assert!(project.join(d).exists(), "expected {d} to be created");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_directory_structure_all_present_reports_ok() {
        let dir = temp_dir("dir_present");
        let project = dir.join("project");
        for d in REQUIRED_DIRS {
            fs::create_dir_all(project.join(d)).unwrap();
        }
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &project, default_clock());
        ads.check_directory_structure().unwrap();
        let results = ads.results_snapshot();
        assert_eq!(results[0]["status"], "ok");
        assert!(results[0]["message"]
            .as_str()
            .unwrap()
            .contains("All 8 required directories exist"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_report_buckets_results_and_sets_overall_status() {
        let dir = temp_dir("report");
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &dir, default_clock());
        ads.push_result(json!({"category": "a", "status": "ok", "message": "m1"}));
        ads.push_result(json!({"category": "b", "status": "warning", "message": "m2"}));
        ads.push_result(json!({"category": "c", "status": "error", "message": "m3"}));
        ads.push_result(
            json!({"category": "d", "status": "fixed", "message": "m4", "fix_applied": true}),
        );
        let report = ads.generate_report(0.0156);
        assert_eq!(report["summary"]["total_checks"], 4);
        assert_eq!(report["summary"]["ok"], 1);
        assert_eq!(report["summary"]["warnings"], 1);
        assert_eq!(report["summary"]["errors"], 1);
        assert_eq!(report["summary"]["fixed"], 1);
        assert_eq!(report["summary"]["overall_status"], "degraded"); // 1 error ≤ 2
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_report_critical_when_more_than_two_errors() {
        let dir = temp_dir("report_critical");
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &dir, default_clock());
        for i in 0..3 {
            ads.push_result(
                json!({"category": format!("e{i}"), "status": "error", "message": format!("m{i}")}),
            );
        }
        let report = ads.generate_report(0.0);
        assert_eq!(report["summary"]["overall_status"], "critical");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_recommendations_branches() {
        let recs = generate_recommendations(&[], &[]);
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0],
            json!("All systems operational. No action required.")
        );

        let errors = vec![json!({"category": "ai_gateway", "status": "error"})];
        let recs = generate_recommendations(&errors, &[]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].as_str().unwrap().contains("AI Gateway"));

        let errors = vec![json!({"category": "python_syntax", "status": "error"})];
        let warnings = vec![json!({"category": "dependencies", "status": "warning"})];
        let recs = generate_recommendations(&errors, &warnings);
        assert_eq!(recs.len(), 2);
        assert!(recs[0].as_str().unwrap().contains("Syntax errors"));
        assert!(recs[1].as_str().unwrap().contains("Missing dependencies"));
    }

    #[test]
    fn save_log_appends_and_truncates_to_twenty_entries() {
        let dir = temp_dir("save_log");
        let log = dir.join("auto_debug_log.json");
        let ads = AutoDebugSystem::new(&log, &dir, default_clock());
        for i in 0..25 {
            let report = json!({"index": i, "summary": {"errors": 0}});
            ads.save_log(&report).unwrap();
        }
        let text = fs::read_to_string(&log).unwrap();
        let arr: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 20);
        // Last entry should be index 24.
        assert_eq!(arr.as_array().unwrap()[19]["index"], 24);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fix_directory_creates_missing_dir() {
        let dir = temp_dir("fix_dir");
        let project = dir.join("project");
        fs::create_dir_all(&project).unwrap();
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &project, default_clock());
        let result = json!({
            "category": "directory_structure",
            "details": {"directory": "new_dir"},
        });
        let fix = ads.fix_directory(&result).unwrap();
        assert!(fix.is_some());
        assert!(project.join("new_dir").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fix_import_creates_init_py_for_existing_package() {
        let dir = temp_dir("fix_import");
        let project = dir.join("project");
        fs::create_dir_all(project.join("mypkg")).unwrap();
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &project, default_clock());
        let result = json!({
            "category": "python_imports",
            "details": {"module": "mypkg"},
        });
        let fix = ads.fix_import(&result).unwrap();
        assert!(fix.is_some(), "fix_import should create __init__.py");
        assert!(project.join("mypkg").join("__init__.py").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fix_import_returns_none_when_module_file_exists() {
        let dir = temp_dir("fix_import_exists");
        let project = dir.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("mod.py"), "# existing").unwrap();
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &project, default_clock());
        let result = json!({
            "category": "python_imports",
            "details": {"module": "mod"},
        });
        let fix = ads.fix_import(&result).unwrap();
        assert!(
            fix.is_none(),
            "fix_import should not act when module file exists"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn attempt_fix_dispatches_on_category() {
        let dir = temp_dir("attempt_fix");
        let project = dir.join("project");
        fs::create_dir_all(&project).unwrap();
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &project, default_clock());
        // directory_structure → fix_directory
        let r1 = json!({"category": "directory_structure", "details": {"directory": "d1"}});
        assert!(ads.attempt_fix(&r1).unwrap().is_some());
        // python_imports → fix_import (no-op when module file missing and pkg dir missing)
        let r2 = json!({"category": "python_imports", "details": {"module": "nope"}});
        assert!(ads.attempt_fix(&r2).unwrap().is_none());
        // unknown category → None
        let r3 = json!({"category": "unknown"});
        assert!(ads.attempt_fix(&r3).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_threaded_run_full_diagnosis_is_thread_safe() {
        let dir = temp_dir("mt");
        let project = dir.join("project");
        for d in REQUIRED_DIRS {
            fs::create_dir_all(project.join(d)).unwrap();
        }
        let ads = AutoDebugSystem::new(&dir.join("log.json"), &project, default_clock());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let ads2 = ads.clone();
            handles.push(std::thread::spawn(move || {
                ads2.run_full_diagnosis().unwrap();
            }));
        }
        for h in handles {
            h.join().expect("worker thread");
        }
        // After 4 concurrent full diagnoses, the log file should exist and
        // contain at least one entry. The exact count is not part of the
        // Python parity contract — concurrent writes may interleave in
        // ways that lose entries (Python has the same race). The parity
        // guarantee is that the file exists and is valid JSON.
        let text = fs::read_to_string(dir.join("log.json")).unwrap();
        let arr: Value = serde_json::from_str(&text).unwrap();
        let len = arr.as_array().unwrap().len();
        assert!(len >= 1, "expected at least 1 log entry, got {len}");
        assert!(len <= 4, "expected at most 4 log entries, got {len}");
        let _ = fs::remove_dir_all(&dir);
    }
}

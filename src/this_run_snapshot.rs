//! This-run observation snapshot helpers.
//!
//! Live collection writes `bridge/` and `data/pt_results.json` as a side
//! effect of Stages 0–4. Pull-request / non-main validation no-ops those
//! stages, which previously left the files missing (analytics `exit 1`) or
//! reused a *prior* `data/pt_results.json` as if it belonged to this run
//! (FUNNEL `relay_attempted=1819` with `testing_candidates=0`).
//!
//! A validation no-op therefore materializes **valid empty** schemas — zero
//! bridges, not fabricated rows — and stamps `data/collection_mode.json` so
//! the funnel can refuse to treat leftover committed observation files as
//! this-run measurements.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::{json, Value};

/// Path of the this-run collection-mode stamp.
pub const COLLECTION_MODE_PATH: &str = "data/collection_mode.json";

/// Empty but schema-valid `bridge/iran_results.json`.
pub const EMPTY_IRAN_RESULTS: &str = "{\n  \"bridges\": [],\n  \"summary\": {\n    \"count\": 0\n  }\n}\n";

/// Empty but schema-valid `bridge/bridge_history.json` (JSON object).
pub const EMPTY_BRIDGE_HISTORY: &str = "{}\n";

/// Empty but schema-valid `bridge/bridge_list_for_testing.json`.
pub const EMPTY_TESTING_LIST: &str = "[]\n";

/// Empty but schema-valid `data/pt_results.json` (this-run relay outcomes).
pub const EMPTY_PT_RESULTS: &str = "[]\n";

/// How this workflow run produced (or did not produce) live observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionMode {
    /// Default-branch live collect/deploy path.
    Live,
    /// Non-main / pull_request validation: no live collect, Worker, or Telegram.
    ValidationNoop,
}

impl CollectionMode {
    /// `true` when this run performed live collection.
    #[must_use]
    pub fn live_collection(self) -> bool {
        matches!(self, Self::Live)
    }

    /// Stable wire name stored in `collection_mode.json`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::ValidationNoop => "validation_noop",
        }
    }
}

/// Parse `data/collection_mode.json`. Missing/invalid stamps default to
/// `live` so historical main-branch checkouts without the file keep using
/// on-disk observation files as this-run evidence.
#[must_use]
pub fn read_collection_mode(repo_root: &Path) -> CollectionMode {
    let path = repo_root.join(COLLECTION_MODE_PATH);
    let Ok(text) = fs::read_to_string(&path) else {
        return CollectionMode::Live;
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return CollectionMode::Live;
    };
    match value.get("mode").and_then(Value::as_str) {
        Some("validation_noop") => CollectionMode::ValidationNoop,
        Some("live") => CollectionMode::Live,
        _ => {
            if value.get("live_collection").and_then(Value::as_bool) == Some(false) {
                CollectionMode::ValidationNoop
            } else {
                CollectionMode::Live
            }
        }
    }
}

/// Atomically replace `path` with `contents` (temp file in the same directory
/// + rename). Never leaves a truncated destination on a failed write.
pub fn atomic_write(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = path.with_file_name(format!(".{}.tmp", file_name.to_string_lossy()));
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn mode_document(mode: CollectionMode, reason: &str) -> String {
    let value = json!({
        "live_collection": mode.live_collection(),
        "mode": mode.as_str(),
        "reason": reason,
    });
    let mut body = serde_json::to_string_pretty(&value).expect("collection_mode json");
    body.push('\n');
    body
}

/// Write the collection-mode stamp. Live mode does **not** wipe observation
/// files — later stages own those paths.
pub fn write_collection_mode(
    repo_root: &Path,
    mode: CollectionMode,
    reason: &str,
) -> io::Result<()> {
    atomic_write(
        &repo_root.join(COLLECTION_MODE_PATH),
        &mode_document(mode, reason),
    )
}

/// Materialize valid empty this-run observation files for a validation no-op.
///
/// Existing committed `data/pt_results.json` from a prior live run is replaced
/// with `[]` so it cannot be counted as this run's relay funnel.
pub fn write_validation_noop_snapshot(repo_root: &Path, reason: &str) -> io::Result<()> {
    fs::create_dir_all(repo_root.join("bridge"))?;
    fs::create_dir_all(repo_root.join("data"))?;
    atomic_write(
        &repo_root.join("bridge/iran_results.json"),
        EMPTY_IRAN_RESULTS,
    )?;
    atomic_write(
        &repo_root.join("bridge/bridge_history.json"),
        EMPTY_BRIDGE_HISTORY,
    )?;
    atomic_write(
        &repo_root.join("bridge/bridge_list_for_testing.json"),
        EMPTY_TESTING_LIST,
    )?;
    atomic_write(&repo_root.join("data/pt_results.json"), EMPTY_PT_RESULTS)?;
    write_collection_mode(repo_root, CollectionMode::ValidationNoop, reason)?;
    Ok(())
}

/// Apply `mode` under `repo_root`.
pub fn apply(repo_root: &Path, mode: CollectionMode, reason: &str) -> io::Result<()> {
    match mode {
        CollectionMode::ValidationNoop => write_validation_noop_snapshot(repo_root, reason),
        CollectionMode::Live => write_collection_mode(repo_root, mode, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "this_run_snapshot_{}_{}",
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validation_noop_writes_parseable_empty_schemas_and_replaces_stale_pt_results() {
        let root = temp_root();
        fs::create_dir_all(root.join("data")).unwrap();
        fs::write(
            root.join("data/pt_results.json"),
            r#"[{"host":"1.2.3.4","port":443,"success":true}]"#,
        )
        .unwrap();

        apply(
            &root,
            CollectionMode::ValidationNoop,
            "not the default branch",
        )
        .unwrap();

        let iran: Value = serde_json::from_str(
            &fs::read_to_string(root.join("bridge/iran_results.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(iran["bridges"].as_array().unwrap().len(), 0);
        assert_eq!(iran["summary"]["count"], 0);

        let history: Value = serde_json::from_str(
            &fs::read_to_string(root.join("bridge/bridge_history.json")).unwrap(),
        )
        .unwrap();
        assert!(history.as_object().unwrap().is_empty());

        let testing: Value = serde_json::from_str(
            &fs::read_to_string(root.join("bridge/bridge_list_for_testing.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(testing.as_array().unwrap().len(), 0);

        let pt: Value = serde_json::from_str(
            &fs::read_to_string(root.join("data/pt_results.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(pt.as_array().unwrap().len(), 0);

        assert_eq!(read_collection_mode(&root), CollectionMode::ValidationNoop);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn live_mode_stamps_without_wiping_existing_observations() {
        let root = temp_root();
        fs::create_dir_all(root.join("data")).unwrap();
        fs::write(root.join("data/pt_results.json"), "[1]\n").unwrap();
        apply(&root, CollectionMode::Live, "main-branch live collection").unwrap();
        assert_eq!(read_collection_mode(&root), CollectionMode::Live);
        assert_eq!(
            fs::read_to_string(root.join("data/pt_results.json")).unwrap(),
            "[1]\n"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_stamp_defaults_to_live() {
        let root = temp_root();
        assert_eq!(read_collection_mode(&root), CollectionMode::Live);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn atomic_write_replaces_destination() {
        let root = temp_root();
        let path = root.join("out.json");
        atomic_write(&path, "first\n").unwrap();
        atomic_write(&path, "second\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second\n");
        let _ = fs::remove_dir_all(&root);
    }
}

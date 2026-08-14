//! Atomic file writes: write to a same-directory temp file, sync, then rename.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::PublishError;

/// Monotonic counter used to make temp-file names unique within a process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `bytes` to `path` atomically.
///
/// The bytes are written to a unique temp file in the same directory, synced
/// to disk, and renamed over `path`. A crash or failure therefore never
/// leaves a partially written file at `path`; on error the temp file is
/// removed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PublishError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| PublishError::InvalidEntryName {
            name: path.display().to_string(),
            reason: "path has no file name",
        })?;

    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let dir = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    let temp = temp_path(dir, file_name);

    let write_result = write_bytes_to_temp(&temp, bytes);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }

    std::fs::rename(&temp, path).map_err(|source| {
        let _ = std::fs::remove_file(&temp);
        PublishError::io("rename_temp_file", source)
    })
}

/// Write bytes to a newly created temp file and sync them to disk.
fn write_bytes_to_temp(temp: &Path, bytes: &[u8]) -> Result<(), PublishError> {
    let mut file = std::fs::File::create(temp)
        .map_err(|source| PublishError::io("create_temp_file", source))?;
    file.write_all(bytes)
        .map_err(|source| PublishError::io("write_temp_file", source))?;
    file.sync_all()
        .map_err(|source| PublishError::io("sync_temp_file", source))?;
    Ok(())
}

/// A unique temp-file path for `file_name` inside `dir`.
fn temp_path(dir: &Path, file_name: &str) -> PathBuf {
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn scratch_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "tbc-publish-atomic-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn write_atomic_creates_and_replaces() {
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.txt");

        write_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_atomic_fails_cleanly_on_a_directory_target() {
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        // Writing over an existing directory fails at the rename step with a
        // typed I/O error; the target directory is left untouched and the temp
        // file is cleaned up.
        let error = write_atomic(&dir, b"bytes").unwrap_err();
        assert!(matches!(error, PublishError::Io { .. }));
        assert!(dir.is_dir());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

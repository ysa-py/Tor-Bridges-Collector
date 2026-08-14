//! Task orchestration: `ci`, `build`, `release`, and checksums.
//!
//! `ci`, `build`, and `release` run cargo through the injected [`Runner`] and
//! classify non-zero exits as [`XtaskError::CommandFailed`] (with argv, status,
//! and stderr). Checksums are pure file I/O over an artifact directory.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::XtaskError;
use crate::runner::{CommandOutput, CommandSpec, Runner};

/// What [`run_release`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseReport {
    /// Number of files checksummed.
    pub files: usize,
}

/// The workspace gate commands, in execution order.
pub fn ci_commands() -> Vec<CommandSpec> {
    vec![
        CommandSpec::cargo(&["fmt", "--all", "--", "--check"]),
        CommandSpec::cargo(&[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ]),
        CommandSpec::cargo(&["test", "--all-features"]),
    ]
}

/// The workspace debug-build command.
pub fn build_command() -> CommandSpec {
    CommandSpec::cargo(&["build", "--workspace"])
}

/// The workspace release-build command.
pub fn release_command() -> CommandSpec {
    CommandSpec::cargo(&["build", "--release", "--workspace"])
}

/// Run the workspace gate: fail fast on the first non-zero command.
pub fn run_ci(runner: &dyn Runner) -> Result<(), XtaskError> {
    for command in ci_commands() {
        run_ok(runner, &command)?;
    }
    Ok(())
}

/// Build the workspace in debug mode.
pub fn run_build(runner: &dyn Runner) -> Result<(), XtaskError> {
    run_ok(runner, &build_command())?;
    Ok(())
}

/// Build the workspace in release mode, then checksum the artifact directory
/// and write a `SHA256SUMS` manifest into it.
pub fn run_release(runner: &dyn Runner, out: &Path) -> Result<ReleaseReport, XtaskError> {
    run_ok(runner, &release_command())?;
    let sums = checksums(out)?;
    write_checksums(out, &sums)?;
    Ok(ReleaseReport { files: sums.len() })
}

/// Execute `command`, treating a non-zero exit as a typed failure.
fn run_ok(runner: &dyn Runner, command: &CommandSpec) -> Result<CommandOutput, XtaskError> {
    let output = runner.run(command)?;
    if output.status != 0 {
        return Err(XtaskError::CommandFailed {
            program: command.program.clone(),
            args: command.args.join(" "),
            status: output.status,
            stderr: output.stderr.clone(),
        });
    }
    Ok(output)
}

/// Compute a deterministic `file name → SHA-256 hex` map over every regular
/// file directly inside `dir` (non-recursive), ordered by file name.
pub fn checksums(dir: &Path) -> Result<BTreeMap<String, String>, XtaskError> {
    let mut names: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|source| XtaskError::io(format!("read dir {}", dir.display()), source))?;
    for entry in entries {
        let entry = entry.map_err(|source| XtaskError::io("read dir entry", source))?;
        let is_file = match entry.file_type() {
            Ok(file_type) => file_type.is_file(),
            Err(_) => false,
        };
        if is_file {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    if names.is_empty() {
        return Err(XtaskError::EmptyChecksum {
            dir: dir.to_path_buf(),
        });
    }
    names.sort();
    let mut sums = BTreeMap::new();
    for name in names {
        let path = dir.join(&name);
        let bytes = std::fs::read(&path)
            .map_err(|source| XtaskError::io(format!("read {name}"), source))?;
        sums.insert(name, tbc_publish::sha256_hex(&bytes));
    }
    Ok(sums)
}

/// Write a `sha256sum`-compatible manifest (`<digest>  <name>` per line).
pub fn write_checksums(dir: &Path, sums: &BTreeMap<String, String>) -> Result<(), XtaskError> {
    let mut text = String::new();
    for (name, digest) in sums {
        text.push_str(digest);
        text.push_str("  ");
        text.push_str(name);
        text.push('\n');
    }
    std::fs::write(dir.join("SHA256SUMS"), text)
        .map_err(|source| XtaskError::io("write SHA256SUMS", source))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// An in-memory [`Runner`] that records commands and returns a scripted
    /// status for every command (defaulting to success).
    #[derive(Default)]
    struct RecordingRunner {
        commands: RefCell<Vec<CommandSpec>>,
        status: i32,
    }

    impl RecordingRunner {
        fn failing() -> Self {
            Self {
                commands: RefCell::new(Vec::new()),
                status: 1,
            }
        }
    }

    impl Runner for RecordingRunner {
        fn run(&self, command: &CommandSpec) -> Result<CommandOutput, XtaskError> {
            self.commands.borrow_mut().push(command.clone());
            Ok(CommandOutput {
                status: self.status,
                stdout: String::new(),
                stderr: if self.status == 0 {
                    String::new()
                } else {
                    "simulated failure".to_owned()
                },
            })
        }
    }

    #[test]
    fn ci_commands_are_the_three_gate_steps() {
        let commands = ci_commands();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0].display(), "cargo fmt --all -- --check");
        assert_eq!(
            commands[1].display(),
            "cargo clippy --all-targets --all-features -- -D warnings"
        );
        assert_eq!(commands[2].display(), "cargo test --all-features");
    }

    #[test]
    fn build_and_release_commands_are_well_formed() {
        assert_eq!(build_command().display(), "cargo build --workspace");
        assert_eq!(
            release_command().display(),
            "cargo build --release --workspace"
        );
    }

    #[test]
    fn ci_succeeds_and_runs_every_command() {
        let runner = RecordingRunner::default();
        run_ci(&runner).unwrap();
        assert_eq!(runner.commands.borrow().len(), 3);
    }

    #[test]
    fn ci_fails_on_first_nonzero_command() {
        let runner = RecordingRunner::failing();
        let error = run_ci(&runner).unwrap_err();
        assert!(matches!(error, XtaskError::CommandFailed { .. }));
        assert_eq!(
            runner.commands.borrow().len(),
            1,
            "fail-fast stops after the first failure"
        );
    }

    #[test]
    fn checksums_hashes_files_and_rejects_empty_dir() {
        let dir = std::env::temp_dir().join(format!("xtask-sums-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.txt"), b"abc").unwrap();
        std::fs::write(dir.join("a.txt"), b"").unwrap();

        let sums = checksums(&dir).unwrap();
        let keys: Vec<&String> = sums.keys().collect();
        assert_eq!(keys, vec!["a.txt", "b.txt"]);
        assert_eq!(
            sums["b.txt"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sums["a.txt"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        write_checksums(&dir, &sums).unwrap();
        let manifest = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        assert_eq!(
            manifest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  a.txt\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  b.txt\n"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checksums_rejects_an_empty_directory() {
        let dir = std::env::temp_dir().join(format!("xtask-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let error = checksums(&dir).unwrap_err();
        assert!(matches!(error, XtaskError::EmptyChecksum { .. }));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

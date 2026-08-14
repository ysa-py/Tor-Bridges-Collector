//! End-to-end integration tests for the `xtask` tool.
//!
//! `schema-gen` and checksums are pure file I/O, so these tests run them for
//! real against scratch directories. `ci`/`build`/`release` are exercised at
//! the command-construction boundary with an in-memory runner (their live
//! execution is the actual `cargo` invocation, which the tests intentionally
//! do not perform).

use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use xtask::{
    dispatch, parse_args, run_release, write_schemas, CommandOutput, CommandSpec, Runner, Task,
    XtaskError,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("xtask-{}-{}-{tag}", std::process::id(), n));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[derive(Default)]
struct RecordingRunner {
    commands: RefCell<Vec<CommandSpec>>,
    status: i32,
}

impl Runner for RecordingRunner {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, XtaskError> {
        self.commands.borrow_mut().push(command.clone());
        Ok(CommandOutput {
            status: self.status,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

fn dispatch_to_string(task: &Task, runner: &dyn Runner) -> String {
    let mut out = Vec::new();
    dispatch(task, runner, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn schema_gen_writes_real_versioned_documents() {
    let dir = scratch_dir("schema");
    let task = Task::SchemaGen { out: dir.clone() };
    let report = dispatch_to_string(&task, &RecordingRunner::default());
    assert!(report.contains("wrote 3 schema(s)"));

    for name in [
        "bridge_line.schema.json",
        "observation.schema.json",
        "bridge_score.schema.json",
    ] {
        let path = dir.join(name);
        assert!(path.exists(), "{name} should exist");
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["type"], "object");
        assert_eq!(value["x-schema-version"], 1);
    }

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn release_builds_and_checksums_via_runner() {
    let dir = scratch_dir("release");
    fs::write(dir.join("tbc"), b"release-binary-bytes").unwrap();

    let runner = RecordingRunner::default();
    let report = run_release(&runner, &dir).unwrap();
    assert_eq!(report.files, 1);

    let commands = runner.commands.borrow();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].display(), "cargo build --release --workspace");

    let manifest = fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    let expected = "363ad27b3593aa13227b5d0cd20cafefe2663c12586d2769c688f5fb45aba48c  tbc\n";
    assert_eq!(manifest, expected);

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn ci_dispatch_runs_all_three_commands() {
    let runner = RecordingRunner::default();
    let report = dispatch_to_string(&Task::Ci, &runner);
    assert_eq!(report, "ci: all commands passed\n");
    assert_eq!(runner.commands.borrow().len(), 3);
}

#[test]
fn help_and_parse_round_trip() {
    let report = dispatch_to_string(&Task::Help, &RecordingRunner::default());
    assert!(report.contains("schema-gen"));
    assert!(report.contains("release"));

    assert_eq!(parse_args(&[]).unwrap(), Task::Help);
    assert_eq!(parse_args(&["ci".to_owned()]).unwrap(), Task::Ci);
}

#[test]
fn release_fails_cleanly_on_empty_artifact_dir() {
    let dir = scratch_dir("release-empty");
    let error = run_release(&RecordingRunner::default(), &dir).unwrap_err();
    assert_eq!(error.kind_name(), "empty_checksum");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn write_schemas_into_custom_directory() {
    let dir = scratch_dir("custom");
    let count = write_schemas(&dir).unwrap();
    assert_eq!(count, 3);
    assert!(dir.join("observation.schema.json").exists());
    fs::remove_dir_all(&dir).unwrap();
}

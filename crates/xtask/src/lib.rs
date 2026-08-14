//! `xtask` — build/release/schema-gen automation (crate 11 of the master
//! spec).
//!
//! This crate is the workspace's build/release tool, reachable as `cargo
//! xtask` (see the `[alias]` in the workspace root). It owns three real tasks:
//!
//! | Task | Responsibility |
//! |---|---|
//! | `schema-gen` | Write versioned JSON Schema documents for the published model types to `schemas/`. |
//! | `ci` | Run the workspace gate: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`. |
//! | `build` / `release` | Build the workspace; `release` additionally writes a deterministic `SHA256SUMS` manifest over the artifact directory. |
//!
//! Command execution is abstracted behind [`Runner`] so the task logic (which
//! commands are run, in which order, and how their exit codes are classified)
//! is unit-tested with an in-memory recorder, while the production
//! [`ProcessRunner`] executes them for real. Schema generation and checksums
//! are pure file I/O and are tested against scratch directories.
//!
//! Production code contains no `unwrap()`, `expect()`, or `panic!`; the deny
//! attributes below turn any of those into a hard `cargo clippy` error. Test
//! modules re-allow them explicitly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;

pub mod args;
pub mod error;
pub mod runner;
pub mod schema;
pub mod task;

pub use args::{parse_args, usage, Task};
pub use error::XtaskError;
pub use runner::{CommandOutput, CommandSpec, ProcessRunner, Runner};
pub use schema::{
    generate_schemas, write_schemas, BRIDGE_LINE_SCHEMA, BRIDGE_SCORE_SCHEMA, OBSERVATION_SCHEMA,
};
pub use task::{
    build_command, checksums, ci_commands, release_command, run_build, run_ci, run_release,
    write_checksums, ReleaseReport,
};

/// Dispatch a parsed [`Task`], writing human-readable progress to `out`.
pub fn dispatch(
    task: &Task,
    runner: &dyn Runner,
    writer: &mut dyn Write,
) -> Result<(), XtaskError> {
    match task {
        Task::Help => {
            let text = args::usage();
            writer
                .write_all(text.as_bytes())
                .map_err(|source| XtaskError::io("write_output", source))
        }
        Task::SchemaGen { out } => {
            let count = write_schemas(out)?;
            write_line(
                writer,
                format!("schema-gen: wrote {count} schema(s) -> {}", out.display()),
            )
        }
        Task::Ci => {
            run_ci(runner)?;
            write_line(writer, "ci: all commands passed".to_owned())
        }
        Task::Build => {
            run_build(runner)?;
            write_line(writer, "build: workspace built".to_owned())
        }
        Task::Release { out } => {
            let report = run_release(runner, out)?;
            write_line(
                writer,
                format!(
                    "release: built workspace and checksummed {} file(s) -> {}",
                    report.files,
                    out.display()
                ),
            )
        }
    }
}

fn write_line(out: &mut dyn Write, line: String) -> Result<(), XtaskError> {
    out.write_all(line.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .map_err(|source| XtaskError::io("write_output", source))
}

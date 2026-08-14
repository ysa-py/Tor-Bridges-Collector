//! Command execution abstraction.
//!
//! Tasks run commands through [`Runner`] so the task logic (which commands
//! are run, in which order, and how exit codes are classified) can be tested
//! with an in-memory recorder, while [`ProcessRunner`] executes them for real.

use crate::error::XtaskError;

/// A single command to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    /// The program to spawn.
    pub program: String,
    /// The arguments, in order.
    pub args: Vec<String>,
}

impl CommandSpec {
    /// Build a `cargo` invocation with the given arguments.
    pub fn cargo(args: &[&str]) -> Self {
        Self {
            program: "cargo".to_owned(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
        }
    }

    /// A human-readable rendering for logs and error messages.
    pub fn display(&self) -> String {
        let mut text = self.program.clone();
        for arg in &self.args {
            text.push(' ');
            text.push_str(arg);
        }
        text
    }
}

/// The captured outcome of a command execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Process exit status (`-1` when terminated by a signal with no code).
    pub status: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

/// Executes a [`CommandSpec`], returning its captured output.
///
/// Implementations never panic on a non-zero exit: the exit status is part of
/// [`CommandOutput`] and the caller decides the policy.
pub trait Runner {
    /// Run `command` and capture its output.
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, XtaskError>;
}

/// The production [`Runner`] backed by [`std::process::Command`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessRunner;

impl Runner for ProcessRunner {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, XtaskError> {
        let output = std::process::Command::new(&command.program)
            .args(&command.args)
            .output()
            .map_err(|source| XtaskError::io(format!("spawn {}", command.program), source))?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cargo_spec_builds_correct_argv() {
        let spec = CommandSpec::cargo(&["build", "--workspace"]);
        assert_eq!(spec.program, "cargo");
        assert_eq!(
            spec.args,
            vec!["build".to_owned(), "--workspace".to_owned()]
        );
        assert_eq!(spec.display(), "cargo build --workspace");
    }

    #[test]
    fn process_runner_executes_successful_command() {
        let runner = ProcessRunner;
        let output = runner
            .run(&CommandSpec {
                program: "true".to_owned(),
                args: Vec::new(),
            })
            .unwrap();
        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, "");
    }

    #[test]
    fn process_runner_reports_nonzero_status_without_panicking() {
        let runner = ProcessRunner;
        let output = runner
            .run(&CommandSpec {
                program: "false".to_owned(),
                args: Vec::new(),
            })
            .unwrap();
        assert_eq!(output.status, 1);
    }
}

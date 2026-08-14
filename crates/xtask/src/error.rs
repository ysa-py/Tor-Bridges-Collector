//! Typed error taxonomy for the `xtask` automation crate.
//!
//! Every fallible operation returns an [`XtaskError`]: argument parsing
//! failures, file I/O, and command execution failures (with the program,
//! argv, exit status, and captured stderr). The binary maps each variant to a
//! documented process exit code.

use std::path::PathBuf;

use thiserror::Error;

/// All failure modes of the `xtask` command-line tool.
#[derive(Debug, Error)]
pub enum XtaskError {
    /// The first argument is not a known task.
    #[error("unknown task {name:?} (run `xtask help` for usage)")]
    UnknownTask { name: String },

    /// A flag was supplied that the task does not accept.
    #[error("unknown flag {flag:?}")]
    UnknownFlag { flag: String },

    /// A flag was given without the value it requires.
    #[error("flag {flag:?} requires a value")]
    MissingValue { flag: String },

    /// A required flag was omitted.
    #[error("flag {flag:?} is required for this task")]
    MissingRequiredFlag { flag: String },

    /// The same flag was supplied more than once.
    #[error("flag {flag:?} was supplied more than once")]
    DuplicateFlag { flag: String },

    /// A flag's value did not parse or validate.
    #[error("invalid value {value:?} for flag {flag:?}: {reason}")]
    InvalidValue {
        flag: String,
        value: String,
        reason: String,
    },

    /// A positional argument appeared where none was expected.
    #[error("unexpected argument {arg:?}")]
    UnexpectedArgument { arg: String },

    /// A file read or write failed.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// A spawned command exited non-zero.
    #[error("command `{program} {args}` failed with status {status}: {stderr}")]
    CommandFailed {
        program: String,
        args: String,
        status: i32,
        stderr: String,
    },

    /// Invalid JSON input or output.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// A checksum task found nothing to hash.
    #[error("no files to checksum in {dir}")]
    EmptyChecksum { dir: PathBuf },
}

impl XtaskError {
    /// Construct an I/O error with the operation that failed as context.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// A stable, metric-safe classifier for observability.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::UnknownTask { .. }
            | Self::UnknownFlag { .. }
            | Self::MissingValue { .. }
            | Self::MissingRequiredFlag { .. }
            | Self::DuplicateFlag { .. }
            | Self::InvalidValue { .. }
            | Self::UnexpectedArgument { .. } => "usage_error",
            Self::Io { .. } => "io_error",
            Self::CommandFailed { .. } => "command_failed",
            Self::Json(_) => "json_error",
            Self::EmptyChecksum { .. } => "empty_checksum",
        }
    }

    /// Process exit code: usage errors are `2`, runtime errors are `1`.
    pub fn exit_code(&self) -> i32 {
        if self.kind_name() == "usage_error" {
            2
        } else {
            1
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_classify_usage_vs_runtime() {
        assert_eq!(
            XtaskError::UnknownTask {
                name: "bogus".to_owned()
            }
            .exit_code(),
            2
        );
        assert_eq!(
            XtaskError::EmptyChecksum {
                dir: PathBuf::from("x")
            }
            .exit_code(),
            1
        );
        assert_eq!(
            XtaskError::io(
                "read",
                std::io::Error::new(std::io::ErrorKind::NotFound, "gone")
            )
            .exit_code(),
            1
        );
    }

    #[test]
    fn kind_names_are_stable() {
        assert_eq!(
            XtaskError::MissingValue {
                flag: "--x".to_owned()
            }
            .kind_name(),
            "usage_error"
        );
        assert_eq!(
            XtaskError::CommandFailed {
                program: "cargo".to_owned(),
                args: String::new(),
                status: 1,
                stderr: String::new(),
            }
            .kind_name(),
            "command_failed"
        );
    }
}

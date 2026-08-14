//! Typed error taxonomy for the `tbc` CLI.
//!
//! Every fallible operation in this crate returns a [`CliError`]: argument
//! parsing failures, configuration failures, file I/O, and (transitively) the
//! typed errors of the pipeline crates the CLI dispatches to. The binary maps
//! each variant to a documented process exit code, so no failure is silent.

use thiserror::Error;

/// All failure modes of the `tbc` command-line interface.
#[derive(Debug, Error)]
pub enum CliError {
    /// The first argument is not a known subcommand.
    #[error("unknown subcommand {name:?} (run `tbc help` for usage)")]
    UnknownSubcommand { name: String },

    /// A flag was supplied that the subcommand does not accept.
    #[error("unknown flag {flag:?}")]
    UnknownFlag { flag: String },

    /// A flag was given without the value it requires.
    #[error("flag {flag:?} requires a value")]
    MissingValue { flag: String },

    /// A required flag was omitted.
    #[error("flag {flag:?} is required for this subcommand")]
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

    /// A configuration file or value was invalid.
    #[error("{0}")]
    Config(String),

    /// A file read or write failed.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// Invalid JSON input.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// A bridge line or other model value was invalid.
    #[error(transparent)]
    Model(#[from] tbc_core::ModelError),

    /// A scoring configuration was invalid.
    #[error(transparent)]
    Score(#[from] tbc_score::ScoreError),

    /// A publication configuration or input was invalid.
    #[error(transparent)]
    Publish(#[from] tbc_publish::PublishError),

    /// An agent configuration was invalid.
    #[error(transparent)]
    Agent(#[from] tbc_agent::AgentError),
}

impl CliError {
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
            Self::UnknownSubcommand { .. }
            | Self::UnknownFlag { .. }
            | Self::MissingValue { .. }
            | Self::MissingRequiredFlag { .. }
            | Self::DuplicateFlag { .. }
            | Self::InvalidValue { .. }
            | Self::UnexpectedArgument { .. } => "usage_error",
            Self::Config(_) => "config_error",
            Self::Io { .. } => "io_error",
            Self::Json(_) => "json_error",
            Self::Model(_) => "model_error",
            Self::Score(_) => "score_error",
            Self::Publish(_) => "publish_error",
            Self::Agent(_) => "agent_error",
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
            CliError::UnknownSubcommand {
                name: "bogus".to_owned()
            }
            .exit_code(),
            2
        );
        assert_eq!(CliError::Config("nope".to_owned()).exit_code(), 1);
        assert_eq!(
            CliError::io(
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
            CliError::MissingValue {
                flag: "--x".to_owned()
            }
            .kind_name(),
            "usage_error"
        );
        let json_error = CliError::Json(serde_json::from_str::<u8>("not json").unwrap_err());
        assert_eq!(json_error.kind_name(), "json_error");
    }
}

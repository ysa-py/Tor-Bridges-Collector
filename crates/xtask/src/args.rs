//! Task argument parsing for the `xtask` tool.
//!
//! Parsing is hand-rolled (matching the workspace's hand-rolled protocol
//! parsers) so every rule is our own tested logic.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::error::XtaskError;

/// A parsed task and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Task {
    /// Print usage.
    Help,
    /// Generate JSON Schema documents into a directory (default `schemas/`).
    SchemaGen { out: PathBuf },
    /// Run the workspace gate (fmt/clippy/test).
    Ci,
    /// Build the workspace.
    Build,
    /// Build the workspace in release mode and checksum the artifact directory
    /// (default `target/release`).
    Release { out: PathBuf },
}

impl Task {
    /// The canonical task name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Help => "help",
            Self::SchemaGen { .. } => "schema-gen",
            Self::Ci => "ci",
            Self::Build => "build",
            Self::Release { .. } => "release",
        }
    }
}

/// Parse `argv` (without the program name) into a [`Task`].
///
/// With no arguments, returns [`Task::Help`].
pub fn parse_args(args: &[String]) -> Result<Task, XtaskError> {
    let Some(name) = args.first() else {
        return Ok(Task::Help);
    };
    let rest = &args[1..];
    match name.as_str() {
        "help" | "--help" | "-h" => {
            expect_no_flags(rest)?;
            Ok(Task::Help)
        }
        "schema-gen" => {
            let flags = parse_flags(rest, &[("out", false)])?;
            Ok(Task::SchemaGen {
                out: path_or(flags.get("out"), "schemas"),
            })
        }
        "ci" => {
            expect_no_flags(rest)?;
            Ok(Task::Ci)
        }
        "build" => {
            expect_no_flags(rest)?;
            Ok(Task::Build)
        }
        "release" => {
            let flags = parse_flags(rest, &[("out", false)])?;
            Ok(Task::Release {
                out: path_or(flags.get("out"), "target/release"),
            })
        }
        other => Err(XtaskError::UnknownTask {
            name: other.to_owned(),
        }),
    }
}

/// The general usage summary.
pub fn usage() -> String {
    "xtask — Tor Bridges Collector build/release/schema-gen automation\n\
\n\
USAGE:\n\
    xtask <task> [options]\n\
\n\
TASKS:\n\
    schema-gen [--out <dir>]   Write versioned JSON Schemas (default schemas/)\n\
    ci                         Run fmt --check, clippy -D warnings, and tests\n\
    build                      Build the workspace\n\
    release [--out <dir>]      Build in release mode and write SHA256SUMS\n\
    help                       Print this usage\n\
\n\
Run `cargo xtask <task>` from the workspace root.\n"
        .to_owned()
}

fn expect_no_flags(args: &[String]) -> Result<(), XtaskError> {
    match args.first() {
        Some(arg) => Err(XtaskError::UnexpectedArgument { arg: arg.clone() }),
        None => Ok(()),
    }
}

fn parse_flags(
    args: &[String],
    spec: &[(&str, bool)],
) -> Result<BTreeMap<String, String>, XtaskError> {
    let mut flags = BTreeMap::new();
    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        let Some(rest) = arg.strip_prefix("--") else {
            return Err(XtaskError::UnexpectedArgument { arg: arg.clone() });
        };
        if rest.is_empty() {
            return Err(XtaskError::UnexpectedArgument { arg: arg.clone() });
        }
        let (key, inline) = match rest.split_once('=') {
            Some((key, value)) => (key, Some(value.to_owned())),
            None => (rest, None),
        };
        if !spec.iter().any(|(name, _)| *name == key) {
            return Err(XtaskError::UnknownFlag {
                flag: format!("--{key}"),
            });
        }
        let value = match inline {
            Some(value) => value,
            None => {
                index += 1;
                let Some(next) = args.get(index) else {
                    return Err(XtaskError::MissingValue {
                        flag: format!("--{key}"),
                    });
                };
                next.clone()
            }
        };
        if flags.insert(key.to_owned(), value).is_some() {
            return Err(XtaskError::DuplicateFlag {
                flag: format!("--{key}"),
            });
        }
        index += 1;
    }
    for (name, required) in spec {
        if *required && !flags.contains_key(*name) {
            return Err(XtaskError::MissingRequiredFlag {
                flag: format!("--{name}"),
            });
        }
    }
    Ok(flags)
}

fn path_or(value: Option<&String>, default: &str) -> PathBuf {
    value
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn no_arguments_yields_help() {
        assert_eq!(parse_args(&[]).unwrap(), Task::Help);
    }

    #[test]
    fn every_task_parses() {
        assert_eq!(parse_args(&argv(&["help"])).unwrap(), Task::Help);
        assert_eq!(parse_args(&argv(&["--help"])).unwrap(), Task::Help);
        assert_eq!(parse_args(&argv(&["ci"])).unwrap(), Task::Ci);
        assert_eq!(parse_args(&argv(&["build"])).unwrap(), Task::Build);
        assert_eq!(
            parse_args(&argv(&["schema-gen"])).unwrap(),
            Task::SchemaGen {
                out: PathBuf::from("schemas")
            }
        );
        assert_eq!(
            parse_args(&argv(&["schema-gen", "--out", "schemas/v2"])).unwrap(),
            Task::SchemaGen {
                out: PathBuf::from("schemas/v2")
            }
        );
        assert_eq!(
            parse_args(&argv(&["release"])).unwrap(),
            Task::Release {
                out: PathBuf::from("target/release")
            }
        );
        assert_eq!(
            parse_args(&argv(&["release", "--out=dist"])).unwrap(),
            Task::Release {
                out: PathBuf::from("dist")
            }
        );
    }

    #[test]
    fn unknown_task_is_rejected() {
        let error = parse_args(&argv(&["bogus"])).unwrap_err();
        assert!(matches!(error, XtaskError::UnknownTask { .. }));
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let error = parse_args(&argv(&["schema-gen", "--nope"])).unwrap_err();
        assert!(matches!(error, XtaskError::UnknownFlag { .. }));
    }

    #[test]
    fn missing_value_is_rejected() {
        let error = parse_args(&argv(&["schema-gen", "--out"])).unwrap_err();
        assert!(matches!(error, XtaskError::MissingValue { .. }));
    }

    #[test]
    fn duplicate_flag_is_rejected() {
        let error = parse_args(&argv(&["schema-gen", "--out", "a", "--out", "b"])).unwrap_err();
        assert!(matches!(error, XtaskError::DuplicateFlag { .. }));
    }

    #[test]
    fn task_names_are_stable() {
        assert_eq!(Task::Help.name(), "help");
        assert_eq!(Task::Ci.name(), "ci");
        assert_eq!(Task::Build.name(), "build");
        assert_eq!(
            Task::SchemaGen {
                out: PathBuf::from("x")
            }
            .name(),
            "schema-gen"
        );
        assert_eq!(
            Task::Release {
                out: PathBuf::from("x")
            }
            .name(),
            "release"
        );
    }
}

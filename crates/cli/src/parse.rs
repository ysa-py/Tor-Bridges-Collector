//! Command-line argument parsing for the `tbc` subcommand surface.
//!
//! Parsing is hand-rolled (matching the workspace's hand-rolled protocol
//! parsers) so every rule — flag forms, required flags, value validation, and
//! duplicate/unknown rejection — is our own tested logic rather than a
//! dependency's behaviour.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::command::Command;
use crate::error::CliError;

/// Parse `argv` (without the program name) into a [`Command`].
///
/// With no arguments, returns [`Command::Help`] with no topic so the binary
/// prints usage and exits 0, matching the standard CLI convention.
pub fn parse_command(args: &[String]) -> Result<Command, CliError> {
    let Some(name) = args.first() else {
        return Ok(Command::Help { topic: None });
    };
    let rest = &args[1..];
    match name.as_str() {
        "version" | "--version" | "-V" => {
            expect_no_flags(rest)?;
            Ok(Command::Version)
        }
        "schema" => {
            expect_no_flags(rest)?;
            Ok(Command::Schema)
        }
        "help" | "--help" | "-h" => Ok(Command::Help {
            topic: at_most_one_positional(rest)?,
        }),
        "collect" => {
            let flags = parse_flags(rest, &[("config", true)])?;
            Ok(Command::Collect {
                config: PathBuf::from(take_required(&flags, "config")?),
            })
        }
        "probe" => {
            let flags = parse_flags(rest, &[("input", true), ("output", true)])?;
            Ok(Command::Probe {
                input: PathBuf::from(take_required(&flags, "input")?),
                output: PathBuf::from(take_required(&flags, "output")?),
            })
        }
        "vantage" => {
            let flags = parse_flags(rest, &[("input", true), ("output", true), ("kind", false)])?;
            Ok(Command::Vantage {
                input: PathBuf::from(take_required(&flags, "input")?),
                output: PathBuf::from(take_required(&flags, "output")?),
                kind: flags.get("kind").cloned(),
            })
        }
        "score" => {
            let flags = parse_flags(rest, &[("input", true), ("output", true)])?;
            Ok(Command::Score {
                input: PathBuf::from(take_required(&flags, "input")?),
                output: PathBuf::from(take_required(&flags, "output")?),
            })
        }
        "publish" => {
            let flags = parse_flags(rest, &[("input", true), ("output", true)])?;
            Ok(Command::Publish {
                input: PathBuf::from(take_required(&flags, "input")?),
                output: PathBuf::from(take_required(&flags, "output")?),
            })
        }
        "agent" => {
            let flags = parse_flags(rest, &[("bind", false), ("port", false)])?;
            let bind = flags
                .get("bind")
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".to_owned());
            let port = match flags.get("port") {
                Some(raw) => parse_port(raw)?,
                None => 8080,
            };
            Ok(Command::Agent { bind, port })
        }
        other => Err(CliError::UnknownSubcommand {
            name: other.to_owned(),
        }),
    }
}

/// Reject every argument for a subcommand that accepts none.
fn expect_no_flags(args: &[String]) -> Result<(), CliError> {
    match args.first() {
        Some(arg) => Err(CliError::UnexpectedArgument { arg: arg.clone() }),
        None => Ok(()),
    }
}

/// Accept at most one positional argument (the `help` topic).
fn at_most_one_positional(args: &[String]) -> Result<Option<String>, CliError> {
    if args.len() > 1 {
        return Err(CliError::UnexpectedArgument {
            arg: args[1].clone(),
        });
    }
    Ok(args.first().cloned())
}

/// Parse `--key value` / `--key=value` flags against a spec, returning values
/// keyed by flag name with every required flag present.
fn parse_flags(
    args: &[String],
    spec: &[(&str, bool)],
) -> Result<BTreeMap<String, String>, CliError> {
    let mut flags = BTreeMap::new();
    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        let Some(rest) = arg.strip_prefix("--") else {
            return Err(CliError::UnexpectedArgument { arg: arg.clone() });
        };
        if rest.is_empty() {
            return Err(CliError::UnexpectedArgument { arg: arg.clone() });
        }
        let (key, inline) = match rest.split_once('=') {
            Some((key, value)) => (key, Some(value.to_owned())),
            None => (rest, None),
        };
        if !spec.iter().any(|(name, _)| *name == key) {
            return Err(CliError::UnknownFlag {
                flag: format!("--{key}"),
            });
        }
        let value = match inline {
            Some(value) => value,
            None => {
                index += 1;
                let Some(next) = args.get(index) else {
                    return Err(CliError::MissingValue {
                        flag: format!("--{key}"),
                    });
                };
                next.clone()
            }
        };
        if flags.insert(key.to_owned(), value).is_some() {
            return Err(CliError::DuplicateFlag {
                flag: format!("--{key}"),
            });
        }
        index += 1;
    }
    for (name, required) in spec {
        if *required && !flags.contains_key(*name) {
            return Err(CliError::MissingRequiredFlag {
                flag: format!("--{name}"),
            });
        }
    }
    Ok(flags)
}

/// Fetch a required flag value that [`parse_flags`] has already guaranteed.
fn take_required(flags: &BTreeMap<String, String>, name: &str) -> Result<String, CliError> {
    flags
        .get(name)
        .cloned()
        .ok_or_else(|| CliError::MissingRequiredFlag {
            flag: format!("--{name}"),
        })
}

/// Parse and range-check a TCP port value.
fn parse_port(raw: &str) -> Result<u16, CliError> {
    let port: u16 = raw.parse().map_err(|_| CliError::InvalidValue {
        flag: "--port".to_owned(),
        value: raw.to_owned(),
        reason: "port must be an integer".to_owned(),
    })?;
    if port == 0 {
        return Err(CliError::InvalidValue {
            flag: "--port".to_owned(),
            value: raw.to_owned(),
            reason: "port must be in 1..=65535".to_owned(),
        });
    }
    Ok(port)
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
        assert_eq!(parse_command(&[]).unwrap(), Command::Help { topic: None });
    }

    #[test]
    fn version_schema_and_help_parse() {
        assert_eq!(
            parse_command(&argv(&["version"])).unwrap(),
            Command::Version
        );
        assert_eq!(
            parse_command(&argv(&["--version"])).unwrap(),
            Command::Version
        );
        assert_eq!(parse_command(&argv(&["-V"])).unwrap(), Command::Version);
        assert_eq!(parse_command(&argv(&["schema"])).unwrap(), Command::Schema);
        assert_eq!(
            parse_command(&argv(&["help"])).unwrap(),
            Command::Help { topic: None }
        );
        assert_eq!(
            parse_command(&argv(&["help", "score"])).unwrap(),
            Command::Help {
                topic: Some("score".to_owned())
            }
        );
    }

    #[test]
    fn every_subcommand_parses_with_flags() {
        assert_eq!(
            parse_command(&argv(&["collect", "--config", "c.json"])).unwrap(),
            Command::Collect {
                config: PathBuf::from("c.json")
            }
        );
        assert_eq!(
            parse_command(&argv(&["probe", "--input", "i", "--output", "o"])).unwrap(),
            Command::Probe {
                input: PathBuf::from("i"),
                output: PathBuf::from("o"),
            }
        );
        assert_eq!(
            parse_command(&argv(&["vantage", "--input", "i", "--output", "o"])).unwrap(),
            Command::Vantage {
                input: PathBuf::from("i"),
                output: PathBuf::from("o"),
                kind: None,
            }
        );
        assert_eq!(
            parse_command(&argv(&[
                "vantage", "--input", "i", "--output", "o", "--kind", "ooni"
            ]))
            .unwrap(),
            Command::Vantage {
                input: PathBuf::from("i"),
                output: PathBuf::from("o"),
                kind: Some("ooni".to_owned()),
            }
        );
        assert_eq!(
            parse_command(&argv(&["score", "--input", "i", "--output", "o"])).unwrap(),
            Command::Score {
                input: PathBuf::from("i"),
                output: PathBuf::from("o"),
            }
        );
        assert_eq!(
            parse_command(&argv(&["publish", "--input", "i", "--output", "o"])).unwrap(),
            Command::Publish {
                input: PathBuf::from("i"),
                output: PathBuf::from("o"),
            }
        );
        assert_eq!(
            parse_command(&argv(&["agent"])).unwrap(),
            Command::Agent {
                bind: "127.0.0.1".to_owned(),
                port: 8080,
            }
        );
        assert_eq!(
            parse_command(&argv(&["agent", "--bind", "0.0.0.0", "--port", "9090"])).unwrap(),
            Command::Agent {
                bind: "0.0.0.0".to_owned(),
                port: 9090,
            }
        );
    }

    #[test]
    fn flag_value_forms_are_equivalent() {
        let space = parse_command(&argv(&["score", "--input", "a", "--output", "b"])).unwrap();
        let equals = parse_command(&argv(&["score", "--input=a", "--output=b"])).unwrap();
        assert_eq!(space, equals);
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        let error = parse_command(&argv(&["bogus"])).unwrap_err();
        assert!(matches!(error, CliError::UnknownSubcommand { .. }));
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let error = parse_command(&argv(&[
            "score", "--nope", "x", "--input", "a", "--output", "b",
        ]))
        .unwrap_err();
        assert!(matches!(error, CliError::UnknownFlag { .. }));
    }

    #[test]
    fn missing_value_is_rejected() {
        let error = parse_command(&argv(&["score", "--input"])).unwrap_err();
        assert!(matches!(error, CliError::MissingValue { .. }));
    }

    #[test]
    fn missing_required_flag_is_rejected() {
        let error = parse_command(&argv(&["score", "--input", "a"])).unwrap_err();
        assert!(matches!(error, CliError::MissingRequiredFlag { .. }));
    }

    #[test]
    fn duplicate_flag_is_rejected() {
        let error = parse_command(&argv(&[
            "score", "--input", "a", "--input", "b", "--output", "o",
        ]))
        .unwrap_err();
        assert!(matches!(error, CliError::DuplicateFlag { .. }));
    }

    #[test]
    fn unexpected_positional_is_rejected() {
        let error = parse_command(&argv(&["score", "a", "b"])).unwrap_err();
        assert!(matches!(error, CliError::UnexpectedArgument { .. }));
        let error = parse_command(&argv(&["version", "extra"])).unwrap_err();
        assert!(matches!(error, CliError::UnexpectedArgument { .. }));
    }

    #[test]
    fn agent_port_is_validated() {
        assert!(matches!(
            parse_command(&argv(&["agent", "--port", "0"])),
            Err(CliError::InvalidValue { .. })
        ));
        assert!(matches!(
            parse_command(&argv(&["agent", "--port", "abc"])),
            Err(CliError::InvalidValue { .. })
        ));
    }
}

//! The `tbc` subcommand surface.

use std::path::PathBuf;

/// Version string reported by `tbc version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The parsed subcommand and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print version information.
    Version,
    /// Print the JSON document schema version (from `tbc-core`).
    Schema,
    /// Print usage, optionally scoped to one subcommand.
    Help { topic: Option<String> },
    /// Validate a sources configuration file.
    Collect { config: PathBuf },
    /// Validate a bridge-line input set before probing.
    Probe { input: PathBuf, output: PathBuf },
    /// Validate a bridge-line input set for in-country measurement.
    Vantage {
        input: PathBuf,
        output: PathBuf,
        kind: Option<String>,
    },
    /// Score observations and write the scores.
    Score { input: PathBuf, output: PathBuf },
    /// Publish bridge lines to deterministic artifacts.
    Publish { input: PathBuf, output: PathBuf },
    /// Validate a volunteer-agent bind configuration.
    Agent { bind: String, port: u16 },
}

impl Command {
    /// The canonical subcommand name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Schema => "schema",
            Self::Help { .. } => "help",
            Self::Collect { .. } => "collect",
            Self::Probe { .. } => "probe",
            Self::Vantage { .. } => "vantage",
            Self::Score { .. } => "score",
            Self::Publish { .. } => "publish",
            Self::Agent { .. } => "agent",
        }
    }
}

/// The general usage summary.
pub fn usage() -> String {
    format!(
        "tbc {VERSION} — Tor Bridges Collector pipeline\n\
\n\
USAGE:\n\
    tbc <subcommand> [options]\n\
\n\
SUBCOMMANDS:\n\
    version          Print version information\n\
    schema           Print the JSON schema version\n\
    help [topic]     Print usage (optionally for one subcommand)\n\
    collect          Validate a sources configuration file\n\
    probe            Validate bridge lines before probing\n\
    vantage          Validate bridge lines for in-country measurement\n\
    score            Score observations\n\
    publish          Publish bridges to deterministic artifacts\n\
    agent            Validate a volunteer-agent configuration\n\
\n\
Run `tbc help <subcommand>` for subcommand-specific options.\n"
    )
}

fn subcommand_help(topic: &str) -> Option<String> {
    let text = match topic {
        "collect" => "tbc collect --config <path>\n\n  --config <path>   Path to a JSON file with a \"sources\" array of URLs.",
        "probe" => {
            "tbc probe --input <path> --output <path>\n\n  --input <path>    File of bridge lines to validate.\n  --output <path>   Where probe observations would be written."
        }
        "vantage" => {
            "tbc vantage --input <path> --output <path> [--kind <name>]\n\n  --input <path>    File of bridge lines.\n  --output <path>   Where vantage observations would be written.\n  --kind <name>     One of: runner, ooni, ripe_atlas, globalping, volunteer_agent."
        }
        "score" => "tbc score --input <path> --output <path>\n\n  --input <path>    JSON array of observations.\n  --output <path>   Where the JSON array of scored bridges is written.",
        "publish" => "tbc publish --input <path> --output <dir>\n\n  --input <path>    File of bridge lines.\n  --output <dir>    Directory for the rendered publication artifacts.",
        "agent" => "tbc agent [--bind <addr>] [--port <n>]\n\n  --bind <addr>     Address to bind (default 127.0.0.1).\n  --port <n>        Port to bind (default 8080).",
        _ => return None,
    };
    Some(text.to_owned())
}

/// Usage text for the whole CLI, or for a single subcommand.
pub fn help_text(topic: Option<&str>) -> String {
    match topic {
        Some(name) => subcommand_help(name).unwrap_or_else(usage),
        None => usage(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn usage_lists_every_subcommand() {
        let text = usage();
        for name in [
            "version", "schema", "help", "collect", "probe", "vantage", "score", "publish", "agent",
        ] {
            assert!(text.contains(name), "usage should list {name}");
        }
    }

    #[test]
    fn command_names_are_stable() {
        assert_eq!(Command::Version.name(), "version");
        assert_eq!(Command::Schema.name(), "schema");
        assert_eq!(Command::Help { topic: None }.name(), "help");
        assert_eq!(
            Command::Collect {
                config: PathBuf::from("c.json")
            }
            .name(),
            "collect"
        );
        assert_eq!(
            Command::Agent {
                bind: "x".into(),
                port: 1
            }
            .name(),
            "agent"
        );
    }

    #[test]
    fn help_text_scopes_to_known_subcommands() {
        assert!(help_text(Some("score")).contains("--input"));
        assert!(help_text(Some("agent")).contains("--bind"));
        // Unknown topics fall back to the general usage summary.
        assert_eq!(help_text(Some("bogus")), usage());
    }
}

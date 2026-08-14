//! Dispatch of a parsed [`Command`] to the pipeline crates.
//!
//! `score` and `publish` are offline (pure computation plus file I/O), so the
//! CLI executes them end-to-end here. `collect`, `probe`, `vantage`, and
//! `agent` are network- or live-service-bound; the CLI validates their inputs
//! and configuration in full (real file reads and typed errors) and reports
//! readiness, while the network execution itself is owned by `tbc-sources`,
//! `tbc-prober`, `tbc-vantage`, and `tbc-agent` respectively — the "second
//! gate" boundary those crates document for their own live paths.

use std::io::Write;
use std::path::Path;

use chrono::Utc;

use tbc_agent::AgentConfig;
use tbc_core::{BridgeLine, Observation, SCHEMA_VERSION};
use tbc_publish::{Publication, PublicationEntry, PublishConfig, Publisher};
use tbc_score::{ScoreConfig, ScoreEngine};

use crate::command::{Command, VERSION};
use crate::error::CliError;

/// Execute `command`, writing human-readable progress to `out`.
pub fn run(command: &Command, out: &mut dyn Write) -> Result<(), CliError> {
    match command {
        Command::Version => write_line(out, format!("tbc {VERSION} (schema v{SCHEMA_VERSION})")),
        Command::Schema => write_line(out, SCHEMA_VERSION.to_string()),
        Command::Help { topic } => {
            let text = crate::command::help_text(topic.as_deref());
            out.write_all(text.as_bytes())
                .map_err(|source| CliError::io("write_output", source))
        }
        Command::Collect { config } => run_collect(config, out),
        Command::Probe { input, output } => run_probe(input, output, out),
        Command::Vantage {
            input,
            output,
            kind,
        } => run_vantage(input, output, kind.as_deref(), out),
        Command::Score { input, output } => run_score(input, output, out),
        Command::Publish { input, output } => run_publish(input, output, out),
        Command::Agent { bind, port } => run_agent(bind, *port, out),
    }
}

/// Write one line to the output stream, mapping I/O failures into [`CliError`].
fn write_line(out: &mut dyn Write, line: String) -> Result<(), CliError> {
    out.write_all(line.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .map_err(|source| CliError::io("write_output", source))
}

fn read_to_string(path: &Path, context: &str) -> Result<String, CliError> {
    std::fs::read_to_string(path).map_err(|source| CliError::io(context, source))
}

fn write_file(path: &Path, contents: &str, context: &str) -> Result<(), CliError> {
    std::fs::write(path, contents).map_err(|source| CliError::io(context, source))
}

// ── Offline subcommands (executed end-to-end) ─────────────────────────────

fn run_score(input: &Path, output: &Path, out: &mut dyn Write) -> Result<(), CliError> {
    let text = read_to_string(input, "read observations input")?;
    let observations: Vec<Observation> = serde_json::from_str(&text)?;
    let engine = ScoreEngine::new(ScoreConfig::default())?;
    let scored = engine.score_all(&observations, Utc::now());
    let json = serde_json::to_string_pretty(&scored)?;
    write_file(output, &json, "write scores output")?;
    write_line(
        out,
        format!(
            "score: scored {} bridge(s) from {} observation(s) -> {}",
            scored.len(),
            observations.len(),
            output.display()
        ),
    )
}

fn run_publish(input: &Path, output: &Path, out: &mut dyn Write) -> Result<(), CliError> {
    let text = read_to_string(input, "read bridge lines input")?;
    let now = Utc::now();
    let mut entries = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let bridge = BridgeLine::parse(trimmed, now)?;
        let name = format!("{}.txt", bridge.transport.to_token());
        entries.push(PublicationEntry {
            name,
            bridge,
            score: None,
        });
    }
    if entries.is_empty() {
        return Err(CliError::Config(
            "publish input contained no bridge lines".to_owned(),
        ));
    }
    let publication = Publication {
        schema_version: SCHEMA_VERSION,
        generated_at: now,
        entries,
    };
    let publisher = Publisher::new(PublishConfig::default())?;
    let report = publisher.write(&publication, output)?;
    write_line(
        out,
        format!(
            "publish: wrote {} file(s) -> {}",
            report.written.len(),
            output.display()
        ),
    )
}

// ── Network-bound subcommands (validated here, executed by their crate) ───

fn run_collect(config: &Path, out: &mut dyn Write) -> Result<(), CliError> {
    let text = read_to_string(config, "read sources config")?;
    let sources = parse_sources_config(&text)?;
    write_line(
        out,
        format!(
            "collect: validated {} source(s) from {}",
            sources.len(),
            config.display()
        ),
    )
}

fn parse_sources_config(text: &str) -> Result<Vec<String>, CliError> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let array = value
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError::Config(r#"config must contain a "sources" array"#.to_owned()))?;
    let mut urls = Vec::with_capacity(array.len());
    for (index, item) in array.iter().enumerate() {
        let url = item
            .as_str()
            .ok_or_else(|| CliError::Config(format!("sources[{index}] must be a string URL")))?;
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(CliError::Config(format!(
                "sources[{index}] must use http:// or https://"
            )));
        }
        urls.push(url.to_owned());
    }
    Ok(urls)
}

fn run_probe(input: &Path, output: &Path, out: &mut dyn Write) -> Result<(), CliError> {
    let count = validate_bridge_lines(input, "probe")?;
    write_line(
        out,
        format!(
            "probe: validated {count} bridge line(s); observations would be written to {}",
            output.display()
        ),
    )
}

fn run_vantage(
    input: &Path,
    output: &Path,
    kind: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let count = validate_bridge_lines(input, "vantage")?;
    let kind_text = match kind {
        Some(kind) => {
            validate_vantage_kind(kind)?;
            kind.to_owned()
        }
        None => "all".to_owned(),
    };
    write_line(
        out,
        format!(
            "vantage: validated {count} bridge line(s) for kind {kind_text}; observations would be written to {}",
            output.display()
        ),
    )
}

fn validate_bridge_lines(input: &Path, context: &str) -> Result<usize, CliError> {
    let text = read_to_string(input, &format!("read {context} input"))?;
    let now = Utc::now();
    let mut count = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        BridgeLine::parse(trimmed, now)?;
        count += 1;
    }
    if count == 0 {
        return Err(CliError::Config(format!(
            "{context} input contained no bridge lines"
        )));
    }
    Ok(count)
}

fn validate_vantage_kind(kind: &str) -> Result<(), CliError> {
    let normalized = kind.trim().to_ascii_lowercase();
    const KNOWN: [&str; 5] = [
        "runner",
        "ooni",
        "ripe_atlas",
        "globalping",
        "volunteer_agent",
    ];
    if KNOWN.contains(&normalized.as_str()) {
        Ok(())
    } else {
        Err(CliError::InvalidValue {
            flag: "--kind".to_owned(),
            value: kind.to_owned(),
            reason: "expected one of runner, ooni, ripe_atlas, globalping, volunteer_agent"
                .to_owned(),
        })
    }
}

fn run_agent(bind: &str, port: u16, out: &mut dyn Write) -> Result<(), CliError> {
    if bind.trim().is_empty() || bind.chars().any(char::is_whitespace) {
        return Err(CliError::InvalidValue {
            flag: "--bind".to_owned(),
            value: bind.to_owned(),
            reason: "bind address must be a non-empty host or IP with no whitespace".to_owned(),
        });
    }
    let config = AgentConfig {
        bind_host: bind.to_owned(),
        bind_port: port,
        ..AgentConfig::default()
    };
    config.validate()?;
    write_line(
        out,
        format!(
            "agent: validated bind {bind}:{port}; run `tbc-agent` for the consent-gated server"
        ),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sources_config_parses_valid_urls() {
        let urls =
            parse_sources_config(r#"{"sources":["https://a.example/list","http://b.example/x"]}"#)
                .unwrap();
        assert_eq!(urls, vec!["https://a.example/list", "http://b.example/x"]);
    }

    #[test]
    fn sources_config_rejects_missing_key() {
        let error = parse_sources_config(r#"{"nope":[]}"#).unwrap_err();
        assert_eq!(error.kind_name(), "config_error");
    }

    #[test]
    fn sources_config_rejects_bad_scheme_and_non_string() {
        let error = parse_sources_config(r#"{"sources":["ftp://a.example"]}"#).unwrap_err();
        assert_eq!(error.kind_name(), "config_error");
        let error = parse_sources_config(r#"{"sources":[42]}"#).unwrap_err();
        assert_eq!(error.kind_name(), "config_error");
    }

    #[test]
    fn vantage_kind_validation_is_exhaustive() {
        for kind in [
            "runner",
            "ooni",
            "ripe_atlas",
            "globalping",
            "volunteer_agent",
        ] {
            assert!(validate_vantage_kind(kind).is_ok(), "{kind} should pass");
        }
        let error = validate_vantage_kind("carrier_pigeon").unwrap_err();
        assert_eq!(error.kind_name(), "usage_error");
    }

    #[test]
    fn agent_bind_validation_rejects_blank() {
        let error = run_agent("  ", 8080, &mut Vec::new()).unwrap_err();
        assert_eq!(error.kind_name(), "usage_error");
    }

    #[test]
    fn agent_accepts_valid_bind_and_port() {
        let mut out = Vec::new();
        run_agent("127.0.0.1", 9090, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("127.0.0.1:9090"));
    }
}

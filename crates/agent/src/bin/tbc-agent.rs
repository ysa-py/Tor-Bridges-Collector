//! Binary entry point for the volunteer in-country agent.
//!
//! Configuration is read from environment variables so a volunteer can run
//! the agent without a config file:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `TBC_AGENT_BIND_HOST` | `0.0.0.0` | Interface to listen on |
//! | `TBC_AGENT_BIND_PORT` | `8080` | TCP port (0 = OS-assigned) |
//! | `TBC_AGENT_CONNECT_TIMEOUT_MS` | `10000` | DNS + connect budget per probe |
//! | `TBC_AGENT_READ_TIMEOUT_MS` | `15000` | HTTP read/write budget |
//! | `TBC_AGENT_MAX_CONCURRENT_PROBES` | `16` | Concurrent measurement cap |
//! | `TBC_AGENT_RATE_BURST` | `5` | Per-client request burst |
//! | `TBC_AGENT_RATE_PER_SECOND` | `1` | Per-client sustained rate |
//! | `TBC_AGENT_ID_PREFIX` | `agent` | `measurement_ref` prefix |
//!
//! Invalid values fail startup with a typed [`AgentError`] instead of falling
//! back to a silent default.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use tbc_agent::{parse_consent_input, AgentConfig, AgentError, AgentServer};

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    tracing_subscriber::fmt::try_init()
        .map_err(|error| AgentError::Config(format!("failed to initialise logging: {error}")))?;

    let config = config_from_env()?;
    let server = AgentServer::new(config)?;
    // The consent screen is mandatory: the binary refuses to bind or send any
    // probe traffic until the volunteer has explicitly agreed.
    prompt_for_consent(&server)?;
    let listener = server.bind().await?;
    let address = listener
        .local_addr()
        .map(|socket| socket.to_string())
        .unwrap_or_else(|_| "unknown address".to_owned());
    tracing::info!(%address, "tbc-agent listening");
    server.run(listener).await
}

/// The unskippable consent screen. It re-prompts on any unrecognized answer,
/// aborts startup on `no` (or EOF), and records consent on `yes` before the
/// server is allowed to bind.
fn prompt_for_consent(server: &AgentServer) -> Result<(), AgentError> {
    use std::io::{BufRead, Write};

    eprintln!(
        "This program performs in-country network measurements (DNS lookups and TCP \
         connects to bridge targets) on your network, and reports anonymized, \
         k-anonymous results upstream. It never sends probe traffic until you agree."
    );
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        print!("Record volunteer consent and start probing? [yes/no]: ");
        std::io::stdout().flush().map_err(|error| AgentError::Io {
            phase: "consent",
            message: error.to_string(),
        })?;
        let line = match lines.next() {
            Some(Ok(line)) => line,
            Some(Err(error)) => {
                return Err(AgentError::Io {
                    phase: "consent",
                    message: error.to_string(),
                })
            }
            None => return Err(AgentError::ConsentRequired),
        };
        match parse_consent_input(&line) {
            Ok(true) => {
                server.grant_consent("terminal_prompt");
                tracing::info!("volunteer consent recorded");
                return Ok(());
            }
            Ok(false) => return Err(AgentError::ConsentRequired),
            Err(error) => eprintln!("{error}"),
        }
    }
}

fn config_from_env() -> Result<AgentConfig, AgentError> {
    let mut config = AgentConfig::default();
    if let Some(value) = env("TBC_AGENT_BIND_HOST") {
        config.bind_host = value;
    }
    config.bind_port = env_parse("TBC_AGENT_BIND_PORT", config.bind_port)?;
    config.connect_timeout =
        Duration::from_millis(env_parse("TBC_AGENT_CONNECT_TIMEOUT_MS", 10_000u64)?);
    config.read_timeout = Duration::from_millis(env_parse("TBC_AGENT_READ_TIMEOUT_MS", 15_000u64)?);
    config.max_concurrent_probes = env_parse("TBC_AGENT_MAX_CONCURRENT_PROBES", 16usize)?;
    config.rate_limit_burst = env_parse("TBC_AGENT_RATE_BURST", 5u32)?;
    config.rate_limit_per_second = env_parse("TBC_AGENT_RATE_PER_SECOND", 1u32)?;
    if let Some(value) = env("TBC_AGENT_ID_PREFIX") {
        config.measurement_id_prefix = value;
    }
    config.validate()?;
    Ok(config)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_parse<T>(name: &str, default: T) -> Result<T, AgentError>
where
    T: std::str::FromStr,
{
    match env(name) {
        None => Ok(default),
        Some(value) => value
            .parse::<T>()
            .map_err(|_| AgentError::Config(format!("{name} is not a valid value: {value}"))),
    }
}

//! Dependency-light CLI parsing for the unified collector binary.

use std::path::PathBuf;

use anyhow::{anyhow, Result};

use super::config::CollectorConfig;
use super::service::CollectorService;

/// Parse process arguments, run the service, and return an exit-oriented
/// result. Keeping parsing here lets both `src/main.rs` and the explicitly
/// named `tor-bridges-collector` binary share exactly one implementation.
pub async fn run_from_env() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args
        .iter()
        .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    {
        println!("{}", usage());
        return Ok(());
    }
    let mut config = CollectorConfig::from_env()?;
    apply_arguments(&mut config, args)?;
    let service = CollectorService::new(config)?;
    let summary = service.run().await?;
    println!(
        "Collector summary: changed_files={} history_entries={} dry_run={}",
        summary.changed_files, summary.history_entries, summary.dry_run
    );
    Ok(())
}

/// Apply documented CLI options to a configuration. Public for deterministic
/// argument parsing tests without altering process environment variables.
pub fn apply_arguments(config: &mut CollectorConfig, args: Vec<String>) -> Result<()> {
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dry-run" => config.dry_run = true,
            "--verbose" | "-v" => config.verbose = true,
            "--bridge-dir" => {
                let value = next_value(&args, &mut index, "--bridge-dir")?;
                config.set_bridge_dir(PathBuf::from(value));
            }
            "--readme" => {
                config.readme_path = PathBuf::from(next_value(&args, &mut index, "--readme")?);
            }
            "--metrics" => {
                config.metrics_output =
                    Some(PathBuf::from(next_value(&args, &mut index, "--metrics")?));
            }
            "--max-workers" => {
                let value = parse_usize(
                    next_value(&args, &mut index, "--max-workers")?,
                    "--max-workers",
                )?;
                if value == 0 || value > 1_000 {
                    return Err(anyhow!("--max-workers must be in 1..=1000"));
                }
                config.max_workers = value;
                config.min_workers = config.min_workers.min(value).max(1);
            }
            "--max-test-per-list" => {
                let value = parse_usize(
                    next_value(&args, &mut index, "--max-test-per-list")?,
                    "--max-test-per-list",
                )?;
                if value > 100_000 {
                    return Err(anyhow!("--max-test-per-list must be in 0..=100000 (0 = adaptive/unbounded)"));
                }
                config.max_test_per_list = value;
            }
            "--timeout-seconds" => {
                let value = parse_u64(
                    next_value(&args, &mut index, "--timeout-seconds")?,
                    "--timeout-seconds",
                )?;
                if value == 0 || value > 120 {
                    return Err(anyhow!("--timeout-seconds must be in 1..=120"));
                }
                config.connect_timeout_secs = value;
            }
            "--retry-count" => {
                let value = parse_usize(
                    next_value(&args, &mut index, "--retry-count")?,
                    "--retry-count",
                )?;
                if value == 0 || value > 10 {
                    return Err(anyhow!("--retry-count must be in 1..=10"));
                }
                config.max_retries = value;
            }
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            unknown => return Err(anyhow!("unknown argument {unknown:?}\n{}", usage())),
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Usage text intentionally includes every mutating/operational option.
pub fn usage() -> &'static str {
    "Usage: tor-bridges-collector [OPTIONS]\n\
\n\
Options:\n\
  --dry-run                    Collect and probe but do not write outputs\n\
  --bridge-dir PATH            Override bridge output directory\n\
  --readme PATH                Override README output path\n\
  --metrics PATH               Write Prometheus text exposition to PATH\n\
  --max-workers N              Override adaptive-concurrency ceiling\n\
  --max-test-per-list N        Test pool ceiling; 0 adapts to all source lines\n\
  --timeout-seconds N          Connect/TLS/WebSocket timeout (1..=120)\n\
  --retry-count N              Per-probe retry count (1..=10)\n\
  --verbose, -v                Request verbose diagnostics\n\
  --help, -h                   Show this help text"
}

fn next_value<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str> {
    *index = index.saturating_add(1);
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("{flag} requires a value"))
}

fn parse_usize(value: &str, flag: &str) -> Result<usize> {
    value
        .parse::<usize>()
        .map_err(|_| anyhow!("{flag} requires an integer, got {value:?}"))
}

fn parse_u64(value: &str, flag: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| anyhow!("{flag} requires an integer, got {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CollectorConfig {
        CollectorConfig::from_env().expect("test environment should produce defaults")
    }

    #[test]
    fn cli_dry_run_and_limits_apply() {
        let mut config = config();
        apply_arguments(
            &mut config,
            vec![
                "--dry-run".to_owned(),
                "--max-workers".to_owned(),
                "12".to_owned(),
                "--max-test-per-list".to_owned(),
                "42".to_owned(),
            ],
        )
        .expect("valid CLI arguments");
        assert!(config.dry_run);
        assert_eq!(config.max_workers, 12);
        assert_eq!(config.max_test_per_list, 42);
    }

    #[test]
    fn cli_rejects_missing_and_unknown_values() {
        let mut config = config();
        assert!(apply_arguments(&mut config, vec!["--metrics".to_owned()]).is_err());
        assert!(apply_arguments(&mut config, vec!["--not-real".to_owned()]).is_err());
    }
}

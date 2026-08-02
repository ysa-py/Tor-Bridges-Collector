//! Bounded Rust-native bridge reachability tester.
//!
//! The test deliberately records exactly what a GitHub runner can establish:
//! a TCP connection (or a transport-capability check for Snowflake).  It does
//! not claim that a result proves Iranian reachability, a full Tor circuit, or
//! successful pluggable-transport negotiation.  Those distinctions remain in
//! the JSON report consumed by the publication layer.

use std::collections::BTreeMap;
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use torshield_ir_ultra::tester::extract_endpoint;

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[derive(Debug)]
struct Options {
    input: PathBuf,
    output: PathBuf,
    workers: usize,
    timeout: Duration,
    max_bridges: usize,
}

fn usage() -> &'static str {
    "Usage: bridge_tester [OPTIONS]\n\
     \n\
     Options:\n\
       --input PATH        JSON bridge list (default: bridge/bridge_list_for_testing.json)\n\
       --output PATH       JSON report (default: bridge/iran_results.json)\n\
       --workers N         Bounded concurrent TCP probes (default: 48)\n\
       --timeout-seconds N Per-probe TCP timeout (default: 5)\n\
       --max-bridges N     Hard safety limit (default: 2500)\n\
       --help              Print this help"
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| invalid(format!("{flag} requires a value")))
}

fn parse_positive<T>(value: String, flag: &str) -> Result<T, Box<dyn std::error::Error>>
where
    T: std::str::FromStr + PartialOrd + From<u8>,
{
    let parsed = value
        .parse::<T>()
        .map_err(|_| invalid(format!("{flag} must be a positive integer")))?;
    if parsed <= T::from(0) {
        return Err(invalid(format!("{flag} must be positive")));
    }
    Ok(parsed)
}

fn parse_args() -> Result<Options, Box<dyn std::error::Error>> {
    let mut options = Options {
        input: PathBuf::from("bridge/bridge_list_for_testing.json"),
        output: PathBuf::from("bridge/iran_results.json"),
        workers: 48,
        timeout: Duration::from_secs(5),
        max_bridges: 2500,
    };
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--input" => options.input = PathBuf::from(next_value(&mut args, "--input")?),
            "--output" => options.output = PathBuf::from(next_value(&mut args, "--output")?),
            "--workers" => {
                options.workers = parse_positive(next_value(&mut args, "--workers")?, "--workers")?
            }
            "--timeout-seconds" => {
                let seconds: u64 = parse_positive(
                    next_value(&mut args, "--timeout-seconds")?,
                    "--timeout-seconds",
                )?;
                options.timeout = Duration::from_secs(seconds);
            }
            "--max-bridges" => {
                options.max_bridges =
                    parse_positive(next_value(&mut args, "--max-bridges")?, "--max-bridges")?
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            unknown => return Err(invalid(format!("unknown argument: {unknown}\n{}", usage()))),
        }
    }
    Ok(options)
}

fn normalise_transport(line: &str, extracted: &str) -> String {
    let first = line
        .trim()
        .strip_prefix("Bridge ")
        .unwrap_or(line.trim())
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match first.as_str() {
        "obfs4" | "webtunnel" | "vanilla" | "snowflake" | "meek_lite" | "conjure"
        | "meek-azure" => first,
        "meek-lite" => "meek_lite".to_string(),
        _ => extracted.to_string(),
    }
}

fn snowflake_capability_result(line: String) -> Value {
    json!({
        "line": line,
        "transport": "snowflake",
        "host": null,
        "port": null,
        "tcp_reachable": false,
        "transport_capable": true,
        "probe_status": "transport_capability",
        "probe_method": "snowflake-webRTC-capability",
        "latency_ms": null,
        "iran_status": "iran_unknown",
        "evidence_scope": "Transport capability only; no TCP socket or Iran-vantage assertion was made.",
        "composite_score": 0.55,
    })
}

async fn probe_one(line: String, timeout_duration: Duration) -> Value {
    let (host, port, extracted_transport) = extract_endpoint(&line);
    let transport = normalise_transport(&line, extracted_transport);
    if transport == "snowflake" {
        return snowflake_capability_result(line);
    }
    let Some(host) = host else {
        return json!({
            "line": line,
            "transport": transport,
            "host": null,
            "port": null,
            "tcp_reachable": false,
            "transport_capable": false,
            "probe_status": "unparseable",
            "probe_method": "none",
            "latency_ms": null,
            "iran_status": "iran_unknown",
            "evidence_scope": "No endpoint could be parsed; no reachability claim was made.",
            "composite_score": 0.0,
        });
    };
    let Some(port) = port else {
        return json!({
            "line": line,
            "transport": transport,
            "host": host,
            "port": null,
            "tcp_reachable": false,
            "transport_capable": false,
            "probe_status": "unparseable",
            "probe_method": "none",
            "latency_ms": null,
            "iran_status": "iran_unknown",
            "evidence_scope": "No endpoint could be parsed; no reachability claim was made.",
            "composite_score": 0.0,
        });
    };

    let started = Instant::now();
    let connection = timeout(timeout_duration, TcpStream::connect((host.as_str(), port))).await;
    let (tcp_reachable, probe_status) = match connection {
        Ok(Ok(_stream)) => (true, "reachable"),
        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => (false, "refused"),
        Ok(Err(_)) => (false, "error"),
        Err(_) => (false, "timeout"),
    };
    let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let composite_score = if tcp_reachable { 0.6 } else { 0.0 };
    json!({
        "line": line,
        "transport": transport,
        "host": host,
        "port": port,
        "tcp_reachable": tcp_reachable,
        "transport_capable": false,
        "probe_status": probe_status,
        "probe_method": "tcp-connect",
        "latency_ms": latency,
        "iran_status": if tcp_reachable { "iran_unknown" } else { "tcp_unreachable" },
        "evidence_scope": "TCP connect from the CI runner only; this is not an Iran-vantage or full Tor-circuit test.",
        "composite_score": composite_score,
    })
}

fn read_lines(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let body = std::fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&body)?;
    let entries = value
        .as_array()
        .ok_or_else(|| invalid("bridge test input must be a JSON array of bridge strings"))?;
    Ok(entries
        .iter()
        .filter_map(Value::as_str)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid(format!("output has no valid file name: {}", path.display())))?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let mut body = serde_json::to_string_pretty(value)?;
    body.push('\n');
    std::fs::write(&temporary, body)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

async fn run(options: &Options) -> Result<Value, Box<dyn std::error::Error>> {
    let lines = read_lines(&options.input)?;
    if lines.len() > options.max_bridges {
        return Err(invalid(format!(
            "refusing to probe {} bridges; --max-bridges is {}",
            lines.len(),
            options.max_bridges
        )));
    }
    let started = chrono::Utc::now();
    let semaphore = Arc::new(Semaphore::new(options.workers));
    let mut tasks = JoinSet::new();
    for line in lines {
        let semaphore = Arc::clone(&semaphore);
        let timeout_duration = options.timeout;
        tasks.spawn(async move {
            let permit = semaphore
                .acquire_owned()
                .await
                .expect("probe semaphore is open");
            let result = probe_one(line, timeout_duration).await;
            drop(permit);
            result
        });
    }

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.map_err(|error| invalid(format!("probe task failed: {error}")))?);
    }
    results.sort_by(|left, right| {
        left.get("line")
            .and_then(Value::as_str)
            .cmp(&right.get("line").and_then(Value::as_str))
    });

    let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut transport_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut reachable = 0_usize;
    let mut capable = 0_usize;
    for result in &results {
        if result.get("tcp_reachable").and_then(Value::as_bool) == Some(true) {
            reachable += 1;
        }
        if result.get("transport_capable").and_then(Value::as_bool) == Some(true) {
            capable += 1;
        }
        if let Some(status) = result.get("probe_status").and_then(Value::as_str) {
            *status_counts.entry(status.to_string()).or_default() += 1;
        }
        if let Some(transport) = result.get("transport").and_then(Value::as_str) {
            *transport_counts.entry(transport.to_string()).or_default() += 1;
        }
    }
    Ok(json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "started_at": started.to_rfc3339(),
        "engine": "torshield-rust-bridge-tester-v1",
        "evidence_scope": "Bounded TCP reachability observations from the executing runner. No Iran-vantage, OONI, ASN, PT-handshake, or full Tor-circuit guarantee is implied.",
        "summary": {
            "total_tested": results.len(),
            "runner_tcp_reachable": reachable,
            "transport_capability_checks": capable,
            "probe_statuses": status_counts,
            "transports": transport_counts,
        },
        "bridges": results,
    }))
}

#[tokio::main]
async fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("bridge_tester: {error}");
        std::process::exit(2);
    });
    match run(&options).await {
        Ok(report) => {
            if let Err(error) = write_json(&options.output, &report) {
                eprintln!(
                    "bridge_tester: failed to write {}: {error}",
                    options.output.display()
                );
                std::process::exit(1);
            }
            let summary = &report["summary"];
            println!(
                "bridge_tester: tested={} runner_tcp_reachable={} capability_checks={} -> {}",
                summary["total_tested"],
                summary["runner_tcp_reachable"],
                summary["transport_capability_checks"],
                options.output.display()
            );
        }
        Err(error) => {
            eprintln!("bridge_tester: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snowflake_is_explicitly_capability_checked_not_falsely_tcp_tested() {
        let result = snowflake_capability_result("snowflake example".to_string());
        assert_eq!(result["tcp_reachable"], false);
        assert_eq!(result["transport_capable"], true);
        assert_eq!(result["iran_status"], "iran_unknown");
    }

    #[test]
    fn explicit_meek_transport_is_not_reclassified_by_its_https_url() {
        assert_eq!(
            normalise_transport(
                "meek_lite 192.0.2.1:80 url=https://cdn.example",
                "webtunnel"
            ),
            "meek_lite"
        );
    }
}

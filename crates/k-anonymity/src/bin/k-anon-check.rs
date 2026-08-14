//! The `k-anon-check` binary: demonstrates k-anonymity enforcement end-to-end.
//!
//! Feeds real `--report` inputs through the real batcher and prints what
//! actually happens to each one:
//!
//! ```text
//! k-anon-check --k 5 --report r1 --report r2 --report r3 --report r4
//!   → every report is HELD (below k = 5): nothing emitted, nothing leaked
//!
//! k-anon-check --k 3 --report r1 --report r2 --report r3
//!   → the 3rd submission EMITS the whole batch of 3 (JSON printed)
//! ```
//!
//! Exit codes: `0` the input was fully processed (held remainder is reported
//! as withheld, not dropped), `1` internal failure, `2` usage/input error.

use std::process::ExitCode;

use chrono::Utc;
use tbc_k_anonymity::{KAnonymityBatcher, Report, Submission};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    let (k, report_ids) = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    let mut batcher = match KAnonymityBatcher::new(k) {
        Ok(batcher) => batcher,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };

    println!("threshold k = {k}");
    let mut emitted_count = 0usize;

    for id in &report_ids {
        let submission = batcher.submit(Report::new(id.clone(), Utc::now()));
        match submission {
            Submission::Held { held } => {
                println!("  {id}: HELD (held {held}/{k} — below threshold, withheld)");
            }
            Submission::Emitted(batch) => {
                emitted_count += 1;
                let json = match serde_json::to_string_pretty(&batch) {
                    Ok(json) => json,
                    Err(error) => {
                        eprintln!("error: failed to serialize emitted batch: {error}");
                        return ExitCode::from(1);
                    }
                };
                println!(
                    "  {id}: EMITTED — whole batch of {} released together:",
                    batch.size
                );
                println!("{json}");
            }
        }
    }

    let remaining = batcher.held();
    if remaining > 0 {
        println!(
            "final state: {remaining} report(s) held and withheld (below k = {k}) — nothing leaked"
        );
    } else if emitted_count > 0 {
        println!("final state: all reports released as whole batches of at least k");
    } else {
        println!("final state: nothing emitted, everything withheld");
    }
    ExitCode::SUCCESS
}

/// Parse `--k <n>` and any number of `--report <id>` flags.
fn parse_args(args: &[String]) -> Result<(usize, Vec<String>), String> {
    let mut k = None;
    let mut reports = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--k" | "-k" => {
                index += 1;
                let raw = args
                    .get(index)
                    .ok_or_else(|| "--k requires a numeric argument".to_owned())?;
                let parsed: usize = raw
                    .parse()
                    .map_err(|_| format!("--k expects a positive integer, got {raw:?}"))?;
                if k.replace(parsed).is_some() {
                    return Err("--k given more than once".to_owned());
                }
            }
            "--report" | "-r" => {
                index += 1;
                let id = args
                    .get(index)
                    .ok_or_else(|| "--report requires an id argument".to_owned())?;
                reports.push(id.clone());
            }
            other => {
                return Err(format!("unknown argument {other:?} (see --help)"));
            }
        }
        index += 1;
    }

    let k = k.unwrap_or(5);
    if reports.is_empty() {
        return Err("at least one --report <id> is required".to_owned());
    }
    Ok((k, reports))
}

fn usage() -> String {
    "k-anon-check — TorShield-IR k-anonymity threshold enforcement\n\
\n\
USAGE:\n\
    k-anon-check [--k <n>] --report <id> [--report <id> ...]\n\
\n\
Feeds each report through the real k-anonymity batcher (default k = 5).\n\
Below k held reports, every submission is withheld. The k-th submission\n\
emits the whole batch as JSON. Exits 0 when the input was fully processed.\n"
        .to_owned()
}

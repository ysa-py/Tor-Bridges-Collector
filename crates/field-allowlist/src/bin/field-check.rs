//! The `field-check` binary: demonstrates the allowlist boundary end-to-end.
//!
//! Reads one JSON report object (or an array of them) from stdin and runs
//! every report through the real allowlist boundary:
//!
//! ```text
//! echo '[{"outcome":"success", ...all allowlisted fields...}]' | field-check
//!   → accepted, canonical allowlisted JSON printed (exit 0)
//!
//! echo '[{"outcome":"success", ...,"ip":"95.216.217.25"}]' | field-check
//!   → rejected: report contains a field outside the allowlist: "ip" (exit 1)
//!
//! echo '[{...token t...},{...token t...}]' | field-check --consume
//!   → the second report is rejected: one-time token reuse rejected (exit 1)
//! ```
//!
//! Exit codes: `0` every report passed the boundary, `1` any report was
//! rejected (processing stops at the first rejection), `2` usage/input error.

use std::io::Read;
use std::process::ExitCode;

use tbc_field_allowlist::{parse_report_value, FieldAllowlistError, TokenRegistry};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    let consume = match parse_flags(&args) {
        Ok(consume) => consume,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    let mut input = String::new();
    if let Err(error) = std::io::stdin().lock().read_to_string(&mut input) {
        eprintln!("error: could not read stdin: {error}");
        return ExitCode::from(2);
    }

    let payloads = match split_payloads(&input) {
        Ok(payloads) => payloads,
        Err(error) => {
            eprintln!("rejected: {error}");
            return ExitCode::from(1);
        }
    };

    let mut registry = TokenRegistry::new();
    let mut accepted = 0usize;

    for payload in payloads {
        let report = match parse_report_value(payload) {
            Ok(report) => report,
            Err(error) => {
                eprintln!("rejected: {error}");
                return ExitCode::from(1);
            }
        };
        if consume {
            if let Err(error) = registry.consume(&report.token) {
                eprintln!("rejected: {error}");
                return ExitCode::from(1);
            }
        }
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("accepted: {json}"),
            Err(error) => {
                eprintln!("error: could not serialize accepted report: {error}");
                return ExitCode::from(1);
            }
        }
        accepted += 1;
    }

    if consume {
        println!(
            "final state: {accepted} report(s) accepted; {} distinct token(s) consumed",
            registry.len()
        );
    } else {
        println!("final state: {accepted} report(s) accepted, all fields allowlisted");
    }
    ExitCode::SUCCESS
}

/// Parse `--consume` (and reject anything else).
fn parse_flags(args: &[String]) -> Result<bool, String> {
    let mut consume = false;
    for arg in args {
        match arg.as_str() {
            "--consume" => consume = true,
            other => return Err(format!("unknown argument {other:?} (see --help)")),
        }
    }
    Ok(consume)
}

/// Accept a single report object or an array of report objects.
fn split_payloads(input: &str) -> Result<Vec<serde_json::Value>, FieldAllowlistError> {
    let value: serde_json::Value = serde_json::from_str(input)?;
    match value {
        serde_json::Value::Array(items) => Ok(items),
        object @ serde_json::Value::Object(_) => Ok(vec![object]),
        _ => Err(FieldAllowlistError::InvalidPayload),
    }
}

fn usage() -> String {
    "field-check — TorShield-IR reported-field allowlist boundary\n\
\n\
USAGE:\n\
    field-check [--consume]\n\
\n\
Reads a JSON report object (or an array of them) from stdin and runs every\n\
report through the allowlist boundary. Only the five Phase-5 fields\n\
(outcome, rtt_bucket, asn_class, token, source) are accepted; any other\n\
field is rejected and named. With --consume, each report's one-time token\n\
is consumed, so a replayed report is rejected. Exits 0 when every report\n\
passed, 1 on the first rejection.\n"
        .to_owned()
}

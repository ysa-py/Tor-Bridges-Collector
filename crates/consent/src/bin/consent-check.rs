//! The `consent-check` binary: demonstrates the consent gate end-to-end.
//!
//! ```text
//! consent-check --yes   → records consent and prints the proof JSON (exit 0)
//! consent-check --no    → refuses, prints a typed refusal, emits no proof (exit 1)
//! consent-check         → reads one line from stdin and applies the same flow
//! ```
//!
//! Exit codes: `0` consented, `1` refused, `2` usage/input error.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    let answer = match flag_answer(&args) {
        Some(answer) => answer,
        None => match read_stdin_line() {
            Some(line) => line,
            None => {
                eprintln!("error: could not read a consent answer from stdin");
                return ExitCode::from(2);
            }
        },
    };

    let consented = match tbc_consent::parse_consent_input(&answer) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };

    if !consented {
        eprintln!("refused: consent not granted — no protected action was performed");
        return ExitCode::from(1);
    }

    let gate = tbc_consent::ConsentGate::new();
    gate.grant("consent-check");
    let proof = match gate.require() {
        Ok(proof) => proof,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };

    let json = match serde_json::to_string_pretty(&proof) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };

    println!("consent recorded:");
    println!("{json}");
    ExitCode::SUCCESS
}

/// Extract a `--yes`/`--no` answer, rejecting any other flag or extra
/// arguments. Returns `None` when no flag was given (meaning: read stdin).
fn flag_answer(args: &[String]) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    if args.len() > 1 {
        eprintln!("error: expected at most one argument");
        std::process::exit(2);
    }
    match args[0].as_str() {
        "--yes" | "-y" => Some("yes".to_owned()),
        "--no" | "-n" => Some("no".to_owned()),
        other => {
            eprintln!("error: unknown argument {other:?}");
            std::process::exit(2);
        }
    }
}

fn read_stdin_line() -> Option<String> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .ok()
        .map(|_| line.trim().to_owned())
}

fn usage() -> String {
    "consent-check — TorShield-IR volunteer consent gate\n\
\n\
USAGE:\n\
    consent-check [--yes | --no]\n\
\n\
With no flag, one line is read from stdin (y/yes or n/no).\n\
Exits 0 when consent is recorded, 1 when refused, 2 on bad input.\n"
        .to_owned()
}

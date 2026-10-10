//! Stamp this-run collection mode and, on a validation no-op, write valid
//! empty observation schemas so analytics do not `exit 1` on missing JSON.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use torshield_ir_ultra::this_run_snapshot::{apply, CollectionMode};

fn main() -> ExitCode {
    let mut mode = None;
    let mut reason = String::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                let value = args.next().unwrap_or_default();
                mode = Some(match value.as_str() {
                    "live" => CollectionMode::Live,
                    "validation_noop" | "validation-noop" => CollectionMode::ValidationNoop,
                    other => {
                        eprintln!("this_run_snapshot: unknown --mode {other}");
                        return ExitCode::from(2);
                    }
                });
            }
            "--reason" => {
                reason = args.next().unwrap_or_default();
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: this_run_snapshot --mode live|validation_noop [--reason TEXT]"
                );
                return ExitCode::SUCCESS;
            }
            unknown => {
                eprintln!("this_run_snapshot: unknown argument {unknown}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(mode) = mode else {
        eprintln!("this_run_snapshot: --mode is required");
        return ExitCode::from(2);
    };
    if reason.is_empty() {
        reason = match mode {
            CollectionMode::Live => "main-branch live collection".to_string(),
            CollectionMode::ValidationNoop => {
                "not the default branch; live collection stays on main".to_string()
            }
        };
    }
    match apply(Path::new("."), mode, &reason) {
        Ok(()) => {
            println!(
                "this_run_snapshot: mode={} live_collection={}",
                mode.as_str(),
                mode.live_collection()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("this_run_snapshot: {error}");
            ExitCode::from(1)
        }
    }
}

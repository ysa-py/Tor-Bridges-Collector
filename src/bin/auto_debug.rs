//! Rust-native auto-debug / self-healing diagnosis entry point.
//!
//! Replaces `python -m torshield_ai_gateway.auto_debug <workflow> <run_id>`,
//! which the completed Python→Rust migration retired. The diagnosis and
//! auto-fix logic lives in `src/auto_debug_system.rs`; this binary is the
//! CLI shim the `AI Self-Healing Engine` workflow invokes.
//!
//! Usage:
//!   auto_debug [WORKFLOW_NAME] [RUN_ID] [--fix] [--output PATH]
//!
//! The command is intentionally non-fatal: a diagnosis that finds problems
//! still exits 0 and records them in the report, because the caller treats
//! this as advisory (it previously ended in `|| true`). Only an I/O failure
//! writing the report is fatal.

use std::error::Error;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};
use torshield_ir_ultra::auto_debug_system::AutoDebugSystem;

struct Options {
    workflow: String,
    run_id: String,
    fix: bool,
    output: PathBuf,
}

fn parse_args() -> Result<Options, String> {
    let mut workflow = String::from("unknown");
    let mut run_id = String::from("unknown");
    let mut fix = false;
    let mut output = PathBuf::from("data/auto_debug_report.json");
    let mut positional = 0_usize;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--fix" => fix = true,
            "--output" => output = PathBuf::from(args.next().ok_or("--output requires a path")?),
            "--help" | "-h" => {
                println!("Usage: auto_debug [WORKFLOW] [RUN_ID] [--fix] [--output PATH]");
                std::process::exit(0);
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown argument: {other}"));
            }
            other => {
                match positional {
                    0 => workflow = other.to_string(),
                    1 => run_id = other.to_string(),
                    _ => return Err(format!("unexpected positional argument: {other}")),
                }
                positional += 1;
            }
        }
    }

    Ok(Options {
        workflow,
        run_id,
        fix,
        output,
    })
}

fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut body = serde_json::to_string_pretty(value)?;
    body.push('\n');
    std::fs::write(path, body)?;
    Ok(())
}

fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("auto_debug: {error}");
        std::process::exit(2);
    });

    let system = AutoDebugSystem::default_with_cwd();
    let diagnosis = if options.fix {
        system.auto_fix_all()
    } else {
        system.run_full_diagnosis()
    };

    let (status, payload) = match diagnosis {
        Ok(value) => ("ok", value),
        Err(error) => ("error", json!({ "error": error.to_string() })),
    };

    let report = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-auto-debug-v1",
        "workflow": options.workflow,
        "run_id": options.run_id,
        "mode": if options.fix { "auto-fix" } else { "diagnose" },
        "status": status,
        "diagnosis": payload,
    });

    if let Err(error) = write_json(&options.output, &report) {
        eprintln!("auto_debug: could not write report: {error}");
        std::process::exit(1);
    }

    println!(
        "auto_debug: {} diagnosis for workflow={} run_id={} -> {}",
        status,
        options.workflow,
        options.run_id,
        options.output.display()
    );
}

//! Whole-run Rust self-healing diagnostics entry point.
//!
//! Without `--log` this is the fast Stage 00 repository preflight.  With a
//! complete job log it performs the full detect -> diagnose -> remediation
//! plan -> safe repair -> verify -> report loop.  It never treats a green
//! process exit as proof that bridge collection was healthy.

use std::error::Error;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};
use torshield_ir_ultra::pipeline_diagnostics::{
    analyze_log_file, human_summary, report_json, safe_repairs, DiagnosticReport, RepairResult,
};

struct Options {
    heal: bool,
    strict: bool,
    log: Option<PathBuf>,
    output: PathBuf,
    repo_root: PathBuf,
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options {
        heal: false,
        strict: false,
        log: None,
        output: PathBuf::from("diagnostics/rust-self-heal.json"),
        repo_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--heal" => options.heal = true,
            "--strict" => options.strict = true,
            "--log" | "--job-log" => {
                options.log = Some(PathBuf::from(
                    args.next().ok_or("--log requires a path")?,
                ));
            }
            "--output" | "--report" => {
                options.output = PathBuf::from(args.next().ok_or("--output requires a path")?);
            }
            "--repo-root" => {
                options.repo_root = PathBuf::from(args.next().ok_or("--repo-root requires a path")?);
            }
            "--help" | "-h" => {
                println!(
                    "Usage: self_heal [--heal] [--strict] [--log PATH] [--output PATH] [--repo-root PATH]"
                );
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }
    Ok(options)
}

fn preflight(repo_root: &Path) -> Value {
    let required = [
        "Cargo.toml",
        "Cargo.lock",
        "src/lib.rs",
        "src/pipeline_diagnostics.rs",
        "bridge/iran_results.json",
        "scripts/self_heal.sh",
        "scripts/self_heal.ps1",
    ];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|path| !repo_root.join(path).is_file())
        .collect();
    json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-self-heal-v2",
        "status": if missing.is_empty() { "healthy" } else { "unhealthy" },
        "required_files_checked": required.len(),
        "missing_files": missing,
        "safe_repairs": [
            "ensure data directory",
            "initialise empty JSON output documents",
            "emit affected-stage retry plan",
        ],
    })
}

fn write_wrapper(
    output: &Path,
    preflight: &Value,
    diagnostics: Option<&DiagnosticReport>,
    repairs: &[RepairResult],
) -> Result<(), Box<dyn Error>> {
    let wrapper = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-self-heal-v2",
        "preflight": preflight,
        "diagnostics": diagnostics.map(report_json),
        "repairs": repairs,
        "status": diagnostics.map(|report| report.status.as_str()).unwrap_or_else(|| {
            preflight["status"].as_str().unwrap_or("unhealthy")
        }),
    });
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut body = serde_json::to_vec_pretty(&wrapper)?;
    body.push(b'\n');
    let temporary = output.with_file_name(format!(
        ".{}.tmp-{}",
        output.file_name().and_then(|name| name.to_str()).unwrap_or("report"),
        std::process::id()
    ));
    std::fs::write(&temporary, body)?;
    std::fs::rename(temporary, output)?;
    Ok(())
}

fn main() {
    let options = parse_args().unwrap_or_else(|error| {
        eprintln!("self_heal: {error}");
        std::process::exit(2);
    });
    let preflight = preflight(&options.repo_root);
    if preflight["status"] != "healthy" {
        eprintln!("self_heal: repository preflight is unhealthy");
    }

    let mut repairs = Vec::new();
    let diagnostics = match options.log.as_deref() {
        Some(log_path) => match analyze_log_file(log_path) {
            Ok(report) => {
                println!("{}", human_summary(&report));
                if options.heal {
                    repairs = safe_repairs(&options.repo_root, &report);
                    for repair in &repairs {
                        println!(
                            "self_heal: {} {} ({})",
                            repair.action, repair.path, repair.detail
                        );
                    }
                }
                Some(report)
            }
            Err(error) => {
                eprintln!("self_heal: cannot analyze {}: {error}", log_path.display());
                None
            }
        },
        None => None,
    };

    if let Err(error) = write_wrapper(&options.output, &preflight, diagnostics.as_ref(), &repairs) {
        eprintln!(
            "self_heal: cannot write {}: {error}",
            options.output.display()
        );
        std::process::exit(1);
    }
    // Keep the existing Stage 00 invocation advisory for backwards
    // compatibility. Callers that need a health gate use --strict.
    if options.strict {
        let preflight_bad = preflight["status"] != "healthy";
        let diagnostics_bad = diagnostics
            .as_ref()
            .is_some_and(|report| report.errors > 0 || report.warnings > 0 || report.unresolved > 0);
        if preflight_bad || diagnostics_bad || diagnostics.is_none() && options.log.is_some() {
            std::process::exit(1);
        }
    }
    println!("self_heal: report written to {}", options.output.display());
}

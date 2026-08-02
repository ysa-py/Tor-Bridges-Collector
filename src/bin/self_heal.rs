//! Rust-native self-healing preflight and diagnostics entry point.

use std::error::Error;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};

fn output_path() -> Result<PathBuf, String> {
    let mut output = PathBuf::from("diagnostics/rust-self-heal.json");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--heal" => {}
            "--output" => output = PathBuf::from(args.next().ok_or("--output requires a path")?),
            "--help" | "-h" => {
                println!("Usage: self_heal [--heal] [--output PATH]");
                std::process::exit(0);
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }
    Ok(output)
}

fn run(output: &Path) -> Result<Value, Box<dyn Error>> {
    let required = [
        "Cargo.toml",
        "Cargo.lock",
        "src/lib.rs",
        "bridge/iran_results.json",
        "scripts/self_heal.sh",
        "scripts/self_heal.ps1",
    ];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|path| !Path::new(path).is_file())
        .collect();
    let report = json!({
        "generated_at": Utc::now().to_rfc3339(),
        "engine": "torshield-rust-self-heal-v1",
        "status": if missing.is_empty() { "healthy" } else { "unhealthy" },
        "required_files_checked": required.len(),
        "missing_files": missing,
        "next_checks": [
            "cargo fmt --all -- --check",
            "cargo check --workspace --all-targets",
            "cargo clippy --workspace --all-targets -- -D warnings",
            "cargo test --workspace",
        ],
    });

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut body = serde_json::to_string_pretty(&report)?;
    body.push('\n');
    std::fs::write(output, body)?;
    if report["status"] != "healthy" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "one or more required project files are missing",
        )
        .into());
    }
    Ok(report)
}

fn main() {
    let output = output_path().unwrap_or_else(|error| {
        eprintln!("self_heal: {error}");
        std::process::exit(2);
    });
    match run(&output) {
        Ok(_) => println!("self_heal: healthy -> {}", output.display()),
        Err(error) => {
            eprintln!("self_heal: {error}");
            std::process::exit(1);
        }
    }
}

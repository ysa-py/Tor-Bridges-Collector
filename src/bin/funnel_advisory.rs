//! Pipeline funnel advisory entry point (additive, advisory-only).
//!
//! Reads the committed pipeline outputs, writes `data/funnel_advisory.json`
//! and emits GitHub Actions `::notice` annotations with the per-stage
//! funnel counts, the non-routable endpoint census, and the relay coverage
//! gap. Never modifies any pipeline file and never fails the workflow on a
//! data condition (only on an unwritable report).

use std::path::PathBuf;

use torshield_ir_ultra::pipeline_funnel_advisory::{
    build_funnel_report, emit_notices, REPORT_FILE,
};

fn main() {
    let repo_root = std::env::var("REPO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let output = PathBuf::from(REPORT_FILE);

    let report = build_funnel_report(&repo_root);
    emit_notices(&report);

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "funnel_advisory: cannot create {}: {error}",
                    parent.display()
                );
                std::process::exit(1);
            }
        }
    }
    let mut body = match serde_json::to_vec_pretty(&report) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("funnel_advisory: cannot serialize report: {error}");
            std::process::exit(1);
        }
    };
    body.push(b'\n');
    if let Err(error) = std::fs::write(&output, body) {
        eprintln!(
            "funnel_advisory: cannot write {}: {error}",
            output.display()
        );
        std::process::exit(1);
    }
    println!("funnel_advisory: report written to {}", output.display());
}

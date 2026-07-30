//! Rust-native entry point for deterministic ECH/fingerprint scoring.

use std::path::Path;

use torshield_ir_ultra::ech_fingerprint_evasion::{run_pipeline, NoProbe};

fn main() {
    let input = Path::new("bridge/bridge_list_for_testing.json");
    let report = Path::new("data/ech_report.json");
    let export = Path::new("export/ech_top_bridges.txt");

    if let Err(error) = run_pipeline(input, report, export, &NoProbe) {
        eprintln!("ech_fingerprint_evasion: {error}");
        std::process::exit(1);
    }
    println!(
        "ech_fingerprint_evasion: scored {} -> {}",
        input.display(),
        report.display()
    );
}

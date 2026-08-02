//! Rust-native entry point for anti-AI DPI bridge scoring.

use std::path::Path;

fn main() {
    let input = Path::new("bridge/bridge_list_for_testing.json");
    let report = Path::new("data/anti_ai_dpi_report.json");
    let export = Path::new("export/anti_ai_dpi_bridges.txt");

    if let Err(error) = torshield_ir_ultra::anti_ai_dpi::run_pipeline(input, report, export) {
        eprintln!("anti_ai_dpi: {error}");
        std::process::exit(1);
    }
    println!(
        "anti_ai_dpi: scored {} -> {}",
        input.display(),
        report.display()
    );
}

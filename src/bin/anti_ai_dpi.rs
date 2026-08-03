//! Rust-native entry point for anti-AI DPI bridge scoring.
//!
//! Runs both engines in the same invocation (additive, zero-error regime):
//!
//!   1. Python-parity `anti_ai_dpi` scoring (unchanged contract):
//!      `data/anti_ai_dpi_report.json` + `export/anti_ai_dpi_bridges.txt`.
//!   2. Iran DPI hardening engine (uTLS profile rotation + TLS ALPN
//!      mutation against TCP handshake inspection, SNI filtering and
//!      protocol-fingerprint detection):
//!      `data/iran_dpi_hardening_report.json`,
//!      `export/iran_dpi_hardened_bridges.txt` and
//!      `data/iran_dpi_tls_mutation_report.json`.

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

    let hardening_report = Path::new("data/iran_dpi_hardening_report.json");
    let hardening_export = Path::new("export/iran_dpi_hardened_bridges.txt");
    let mutation_report = Path::new("data/iran_dpi_tls_mutation_report.json");
    if let Err(error) = torshield_ir_ultra::anti_ai_dpi::run_hardened_pipeline(
        input,
        hardening_report,
        hardening_export,
        mutation_report,
    ) {
        eprintln!("anti_ai_dpi: hardened pipeline: {error}");
        std::process::exit(1);
    }
    println!(
        "anti_ai_dpi: hardened -> {} + {} + {}",
        hardening_report.display(),
        hardening_export.display(),
        mutation_report.display()
    );
}

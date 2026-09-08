//! Rust-native entry point for deterministic ECH/fingerprint scoring.

use std::path::Path;

use torshield_ir_ultra::ech_fingerprint_evasion::{
    enrich_with_relay_evidence, run_pipeline, NoProbe,
};
use torshield_ir_ultra::pipeline_funnel_advisory::read_json_file;

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

    // ADDITIVE (2026-09-08): join the freshly scored report with the live
    // probe-relay observations and stamp every entry with an honesty label
    // for the ECH status (static inference — no live handshake runs in CI)
    // plus the real relay reachability evidence. Enrichment failure is
    // non-fatal: the un-enriched report from run_pipeline stays on disk.
    if let Some(mut document) = read_json_file(report) {
        let relay = read_json_file(Path::new("data/pt_results.json"))
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        let enriched = enrich_with_relay_evidence(&mut document, &relay);
        let mut body = match serde_json::to_vec_pretty(&document) {
            Ok(body) => body,
            Err(error) => {
                eprintln!("ech_fingerprint_evasion: enrichment serialize failed: {error}");
                return;
            }
        };
        body.push(b'\n');
        if let Err(error) = std::fs::write(report, body) {
            eprintln!("ech_fingerprint_evasion: enrichment write failed: {error}");
            return;
        }
        println!(
            "ech_fingerprint_evasion: relay-evidence enrichment applied to {enriched} scored bridge(s)"
        );
    }
}

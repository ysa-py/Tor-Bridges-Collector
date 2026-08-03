//! Rust-native mass dynamic bridge ingestion engine.
//!
//! Harvests bridge candidates from BridgeDB, MOAT, Telegram previews,
//! OnionHop/community mirrors and the static built-in pool with ordered
//! per-source fallback, then merges everything into
//! `bridge/bridge_history.json` and rewrites
//! `bridge/bridge_list_for_testing.json`.
//!
//! Production usage (with live sources):
//!
//! ```text
//! cargo run --features network --bin mass_ingest [BRIDGE_DIR]
//! ```
//!
//! Default build (no `network` feature) merges the static seed only and
//! reports `"offline": true` — the workflow always enables `network`.

use std::path::PathBuf;

fn main() {
    let bridge_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("bridge"));
    match torshield_ir_ultra::mass_ingestion::run_mass_ingestion(&bridge_dir) {
        Ok(summary) => {
            println!(
                "mass_ingest: harvested {} lines ({} new to history, {} history records, {} testing candidates)",
                summary.lines_harvested,
                summary.lines_merged,
                summary.history_records,
                summary.testing_count
            );
        }
        Err(error) => {
            eprintln!("mass_ingest: {error}");
            std::process::exit(1);
        }
    }
}

//! Binary entry point for the advanced WebTunnel supply module.
//!
//! Runs the strictly-additive, fully-automated WebTunnel supply expansion
//! described in [`torshield_ir_ultra::webtunnel_supply_advanced`]: bounded
//! extra draws of the canonical WebTunnel pages (merged through the exact
//! existing validation/dedup pipeline), the automatic canonical-docs audit,
//! the probe-history sidecar update, and the additive diagnostics section.
//!
//! When the `network` feature is disabled the binary still runs: it writes
//! the diagnostics (all counters zero) and exits cleanly, mirroring the
//! core `scraper` and `supply_extender` binaries' offline behaviour.

use torshield_ir_ultra::webtunnel_supply_advanced::run_advanced_supply;

/// Network-backed path: performs the extra draws and the docs audit.
#[cfg(feature = "network")]
fn dispatch() -> Result<(), Box<dyn std::error::Error>> {
    let client = torshield_ir_ultra::scraper::ReqwestHttpFetch::new(
        std::time::Duration::from_secs(30),
    );
    run_advanced_supply(true, Some(&client), chrono::Utc::now().to_rfc3339())
}

/// Offline path: pure diagnostics pass with zero request counters.
#[cfg(not(feature = "network"))]
fn dispatch() -> Result<(), Box<dyn std::error::Error>> {
    run_advanced_supply(false, None, chrono::Utc::now().to_rfc3339())
}

fn main() {
    if let Err(error) = dispatch() {
        eprintln!("webtunnel_supply_advanced: {error}");
        std::process::exit(1);
    }
}

//! Rust-native OONI correlation entry point.
//!
//! The collection workflow invokes this with the `network` feature after the
//! bounded runner-side probe.  OONI responses are supplemental evidence: a
//! temporary API failure produces a neutral, recorded result rather than
//! fabricating an Iranian reachability claim or aborting bridge publication.

#[cfg(feature = "network")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;

    use chrono::Utc;
    use torshield_ir_ultra::ooni_correlator::{run_pipeline, ReqwestOoniHttpFetch};
    use torshield_ir_ultra::quarantine_manager::QuarantineManager;

    let mut quarantine = QuarantineManager::new_lenient(
        Path::new("data/quarantine_state.json"),
        Path::new("data/quarantine_events.jsonl"),
    );
    let client = ReqwestOoniHttpFetch::default();
    let outcome = run_pipeline(
        Path::new("bridge/iran_results.json"),
        Path::new("data/scheduler_results.json"),
        Path::new("data/latest-results.json"),
        Path::new("docs/iran-bridge-status.md"),
        &client,
        Utc::now(),
        7,
        Some(&mut quarantine),
    )?;
    println!(
        "ooni_correlator: total={} above_threshold={} pass_rate={:.1}% quality_gate={}",
        outcome.total,
        outcome.above_threshold,
        outcome.pass_rate * 100.0,
        if outcome.passed {
            "passed"
        } else {
            "advisory-warning"
        },
    );
    Ok(())
}

#[cfg(not(feature = "network"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "ooni_correlator requires cargo --features network",
    )))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ooni_correlator: {error}");
        std::process::exit(1);
    }
}

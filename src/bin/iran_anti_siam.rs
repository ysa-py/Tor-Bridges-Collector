//! Rust-native entry point for Iran SIAM scoring and export generation.

use std::path::Path;

use chrono::Utc;
use torshield_ir_ultra::iran_anti_siam::{real_score_all, run_pipeline};

fn main() {
    let result = run_pipeline(
        Path::new("bridge"),
        Path::new("data"),
        Path::new("export"),
        Path::new("docs"),
        Path::new("data/ja3_rotation_plan.json"),
        Utc::now(),
        real_score_all,
    );

    match result {
        Ok(output) => println!(
            "iran_anti_siam: scored {} bridges (phantom={}, stealth={})",
            output.total_scored, output.wrote_phantom, output.wrote_stealth
        ),
        Err(error) => {
            eprintln!("iran_anti_siam: {error}");
            std::process::exit(1);
        }
    }
}

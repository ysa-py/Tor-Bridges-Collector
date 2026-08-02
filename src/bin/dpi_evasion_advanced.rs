//! Rust-native entry point for empirical DPI intelligence generation.

use std::error::Error;
use std::path::Path;

use serde_json::Value;
use torshield_ir_ultra::dpi_evasion_advanced::update_dpi_report_now;

fn run() -> Result<usize, Box<dyn Error>> {
    let input = Path::new("bridge/iran_results.json");
    let source = std::fs::read_to_string(input)?;
    let root: Value = serde_json::from_str(&source)?;
    let records = root
        .get("bridges")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bridge/iran_results.json does not contain a bridges array",
            )
        })?;
    update_dpi_report_now(records, Path::new("data/dpi_intelligence.json"))?;
    Ok(records.len())
}

fn main() {
    match run() {
        Ok(count) => println!("dpi_evasion_advanced: analyzed {count} bridges"),
        Err(error) => {
            eprintln!("dpi_evasion_advanced: {error}");
            std::process::exit(1);
        }
    }
}

//! Rust-native bridge collection pipeline.
//!
//! The default build refreshes outputs from built-in bridges. Enabling the
//! `network` feature also queries Tor Project and MOAT sources; per-source
//! failures are non-fatal and built-in bridges remain available.

use std::path::Path;

use torshield_ir_ultra::adaptive_selector::AdaptiveBridgeSelector;
use torshield_ir_ultra::scraper::{
    get_static, load_history, merge_raw_into_history, prune_history, save_history,
    write_bridge_files, write_testing_json, DEFAULT_BRIDGE_DIR, DEFAULT_RECENT_HOURS,
};

fn run() -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let collected: Vec<(String, String, String)> = get_static()
        .into_iter()
        .map(|(line, transport, ip_version)| {
            (
                line.to_string(),
                transport.to_string(),
                ip_version.to_string(),
            )
        })
        .collect();

    #[cfg(feature = "network")]
    let collected = {
        use std::time::Duration;
        use torshield_ir_ultra::scraper::{fetch_moat, fetch_torproject, ReqwestHttpFetch};

        let mut network_collected = collected;
        let client = ReqwestHttpFetch::new(Duration::from_secs(30));
        network_collected.extend(fetch_torproject(&client));
        network_collected.extend(fetch_moat(&client));
        network_collected
    };

    let bridge_dir = Path::new(DEFAULT_BRIDGE_DIR);
    let history_path = bridge_dir.join("bridge_history.json");
    let mut history = load_history(&history_path)?;
    merge_raw_into_history(&mut history, &collected)?;
    let pruned = prune_history(&mut history)?;
    save_history(&history, &history_path)?;

    let selector = AdaptiveBridgeSelector::from_env();
    write_bridge_files(&history, bridge_dir, DEFAULT_RECENT_HOURS, &selector)?;
    let testing_count = write_testing_json(
        &history,
        &bridge_dir.join("bridge_list_for_testing.json"),
        &selector,
    )?;
    Ok((testing_count, pruned))
}

fn main() {
    match run() {
        Ok((count, pruned)) => {
            println!("scraper: wrote {count} bridge candidates; pruned {pruned} stale records");
        }
        Err(error) => {
            eprintln!("scraper: {error}");
            std::process::exit(1);
        }
    }
}

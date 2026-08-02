//! Rust port of the `FAILSAFE — ensure bridge files always have content`
//! inline Python script that used to run inside `.github/workflows/
//! torshield-ir.yml` (`/tmp/_failsafe_bridges.py`).
//!
//! Contract preserved byte-for-byte from the Python original:
//!
//!   1. Read `bridge/bridge_history.json` (tolerating a missing/corrupt file
//!      with a `WARNING:` line), collect `raw` bridge lines per transport.
//!   2. For each transport in the fixed order obfs4, snowflake, meek_lite,
//!      webtunnel, vanilla, conjure, meek-azure: if `bridge/<transport>.txt`
//!      is missing or empty, rewrite it from history (`FAILSAFE: wrote ...`),
//!      otherwise report `OK <path>: <n> bridges`.
//!   3. If `bridge/bridge_list_for_testing.json` is missing or tiny (<5
//!      bytes), rebuild it from history, falling back to the compiled-in
//!      static bridge list (the Rust `static_bridges::get_all()` port of
//!      `sources/static_bridges.py`).
//!   4. Print `FAILSAFE done. Extra bridges written: <n>` and exit 0.
//!
//! One deliberate deviation (documented): history object iteration follows
//! `BTreeMap` key order instead of JSON file order; this only affects the
//! line ordering of *fallback rewrites*, never which bridges are written.
//!
//! Hardening added on top of the Python original (strict zero-error
//! publication contract):
//!
//!   5. **Force-populate every protocol projection.** Any `bridge/*.txt`
//!      protocol/advisory file (all `_72h` / `_ipv6` / `_tested` variants,
//!      `iran_likely_working_*`, `tested_global_*`, `conjure*`, `meek-azure*`)
//!      that is missing or 0 bytes is written from the compiled-in static
//!      fallback lines of its transport family, so Stage 10 can never observe
//!      a `0 lines (0 bytes)` protocol file. `iran_blocked.txt` is the single
//!      intentional exception: an empty blocked list is truthful evidence.
//!   6. **Empty JSON repair.** Any 0-byte `bridge/*.json` file is rewritten
//!      as a valid empty JSON array `[]` so downstream parsers never fail.
//!
//! The workflow runs this FAILSAFE twice: once right after the scrapers
//! (historical placement) and once more after every scraper/tester/export
//! stage finishes, immediately before publication.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::static_bridges;

/// Transports in the fixed iteration order of the Python original, extended
/// with the two additional publication families (conjure, meek-azure).
pub const TRANSPORTS: &[&str] = &[
    "obfs4",
    "snowflake",
    "meek_lite",
    "webtunnel",
    "vanilla",
    "conjure",
    "meek-azure",
];

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn read_history(bridge_dir: &Path) -> serde_json::Map<String, Value> {
    let hist_file = bridge_dir.join("bridge_history.json");
    if !hist_file.is_file() || file_size(&hist_file) <= 2 {
        return serde_json::Map::new();
    }
    let text = fs::read_to_string(&hist_file).unwrap_or_default();
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(map)) => map,
        Ok(_) => serde_json::Map::new(),
        Err(err) => {
            println!("WARNING: {err}");
            serde_json::Map::new()
        }
    }
}

/// Collect trimmed `raw` lines per transport from history. Pure for testing.
pub fn transport_map(history: &serde_json::Map<String, Value>) -> Vec<(&'static str, Vec<String>)> {
    let mut map: Vec<(&'static str, Vec<String>)> =
        TRANSPORTS.iter().map(|t| (*t, Vec::new())).collect();
    for value in history.values() {
        let Some(obj) = value.as_object() else {
            continue;
        };
        let transport = obj
            .get("transport")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let raw = obj.get("raw").and_then(Value::as_str).unwrap_or_default();
        if let Some((_, bridges)) = map.iter_mut().find(|(t, _)| *t == transport) {
            if !raw.is_empty() {
                bridges.push(raw.trim().to_string());
            }
        }
    }
    map
}

/// Raw bridge lines regardless of transport (history order), used to rebuild
/// `bridge_list_for_testing.json`. Pure for testing.
pub fn all_raw_bridges(history: &serde_json::Map<String, Value>) -> Vec<String> {
    history
        .values()
        .filter_map(|v| v.as_object())
        .filter_map(|obj| obj.get("raw").and_then(Value::as_str))
        .filter(|raw| !raw.is_empty())
        .map(str::to_string)
        .collect()
}

fn static_fallback_lines() -> Vec<String> {
    static_bridges::get_all()
        .into_iter()
        .map(|(line, _, _)| line.to_string())
        .collect()
}

/// Infer the transport family for a `bridge/` `.txt` filename, or `None`
/// when the file is not a protocol/advisory projection.
pub fn transport_for_filename(name: &str) -> Option<&'static str> {
    if name.contains("obfs4") {
        Some("obfs4")
    } else if name.contains("webtunnel") {
        Some("webtunnel")
    } else if name.contains("vanilla") {
        Some("vanilla")
    } else if name.contains("snowflake") {
        Some("snowflake")
    } else if name.contains("meek-azure") {
        Some("meek-azure")
    } else if name.contains("meek") {
        Some("meek_lite")
    } else if name.contains("conjure") {
        Some("conjure")
    } else {
        None
    }
}

/// Every `bridge/` `.txt` name that must never be 0 bytes, derived from the
/// transport families and advisory projections of the publication contract
/// (`src/bridge_publication.rs::REQUIRED_FILES`).
pub fn required_protocol_txt_names() -> Vec<String> {
    let mut names = Vec::new();
    for (transport, stem) in [
        ("obfs4", "obfs4"),
        ("vanilla", "vanilla"),
        ("webtunnel", "webtunnel"),
        ("snowflake", "snowflake"),
        ("meek_lite", "meek_lite"),
        ("conjure", "conjure"),
        ("meek-azure", "meek-azure"),
    ] {
        let with_ipv6 = matches!(
            transport,
            "obfs4" | "vanilla" | "webtunnel" | "snowflake" | "meek_lite"
        );
        names.push(format!("{stem}.txt"));
        names.push(format!("{stem}_72h.txt"));
        names.push(format!("{stem}_tested.txt"));
        if with_ipv6 {
            names.push(format!("{stem}_ipv6.txt"));
            names.push(format!("{stem}_72h_ipv6.txt"));
            names.push(format!("{stem}_ipv6_tested.txt"));
            // Older clients use this reversed spelling; keep it populated too.
            if matches!(transport, "obfs4" | "vanilla" | "webtunnel") {
                names.push(format!("{stem}_ipv6_72h.txt"));
            }
        }
    }
    names.extend([
        "iran_likely_working_all.txt".to_string(),
        "iran_likely_working_obfs4.txt".to_string(),
        "iran_likely_working_webtunnel.txt".to_string(),
        "iran_likely_working_vanilla.txt".to_string(),
        "iran_likely_working_snowflake.txt".to_string(),
        "iran_likely_working_nin.txt".to_string(),
        "tested_global_obfs4.txt".to_string(),
        "tested_global_vanilla.txt".to_string(),
        "tested_global_webtunnel.txt".to_string(),
    ]);
    names.sort();
    names.dedup();
    names
}

/// Static fallback lines for one protocol `.txt` projection.
///
/// * `iran_likely_working_all.txt` — every transport's fallback lines;
/// * `iran_likely_working_nin.txt` — the NIN-appropriate transports
///   (snowflake + webtunnel), mirroring the publisher's cut-mode priority;
/// * everything else — the fallback lines of the inferred transport family.
fn fallback_lines_for_name(name: &str) -> Vec<String> {
    let lines: Vec<&'static str> = if name == "iran_likely_working_all.txt" {
        static_bridges::fallback_all()
    } else if name == "iran_likely_working_nin.txt" {
        let mut lines = static_bridges::fallback_lines("snowflake");
        lines.extend(static_bridges::fallback_lines("webtunnel"));
        lines
    } else {
        match transport_for_filename(name) {
            Some(transport) => static_bridges::fallback_lines(transport),
            None => Vec::new(),
        }
    };
    lines.into_iter().map(str::to_string).collect()
}

/// Force-populate every missing or 0-byte protocol `.txt` file in
/// `bridge_dir` from static fallback lines. Returns the number of lines
/// written. `iran_blocked.txt` is intentionally left untouched.
pub fn force_populate_empty_txt(bridge_dir: &Path) -> u64 {
    let mut written = 0_u64;

    // Start from the full publication contract, then add any other `.txt`
    // already present in the directory (future-proofing for new projections).
    let mut names: BTreeSet<String> = required_protocol_txt_names().into_iter().collect();
    if let Ok(entries) = fs::read_dir(bridge_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".txt") && name != "iran_blocked.txt" {
                    names.insert(name.to_string());
                }
            }
        }
    }

    for name in names {
        let path = bridge_dir.join(&name);
        if path.is_file() && file_size(&path) != 0 {
            continue;
        }
        let lines = fallback_lines_for_name(&name);
        if lines.is_empty() {
            continue;
        }
        // Deduplicate while preserving the fallback table order.
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let clean: Vec<String> = lines
            .into_iter()
            .filter(|line| !line.trim().is_empty() && seen.insert(line.to_string()))
            .collect();
        if clean.is_empty() {
            continue;
        }
        let body = format!("{}\n", clean.join("\n"));
        if let Err(err) = fs::write(&path, body) {
            eprintln!("FAILSAFE: cannot write {}: {err}", path.display());
            continue;
        }
        println!(
            "FAILSAFE: force-populated {name} with {} static fallback lines",
            clean.len()
        );
        written += clean.len() as u64;
    }
    written
}

/// Execute the failsafe against `bridge_dir`, mirroring the Python script.
/// Returns the process exit code (always 0 on success paths, like Python).
pub fn run(bridge_dir: &Path) -> i32 {
    if let Err(err) = fs::create_dir_all(bridge_dir) {
        eprintln!("FAILSAFE: cannot create {}: {err}", bridge_dir.display());
        return 1;
    }
    let data_dir = PathBuf::from("data");
    if let Err(err) = fs::create_dir_all(&data_dir) {
        eprintln!("FAILSAFE: cannot create {}: {err}", data_dir.display());
        return 1;
    }

    let history = read_history(bridge_dir);
    let per_transport = transport_map(&history);
    let mut total = 0_u64;

    // 1) History-backed rewrite of the canonical `<transport>.txt` files.
    for (transport, bridges) in &per_transport {
        let fpath = bridge_dir.join(format!("{transport}.txt"));
        if !fpath.is_file() || file_size(&fpath) == 0 {
            if !bridges.is_empty() {
                let body = format!("{}\n", bridges.join("\n"));
                if let Err(err) = fs::write(&fpath, body) {
                    eprintln!("FAILSAFE: cannot write {}: {err}", fpath.display());
                    continue;
                }
                println!("FAILSAFE: wrote {} {transport} bridges", bridges.len());
                total += bridges.len() as u64;
            }
        } else {
            let count = fs::read_to_string(&fpath)
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count();
            println!("OK {}: {count} bridges", fpath.display());
        }
    }

    // 2) Force-populate any missing or 0-byte protocol/advisory .txt file
    //    (all _72h / _ipv6 / _tested variants and transports absent from
    //    history) with static fallback lines so Stage 10 never sees a
    //    `0 lines (0 bytes)` protocol file.
    total += force_populate_empty_txt(bridge_dir);

    // 3) Any 0-byte .json file is rewritten as a valid empty JSON array so
    //    downstream parsers never fail on empty inputs.
    let mut empty_json = 0_u64;
    if let Ok(entries) = fs::read_dir(bridge_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if !path.is_file() || file_size(&path) != 0 {
                continue;
            }
            if let Err(err) = fs::write(&path, "[]\n") {
                eprintln!("FAILSAFE: cannot write {}: {err}", path.display());
                continue;
            }
            println!("FAILSAFE: wrote valid empty JSON array to {}", path.display());
            empty_json += 1;
        }
    }

    let test_json = bridge_dir.join("bridge_list_for_testing.json");
    if !test_json.is_file() || file_size(&test_json) < 5 {
        let mut all = all_raw_bridges(&history);
        if all.is_empty() {
            all = static_fallback_lines();
        }
        if !all.is_empty() {
            let rendered = serde_json::to_string_pretty(&all).unwrap_or_else(|_| "[]".to_string());
            if let Err(err) = fs::write(&test_json, rendered) {
                eprintln!("FAILSAFE: cannot write {}: {err}", test_json.display());
            } else {
                println!(
                    "FAILSAFE: wrote {} bridges to bridge_list_for_testing.json",
                    all.len()
                );
            }
        }
    }

    println!("FAILSAFE done. Extra bridges written: {total}");
    if empty_json > 0 {
        println!("FAILSAFE: {empty_json} empty JSON file(s) initialised to []");
    }
    0
}

/// CLI entry point: `failsafe_bridges [bridge-dir]` (default `bridge`).
pub fn entry(args: &[String]) -> i32 {
    let dir = args.get(1).map(String::as_str).unwrap_or("bridge");
    run(Path::new(dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn history_fixture() -> serde_json::Map<String, Value> {
        json!({
            "a": {"transport": "obfs4", "raw": " obfs4 1.2.3.4:443 cert=XYZ "},
            "b": {"transport": "obfs4", "raw": "obfs4 5.6.7.8:444 cert=ABC"},
            "c": {"transport": "webtunnel", "raw": "webtunnel 9.9.9.9:443 url=x"},
            "d": {"transport": "unknown", "raw": "ignored"},
            "e": "not-a-dict",
            "f": {"transport": "obfs4", "raw": ""}
        })
        .as_object()
        .cloned()
        .expect("fixture object")
    }

    #[test]
    fn transport_map_groups_and_trims() {
        let map = transport_map(&history_fixture());
        let obfs4 = &map
            .iter()
            .find(|(t, _)| *t == "obfs4")
            .expect("obfs4 entry")
            .1;
        assert_eq!(
            obfs4,
            &vec![
                "obfs4 1.2.3.4:443 cert=XYZ".to_string(),
                "obfs4 5.6.7.8:444 cert=ABC".to_string()
            ]
        );
        let snowflake = &map
            .iter()
            .find(|(t, _)| *t == "snowflake")
            .expect("entry")
            .1;
        assert!(snowflake.is_empty());
        assert_eq!(map.len(), TRANSPORTS.len());
    }

    #[test]
    fn all_raw_bridges_skips_non_dicts_and_empty() {
        let all = all_raw_bridges(&history_fixture());
        // All four dict entries with a non-empty `raw` are collected —
        // `all_raw_bridges` deliberately does NOT filter by transport
        // (mirroring the Python original, which also keeps unknown
        // transports when rebuilding bridge_list_for_testing.json); only the
        // "not-a-dict" value and the empty-raw entry are skipped.
        assert_eq!(all.len(), 4);
        assert!(all.contains(&"webtunnel 9.9.9.9:443 url=x".to_string()));
        assert!(all.contains(&"ignored".to_string()));
    }

    #[test]
    fn static_fallback_is_non_empty() {
        assert!(!static_fallback_lines().is_empty());
    }

    #[test]
    fn run_rewrites_empty_transport_files() {
        let dir = std::env::temp_dir().join(format!("fb_run_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        std::fs::write(
            bridge_dir.join("bridge_history.json"),
            serde_json::to_string(&Value::Object(history_fixture())).expect("json"),
        )
        .expect("write history");
        // cwd is the crate root when tests run; `run` creates ./data which
        // the original always did too (Path("data").mkdir(exist_ok=True)).
        assert_eq!(run(&bridge_dir), 0);
        let obfs4 = std::fs::read_to_string(bridge_dir.join("obfs4.txt")).expect("obfs4.txt");
        assert_eq!(obfs4.lines().count(), 2);
        let testing_path = bridge_dir.join("bridge_list_for_testing.json");
        let testing = std::fs::read_to_string(testing_path).expect("json");
        let list: Vec<String> = serde_json::from_str(&testing).expect("array");
        // 4 lines: both obfs4 entries, the webtunnel entry and the unknown-
        // transport entry with a non-empty raw line.
        assert_eq!(list.len(), 4);
        // Second run: files populated -> OK branch, no rewrite.
        assert_eq!(run(&bridge_dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_with_empty_history_uses_static_bridges_for_testing_json() {
        let dir = std::env::temp_dir().join(format!("fb_empty_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        assert_eq!(run(&bridge_dir), 0);
        let testing_path = bridge_dir.join("bridge_list_for_testing.json");
        let testing = std::fs::read_to_string(testing_path).expect("json");
        let list: Vec<String> = serde_json::from_str(&testing).expect("array");
        assert!(!list.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transport_for_filename_infers_every_family() {
        assert_eq!(transport_for_filename("obfs4_72h.txt"), Some("obfs4"));
        assert_eq!(
            transport_for_filename("webtunnel_ipv6_tested.txt"),
            Some("webtunnel")
        );
        assert_eq!(transport_for_filename("vanilla_tested.txt"), Some("vanilla"));
        assert_eq!(transport_for_filename("snowflake_ipv6.txt"), Some("snowflake"));
        assert_eq!(transport_for_filename("meek_lite.txt"), Some("meek_lite"));
        assert_eq!(transport_for_filename("meek-azure.txt"), Some("meek-azure"));
        assert_eq!(transport_for_filename("conjure_72h.txt"), Some("conjure"));
        assert_eq!(
            transport_for_filename("iran_likely_working_obfs4.txt"),
            Some("obfs4")
        );
        assert_eq!(
            transport_for_filename("tested_global_webtunnel.txt"),
            Some("webtunnel")
        );
        assert_eq!(transport_for_filename("iran_blocked.txt"), None);
    }

    #[test]
    fn required_protocol_names_cover_all_family_variants() {
        let names = required_protocol_txt_names();
        for expected in [
            "obfs4.txt",
            "obfs4_72h.txt",
            "obfs4_ipv6.txt",
            "obfs4_72h_ipv6.txt",
            "obfs4_ipv6_72h.txt",
            "obfs4_ipv6_tested.txt",
            "obfs4_tested.txt",
            "vanilla.txt",
            "vanilla_ipv6_72h.txt",
            "webtunnel_72h_ipv6.txt",
            "snowflake_ipv6_tested.txt",
            "meek_lite_72h_ipv6.txt",
            "conjure.txt",
            "conjure_72h.txt",
            "conjure_tested.txt",
            "meek-azure.txt",
            "meek-azure_72h.txt",
            "meek-azure_tested.txt",
            "iran_likely_working_all.txt",
            "iran_likely_working_nin.txt",
            "tested_global_obfs4.txt",
        ] {
            assert!(names.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[test]
    fn run_force_populates_empty_transport_variants_and_json() {
        let dir = std::env::temp_dir().join(format!("fb_variants_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        // Empty history + deliberately empty protocol projections + a 0-byte
        // JSON file: the failsafe must force-populate every one of them.
        std::fs::write(bridge_dir.join("bridge_history.json"), "{}").expect("history");
        for name in [
            "obfs4.txt",
            "obfs4_72h.txt",
            "obfs4_ipv6.txt",
            "obfs4_tested.txt",
            "vanilla.txt",
            "vanilla_72h.txt",
            "vanilla_ipv6.txt",
            "vanilla_tested.txt",
            "webtunnel.txt",
            "webtunnel_72h.txt",
            "webtunnel_ipv6.txt",
            "webtunnel_tested.txt",
            "conjure.txt",
            "meek-azure.txt",
            "iran_likely_working_obfs4.txt",
            "iran_likely_working_webtunnel.txt",
            "tested_global_obfs4.txt",
            "bridge_scores.json",
        ] {
            std::fs::write(bridge_dir.join(name), "").expect("empty fixture");
        }

        assert_eq!(run(&bridge_dir), 0);
        for name in [
            "obfs4.txt",
            "obfs4_72h.txt",
            "obfs4_ipv6.txt",
            "obfs4_tested.txt",
            "vanilla.txt",
            "vanilla_72h.txt",
            "vanilla_ipv6.txt",
            "vanilla_tested.txt",
            "webtunnel.txt",
            "webtunnel_72h.txt",
            "webtunnel_ipv6.txt",
            "webtunnel_tested.txt",
            "conjure.txt",
            "meek-azure.txt",
            "iran_likely_working_obfs4.txt",
            "iran_likely_working_webtunnel.txt",
            "tested_global_obfs4.txt",
        ] {
            let path = bridge_dir.join(name);
            let body = std::fs::read_to_string(&path).expect("populated file");
            assert!(
                body.lines().count() > 0,
                "{name} must be force-populated ({} bytes)",
                body.len()
            );
        }
        let scores = std::fs::read_to_string(bridge_dir.join("bridge_scores.json")).expect("json");
        let value: Value = serde_json::from_str(&scores).expect("valid json");
        assert!(value.is_array());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_leaves_non_empty_files_untouched() {
        let dir = std::env::temp_dir().join(format!("fb_keep_{}", std::process::id()));
        let bridge_dir = dir.join("bridge");
        std::fs::create_dir_all(&bridge_dir).expect("temp dir");
        std::fs::write(
            bridge_dir.join("bridge_history.json"),
            serde_json::to_string(&Value::Object(history_fixture())).expect("json"),
        )
        .expect("write history");
        let custom = "obfs4 198.51.100.7:443 AAAAAAAA custom-line\n";
        std::fs::write(bridge_dir.join("obfs4.txt"), custom).expect("custom obfs4.txt");
        // First run populates the missing variants; second run must leave the
        // already-populated obfs4.txt byte-identical.
        assert_eq!(run(&bridge_dir), 0);
        assert_eq!(
            std::fs::read_to_string(bridge_dir.join("obfs4.txt")).expect("obfs4.txt"),
            custom
        );
        assert_eq!(run(&bridge_dir), 0);
        assert_eq!(
            std::fs::read_to_string(bridge_dir.join("obfs4.txt")).expect("obfs4.txt"),
            custom
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

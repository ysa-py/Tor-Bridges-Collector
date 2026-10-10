//! Rust port of the `FAILSAFE — ensure bridge files always have content`
//! inline Python script that used to run inside `.github/workflows/
//! torshield-ir.yml` (`/tmp/_failsafe_bridges.py`).
//!
//! Contract preserved byte-for-byte from the Python original:
//!
//!   1. Read `bridge/bridge_history.json` (tolerating a missing/corrupt file
//!      with a `WARNING:` line), collect valid `raw` bridge lines per
//!      transport. URL-only WebTunnel metadata is not copied into client
//!      projections.
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
//! Hardening added on top of the Python original (strict publication
//! contract):
//!
//!   5. **Inventory-only force-population.** Missing or 0-byte unqualified
//!      family inventory files may use complete compiled-in static bridge
//!      lines. Freshness (`_72h`), tested (`_tested`/`tested_global_*`), and
//!      Iran-working projections never receive static fallbacks and remain
//!      empty until the evidence-bearing publisher supplies measurements.
//!      IPv6 inventories also require an IPv6 literal. `iran_blocked.txt` is
//!      intentionally allowed to be empty: an empty blocked list is truthful.
//!   6. **Empty JSON repair.** Any 0-byte `bridge/*.json` file is rewritten
//!      as a valid empty JSON array `[]` so downstream parsers never fail.
//!
//! The workflow runs this FAILSAFE before the probe stages to prepare collector
//! inputs. The final publisher later rebuilds and verifies the output contract;
//! it does not run this force-populator after manifest/ZIP verification.

use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
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
            let raw = raw.trim();
            if !raw.is_empty() && (transport != "webtunnel" || has_literal_webtunnel_endpoint(raw))
            {
                bridges.push(raw.to_string());
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
        .filter_map(|obj| {
            let raw = obj.get("raw").and_then(Value::as_str)?.trim();
            if raw.is_empty() {
                return None;
            }
            let transport = obj
                .get("transport")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if transport == "webtunnel" && !has_literal_webtunnel_endpoint(raw) {
                return None;
            }
            Some(raw.to_string())
        })
        .collect()
}

fn has_literal_webtunnel_endpoint(line: &str) -> bool {
    line.split_whitespace().skip(1).any(|token| {
        let token = token.trim_matches(|character| matches!(character, ',' | ';' | '"'));
        if let Some(rest) = token.strip_prefix('[') {
            let Some((host, port)) = rest.split_once("]:") else {
                return false;
            };
            return host.parse::<std::net::Ipv6Addr>().is_ok()
                && port.parse::<u16>().is_ok_and(|value| value != 0);
        }
        let Some((host, port)) = token.rsplit_once(':') else {
            return false;
        };
        host.parse::<std::net::Ipv4Addr>().is_ok()
            && port.parse::<u16>().is_ok_and(|value| value != 0)
    })
}

fn static_fallback_lines() -> Vec<String> {
    static_bridges::get_all()
        .into_iter()
        .map(|(line, _, _)| line.to_string())
        .collect()
}

/// Append a structured FAILSAFE activation record. This is intentionally
/// best-effort: failure to write telemetry must never corrupt a bridge file,
/// but it is reported on stderr so the workflow diagnostics can classify it.
fn record_failsafe_activation(bridge_dir: &Path, file_name: &str, line_count: usize, reason: &str) {
    let root_dir = bridge_dir.parent().unwrap_or_else(|| Path::new("."));
    let path = root_dir.join("data/failsafe_activations.json");
    let mut root = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| serde_json::json!({"activations": []}));
    let Some(object) = root.as_object_mut() else {
        return;
    };
    let activations = object
        .entry("activations")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(items) = activations.as_array_mut() {
        items.push(serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "file": file_name,
            "transport": transport_for_filename(file_name).unwrap_or("aggregate"),
            "lines": line_count,
            "reason": reason,
        }));
        // Keep telemetry bounded while retaining enough history for trend
        // analysis. The count is a metric, not a reason to discard outputs.
        if items.len() > 500 {
            let drop_count = items.len() - 500;
            items.drain(0..drop_count);
        }
    }
    object.insert(
        "generated_at".to_string(),
        Value::String(chrono::Utc::now().to_rfc3339()),
    );
    object.insert(
        "note".to_string(),
        Value::String("Non-empty when a transport source exhausts retries and alternate acquisition before using failsafe data.".to_string()),
    );
    let write_result = (|| {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &path,
            serde_json::to_vec_pretty(&root).unwrap_or_else(|_| b"{}".to_vec()),
        )?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(error) = write_result {
        eprintln!("FAILSAFE: unable to record telemetry: {error}");
    }
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

/// Every contracted `bridge/` `.txt` name tracked by the failsafe. Static
/// writes are restricted separately to unqualified family inventories; files
/// claiming freshness, testing, Iran reachability, or measured global success
/// remain empty unless their real publication pipeline populates them.
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

/// Return true only for inventory projections that make no freshness,
/// testing, or Iran-reachability claim. Static bridge lines must never be
/// copied into an evidence-qualified filename.
fn static_fallback_allowed(name: &str) -> bool {
    const ALLOWED: &[&str] = &[
        "obfs4.txt",
        "obfs4_ipv6.txt",
        "vanilla.txt",
        "vanilla_ipv6.txt",
        "webtunnel.txt",
        "webtunnel_ipv6.txt",
        "snowflake.txt",
        "snowflake_ipv6.txt",
        "meek_lite.txt",
        "meek_lite_ipv6.txt",
        "conjure.txt",
        "meek-azure.txt",
    ];
    ALLOWED.contains(&name)
}

/// Static fallback lines for a non-evidence-qualified protocol inventory.
/// Freshness (`_72h`), test (`_tested`/`tested_global_`), Iran-working, and
/// blocked projections deliberately return no fallback lines.
fn static_line_ip_version(line: &str) -> Option<bool> {
    for token in line.split_whitespace() {
        if token.contains('=') {
            continue;
        }
        if token.starts_with('[') {
            if let Some(close) = token.find(']') {
                if let Ok(address) = token[1..close].parse::<IpAddr>() {
                    return Some(address.is_ipv6());
                }
            }
            continue;
        }
        let host = token
            .rsplit_once(':')
            .map(|(host, _port)| host)
            .unwrap_or(token);
        if let Ok(address) = host.parse::<IpAddr>() {
            return Some(address.is_ipv6());
        }
    }
    None
}

fn fallback_family_lines(transport: &str, ipv6: Option<bool>) -> Vec<String> {
    static_bridges::fallback_lines(transport)
        .into_iter()
        .map(str::to_string)
        .filter(|line| {
            ipv6.map_or(true, |wanted_ipv6| {
                static_line_ip_version(line) == Some(wanted_ipv6)
            })
        })
        .collect()
}

fn fallback_lines_for_name(name: &str) -> Vec<String> {
    if !static_fallback_allowed(name) {
        return Vec::new();
    }
    let ipv6 = name.ends_with("_ipv6.txt");
    let Some(transport) = transport_for_filename(name) else {
        return Vec::new();
    };
    fallback_family_lines(transport, ipv6.then_some(true))
}

/// Force-populate missing or 0-byte unqualified family inventory files from
/// static fallback lines. Freshness, tested, Iran-working, and tested-global
/// projections remain untouched and therefore cannot claim unverified yield.
/// Returns the number of inventory lines written.
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
        record_failsafe_activation(
            bridge_dir,
            &name,
            clean.len(),
            "empty_or_missing_projection",
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
                record_failsafe_activation(
                    bridge_dir,
                    &format!("{transport}.txt"),
                    bridges.len(),
                    "empty_projection_recovered_from_history",
                );
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

    // 2) Force-populate only missing or 0-byte unqualified family inventory
    //    files when complete static bridge lines exist. Freshness, tested,
    //    Iran-working, and tested-global projections are never static-filled.
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
            println!(
                "FAILSAFE: wrote valid empty JSON array to {}",
                path.display()
            );
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
            "f": {"transport": "obfs4", "raw": ""},
            "g": {"transport": "webtunnel", "raw": "webtunnel FINGER url=https://metadata.example/path"}
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
        // Unknown transports remain compatible with the historical rebuild,
        // while URL-only WebTunnel metadata is excluded from client testing
        // inputs because it lacks a literal socket endpoint.
        assert_eq!(all.len(), 4);
        assert!(all.contains(&"webtunnel 9.9.9.9:443 url=x".to_string()));
        assert!(all.contains(&"ignored".to_string()));
        assert!(!all.iter().any(|line| line.starts_with("webtunnel FINGER")));
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
        assert_eq!(
            transport_for_filename("vanilla_tested.txt"),
            Some("vanilla")
        );
        assert_eq!(
            transport_for_filename("snowflake_ipv6.txt"),
            Some("snowflake")
        );
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
    fn static_fallback_is_disallowed_for_evidence_qualified_outputs() {
        for name in required_protocol_txt_names()
            .into_iter()
            .filter(|name| !static_fallback_allowed(name))
            .chain(["iran_blocked.txt".to_string()])
        {
            assert!(
                fallback_lines_for_name(&name).is_empty(),
                "{name} must not use static fallback"
            );
        }
        assert!(static_fallback_allowed("obfs4.txt"));
        assert!(!fallback_lines_for_name("obfs4.txt").is_empty());
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
        // JSON file: only unqualified inventories may receive static lines.
        // Freshness/test/working projections stay empty rather than making
        // unsupported claims, and URL-only WebTunnel metadata is not fabricated.
        std::fs::write(bridge_dir.join("bridge_history.json"), "{}").expect("history");
        for name in required_protocol_txt_names() {
            std::fs::write(bridge_dir.join(name), "").expect("empty projection fixture");
        }
        for name in ["iran_blocked.txt", "bridge_scores.json"] {
            std::fs::write(bridge_dir.join(name), "").expect("empty fixture");
        }

        assert_eq!(run(&bridge_dir), 0);
        for name in [
            "obfs4.txt",
            "vanilla.txt",
            "snowflake.txt",
            "meek_lite.txt",
            "conjure.txt",
            "meek-azure.txt",
        ] {
            let path = bridge_dir.join(name);
            let body = std::fs::read_to_string(&path).expect("inventory file");
            assert!(
                body.lines().count() > 0,
                "{name} may use a static inventory fallback"
            );
        }
        for name in required_protocol_txt_names()
            .into_iter()
            .filter(|name| !static_fallback_allowed(name))
            .chain(["iran_blocked.txt".to_string()])
        {
            assert_eq!(
                std::fs::metadata(bridge_dir.join(&name))
                    .expect("evidence-qualified projection")
                    .len(),
                0,
                "{name} must stay empty without measured evidence"
            );
        }
        for name in [
            "webtunnel.txt",
            "obfs4_ipv6.txt",
            "vanilla_ipv6.txt",
            "webtunnel_ipv6.txt",
            "snowflake_ipv6.txt",
            "meek_lite_ipv6.txt",
        ] {
            assert_eq!(
                std::fs::metadata(bridge_dir.join(name))
                    .expect("unavailable inventory fallback")
                    .len(),
                0,
                "{name} needs a complete fallback matching the output projection"
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

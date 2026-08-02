//! Rust port of the `FAILSAFE — ensure bridge files always have content`
//! inline Python script that used to run inside `.github/workflows/
//! torshield-ir.yml` (`/tmp/_failsafe_bridges.py`).
//!
//! Contract preserved byte-for-byte:
//!
//!   1. Read `bridge/bridge_history.json` (tolerating a missing/corrupt file
//!      with a `WARNING:` line), collect `raw` bridge lines per transport.
//!   2. For each transport in the fixed order obfs4, snowflake, meek_lite,
//!      webtunnel, vanilla: if `bridge/<transport>.txt` is missing or empty,
//!      rewrite it from history (`FAILSAFE: wrote ...`), otherwise report
//!      `OK <path>: <n> bridges`.
//!   3. If `bridge/bridge_list_for_testing.json` is missing or tiny (<5
//!      bytes), rebuild it from history, falling back to the compiled-in
//!      static bridge list (the Rust `static_bridges::get_all()` port of
//!      `sources/static_bridges.py`).
//!   4. Print `FAILSAFE done. Extra bridges written: <n>` and exit 0.
//!
//! One deliberate deviation (documented): history object iteration follows
//! `BTreeMap` key order instead of JSON file order; this only affects the
//! line ordering of *fallback rewrites*, never which bridges are written.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::static_bridges;

/// Transports in the fixed iteration order of the Python original.
pub const TRANSPORTS: &[&str] = &["obfs4", "snowflake", "meek_lite", "webtunnel", "vanilla"];

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
}

#![allow(warnings)]
// Differential parity tests for `src/history.rs` vs `core/history.py`.
//
// Covers `_normalize_key` (the dedup canonicalization) and the query/
// aggregation surface (`get_stats`, `get_recent`, `get_tested`,
// `get_by_transport`) driven over an identical, crafted in-memory database
// with a pinned clock. The Python oracle's `utc_now`/`utc_now_iso` are
// monkeypatched to the same fixed instant as the injected Rust clock, so
// the time-dependent `get_recent` cutoff and the `get_stats` "updated"
// timestamp are deterministic and directly comparable.
//
// This also pins the Session-11 fix to `now_iso()`: it now emits Python's
// `isoformat()` shape (`+00:00`, fractional only when microseconds are
// nonzero) rather than chrono's `...000000Z`.

use std::process::Command;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};
use torshield_ir_ultra::history::HistoryManager;

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

/// Drive the Python `HistoryManager` with a fixed clock and a crafted db.
fn run_python(now_iso: &str, db_json: &str, body: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!(
        "import json\n\
         from datetime import datetime\n\
         import core.history as H\n\
         fixed = datetime.fromisoformat('{now_iso}')\n\
         H.utc_now = lambda: fixed\n\
         H.utc_now_iso = lambda: fixed.isoformat()\n\
         h = H.HistoryManager()\n\
         h._db = json.loads(r'''{db_json}''')\n\
         {body}\n"
    );
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("-c")
        .arg(&script)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn run_python_normalize(line: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("-c")
        .arg(format!(
            "from core.history import HistoryManager; \
             print(repr(HistoryManager._normalize_key(r'''{line}''')))"
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn parity_normalize_key() {
    let cases = [
        "Bridge obfs4 1.2.3.4:443",
        "obfs4 1.2.3.4:443",
        "  Bridge  obfs4 1.2.3.4:443  ",
        "OBFS4 1.2.3.4:443 CERT=ABC",
        "Bridge ",
        "",
        "   ",
        "BridgeNoSpace",
        "Bridge Bridge x",
    ];
    for line in cases {
        // Python prints repr(...) e.g. "'obfs4 1.2.3.4:443'"; strip the quotes.
        let py = run_python_normalize(line);
        let py_val = py.trim_matches('\'');
        assert_eq!(
            py_val,
            HistoryManager::normalize_key(line),
            "normalize_key({line:?})"
        );
    }
}

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 28, 12, 0, 0).unwrap()
}
const FIXED_NOW_ISO: &str = "2026-06-28T12:00:00+00:00";

/// A crafted history db exercising: multiple transports, tested/untested/
/// failing records, and first_seen values inside and outside the 72h window.
fn crafted_db() -> Value {
    json!({
        "obfs4 1.1.1.1:443": {
            "raw": "obfs4 1.1.1.1:443", "transport": "obfs4",
            "first_seen": "2026-06-28T11:00:00+00:00", "last_seen": "2026-06-28T11:00:00+00:00",
            "test_pass": true, "test_time": "2026-06-28T11:30:00+00:00", "latency_ms": 120, "score": 80
        },
        "webtunnel 2.2.2.2:8443": {
            "raw": "webtunnel 2.2.2.2:8443", "transport": "webtunnel",
            "first_seen": "2026-06-26T12:00:00+00:00", "last_seen": "2026-06-27T12:00:00+00:00",
            "test_pass": false, "test_time": "2026-06-27T00:00:00+00:00", "latency_ms": null, "score": 10
        },
        "obfs4 3.3.3.3:443": {
            "raw": "obfs4 3.3.3.3:443", "transport": "obfs4",
            "first_seen": "2026-06-20T12:00:00+00:00", "last_seen": "2026-06-25T12:00:00+00:00",
            "test_pass": null, "test_time": null, "latency_ms": null, "score": 0
        },
        "snowflake 4.4.4.4:80": {
            "raw": "snowflake 4.4.4.4:80", "transport": "snowflake",
            "first_seen": "2026-06-28T09:00:00+00:00", "last_seen": "2026-06-28T09:00:00+00:00",
            "test_pass": true, "test_time": "2026-06-28T09:05:00+00:00", "latency_ms": 45, "score": 95
        }
    })
}

#[test]
fn parity_get_stats_includes_updated() {
    let db = crafted_db();
    let db_str = serde_json::to_string(&db).unwrap();
    let py = run_python(
        FIXED_NOW_ISO,
        &db_str,
        "print(json.dumps(h.get_stats(), sort_keys=True, ensure_ascii=False))",
    );
    let mgr = load_mgr(&db_str);
    let py_val: Value = serde_json::from_str(&py).unwrap();
    assert_eq!(py_val, mgr.get_stats(), "get_stats mismatch");
}

fn load_mgr(db_str: &str) -> HistoryManager {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let uniq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp =
        std::env::temp_dir().join(format!("hist_parity_q_{}_{uniq}.json", std::process::id()));
    std::fs::write(&tmp, db_str).unwrap();
    let mgr = HistoryManager::new(
        &tmp,
        &std::env::temp_dir(),
        &std::env::temp_dir(),
        fixed_now(),
    )
    .unwrap();
    let _ = std::fs::remove_file(&tmp);
    mgr
}

fn sorted_raws(records: Vec<torshield_ir_ultra::history::BridgeRecord>) -> Vec<String> {
    let mut v: Vec<String> = records.into_iter().map(|r| r.raw).collect();
    v.sort();
    v
}

#[test]
fn parity_get_recent_get_tested_get_by_transport() {
    let db = crafted_db();
    let db_str = serde_json::to_string(&db).unwrap();
    let mgr = load_mgr(&db_str);

    // get_recent(72): only first_seen within 72h of fixed_now.
    let py_recent = run_python(
        FIXED_NOW_ISO,
        &db_str,
        "print(json.dumps(sorted(v['raw'] for v in h.get_recent(72))))",
    );
    let py_recent_v: Value = serde_json::from_str(&py_recent).unwrap();
    assert_eq!(
        py_recent_v,
        json!(sorted_raws(mgr.get_recent(72))),
        "get_recent(72)"
    );

    // get_tested(True) and get_tested(False)
    for (lit, passed) in [("True", true), ("False", false)] {
        let py = run_python(
            FIXED_NOW_ISO,
            &db_str,
            &format!("print(json.dumps(sorted(v['raw'] for v in h.get_tested({lit}))))"),
        );
        let pv: Value = serde_json::from_str(&py).unwrap();
        assert_eq!(
            pv,
            json!(sorted_raws(mgr.get_tested(passed))),
            "get_tested({lit})"
        );
    }

    // get_by_transport
    for t in ["obfs4", "OBFS4", "snowflake", "meek_lite"] {
        let py = run_python(
            FIXED_NOW_ISO,
            &db_str,
            &format!("print(json.dumps(sorted(v['raw'] for v in h.get_by_transport(r'''{t}'''))))"),
        );
        let pv: Value = serde_json::from_str(&py).unwrap();
        assert_eq!(
            pv,
            json!(sorted_raws(mgr.get_by_transport(t))),
            "get_by_transport({t})"
        );
    }
}

#[test]
fn parity_get_stats_updated_nonzero_micros() {
    // Prove the now_iso() format fix for the fractional-seconds branch.
    let now = Utc.with_ymd_and_hms(2026, 6, 28, 12, 0, 0).unwrap()
        + chrono::Duration::microseconds(500_000);
    let now_iso = "2026-06-28T12:00:00.500000+00:00";
    let db = json!({});
    let db_str = serde_json::to_string(&db).unwrap();
    let py = run_python(
        now_iso,
        &db_str,
        "print(json.dumps(h.get_stats(), sort_keys=True, ensure_ascii=False))",
    );
    let tmp = std::env::temp_dir().join(format!("hist_parity_micros_{}.json", std::process::id()));
    std::fs::write(&tmp, &db_str).unwrap();
    let mgr = HistoryManager::new(&tmp, &std::env::temp_dir(), &std::env::temp_dir(), now).unwrap();
    let _ = std::fs::remove_file(&tmp);
    let py_val: Value = serde_json::from_str(&py).unwrap();
    assert_eq!(
        py_val,
        mgr.get_stats(),
        "get_stats updated (nonzero micros)"
    );
}

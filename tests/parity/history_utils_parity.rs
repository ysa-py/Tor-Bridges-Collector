// Parity tests for `src/history_utils.rs` vs `sources/history_utils.py`.
//
// Each test invokes a fresh Python interpreter on `sources/history_utils.py`
// (via `core.dt_utils`) and asserts byte-identical JSON output from the
// Rust port. Covers every branch documented in the task spec:
// - `parse_history_dt` on aware/naive/None/malformed input
// - `normalize_history_timestamps` on str entries, dict entries with
//   `first_seen`/`last_seen`, and mixed dicts
// - `history_entry_timestamp` on str, dict-with-both (prefer_last_seen
//   true/false), dict-with-only-one, and None
// - `cleanup_history` with an INJECTABLE clock (mocked `utc_now`) so
//   cutoff behavior is deterministic

use std::path::PathBuf;
use std::process::Command;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use torshield_ir_ultra::history_utils::{
    cleanup_history_with_now, history_entry_timestamp, normalize_history_timestamps,
    parse_history_dt,
};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────

fn python_executable() -> PathBuf {
    if let Ok(path) = std::env::var("PYTHON") {
        return PathBuf::from(path);
    }
    for candidate in [
        "/root/.pyenv/shims/python",
        "/usr/local/bin/python",
        "/usr/bin/python3",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("python")
}

/// Dispatch a single JSON command to the Python `sources.history_utils`
/// module and return the parsed JSON output.
///
/// The Python helper mocks `utc_now` inside the `sources.history_utils`
/// module namespace so `cleanup_history` uses a deterministic clock
/// matching the Rust `cleanup_history_with_now` `now` parameter.
fn python_history(cmd: &Value) -> Value {
    let cmd_json = serde_json::to_string(cmd)
        .unwrap_or_else(|err| panic!("history_utils parity cmd must serialize: {err}"));
    let script = r#"
import json, sys
from datetime import datetime, timezone
import sources.history_utils as hu

cmd = json.loads(sys.argv[1])
op = cmd['op']
if op == 'parse_history_dt':
    print(json.dumps(hu.parse_history_dt(cmd['value']).isoformat()))
elif op == 'normalize':
    history = cmd['history']
    hu.normalize_history_timestamps(history)
    print(json.dumps(history, sort_keys=True))
elif op == 'history_entry_timestamp':
    prefer = cmd.get('prefer_last_seen', True)
    print(json.dumps(hu.history_entry_timestamp(cmd['entry'], prefer_last_seen=prefer)))
elif op == 'cleanup_history':
    # Mock utc_now in the history_utils namespace (history_utils imports
    # utc_now directly, so we must patch the re-bound reference, not
    # core.dt_utils.utc_now).
    hu.utc_now = lambda: datetime.fromisoformat(cmd['now'])
    history = cmd['history']
    result = hu.cleanup_history(
        history,
        cmd['retention_days'],
        prefer_last_seen=cmd.get('prefer_last_seen', True),
    )
    print(json.dumps(result, sort_keys=True))
else:
    raise SystemExit('unknown op: ' + op)
"#
    .to_string();
    let output = Command::new(python_executable())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .env("PYTHONPATH", env!("CARGO_MANIFEST_DIR"))
        .arg("-c")
        .arg(script)
        .arg(&cmd_json)
        .output()
        .unwrap_or_else(|err| panic!("python history_utils helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python history_utils helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python history_utils helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_history_dt parity (4 Python subprocess cases)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_parse_history_dt_aware_offset() {
    let py = python_history(&json!({
        "op": "parse_history_dt",
        "value": "2026-06-05T08:45:38+03:30"
    }));
    let rs = parse_history_dt(Some("2026-06-05T08:45:38+03:30")).to_rfc3339();
    assert_eq!(py, json!(rs));
    assert_eq!(py, json!("2026-06-05T05:15:38+00:00"));
}

#[test]
fn parity_parse_history_dt_naive_string() {
    let py = python_history(&json!({
        "op": "parse_history_dt",
        "value": "2026-06-05T07:45:38"
    }));
    let rs = parse_history_dt(Some("2026-06-05T07:45:38")).to_rfc3339();
    assert_eq!(py, json!(rs));
    assert_eq!(py, json!("2026-06-05T07:45:38+00:00"));
}

#[test]
fn parity_parse_history_dt_none_uses_fallback() {
    let py = python_history(&json!({
        "op": "parse_history_dt",
        "value": null
    }));
    let rs = parse_history_dt(None).to_rfc3339();
    assert_eq!(py, json!(rs));
    assert_eq!(py, json!("2000-01-01T00:00:00+00:00"));
}

#[test]
fn parity_parse_history_dt_malformed_uses_fallback() {
    let py = python_history(&json!({
        "op": "parse_history_dt",
        "value": "not-a-date"
    }));
    let rs = parse_history_dt(Some("not-a-date")).to_rfc3339();
    assert_eq!(py, json!(rs));
    assert_eq!(py, json!("2000-01-01T00:00:00+00:00"));
}

// ─────────────────────────────────────────────────────────────────────────────
// normalize_history_timestamps parity (3 Python subprocess cases)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_normalize_str_entries() {
    let history = json!({
        "a": "2026-06-05T07:45:38",
        "b": "2026-06-05T08:45:38+03:30",
    });
    let py = python_history(&json!({
        "op": "normalize",
        "history": history,
    }));
    let mut rs = history.clone();
    normalize_history_timestamps(&mut rs).unwrap();
    assert_eq!(py, rs);
    assert_eq!(
        py,
        json!({
            "a": "2026-06-05T07:45:38+00:00",
            "b": "2026-06-05T05:15:38+00:00",
        })
    );
}

#[test]
fn parity_normalize_dict_entries_with_first_seen_and_last_seen() {
    let history = json!({
        "a": {
            "first_seen": "2026-06-05T07:45:38",
            "last_seen": "2026-06-05T08:45:38+03:30",
            "meta": "extra",
        }
    });
    let py = python_history(&json!({
        "op": "normalize",
        "history": history,
    }));
    let mut rs = history.clone();
    normalize_history_timestamps(&mut rs).unwrap();
    assert_eq!(py, rs);
    assert_eq!(
        py,
        json!({
            "a": {
                "first_seen": "2026-06-05T07:45:38+00:00",
                "last_seen": "2026-06-05T05:15:38+00:00",
                "meta": "extra",
            }
        })
    );
}

#[test]
fn parity_normalize_mixed_dict() {
    let history = json!({
        "a": "2026-06-05T07:45:38",
        "b": {
            "first_seen": "2026-06-05T07:45:38",
            "last_seen": "2026-06-05T08:45:38+03:30",
        },
        "c": "not-a-date",
        "d": {"meta": "no timestamps"},
    });
    let py = python_history(&json!({
        "op": "normalize",
        "history": history,
    }));
    let mut rs = history.clone();
    normalize_history_timestamps(&mut rs).unwrap();
    assert_eq!(py, rs);
    assert_eq!(
        py,
        json!({
            "a": "2026-06-05T07:45:38+00:00",
            "b": {
                "first_seen": "2026-06-05T07:45:38+00:00",
                "last_seen": "2026-06-05T05:15:38+00:00",
            },
            "c": "2000-01-01T00:00:00+00:00",
            "d": {"meta": "no timestamps"},
        })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// history_entry_timestamp parity (5 Python subprocess cases)
// ─────────────────────────────────────────────────────────────────────────────

fn rust_entry_timestamp(entry: &Value, prefer_last_seen: bool) -> Value {
    match history_entry_timestamp(entry, prefer_last_seen) {
        Some(s) => json!(s),
        None => json!(null),
    }
}

#[test]
fn parity_history_entry_timestamp_str_entry() {
    let entry = json!("2026-06-05T07:45:38");
    let py = python_history(&json!({
        "op": "history_entry_timestamp",
        "entry": entry,
        "prefer_last_seen": true,
    }));
    let rs = rust_entry_timestamp(&entry, true);
    assert_eq!(py, rs);
    assert_eq!(py, json!("2026-06-05T07:45:38"));
}

#[test]
fn parity_history_entry_timestamp_dict_both_prefer_last_seen() {
    let entry = json!({
        "first_seen": "2026-06-05T07:45:38",
        "last_seen": "2026-06-06T07:45:38",
    });
    let py = python_history(&json!({
        "op": "history_entry_timestamp",
        "entry": entry,
        "prefer_last_seen": true,
    }));
    let rs = rust_entry_timestamp(&entry, true);
    assert_eq!(py, rs);
    assert_eq!(py, json!("2026-06-06T07:45:38"));
}

#[test]
fn parity_history_entry_timestamp_dict_both_prefer_first_seen() {
    let entry = json!({
        "first_seen": "2026-06-05T07:45:38",
        "last_seen": "2026-06-06T07:45:38",
    });
    let py = python_history(&json!({
        "op": "history_entry_timestamp",
        "entry": entry,
        "prefer_last_seen": false,
    }));
    let rs = rust_entry_timestamp(&entry, false);
    assert_eq!(py, rs);
    assert_eq!(py, json!("2026-06-05T07:45:38"));
}

#[test]
fn parity_history_entry_timestamp_dict_only_one_timestamp() {
    let entry = json!({"first_seen": "2026-06-05T07:45:38"});
    let py_prefer_last = python_history(&json!({
        "op": "history_entry_timestamp",
        "entry": entry,
        "prefer_last_seen": true,
    }));
    let rs_prefer_last = rust_entry_timestamp(&entry, true);
    assert_eq!(py_prefer_last, rs_prefer_last);
    assert_eq!(py_prefer_last, json!("2026-06-05T07:45:38"));

    let entry2 = json!({"last_seen": "2026-06-07T07:45:38"});
    let py_prefer_first = python_history(&json!({
        "op": "history_entry_timestamp",
        "entry": entry2,
        "prefer_last_seen": false,
    }));
    let rs_prefer_first = rust_entry_timestamp(&entry2, false);
    assert_eq!(py_prefer_first, rs_prefer_first);
    assert_eq!(py_prefer_first, json!("2026-06-07T07:45:38"));
}

#[test]
fn parity_history_entry_timestamp_none_and_dict_without_timestamps() {
    // None entry — neither str nor dict → None.
    let py_none = python_history(&json!({
        "op": "history_entry_timestamp",
        "entry": null,
        "prefer_last_seen": true,
    }));
    let rs_none = rust_entry_timestamp(&json!(null), true);
    assert_eq!(py_none, rs_none);
    assert_eq!(py_none, json!(null));

    // Dict without any timestamp fields → falls through both branches → None.
    let entry = json!({"meta": "foo"});
    let py = python_history(&json!({
        "op": "history_entry_timestamp",
        "entry": entry,
        "prefer_last_seen": true,
    }));
    let rs = rust_entry_timestamp(&entry, true);
    assert_eq!(py, rs);
    assert_eq!(py, json!(null));
}

// ─────────────────────────────────────────────────────────────────────────────
// cleanup_history parity with INJECTABLE clock (2 Python subprocess cases)
// ─────────────────────────────────────────────────────────────────────────────

fn parse_utc(iso: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(iso)
        .unwrap_or_else(|err| panic!("test fixture iso must parse: {err}"))
        .with_timezone::<Utc>(&Utc)
}

#[test]
fn parity_cleanup_history_removes_stale_and_keeps_recent_with_injected_clock() {
    let history = json!({
        "old_str": "2025-01-01T00:00:00",
        "new_str": "2026-06-09T00:00:00",
        "old_dict": {
            "first_seen": "2025-01-01T00:00:00",
            "last_seen": "2025-06-01T00:00:00",
        },
        "new_dict": {
            "first_seen": "2026-06-08T00:00:00",
            "last_seen": "2026-06-09T00:00:00",
        },
    });
    let now_iso = "2026-06-10T12:00:00+00:00";
    let py = python_history(&json!({
        "op": "cleanup_history",
        "history": history,
        "retention_days": 7,
        "prefer_last_seen": true,
        "now": now_iso,
    }));
    let mut rs = history.clone();
    cleanup_history_with_now(&mut rs, 7, true, parse_utc(now_iso)).unwrap();
    assert_eq!(py, rs);
    assert_eq!(
        py,
        json!({
            "new_str": "2026-06-09T00:00:00",
            "new_dict": {
                "first_seen": "2026-06-08T00:00:00",
                "last_seen": "2026-06-09T00:00:00",
            },
        })
    );
}

#[test]
fn parity_cleanup_history_prefer_first_seen_swaps_order() {
    // An entry whose first_seen is recent but last_seen is stale should be
    // RETAINED when prefer_last_seen=False (use first_seen) but DROPPED when
    // prefer_last_seen=True (use last_seen). Verifies both branches.
    let history = json!({
        "mixed": {
            "first_seen": "2026-06-09T00:00:00",
            "last_seen": "2025-01-01T00:00:00",
        },
    });
    let now_iso = "2026-06-10T12:00:00+00:00";

    let py_first = python_history(&json!({
        "op": "cleanup_history",
        "history": history,
        "retention_days": 7,
        "prefer_last_seen": false,
        "now": now_iso,
    }));
    let mut rs_first = history.clone();
    cleanup_history_with_now(&mut rs_first, 7, false, parse_utc(now_iso)).unwrap();
    assert_eq!(py_first, rs_first);
    assert_eq!(
        py_first,
        json!({
            "mixed": {
                "first_seen": "2026-06-09T00:00:00",
                "last_seen": "2025-01-01T00:00:00",
            },
        })
    );

    let py_last = python_history(&json!({
        "op": "cleanup_history",
        "history": history,
        "retention_days": 7,
        "prefer_last_seen": true,
        "now": now_iso,
    }));
    let mut rs_last = history.clone();
    cleanup_history_with_now(&mut rs_last, 7, true, parse_utc(now_iso)).unwrap();
    assert_eq!(py_last, rs_last);
    assert_eq!(py_last, json!({}));
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust-only edge case: non-object root returns typed error (no panic)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rust_normalize_rejects_non_object_root_without_panic() {
    let mut bad = json!([1, 2, 3]);
    let err = normalize_history_timestamps(&mut bad).unwrap_err();
    assert!(matches!(
        err,
        torshield_ir_ultra::history_utils::HistoryError::NotAnObject { actual: "array" }
    ));
}

#[test]
fn rust_cleanup_rejects_non_object_root_without_panic() {
    let mut bad = json!("not-an-object");
    let now = parse_utc("2026-06-10T12:00:00+00:00");
    let err = cleanup_history_with_now(&mut bad, 7, true, now).unwrap_err();
    assert!(matches!(
        err,
        torshield_ir_ultra::history_utils::HistoryError::NotAnObject { actual: "string" }
    ));
}

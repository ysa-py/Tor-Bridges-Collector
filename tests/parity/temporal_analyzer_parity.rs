#![allow(warnings)]
// Differential parity tests for `src/temporal_analyzer.rs` vs
// `core/temporal_analyzer.py`.
//
// `current_threat_level` is compared across a full day of IRST hours plus a
// Friday (the VARIABLE special-case) using the explicit `now` argument the
// Python API accepts. `best_connection_windows` and `get_status` read the
// wall clock internally, so the Python oracle's `current_iran_time` is
// monkeypatched to a fixed IRST instant that exactly matches the injected
// Rust clock (`IranTemporalAnalyzer::new(utc)`), making both deterministic.
//
// IRAN_TZ is a fixed UTC+3:30 offset in both implementations (Iran observes
// no DST), so no timezone-database divergence is possible.

use std::process::Command;

use chrono::{DateTime, Utc};
use serde_json::Value;
use torshield_ir_ultra::temporal_analyzer::IranTemporalAnalyzer;

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(body: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let script = format!(
        "import json\n\
         from datetime import datetime\n\
         import core.temporal_analyzer as ta\n\
         a = ta.IranTemporalAnalyzer()\n\
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

/// Parse an IRST (`+03:30`) RFC3339 string into a UTC instant for the Rust
/// analyzer's injectable clock.
fn irst_to_utc(irst: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(irst)
        .unwrap()
        .with_timezone(&Utc)
}

// A Monday (2026-07-06) across representative hours + a Friday (2026-07-10).
const IRST_INSTANTS: &[&str] = &[
    "2026-07-06T00:00:00+03:30", // LOW
    "2026-07-06T03:00:00+03:30", // LOW
    "2026-07-06T05:59:00+03:30", // LOW (boundary)
    "2026-07-06T06:00:00+03:30", // MEDIUM (boundary)
    "2026-07-06T08:00:00+03:30", // MEDIUM
    "2026-07-06T09:00:00+03:30", // HIGH (boundary)
    "2026-07-06T15:00:00+03:30", // HIGH
    "2026-07-06T21:59:00+03:30", // HIGH (boundary)
    "2026-07-06T22:00:00+03:30", // MEDIUM (boundary)
    "2026-07-06T23:30:00+03:30", // MEDIUM
    "2026-07-10T03:00:00+03:30", // Friday -> VARIABLE
    "2026-07-10T15:00:00+03:30", // Friday -> VARIABLE
];

#[test]
fn parity_current_threat_level() {
    let analyzer = IranTemporalAnalyzer::new(Utc::now());
    for irst in IRST_INSTANTS {
        let py = run_python(&format!(
            "print(a.current_threat_level(datetime.fromisoformat('{irst}')))"
        ));
        let rs = analyzer.current_threat_level_at(irst_to_utc(irst));
        assert_eq!(py, rs, "current_threat_level at {irst}");
    }
}

/// Compare `best_connection_windows(3)` with a fixed clock.
#[test]
fn parity_best_connection_windows() {
    for irst in [
        "2026-07-06T01:00:00+03:30", // inside a LOW window
        "2026-07-06T05:00:00+03:30",
        "2026-07-06T10:00:00+03:30", // HIGH now; next LOW upcoming
        "2026-07-06T23:00:00+03:30", // near midnight rollover
        "2026-07-09T20:00:00+03:30", // Thursday evening -> LOW window rolls into Fri (skipped)
    ] {
        let py = run_python(&format!(
            "a.current_iran_time = lambda: datetime.fromisoformat('{irst}')\n\
             print(json.dumps(a.best_connection_windows(3), ensure_ascii=False))"
        ));
        let analyzer = IranTemporalAnalyzer::new(irst_to_utc(irst));
        let rs: Value = Value::Array(analyzer.best_connection_windows(3));
        let py_val: Value = serde_json::from_str(&py).unwrap();
        assert_eq!(py_val, rs, "best_connection_windows at {irst}");
    }
}

/// Compare `get_status()` with a fixed clock (covers weekday name,
/// iran_time formatting, threat level, and embedded windows).
#[test]
fn parity_get_status() {
    for irst in [
        "2026-07-06T01:00:00+03:30", // Monday LOW
        "2026-07-06T15:00:00+03:30", // Monday HIGH
        "2026-07-10T12:00:00+03:30", // Friday VARIABLE
        "2026-07-12T04:00:00+03:30", // Sunday LOW
    ] {
        let py = run_python(&format!(
            "a.current_iran_time = lambda: datetime.fromisoformat('{irst}')\n\
             print(json.dumps(a.get_status(), ensure_ascii=False))"
        ));
        let analyzer = IranTemporalAnalyzer::new(irst_to_utc(irst));
        let rs = analyzer.get_status();
        let py_val: Value = serde_json::from_str(&py).unwrap();
        assert_eq!(py_val, rs, "get_status at {irst}");
    }
}

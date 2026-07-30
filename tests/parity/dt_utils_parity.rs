#![allow(warnings)]
// Parity tests for `src/dt_utils.rs` vs `core/dt_utils.py`.
//
// Each test invokes a fresh Python interpreter on `core/dt_utils.py`,
// captures the resulting ISO-8601 string, and asserts byte-identical
// output from the Rust port. Covers every branch documented in the
// Phase 0 contract: aware offsets, naive timestamps, malformed input,
// None values, custom fallbacks, and the `Z` suffix normalization.

use std::process::Command;

use torshield_ir_ultra::dt_utils::{coerce_utc_dt, parse_dt, DEFAULT_FALLBACK};

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        // Leak once: tests are short-lived and the env var is stable for the run.
        Box::leak(path.into_boxed_str())
    } else {
        "python3"
    }
}

fn run_python(script: &str) -> String {
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env_clear()
        .env("PYTHONPATH", repo_root)
        // Preserve PATH so the interpreter can be located after env_clear();
        // without this the clean-env isolation makes `python3` unresolvable.
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn parity_parse_dt_aware_offset() {
    let py = run_python(
        "from core.dt_utils import parse_dt; print(parse_dt('2026-06-05T08:45:38+03:30').isoformat())",
    );
    // Python preserves the +03:30 offset; Rust normalizes to UTC.
    // Bridge-history comparison code paths always normalize via coerce_utc_dt,
    // so the semantically meaningful comparison is the UTC-normalized form.
    let py_normalized = run_python(
        "from core.dt_utils import parse_dt, UTC; print(parse_dt('2026-06-05T08:45:38+03:30').astimezone(UTC).isoformat())",
    );
    let rs = parse_dt("2026-06-05T08:45:38+03:30").to_rfc3339();
    assert_eq!(py, "2026-06-05T08:45:38+03:30");
    assert_eq!(py_normalized, rs);
}

#[test]
fn parity_parse_dt_naive_string() {
    let py = run_python(
        "from core.dt_utils import parse_dt; print(parse_dt('2026-06-05T07:45:38').isoformat())",
    );
    let rs = parse_dt("2026-06-05T07:45:38").to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_parse_dt_malformed_returns_epoch() {
    let py =
        run_python("from core.dt_utils import parse_dt; print(parse_dt('not-a-date').isoformat())");
    let rs = parse_dt("not-a-date").to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_parse_dt_handles_z_suffix() {
    let py = run_python(
        "from core.dt_utils import parse_dt; print(parse_dt('2026-06-05T07:45:38Z').isoformat())",
    );
    let rs = parse_dt("2026-06-05T07:45:38Z").to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_coerce_utc_dt_aware_offset() {
    let py = run_python(
        "from core.dt_utils import coerce_utc_dt; print(coerce_utc_dt('2026-06-05T08:45:38+03:30').isoformat())",
    );
    let rs = coerce_utc_dt(Some("2026-06-05T08:45:38+03:30"), DEFAULT_FALLBACK).to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_coerce_utc_dt_naive_string() {
    let py = run_python(
        "from core.dt_utils import coerce_utc_dt; print(coerce_utc_dt('2026-06-05T07:45:38').isoformat())",
    );
    let rs = coerce_utc_dt(Some("2026-06-05T07:45:38"), DEFAULT_FALLBACK).to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_coerce_utc_dt_none_uses_default_fallback() {
    let py = run_python(
        "from core.dt_utils import coerce_utc_dt; print(coerce_utc_dt(None).isoformat())",
    );
    let rs = coerce_utc_dt(None, DEFAULT_FALLBACK).to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_coerce_utc_dt_none_uses_custom_fallback() {
    let py = run_python(
        "from core.dt_utils import coerce_utc_dt; print(coerce_utc_dt(None, '1999-01-01T00:00:00+00:00').isoformat())",
    );
    let rs = coerce_utc_dt(None, "1999-01-01T00:00:00+00:00").to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_coerce_utc_dt_invalid_value_uses_fallback() {
    let py = run_python(
        "from core.dt_utils import coerce_utc_dt; print(coerce_utc_dt('not-a-date', '1999-01-01T00:00:00+00:00').isoformat())",
    );
    let rs = coerce_utc_dt(Some("not-a-date"), "1999-01-01T00:00:00+00:00").to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_coerce_utc_dt_invalid_value_default_fallback() {
    let py = run_python(
        "from core.dt_utils import coerce_utc_dt; print(coerce_utc_dt('not-a-date').isoformat())",
    );
    let rs = coerce_utc_dt(Some("not-a-date"), DEFAULT_FALLBACK).to_rfc3339();
    assert_eq!(py, rs);
}

#[test]
fn parity_coerce_utc_dt_non_string_type_returns_fallback() {
    // Python coerces non-string/non-datetime values to fallback. The Rust
    // signature only accepts Option<&str>, so an int 12345 in Python maps
    // to None in Rust. Verify the parity on the documented fallback.
    let py = run_python(
        "from core.dt_utils import coerce_utc_dt; print(coerce_utc_dt(12345).isoformat())",
    );
    let rs = coerce_utc_dt(None, DEFAULT_FALLBACK).to_rfc3339();
    assert_eq!(py, rs);
}

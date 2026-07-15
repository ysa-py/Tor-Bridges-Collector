// Parity tests for `src/iran_bridge_prioritizer.rs` vs
// `core/iran_bridge_prioritizer.py`.
//
// Each test dispatches a JSON command to a Python helper that imports
// `core.iran_bridge_prioritizer` and calls the matching function on the
// same input, patching relevant `config.*` module attributes beforehand
// (mirroring how `getattr(config, FLAG, default)` reads them fresh on
// every call — verified: setting `config.X = value` before the call is
// observed by the function). The Rust port is invoked on the identical
// input/config and the JSON outputs are compared for equality (parsed
// [`Value`] comparison so object key ordering is irrelevant).
//
// Coverage:
// * `score_bridge` over: preferred/non-preferred port, each of the four
//   `_recency_score` age buckets, each of the `_reachability_score`
//   branches (identity flags, nested metadata dict with bool flags, nested
//   metadata `score` field with clamping, RIPE Atlas fallback flags,
//   default zero), single-transport-name detection via the raw line, and
//   weighted-score computation with non-default config weights.
// * `_context_multiplier` over `UTLS_EVASION_MODE`, `NIN_MODE`, the two
//   IRST time-window flags (including a wraparound window), and
//   `RIPE_ATLAS_API_KEY` presence — via `score_bridge`'s end-to-end score,
//   since `_context_multiplier` itself is private in the Python original.
// * `prioritize_bridges` over the disabled passthrough, the annotated
//   sort, the unannotated (stripped) output, and descending-score /
//   ascending-index tie-break ordering across 3+ records.
// * Field preservation: arbitrary extra keys on the input record survive
//   unmodified in the output, and the input record itself is never
//   mutated (Python's `copy.deepcopy`).

use std::process::Command;

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use torshield_ir_ultra::config::{from_env_map, Config, EnvMap};
use torshield_ir_ultra::iran_bridge_prioritizer::{prioritize_bridges, score_bridge};

// ─────────────────────────────────────────────────────────────────────────────
// Python helper
// ─────────────────────────────────────────────────────────────────────────────
//
// All data (record/records, now_iso, annotate, config overrides) is
// bundled into one JSON payload and passed as a single argv string, the
// same way `onionhop_collector_parity.rs` passes its `cmd` JSON. This
// avoids ever needing to render a JSON value as Python source text: the
// Python side does one `json.loads(sys.argv[1])` and works with native
// Python values directly, so bool/int/float/str all round-trip through
// serde_json -> JSON text -> Python's json module with no manual
// literal-formatting step (and thus no escaping bugs) anywhere.

fn python_executable() -> &'static str {
    if let Ok(path) = std::env::var("PYTHON") {
        return Box::leak(path.into_boxed_str());
    }
    "python3"
}

/// One `(python config attr name, JSON value)` override pair, applied on
/// the Python side via `setattr(config, attr, value)` and on the Rust side
/// via [`apply_overrides`]. Kept as a `serde_json::Value` end-to-end so
/// there is exactly one encoding of each value, not a second hand-written
/// Python-literal rendering that could drift from it.
#[derive(Clone)]
struct ConfigOverride {
    attr: &'static str,
    value: Value,
}

fn ov_bool(attr: &'static str, value: bool) -> ConfigOverride {
    ConfigOverride { attr, value: json!(value) }
}

fn ov_int(attr: &'static str, value: i64) -> ConfigOverride {
    ConfigOverride { attr, value: json!(value) }
}

fn ov_float(attr: &'static str, value: f64) -> ConfigOverride {
    ConfigOverride { attr, value: json!(value) }
}

fn ov_str(attr: &'static str, value: &str) -> ConfigOverride {
    ConfigOverride { attr, value: json!(value) }
}

fn overrides_to_json(overrides: &[ConfigOverride]) -> Value {
    let map: Map<String, Value> = overrides
        .iter()
        .map(|ov| (ov.attr.to_string(), ov.value.clone()))
        .collect();
    Value::Object(map)
}

const SCORE_BRIDGE_SCRIPT: &str = r#"
import json, sys
import config

payload = json.loads(sys.argv[1])
for attr, value in payload["overrides"].items():
    setattr(config, attr, value)

import core.iran_bridge_prioritizer as ibp
from datetime import datetime

record = payload["record"]
now = datetime.fromisoformat(payload["now_iso"])
result = ibp.score_bridge(record, now=now)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
"#;

const PRIORITIZE_BRIDGES_SCRIPT: &str = r#"
import json, sys
import config

payload = json.loads(sys.argv[1])
for attr, value in payload["overrides"].items():
    setattr(config, attr, value)

import core.iran_bridge_prioritizer as ibp
from datetime import datetime

records = payload["records"]
now = datetime.fromisoformat(payload["now_iso"])
result = ibp.prioritize_bridges(records, annotate=payload["annotate"], now=now)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
"#;

/// Dispatch a `score_bridge` call to Python with the given record, `now`,
/// and config overrides. Returns the parsed JSON output (the full
/// annotated record).
fn python_score_bridge(record: &Value, now_iso: &str, overrides: &[ConfigOverride]) -> Value {
    let payload = json!({
        "record": record,
        "now_iso": now_iso,
        "overrides": overrides_to_json(overrides),
    });
    run_python_script(SCORE_BRIDGE_SCRIPT, &payload)
}

fn python_prioritize_bridges(
    records: &[Value],
    now_iso: &str,
    annotate: bool,
    overrides: &[ConfigOverride],
) -> Value {
    let payload = json!({
        "records": records,
        "now_iso": now_iso,
        "annotate": annotate,
        "overrides": overrides_to_json(overrides),
    });
    run_python_script(PRIORITIZE_BRIDGES_SCRIPT, &payload)
}

fn run_python_script(script: &str, payload: &Value) -> Value {
    let payload_json = serde_json::to_string(payload).expect("payload must serialize");
    let repo_root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(script)
        .arg(&payload_json)
        .output()
        .unwrap_or_else(|err| panic!("python helper must execute: {err}"));
    assert!(
        output.status.success(),
        "python helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "python helper must emit JSON: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust-side helpers
// ─────────────────────────────────────────────────────────────────────────────

fn default_cfg() -> Config {
    from_env_map(&EnvMap::new()).expect("default env map parses")
}

fn apply_overrides(cfg: &mut Config, overrides: &[ConfigOverride]) {
    for ov in overrides {
        match ov.attr {
            "UTLS_EVASION_MODE" => cfg.utls_evasion_mode = ov.value.as_bool().unwrap(),
            "NIN_MODE" => cfg.nin_mode = ov.value.as_bool().unwrap(),
            "IRST_HIGH_CENSORSHIP_START" => {
                cfg.irst_high_censorship_start = ov.value.as_i64().unwrap()
            }
            "IRST_HIGH_CENSORSHIP_END" => {
                cfg.irst_high_censorship_end = ov.value.as_i64().unwrap()
            }
            "IRST_ULTRA_STEALTH_START" => {
                cfg.irst_ultra_stealth_start = ov.value.as_i64().unwrap()
            }
            "IRST_ULTRA_STEALTH_END" => cfg.irst_ultra_stealth_end = ov.value.as_i64().unwrap(),
            "RIPE_ATLAS_API_KEY" => {
                cfg.ripe_atlas_api_key = ov.value.as_str().unwrap().to_string()
            }
            "IRAN_BRIDGE_PRIORITIZATION_ENABLED" => {
                cfg.iran_bridge_prioritization_enabled = ov.value.as_bool().unwrap()
            }
            "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT" => {
                cfg.iran_bridge_prioritization_weight_port = ov.value.as_f64().unwrap()
            }
            "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT" => {
                cfg.iran_bridge_prioritization_weight_transport = ov.value.as_f64().unwrap()
            }
            "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY" => {
                cfg.iran_bridge_prioritization_weight_recency = ov.value.as_f64().unwrap()
            }
            "IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY" => {
                cfg.iran_bridge_prioritization_weight_reachability = ov.value.as_f64().unwrap()
            }
            other => panic!("apply_overrides: unhandled config attr {other}"),
        }
    }
}

fn parse_now(now_iso: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(now_iso)
        .unwrap_or_else(|err| panic!("now_iso must parse: {err}"))
        .with_timezone(&Utc)
}

fn rust_score_bridge(record: &Value, now_iso: &str, overrides: &[ConfigOverride]) -> Value {
    let mut cfg = default_cfg();
    apply_overrides(&mut cfg, overrides);
    let record_map: Map<String, Value> = record.as_object().unwrap().clone();
    let now = parse_now(now_iso);
    let result = score_bridge(&record_map, &cfg, now);
    Value::Object(result)
}

fn rust_prioritize_bridges(
    records: &[Value],
    now_iso: &str,
    annotate: bool,
    overrides: &[ConfigOverride],
) -> Value {
    let mut cfg = default_cfg();
    apply_overrides(&mut cfg, overrides);
    let record_maps: Vec<Map<String, Value>> = records
        .iter()
        .map(|r| r.as_object().unwrap().clone())
        .collect();
    let now = parse_now(now_iso);
    let result = prioritize_bridges(&record_maps, &cfg, annotate, now);
    Value::Array(result.into_iter().map(Value::Object).collect())
}

const FIXED_NOW: &str = "2026-06-30T12:00:00+00:00";

// ─────────────────────────────────────────────────────────────────────────────
// score_bridge — port / transport / preservation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_score_bridge_preferred_port_full_signals() {
    let record = json!({
        "port": 443,
        "reachable": true,
        "last_seen": FIXED_NOW,
        "transport": "snowflake",
        "custom_untouched_field": "must survive"
    });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_non_preferred_port_from_raw_line() {
    let record = json!({
        "raw": "obfs4 1.2.3.4:31337 ABCDEF0123456789",
    });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_port_out_of_range_falls_back_to_regex() {
    let record = json!({
        "port": 99999,
        "raw": "webtunnel 5.6.7.8:8443 xyz"
    });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_transport_detected_from_raw_line() {
    let record = json!({ "raw": "meek_lite fronted bridge url=https://x" });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_unknown_transport() {
    let record = json!({ "raw": "totally unrecognized bridge line" });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

// ─────────────────────────────────────────────────────────────────────────────
// score_bridge — recency buckets
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_score_bridge_recency_within_24h() {
    let record = json!({ "last_seen": "2026-06-30T11:00:00+00:00" });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_recency_within_72h() {
    let record = json!({ "last_seen": "2026-06-28T00:00:00+00:00" });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_recency_within_7d() {
    let record = json!({ "last_seen": "2026-06-24T00:00:00+00:00" });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_recency_within_30d() {
    let record = json!({ "last_seen": "2026-06-05T00:00:00+00:00" });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_recency_beyond_30d() {
    let record = json!({ "last_seen": "2025-01-01T00:00:00+00:00" });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_recency_no_timestamp_field() {
    let record = json!({ "port": 443 });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_recency_prefers_last_seen_over_tested_at() {
    let record = json!({
        "last_seen": "2026-06-30T11:00:00+00:00",
        "tested_at": "2025-01-01T00:00:00+00:00"
    });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_recency_falls_back_through_empty_string() {
    let record = json!({
        "last_seen": "",
        "tested_at": "2026-06-30T11:00:00+00:00"
    });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

// ─────────────────────────────────────────────────────────────────────────────
// score_bridge — reachability branches
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_score_bridge_reachability_identity_true() {
    for key in ["reachable", "test_pass", "success", "is_reachable"] {
        let record = json!({ key: true });
        let py = python_score_bridge(&record, FIXED_NOW, &[]);
        let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
        assert_eq!(py, rs, "mismatch for key {key}");
    }
}

#[test]
fn parity_score_bridge_reachability_identity_false() {
    let record = json!({ "reachable": false });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_reachability_non_bool_truthy_is_ignored() {
    // Python: `record.get(key) is True` — the integer 1 is truthy but is
    // NOT identity-equal to True, so this must fall through past the
    // identity checks entirely (and land on the 0.0 default, since no
    // other reachability signal is present).
    let record = json!({ "reachable": 1 });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_reachability_nested_metadata_bool_flags() {
    let record = json!({ "reachability": { "success": true } });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_reachability_nested_metadata_score_field() {
    let record = json!({ "reachability_metadata": { "score": 0.42 } });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_reachability_nested_metadata_score_clamped_high() {
    let record = json!({ "reachability": { "score": 7.5 } });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_reachability_nested_metadata_score_clamped_low() {
    let record = json!({ "reachability": { "score": -3.0 } });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_reachability_atlas_fallback() {
    let record = json!({ "ripe_atlas_reachable": true });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);

    let record2 = json!({ "atlas_success": true });
    let py2 = python_score_bridge(&record2, FIXED_NOW, &[]);
    let rs2 = rust_score_bridge(&record2, FIXED_NOW, &[]);
    assert_eq!(py2, rs2);
}

#[test]
fn parity_score_bridge_reachability_default_zero() {
    let record = json!({ "port": 443 });
    let py = python_score_bridge(&record, FIXED_NOW, &[]);
    let rs = rust_score_bridge(&record, FIXED_NOW, &[]);
    assert_eq!(py, rs);
}

// ─────────────────────────────────────────────────────────────────────────────
// score_bridge — context multiplier (config-driven)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_score_bridge_utls_evasion_mode_flag() {
    let record = json!({ "port": 443 });
    let overrides = [ov_bool("UTLS_EVASION_MODE", true)];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_nin_mode_flag() {
    let record = json!({ "port": 443 });
    let overrides = [ov_bool("NIN_MODE", true)];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_ripe_atlas_api_key_present() {
    let record = json!({ "port": 443 });
    let overrides = [ov_str("RIPE_ATLAS_API_KEY", "some-key-value")];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_irst_high_censorship_window_hit() {
    // 2026-06-30T12:00:00+00:00 = 15:30 IRST (UTC+03:30). Default window
    // is [18, 1] (wraparound). Set the window to explicitly include 15:30.
    let record = json!({ "port": 443 });
    let overrides = [
        ov_int("IRST_HIGH_CENSORSHIP_START", 10),
        ov_int("IRST_HIGH_CENSORSHIP_END", 20),
    ];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_irst_ultra_stealth_window_wraparound_hit() {
    // Force a wraparound window (start > end) that includes 15:30 IRST.
    let record = json!({ "port": 443 });
    let overrides = [
        ov_int("IRST_ULTRA_STEALTH_START", 15),
        ov_int("IRST_ULTRA_STEALTH_END", 2),
    ];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_irst_window_miss() {
    let record = json!({ "port": 443 });
    let overrides = [
        ov_int("IRST_HIGH_CENSORSHIP_START", 1),
        ov_int("IRST_HIGH_CENSORSHIP_END", 2),
        ov_int("IRST_ULTRA_STEALTH_START", 3),
        ov_int("IRST_ULTRA_STEALTH_END", 4),
    ];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_all_multipliers_stacked() {
    let record = json!({
        "port": 443,
        "reachable": true,
        "last_seen": FIXED_NOW,
        "transport": "snowflake"
    });
    let overrides = [
        ov_bool("UTLS_EVASION_MODE", true),
        ov_bool("NIN_MODE", true),
        ov_str("RIPE_ATLAS_API_KEY", "key"),
        ov_int("IRST_HIGH_CENSORSHIP_START", 10),
        ov_int("IRST_HIGH_CENSORSHIP_END", 20),
        ov_int("IRST_ULTRA_STEALTH_START", 10),
        ov_int("IRST_ULTRA_STEALTH_END", 20),
    ];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

// ─────────────────────────────────────────────────────────────────────────────
// score_bridge — non-default weights
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_score_bridge_custom_weights() {
    let record = json!({
        "port": 443,
        "reachable": true,
        "last_seen": FIXED_NOW,
        "transport": "obfs4"
    });
    let overrides = [
        ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT", 2.5),
        ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT", 0.5),
        ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY", 0.0),
        ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY", 1.5),
    ];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_all_weights_zero_falls_back_to_divisor_one() {
    // Python: `total_weight = sum(...) or 1.0` — when every weight is
    // clamped to 0.0, the divisor becomes 1.0 rather than a ZeroDivisionError.
    let record = json!({ "port": 443, "reachable": true });
    let overrides = [
        ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT", 0.0),
        ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_TRANSPORT", 0.0),
        ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_RECENCY", 0.0),
        ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_REACHABILITY", 0.0),
    ];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_score_bridge_negative_weight_clamped_to_zero() {
    let record = json!({ "port": 443, "reachable": true });
    let overrides = [ov_float("IRAN_BRIDGE_PRIORITIZATION_WEIGHT_PORT", -5.0)];
    let py = python_score_bridge(&record, FIXED_NOW, &overrides);
    let rs = rust_score_bridge(&record, FIXED_NOW, &overrides);
    assert_eq!(py, rs);
}

// ─────────────────────────────────────────────────────────────────────────────
// prioritize_bridges
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_prioritize_bridges_disabled_passthrough() {
    let records = vec![
        json!({"id": 1, "port": 443}),
        json!({"id": 2, "port": 21}),
    ];
    // IRAN_BRIDGE_PRIORITIZATION_ENABLED defaults to false — no override needed.
    let py = python_prioritize_bridges(&records, FIXED_NOW, true, &[]);
    let rs = rust_prioritize_bridges(&records, FIXED_NOW, true, &[]);
    assert_eq!(py, rs);
}

#[test]
fn parity_prioritize_bridges_enabled_sorts_descending() {
    let records = vec![
        json!({"id": "low", "port": 21}),
        json!({
            "id": "high", "port": 443, "reachable": true,
            "last_seen": FIXED_NOW, "transport": "snowflake"
        }),
        json!({"id": "mid", "port": 443}),
    ];
    let overrides = [ov_bool("IRAN_BRIDGE_PRIORITIZATION_ENABLED", true)];
    let py = python_prioritize_bridges(&records, FIXED_NOW, true, &overrides);
    let rs = rust_prioritize_bridges(&records, FIXED_NOW, true, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_prioritize_bridges_tie_break_preserves_original_order() {
    // All three records score identically (empty signals) -> original
    // index order must be preserved in both implementations.
    let records = vec![
        json!({"id": 0}),
        json!({"id": 1}),
        json!({"id": 2}),
        json!({"id": 3}),
    ];
    let overrides = [ov_bool("IRAN_BRIDGE_PRIORITIZATION_ENABLED", true)];
    let py = python_prioritize_bridges(&records, FIXED_NOW, true, &overrides);
    let rs = rust_prioritize_bridges(&records, FIXED_NOW, true, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_prioritize_bridges_unannotated_strips_key() {
    let records = vec![
        json!({"id": "a", "port": 443}),
        json!({"id": "b", "port": 21}),
    ];
    let overrides = [ov_bool("IRAN_BRIDGE_PRIORITIZATION_ENABLED", true)];
    let py = python_prioritize_bridges(&records, FIXED_NOW, false, &overrides);
    let rs = rust_prioritize_bridges(&records, FIXED_NOW, false, &overrides);
    assert_eq!(py, rs);
}

#[test]
fn parity_prioritize_bridges_empty_list() {
    let records: Vec<Value> = vec![];
    let overrides = [ov_bool("IRAN_BRIDGE_PRIORITIZATION_ENABLED", true)];
    let py = python_prioritize_bridges(&records, FIXED_NOW, true, &overrides);
    let rs = rust_prioritize_bridges(&records, FIXED_NOW, true, &overrides);
    assert_eq!(py, rs);
    assert_eq!(py, json!([]));
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-mutation of the original record (Rust-only structural check; the
// borrow checker + `&Map` signature already make this statically true,
// but this documents the guarantee the Python `copy.deepcopy` provides).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn score_bridge_does_not_mutate_input_record() {
    let cfg = default_cfg();
    let now = parse_now(FIXED_NOW);
    let original: Map<String, Value> =
        json!({"port": 443, "raw": "obfs4 1.2.3.4:443 ABC"})
            .as_object()
            .unwrap()
            .clone();
    let before = original.clone();
    let _ = score_bridge(&original, &cfg, now);
    assert_eq!(original, before, "input record must remain unmodified");
}

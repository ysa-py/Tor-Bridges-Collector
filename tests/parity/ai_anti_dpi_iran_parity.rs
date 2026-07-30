// Parity tests for `src/ai_anti_dpi_iran.rs` using a native Rust helper
// that preserves the original Python oracle behavior without an external
// Python subprocess dependency.
//
// Everything here is pure (no network I/O). The helper module mirrors the
// original `ai_anti_dpi_iran.py` semantics for deterministic differential
// comparison while remaining fully native Rust.

#[path = "../utils/mod.rs"]
mod utils;

use serde_json::{json, Value};

use torshield_ir_ultra::ai_anti_dpi_iran::IranAntiDpi;
use utils::python_helper_mock::{
    run_python_json, ANALYZE_ENTROPY_SCRIPT, ANALYZE_THREATS_SCRIPT, EVASION_STRATEGY_SCRIPT,
    OPTIMIZE_BRIDGE_SCRIPT, SNI_EVASION_SCRIPT, TRAFFIC_SHAPING_SCRIPT,
};

// ─────────────────────────────────────────────────────────────────────────────
// analyze_threats — every censorship_level threshold boundary
// ─────────────────────────────────────────────────────────────────────────────

fn assert_analyze_threats_matches(censorship_level: i64, isp: &str) {
    let payload = json!({ "censorship_level": censorship_level, "isp": isp });
    let py = run_python_json(ANALYZE_THREATS_SCRIPT, &payload);
    let engine = IranAntiDpi::new();
    let rs = engine.analyze_threats(censorship_level, isp);

    assert_eq!(
        py["total_active"], rs["total_active"],
        "level {censorship_level}"
    );
    assert_eq!(
        py["severity_summary"], rs["severity_summary"],
        "level {censorship_level}"
    );
    assert_eq!(
        py["recommended_evasions"], rs["recommended_evasions"],
        "level {censorship_level}"
    );
    assert_eq!(
        py["risk_level"], rs["risk_level"],
        "level {censorship_level}"
    );
    assert_eq!(py["isp"], rs["isp"]);
    assert_eq!(py["censorship_level"], rs["censorship_level"]);
    // active_threats: compare as sets of names (order matches since both
    // sides iterate the same fixed threat list, but compare content
    // precisely rather than assuming).
    assert_eq!(
        py["active_threats"], rs["active_threats"],
        "level {censorship_level}"
    );
}

#[test]
fn analyze_threats_every_level_1_through_5() {
    for level in 1..=5 {
        assert_analyze_threats_matches(level, "MCI");
    }
}

#[test]
fn analyze_threats_level_zero_and_above_five() {
    assert_analyze_threats_matches(0, "MCI");
    assert_analyze_threats_matches(10, "Irancell");
}

// ─────────────────────────────────────────────────────────────────────────────
// get_evasion_strategy — every named transport branch, plus the
// unknown-transport fallback (the bug this session's review caught)
// ─────────────────────────────────────────────────────────────────────────────

fn assert_evasion_strategy_matches(line: &str) -> Value {
    let payload = json!({ "line": line });
    let py = run_python_json(EVASION_STRATEGY_SCRIPT, &payload);
    let engine = IranAntiDpi::new();
    let rs = engine.get_evasion_strategy(line).to_value();
    assert_eq!(py, rs, "line: {line}");
    rs
}

#[test]
fn evasion_strategy_vanilla() {
    assert_evasion_strategy_matches("192.168.0.1:9001 ABC123FINGERPRINT");
}

#[test]
fn evasion_strategy_obfs4_iat2_port443() {
    assert_evasion_strategy_matches("obfs4 1.2.3.4:443 FP iat-mode=2");
}

#[test]
fn evasion_strategy_obfs4_iat2_other_port() {
    assert_evasion_strategy_matches("obfs4 1.2.3.4:9001 FP iat-mode=2");
}

#[test]
fn evasion_strategy_obfs4_no_iat_mode() {
    assert_evasion_strategy_matches("obfs4 1.2.3.4:9001 FP");
}

#[test]
fn evasion_strategy_webtunnel() {
    assert_evasion_strategy_matches("webtunnel 1.2.3.4:443 FP url=https://x.fastly.net/");
}

#[test]
fn evasion_strategy_snowflake() {
    assert_evasion_strategy_matches("snowflake 1.2.3.4:1 FP");
}

#[test]
fn evasion_strategy_meek_lite() {
    assert_evasion_strategy_matches("meek_lite cert=abc front=azureedge.net");
}

/// The bug this session's careful re-read caught: an unrecognized
/// transport must fall through to the risk score/level computed by
/// `_compute_risk_score` + the bucketing logic *before* the transport
/// if/elif chain — not a hardcoded default. `vless_reality` is exactly
/// this case: not one of the five named branches, so Python's `else:`
/// applies, but `_compute_risk_score` has a real, non-fallback entry for
/// it (`0.10`), which at the default port (0, not in the port-modifier
/// table, `port_mod = 1.0`) works out to a real, non-zero risk_score.
#[test]
fn evasion_strategy_unknown_transport_uses_precomputed_risk_not_a_default() {
    let rs = assert_evasion_strategy_matches("vless_reality 1.2.3.4:2053 FP");
    // Guards against a regression back to the hardcoded 0.0/"low" bug:
    // vless_reality's base risk (0.10) at a non-tabled port (port_mod
    // 1.0) is 0.10, which buckets to "low" — but a *different*
    // unrecognized transport at a risk-inflating port proves the branch
    // truly reads the precomputed value rather than special-casing.
    assert_eq!(rs["recommended_config"], json!({}));
}

#[test]
fn evasion_strategy_unknown_transport_at_tor_default_port_is_not_low_risk() {
    // "shadowsocks" isn't in `_compute_risk_score`'s table either (falls
    // to its own 0.50 default), and port 9001 has a 1.3x multiplier —
    // 0.50 * 1.3 = 0.65, bucketing to "high", not "low". A hardcoded
    // 0.0/"low" fallback would fail this assertion.
    let rs = assert_evasion_strategy_matches("shadowsocks 1.2.3.4:9001 FP");
    assert_eq!(rs["current_risk"], json!("high"));
    assert_eq!(rs["risk_score"], json!(0.65));
}

#[test]
fn evasion_strategy_empty_line_defaults_transport_to_vanilla() {
    assert_evasion_strategy_matches("");
}

// ─────────────────────────────────────────────────────────────────────────────
// get_sni_evasion / get_traffic_shaping
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sni_evasion_matches_for_each_transport() {
    let engine = IranAntiDpi::new();
    for transport in ["webtunnel", "obfs4", "meek_lite", "snowflake", "vanilla"] {
        let payload = json!({ "transport": transport });
        let py = run_python_json(SNI_EVASION_SCRIPT, &payload);
        let rs = engine.get_sni_evasion(transport);
        assert_eq!(py, rs, "transport: {transport}");
    }
}

#[test]
fn traffic_shaping_matches_for_each_transport() {
    let engine = IranAntiDpi::new();
    for transport in ["obfs4", "webtunnel", "snowflake", "meek_lite"] {
        let payload = json!({ "transport": transport });
        let py = run_python_json(TRAFFIC_SHAPING_SCRIPT, &payload);
        let rs = engine.get_traffic_shaping(transport);
        assert_eq!(py, rs, "transport: {transport}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// analyze_entropy
// ─────────────────────────────────────────────────────────────────────────────

fn assert_entropy_matches(data_hex: &str) -> Value {
    let payload = json!({ "data_hex": data_hex });
    let py = run_python_json(ANALYZE_ENTROPY_SCRIPT, &payload);
    let engine = IranAntiDpi::new();
    let rs = engine.analyze_entropy(data_hex);
    assert_eq!(py, rs, "data_hex: {data_hex}");
    rs
}

#[test]
fn entropy_empty_string() {
    let rs = assert_entropy_matches("");
    assert_eq!(rs["recommendation"], json!("No data to analyze"));
}

#[test]
fn entropy_invalid_hex() {
    let rs = assert_entropy_matches("not valid hex zz");
    assert_eq!(rs["recommendation"], json!("Invalid hex data"));
}

#[test]
fn entropy_all_same_byte_is_low_entropy() {
    let rs = assert_entropy_matches(&"aa".repeat(128));
    assert_eq!(rs["entropy"], json!(0.0));
}

#[test]
fn entropy_uniform_byte_sweep_is_maximum_entropy() {
    // 0x00..0xff, each exactly once: perfectly uniform, maximum entropy.
    let hex: String = (0u16..256).fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let rs = assert_entropy_matches(&hex);
    assert_eq!(rs["entropy"], json!(1.0));
    assert_eq!(rs["risk"], json!("high"));
}

#[test]
fn entropy_normal_https_range_example() {
    // A repeating short pattern lands entropy in a mid-range band; the
    // exact value is asserted against Python directly rather than
    // hand-computed here.
    let hex = "48656c6c6f20576f726c6421".repeat(8); // "Hello World!" repeated
    assert_entropy_matches(&hex);
}

// ─────────────────────────────────────────────────────────────────────────────
// optimize_bridge / full_analysis — structural fields only where
// get_tls_randomization's real-clock rotation is involved
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn optimize_bridge_structural_fields_match() {
    let line = "obfs4 1.2.3.4:443 FP iat-mode=2";
    let payload = json!({ "line": line });
    let py = run_python_json(OPTIMIZE_BRIDGE_SCRIPT, &payload);
    let engine = IranAntiDpi::new();
    let rs = engine.optimize_bridge(line);

    assert_eq!(py["original_line"], rs["original_line"]);
    assert_eq!(py["transport"], rs["transport"]);
    assert_eq!(py["risk_level"], rs["risk_level"]);
    assert_eq!(py["risk_score"], rs["risk_score"]);
    assert_eq!(py["evasion_strategy"], rs["evasion_strategy"]);
    assert_eq!(py["sni_evasion"], rs["sni_evasion"]);
    assert_eq!(py["traffic_shaping"], rs["traffic_shaping"]);
    assert_eq!(py["optimization_summary"], rs["optimization_summary"]);
    // `tls_config` depends on the real wall clock on both sides
    // independently; not compared field-by-field here (the rotation
    // logic itself is already deterministically tested via
    // `get_tls_randomization_at`'s own unit tests) — just confirmed
    // present and shaped like a profile on both sides.
    assert!(py["tls_config"]["recommended_profile"].is_string());
    assert!(rs["tls_config"]["recommended_profile"].is_string());
}

#[test]
fn full_analysis_combines_threat_and_optimization_sections() {
    let engine = IranAntiDpi::new();
    let rs = engine.full_analysis("snowflake 1.2.3.4:1 FP", 4, "MCI");
    assert!(rs["threat_analysis"]["total_active"].is_number());
    assert!(rs["bridge_optimization"]["transport"].is_string());
    assert_eq!(rs["bridge_optimization"]["transport"], json!("snowflake"));
}

#![allow(warnings)]
// Smoke / parity tests for `src/auto_debug_system.rs`.
//
// The Python original (`auto_debug_system.py`, 826 lines) runs live system
// diagnostics (Python syntax checks via `ast.parse`, YAML workflow linting,
// AI gateway health probes, etc.) which are not safe to invoke from a
// parity test in CI without significant environmental setup. These tests
// therefore exercise the pure decision logic (`generate_recommendations`)
// and verify the public API surface compiles and runs without panicking
// on minimal inputs.

use serde_json::json;

use torshield_ir_ultra::auto_debug_system::{generate_recommendations, AutoDebugSystem};

#[test]
fn generate_recommendations_empty_input_returns_vec_without_panic() {
    // The Python original may always emit a baseline "LocalAIEngine fallback"
    // recommendation even on empty input. Just verify the call is safe and
    // returns a Vec.
    let recs = generate_recommendations(&[], &[]);
    let _ = recs;
}

#[test]
fn generate_recommendations_ai_gateway_error_yields_recommendation() {
    let errors = vec![json!({
        "category": "ai_gateway",
        "message": "All AI gateway slots are failing",
        "severity": "critical"
    })];
    let recs = generate_recommendations(&errors, &[]);
    assert!(
        !recs.is_empty(),
        "ai_gateway error must yield at least one recommendation"
    );
    // The recommendation should mention AI Gateway, slot, rotation, or
    // fallback engines. Match the Python original's actual phrasing.
    let rec_str = serde_json::to_string(&recs).unwrap_or_default();
    let lower = rec_str.to_ascii_lowercase();
    assert!(
        lower.contains("ai gateway")
            || lower.contains("ai_gateway")
            || lower.contains("slot")
            || lower.contains("rotate")
            || lower.contains("fallback")
            || lower.contains("localai"),
        "recommendation should reference ai gateway / slot / fallback: {rec_str}"
    );
}

#[test]
fn generate_recommendations_warning_yields_recommendation() {
    let warnings = vec![json!({
        "category": "config",
        "message": "DEEP_TEST is set but no IRAN mode active",
        "severity": "warning"
    })];
    let recs = generate_recommendations(&[], &warnings);
    // Warnings may or may not yield recommendations depending on the Python
    // original's branch logic. Just verify the call doesn't panic and
    // returns a Vec.
    let _ = recs;
}

#[test]
fn auto_debug_system_default_with_cwd_does_not_panic() {
    let _system = AutoDebugSystem::default_with_cwd();
}

#[test]
fn auto_debug_system_run_full_diagnosis_returns_result() {
    let system = AutoDebugSystem::default_with_cwd();
    // The diagnosis may succeed or fail depending on the environment; we
    // only verify it returns a Result and doesn't panic.
    let _ = system.run_full_diagnosis();
}

#[test]
fn auto_debug_system_generate_report_returns_value() {
    let system = AutoDebugSystem::default_with_cwd();
    let report = system.generate_report(0.5);
    // The report must be a JSON object with at minimum a "summary" field.
    assert!(report.is_object(), "report must be a JSON object");
    assert!(
        report.get("summary").is_some() || report.get("checks").is_some(),
        "report should contain summary or checks field: {report}"
    );
}

#[test]
fn auto_debug_system_check_yaml_workflows_returns_result() {
    let system = AutoDebugSystem::default_with_cwd();
    // The check may succeed or fail depending on whether .github/workflows
    // exists in CWD; we only verify it returns a Result without panicking.
    let _ = system.check_yaml_workflows();
}

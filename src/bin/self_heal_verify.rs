//! Self-Healing Verification Binary (Phase 4 — Feature 1)
//!
//! Runs the injected-failure verification suite and exits with:
//! - Exit code 0 if all tests pass
//! - Exit code 1 if any test fails
//!
//! This binary is designed to be called from CI workflows as a
//! self-healing verification step.

use torshield_ir_ultra::injected_failure_tests;

fn main() {
    eprintln!("=== Self-Healing Verification Suite ===");
    eprintln!("Running injected-failure tests...\n");

    let report = injected_failure_tests::test_report();
    let total = report["total_tests"].as_u64().unwrap_or(0);
    let passed = report["passed"].as_u64().unwrap_or(0);
    let failed = report["failed"].as_u64().unwrap_or(0);
    let all_passed = report["all_passed"].as_bool().unwrap_or(false);

    // Print individual test results
    if let Some(tests) = report["tests"].as_array() {
        for test in tests {
            let name = test["test_name"].as_str().unwrap_or("unknown");
            let passed = test["passed"].as_bool().unwrap_or(false);
            let desc = test["description"].as_str().unwrap_or("");
            let status = if passed { "✓ PASS" } else { "✗ FAIL" };
            eprintln!("  {status} {name}: {desc}");
        }
    }

    eprintln!("\n=== Results ===");
    eprintln!("Total: {total} | Passed: {passed} | Failed: {failed}");

    if all_passed {
        eprintln!("\n✓ All self-healing verification tests passed.");
        std::process::exit(0);
    } else {
        eprintln!("\n✗ Some self-healing verification tests failed.");
        eprintln!("Report: {}", serde_json::to_string_pretty(&report).unwrap_or_default());
        std::process::exit(1);
    }
}

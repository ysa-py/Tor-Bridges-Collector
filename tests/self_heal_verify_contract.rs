//! Process-level contract test for the Phase 4 self-healing verification
//! binary (`src/bin/self_heal_verify.rs`).
//!
//! The library-level injected-failure suite (`src/injected_failure_tests.rs`)
//! is already exercised by `cargo test`; this contract additionally runs the
//! **real binary process** (via the `CARGO_BIN_EXE_*` env var Cargo sets for
//! integration tests) so that every CI run of `cargo test --workspace`
//! proves, end-to-end and unattendably, that:
//!
//! 1. the verification binary actually executes the full injected-failure
//!    suite inside a real OS process (not just as a unit test),
//! 2. all 10 synthetic upstream failure modes are transparently recovered by
//!    the source-health, circuit-breaker and telemetry layers, and
//! 3. the process exits 0 — with no crash — exactly as the CI self-healing
//!    hook requires.
//!
//! If any recovery path regresses, this test (and therefore the parity gate)
//! fails loudly instead of silently under-producing bridges.

use std::process::Command;

/// Run the binary and return its captured output.
fn run_self_heal_verify() -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_self_heal_verify"))
        .output()
        .expect("spawn self_heal_verify binary")
}

#[test]
fn self_heal_verify_binary_recovers_all_injected_failures() {
    let output = run_self_heal_verify();

    assert!(
        output.status.success(),
        "self_heal_verify must exit 0; status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));

    // The binary reports to stderr; verify the full suite ran and passed.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Total: 10 | Passed: 10 | Failed: 0"),
        "expected 10/10 injected-failure recoveries, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ All self-healing verification tests passed."),
        "missing success banner in stderr:\n{stderr}"
    );

    // Every one of the 10 injected failure modes must appear as PASS.
    for name in [
        "corrupted_payload_handling",
        "timeout_handling",
        "invalid_bridge_signatures",
        "source_outage_circuit_breaker",
        "partial_data_loss",
        "circuit_breaker_trip_and_recovery",
        "source_health_quarantine_recovery",
        "dedup_under_mixed_sources",
        "censorship_fusion_under_outage",
        "telemetry_anomaly_detection",
    ] {
        assert!(
            stderr.contains(&format!("✓ PASS {name}")),
            "missing PASS line for injected failure mode '{name}':\n{stderr}"
        );
    }
    assert!(!stderr.contains("✗ FAIL"), "found FAIL line in:\n{stderr}");
}

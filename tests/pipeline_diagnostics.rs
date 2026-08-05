//! Regression guards for the whole-run log classifier. These fixtures model
//! the silent-success conditions from the collector incident: MOAT schema
//! mismatch, a zero-handshake verification result, a static FAILSAFE write,
//! and the optional Zig stage being skipped.

use torshield_ir_ultra::pipeline_diagnostics::{analyze_log, AnomalyKind};

#[test]
fn swallowed_collection_defects_are_not_reported_as_healthy() {
    let log = r#"2026-08-05T12:00:00Z Stage 3 — probe_scheduler
MOAT [builtin]: 0 bridges fetched
obfs4 verify: only 0/255 handshakes (minimum 51); retaining TCP-reachable set
FAILSAFE: force-populated webtunnel.txt with 4 static fallback lines
Zig not available — skipping Stage 8q
Process completed with exit code 0
"#;
    let report = analyze_log(log, "run-31004820127");

    assert_eq!(report.total_lines, 6);
    assert_eq!(report.status, "failed");
    assert!(report.failsafe_triggers >= 1);
    for kind in [
        AnomalyKind::MoatEmpty,
        AnomalyKind::HandshakeFailure,
        AnomalyKind::FailsafeFallback,
        AnomalyKind::SkippedStage,
    ] {
        assert!(
            report.events.iter().any(|event| event.kind == kind),
            "missing diagnostic event {kind:?}: {:?}",
            report.events
        );
    }
    assert!(!report.remediation_plan.is_empty());
}

#[test]
fn ordinary_success_is_preserved_without_false_positive_errors() {
    let report = analyze_log(
        "Stage 1 — Scraper (all sources)\ncollection complete: 123 bridges\nStage 9b — Verify publication contract\nPublication contract verified\n",
        "successful-job",
    );
    assert_eq!(report.errors, 0);
    assert_eq!(report.warnings, 0);
    assert_eq!(report.events.len(), 0);
}

#[test]
fn secret_bearing_log_lines_are_redacted_in_events() {
    let report = analyze_log(
        "warning: HTTP 429 Authorization: Bearer super-secret-value\n",
        "secret-fixture",
    );
    assert_eq!(report.events.len(), 1);
    assert!(!report.events[0].raw_line.contains("super-secret-value"));
    assert!(report.events[0].raw_line.contains("***"));
}

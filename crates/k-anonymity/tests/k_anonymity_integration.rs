//! End-to-end integration tests for k-anonymity enforcement.
//!
//! These exercise the full public path — configure a threshold, feed reports,
//! and observe what is withheld versus what is emitted — including the two
//! adversarial cases the Phase-2 contract demands: exactly `k - 1` reports
//! (must be withheld, nothing may be emitted) and exactly `k` reports (must
//! emit a whole batch of `k`).

use chrono::{DateTime, Utc};
use tbc_k_anonymity::{KAnonymityBatcher, Report, Submission};

fn report(id: &str, timestamp: i64) -> Report {
    let at = DateTime::<Utc>::from_timestamp(timestamp, 0).expect("test timestamps are in range");
    Report::new(id.to_owned(), at)
}

#[test]
fn exactly_k_minus_one_reports_are_withheld_and_nothing_is_emitted() {
    let mut batcher = KAnonymityBatcher::new(5).expect("k=5 is valid");
    let mut saw_emission = false;
    for index in 0..4 {
        // k - 1 = 4 reports: every one of them must be withheld.
        match batcher.submit(report(&format!("r{index}"), 1_700_000_000 + index)) {
            Submission::Held { held } => {
                assert_eq!(held, index as usize + 1);
            }
            Submission::Emitted(_) => saw_emission = true,
        }
    }
    assert!(!saw_emission, "k-1 reports must never trigger an emission");
    assert_eq!(batcher.held(), 4);
    assert!(
        !batcher.is_ready(),
        "held count must stay below the threshold"
    );
}

#[test]
fn exactly_k_reports_emit_one_whole_batch_and_drain() {
    let mut batcher = KAnonymityBatcher::new(5).expect("k=5 is valid");
    let mut emitted = None;
    for index in 0..5 {
        match batcher.submit(report(&format!("r{index}"), 1_700_000_000 + index)) {
            Submission::Held { .. } => {}
            Submission::Emitted(batch) => emitted = Some(batch),
        }
    }
    let batch = emitted.expect("the k-th report must emit the whole batch");
    assert_eq!(batch.size, 5);
    assert_eq!(batch.reports.len(), 5);
    assert_eq!(batch.reports[0].id, "r0");
    assert_eq!(batch.reports[4].id, "r4");
    assert_eq!(batcher.held(), 0, "emission drains the batcher");
}

#[test]
fn below_k_reports_can_never_be_observed_individually() {
    // The public API only exposes a count while below k — there is no accessor
    // that returns a single withheld report. This test pins that contract:
    // after k-1 submissions the only observable state is the held count.
    let mut batcher = KAnonymityBatcher::new(5).expect("k=5 is valid");
    for index in 0..4 {
        let submission = batcher.submit(report(&format!("secret-{index}"), 1_700_000_000 + index));
        match submission {
            Submission::Held { held } => assert_eq!(held, index as usize + 1),
            Submission::Emitted(_) => panic!("below-k submission must not emit"),
        }
    }
    assert_eq!(batcher.held(), 4);
    // No batch exists to be serialized: the withheld reports stay in the
    // batcher until a k-th report arrives.
    assert!(!batcher.is_ready());
}

#[test]
fn groups_are_released_whole_in_submission_order() {
    let mut batcher = KAnonymityBatcher::new(3).expect("k=3 is valid");
    batcher.submit(report("first", 1_700_000_000));
    batcher.submit(report("second", 1_700_000_001));
    let batch = match batcher.submit(report("third", 1_700_000_002)) {
        Submission::Emitted(batch) => batch,
        Submission::Held { .. } => panic!("k-th report must emit"),
    };
    let ids: Vec<&str> = batch
        .reports
        .iter()
        .map(|report| report.id.as_str())
        .collect();
    assert_eq!(ids, vec!["first", "second", "third"]);
    assert_eq!(
        batch.first_recorded_at,
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap()
    );
    assert_eq!(
        batch.last_recorded_at,
        DateTime::<Utc>::from_timestamp(1_700_000_002, 0).unwrap()
    );
}

#[test]
fn the_next_batch_needs_another_full_k() {
    let mut batcher = KAnonymityBatcher::new(3).expect("k=3 is valid");
    for index in 0..3 {
        batcher.submit(report(&format!("a{index}"), 1_700_000_000 + index));
    }
    assert_eq!(batcher.held(), 0, "first batch drained");
    // One report after the drain must be held again, never emitted alone.
    assert!(matches!(
        batcher.submit(report("b0", 1_700_000_010)),
        Submission::Held { held: 1 }
    ));
}

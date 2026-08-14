//! The k-anonymity batcher: withhold below `k`, emit whole batches at `k`.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::KAnonymityConfig;
use crate::error::KAnonymityError;
use crate::report::Report;

/// A batch of at least `k` reports released together.
///
/// This is the only way reports leave the batcher: as a group, never singly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Batch {
    /// Number of reports in the batch (equal to the threshold `k`).
    pub size: usize,
    /// Earliest `recorded_at` among the batch's reports.
    pub first_recorded_at: DateTime<Utc>,
    /// Latest `recorded_at` among the batch's reports.
    pub last_recorded_at: DateTime<Utc>,
    /// The reports, in submission order.
    pub reports: Vec<Report>,
}

impl Batch {
    /// Build a batch from a non-empty, ordered report list.
    fn from_reports(reports: Vec<Report>) -> Self {
        let size = reports.len();
        let first_recorded_at = reports
            .iter()
            .map(|report| report.recorded_at)
            .min()
            .unwrap_or_else(Utc::now);
        let last_recorded_at = reports
            .iter()
            .map(|report| report.recorded_at)
            .max()
            .unwrap_or_else(Utc::now);
        Self {
            size,
            first_recorded_at,
            last_recorded_at,
            reports,
        }
    }
}

/// The outcome of one [`KAnonymityBatcher::submit`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// The report was withheld; nothing was emitted. `held` is the number of
    /// reports currently held (always below the threshold `k`).
    Held { held: usize },
    /// The threshold was reached: the whole held batch was emitted.
    Emitted(Batch),
}

/// Aggregates reports and releases them only in groups of at least `k`.
#[derive(Debug, Clone)]
pub struct KAnonymityBatcher {
    k: usize,
    held: Vec<Report>,
}

impl KAnonymityBatcher {
    /// Construct a batcher with threshold `k` (rejects `k == 0`).
    pub fn new(k: usize) -> Result<Self, KAnonymityError> {
        Self::with_config(KAnonymityConfig { k })
    }

    /// Construct a batcher from a validated configuration.
    pub fn with_config(config: KAnonymityConfig) -> Result<Self, KAnonymityError> {
        config.validate()?;
        Ok(Self {
            k: config.k,
            held: Vec::new(),
        })
    }

    /// The configured threshold.
    pub fn k(&self) -> usize {
        self.k
    }

    /// How many reports are currently held (below the threshold).
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Whether a submission would emit a batch (held count is at `k` or above).
    pub fn is_ready(&self) -> bool {
        self.held.len() >= self.k
    }

    /// Submit one report.
    ///
    /// Below `k` held reports, returns [`Submission::Held`] and the report is
    /// withheld (it cannot be observed individually). When the held count
    /// reaches `k`, the entire held batch is returned as
    /// [`Submission::Emitted`] and the batcher drains.
    pub fn submit(&mut self, report: Report) -> Submission {
        self.held.push(report);
        if self.held.len() >= self.k {
            Submission::Emitted(Batch::from_reports(std::mem::take(&mut self.held)))
        } else {
            Submission::Held {
                held: self.held.len(),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn report(id: &str, at: DateTime<Utc>) -> Report {
        Report::new(id, at)
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn exactly_k_minus_one_reports_are_withheld_and_never_emitted() {
        let mut batcher = KAnonymityBatcher::new(3).unwrap();
        let mut submissions = Vec::new();
        for index in 0..2 {
            // k - 1 = 2 reports
            submissions.push(batcher.submit(report(&format!("r{index}"), now())));
        }
        assert_eq!(submissions.len(), 2);
        for submission in &submissions {
            assert!(
                matches!(submission, Submission::Held { .. }),
                "every below-k submission must be held"
            );
        }
        assert_eq!(batcher.held(), 2);
        assert!(!batcher.is_ready());
    }

    #[test]
    fn exactly_k_reports_emit_a_batch_of_k_and_drain() {
        let mut batcher = KAnonymityBatcher::new(3).unwrap();
        let mut emitted = None;
        for index in 0..3 {
            let submission = batcher.submit(report(&format!("r{index}"), now()));
            match submission {
                Submission::Held { held } => assert_eq!(held, index + 1),
                Submission::Emitted(batch) => emitted = Some(batch),
            }
        }
        let batch = emitted.expect("the k-th submission must emit");
        assert_eq!(batch.size, 3);
        assert_eq!(batch.reports.len(), 3);
        assert_eq!(batch.reports[0].id, "r0");
        assert_eq!(batch.reports[2].id, "r2");
        assert_eq!(batcher.held(), 0, "emission drains the batcher");
    }

    #[test]
    fn threshold_of_one_emits_immediately() {
        let mut batcher = KAnonymityBatcher::new(1).unwrap();
        match batcher.submit(report("solo", now())) {
            Submission::Emitted(batch) => assert_eq!(batch.size, 1),
            Submission::Held { .. } => panic!("k=1 must emit on the first report"),
        }
        assert_eq!(batcher.held(), 0);
    }

    #[test]
    fn after_emission_the_next_batch_needs_another_k() {
        let mut batcher = KAnonymityBatcher::new(2).unwrap();
        batcher.submit(report("a", now()));
        assert!(matches!(
            batcher.submit(report("b", now())),
            Submission::Emitted(_)
        ));
        // Next batch starts from zero again: one report is held, not emitted.
        assert!(matches!(
            batcher.submit(report("c", now())),
            Submission::Held { held: 1 }
        ));
    }

    #[test]
    fn batch_window_uses_first_and_last_recorded_at() {
        let mut batcher = KAnonymityBatcher::new(3).unwrap();
        let t0 = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let t1 = DateTime::<Utc>::from_timestamp(1_700_000_010, 0).unwrap();
        let t2 = DateTime::<Utc>::from_timestamp(1_700_000_020, 0).unwrap();
        batcher.submit(report("mid", t1));
        batcher.submit(report("late", t2));
        let batch = match batcher.submit(report("early", t0)) {
            Submission::Emitted(batch) => batch,
            Submission::Held { .. } => panic!("third report must emit"),
        };
        assert_eq!(batch.first_recorded_at, t0);
        assert_eq!(batch.last_recorded_at, t2);
    }

    #[test]
    fn zero_threshold_is_rejected() {
        assert!(matches!(
            KAnonymityBatcher::new(0),
            Err(KAnonymityError::ZeroThreshold { .. })
        ));
    }

    #[test]
    fn batch_serializes_size_and_reports() {
        let mut batcher = KAnonymityBatcher::new(2).unwrap();
        batcher.submit(report("a", now()));
        let batch = match batcher.submit(report("b", now())) {
            Submission::Emitted(batch) => batch,
            Submission::Held { .. } => panic!("second report must emit"),
        };
        let value = serde_json::to_value(&batch).unwrap();
        assert_eq!(value["size"], 2);
        assert_eq!(value["reports"].as_array().unwrap().len(), 2);
        assert!(value["first_recorded_at"].is_string());
    }
}

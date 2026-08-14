//! k-anonymity batching for upstream reports.
//!
//! The agent must not emit a report unless the k-anonymity batch condition is
//! met. [`KAnonymityBatcher`] accumulates [`AnonymizedReport`]s and only
//! releases a batch once at least `threshold` reports are held; below the
//! threshold every submission is queued (withheld), never emitted.

use std::collections::VecDeque;

use crate::error::AgentError;
use crate::report::AnonymizedReport;

/// The outcome of submitting a report to the batcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// The report was queued; the batch is withheld because fewer than
    /// `threshold` reports are held.
    Queued {
        /// How many reports are currently held.
        held: usize,
    },
    /// The threshold was met and a batch of anonymized reports was emitted.
    Emitted(Vec<AnonymizedReport>),
}

/// Accumulates reports until the k-anonymity threshold is met.
#[derive(Debug)]
pub struct KAnonymityBatcher {
    threshold: usize,
    queue: VecDeque<AnonymizedReport>,
}

impl KAnonymityBatcher {
    /// A batcher that emits only when at least `threshold` reports are held.
    pub fn new(threshold: usize) -> Result<Self, AgentError> {
        if threshold == 0 {
            return Err(AgentError::Config(
                "k_anonymity_threshold must be at least one".to_owned(),
            ));
        }
        Ok(Self {
            threshold,
            queue: VecDeque::new(),
        })
    }

    /// The k-anonymity threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// How many reports are currently withheld in the queue.
    pub fn held(&self) -> usize {
        self.queue.len()
    }

    /// Submit one report. Below the threshold it is queued (withheld); at the
    /// threshold the whole queue drains and is emitted as one batch.
    pub fn submit(&mut self, report: AnonymizedReport) -> Submission {
        self.queue.push_back(report);
        if self.queue.len() >= self.threshold {
            Submission::Emitted(self.queue.drain(..).collect())
        } else {
            Submission::Queued {
                held: self.queue.len(),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::report::{AsnClass, Outcome, ReportSource, RttBucket};

    fn report() -> AnonymizedReport {
        AnonymizedReport {
            outcome: Outcome::Success,
            rtt_bucket: RttBucket::Rtt0To50,
            asn_class: AsnClass::Medium,
            token: crate::report::OneTimeToken::generate(),
            source: ReportSource::Phase5Volunteer,
        }
    }

    #[test]
    fn zero_threshold_is_rejected() {
        assert!(KAnonymityBatcher::new(0).is_err());
    }

    #[test]
    fn reports_are_withheld_below_threshold() {
        let mut batcher = KAnonymityBatcher::new(3).unwrap();
        assert_eq!(batcher.submit(report()), Submission::Queued { held: 1 });
        assert_eq!(batcher.submit(report()), Submission::Queued { held: 2 });
        assert_eq!(batcher.held(), 2);
    }

    #[test]
    fn threshold_emits_the_whole_batch_and_drains() {
        let mut batcher = KAnonymityBatcher::new(3).unwrap();
        batcher.submit(report());
        batcher.submit(report());
        let third = batcher.submit(report());
        match third {
            Submission::Emitted(batch) => assert_eq!(batch.len(), 3),
            other => panic!("expected Emitted, got {other:?}"),
        }
        assert_eq!(batcher.held(), 0);
    }

    #[test]
    fn threshold_of_one_emits_immediately() {
        let mut batcher = KAnonymityBatcher::new(1).unwrap();
        match batcher.submit(report()) {
            Submission::Emitted(batch) => assert_eq!(batch.len(), 1),
            other => panic!("expected Emitted, got {other:?}"),
        }
    }
}

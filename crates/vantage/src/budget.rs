//! Quota budget: the in-code guard behind every external call.
//!
//! The master spec requires every external call to be quota-aware and
//! budget-guarded *in code*, not just in documentation. [`Budget`] is a
//! simple, deterministic remaining-call counter that adapters decrement
//! before each HTTP round-trip; once it reaches zero every further call fails
//! with [`VantageError::QuotaExhausted`] instead of being sent.

use crate::error::VantageError;

/// A remaining-external-call budget for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    remaining: u64,
}

impl Budget {
    /// Create a budget allowing `limit` external calls.
    pub fn new(limit: u64) -> Self {
        Self { remaining: limit }
    }

    /// The number of external calls still available.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Reserve one external call, failing once the budget is exhausted.
    pub fn spend(&mut self) -> Result<(), VantageError> {
        if self.remaining == 0 {
            return Err(VantageError::QuotaExhausted);
        }
        self.remaining -= 1;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn budget_spends_down_to_zero() {
        let mut budget = Budget::new(3);
        assert_eq!(budget.remaining(), 3);
        assert!(budget.spend().is_ok());
        assert!(budget.spend().is_ok());
        assert!(budget.spend().is_ok());
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn budget_fails_cleanly_when_exhausted() {
        let mut budget = Budget::new(1);
        assert!(budget.spend().is_ok());
        let error = budget.spend().unwrap_err();
        assert!(matches!(error, VantageError::QuotaExhausted));
        assert_eq!(error.kind_name(), "quota_exhausted");
    }

    #[test]
    fn zero_budget_is_exhausted_immediately() {
        let mut budget = Budget::new(0);
        assert!(budget.spend().is_err());
    }
}

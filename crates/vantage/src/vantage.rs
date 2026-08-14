//! The pluggable [`Vantage`] trait.
//!
//! Every in-country measurement adapter implements this trait: it names the
//! platform it speaks to and turns a [`MeasurementRequest`] into a normalized
//! [`ProbeResult`], spending the shared quota [`Budget`] on every external
//! call so a run can never exceed its budget.

use tbc_core::VantageKind;

use crate::budget::Budget;
use crate::error::VantageError;
use crate::request::{MeasurementRequest, ProbeResult};
use crate::BoxFuture;

/// A pluggable in-country measurement adapter.
pub trait Vantage: Send + Sync {
    /// The vantage kind this adapter represents (used for observation
    /// metadata).
    fn kind(&self) -> VantageKind;

    /// Run a measurement for `request`, spending from `budget` per external
    /// call, and return the normalized result.
    fn run<'a>(
        &'a self,
        request: &'a MeasurementRequest,
        budget: &'a mut Budget,
    ) -> BoxFuture<'a, Result<ProbeResult, VantageError>>;
}

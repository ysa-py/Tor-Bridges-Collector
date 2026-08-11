//! Shared cancellation flag polled by long-running stages so they can
//! flush partial results before the CI runner's follow-up SIGKILL arrives.
//!
//! Set by the pipeline binary's SIGTERM/SIGINT handler; checked by
//! `nin_advanced_bypass::run_main_with_probe_budget` (and any future
//! long-running stage) inside their inner loops.

use std::sync::atomic::{AtomicBool, Ordering};

/// Raised when the process receives SIGTERM (GitHub Actions job
/// cancellation) or SIGINT.  Once set, long-running loops should
/// finalise whatever partial data they have accumulated, write their
/// output files, and return cleanly instead of blocking until the
/// runner escalates to SIGKILL.
pub static CANCELLED: AtomicBool = AtomicBool::new(false);

/// Convenience helper: returns `CANCELLED.load(Ordering::SeqCst)`.
#[inline]
pub fn is_cancelled() -> bool {
    CANCELLED.load(Ordering::SeqCst)
}

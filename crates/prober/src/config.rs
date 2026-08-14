//! Probe configuration and budget guardrails.
//!
//! [`ProbeConfig`] carries the per-bridge and per-run budgets (timeouts,
//! retry counts, backoff bounds, and a per-run bridge cap). Every external
//! probe is bounded by these values in code — not merely by documentation — so
//! a runaway or adversarial endpoint cannot exhaust the runner.

use std::time::Duration;

use crate::error::ProbeError;

/// Configuration for the [`crate::Prober`].
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Budget for DNS resolution plus the TCP connect per attempt.
    pub connect_timeout: Duration,
    /// Budget for each socket read operation.
    pub read_timeout: Duration,
    /// Budget for each socket write operation.
    pub write_timeout: Duration,
    /// Maximum attempts per bridge (1 = no retry).
    pub max_attempts: u32,
    /// Base of the exponential backoff between attempts.
    pub backoff_base: Duration,
    /// Upper bound of the exponential backoff between attempts.
    pub backoff_max: Duration,
    /// Maximum number of bridges probed per run (quota guard).
    pub max_bridges_per_run: usize,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(15),
            max_attempts: 3,
            backoff_base: Duration::from_millis(250),
            backoff_max: Duration::from_secs(5),
            max_bridges_per_run: 1024,
        }
    }
}

impl ProbeConfig {
    /// Reject configurations that would make probes unbounded or degenerate.
    pub fn validate(&self) -> Result<(), ProbeError> {
        if self.connect_timeout.is_zero() {
            return Err(ProbeError::Config(
                "connect_timeout must be greater than zero".to_owned(),
            ));
        }
        if self.read_timeout.is_zero() {
            return Err(ProbeError::Config(
                "read_timeout must be greater than zero".to_owned(),
            ));
        }
        if self.write_timeout.is_zero() {
            return Err(ProbeError::Config(
                "write_timeout must be greater than zero".to_owned(),
            ));
        }
        if self.max_attempts == 0 {
            return Err(ProbeError::Config(
                "max_attempts must be at least one".to_owned(),
            ));
        }
        if self.backoff_base > self.backoff_max {
            return Err(ProbeError::Config(
                "backoff_base must not exceed backoff_max".to_owned(),
            ));
        }
        if self.max_bridges_per_run == 0 {
            return Err(ProbeError::Config(
                "max_bridges_per_run must be at least one".to_owned(),
            ));
        }
        Ok(())
    }
}

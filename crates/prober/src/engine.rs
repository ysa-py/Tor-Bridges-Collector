//! The [`Prober`] engine: per-bridge probing with retry/backoff and a
//! per-run budget guard.
//!
//! [`Prober::probe_bridge`] folds a bridge's attempts into a single
//! [`BridgeProbeResult`] (retrying only transient failures), and
//! [`Prober::probe_many`] runs a batch under the configured bridge budget,
//! recording — rather than silently dropping — any inputs that were skipped.

use std::sync::Arc;
use std::time::Instant;

use tbc_core::{BridgeLine, Clock};

use crate::config::ProbeConfig;
use crate::error::ProbeError;
use crate::probe;
use crate::result::{BridgeProbeResult, ProbeDetail, ProbeOutcome, ProbeReport};
use crate::retry;
use crate::socket::Socket;

/// A handshake-level bridge prober with retry and budget policy.
#[derive(Debug, Clone)]
pub struct Prober {
    config: ProbeConfig,
    clock: Arc<dyn Clock>,
}

impl Prober {
    /// Construct a prober, validating its configuration up front.
    pub fn new(config: ProbeConfig, clock: Arc<dyn Clock>) -> Result<Self, ProbeError> {
        config.validate()?;
        Ok(Self { config, clock })
    }

    /// The active configuration.
    pub fn config(&self) -> &ProbeConfig {
        &self.config
    }

    /// Probe one bridge, folding transient-failure retries into one result.
    pub async fn probe_bridge(&self, bridge: &BridgeLine) -> BridgeProbeResult {
        let bridge_key = bridge.canonical_key();
        let transport = bridge.transport.clone();
        let (outcome, attempts) = match probe::target(bridge) {
            Ok((host, port)) => self.probe_with_retry(bridge, &host, port).await,
            Err(error) => (ProbeOutcome::from_error(&error), 0),
        };
        BridgeProbeResult {
            bridge_key,
            transport,
            outcome,
            attempts,
        }
    }

    /// Probe a batch of bridges under the configured per-run budget. Bridges
    /// beyond the budget are recorded as skipped, never silently dropped.
    pub async fn probe_many(&self, bridges: &[BridgeLine]) -> ProbeReport {
        let mut report = ProbeReport::default();
        let budget = self.config.max_bridges_per_run;
        for bridge in bridges {
            if report.results.len() >= budget {
                report.budget_exhausted = true;
                report.skipped = bridges.len().saturating_sub(report.results.len());
                tracing::warn!(
                    budget,
                    skipped = report.skipped,
                    "probe run budget exhausted; remaining bridges skipped"
                );
                break;
            }
            report.results.push(self.probe_bridge(bridge).await);
        }
        report
    }

    /// Retry a single probe attempt until it succeeds, fails definitively, or
    /// exhausts `max_attempts`, returning the folded outcome and attempt count.
    async fn probe_with_retry(
        &self,
        bridge: &BridgeLine,
        host: &str,
        port: u16,
    ) -> (ProbeOutcome, u32) {
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            match self.probe_once(bridge, host, port).await {
                Ok(detail) => return (ProbeOutcome::reachable(detail), attempts),
                Err(error) => {
                    let retryable = error.is_retryable();
                    let outcome = ProbeOutcome::from_error(&error);
                    if !retryable || attempts >= self.config.max_attempts {
                        return (outcome, attempts);
                    }
                    let delay = retry::backoff_delay(
                        attempts - 1,
                        self.config.backoff_base,
                        self.config.backoff_max,
                    );
                    tracing::debug!(
                        attempts,
                        transport = %bridge.transport,
                        delay_ms = delay.as_millis(),
                        "transient probe failure; retrying after backoff"
                    );
                    tokio::time::sleep(retry::full_jitter(delay)).await;
                }
            }
        }
    }

    /// Connect and run one handshake attempt.
    async fn probe_once(
        &self,
        bridge: &BridgeLine,
        host: &str,
        port: u16,
    ) -> Result<ProbeDetail, ProbeError> {
        let started = Instant::now();
        let mut socket = Socket::connect(host, port, self.config.connect_timeout).await?;
        let evidence =
            probe::handshake(bridge, &mut socket, &self.config, self.clock.as_ref()).await?;
        let rtt_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(ProbeDetail {
            evidence: Some(evidence),
            rtt_ms: Some(rtt_ms),
        })
    }
}

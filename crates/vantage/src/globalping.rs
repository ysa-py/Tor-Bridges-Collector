//! Globalping adapter (free tier, no API key).
//!
//! Submits a one-off ICMP measurement to the Globalping API and polls until it
//! reaches a terminal state, then normalizes the result. Reachability probe
//! kinds are approximated with `ping` (ICMP reachability of the bridge IP);
//! `TcpTraceroute` maps to `traceroute`. This is a vantage-layer reachability
//! signal, not a handshake — which is exactly what a Globalping probe can
//! provide.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::Deserialize;
use tbc_core::{ProbeKind, VantageKind, Verdict};

use crate::budget::Budget;
use crate::error::VantageError;
use crate::platform;
use crate::request::{MeasurementRequest, ProbeResult};
use crate::transport::{HttpTransport, Method, VantageRequest};
use crate::vantage::Vantage;
use crate::BoxFuture;

/// A Globalping in-country measurement adapter.
#[derive(Debug, Clone)]
pub struct GlobalpingVantage {
    base_url: String,
    http: Arc<dyn HttpTransport>,
    max_polls: u32,
    poll_interval: Duration,
}

impl GlobalpingVantage {
    /// Build the adapter from a base URL (no trailing slash), a transport,
    /// and the poll policy.
    pub fn new(
        base_url: String,
        http: Arc<dyn HttpTransport>,
        max_polls: u32,
        poll_interval: Duration,
    ) -> Result<Self, VantageError> {
        if base_url.trim().is_empty() {
            return Err(VantageError::Config(
                "globalping base_url must not be empty".to_owned(),
            ));
        }
        if max_polls == 0 {
            return Err(VantageError::Config(
                "globalping max_polls must be at least one".to_owned(),
            ));
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http,
            max_polls,
            poll_interval,
        })
    }
}

#[derive(Debug, Deserialize)]
struct Created {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Measurement {
    status: String,
    #[serde(default)]
    results: Vec<Probe>,
}

#[derive(Debug, Deserialize)]
struct Probe {
    #[serde(default)]
    result: ProbeResultPayload,
}

#[derive(Debug, Default, Deserialize)]
struct ProbeResultPayload {
    #[serde(default)]
    status: String,
    #[serde(default)]
    resolved_address: Option<String>,
    #[serde(default)]
    raw_output: Option<String>,
    #[serde(default)]
    timings: Vec<Timing>,
}

#[derive(Debug, Deserialize)]
struct Timing {
    rtt: f64,
}

impl Vantage for GlobalpingVantage {
    fn kind(&self) -> VantageKind {
        VantageKind::Globalping
    }

    fn run<'a>(
        &'a self,
        request: &'a MeasurementRequest,
        budget: &'a mut Budget,
    ) -> BoxFuture<'a, Result<ProbeResult, VantageError>> {
        Box::pin(async move {
            let body = serde_json::json!({
                "type": globalping_type(request.probe_kind),
                "target": request.target,
                "limit": 1,
            });
            let body_bytes = serde_json::to_vec(&body)?;

            budget.spend()?;
            let created: Created = platform::parse_json(
                platform::call(
                    self.http.as_ref(),
                    &VantageRequest {
                        method: Method::Post,
                        url: format!("{}/v1/measurements", self.base_url),
                        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                        body: Some(body_bytes),
                    },
                )
                .await?,
                "globalping",
            )?;

            for _ in 0..self.max_polls {
                budget.spend()?;
                let response = platform::call(
                    self.http.as_ref(),
                    &VantageRequest {
                        method: Method::Get,
                        url: format!("{}/v1/measurements/{}", self.base_url, created.id),
                        headers: Vec::new(),
                        body: None,
                    },
                )
                .await?;
                let measurement: Measurement = platform::parse_json(response, "globalping")?;
                match measurement.status.as_str() {
                    "finished" => return normalize(&measurement, &created.id),
                    "failed" => {
                        return Err(VantageError::MeasurementFailed {
                            platform: "globalping",
                            message: "measurement status is failed".to_owned(),
                        })
                    }
                    _ => tokio::time::sleep(self.poll_interval).await,
                }
            }
            Err(VantageError::PollExhausted {
                platform: "globalping",
            })
        })
    }
}

/// Map a probe kind to the Globalping measurement type.
fn globalping_type(probe_kind: ProbeKind) -> &'static str {
    match probe_kind {
        ProbeKind::TcpTraceroute => "traceroute",
        ProbeKind::TcpConnect
        | ProbeKind::Obfs4Handshake
        | ProbeKind::WebTunnelUpgrade
        | ProbeKind::TlsSni
        | ProbeKind::TorBootstrap => "ping",
    }
}

/// Normalize a finished measurement into a `ProbeResult`.
///
/// The reachability signal is deliberately strict: a probe counts as
/// responding only if it returned at least one positive-rtt timing (a reply
/// packet). A `finished` probe with no timings means packet loss or an
/// unanswered probe, which is normalized to [`Verdict::Timeout`]. Probes whose
/// own status is `failed` are skipped.
fn normalize(measurement: &Measurement, id: &str) -> Result<ProbeResult, VantageError> {
    let mut best_rtt: Option<u64> = None;
    let mut reachable = false;
    let mut evidence: Option<String> = None;

    for probe in &measurement.results {
        if probe.result.status == "failed" {
            continue;
        }
        if let Some(rtt) = min_rtt(&probe.result.timings) {
            best_rtt = Some(match best_rtt {
                Some(existing) => existing.min(rtt),
                None => rtt,
            });
            reachable = true;
        }
        if evidence.is_none() {
            evidence = probe.result.raw_output.clone().or_else(|| {
                probe
                    .result
                    .resolved_address
                    .as_ref()
                    .map(|address| format!("resolved {address}"))
            });
        }
    }

    if reachable {
        Ok(ProbeResult {
            verdict: Verdict::Reachable,
            rtt_ms: best_rtt,
            error_class: None,
            raw_evidence: evidence,
            measurement_ref: id.to_owned(),
            measured_at: Utc::now(),
        })
    } else {
        Ok(ProbeResult {
            verdict: Verdict::Timeout,
            rtt_ms: None,
            error_class: Some("no_response".to_owned()),
            raw_evidence: evidence,
            measurement_ref: id.to_owned(),
            measured_at: Utc::now(),
        })
    }
}

fn min_rtt(timings: &[Timing]) -> Option<u64> {
    timings
        .iter()
        .map(|timing| timing.rtt.round() as u64)
        .filter(|rtt| *rtt > 0)
        .min()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn probe_kinds_map_to_measurement_types() {
        assert_eq!(globalping_type(ProbeKind::TcpConnect), "ping");
        assert_eq!(globalping_type(ProbeKind::Obfs4Handshake), "ping");
        assert_eq!(globalping_type(ProbeKind::TcpTraceroute), "traceroute");
    }

    #[test]
    fn normalize_reports_reachable_with_min_rtt() {
        let measurement = Measurement {
            status: "finished".to_owned(),
            results: vec![
                Probe {
                    result: ProbeResultPayload {
                        status: "finished".to_owned(),
                        resolved_address: Some("1.2.3.4".to_owned()),
                        raw_output: Some("64 bytes from 1.2.3.4".to_owned()),
                        timings: vec![Timing { rtt: 22.4 }, Timing { rtt: 18.2 }],
                    },
                },
                Probe {
                    result: ProbeResultPayload {
                        status: "finished".to_owned(),
                        resolved_address: Some("1.2.3.4".to_owned()),
                        raw_output: None,
                        timings: vec![Timing { rtt: 30.0 }],
                    },
                },
            ],
        };
        let result = normalize(&measurement, "gp-1").unwrap();
        assert_eq!(result.verdict, Verdict::Reachable);
        assert_eq!(result.rtt_ms, Some(18));
        assert_eq!(result.measurement_ref, "gp-1");
    }

    #[test]
    fn normalize_reports_timeout_when_no_probe_responded() {
        let measurement = Measurement {
            status: "finished".to_owned(),
            results: vec![Probe {
                result: ProbeResultPayload {
                    status: "finished".to_owned(),
                    resolved_address: None,
                    raw_output: Some("100% packet loss".to_owned()),
                    timings: Vec::new(),
                },
            }],
        };
        let result = normalize(&measurement, "gp-2").unwrap();
        assert_eq!(result.verdict, Verdict::Timeout);
        assert_eq!(result.error_class.as_deref(), Some("no_response"));
    }
}

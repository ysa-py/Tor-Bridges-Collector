//! RIPE Atlas adapter (credit-based, requires an API key).
//!
//! Submits a one-off ICMP measurement to the RIPE Atlas API from an
//! in-country probe (defaulting to `IR`) and polls `/latest/` until results
//! arrive. The API key is required to create measurements; when it is absent
//! the adapter fails cleanly with [`VantageError::MissingApiKey`] rather than
//! pretending a measurement ran.

use std::net::IpAddr;
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

/// A RIPE Atlas in-country measurement adapter.
#[derive(Debug, Clone)]
pub struct RipeAtlasVantage {
    base_url: String,
    http: Arc<dyn HttpTransport>,
    api_key: Option<String>,
    default_country: String,
    max_polls: u32,
    poll_interval: Duration,
}

impl RipeAtlasVantage {
    /// Build the adapter from a base URL, transport, optional API key,
    /// default measurement country, and poll policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: String,
        http: Arc<dyn HttpTransport>,
        api_key: Option<String>,
        default_country: String,
        max_polls: u32,
        poll_interval: Duration,
    ) -> Result<Self, VantageError> {
        if base_url.trim().is_empty() {
            return Err(VantageError::Config(
                "ripe_atlas base_url must not be empty".to_owned(),
            ));
        }
        if max_polls == 0 {
            return Err(VantageError::Config(
                "ripe_atlas max_polls must be at least one".to_owned(),
            ));
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http,
            api_key,
            default_country,
            max_polls,
            poll_interval,
        })
    }

    fn authorization(&self) -> Result<String, VantageError> {
        let key = self.api_key.as_deref().ok_or(VantageError::MissingApiKey {
            platform: "ripe_atlas",
        })?;
        Ok(format!("Key {key}"))
    }

    fn country_for(&self, request: &MeasurementRequest) -> String {
        request
            .country
            .clone()
            .unwrap_or_else(|| self.default_country.clone())
    }
}

#[derive(Debug, Deserialize)]
struct Created {
    measurements: Vec<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct AtlasResult {
    #[serde(default)]
    avg: Option<f64>,
    #[serde(default)]
    rcvd: u64,
    #[serde(default)]
    status: Option<String>,
}

impl Vantage for RipeAtlasVantage {
    fn kind(&self) -> VantageKind {
        VantageKind::RipeAtlas
    }

    fn run<'a>(
        &'a self,
        request: &'a MeasurementRequest,
        budget: &'a mut Budget,
    ) -> BoxFuture<'a, Result<ProbeResult, VantageError>> {
        Box::pin(async move {
            let af = match request.target.parse::<IpAddr>() {
                Ok(ip) if ip.is_ipv6() => 6,
                _ => 4,
            };
            let body = serde_json::json!({
                "definitions": [{
                    "type": atlas_type(request.probe_kind),
                    "target": request.target,
                    "af": af,
                    "description": "tbc-vantage bridge reachability",
                    "is_oneoff": true,
                }],
                "probes": [{
                    "type": "country",
                    "value": self.country_for(request),
                    "requested": 1,
                }],
            });
            let body_bytes = serde_json::to_vec(&body)?;
            let authorization = self.authorization()?;

            budget.spend()?;
            let created: Created = platform::parse_json(
                platform::call(
                    self.http.as_ref(),
                    &VantageRequest {
                        method: Method::Post,
                        url: format!("{}/api/v2/measurements/", self.base_url),
                        headers: vec![
                            ("Authorization".to_owned(), authorization),
                            ("Content-Type".to_owned(), "application/json".to_owned()),
                        ],
                        body: Some(body_bytes),
                    },
                )
                .await?,
                "ripe_atlas",
            )?;
            let id = *created.measurements.first().ok_or_else(|| {
                VantageError::Parse("ripe_atlas created no measurement id".to_owned())
            })?;

            for _ in 0..self.max_polls {
                budget.spend()?;
                let response = platform::call(
                    self.http.as_ref(),
                    &VantageRequest {
                        method: Method::Get,
                        url: format!(
                            "{}/api/v2/measurements/{id}/latest/?key={}",
                            self.base_url,
                            self.api_key.as_deref().unwrap_or("")
                        ),
                        headers: Vec::new(),
                        body: None,
                    },
                )
                .await?;
                let results: Vec<AtlasResult> = platform::parse_json(response, "ripe_atlas")?;
                if !results.is_empty() {
                    return normalize(&results, &id.to_string());
                }
                tokio::time::sleep(self.poll_interval).await;
            }
            Err(VantageError::PollExhausted {
                platform: "ripe_atlas",
            })
        })
    }
}

/// Map a probe kind to the RIPE Atlas measurement type.
fn atlas_type(probe_kind: ProbeKind) -> &'static str {
    match probe_kind {
        ProbeKind::TcpTraceroute => "traceroute",
        ProbeKind::TlsSni => "sslcert",
        ProbeKind::TcpConnect
        | ProbeKind::Obfs4Handshake
        | ProbeKind::WebTunnelUpgrade
        | ProbeKind::TorBootstrap => "ping",
    }
}

/// Normalize the latest RIPE Atlas results into a `ProbeResult`.
fn normalize(results: &[AtlasResult], id: &str) -> Result<ProbeResult, VantageError> {
    let responded = results.iter().any(|result| result.rcvd > 0);
    let best_rtt = results
        .iter()
        .filter_map(|result| result.avg)
        .filter(|avg| *avg > 0.0)
        .fold(None::<f64>, |acc, avg| {
            Some(match acc {
                Some(existing) => existing.min(avg),
                None => avg,
            })
        });

    let raw_evidence = results.first().and_then(|result| result.status.clone());

    if responded {
        Ok(ProbeResult {
            verdict: Verdict::Reachable,
            rtt_ms: best_rtt.map(|avg| avg.round() as u64),
            error_class: None,
            raw_evidence,
            measurement_ref: id.to_owned(),
            measured_at: Utc::now(),
        })
    } else {
        Ok(ProbeResult {
            verdict: Verdict::Timeout,
            rtt_ms: None,
            error_class: Some("no_response".to_owned()),
            raw_evidence,
            measurement_ref: id.to_owned(),
            measured_at: Utc::now(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn probe_kinds_map_to_atlas_types() {
        assert_eq!(atlas_type(ProbeKind::TcpConnect), "ping");
        assert_eq!(atlas_type(ProbeKind::TlsSni), "sslcert");
        assert_eq!(atlas_type(ProbeKind::TcpTraceroute), "traceroute");
    }

    #[test]
    fn normalize_reports_reachable_when_a_probe_responded() {
        let results = vec![
            AtlasResult {
                avg: Some(33.0),
                rcvd: 3,
                status: Some("done".to_owned()),
            },
            AtlasResult {
                avg: Some(28.5),
                rcvd: 3,
                status: Some("done".to_owned()),
            },
        ];
        let result = normalize(&results, "12345").unwrap();
        assert_eq!(result.verdict, Verdict::Reachable);
        assert_eq!(result.rtt_ms, Some(29));
    }

    #[test]
    fn normalize_reports_timeout_when_nothing_responded() {
        let results = vec![AtlasResult {
            avg: None,
            rcvd: 0,
            status: Some("done".to_owned()),
        }];
        let result = normalize(&results, "12346").unwrap();
        assert_eq!(result.verdict, Verdict::Timeout);
        assert_eq!(result.error_class.as_deref(), Some("no_response"));
    }
}

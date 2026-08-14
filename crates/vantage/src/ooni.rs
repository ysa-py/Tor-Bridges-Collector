//! OONI open-data adapter (no API key).
//!
//! OONI publishes censorship measurements taken by volunteers. This adapter
//! queries the OONI API for existing web-connectivity results for a target
//! (typically a WebTunnel/meek front domain) from a country (default `IR`),
//! and normalizes the `confirmed`/`anomaly` flags into a verdict: a
//! `confirmed` block becomes [`tbc_core::Verdict::Blocked`], an unconfirmed
//! `anomaly` is inconclusive, and clean results are reachable.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tbc_core::{VantageKind, Verdict};

use crate::budget::Budget;
use crate::error::VantageError;
use crate::platform;
use crate::request::{MeasurementRequest, ProbeResult};
use crate::transport::{HttpTransport, Method, VantageRequest};
use crate::vantage::Vantage;
use crate::BoxFuture;

/// An OONI open-data adapter.
#[derive(Debug, Clone)]
pub struct OoniVantage {
    base_url: String,
    http: Arc<dyn HttpTransport>,
    default_country: String,
    limit: u32,
}

impl OoniVantage {
    /// Build the adapter from a base URL, transport, default country, and
    /// result limit.
    pub fn new(
        base_url: String,
        http: Arc<dyn HttpTransport>,
        default_country: String,
        limit: u32,
    ) -> Result<Self, VantageError> {
        if base_url.trim().is_empty() {
            return Err(VantageError::Config(
                "ooni base_url must not be empty".to_owned(),
            ));
        }
        if limit == 0 {
            return Err(VantageError::Config(
                "ooni limit must be at least one".to_owned(),
            ));
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http,
            default_country,
            limit,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
struct OoniResponse {
    #[serde(default)]
    results: Vec<OoniMeasurement>,
}

#[derive(Debug, Deserialize)]
struct OoniMeasurement {
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    anomaly: bool,
    #[serde(default)]
    test_name: Option<String>,
    #[serde(default)]
    measurement_start_time: Option<String>,
    #[serde(default)]
    report_id: Option<String>,
}

impl Vantage for OoniVantage {
    fn kind(&self) -> VantageKind {
        VantageKind::Ooni
    }

    fn run<'a>(
        &'a self,
        request: &'a MeasurementRequest,
        budget: &'a mut Budget,
    ) -> BoxFuture<'a, Result<ProbeResult, VantageError>> {
        Box::pin(async move {
            let country = request
                .country
                .clone()
                .unwrap_or_else(|| self.default_country.clone());
            let url = measurements_url(&self.base_url, &country, &request.target, self.limit);

            budget.spend()?;
            let response = platform::call(
                self.http.as_ref(),
                &VantageRequest {
                    method: Method::Get,
                    url,
                    headers: Vec::new(),
                    body: None,
                },
            )
            .await?;
            let parsed: OoniResponse = platform::parse_json(response, "ooni")?;
            Ok(normalize(&parsed))
        })
    }
}

/// Build the measurements query URL, confining the non-`Send`
/// `form_urlencoded::Serializer` to this function so the async block stays
/// `Send`.
fn measurements_url(base_url: &str, country: &str, input: &str, limit: u32) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("probe_cc", country);
    query.append_pair("input", input);
    query.append_pair("test_name", "web_connectivity");
    query.append_pair("limit", &limit.to_string());
    format!("{base_url}/api/v1/measurements?{}", query.finish())
}

/// Normalize OONI results into a `ProbeResult`.
fn normalize(response: &OoniResponse) -> ProbeResult {
    let confirmed = response.results.iter().find(|result| result.confirmed);
    let anomalous = response.results.iter().find(|result| result.anomaly);

    let (verdict, error_class) = if let Some(result) = confirmed {
        (
            Verdict::Blocked {
                evidence: result
                    .test_name
                    .clone()
                    .unwrap_or_else(|| "ooni_confirmed".to_owned()),
            },
            Some("confirmed_blocked".to_owned()),
        )
    } else if anomalous.is_some() {
        (Verdict::Inconclusive, Some("ooni_anomaly".to_owned()))
    } else if response.results.is_empty() {
        (Verdict::Inconclusive, Some("no_data".to_owned()))
    } else {
        (Verdict::Reachable, None)
    };

    let newest = response
        .results
        .iter()
        .filter_map(|result| result.measurement_start_time.as_deref())
        .filter_map(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
        .max();

    ProbeResult {
        verdict,
        rtt_ms: None,
        error_class,
        raw_evidence: confirmed
            .or(anomalous)
            .and_then(|result| result.report_id.clone()),
        measurement_ref: response
            .results
            .first()
            .and_then(|result| result.report_id.clone())
            .unwrap_or_else(|| {
                format!(
                    "ooni:{country_count}",
                    country_count = response.results.len()
                )
            }),
        measured_at: newest
            .map(|timestamp| timestamp.with_timezone(&Utc))
            .unwrap_or_else(Utc::now),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn normalize_confirmed_block_is_blocked() {
        let response = OoniResponse {
            results: vec![OoniMeasurement {
                confirmed: true,
                anomaly: false,
                test_name: Some("web_connectivity".to_owned()),
                measurement_start_time: Some("2026-08-14T00:00:00Z".to_owned()),
                report_id: Some("r-1".to_owned()),
            }],
        };
        let result = normalize(&response);
        assert!(matches!(result.verdict, Verdict::Blocked { .. }));
        assert_eq!(result.error_class.as_deref(), Some("confirmed_blocked"));
        assert_eq!(result.measurement_ref, "r-1");
    }

    #[test]
    fn normalize_anomaly_is_inconclusive() {
        let response = OoniResponse {
            results: vec![OoniMeasurement {
                confirmed: false,
                anomaly: true,
                test_name: None,
                measurement_start_time: None,
                report_id: None,
            }],
        };
        let result = normalize(&response);
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert_eq!(result.error_class.as_deref(), Some("ooni_anomaly"));
    }

    #[test]
    fn normalize_clean_result_is_reachable() {
        let response = OoniResponse {
            results: vec![OoniMeasurement {
                confirmed: false,
                anomaly: false,
                test_name: Some("web_connectivity".to_owned()),
                measurement_start_time: Some("2026-08-13T00:00:00Z".to_owned()),
                report_id: Some("r-2".to_owned()),
            }],
        };
        let result = normalize(&response);
        assert_eq!(result.verdict, Verdict::Reachable);
        assert_eq!(result.measurement_ref, "r-2");
    }

    #[test]
    fn normalize_no_results_is_inconclusive() {
        let result = normalize(&OoniResponse {
            results: Vec::new(),
        });
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert_eq!(result.error_class.as_deref(), Some("no_data"));
    }
}

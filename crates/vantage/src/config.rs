//! Vantage adapter configuration.
//!
//! [`VantageConfig`] carries the platform endpoints, per-request timeout,
//! poll policy, default in-country measurement location, and the run's quota
//! limit. Adapters receive the parts they need from a validated config.

use std::time::Duration;

use crate::error::VantageError;

/// Configuration shared by the vantage adapters.
#[derive(Debug, Clone)]
pub struct VantageConfig {
    /// Globalping API base URL (no trailing slash).
    pub globalping_base_url: String,
    /// RIPE Atlas API base URL (no trailing slash).
    pub ripe_atlas_base_url: String,
    /// OONI API base URL (no trailing slash).
    pub ooni_base_url: String,
    /// Volunteer-agent base URL (no trailing slash).
    pub agent_base_url: String,
    /// Per-HTTP-request timeout.
    pub timeout: Duration,
    /// Maximum poll iterations while waiting for an async measurement.
    pub max_polls: u32,
    /// Delay between poll iterations.
    pub poll_interval: Duration,
    /// Number of external calls allowed for the run (quota).
    pub quota_limit: u64,
    /// Country code used for in-country measurements when a request does not
    /// specify one (`IR` by default — the target censorship environment).
    pub default_country: String,
}

impl Default for VantageConfig {
    fn default() -> Self {
        Self {
            globalping_base_url: "https://api.globalping.io".to_owned(),
            ripe_atlas_base_url: "https://atlas.ripe.net".to_owned(),
            ooni_base_url: "https://api.ooni.io".to_owned(),
            agent_base_url: "http://127.0.0.1:8080".to_owned(),
            timeout: Duration::from_secs(15),
            max_polls: 30,
            poll_interval: Duration::from_secs(2),
            quota_limit: 10_000,
            default_country: "IR".to_owned(),
        }
    }
}

impl VantageConfig {
    /// Reject configurations that would make probes unbounded or ill-formed.
    pub fn validate(&self) -> Result<(), VantageError> {
        for (name, value) in [
            ("globalping_base_url", &self.globalping_base_url),
            ("ripe_atlas_base_url", &self.ripe_atlas_base_url),
            ("ooni_base_url", &self.ooni_base_url),
            ("agent_base_url", &self.agent_base_url),
        ] {
            if value.is_empty() {
                return Err(VantageError::Config(format!("{name} must not be empty")));
            }
        }
        if self.timeout.is_zero() {
            return Err(VantageError::Config(
                "timeout must be greater than zero".to_owned(),
            ));
        }
        if self.max_polls == 0 {
            return Err(VantageError::Config(
                "max_polls must be at least one".to_owned(),
            ));
        }
        if self.quota_limit == 0 {
            return Err(VantageError::Config(
                "quota_limit must be at least one".to_owned(),
            ));
        }
        if self.default_country.len() != 2
            || !self
                .default_country
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic())
        {
            return Err(VantageError::Config(
                "default_country must be a two-letter ISO country code".to_owned(),
            ));
        }
        Ok(())
    }

    /// The country used for an in-country measurement, preferring the
    /// request's explicit country over the configured default.
    pub fn country_for(&self, request: &crate::request::MeasurementRequest) -> String {
        request
            .country
            .clone()
            .unwrap_or_else(|| self.default_country.clone())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        assert!(VantageConfig::default().validate().is_ok());
    }

    #[test]
    fn rejects_empty_base_url() {
        let config = VantageConfig {
            ooni_base_url: String::new(),
            ..VantageConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_bad_country_code() {
        let config = VantageConfig {
            default_country: "Iran".to_owned(),
            ..VantageConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn country_for_prefers_request_country() {
        let config = VantageConfig::default();
        let request = crate::request::MeasurementRequest {
            target: "1.2.3.4".to_owned(),
            port: 443,
            probe_kind: tbc_core::ProbeKind::TcpConnect,
            country: Some("DE".to_owned()),
            asn: None,
        };
        assert_eq!(config.country_for(&request), "DE");
        let no_country = crate::request::MeasurementRequest {
            country: None,
            ..request
        };
        assert_eq!(config.country_for(&no_country), "IR");
    }
}

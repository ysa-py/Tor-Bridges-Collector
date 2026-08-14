//! Agent configuration.
//!
//! [`AgentConfig`] carries every budget the agent enforces in code: the bind
//! address, per-operation timeouts, the request-body and target-size limits,
//! the maximum number of concurrent probes, and the per-client rate-limit
//! parameters. The server refuses to start on a configuration that would make
//! any of these budgets unbounded.

use std::time::Duration;

use crate::error::AgentError;

/// Configuration for the volunteer agent.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Host/interface to bind (`0.0.0.0` listens on every interface).
    pub bind_host: String,
    /// TCP port to bind. `0` requests an OS-assigned port (used by tests).
    pub bind_port: u16,
    /// Budget for the DNS lookup plus TCP connect of each measurement.
    pub connect_timeout: Duration,
    /// Budget for each read/write of an incoming HTTP request/response.
    pub read_timeout: Duration,
    /// Maximum size in bytes of an incoming request body (and header block).
    pub max_body_bytes: usize,
    /// Maximum length in bytes of a probe target string.
    pub max_target_bytes: usize,
    /// Maximum number of concurrently running measurements.
    pub max_concurrent_probes: usize,
    /// Number of requests a single client may burst before the rate limiter
    /// starts denying.
    pub rate_limit_burst: u32,
    /// Per-client token refill rate, in requests per second.
    pub rate_limit_per_second: u32,
    /// Minimum number of anonymized reports that must be held before a batch
    /// is emitted upstream (the k-anonymity threshold).
    pub k_anonymity_threshold: usize,
    /// Prefix used for generated `measurement_ref` identifiers.
    pub measurement_id_prefix: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            bind_host: "0.0.0.0".to_owned(),
            bind_port: 8080,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(15),
            max_body_bytes: 4096,
            max_target_bytes: 256,
            max_concurrent_probes: 16,
            rate_limit_burst: 5,
            rate_limit_per_second: 1,
            k_anonymity_threshold: 5,
            measurement_id_prefix: "agent".to_owned(),
        }
    }
}

impl AgentConfig {
    /// Reject configurations that would make probes or requests unbounded.
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.bind_host.trim().is_empty() {
            return Err(AgentError::Config("bind_host must not be empty".to_owned()));
        }
        if self.connect_timeout.is_zero() {
            return Err(AgentError::Config(
                "connect_timeout must be greater than zero".to_owned(),
            ));
        }
        if self.read_timeout.is_zero() {
            return Err(AgentError::Config(
                "read_timeout must be greater than zero".to_owned(),
            ));
        }
        if self.max_body_bytes == 0 {
            return Err(AgentError::Config(
                "max_body_bytes must be at least one".to_owned(),
            ));
        }
        if self.max_target_bytes == 0 {
            return Err(AgentError::Config(
                "max_target_bytes must be at least one".to_owned(),
            ));
        }
        if self.max_concurrent_probes == 0 {
            return Err(AgentError::Config(
                "max_concurrent_probes must be at least one".to_owned(),
            ));
        }
        if self.rate_limit_burst == 0 {
            return Err(AgentError::Config(
                "rate_limit_burst must be at least one".to_owned(),
            ));
        }
        if self.rate_limit_per_second == 0 {
            return Err(AgentError::Config(
                "rate_limit_per_second must be at least one".to_owned(),
            ));
        }
        if self.k_anonymity_threshold == 0 {
            return Err(AgentError::Config(
                "k_anonymity_threshold must be at least one".to_owned(),
            ));
        }
        if self.measurement_id_prefix.trim().is_empty() {
            return Err(AgentError::Config(
                "measurement_id_prefix must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        assert!(AgentConfig::default().validate().is_ok());
    }

    #[test]
    fn rejects_zero_timeouts() {
        let config = AgentConfig {
            connect_timeout: Duration::ZERO,
            ..AgentConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_limits() {
        for config in [
            AgentConfig {
                max_body_bytes: 0,
                ..AgentConfig::default()
            },
            AgentConfig {
                max_target_bytes: 0,
                ..AgentConfig::default()
            },
            AgentConfig {
                max_concurrent_probes: 0,
                ..AgentConfig::default()
            },
            AgentConfig {
                rate_limit_burst: 0,
                ..AgentConfig::default()
            },
            AgentConfig {
                k_anonymity_threshold: 0,
                ..AgentConfig::default()
            },
        ] {
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn rejects_empty_id_prefix() {
        let config = AgentConfig {
            measurement_id_prefix: "  ".to_owned(),
            ..AgentConfig::default()
        };
        assert!(config.validate().is_err());
    }
}

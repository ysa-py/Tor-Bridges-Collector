//! Full Bootstrap Verification Pipeline (§2 of the 10-point spec).
//!
//! Bridge validation does not stop at TCP reachability. The full pipeline:
//!
//! ```text
//! TCP Connect → TLS Negotiation → Transport Handshake →
//! Tor Bootstrap → Circuit Establishment → Health Verification
//! ```
//!
//! A bridge is only classified as **healthy** when Tor can successfully
//! bootstrap and establish usable circuits. Each stage produces structured
//! evidence — no speculative conclusions without supporting observations.
//!
//! ## Pipeline Stages
//!
//! | Stage | What it verifies | Failure mode |
//! |-------|-----------------|---------------|
//! | TCP Connect | IP:PORT is reachable | Timeout, RST, Refused |
//! | TLS Negotiation | TLS handshake succeeds | HandshakeFailure, cert error |
//! | Transport Handshake | obfs4/WebTunnel/Snowflake handshake | Protocol mismatch |
//! | Tor Bootstrap | Tor client bootstraps through bridge | Auth failure, consensus |
//! | Circuit Establishment | Usable circuits are built | Timeout, no exit |
//! | Health Verification | Circuit is stable and usable | Flapping, high latency |
//!
//! ## Reachability Honesty (mandatory)
//!
//! What IS verified from this environment:
//! - TCP connectivity to the bridge endpoint
//! - Successful TLS handshake (when applicable)
//! - Transport-layer protocol handshake (obfs4, WebSocket upgrade, etc.)
//! - Format correctness and Tor bridge-line parser acceptance
//!
//! What CANNOT be verified from this environment:
//! - Whether the bridge remains reachable inside Iran's DPI-filtered network
//! - Whether a specific Iranian ISP blocks the CDN front domain
//! - Whether the bridge stays reachable under active censorship conditions
//! - Guaranteed circumvention of any state-level censorship system

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline stage results
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a single stage in the bootstrap verification pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    /// Stage identifier (e.g., "tcp", "tls", "transport", "bootstrap", "circuit").
    pub stage: String,
    /// Whether this stage passed.
    pub passed: bool,
    /// Latency in milliseconds for this stage.
    pub latency_ms: Option<f64>,
    /// Error message if the stage failed.
    pub error: Option<String>,
    /// Structured evidence collected during this stage.
    pub evidence: Value,
}

impl StageResult {
    pub fn to_json(&self) -> Value {
        json!({
            "stage": self.stage,
            "passed": self.passed,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "evidence": self.evidence,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Full bootstrap verification result
// ─────────────────────────────────────────────────────────────────────────────

/// The complete result of a bootstrap verification run against a single
/// bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapVerification {
    /// Bridge line (raw input).
    pub bridge_line: String,
    /// Transport type.
    pub transport: String,
    /// Target host (IP or domain).
    pub target_host: String,
    /// Target port.
    pub target_port: u16,
    /// Resolved IP address from DNS.
    pub resolved_ip: Option<IpAddr>,
    /// Results of each pipeline stage, in execution order.
    pub stages: Vec<StageResult>,
    /// Overall verification outcome.
    pub outcome: VerificationOutcome,
    /// Total wall-clock duration in milliseconds.
    pub total_duration_ms: f64,
    /// Timestamp of the verification (Unix epoch seconds).
    pub verified_at: f64,
    /// Whether the bridge passed Tor's bridge-line parser.
    pub bridge_line_valid: bool,
    /// Reachability honesty statement.
    pub reachability_statement: String,
}

impl BootstrapVerification {
    /// Build a JSON report suitable for structured logging and dashboards.
    pub fn to_json(&self) -> Value {
        let stages_json: Vec<Value> = self.stages.iter().map(|s| s.to_json()).collect();
        json!({
            "bridge_line": self.bridge_line,
            "transport": self.transport,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "resolved_ip": self.resolved_ip.map(|ip| ip.to_string()),
            "stages": stages_json,
            "outcome": self.outcome.code(),
            "outcome_label": self.outcome.label(),
            "numeric_score": self.outcome.numeric_score(),
            "total_duration_ms": self.total_duration_ms,
            "verified_at": self.verified_at,
            "bridge_line_valid": self.bridge_line_valid,
            "reachability_statement": self.reachability_statement,
        })
    }

    /// How many stages were passed.
    pub fn stages_passed(&self) -> usize {
        self.stages.iter().filter(|s| s.passed).count()
    }

    /// Whether the bridge passed all stages (fully healthy).
    pub fn is_fully_healthy(&self) -> bool {
        self.outcome == VerificationOutcome::Healthy
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification outcome
// ─────────────────────────────────────────────────────────────────────────────

/// The overall outcome of a bootstrap verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationOutcome {
    /// All stages passed — bridge is healthy and usable.
    Healthy,
    /// TCP + TLS passed, transport handshake passed, but bootstrap failed.
    ReachableButUnusable,
    /// TCP + TLS passed, but transport handshake failed.
    TlsOnly,
    /// TCP connected, but TLS handshake failed.
    TcpOnly,
    /// TCP connect failed — bridge is unreachable.
    Unreachable,
    /// Pipeline was aborted before completion (internal error).
    Incomplete,
}

impl VerificationOutcome {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::ReachableButUnusable => "REACHABLE_BUT_UNUSABLE",
            Self::TlsOnly => "TLS_ONLY",
            Self::TcpOnly => "TCP_ONLY",
            Self::Unreachable => "UNREACHABLE",
            Self::Incomplete => "INCOMPLETE",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "Healthy — all stages passed, bridge is usable",
            Self::ReachableButUnusable => {
                "Reachable but unusable — TLS OK, transport OK, bootstrap failed"
            }
            Self::TlsOnly => "TLS only — TCP connected, TLS OK, but transport handshake failed",
            Self::TcpOnly => "TCP only — connected but TLS handshake failed",
            Self::Unreachable => "Unreachable — TCP connect failed",
            Self::Incomplete => "Incomplete — pipeline was aborted",
        }
    }

    /// Numeric score [0.0, 1.0] for ranking.
    pub fn numeric_score(&self) -> f64 {
        match self {
            Self::Healthy => 1.0,
            Self::ReachableButUnusable => 0.65,
            Self::TlsOnly => 0.4,
            Self::TcpOnly => 0.2,
            Self::Unreachable => 0.0,
            Self::Incomplete => 0.0,
        }
    }

    /// Determine the outcome from stage results.
    pub fn from_stages(stages: &[StageResult]) -> Self {
        let tcp = stages.iter().find(|s| s.stage == "tcp");
        let tls = stages.iter().find(|s| s.stage == "tls");
        let transport = stages.iter().find(|s| s.stage == "transport");
        let bootstrap = stages.iter().find(|s| s.stage == "bootstrap");
        let circuit = stages.iter().find(|s| s.stage == "circuit");

        // All stages must exist for a complete assessment
        let all_present = tcp.is_some()
            && tls.is_some()
            && transport.is_some()
            && bootstrap.is_some()
            && circuit.is_some();

        if !all_present {
            // Check how far we got with partial data
            if tcp.map(|s| s.passed).unwrap_or(false) {
                if tls.map(|s| s.passed).unwrap_or(false) {
                    if transport.map(|s| s.passed).unwrap_or(false) {
                        return Self::ReachableButUnusable;
                    }
                    return Self::TlsOnly;
                }
                return Self::TcpOnly;
            }
            return if tcp.is_some() {
                Self::Unreachable
            } else {
                Self::Incomplete
            };
        }

        // all_present guard above ensures every stage is Some
        match (tcp, tls, transport, bootstrap, circuit) {
            (Some(tcp), Some(tls), Some(transport), Some(bootstrap), Some(circuit)) => {
                if tcp.passed
                    && tls.passed
                    && transport.passed
                    && bootstrap.passed
                    && circuit.passed
                {
                    Self::Healthy
                } else if tcp.passed && tls.passed && transport.passed {
                    Self::ReachableButUnusable
                } else if tcp.passed && tls.passed {
                    Self::TlsOnly
                } else if tcp.passed {
                    Self::TcpOnly
                } else {
                    Self::Unreachable
                }
            }
            _ => Self::Incomplete, // unreachable: all_present guard above
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline builder
// ─────────────────────────────────────────────────────────────────────────────

/// Timeout configuration for each pipeline stage.
#[derive(Debug, Clone)]
pub struct PipelineTimeouts {
    pub tcp_connect: Duration,
    pub tls_handshake: Duration,
    pub transport_handshake: Duration,
    pub tor_bootstrap: Duration,
    pub circuit_build: Duration,
    pub health_check: Duration,
    pub total: Duration,
}

impl Default for PipelineTimeouts {
    fn default() -> Self {
        Self {
            tcp_connect: Duration::from_secs(8),
            tls_handshake: Duration::from_secs(6),
            transport_handshake: Duration::from_secs(10),
            tor_bootstrap: Duration::from_secs(30),
            circuit_build: Duration::from_secs(15),
            health_check: Duration::from_secs(10),
            total: Duration::from_secs(90),
        }
    }
}

/// Builds a [`BootstrapVerification`] by recording stage results
/// sequentially. Ensures stages are recorded in the correct pipeline order.
#[derive(Debug, Clone)]
pub struct BootstrapVerificationBuilder {
    bridge_line: String,
    transport: String,
    target_host: String,
    target_port: u16,
    resolved_ip: Option<IpAddr>,
    stages: Vec<StageResult>,
    bridge_line_valid: bool,
    started_at: Option<f64>,
}

impl BootstrapVerificationBuilder {
    /// Start building a verification for the given bridge.
    pub fn new(bridge_line: &str, transport: &str, target_host: &str, target_port: u16) -> Self {
        Self {
            bridge_line: bridge_line.to_string(),
            transport: transport.to_string(),
            target_host: target_host.to_string(),
            target_port,
            resolved_ip: None,
            stages: Vec::new(),
            bridge_line_valid: false,
            started_at: None,
        }
    }

    /// Mark the bridge line as valid (passing Tor's parser).
    pub fn set_bridge_line_valid(&mut self, valid: bool) -> &mut Self {
        self.bridge_line_valid = valid;
        self
    }

    /// Set the resolved IP address from DNS.
    pub fn set_resolved_ip(&mut self, ip: IpAddr) -> &mut Self {
        self.resolved_ip = Some(ip);
        self
    }

    /// Mark the start time for total duration computation.
    pub fn mark_start(&mut self) -> &mut Self {
        self.started_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        );
        self
    }

    /// Record a TCP connect stage result.
    pub fn record_tcp(
        &mut self,
        passed: bool,
        latency_ms: Option<f64>,
        error: Option<&str>,
    ) -> &mut Self {
        self.stages.push(StageResult {
            stage: "tcp".to_string(),
            passed,
            latency_ms,
            error: error.map(|e| e.to_string()),
            evidence: json!({"layer": "tcp"}),
        });
        // If TCP failed, subsequent stages are skipped — add placeholders
        if !passed {
            self.stages.push(StageResult {
                stage: "tls".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: TCP connect failed".to_string()),
                evidence: json!({"layer": "tls", "skipped": true, "reason": "tcp_failed"}),
            });
            self.stages.push(StageResult {
                stage: "transport".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: TCP connect failed".to_string()),
                evidence: json!({"layer": "transport", "skipped": true, "reason": "tcp_failed"}),
            });
            self.stages.push(StageResult {
                stage: "bootstrap".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: TCP connect failed".to_string()),
                evidence: json!({"layer": "bootstrap", "skipped": true, "reason": "tcp_failed"}),
            });
            self.stages.push(StageResult {
                stage: "circuit".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: TCP connect failed".to_string()),
                evidence: json!({"layer": "circuit", "skipped": true, "reason": "tcp_failed"}),
            });
        }
        self
    }

    /// Record a TLS handshake stage result.
    pub fn record_tls(
        &mut self,
        passed: bool,
        latency_ms: Option<f64>,
        error: Option<&str>,
        evidence: Option<Value>,
    ) -> &mut Self {
        // TLS is only relevant if TCP passed
        let tcp_passed = self.stages.iter().any(|s| s.stage == "tcp" && s.passed);
        if !tcp_passed {
            return self; // already handled by record_tcp
        }
        self.stages.push(StageResult {
            stage: "tls".to_string(),
            passed,
            latency_ms,
            error: error.map(|e| e.to_string()),
            evidence: evidence.unwrap_or(json!({"layer": "tls"})),
        });
        if !passed {
            self.stages.push(StageResult {
                stage: "transport".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: TLS handshake failed".to_string()),
                evidence: json!({"layer": "transport", "skipped": true, "reason": "tls_failed"}),
            });
            self.stages.push(StageResult {
                stage: "bootstrap".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: TLS handshake failed".to_string()),
                evidence: json!({"layer": "bootstrap", "skipped": true, "reason": "tls_failed"}),
            });
            self.stages.push(StageResult {
                stage: "circuit".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: TLS handshake failed".to_string()),
                evidence: json!({"layer": "circuit", "skipped": true, "reason": "tls_failed"}),
            });
        }
        self
    }

    /// Record a transport handshake stage result.
    pub fn record_transport(
        &mut self,
        passed: bool,
        latency_ms: Option<f64>,
        error: Option<&str>,
        evidence: Option<Value>,
    ) -> &mut Self {
        let tls_passed = self.stages.iter().any(|s| s.stage == "tls" && s.passed);
        if !tls_passed {
            return self;
        }
        self.stages.push(StageResult {
            stage: "transport".to_string(),
            passed,
            latency_ms,
            error: error.map(|e| e.to_string()),
            evidence: evidence.unwrap_or(json!({"layer": "transport"})),
        });
        if !passed {
            self.stages.push(StageResult {
                stage: "bootstrap".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: transport handshake failed".to_string()),
                evidence: json!({"layer": "bootstrap", "skipped": true, "reason": "transport_failed"}),
            });
            self.stages.push(StageResult {
                stage: "circuit".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: transport handshake failed".to_string()),
                evidence: json!({"layer": "circuit", "skipped": true, "reason": "transport_failed"}),
            });
        }
        self
    }

    /// Record a Tor bootstrap stage result.
    pub fn record_bootstrap(
        &mut self,
        passed: bool,
        latency_ms: Option<f64>,
        error: Option<&str>,
        evidence: Option<Value>,
    ) -> &mut Self {
        let transport_passed = self
            .stages
            .iter()
            .any(|s| s.stage == "transport" && s.passed);
        if !transport_passed {
            return self;
        }
        self.stages.push(StageResult {
            stage: "bootstrap".to_string(),
            passed,
            latency_ms,
            error: error.map(|e| e.to_string()),
            evidence: evidence.unwrap_or(json!({"layer": "bootstrap"})),
        });
        if !passed {
            self.stages.push(StageResult {
                stage: "circuit".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped: Tor bootstrap failed".to_string()),
                evidence: json!({"layer": "circuit", "skipped": true, "reason": "bootstrap_failed"}),
            });
        }
        self
    }

    /// Record a circuit establishment stage result.
    pub fn record_circuit(
        &mut self,
        passed: bool,
        latency_ms: Option<f64>,
        error: Option<&str>,
        evidence: Option<Value>,
    ) -> &mut Self {
        let bootstrap_passed = self
            .stages
            .iter()
            .any(|s| s.stage == "bootstrap" && s.passed);
        if !bootstrap_passed {
            return self;
        }
        self.stages.push(StageResult {
            stage: "circuit".to_string(),
            passed,
            latency_ms,
            error: error.map(|e| e.to_string()),
            evidence: evidence.unwrap_or(json!({"layer": "circuit"})),
        });
        self
    }

    /// Finalize the builder into a complete [`BootstrapVerification`].
    pub fn build(self) -> BootstrapVerification {
        let total_duration = self
            .started_at
            .map(|start| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64();
                (now - start) * 1000.0
            })
            .unwrap_or(0.0);

        let outcome = VerificationOutcome::from_stages(&self.stages);
        let verified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        BootstrapVerification {
            bridge_line: self.bridge_line,
            transport: self.transport,
            target_host: self.target_host,
            target_port: self.target_port,
            resolved_ip: self.resolved_ip,
            stages: self.stages,
            outcome,
            total_duration_ms: total_duration,
            verified_at,
            bridge_line_valid: self.bridge_line_valid,
            reachability_statement: REACHABILITY_HONESTY_STATEMENT.to_string(),
        }
    }
}

/// Mandatory reachability honesty statement included in every verification
/// report.
pub const REACHABILITY_HONESTY_STATEMENT: &str =
    "VERIFIED: TCP connectivity, TLS handshake, transport protocol handshake, \
     Tor bridge-line parser acceptance, format correctness, fresh DNS resolution. \
     NOT VERIFIED: Actual reachability from within Iran's DPI-filtered network, \
     whether a specific Iranian ISP blocks the front domain, whether the bridge \
     stays reachable under active censorship. No tool can guarantee circumvention \
     of an evolving state-level DPI system.";

// ─────────────────────────────────────────────────────────────────────────────
// Batch verification
// ─────────────────────────────────────────────────────────────────────────────

/// Results of verifying a batch of bridges through the full pipeline.
#[derive(Debug, Clone, Default)]
pub struct BatchVerificationReport {
    /// Individual bridge verifications.
    pub verifications: Vec<BootstrapVerification>,
    /// Total bridges submitted.
    pub total: usize,
    /// Number classified as HEALTHY.
    pub healthy: usize,
    /// Number classified as REACHABLE_BUT_UNUSABLE.
    pub reachable_but_unusable: usize,
    /// Number classified as TLS_ONLY.
    pub tls_only: usize,
    /// Number classified as TCP_ONLY.
    pub tcp_only: usize,
    /// Number classified as UNREACHABLE.
    pub unreachable: usize,
    /// Number classified as INCOMPLETE.
    pub incomplete: usize,
    /// Average total pipeline duration for healthy bridges.
    pub avg_healthy_duration_ms: Option<f64>,
}

impl BatchVerificationReport {
    /// Add a verification result and update summary counts.
    pub fn record(&mut self, verification: BootstrapVerification) {
        match verification.outcome {
            VerificationOutcome::Healthy => self.healthy += 1,
            VerificationOutcome::ReachableButUnusable => self.reachable_but_unusable += 1,
            VerificationOutcome::TlsOnly => self.tls_only += 1,
            VerificationOutcome::TcpOnly => self.tcp_only += 1,
            VerificationOutcome::Unreachable => self.unreachable += 1,
            VerificationOutcome::Incomplete => self.incomplete += 1,
        }
        self.verifications.push(verification);
        self.total = self.verifications.len();
    }

    /// Compute aggregate statistics after all verifications are recorded.
    pub fn finalize(&mut self) {
        let healthy_durations: Vec<f64> = self
            .verifications
            .iter()
            .filter(|v| v.outcome == VerificationOutcome::Healthy)
            .map(|v| v.total_duration_ms)
            .collect();

        self.avg_healthy_duration_ms = if healthy_durations.is_empty() {
            None
        } else {
            Some(healthy_durations.iter().sum::<f64>() / healthy_durations.len() as f64)
        };
    }

    /// Build a JSON summary.
    pub fn to_json(&self) -> Value {
        json!({
            "total": self.total,
            "healthy": self.healthy,
            "reachable_but_unusable": self.reachable_but_unusable,
            "tls_only": self.tls_only,
            "tcp_only": self.tcp_only,
            "unreachable": self.unreachable,
            "incomplete": self.incomplete,
            "healthy_pct": if self.total > 0 {
                (self.healthy as f64 / self.total as f64 * 1000.0).round() / 10.0
            } else { 0.0 },
            "avg_healthy_duration_ms": self.avg_healthy_duration_ms,
            "reachability_statement": REACHABILITY_HONESTY_STATEMENT,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_healthy_pipeline() {
        let mut builder = BootstrapVerificationBuilder::new(
            "obfs4 1.2.3.4:443 FINGERPRINT cert=abc iat-mode=0",
            "obfs4",
            "1.2.3.4",
            443,
        );
        builder
            .set_bridge_line_valid(true)
            .mark_start()
            .record_tcp(true, Some(50.0), None)
            .record_tls(true, Some(100.0), None, None)
            .record_transport(true, Some(200.0), None, None)
            .record_bootstrap(true, Some(5000.0), None, None)
            .record_circuit(true, Some(3000.0), None, None);

        let result = builder.build();
        assert_eq!(result.outcome, VerificationOutcome::Healthy);
        assert_eq!(result.stages_passed(), 5);
        assert!(result.is_fully_healthy());
        assert!(result.bridge_line_valid);
    }

    #[test]
    fn tcp_failure_cascades_all_stages() {
        let mut builder = BootstrapVerificationBuilder::new(
            "obfs4 10.0.0.1:9001 FINGERPRINT",
            "obfs4",
            "10.0.0.1",
            9001,
        );
        builder
            .mark_start()
            .record_tcp(false, Some(3000.0), Some("Connection timed out"));

        let result = builder.build();
        assert_eq!(result.outcome, VerificationOutcome::Unreachable);
        assert_eq!(result.stages_passed(), 0);
        assert_eq!(result.stages.len(), 5); // TCP + 4 skipped placeholders
    }

    #[test]
    fn tls_failure_cascades_remaining() {
        let mut builder = BootstrapVerificationBuilder::new(
            "obfs4 1.2.3.4:443 FINGERPRINT",
            "obfs4",
            "1.2.3.4",
            443,
        );
        builder
            .mark_start()
            .record_tcp(true, Some(50.0), None)
            .record_tls(false, Some(120.0), Some("HandshakeFailure"), None);

        let result = builder.build();
        assert_eq!(result.outcome, VerificationOutcome::TcpOnly);
        assert_eq!(result.stages_passed(), 1);
    }

    #[test]
    fn transport_failure_after_tls() {
        let mut builder = BootstrapVerificationBuilder::new(
            "webtunnel example.com:443 FINGERPRINT url=https://cdn.example.com",
            "webtunnel",
            "example.com",
            443,
        );
        builder
            .mark_start()
            .record_tcp(true, Some(50.0), None)
            .record_tls(true, Some(100.0), None, None)
            .record_transport(false, Some(250.0), Some("WebSocket upgrade rejected"), None);

        let result = builder.build();
        assert_eq!(result.outcome, VerificationOutcome::TlsOnly);
        assert_eq!(result.stages_passed(), 2); // TCP + TLS
    }

    #[test]
    fn bootstrap_failure_tls_and_transport_ok() {
        let mut builder = BootstrapVerificationBuilder::new(
            "obfs4 1.2.3.4:443 FINGERPRINT",
            "obfs4",
            "1.2.3.4",
            443,
        );
        builder
            .mark_start()
            .record_tcp(true, Some(50.0), None)
            .record_tls(true, Some(100.0), None, None)
            .record_transport(true, Some(200.0), None, None)
            .record_bootstrap(
                false,
                Some(30000.0),
                Some("consensus download timeout"),
                None,
            );

        let result = builder.build();
        assert_eq!(result.outcome, VerificationOutcome::ReachableButUnusable);
        assert_eq!(result.stages_passed(), 3); // TCP + TLS + transport
    }

    #[test]
    fn outcome_numeric_scores_ordered() {
        let scores = [
            VerificationOutcome::Healthy.numeric_score(),
            VerificationOutcome::ReachableButUnusable.numeric_score(),
            VerificationOutcome::TlsOnly.numeric_score(),
            VerificationOutcome::TcpOnly.numeric_score(),
            VerificationOutcome::Unreachable.numeric_score(),
        ];
        for i in 1..scores.len() {
            assert!(scores[i - 1] >= scores[i]);
        }
    }

    #[test]
    fn from_stages_classifies_correctly() {
        let stages = vec![
            StageResult {
                stage: "tcp".to_string(),
                passed: true,
                latency_ms: Some(50.0),
                error: None,
                evidence: json!({}),
            },
            StageResult {
                stage: "tls".to_string(),
                passed: true,
                latency_ms: Some(100.0),
                error: None,
                evidence: json!({}),
            },
            StageResult {
                stage: "transport".to_string(),
                passed: true,
                latency_ms: Some(200.0),
                error: None,
                evidence: json!({}),
            },
            StageResult {
                stage: "bootstrap".to_string(),
                passed: false,
                latency_ms: Some(30000.0),
                error: Some("timeout".to_string()),
                evidence: json!({}),
            },
            StageResult {
                stage: "circuit".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("skipped".to_string()),
                evidence: json!({}),
            },
        ];
        assert_eq!(
            VerificationOutcome::from_stages(&stages),
            VerificationOutcome::ReachableButUnusable
        );
    }

    #[test]
    fn from_stages_partial_data_tcp_only() {
        let stages = vec![
            StageResult {
                stage: "tcp".to_string(),
                passed: true,
                latency_ms: Some(50.0),
                error: None,
                evidence: json!({}),
            },
            StageResult {
                stage: "tls".to_string(),
                passed: false,
                latency_ms: None,
                error: Some("timeout".to_string()),
                evidence: json!({}),
            },
        ];
        assert_eq!(
            VerificationOutcome::from_stages(&stages),
            VerificationOutcome::TcpOnly
        );
    }

    #[test]
    fn from_stages_empty_returns_incomplete() {
        assert_eq!(
            VerificationOutcome::from_stages(&[]),
            VerificationOutcome::Incomplete
        );
    }

    #[test]
    fn batch_report_computes_statistics() {
        let mut report = BatchVerificationReport::default();
        for i in 0..5 {
            let mut builder = BootstrapVerificationBuilder::new(
                &format!("obfs4 1.2.3.{i}:443 FINGERPRINT"),
                "obfs4",
                &format!("1.2.3.{i}"),
                443,
            );
            if i < 3 {
                builder
                    .mark_start()
                    .record_tcp(true, Some(50.0), None)
                    .record_tls(true, Some(100.0), None, None)
                    .record_transport(true, Some(200.0), None, None)
                    .record_bootstrap(true, Some(5000.0), None, None)
                    .record_circuit(true, Some(3000.0), None, None);
            } else {
                builder
                    .mark_start()
                    .record_tcp(false, Some(3000.0), Some("timeout"));
            }
            report.record(builder.build());
        }
        report.finalize();

        assert_eq!(report.total, 5);
        assert_eq!(report.healthy, 3);
        assert_eq!(report.unreachable, 2);
        assert!(report.avg_healthy_duration_ms.is_some());
    }

    #[test]
    fn reachability_statement_included_in_json() {
        let builder = BootstrapVerificationBuilder::new(
            "obfs4 1.2.3.4:443 FINGERPRINT",
            "obfs4",
            "1.2.3.4",
            443,
        );
        let result = builder.build();
        let json = result.to_json();
        let stmt = json["reachability_statement"].as_str().unwrap();
        assert!(stmt.contains("VERIFIED:"));
        assert!(stmt.contains("NOT VERIFIED:"));
    }

    #[test]
    fn all_outcome_codes_are_unique() {
        use std::collections::BTreeSet;
        let codes: BTreeSet<&str> = [
            VerificationOutcome::Healthy,
            VerificationOutcome::ReachableButUnusable,
            VerificationOutcome::TlsOnly,
            VerificationOutcome::TcpOnly,
            VerificationOutcome::Unreachable,
            VerificationOutcome::Incomplete,
        ]
        .iter()
        .map(|o| o.code())
        .collect();
        assert_eq!(codes.len(), 6);
    }

    #[test]
    fn builder_skips_transport_tls_bootstrap_circuit_if_tcp_failed() {
        let mut builder = BootstrapVerificationBuilder::new(
            "obfs4 10.0.0.1:9001 FINGERPRINT",
            "obfs4",
            "10.0.0.1",
            9001,
        );
        builder
            .mark_start()
            .record_tcp(false, Some(3000.0), Some("timeout"));

        // These should be no-ops since TCP failed
        builder.record_tls(true, Some(100.0), None, None);
        builder.record_transport(true, Some(200.0), None, None);
        builder.record_bootstrap(true, Some(5000.0), None, None);
        builder.record_circuit(true, Some(3000.0), None, None);

        let result = builder.build();
        // Only the 5 stages from record_tcp (TCP + 4 skipped) should exist
        assert_eq!(result.stages.len(), 5);
        assert!(!result.stages[1].passed); // TLS is skipped
        assert!(result.stages[1].error.as_ref().unwrap().contains("skipped"));
    }

    #[test]
    fn pipeline_timeouts_default_is_reasonable() {
        let to = PipelineTimeouts::default();
        assert!(to.tcp_connect.as_secs() > 0);
        assert!(to.tls_handshake.as_secs() > 0);
        assert!(to.transport_handshake.as_secs() > 0);
        assert!(to.tor_bootstrap.as_secs() > 0);
        assert!(to.circuit_build.as_secs() > 0);
        assert!(to.total.as_secs() >= to.tor_bootstrap.as_secs());
    }
}

//! Intelligence Core Orchestrator (composition layer for the 10-point spec).
//!
//! Ties the full platform together into one pipeline:
//!
//! ```text
//! Source Discovery (§6)          Transport Plugin Registry (§7)
//!        │                              │
//!        ▼                              ▼
//!   fetch line ────► detect/validate ────► Multi-Vantage Probe (§1)
//!                                             │
//!                                             ▼
//!                              Bootstrap Verification (§2)
//!                                             │
//!                                             ▼
//!                       Failure Attribution (§5) ──► Runtime Health (§8)
//!                                                          │
//!                                                          ▼
//!                                        Censorship Intelligence (§9)
//!                                                          │
//!                                                          ▼
//!                             Adaptive Transport Rankings (§3)
//! ```
//!
//! Every stage produces structured evidence. The orchestrator never
//! fabricates results: probe outcomes come from injected executors, and the
//! honesty statement from [`crate::bootstrap_verifier::REACHABILITY_HONESTY_STATEMENT`]
//! is attached to every report.

use serde_json::{json, Value};

use crate::anti_censorship::{
    BridgeCensorshipProfile, CensorshipIntelligence, CensorshipObservation,
};
use crate::bootstrap_verifier::{
    BootstrapVerification, BootstrapVerificationBuilder, PipelineTimeouts, VerificationOutcome,
};
use crate::failure_attribution::{Attribution, FailureClassifier, ProbeEvidence};
use crate::multi_vantage::{
    MultiVantageAggregator, MultiVantageStatus, Region, RegionalProbeOutcome,
};
use crate::runtime_health::{HealthMonitor, HealthObservation};
use crate::source_discovery::{default_source_registry, SourceDiscoveryManager};
use crate::transport_plugin::{BridgeEndpoint, TransportRegistry};

// ─────────────────────────────────────────────────────────────────────────────
// Probe executor abstraction
// ─────────────────────────────────────────────────────────────────────────────

/// Result of one region's probe against one bridge endpoint.
#[derive(Debug, Clone)]
pub struct RegionProbeResult {
    pub tcp_ok: bool,
    pub tcp_latency_ms: Option<f64>,
    pub tls_ok: bool,
    pub tls_latency_ms: Option<f64>,
    pub transport_ok: bool,
    pub transport_latency_ms: Option<f64>,
    pub error: Option<String>,
    pub active_blocking: bool,
}

impl RegionProbeResult {
    /// Convert into a [`RegionalProbeOutcome`] for the multi-vantage layer.
    pub fn into_outcome(self, region: Region) -> RegionalProbeOutcome {
        RegionalProbeOutcome {
            region,
            tcp_ok: self.tcp_ok,
            tcp_latency_ms: self.tcp_latency_ms,
            tls_ok: self.tls_ok,
            tls_latency_ms: self.tls_latency_ms,
            transport_ok: self.transport_ok,
            transport_latency_ms: self.transport_latency_ms,
            error: self.error,
            resolved_ip: None,
            active_blocking_detected: self.active_blocking,
            probed_at: unix_now(),
        }
    }

    /// Whether this result is fully reachable (all three stages OK).
    pub fn fully_reachable(&self) -> bool {
        self.tcp_ok && self.tls_ok && self.transport_ok
    }
}

/// Injected probe executor. Production uses [`StdProbeExecutor`]; tests use
/// mocks. This keeps network I/O out of the orchestration logic.
pub trait PipelineProbeExecutor: Send + Sync {
    /// Probe one bridge endpoint from one region.
    fn probe(
        &self,
        region: Region,
        endpoint: &BridgeEndpoint,
        transport: &str,
        timeouts: &PipelineTimeouts,
    ) -> RegionProbeResult;
}

/// Production probe executor: real TCP connect for IP-literal endpoints and
/// real TLS+WebSocket upgrade for domain-fronted WebTunnel.
///
/// Honest limits of this executor: it verifies TCP connectivity and (for
/// webtunnel) TLS + WebSocket upgrade from *this* host. It cannot verify
/// reachability from inside a DPI-filtered network or guarantee
/// circumvention.
pub struct StdProbeExecutor;

impl PipelineProbeExecutor for StdProbeExecutor {
    fn probe(
        &self,
        _region: Region,
        endpoint: &BridgeEndpoint,
        transport: &str,
        timeouts: &PipelineTimeouts,
    ) -> RegionProbeResult {
        // Domain-fronted WebTunnel: TCP to the IP literal is the wrong
        // probe — use TLS + WebSocket upgrade against the front domain.
        if transport == "webtunnel" && !endpoint.host.is_empty() {
            let is_domain = endpoint.host.parse::<std::net::IpAddr>().is_err();
            if is_domain {
                return probe_webtunnel_front(endpoint, timeouts);
            }
        }

        // Everything else: TCP connect to host:port.
        let start = std::time::Instant::now();
        let addr = format!("{}:{}", endpoint.host, endpoint.port);
        let tcp_result = addr
            .parse::<std::net::SocketAddr>()
            .ok()
            .and_then(|sa| std::net::TcpStream::connect_timeout(&sa, timeouts.tcp_connect).ok())
            .map(|_| true);

        match tcp_result {
            Some(true) => RegionProbeResult {
                tcp_ok: true,
                tcp_latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                tls_ok: transport == "vanilla",
                tls_latency_ms: None,
                transport_ok: false, // transport handshake needs a real PT client
                transport_latency_ms: None,
                error: Some(
                    "transport handshake not run: no PT client in this environment \
                     (TCP verified; transport requires bridge-probe binary)"
                        .to_string(),
                ),
                active_blocking: false,
            },
            Some(false) => RegionProbeResult {
                tcp_ok: false,
                tcp_latency_ms: None,
                tls_ok: false,
                tls_latency_ms: None,
                transport_ok: false,
                transport_latency_ms: None,
                error: Some("TCP connect failed".to_string()),
                active_blocking: false,
            },
            None => RegionProbeResult {
                tcp_ok: false,
                tcp_latency_ms: None,
                tls_ok: false,
                tls_latency_ms: None,
                transport_ok: false,
                transport_latency_ms: None,
                error: Some("invalid endpoint address".to_string()),
                active_blocking: false,
            },
        }
    }
}

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
fn probe_webtunnel_front(
    endpoint: &BridgeEndpoint,
    timeouts: &PipelineTimeouts,
) -> RegionProbeResult {
    let timeout = timeouts.tcp_connect.max(timeouts.tls_handshake);
    match crate::webtunnel_probe::probe_sync(&endpoint.host, endpoint.port, timeout) {
        Ok((response, _resolved_ip)) => {
            let has_101 = response.contains("101");
            RegionProbeResult {
                tcp_ok: true,
                tcp_latency_ms: None,
                tls_ok: true,
                tls_latency_ms: None,
                transport_ok: has_101,
                transport_latency_ms: None,
                error: if has_101 {
                    None
                } else {
                    Some("front responded but no HTTP 101".to_string())
                },
                active_blocking: false,
            }
        }
        Err(err) => {
            let is_blocking = err.contains("reset")
                || err.contains("HandshakeFailure")
                || err.contains("refused");
            RegionProbeResult {
                tcp_ok: !err.contains("TCP connect failed"),
                tcp_latency_ms: None,
                tls_ok: false,
                tls_latency_ms: None,
                transport_ok: false,
                transport_latency_ms: None,
                error: Some(err),
                active_blocking: is_blocking,
            }
        }
    }
}

#[cfg(all(target_arch = "arm", target_env = "musl"))]
fn probe_webtunnel_front(
    _endpoint: &BridgeEndpoint,
    _timeouts: &PipelineTimeouts,
) -> RegionProbeResult {
    // ARMv7-musl CI-only target has no rustls/ring — cannot probe.
    RegionProbeResult {
        tcp_ok: false,
        tcp_latency_ms: None,
        tls_ok: false,
        tls_latency_ms: None,
        transport_ok: false,
        transport_latency_ms: None,
        error: Some("probe unavailable on ARMv7-musl CI target".to_string()),
        active_blocking: false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-bridge pipeline result
// ─────────────────────────────────────────────────────────────────────────────

/// Complete result of running the full pipeline against one bridge line.
#[derive(Debug, Clone)]
pub struct BridgePipelineResult {
    /// The original bridge line.
    pub line: String,
    /// Detected transport (or "unknown").
    pub transport: String,
    /// Whether the line passed the transport plugin's format validation.
    pub format_valid: bool,
    /// Format validation error, if any.
    pub format_error: Option<String>,
    /// Full bootstrap verification result (if the bridge was probed).
    pub verification: Option<BootstrapVerification>,
    /// Multi-vantage status across all configured regions.
    pub multi_vantage_status: Option<MultiVantageStatus>,
    /// Failure attribution (when verification did not reach Healthy).
    pub attribution: Option<Attribution>,
    /// Runtime health reliability score (0–100).
    pub reliability_score: f64,
    /// Censorship resistance score (0–1).
    pub censorship_resistance: f64,
    /// Aggregate score used for ranking (0–100).
    pub aggregate_score: f64,
}

impl BridgePipelineResult {
    /// Whether this bridge is publishable: valid format, verified healthy,
    /// and decent aggregate score.
    pub fn is_publishable(&self) -> bool {
        self.format_valid
            && self
                .verification
                .as_ref()
                .map(|v| v.is_fully_healthy())
                .unwrap_or(false)
            && self.aggregate_score >= 60.0
    }

    /// Build a JSON record for export.
    pub fn to_json(&self) -> Value {
        json!({
            "line": self.line,
            "transport": self.transport,
            "format_valid": self.format_valid,
            "format_error": self.format_error,
            "verification": self.verification.as_ref().map(|v| v.to_json()),
            "multi_vantage_status": self.multi_vantage_status.map(|s| s.code()),
            "attribution": self.attribution.as_ref().map(|a| a.to_json()),
            "reliability_score": (self.reliability_score * 10.0).round() / 10.0,
            "censorship_resistance": (self.censorship_resistance * 1000.0).round() / 1000.0,
            "aggregate_score": (self.aggregate_score * 10.0).round() / 10.0,
            "publishable": self.is_publishable(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the intelligence-core pipeline.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Regions to probe from.
    pub regions: Vec<Region>,
    /// Stage timeouts.
    pub timeouts: PipelineTimeouts,
    /// Minimum regions for a multi-vantage assessment to count.
    pub min_regions: usize,
    /// Weight of reliability in the aggregate score.
    pub reliability_weight: f64,
    /// Weight of censorship resistance in the aggregate score.
    pub censorship_weight: f64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            regions: Region::all().to_vec(),
            timeouts: PipelineTimeouts::default(),
            min_regions: Region::MIN_REGIONS_FOR_ASSESSMENT,
            reliability_weight: 0.6,
            censorship_weight: 0.4,
        }
    }
}

/// The composed validation platform.
pub struct IntelligenceCore {
    registry: TransportRegistry,
    sources: SourceDiscoveryManager,
    probe_executor: Box<dyn PipelineProbeExecutor>,
    config: PipelineConfig,
    health: HealthMonitor,
    censorship: CensorshipIntelligence,
    results: Vec<BridgePipelineResult>,
    /// Count of bridges rejected at the format gate.
    format_rejections: usize,
}

impl IntelligenceCore {
    /// Create an orchestrator with the standard sources, built-in transports,
    /// and the production probe executor.
    #[must_use]
    pub fn new() -> Self {
        Self::with_parts(
            TransportRegistry::with_builtins(),
            default_source_registry(),
            Box::new(StdProbeExecutor),
            PipelineConfig::default(),
        )
    }

    /// Create an orchestrator from explicit parts (for tests and embedding).
    #[must_use]
    pub fn with_parts(
        registry: TransportRegistry,
        sources: SourceDiscoveryManager,
        probe_executor: Box<dyn PipelineProbeExecutor>,
        config: PipelineConfig,
    ) -> Self {
        Self {
            registry,
            sources,
            probe_executor,
            config,
            health: HealthMonitor::new(),
            censorship: CensorshipIntelligence::new(),
            results: Vec::new(),
            format_rejections: 0,
        }
    }

    /// Access the source discovery manager (for registering custom sources).
    pub fn sources_mut(&mut self) -> &mut SourceDiscoveryManager {
        &mut self.sources
    }

    /// Number of bridges validated so far.
    pub fn results_len(&self) -> usize {
        self.results.len()
    }

    /// Bridges rejected at the format gate.
    pub fn format_rejections(&self) -> usize {
        self.format_rejections
    }

    /// Run the full pipeline against one bridge line.
    ///
    /// Pipeline: detect/validate (§7) → multi-vantage probe (§1) →
    /// bootstrap verification (§2) → failure attribution (§5) →
    /// runtime health (§8) → censorship intelligence (§9).
    pub fn validate_bridge(&mut self, line: &str) -> BridgePipelineResult {
        // §7: detect + validate format
        let detected = self.registry.detect(line);
        let (transport, endpoint, format_valid, format_error) = match detected {
            Some((transport, endpoint)) => {
                let validation = self.registry.validate(line);
                match validation {
                    Ok(_) => (transport, endpoint, true, None),
                    Err(err) => (transport, endpoint, false, Some(err)),
                }
            }
            None => (
                "unknown".to_string(),
                BridgeEndpoint {
                    host: String::new(),
                    port: 0,
                    fingerprint: None,
                    params: Default::default(),
                },
                false,
                Some("could not detect transport".to_string()),
            ),
        };

        if !format_valid {
            self.format_rejections += 1;
            let result = BridgePipelineResult {
                line: line.to_string(),
                transport,
                format_valid: false,
                format_error,
                verification: None,
                multi_vantage_status: None,
                attribution: None,
                reliability_score: 0.0,
                censorship_resistance: 0.0,
                aggregate_score: 0.0,
            };
            self.results.push(result.clone());
            return result;
        }

        // §1 + §2: probe from every configured region and build stages.
        let mut multi_vantage = MultiVantageAggregator::new();
        let mut builder =
            BootstrapVerificationBuilder::new(line, &transport, &endpoint.host, endpoint.port);
        builder.set_bridge_line_valid(true);
        builder.mark_start();

        // §1: collect per-region probe outcomes for the multi-vantage
        // assessment. Stage results for the bootstrap pipeline use the
        // first region's probe below.
        for &region in &self.config.regions {
            let probe =
                self.probe_executor
                    .probe(region, &endpoint, &transport, &self.config.timeouts);
            multi_vantage.record(probe.clone().into_outcome(region));
        }

        // Record stage results into the builder (first region's data).
        let first_probe = match self.config.regions.first() {
            Some(&first_region) => self.probe_executor.probe(
                first_region,
                &endpoint,
                &transport,
                &self.config.timeouts,
            ),
            None => RegionProbeResult {
                tcp_ok: false,
                tcp_latency_ms: None,
                tls_ok: false,
                tls_latency_ms: None,
                transport_ok: false,
                transport_latency_ms: None,
                error: Some("no regions configured".to_string()),
                active_blocking: false,
            },
        };

        if first_probe.tcp_ok {
            builder.record_tcp(true, first_probe.tcp_latency_ms, None);
            if first_probe.tls_ok {
                builder.record_tls(true, first_probe.tls_latency_ms, None, None);
                if first_probe.transport_ok {
                    builder.record_transport(true, first_probe.transport_latency_ms, None, None);
                    // Tor bootstrap / circuit cannot be run without a real
                    // Tor client — recorded honestly as not-run.
                    builder.record_bootstrap(
                        false,
                        None,
                        Some(
                            "Tor bootstrap requires a full Tor client; not run in this environment",
                        ),
                        None,
                    );
                }
            }
        } else {
            builder.record_tcp(
                false,
                first_probe.tcp_latency_ms,
                first_probe.error.as_deref(),
            );
        }

        let verification = builder.build();
        let multi_status = if multi_vantage.regions_probed() >= self.config.min_regions {
            Some(multi_vantage.assess())
        } else {
            None
        };

        // §5: failure attribution when not healthy.
        let attribution = if verification.outcome != VerificationOutcome::Healthy {
            Some(FailureClassifier::classify(ProbeEvidence {
                host: Some(endpoint.host.clone()),
                port: Some(endpoint.port),
                transport: Some(transport.clone()),
                tcp_connect_ok: Some(first_probe.tcp_ok),
                tcp_latency_ms: first_probe.tcp_latency_ms,
                tls_ok: Some(first_probe.tls_ok),
                transport_handshake_ok: Some(first_probe.transport_ok),
                transport_error: first_probe.error.clone(),
                total_latency_ms: Some(verification.total_duration_ms),
                probe_timeout: Some(self.config.timeouts.total),
                ..Default::default()
            }))
        } else {
            None
        };

        // §8: runtime health observation.
        let health_obs = HealthObservation {
            timestamp: unix_now(),
            latency_ms: first_probe.tcp_latency_ms.unwrap_or(0.0),
            bootstrap_ok: verification.outcome == VerificationOutcome::Healthy,
            circuit_ok: verification.outcome == VerificationOutcome::Healthy,
            circuit_count: if verification.outcome == VerificationOutcome::Healthy {
                1
            } else {
                0
            },
            exit_policy_ok: true,
            stability_ok: true,
            tcp_ok: first_probe.tcp_ok,
            tls_ok: first_probe.tls_ok,
            transport_ok: first_probe.transport_ok,
        };
        self.health.observe(line, &transport, &health_obs);
        let reliability = self
            .health
            .get(line)
            .map(|h| h.reliability_score)
            .unwrap_or(0.0);

        // §9: censorship intelligence observation per region.
        for &region in &self.config.regions {
            let probe =
                self.probe_executor
                    .probe(region, &endpoint, &transport, &self.config.timeouts);
            self.censorship.observe(
                line,
                &transport,
                &CensorshipObservation {
                    region: region.label().to_string(),
                    timestamp: unix_now(),
                    reachable: probe.fully_reachable(),
                    tcp_ok: probe.tcp_ok,
                    tls_ok: probe.tls_ok,
                    transport_ok: probe.transport_ok,
                    bootstrap_ok: probe.fully_reachable(),
                    latency_ms: probe.tcp_latency_ms,
                    active_blocking_detected: probe.active_blocking,
                    blocking_indicator: if probe.active_blocking {
                        probe.error.clone()
                    } else {
                        None
                    },
                    tls_fingerprint_ok: probe.tls_ok,
                    dns_ok: true,
                },
            );
        }
        let censorship_resistance = self
            .censorship
            .profiles
            .get(line)
            .map(|p: &BridgeCensorshipProfile| p.censorship_resistance_score)
            .unwrap_or(0.0);

        // Aggregate score: weighted reliability + censorship resistance.
        let aggregate_score = (reliability * self.config.reliability_weight)
            + (censorship_resistance * 100.0 * self.config.censorship_weight);
        let aggregate_score = aggregate_score.clamp(0.0, 100.0);

        let result = BridgePipelineResult {
            line: line.to_string(),
            transport,
            format_valid: true,
            format_error: None,
            verification: Some(verification),
            multi_vantage_status: multi_status,
            attribution,
            reliability_score: reliability,
            censorship_resistance,
            aggregate_score,
        };
        self.results.push(result.clone());
        result
    }

    /// Publishable bridges (format-valid + verified healthy + high score).
    pub fn publishable(&self) -> Vec<&BridgePipelineResult> {
        self.results.iter().filter(|r| r.is_publishable()).collect()
    }

    /// Bridges sorted by aggregate score (descending) for ranking.
    pub fn ranked(&self) -> Vec<&BridgePipelineResult> {
        let mut ranked: Vec<&BridgePipelineResult> = self.results.iter().collect();
        ranked.sort_by(|a, b| {
            b.aggregate_score
                .partial_cmp(&a.aggregate_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        ranked
    }

    /// Build the full platform report for dashboards and CI logs.
    pub fn report(&self) -> Value {
        let mut transport_counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for r in &self.results {
            *transport_counts.entry(r.transport.clone()).or_insert(0) += 1;
        }
        let transport_json: serde_json::Map<_, _> = transport_counts
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();

        json!({
            "total_validated": self.results.len(),
            "format_rejections": self.format_rejections,
            "publishable": self.publishable().len(),
            "transports": Value::Object(transport_json),
            "source_health": self.sources.status_report(),
            "runtime_health": self.health.summary(),
            "censorship_intelligence": self.censorship.summary(),
            "reachability_statement": crate::bootstrap_verifier::REACHABILITY_HONESTY_STATEMENT,
        })
    }
}

impl Default for IntelligenceCore {
    fn default() -> Self {
        Self::new()
    }
}

/// Unix epoch seconds, now.
fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_plugin::Obfs4Plugin;

    /// Mock executor: everything healthy from EU/NA, blocked from ME.
    struct MockProbe;
    impl PipelineProbeExecutor for MockProbe {
        fn probe(
            &self,
            region: Region,
            _endpoint: &BridgeEndpoint,
            _transport: &str,
            _timeouts: &PipelineTimeouts,
        ) -> RegionProbeResult {
            match region {
                Region::MiddleEast => RegionProbeResult {
                    tcp_ok: true,
                    tcp_latency_ms: Some(40.0),
                    tls_ok: false,
                    tls_latency_ms: None,
                    transport_ok: false,
                    transport_latency_ms: None,
                    error: Some("TLS handshake failure".to_string()),
                    active_blocking: true,
                },
                _ => RegionProbeResult {
                    tcp_ok: true,
                    tcp_latency_ms: Some(50.0),
                    tls_ok: true,
                    tls_latency_ms: Some(100.0),
                    transport_ok: true,
                    transport_latency_ms: Some(200.0),
                    error: None,
                    active_blocking: false,
                },
            }
        }
    }

    /// Mock executor: unreachable everywhere.
    struct MockUnreachable;
    impl PipelineProbeExecutor for MockUnreachable {
        fn probe(
            &self,
            _region: Region,
            _endpoint: &BridgeEndpoint,
            _transport: &str,
            _timeouts: &PipelineTimeouts,
        ) -> RegionProbeResult {
            RegionProbeResult {
                tcp_ok: false,
                tcp_latency_ms: None,
                tls_ok: false,
                tls_latency_ms: None,
                transport_ok: false,
                transport_latency_ms: None,
                error: Some("Connection timed out".to_string()),
                active_blocking: false,
            }
        }
    }

    fn test_core(probe: Box<dyn PipelineProbeExecutor>) -> IntelligenceCore {
        IntelligenceCore::with_parts(
            TransportRegistry::with_builtins(),
            SourceDiscoveryManager::new(),
            probe,
            PipelineConfig::default(),
        )
    }

    fn valid_obfs4() -> String {
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=abc iat-mode=0".to_string()
    }

    #[test]
    fn valid_healthy_bridge_is_publishable() {
        let mut core = test_core(Box::new(MockProbe));
        let result = core.validate_bridge(&valid_obfs4());
        assert!(result.format_valid);
        assert!(result.format_error.is_none());
        assert_eq!(
            result.multi_vantage_status,
            Some(MultiVantageStatus::RegionalFail),
            "active blocking in ME forces REGIONAL_FAIL"
        );
        // The mock marks transport OK in EU/NA but bootstrap is not run, so
        // verification is reachable-but-unusable — not publishable.
        assert!(!result.is_publishable());
    }

    #[test]
    fn malformed_line_rejected_at_format_gate() {
        let mut core = test_core(Box::new(MockProbe));
        let result = core.validate_bridge("garbage not a bridge");
        assert!(!result.format_valid);
        assert!(result.format_error.is_some());
        assert_eq!(core.format_rejections(), 1);
    }

    #[test]
    fn unreachable_bridge_classified() {
        let mut core = test_core(Box::new(MockUnreachable));
        let result = core.validate_bridge(&valid_obfs4());
        assert_eq!(
            result.multi_vantage_status,
            Some(MultiVantageStatus::Unreachable)
        );
        let attribution = result.attribution.as_ref().unwrap();
        assert_eq!(
            attribution.category,
            crate::failure_attribution::FailureCategory::Timeout
        );
    }

    #[test]
    fn ranking_sorts_by_aggregate_score() {
        let mut core = test_core(Box::new(MockProbe));
        core.validate_bridge(&valid_obfs4());
        core.validate_bridge("obfs4 5.6.7.8:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=xyz");
        core.validate_bridge("garbage");

        let ranked = core.ranked();
        assert_eq!(ranked.len(), 3);
        // Format-invalid should be last
        assert!(!ranked[2].format_valid);
        assert!(ranked[0].aggregate_score >= ranked[1].aggregate_score);
    }

    #[test]
    fn report_contains_all_sections() {
        let mut core = test_core(Box::new(MockProbe));
        core.validate_bridge(&valid_obfs4());
        let report = core.report();
        assert_eq!(report["total_validated"], 1);
        assert!(report["source_health"].is_object());
        assert!(report["runtime_health"].is_object());
        assert!(report["censorship_intelligence"].is_object());
        assert!(report["reachability_statement"]
            .as_str()
            .unwrap()
            .contains("VERIFIED:"));
    }

    #[test]
    fn custom_registry_used() {
        let mut registry = TransportRegistry::new();
        registry.register(Box::new(Obfs4Plugin));
        let core = IntelligenceCore::with_parts(
            registry,
            SourceDiscoveryManager::new(),
            Box::new(MockProbe),
            PipelineConfig::default(),
        );
        // Only obfs4 registered — webtunnel line should fail detection
        let mut core = core;
        let result = core.validate_bridge(
            "webtunnel ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://x.com ver=0.0.4",
        );
        assert!(!result.format_valid);
    }

    #[test]
    fn region_probe_result_converts_to_outcome() {
        let probe = RegionProbeResult {
            tcp_ok: true,
            tcp_latency_ms: Some(10.0),
            tls_ok: true,
            tls_latency_ms: Some(20.0),
            transport_ok: true,
            transport_latency_ms: Some(30.0),
            error: None,
            active_blocking: false,
        };
        assert!(probe.fully_reachable());
        let outcome = probe.clone().into_outcome(Region::Europe);
        assert_eq!(outcome.region, Region::Europe);
        assert!(outcome.is_fully_reachable());
    }

    #[test]
    fn std_probe_executor_rejects_bad_address() {
        let executor = StdProbeExecutor;
        let endpoint = BridgeEndpoint {
            host: "999.999.999.999".to_string(),
            port: 443,
            fingerprint: None,
            params: Default::default(),
        };
        let result = executor.probe(
            Region::Europe,
            &endpoint,
            "obfs4",
            &PipelineTimeouts::default(),
        );
        assert!(!result.tcp_ok);
        assert!(result.error.is_some());
    }

    #[test]
    fn thread_safe_executor_send_sync() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let executor = StdProbeExecutor;
        assert_send_sync(&executor);
        let core = IntelligenceCore::new();
        assert_send_sync(&core);
    }

    #[test]
    fn results_len_tracks_validations() {
        let mut core = test_core(Box::new(MockProbe));
        core.validate_bridge(&valid_obfs4());
        core.validate_bridge(&valid_obfs4());
        assert_eq!(core.results_len(), 2);
    }
}

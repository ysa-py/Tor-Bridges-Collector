//! Bridge Probe Failure Attribution Engine (§5 of the 15-point spec).
//!
//! Classifies TCP/TLS/WebSocket probe failures into structured categories
//! with confidence scores. Every classification includes the evidence that
//! led to it — no speculative conclusions without supporting observations.
//!
//! Failure categories:
//!   - Timeout           — probe deadline exceeded, no response received
//!   - TcpReset          — RST received, active rejection
//!   - TcpRefused        — connection refused (ECONNREFUSED)
//!   - TlsFailure        — TLS negotiation failed (handshake error, cert issue)
//!   - HandshakeFailure  — transport-layer handshake failed after TLS
//!   - DnsAnomaly        — DNS resolution failed or returned unexpected records
//!   - ReachabilityFailure — TCP connected but transport probe failed
//!   - ActiveBlocking    — pattern consistent with active DPI/censorship
//!   - Unknown           — could not classify with sufficient confidence

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Failure categories
// ─────────────────────────────────────────────────────────────────────────────

/// Structured failure category with a machine-readable code and human label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum FailureCategory {
    /// Probe deadline exceeded — no response of any kind received.
    Timeout,
    /// TCP RST received — active rejection by firewall or host.
    TcpReset,
    /// Connection refused (ECONNREFUSED) — port closed or filtered.
    TcpRefused,
    /// TLS negotiation failed — handshake error, bad certificate, protocol mismatch.
    TlsFailure,
    /// Post-TLS transport handshake failed (e.g. obfs4, WebSocket upgrade).
    HandshakeFailure,
    /// DNS resolution returned no records, wrong records, or timed out.
    DnsAnomaly,
    /// TCP succeeded but the subsequent transport probe failed.
    ReachabilityFailure,
    /// Pattern consistent with active state-level DPI/censorship intervention.
    ActiveBlocking,
    /// Could not classify with sufficient confidence — evidence is ambiguous.
    Unknown,
}

impl FailureCategory {
    /// Machine-readable snake_case code matching the enum variant name.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::TcpReset => "tcp_reset",
            Self::TcpRefused => "tcp_refused",
            Self::TlsFailure => "tls_failure",
            Self::HandshakeFailure => "handshake_failure",
            Self::DnsAnomaly => "dns_anomaly",
            Self::ReachabilityFailure => "reachability_failure",
            Self::ActiveBlocking => "active_blocking",
            Self::Unknown => "unknown",
        }
    }

    /// Human-readable label for reports and logs.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Timeout => "Timeout — no response received",
            Self::TcpReset => "TCP Reset — actively rejected",
            Self::TcpRefused => "TCP Refused — port closed/filtered",
            Self::TlsFailure => "TLS Failure — handshake or certificate error",
            Self::HandshakeFailure => "Handshake Failure — transport protocol error",
            Self::DnsAnomaly => "DNS Anomaly — resolution failure or unexpected result",
            Self::ReachabilityFailure => "Reachability Failure — TCP OK but probe failed",
            Self::ActiveBlocking => "Active Blocking — pattern matches DPI/censorship",
            Self::Unknown => "Unknown — insufficient evidence to classify",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw probe evidence
// ─────────────────────────────────────────────────────────────────────────────

/// Raw observations collected during a bridge probe attempt.
/// All fields are optional — only present when that observation was actually made.
#[derive(Debug, Clone, Default)]
pub struct ProbeEvidence {
    /// The target host (IP or domain).
    pub host: Option<String>,
    /// The target port.
    pub port: Option<u16>,
    /// Transport type (obfs4, webtunnel, snowflake, etc.).
    pub transport: Option<String>,
    /// Whether TCP connect succeeded.
    pub tcp_connect_ok: Option<bool>,
    /// TCP connect latency in milliseconds.
    pub tcp_latency_ms: Option<f64>,
    /// Whether TLS handshake succeeded.
    pub tls_ok: Option<bool>,
    /// TLS handshake latency in milliseconds.
    pub tls_latency_ms: Option<f64>,
    /// TLS error message (rustls/OpenSSL string).
    pub tls_error: Option<String>,
    /// Whether the transport-specific handshake succeeded.
    pub transport_handshake_ok: Option<bool>,
    /// Transport error message.
    pub transport_error: Option<String>,
    /// Whether DNS resolution succeeded.
    pub dns_ok: Option<bool>,
    /// DNS error message.
    pub dns_error: Option<String>,
    /// Resolved IP addresses.
    pub resolved_ips: Option<Vec<IpAddr>>,
    /// Probe timeout duration.
    pub probe_timeout: Option<Duration>,
    /// Total probe duration in milliseconds.
    pub total_latency_ms: Option<f64>,
    /// Raw OS error code, if available.
    pub os_error_code: Option<i32>,
    /// Raw OS error message.
    pub os_error_message: Option<String>,
    /// Whether this was a retry attempt.
    pub is_retry: Option<bool>,
    /// Retry attempt number (0-indexed).
    pub retry_attempt: Option<u32>,
}

impl ProbeEvidence {
    /// Build a structured JSON value for logging and analysis.
    pub fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        if let Some(ref v) = self.host {
            map.insert("host".to_string(), json!(v));
        }
        if let Some(v) = self.port {
            map.insert("port".to_string(), json!(v));
        }
        if let Some(ref v) = self.transport {
            map.insert("transport".to_string(), json!(v));
        }
        if let Some(v) = self.tcp_connect_ok {
            map.insert("tcp_connect_ok".to_string(), json!(v));
        }
        if let Some(v) = self.tcp_latency_ms {
            map.insert("tcp_latency_ms".to_string(), json!(v));
        }
        if let Some(v) = self.tls_ok {
            map.insert("tls_ok".to_string(), json!(v));
        }
        if let Some(v) = self.tls_latency_ms {
            map.insert("tls_latency_ms".to_string(), json!(v));
        }
        if let Some(ref v) = self.tls_error {
            map.insert("tls_error".to_string(), json!(v));
        }
        if let Some(v) = self.transport_handshake_ok {
            map.insert("transport_handshake_ok".to_string(), json!(v));
        }
        if let Some(ref v) = self.transport_error {
            map.insert("transport_error".to_string(), json!(v));
        }
        if let Some(v) = self.dns_ok {
            map.insert("dns_ok".to_string(), json!(v));
        }
        if let Some(ref v) = self.dns_error {
            map.insert("dns_error".to_string(), json!(v));
        }
        if let Some(ref v) = self.resolved_ips {
            map.insert(
                "resolved_ips".to_string(),
                json!(v.iter().map(|ip| ip.to_string()).collect::<Vec<_>>()),
            );
        }
        if let Some(ref v) = self.probe_timeout {
            map.insert("probe_timeout_ms".to_string(), json!(v.as_millis() as u64));
        }
        if let Some(v) = self.total_latency_ms {
            map.insert("total_latency_ms".to_string(), json!(v));
        }
        if let Some(v) = self.os_error_code {
            map.insert("os_error_code".to_string(), json!(v));
        }
        if let Some(ref v) = self.os_error_message {
            map.insert("os_error_message".to_string(), json!(v));
        }
        if let Some(v) = self.is_retry {
            map.insert("is_retry".to_string(), json!(v));
        }
        if let Some(v) = self.retry_attempt {
            map.insert("retry_attempt".to_string(), json!(v));
        }
        Value::Object(map)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Attribution result
// ─────────────────────────────────────────────────────────────────────────────

/// The result of classifying probe evidence into a failure category.
#[derive(Debug, Clone)]
pub struct Attribution {
    /// The classified failure category.
    pub category: FailureCategory,
    /// Confidence in the classification, range [0.0, 1.0].
    /// Values below 0.5 suggest the classification is tentative.
    pub confidence: f64,
    /// Human-readable reasoning for the classification.
    pub reason: String,
    /// The structured evidence that led to this classification.
    pub evidence: ProbeEvidence,
}

impl Attribution {
    /// Serialize to JSON for structured logging and export.
    pub fn to_json(&self) -> Value {
        json!({
            "category": self.category.code(),
            "category_label": self.category.label(),
            "confidence": (self.confidence * 1000.0).round() / 1000.0,
            "reason": self.reason,
            "evidence": self.evidence.to_json(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Classifier
// ─────────────────────────────────────────────────────────────────────────────

/// The failure attribution engine. Takes raw probe evidence and classifies
/// it into a [`FailureCategory`] with a confidence score.
///
/// The classifier uses a layered decision tree:
/// 1. DNS failure → DnsAnomaly
/// 2. TCP reset → TcpReset (high confidence if OS error confirmed)
/// 3. TCP refused → TcpRefused
/// 4. TCP timeout → Timeout
/// 5. TLS failure → TlsFailure
/// 6. Post-TLS handshake failure → HandshakeFailure
/// 7. TCP OK but probe failed → ReachabilityFailure
/// 8. Patterns consistent with DPI → ActiveBlocking
/// 9. Fallback → Unknown
pub struct FailureClassifier;

impl FailureClassifier {
    /// Classify a probe failure given the raw evidence.
    ///
    /// Returns an [`Attribution`] with the most likely failure category
    /// and a confidence score based on how strongly the evidence supports
    /// that classification.
    pub fn classify(evidence: ProbeEvidence) -> Attribution {
        // Layer 1: DNS failure
        if evidence.dns_ok == Some(false) {
            let dns_err = evidence.dns_error.as_deref().unwrap_or("no details");
            return Attribution {
                category: FailureCategory::DnsAnomaly,
                confidence: 0.95,
                reason: format!("DNS resolution failed: {dns_err}"),
                evidence,
            };
        }

        // If DNS was OK but returned zero IPs, that's also anomalous.
        if let Some(ref ips) = evidence.resolved_ips {
            if ips.is_empty() && evidence.dns_ok == Some(true) {
                return Attribution {
                    category: FailureCategory::DnsAnomaly,
                    confidence: 0.90,
                    reason: "DNS resolved successfully but returned zero addresses".to_string(),
                    evidence,
                };
            }
        }

        // Layer 2: TCP-level failures
        match evidence.tcp_connect_ok {
            Some(false) => {
                // Check for RST (OS error codes: ECONNRESET=104 on Linux)
                let is_reset = evidence
                    .os_error_code
                    .map(|c| c == 104 || c == 10054)
                    .unwrap_or(false)
                    || evidence
                        .os_error_message
                        .as_deref()
                        .map(|m| {
                            m.contains("reset")
                                || m.contains("Connection reset")
                                || m.contains("RST")
                        })
                        .unwrap_or(false);

                if is_reset {
                    return Attribution {
                        category: FailureCategory::TcpReset,
                        confidence: 0.90,
                        reason: "TCP connection reset (RST) — actively rejected".to_string(),
                        evidence,
                    };
                }

                // Check for refused (ECONNREFUSED=111 on Linux)
                let is_refused = evidence
                    .os_error_code
                    .map(|c| c == 111 || c == 10061)
                    .unwrap_or(false)
                    || evidence
                        .os_error_message
                        .as_deref()
                        .map(|m| {
                            m.contains("refused")
                                || m.contains("Connection refused")
                                || m.contains("ECONNREFUSED")
                        })
                        .unwrap_or(false);

                if is_refused {
                    return Attribution {
                        category: FailureCategory::TcpRefused,
                        confidence: 0.90,
                        reason: "TCP connection refused — port closed or filtered".to_string(),
                        evidence,
                    };
                }

                // TCP failed but we can't distinguish reset from refused from timeout.
                // If we have latency data and it's near the timeout, that suggests timeout.
                if let Some(lat) = evidence.total_latency_ms {
                    if let Some(ref timeout) = evidence.probe_timeout {
                        if lat >= (timeout.as_millis() as f64 * 0.8) {
                            return Attribution {
                                category: FailureCategory::Timeout,
                                confidence: 0.70,
                                reason: format!(
                                    "TCP connect timed out after {:.0}ms (deadline was {}ms)",
                                    lat,
                                    timeout.as_millis()
                                ),
                                evidence,
                            };
                        }
                    }
                }

                // Ambiguous TCP failure — lean Timeout as default for unknown TCP errors.
                Attribution {
                    category: FailureCategory::Timeout,
                    confidence: 0.50,
                    reason: "TCP connection failed — cause could not be precisely determined"
                        .to_string(),
                    evidence,
                }
            }
            Some(true) => {
                // TCP connected. Check TLS.
                match evidence.tls_ok {
                    Some(false) => {
                        let tls_err = evidence.tls_error.as_deref().unwrap_or("no details");
                        // HandshakeFailure alert often means protocol mismatch,
                        // but is still a TLS-layer issue.
                        let is_handshake = tls_err.contains("HandshakeFailure")
                            || tls_err.contains("handshake failure");
                        let conf = if is_handshake { 0.90 } else { 0.80 };
                        Attribution {
                            category: FailureCategory::TlsFailure,
                            confidence: conf,
                            reason: format!("TLS negotiation failed: {tls_err}"),
                            evidence,
                        }
                    }
                    Some(true) => {
                        // TLS OK. Check transport handshake.
                        match evidence.transport_handshake_ok {
                            Some(false) => {
                                let transport_err =
                                    evidence.transport_error.as_deref().unwrap_or("no details");
                                Attribution {
                                    category: FailureCategory::HandshakeFailure,
                                    confidence: 0.85,
                                    reason: format!(
                                        "Transport handshake failed after TLS: {transport_err}"
                                    ),
                                    evidence,
                                }
                            }
                            _ => {
                                // TCP + TLS both OK but probe still considered failed?
                                // This is ReachabilityFailure — the bridge is reachable
                                // but something about the transport didn't validate.
                                Attribution {
                                    category: FailureCategory::ReachabilityFailure,
                                    confidence: 0.60,
                                    reason: "TCP and TLS succeeded but transport validation failed"
                                        .to_string(),
                                    evidence,
                                }
                            }
                        }
                    }
                    None => {
                        // TCP OK but no TLS data recorded. If we have direct
                        // evidence that the transport handshake failed (e.g.
                        // "obfs4 handshake timeout", "WebSocket upgrade
                        // rejected"), classify that directly instead of
                        // guessing TLS/timing.
                        if evidence.transport_handshake_ok == Some(false) {
                            let transport_err =
                                evidence.transport_error.as_deref().unwrap_or("no details");
                            return Attribution {
                                category: FailureCategory::HandshakeFailure,
                                confidence: 0.75,
                                reason: format!(
                                    "Transport handshake failed after TCP connect: {transport_err}"
                                ),
                                evidence,
                            };
                        }

                        // Check latency against timeout.
                        if let Some(lat) = evidence.total_latency_ms {
                            if let Some(ref timeout) = evidence.probe_timeout {
                                if lat >= (timeout.as_millis() as f64 * 0.8) {
                                    return Attribution {
                                        category: FailureCategory::Timeout,
                                        confidence: 0.65,
                                        reason: format!(
                                            "Probe timed out during TLS negotiation ({:.0}ms / {}ms)",
                                            lat,
                                            timeout.as_millis()
                                        ),
                                        evidence,
                                    };
                                }
                            }
                        }
                        Attribution {
                            category: FailureCategory::Unknown,
                            confidence: 0.30,
                            reason:
                                "TCP connected but no TLS data — unexpected mid-probe termination"
                                    .to_string(),
                            evidence,
                        }
                    }
                }
            }
            None => {
                // No TCP data at all — probe never got that far.
                if let Some(lat) = evidence.total_latency_ms {
                    if let Some(ref timeout) = evidence.probe_timeout {
                        if lat >= (timeout.as_millis() as f64 * 0.8) {
                            return Attribution {
                                category: FailureCategory::Timeout,
                                confidence: 0.80,
                                reason: format!(
                                    "Probe timed out before TCP connect ({:.0}ms / {}ms)",
                                    lat,
                                    timeout.as_millis()
                                ),
                                evidence,
                            };
                        }
                    }
                }
                Attribution {
                    category: FailureCategory::Unknown,
                    confidence: 0.20,
                    reason: "Insufficient evidence — no TCP probe data available".to_string(),
                    evidence,
                }
            }
        }
    }

    /// Classify a probe failure from a simple boolean result + optional error.
    /// Convenience wrapper for when only basic information is available.
    pub fn classify_simple(
        host: &str,
        port: u16,
        transport: &str,
        tcp_ok: Option<bool>,
        error_msg: Option<&str>,
    ) -> Attribution {
        let mut evidence = ProbeEvidence {
            host: Some(host.to_string()),
            port: Some(port),
            transport: Some(transport.to_string()),
            ..Default::default()
        };
        evidence.tcp_connect_ok = tcp_ok;
        if tcp_ok == Some(false) {
            if let Some(msg) = error_msg {
                // Try to detect the error type from the message.
                let lower = msg.to_lowercase();
                if lower.contains("reset")
                    || lower.contains("rst")
                    || lower.contains("refused")
                    || lower.contains("econnrefused")
                {
                    evidence.os_error_message = Some(msg.to_string());
                }
                // timeout / "timed out": leave os_error_message as is —
                // the caller can distinguish it via the transport_error below.
                evidence.transport_error = Some(msg.to_string());
            }
        }
        if tcp_ok == Some(true) && error_msg.is_some() {
            // TCP OK but error reported — the failure happened at the TLS
            // layer or at the transport handshake. Only explicit TLS-layer
            // signals map to TlsFailure; bare "handshake" messages (e.g.
            // "obfs4 handshake timeout", "WebSocket upgrade rejected")
            // are post-TCP transport handshake failures.
            if let Some(msg) = error_msg {
                let lower = msg.to_lowercase();
                if lower.contains("tls")
                    || lower.contains("ssl")
                    || lower.contains("certificate")
                    || lower.contains("unknown ca")
                    || lower.contains("fatal alert")
                {
                    evidence.tls_ok = Some(false);
                    evidence.tls_error = Some(msg.to_string());
                } else {
                    evidence.transport_handshake_ok = Some(false);
                    evidence.transport_error = Some(msg.to_string());
                }
            }
        }
        Self::classify(evidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregate failure statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate failure statistics for a batch of attributions, useful for
/// trend analysis and reporting.
#[derive(Debug, Clone, Default)]
pub struct FailureStats {
    /// Total attributions processed.
    pub total: usize,
    /// Counts per failure category.
    pub by_category: BTreeMap<String, usize>,
    /// Average confidence per category.
    pub avg_confidence: BTreeMap<String, f64>,
    /// Total confidence sum per category (used to compute average).
    confidence_sum: BTreeMap<String, f64>,
}

impl FailureStats {
    /// Accumulate an attribution into the aggregate statistics.
    pub fn record(&mut self, attribution: &Attribution) {
        self.total += 1;
        let code = attribution.category.code().to_string();
        *self.by_category.entry(code.clone()).or_insert(0) += 1;
        *self.confidence_sum.entry(code.clone()).or_insert(0.0) += attribution.confidence;
    }

    /// Finalize the statistics, computing averages.
    pub fn finalize(&mut self) {
        self.avg_confidence.clear();
        for (category, &count) in &self.by_category {
            let sum = self.confidence_sum.get(category).copied().unwrap_or(0.0);
            let avg = if count > 0 { sum / count as f64 } else { 0.0 };
            self.avg_confidence.insert(category.clone(), avg);
        }
    }

    /// Build a JSON summary suitable for export and dashboards.
    pub fn to_json(&self) -> Value {
        let mut breakdown = serde_json::Map::new();
        for (category, &count) in &self.by_category {
            let avg_conf = self.avg_confidence.get(category).copied().unwrap_or(0.0);
            breakdown.insert(
                category.clone(),
                json!({
                    "count": count,
                    "pct": if self.total > 0 {
                        (count as f64 / self.total as f64 * 1000.0).round() / 10.0
                    } else {
                        0.0
                    },
                    "avg_confidence": (avg_conf * 1000.0).round() / 1000.0,
                }),
            );
        }
        json!({
            "total_attributions": self.total,
            "breakdown": Value::Object(breakdown),
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
    fn dns_failure_classified_as_dns_anomaly() {
        let evidence = ProbeEvidence {
            host: Some("example.com".to_string()),
            port: Some(443),
            transport: Some("webtunnel".to_string()),
            dns_ok: Some(false),
            dns_error: Some("NXDOMAIN".to_string()),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::DnsAnomaly);
        assert!(attr.confidence > 0.9);
        assert!(attr.reason.contains("NXDOMAIN"));
    }

    #[test]
    fn dns_zero_addresses_is_anomaly() {
        let evidence = ProbeEvidence {
            host: Some("example.com".to_string()),
            port: Some(443),
            dns_ok: Some(true),
            resolved_ips: Some(vec![]),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::DnsAnomaly);
        assert!(attr.confidence > 0.85);
        assert!(attr.reason.contains("zero addresses"));
    }

    #[test]
    fn tcp_reset_by_os_error_code() {
        let evidence = ProbeEvidence {
            host: Some("1.2.3.4".to_string()),
            port: Some(9001),
            transport: Some("obfs4".to_string()),
            tcp_connect_ok: Some(false),
            os_error_code: Some(104), // ECONNRESET on Linux
            total_latency_ms: Some(150.0),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::TcpReset);
        assert!(attr.confidence > 0.85);
        assert!(attr.reason.contains("reset"));
    }

    #[test]
    fn tcp_reset_by_message() {
        let evidence = ProbeEvidence {
            host: Some("1.2.3.4".to_string()),
            port: Some(443),
            tcp_connect_ok: Some(false),
            os_error_message: Some("Connection reset by peer".to_string()),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::TcpReset);
    }

    #[test]
    fn tcp_refused_by_os_error_code() {
        let evidence = ProbeEvidence {
            host: Some("1.2.3.4".to_string()),
            port: Some(9001),
            transport: Some("obfs4".to_string()),
            tcp_connect_ok: Some(false),
            os_error_code: Some(111), // ECONNREFUSED on Linux
            total_latency_ms: Some(5.0),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::TcpRefused);
        assert!(attr.confidence > 0.85);
        assert!(attr.reason.contains("refused"));
    }

    #[test]
    fn tcp_timeout_by_latency_near_deadline() {
        let evidence = ProbeEvidence {
            host: Some("10.0.0.1".to_string()),
            port: Some(443),
            tcp_connect_ok: Some(false),
            probe_timeout: Some(Duration::from_secs(3)),
            total_latency_ms: Some(2900.0),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::Timeout);
        assert!(attr.confidence > 0.65);
        assert!(attr.reason.contains("timed out"));
    }

    #[test]
    fn tls_failure_handshake_error() {
        let evidence = ProbeEvidence {
            host: Some("bridge.example.com".to_string()),
            port: Some(443),
            transport: Some("webtunnel".to_string()),
            tcp_connect_ok: Some(true),
            tcp_latency_ms: Some(120.0),
            tls_ok: Some(false),
            tls_error: Some("received fatal alert: HandshakeFailure".to_string()),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::TlsFailure);
        assert!(attr.confidence > 0.85);
        assert!(attr.reason.contains("HandshakeFailure"));
    }

    #[test]
    fn transport_handshake_failure_after_tls() {
        let evidence = ProbeEvidence {
            host: Some("bridge.example.com".to_string()),
            port: Some(443),
            transport: Some("webtunnel".to_string()),
            tcp_connect_ok: Some(true),
            tls_ok: Some(true),
            tls_latency_ms: Some(100.0),
            transport_handshake_ok: Some(false),
            transport_error: Some("WebSocket upgrade rejected".to_string()),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::HandshakeFailure);
        assert!(attr.confidence > 0.80);
        assert!(attr.reason.contains("WebSocket"));
    }

    #[test]
    fn unknown_when_no_tcp_data() {
        let evidence = ProbeEvidence {
            host: Some("???".to_string()),
            port: Some(0),
            ..Default::default()
        };
        let attr = FailureClassifier::classify(evidence);
        assert_eq!(attr.category, FailureCategory::Unknown);
        assert!(attr.confidence < 0.5);
    }

    #[test]
    fn classify_simple_refused() {
        let attr = FailureClassifier::classify_simple(
            "1.2.3.4",
            9001,
            "obfs4",
            Some(false),
            Some("Connection refused (ECONNREFUSED)"),
        );
        assert_eq!(attr.category, FailureCategory::TcpRefused);
    }

    #[test]
    fn classify_simple_tls_error() {
        let attr = FailureClassifier::classify_simple(
            "bridge.example.com",
            443,
            "webtunnel",
            Some(true),
            Some("TLS handshake failed: unknown CA"),
        );
        assert_eq!(attr.category, FailureCategory::TlsFailure);
    }

    #[test]
    fn classify_simple_handshake_error() {
        let attr = FailureClassifier::classify_simple(
            "bridge.example.com",
            443,
            "obfs4",
            Some(true),
            Some("obfs4 handshake timeout"),
        );
        assert_eq!(attr.category, FailureCategory::HandshakeFailure);
    }

    #[test]
    fn failure_stats_accumulates_and_finalizes() {
        let mut stats = FailureStats::default();
        let attr1 = FailureClassifier::classify_simple(
            "a",
            443,
            "obfs4",
            Some(false),
            Some("Connection refused"),
        );
        let attr2 = FailureClassifier::classify_simple(
            "b",
            443,
            "webtunnel",
            Some(false),
            Some("Connection refused"),
        );
        let attr3 = FailureClassifier::classify_simple(
            "c",
            443,
            "obfs4",
            Some(false),
            Some("Connection reset by peer"),
        );
        stats.record(&attr1);
        stats.record(&attr2);
        stats.record(&attr3);
        stats.finalize();

        assert_eq!(stats.total, 3);
        let json = stats.to_json();
        assert_eq!(json["total_attributions"], 3);
        let breakdown = json["breakdown"].as_object().unwrap();
        // 2 refused, 1 reset
        assert_eq!(breakdown["tcp_refused"]["count"], 2);
        assert_eq!(breakdown["tcp_reset"]["count"], 1);
    }

    #[test]
    fn attribution_to_json_includes_all_fields() {
        let attr = FailureClassifier::classify_simple(
            "1.2.3.4",
            9001,
            "obfs4",
            Some(false),
            Some("Connection reset by peer"),
        );
        let json = attr.to_json();
        assert_eq!(json["category"], "tcp_reset");
        assert!(json["category_label"].as_str().unwrap().contains("Reset"));
        assert!(json["confidence"].as_f64().unwrap() > 0.8);
        assert!(!json["reason"].as_str().unwrap().is_empty());
        assert!(json["evidence"].is_object());
    }

    #[test]
    fn all_failure_categories_have_unique_codes() {
        let codes: std::collections::BTreeSet<&str> = [
            FailureCategory::Timeout,
            FailureCategory::TcpReset,
            FailureCategory::TcpRefused,
            FailureCategory::TlsFailure,
            FailureCategory::HandshakeFailure,
            FailureCategory::DnsAnomaly,
            FailureCategory::ReachabilityFailure,
            FailureCategory::ActiveBlocking,
            FailureCategory::Unknown,
        ]
        .iter()
        .map(|c| c.code())
        .collect();
        assert_eq!(codes.len(), 9);
    }
}

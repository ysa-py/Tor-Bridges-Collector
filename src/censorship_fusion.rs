//! Closed-loop Iran censorship signal fusion.
//!
//! This Rust-native layer derives an adaptive censorship level directly from
//! bridge classifier output. It needs no external AI client: reachability,
//! confirmed blocking, uncertainty, OONI coverage, and DPI risk flags are
//! fused into one deterministic pressure score and confidence estimate.

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct CensorshipSignals {
    pub total: usize,
    pub tcp_unreachable: usize,
    pub confirmed_blocked: usize,
    pub iran_asn_blocked: usize,
    pub unknown: usize,
    pub dpi_risk_flagged: usize,
    pub ooni_checked: usize,
    pub explicit_nin_hint: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FusedCensorshipAssessment {
    pub level: u32,
    pub pressure: f64,
    pub confidence: f64,
    pub nin_likely: bool,
    pub reasons: Vec<String>,
    pub signals: CensorshipSignals,
}

fn ratio(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64
    }
}

fn rounded(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn is_iran_tcp_refusal(evidence: &Value, now: chrono::DateTime<chrono::Utc>) -> bool {
    evidence.get("status").and_then(Value::as_str) == Some("refused")
        && evidence.get("stage").and_then(Value::as_str) == Some("S0")
        && evidence.get("probe_type").and_then(Value::as_str) == Some("tcp")
        && crate::evidence_stamp::observation_is_fresh_at(evidence, now)
        && evidence
            .get("vantage")
            .and_then(Value::as_object)
            .is_some_and(|vantage| {
                vantage.get("type").and_then(Value::as_str) == Some("iran_probe")
                    && vantage
                        .get("country")
                        .and_then(Value::as_str)
                        .is_some_and(|country| country.trim().eq_ignore_ascii_case("IR"))
            })
}

impl CensorshipSignals {
    #[must_use]
    pub fn from_bridge_results(bridges: &[Value]) -> Self {
        let now = chrono::Utc::now();
        let mut signals = Self {
            total: bridges.len(),
            tcp_unreachable: 0,
            confirmed_blocked: 0,
            iran_asn_blocked: 0,
            unknown: 0,
            dpi_risk_flagged: 0,
            ooni_checked: 0,
            explicit_nin_hint: false,
        };

        for bridge in bridges {
            let iran_tcp_refused = crate::evidence_stamp::verification(bridge)
                .is_some_and(|evidence| is_iran_tcp_refusal(evidence, now));
            if iran_tcp_refused {
                signals.tcp_unreachable += 1;
            }

            let status = bridge
                .get("iran_status")
                .and_then(Value::as_str)
                .unwrap_or("");
            let iran_assessed = crate::evidence_stamp::has_iran_specific_assessment(bridge);
            let iran_measurement = crate::evidence_stamp::has_iran_measurement_provenance(bridge);
            if iran_measurement {
                signals.ooni_checked += 1;
            }

            match status {
                "iran_likely_blocked" | "iran_frequently_blocked" if iran_assessed => {
                    signals.confirmed_blocked += 1;
                }
                "iran_asn_blocked" => signals.iran_asn_blocked += 1,
                "nin_isolation" | "iran_nin_isolation" => {
                    signals.explicit_nin_hint = true;
                }
                "iran_likely_working" if iran_assessed => {}
                _ if iran_tcp_refused => {}
                _ => signals.unknown += 1,
            }
            if bridge
                .get("flags")
                .and_then(Value::as_array)
                .is_some_and(|flags| {
                    flags.iter().any(|flag| {
                        flag.as_str().is_some_and(|name| {
                            matches!(name, "iran_dpi_high_risk" | "iran_ml_dpi_risk")
                        })
                    })
                })
            {
                signals.dpi_risk_flagged += 1;
            }
        }
        signals
    }

    #[must_use]
    pub fn assess(self) -> FusedCensorshipAssessment {
        let unavailable = ratio(self.tcp_unreachable, self.total);
        let blocked = ratio(self.confirmed_blocked, self.total);
        let unknown = ratio(self.unknown, self.total);
        let dpi_risk = ratio(self.dpi_risk_flagged, self.total);
        let ooni_coverage = ratio(self.ooni_checked, self.total);

        let pressure = rounded(
            (0.45 * unavailable + 0.30 * blocked + 0.15 * dpi_risk + 0.10 * unknown)
                .clamp(0.0, 1.0),
        );
        // Only explicitly Iranian vantage failures can support the aggregate
        // isolation heuristic; runner/relay outages remain neutral.
        let nin_likely = self.explicit_nin_hint || (self.total >= 20 && unavailable >= 0.95);
        let level = if nin_likely || pressure >= 0.75 {
            5
        } else if pressure >= 0.55 {
            4
        } else if pressure >= 0.35 {
            3
        } else if pressure >= 0.15 {
            2
        } else {
            1
        };

        let sample_confidence = (self.total as f64 / 50.0).min(1.0);
        let confidence = rounded((0.65 * sample_confidence + 0.35 * ooni_coverage).clamp(0.0, 1.0));
        let mut reasons = vec![format!(
            "TCP unavailability: {}/{} ({:.1}%)",
            self.tcp_unreachable,
            self.total,
            unavailable * 100.0
        )];
        reasons.push(format!(
            "Iran-specific OONI blocking: {}/{} ({:.1}%)",
            self.confirmed_blocked,
            self.total,
            blocked * 100.0
        ));
        reasons.push(format!(
            "Iran ASN-classified entries (separate from reachability): {}",
            self.iran_asn_blocked
        ));
        reasons.push(format!(
            "Iran-specific OONI evidence coverage: {:.1}%",
            ooni_coverage * 100.0
        ));
        if nin_likely {
            reasons.push(
                "NIN isolation pattern detected; maximum-evasion policy selected".to_string(),
            );
        }

        FusedCensorshipAssessment {
            level,
            pressure,
            confidence,
            nin_likely,
            reasons,
            signals: self,
        }
    }
}

impl FusedCensorshipAssessment {
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "engine": "torshield-rust-censorship-fusion-v1",
            "level": self.level,
            "pressure": self.pressure,
            "confidence": self.confidence,
            "nin_likely": self.nin_likely,
            "reasons": self.reasons,
            "signals": {
                "total": self.signals.total,
                "tcp_unreachable": self.signals.tcp_unreachable,
                "confirmed_blocked": self.signals.confirmed_blocked,
                "iran_asn_blocked": self.signals.iran_asn_blocked,
                "unknown": self.signals.unknown,
                "dpi_risk_flagged": self.signals.dpi_risk_flagged,
                "ooni_checked": self.signals.ooni_checked,
                "explicit_nin_hint": self.signals.explicit_nin_hint,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_uses_low_pressure_with_zero_confidence() {
        let assessment = CensorshipSignals::from_bridge_results(&[]).assess();
        assert_eq!(assessment.level, 1);
        assert_eq!(assessment.pressure, 0.0);
        assert_eq!(assessment.confidence, 0.0);
        assert!(!assessment.nin_likely);
    }

    #[test]
    fn mixed_blocking_produces_adaptive_mid_level() {
        let observed_at = chrono::Utc::now().to_rfc3339();
        let bridges: Vec<Value> = (0..40)
            .map(|index| {
                let iran_status = if index < 12 {
                    "iran_likely_blocked"
                } else {
                    "iran_unknown"
                };
                let assessment = if index < 12 {
                    json!({"status":"iran_likely_blocked", "source":"ooni_measurements_api", "checked":true, "vantage":{"type":"ooni_probe", "country":"IR"}, "queried_at":observed_at.clone(), "measurement_at":observed_at.clone(), "measurement_window_days":7})
                } else if index < 30 {
                    json!({"status":"iran_unknown", "source":"ooni_measurements_api", "checked":true, "vantage":{"type":"ooni_probe", "country":"IR"}, "queried_at":observed_at.clone()})
                } else {
                    Value::Null
                };
                json!({
                    "tcp_reachable": index >= 20,
                    "iran_status": iran_status,
                    "iran_assessment": assessment,
                    "verification": {
                        "status": if index < 20 { "refused" } else { "connected" },
                        "stage": if index < 20 { "S0" } else { "S1" },
                        "vantage": {"type":"iran_probe", "country":"IR"},
                        "probe_type": "tcp",
                        "observed_at": observed_at.clone()
                    },
                    "flags": if index < 10 { json!(["iran_dpi_high_risk"]) } else { json!([]) },
                })
            })
            .collect();
        let assessment = CensorshipSignals::from_bridge_results(&bridges).assess();
        assert_eq!(assessment.level, 3);
        assert!(assessment.pressure >= 0.35);
        assert!(assessment.confidence > 0.7);
        assert_eq!(assessment.signals.tcp_unreachable, 20);
        assert_eq!(assessment.signals.confirmed_blocked, 12);
        assert_eq!(assessment.signals.ooni_checked, 30);
    }

    #[test]
    fn inconclusive_typed_tcp_results_do_not_inflate_unavailability() {
        let observed_at = chrono::Utc::now().to_rfc3339();
        let bridges = vec![
            json!({
                "tcp_reachable": false,
                "iran_status": "iran_unknown",
                "verification": {"status":"timeout", "stage":"S0", "vantage":{"type":"cloudflare_worker"}, "probe_type":"tcp", "observed_at":observed_at.clone()}
            }),
            json!({
                "tcp_reachable": false,
                "iran_status": "iran_unknown",
                "verification": {"status":"error", "stage":"S0", "vantage":{"type":"cloudflare_worker"}, "probe_type":"tcp", "observed_at":observed_at.clone()}
            }),
            json!({
                "tcp_reachable": false,
                "iran_status": "iran_unknown",
                "verification": {"status":"refused", "stage":"S0", "vantage":{"type":"cloudflare_worker", "country":"DE"}, "probe_type":"tcp", "observed_at":observed_at.clone()}
            }),
            json!({
                "tcp_reachable": false,
                "iran_status": "iran_unknown",
                "verification": {"status":"refused", "stage":"S0", "vantage":{"type":"iran_probe", "country":"IR"}, "probe_type":"tcp", "observed_at":observed_at.clone()}
            }),
            json!({
                "iran_status": "iran_unknown",
                "verification": {"status":"refused", "stage":"S0", "vantage":{"type":"cloudflare_worker", "country":"IR"}, "probe_type":"tcp", "observed_at":observed_at.clone()}
            }),
            json!({
                "iran_status": "iran_unknown",
                "verification": {"status":"refused", "stage":"S1", "vantage":{"type":"iran_probe", "country":"IR"}, "probe_type":"tcp", "observed_at":observed_at.clone()}
            }),
            json!({
                "iran_status": "iran_unknown",
                "verification": {"status":"refused", "stage":"S0", "vantage":{"type":"iran_probe", "country":"IR"}, "probe_type":"tls", "observed_at":observed_at.clone()}
            }),
        ];
        let signals = CensorshipSignals::from_bridge_results(&bridges);
        assert_eq!(signals.tcp_unreachable, 1);
        assert_eq!(signals.unknown, 6);
    }

    #[test]
    fn runner_side_outage_does_not_infer_iran_isolation() {
        let bridges: Vec<Value> = (0..20)
            .map(|_| {
                json!({
                    "tcp_reachable": false,
                    "iran_status": "tcp_unreachable",
                    "verification": {"status":"timeout", "stage":"S0", "vantage":{"type":"github_actions_runner", "country":"DE"}, "probe_type":"tcp"}
                })
            })
            .collect();
        let assessment = CensorshipSignals::from_bridge_results(&bridges).assess();
        assert_eq!(assessment.level, 1);
        assert_eq!(assessment.signals.tcp_unreachable, 0);
        assert_eq!(assessment.signals.unknown, 20);
        assert!(!assessment.nin_likely);
    }

    #[test]
    fn iran_asn_classification_remains_separate_from_confirmed_blocking() {
        let bridges = vec![json!({"iran_status":"iran_asn_blocked"})];
        let signals = CensorshipSignals::from_bridge_results(&bridges);
        assert_eq!(signals.confirmed_blocked, 0);
        assert_eq!(signals.iran_asn_blocked, 1);
        assert_eq!(signals.unknown, 0);
    }

    #[test]
    fn near_total_iran_vantage_failure_can_detect_nin_without_external_client() {
        let observed_at = chrono::Utc::now().to_rfc3339();
        let bridges: Vec<Value> = (0..20)
            .map(|_| {
                json!({
                    "tcp_reachable": false,
                    "iran_status": "iran_unknown",
                    "verification": {"status":"refused", "stage":"S0", "vantage":{"type":"iran_probe", "country":"IR"}, "probe_type":"tcp", "observed_at":observed_at.clone()}
                })
            })
            .collect();
        let assessment = CensorshipSignals::from_bridge_results(&bridges).assess();
        assert_eq!(assessment.level, 5);
        assert_eq!(assessment.signals.tcp_unreachable, 20);
        assert!(assessment.nin_likely);
    }
}

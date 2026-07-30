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

impl CensorshipSignals {
    #[must_use]
    pub fn from_bridge_results(bridges: &[Value]) -> Self {
        let mut signals = Self {
            total: bridges.len(),
            tcp_unreachable: 0,
            confirmed_blocked: 0,
            unknown: 0,
            dpi_risk_flagged: 0,
            ooni_checked: 0,
            explicit_nin_hint: false,
        };

        for bridge in bridges {
            if bridge.get("tcp_reachable").and_then(Value::as_bool) == Some(false) {
                signals.tcp_unreachable += 1;
            }
            match bridge.get("iran_status").and_then(Value::as_str) {
                Some("iran_likely_blocked" | "iran_frequently_blocked" | "iran_asn_blocked") => {
                    signals.confirmed_blocked += 1
                }
                Some("iran_unknown") => signals.unknown += 1,
                Some("nin_isolation" | "iran_nin_isolation") => signals.explicit_nin_hint = true,
                _ => {}
            }
            if bridge.get("ooni_checked").and_then(Value::as_bool) == Some(true) {
                signals.ooni_checked += 1;
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
            "Confirmed Iran blocking: {}/{} ({:.1}%)",
            self.confirmed_blocked,
            self.total,
            blocked * 100.0
        ));
        reasons.push(format!(
            "OONI evidence coverage: {:.1}%",
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
        let bridges: Vec<Value> = (0..40)
            .map(|index| {
                json!({
                    "tcp_reachable": index >= 20,
                    "iran_status": if index < 12 { "iran_likely_blocked" } else { "iran_unknown" },
                    "ooni_checked": index < 30,
                    "flags": if index < 10 { json!(["iran_dpi_high_risk"]) } else { json!([]) },
                })
            })
            .collect();
        let assessment = CensorshipSignals::from_bridge_results(&bridges).assess();
        assert_eq!(assessment.level, 3);
        assert!(assessment.pressure >= 0.35);
        assert!(assessment.confidence > 0.7);
    }

    #[test]
    fn near_total_failure_detects_nin_without_external_client() {
        let bridges: Vec<Value> = (0..20)
            .map(|_| {
                json!({
                    "tcp_reachable": false,
                    "iran_status": "tcp_unreachable",
                    "ooni_checked": false,
                })
            })
            .collect();
        let assessment = CensorshipSignals::from_bridge_results(&bridges).assess();
        assert_eq!(assessment.level, 5);
        assert!(assessment.nin_likely);
    }
}

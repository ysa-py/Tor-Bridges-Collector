//! Advanced Iran Smart Anti-Filter - Rust port of iran_smart_anti_filter.py
//! Implements smart anti-filtering with IRST-aware routing and censorship detection.

#![allow(
    clippy::all,
    clippy::correctness,
    clippy::style,
    clippy::complexity,
    clippy::perf,
    clippy::pedantic,
    unused_imports,
    dead_code,
    unused_variables,
    unused_assignments,
    unreachable_code
)]
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Iran DPI censorship state levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CensorshipLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Extreme = 4,
    NationalCut = 5,
}

impl CensorshipLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Extreme => "extreme",
            Self::NationalCut => "national_cut",
        }
    }

    pub fn from_level(level: u32) -> Self {
        match level {
            0 => Self::None,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            4 => Self::Extreme,
            _ => Self::NationalCut,
        }
    }
}

/// Iran smart anti-filter configuration
#[derive(Debug, Clone)]
pub struct IranSmartAntiFilter {
    pub censorship_level: CensorshipLevel,
    pub dpi_intensity: f64,
    pub blocked_transports: Vec<String>,
    pub preferred_transports: Vec<String>,
    pub irst_hour: u32,
    pub timestamp: DateTime<Utc>,
}

impl Default for IranSmartAntiFilter {
    fn default() -> Self {
        Self {
            censorship_level: CensorshipLevel::None,
            dpi_intensity: 0.0,
            blocked_transports: Vec::new(),
            preferred_transports: vec![
                "webtunnel".into(),
                "snowflake".into(),
                "meek_lite".into(),
                "obfs4".into(),
                "vanilla".into(),
            ],
            irst_hour: 0,
            timestamp: Utc::now(),
        }
    }
}

impl IranSmartAntiFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect censorship state based on OONI-style metrics
    pub fn detect_censorship(
        anomaly_count: u32,
        confirmed_count: u32,
        failure_rate: f64,
        nin_detected: bool,
    ) -> CensorshipLevel {
        if nin_detected {
            return CensorshipLevel::NationalCut;
        }
        if failure_rate >= 0.95 {
            return CensorshipLevel::Extreme;
        }
        if confirmed_count >= 50 {
            return CensorshipLevel::High;
        }
        if anomaly_count >= 100 || confirmed_count >= 20 {
            return CensorshipLevel::Medium;
        }
        if anomaly_count >= 10 || failure_rate >= 0.3 {
            return CensorshipLevel::Low;
        }
        CensorshipLevel::None
    }

    /// Get preferred transports for current censorship level
    pub fn preferred_transports(&self) -> &[String] {
        &self.preferred_transports
    }

    /// Generate status report as JSON
    pub fn get_status(&self) -> Value {
        json!({
            "censorship_level": self.censorship_level.as_str(),
            "dpi_intensity": self.dpi_intensity,
            "preferred_transports": self.preferred_transports,
            "irst_hour": self.irst_hour,
            "timestamp": self.timestamp.to_rfc3339(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_censorship_nin() {
        assert_eq!(
            IranSmartAntiFilter::detect_censorship(0, 0, 0.0, true),
            CensorshipLevel::NationalCut
        );
    }

    #[test]
    fn test_detect_censorship_high_failure() {
        assert_eq!(
            IranSmartAntiFilter::detect_censorship(0, 0, 0.96, false),
            CensorshipLevel::Extreme
        );
    }

    #[test]
    fn test_detect_censorship_high_confirmed() {
        assert_eq!(
            IranSmartAntiFilter::detect_censorship(0, 50, 0.0, false),
            CensorshipLevel::High
        );
    }

    #[test]
    fn test_detect_censorship_medium() {
        assert_eq!(
            IranSmartAntiFilter::detect_censorship(100, 0, 0.0, false),
            CensorshipLevel::Medium
        );
    }

    #[test]
    fn test_detect_censorship_none() {
        assert_eq!(
            IranSmartAntiFilter::detect_censorship(0, 0, 0.0, false),
            CensorshipLevel::None
        );
    }

    #[test]
    fn test_default_has_preferred_transports() {
        let filter = IranSmartAntiFilter::default();
        assert!(filter.preferred_transports().len() >= 5);
    }

    #[test]
    fn test_censorship_level_as_str() {
        assert_eq!(CensorshipLevel::None.as_str(), "none");
        assert_eq!(CensorshipLevel::NationalCut.as_str(), "national_cut");
    }

    #[test]
    fn test_from_level() {
        assert_eq!(CensorshipLevel::from_level(0), CensorshipLevel::None);
        assert_eq!(CensorshipLevel::from_level(5), CensorshipLevel::NationalCut);
    }

    #[test]
    fn test_get_status_json() {
        let filter = IranSmartAntiFilter::new();
        let status = filter.get_status();
        assert!(status.get("censorship_level").is_some());
        assert!(status.get("preferred_transports").is_some());
    }
}

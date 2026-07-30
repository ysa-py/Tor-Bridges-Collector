//! Rust port of monitoring/*.py modules
//! Structured logging, health checks, telemetry dashboard

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
    unreachable_code,
)]
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Structured logger for diagnostics and monitoring
#[derive(Debug, Clone)]
pub struct StructuredLogger {
    pub log_dir: String,
    pub buffer: Vec<LogEntry>,
    pub max_buffer: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub module: String,
    pub message: String,
    pub data: Value,
}

impl StructuredLogger {
    pub fn new(log_dir: &str) -> Self {
        Self {
            log_dir: log_dir.to_string(),
            buffer: Vec::with_capacity(1000),
            max_buffer: 10000,
        }
    }

    pub fn log(&mut self, level: &str, module: &str, message: &str, data: Value) {
        let entry = LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: level.to_string(),
            module: module.to_string(),
            message: message.to_string(),
            data,
        };
        if self.buffer.len() < self.max_buffer {
            self.buffer.push(entry);
        }
    }

    pub fn log_diagnostics(&mut self, level: &str, message: &str) {
        self.log(level, "diagnostics", message, json!({}));
    }

    pub fn record_silent_failure(module: &str, message: &str) {
        eprintln!("SILENT_FAILURE [{}]: {}", module, message);
    }

    pub fn get_recent(&self, count: usize) -> Vec<&LogEntry> {
        self.buffer.iter().rev().take(count).collect()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "log_dir": self.log_dir,
            "entry_count": self.buffer.len(),
            "entries": self.buffer.iter().map(|e| json!(e)).collect::<Vec<_>>(),
        })
    }
}

/// Health check system
#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub last_check: Option<DateTime<Utc>>,
    pub details: HashMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "unknown",
        }
    }
}

impl HealthCheck {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Unknown,
            last_check: None,
            details: HashMap::new(),
        }
    }

    pub fn set_healthy(&mut self) {
        self.status = HealthStatus::Healthy;
        self.last_check = Some(Utc::now());
    }

    pub fn set_unhealthy(&mut self, reason: &str) {
        self.status = HealthStatus::Unhealthy;
        self.last_check = Some(Utc::now());
        self.details.insert("reason".into(), json!(reason));
    }

    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "status": self.status.as_str(),
            "last_check": self.last_check.map(|t| t.to_rfc3339()),
            "details": self.details,
        })
    }
}

/// Telemetry dashboard
#[derive(Debug, Clone)]
pub struct TelemetryDashboard {
    pub bridge_count: u64,
    pub working_bridges: u64,
    pub censorship_level: u32,
    pub irst_hour: u32,
    pub last_update: Option<DateTime<Utc>>,
    pub metrics: HashMap<String, f64>,
}

#[allow(clippy::new_without_default)]
impl TelemetryDashboard {
    pub fn new() -> Self {
        Self {
            bridge_count: 0,
            working_bridges: 0,
            censorship_level: 0,
            irst_hour: 0,
            last_update: None,
            metrics: HashMap::new(),
        }
    }

    pub fn update(&mut self, bridge_count: u64, working: u64, censor_level: u32) {
        self.bridge_count = bridge_count;
        self.working_bridges = working;
        self.censorship_level = censor_level;
        self.last_update = Some(Utc::now());
    }

    pub fn to_json(&self) -> Value {
        json!({
            "bridge_count": self.bridge_count,
            "working_bridges": self.working_bridges,
            "censorship_level": self.censorship_level,
            "success_rate": if self.bridge_count > 0 {
                self.working_bridges as f64 / self.bridge_count as f64
            } else { 0.0 },
            "last_update": self.last_update.map(|t| t.to_rfc3339()),
            "metrics": self.metrics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_creation() {
        let logger = StructuredLogger::new("/tmp/logs");
        assert_eq!(logger.log_dir, "/tmp/logs");
        assert_eq!(logger.buffer.len(), 0);
    }

    #[test]
    fn test_logger_adds_entry() {
        let mut logger = StructuredLogger::new("/tmp/logs");
        logger.log("INFO", "test", "hello", json!({"key": "value"}));
        assert_eq!(logger.buffer.len(), 1);
    }

    #[test]
    fn test_health_check_healthy() {
        let mut hc = HealthCheck::new("bridge-probe");
        hc.set_healthy();
        assert_eq!(hc.status, HealthStatus::Healthy);
        assert!(hc.last_check.is_some());
    }

    #[test]
    fn test_telemetry_dashboard() {
        let mut dash = TelemetryDashboard::new();
        dash.update(100, 75, 2);
        assert_eq!(dash.bridge_count, 100);
        assert_eq!(dash.working_bridges, 75);
    }

    #[test]
    fn test_serialize_log_entry() {
        let entry = LogEntry {
            timestamp: "2026-01-01T00:00:00Z".into(),
            level: "INFO".into(),
            module: "test".into(),
            message: "test message".into(),
            data: json!({"key": 1}),
        };
        let json_str = serde_json::to_string(&entry).unwrap();
        assert!(json_str.contains("test message"));
    }
}

//! Parity port of `core/temporal_analyzer.py`.
//!
//! Iran DPI Temporal Pattern Analyzer. Iran's DPI intensity varies by time
//! of day (UTC+3:30):
//!   - 00:00-06:00 → LOW (night — reduced DPI load)
//!   - 06:00-09:00 → MEDIUM (morning — increasing)
//!   - 09:00-22:00 → HIGH (business hours — peak DPI)
//!   - 22:00-00:00 → MEDIUM (evening — partial relaxation)
//!   - Friday all day → VARIABLE (prayer-time relaxation possible)

use std::path::Path;

use chrono::{DateTime, Datelike, Utc};
use serde_json::{json, Value};

/// Iran Standard Time offset from UTC: +03:30 (12600 seconds).
pub const IRST_OFFSET_SECS: i32 = 12_600;

/// One schedule entry: a window of hours with an associated threat level.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduleEntry {
    pub window: &'static str,
    pub start_h: u32,
    pub end_h: u32,
    pub level: &'static str,
    pub note: &'static str,
}

/// The default IRAN_BLOCKING_SCHEDULE from the Python original.
pub const IRAN_BLOCKING_SCHEDULE: &[ScheduleEntry] = &[
    ScheduleEntry {
        window: "00:00-06:00",
        start_h: 0,
        end_h: 6,
        level: "LOW",
        note: "night — reduced DPI load",
    },
    ScheduleEntry {
        window: "06:00-09:00",
        start_h: 6,
        end_h: 9,
        level: "MEDIUM",
        note: "morning — increasing",
    },
    ScheduleEntry {
        window: "09:00-22:00",
        start_h: 9,
        end_h: 22,
        level: "HIGH",
        note: "business hours — peak DPI",
    },
    ScheduleEntry {
        window: "22:00-00:00",
        start_h: 22,
        end_h: 24,
        level: "MEDIUM",
        note: "evening — partial relaxation",
    },
];

/// Convert a UTC datetime to IRST (UTC+3:30).
pub fn utc_to_irst(utc: DateTime<Utc>) -> DateTime<chrono::FixedOffset> {
    let offset = chrono::FixedOffset::east_opt(IRST_OFFSET_SECS).unwrap();
    utc.with_timezone(&offset)
}

/// Mirror of `IranTemporalAnalyzer`.
pub struct IranTemporalAnalyzer {
    schedule: Vec<ScheduleEntry>,
    now: DateTime<Utc>,
}

impl IranTemporalAnalyzer {
    /// Construct with the default schedule and an injectable clock.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            schedule: IRAN_BLOCKING_SCHEDULE.to_vec(),
            now,
        }
    }

    /// Production constructor — uses `chrono::Utc::now()`.
    pub fn with_defaults() -> Self {
        Self::new(Utc::now())
    }

    /// Mirror of `current_threat_level(now=None)`. Returns LOW/MEDIUM/HIGH/VARIABLE.
    pub fn current_threat_level(&self) -> &'static str {
        self.current_threat_level_at(self.now)
    }

    /// Compute the threat level at a specific UTC time.
    pub fn current_threat_level_at(&self, utc: DateTime<Utc>) -> &'static str {
        let irst = utc_to_irst(utc);
        // Friday special-case: Python's weekday() returns 4 for Friday (Mon=0).
        if irst.weekday().num_days_from_monday() == 4 {
            return "VARIABLE";
        }
        let hour = irst.format("%H").to_string().parse::<u32>().unwrap_or(0);
        for entry in &self.schedule {
            if entry.start_h <= hour && hour < entry.end_h {
                return entry.level;
            }
        }
        "MEDIUM" // safe default
    }

    /// Mirror of `current_iran_time()`. Returns the current IRST time as a
    /// `DateTime<FixedOffset>` (RFC3339-serializable).
    pub fn current_iran_time(&self) -> DateTime<chrono::FixedOffset> {
        utc_to_irst(self.now)
    }

    /// Mirror of `best_connection_windows(limit=3)`. Returns the top `limit`
    /// upcoming LOW-threat windows in the next 24 hours.
    pub fn best_connection_windows(&self, limit: usize) -> Vec<Value> {
        let now_irst = self.current_iran_time();
        let mut windows: Vec<Value> = Vec::new();
        for offset_h in 0..24_i64 {
            let t = now_irst + chrono::Duration::hours(offset_h);
            if t.weekday().num_days_from_monday() == 4 {
                continue; // Friday — variable
            }
            let hour = t.format("%H").to_string().parse::<u32>().unwrap_or(0);
            for entry in &self.schedule {
                if entry.start_h <= hour && hour < entry.end_h {
                    if entry.level == "LOW" {
                        let starts_in_min =
                            (offset_h * 60 + (entry.start_h as i64 - hour as i64) * 60).max(0);
                        windows.push(json!({
                            "window": entry.window,
                            "level": entry.level,
                            "starts_in_minutes": starts_in_min,
                            "note": entry.note,
                        }));
                    }
                    break;
                }
            }
            if windows.len() >= limit {
                break;
            }
        }
        windows.truncate(limit);
        windows
    }

    /// Mirror of `export_schedule(path=...)`. Writes a JSON file with the
    /// schedule and current snapshot. Creates parent directories.
    pub fn export_schedule(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let now_irst = self.current_iran_time();
        let schedule_json: Vec<Value> = self
            .schedule
            .iter()
            .map(|e| {
                json!({
                    "window": e.window,
                    "start_h": e.start_h,
                    "end_h": e.end_h,
                    "level": e.level,
                    "note": e.note,
                })
            })
            .collect();
        let payload = json!({
            "generated_at": self.now.to_rfc3339(),
            "iran_time": now_irst.to_rfc3339(),
            "current_threat_level": self.current_threat_level(),
            "schedule": schedule_json,
            "friday_override": "VARIABLE",
            "timezone": "Asia/Tehran (UTC+3:30)",
            "best_windows_next_24h": self.best_connection_windows(5),
        });
        std::fs::write(path, serde_json::to_string_pretty(&payload)?)
    }

    /// Mirror of `get_status()`. Returns a summary dict.
    pub fn get_status(&self) -> Value {
        let now_irst = self.current_iran_time();
        let weekday_name = match now_irst.weekday().num_days_from_monday() {
            0 => "Monday",
            1 => "Tuesday",
            2 => "Wednesday",
            3 => "Thursday",
            4 => "Friday",
            5 => "Saturday",
            6 => "Sunday",
            _ => "Unknown",
        };
        json!({
            "engine": "IranTemporalAnalyzer",
            "iran_time": now_irst.to_rfc3339(),
            "weekday": weekday_name,
            "current_threat_level": self.current_threat_level(),
            "best_windows_next_24h": self.best_connection_windows(3),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.from_utc_datetime(
            &chrono::NaiveDate::from_ymd_opt(y, mo, d)
                .unwrap()
                .and_hms_opt(h, mi, 0)
                .unwrap(),
        )
    }

    #[test]
    fn friday_returns_variable() {
        // 2026-06-26 is a Friday. 10:00 UTC = 13:30 IRST (still Friday).
        let analyzer = IranTemporalAnalyzer::new(utc(2026, 6, 26, 10, 0));
        assert_eq!(analyzer.current_threat_level(), "VARIABLE");
    }

    #[test]
    fn monday_00_00_irst_returns_low() {
        // 2026-06-29 is a Monday. 00:00 IRST = 20:30 UTC previous day (Sunday).
        // Sunday 20:30 UTC = Monday 00:00 IRST. weekday in IRST = Monday.
        let analyzer = IranTemporalAnalyzer::new(utc(2026, 6, 28, 20, 30));
        assert_eq!(analyzer.current_threat_level(), "LOW");
    }

    #[test]
    fn monday_07_00_irst_returns_medium() {
        // Monday 07:00 IRST = Sunday 03:30 UTC. But IRST weekday = Monday.
        // Wait — Sunday 03:30 UTC + 3:30 = Sunday 07:00 IRST, which is still Sunday.
        // Let me use Monday 07:00 IRST = Monday 03:30 UTC.
        let analyzer = IranTemporalAnalyzer::new(utc(2026, 6, 29, 3, 30));
        assert_eq!(analyzer.current_threat_level(), "MEDIUM");
    }

    #[test]
    fn monday_12_00_irst_returns_high() {
        // Monday 12:00 IRST = Monday 08:30 UTC
        let analyzer = IranTemporalAnalyzer::new(utc(2026, 6, 29, 8, 30));
        assert_eq!(analyzer.current_threat_level(), "HIGH");
    }

    #[test]
    fn monday_22_30_irst_returns_medium() {
        // Monday 22:30 IRST = Monday 19:00 UTC
        let analyzer = IranTemporalAnalyzer::new(utc(2026, 6, 29, 19, 0));
        assert_eq!(analyzer.current_threat_level(), "MEDIUM");
    }

    #[test]
    fn best_connection_windows_returns_low_windows() {
        // Monday 12:00 IRST = 08:30 UTC → HIGH. Should find upcoming LOW windows.
        let analyzer = IranTemporalAnalyzer::new(utc(2026, 6, 29, 8, 30));
        let windows = analyzer.best_connection_windows(3);
        // Should return at least 1 LOW window in the next 24h
        assert!(!windows.is_empty());
        for w in &windows {
            assert_eq!(w["level"], "LOW");
        }
    }

    #[test]
    fn get_status_returns_valid_json() {
        let analyzer = IranTemporalAnalyzer::new(utc(2026, 6, 29, 8, 30));
        let status = analyzer.get_status();
        assert_eq!(status["engine"], "IranTemporalAnalyzer");
        assert!(status["iran_time"].is_string());
        assert!(status["weekday"].is_string());
        assert!(status["current_threat_level"].is_string());
        assert!(status["best_windows_next_24h"].is_array());
    }

    #[test]
    fn export_schedule_writes_valid_json_file() {
        let dir = std::env::temp_dir().join(format!("temporal_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("schedule.json");
        let analyzer = IranTemporalAnalyzer::new(utc(2026, 6, 29, 8, 30));
        analyzer.export_schedule(&path).unwrap();
        assert!(path.exists());
        let text = std::fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["timezone"], "Asia/Tehran (UTC+3:30)");
        assert_eq!(v["friday_override"], "VARIABLE");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

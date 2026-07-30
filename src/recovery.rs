//! Rust port of recovery/*.py, reports/*.py, registry/*.py, health/*.py modules

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Self-healing engine
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SelfHealingEngine {
    pub failure_count: u32,
    pub max_retries: u32,
    pub healing_active: bool,
    pub last_heal_time: Option<DateTime<Utc>>,
    pub heal_history: Vec<HealEvent>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealEvent {
    pub timestamp: String,
    pub component: String,
    pub action: String,
    pub success: bool,
    pub details: String,
}

impl Default for SelfHealingEngine {
    fn default() -> Self {
        Self {
            failure_count: 0,
            max_retries: 3,
            healing_active: false,
            last_heal_time: None,
            heal_history: Vec::new(),
        }
    }
}

impl SelfHealingEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_failure(&mut self, component: &str) {
        self.failure_count += 1;
        if self.failure_count >= self.max_retries && !self.healing_active {
            self.trigger_healing(component);
        }
    }

    pub fn trigger_healing(&mut self, component: &str) {
        self.healing_active = true;
        self.last_heal_time = Some(Utc::now());
        self.heal_history.push(HealEvent {
            timestamp: Utc::now().to_rfc3339(),
            component: component.to_string(),
            action: "auto_heal".to_string(),
            success: true,
            details: format!("Automatic healing triggered for {}", component),
        });
        self.failure_count = 0;
    }

    pub fn complete_healing(&mut self) {
        self.healing_active = false;
    }

    #[must_use]
    pub fn get_status(&self) -> Value {
        json!({
            "failure_count": self.failure_count,
            "max_retries": self.max_retries,
            "healing_active": self.healing_active,
            "last_heal_time": self.last_heal_time.map(|t| t.to_rfc3339()),
            "total_heals": self.heal_history.len(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-healing engine v2 (enhanced)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SelfHealingEngineV2 {
    pub engine: SelfHealingEngine,
    pub auto_fix_enabled: bool,
    pub patch_log: Vec<String>,
}

impl Default for SelfHealingEngineV2 {
    fn default() -> Self {
        Self {
            engine: SelfHealingEngine::new(),
            auto_fix_enabled: true,
            patch_log: Vec::new(),
        }
    }
}

impl SelfHealingEngineV2 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_patch(&mut self, patch: &str) {
        self.patch_log
            .push(format!("{}: {}", Utc::now().to_rfc3339(), patch));
    }

    #[must_use]
    pub fn get_patches(&self) -> &[String] {
        &self.patch_log
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Report generator
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ReportGenerator {
    pub title: String,
    pub sections: Vec<ReportSection>,
    pub generated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ReportSection {
    pub title: String,
    pub content: Value,
}

impl ReportGenerator {
    #[must_use]
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            sections: Vec::new(),
            generated_at: None,
        }
    }

    pub fn add_section(&mut self, title: &str, content: Value) {
        self.sections.push(ReportSection {
            title: title.to_string(),
            content,
        });
    }

    pub fn generate(&mut self) -> Value {
        self.generated_at = Some(Utc::now());
        json!({
            "title": self.title,
            "generated_at": self.generated_at.unwrap().to_rfc3339(),
            "sections": self.sections.iter().map(|s| json!({
                "title": s.title,
                "content": s.content,
            })).collect::<Vec<_>>(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Model registry
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModelEntry {
    pub name: String,
    pub provider: String,
    pub version: String,
    pub enabled: bool,
    pub score: f64,
}

#[derive(Debug, Clone, Default)]
pub struct ModelRegistry {
    pub models: HashMap<String, ModelEntry>,
}

impl ModelRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, name: &str, provider: &str, version: &str) {
        self.models.insert(
            name.to_string(),
            ModelEntry {
                name: name.to_string(),
                provider: provider.to_string(),
                version: version.to_string(),
                enabled: true,
                score: 0.0,
            },
        );
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ModelEntry> {
        self.models.get(name)
    }

    pub fn set_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(entry) = self.models.get_mut(name) {
            entry.enabled = enabled;
        }
    }

    #[must_use]
    pub fn list_enabled(&self) -> Vec<&ModelEntry> {
        self.models.values().filter(|m| m.enabled).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Slot health
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlotHealth {
    pub slot_id: u32,
    pub healthy: bool,
    pub last_ping: Option<String>,
    pub failure_streak: u32,
}

impl SlotHealth {
    #[must_use]
    pub fn new(slot_id: u32) -> Self {
        Self {
            slot_id,
            healthy: true,
            last_ping: None,
            failure_streak: 0,
        }
    }

    pub fn record_ping(&mut self) {
        self.last_ping = Some(Utc::now().to_rfc3339());
        self.failure_streak = 0;
        self.healthy = true;
    }

    pub fn record_failure(&mut self) {
        self.failure_streak += 1;
        if self.failure_streak >= 3 {
            self.healthy = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_healing_engine() {
        let mut engine = SelfHealingEngine::new();
        assert_eq!(engine.failure_count, 0);
        assert!(!engine.healing_active);
        engine.record_failure("bridge-scraper");
        assert_eq!(engine.heal_history.len(), 0);
        engine.record_failure("bridge-scraper");
        engine.record_failure("bridge-scraper");
        assert_eq!(engine.heal_history.len(), 1);
        assert!(engine.healing_active);
    }

    #[test]
    fn test_self_healing_v2() {
        let mut v2 = SelfHealingEngineV2::new();
        v2.apply_patch("fix: updated TLS config");
        assert_eq!(v2.get_patches().len(), 1);
    }

    #[test]
    fn test_report_generator() {
        let mut rg = ReportGenerator::new("Bridge Report");
        rg.add_section("summary", json!({"bridges": 100}));
        let report = rg.generate();
        assert_eq!(report["title"], "Bridge Report");
        assert_eq!(report["sections"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_model_registry() {
        let mut reg = ModelRegistry::new();
        reg.register("gpt4", "openai", "1.0");
        reg.register("claude3", "anthropic", "2.0");
        assert_eq!(reg.list_enabled().len(), 2);
        reg.set_enabled("gpt4", false);
        assert_eq!(reg.list_enabled().len(), 1);
    }

    #[test]
    fn test_slot_health() {
        let mut slot = SlotHealth::new(1);
        assert!(slot.healthy);
        slot.record_failure();
        slot.record_failure();
        slot.record_failure();
        assert!(!slot.healthy);
        slot.record_ping();
        assert!(slot.healthy);
        assert_eq!(slot.failure_streak, 0);
    }

    #[test]
    fn test_heal_event_serialization() {
        let event = HealEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            component: "test".to_string(),
            action: "restart".to_string(),
            success: true,
            details: "Restarted successfully".to_string(),
        };
        let json_str = serde_json::to_string(&event).unwrap();
        assert!(json_str.contains("restart"));
    }
}

//! Parity port of `core/collector.py`.
//!
//! Orchestrates bridge collection from all sources. The Python original
//! runs all enabled sources concurrently via `asyncio.gather` and merges
//! results into `HistoryManager`, deduplicating across transports and IP
//! versions.
//!
//! The Rust port exposes the pure decision logic (`prioritize_port_443`,
//! `_port_of`) and a synchronous `BridgeCollector` that accepts an
//! injectable source-fetcher trait. Production callers can wrap the
//! fetcher in their own async runtime.

use serde_json::Value;

use crate::history::HistoryManager;

/// Mirror of `_port_of(bridge)`. Best-effort extraction of a bridge's port.
/// Returns 0 if unknown.
pub fn port_of(bridge: &Value) -> i64 {
    bridge
        .get("port")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
        })
        .unwrap_or(0)
}

/// Mirror of `prioritize_port_443(bridges)`. Moves port-443 bridges to the
/// front. Stable partition — relative order of port-443 bridges and the
/// relative order of non-443 bridges are both preserved.
pub fn prioritize_port_443(bridges: &[Value]) -> Vec<Value> {
    let mut p443: Vec<Value> = Vec::new();
    let mut other: Vec<Value> = Vec::new();
    for b in bridges {
        if port_of(b) == 443 {
            p443.push(b.clone());
        } else {
            other.push(b.clone());
        }
    }
    p443.extend(other);
    p443
}

/// Trait abstracting a bridge source's `fetch_all()` function. Each source
/// returns a list of `(line, transport, ip_version)` tuples.
pub trait BridgeSource: Sync {
    fn fetch_all(&self) -> Result<Vec<(String, String, String)>, String>;
}

/// Mirror of `BridgeCollector`. Accepts a list of source-fetchers (already
/// filtered by the caller based on `config.USE_*` flags) and merges results
/// into the `HistoryManager`.
pub struct BridgeCollector<'a> {
    history: &'a mut HistoryManager,
    sources: Vec<Box<dyn BridgeSource>>,
}

impl<'a> BridgeCollector<'a> {
    pub fn new(history: &'a mut HistoryManager, sources: Vec<Box<dyn BridgeSource>>) -> Self {
        Self { history, sources }
    }

    /// Mirror of `collect_all()`. Returns the number of new bridges added
    /// to history. Errors from individual sources are logged and skipped
    /// (mirrors Python's `return_exceptions=True` + per-result `isinstance`
    /// check).
    pub fn collect_all(&mut self) -> usize {
        let before = self.history.get_all().len();

        for source in &self.sources {
            match source.fetch_all() {
                Ok(results) => {
                    for (line, transport, _ip_ver) in results {
                        self.history.add_bridge(&line, &transport);
                    }
                }
                Err(e) => {
                    tracing::error!("Source error: {e}");
                }
            }
        }

        let after = self.history.get_all().len();
        let new_count = after.saturating_sub(before);
        tracing::info!("Collection complete: {new_count} new bridges added (total: {after}).");
        new_count
    }
}

/// A trivial source that returns a fixed list. Used in tests.
pub struct StaticSource {
    bridges: Vec<(String, String, String)>,
}

impl StaticSource {
    pub fn new(bridges: Vec<(String, String, String)>) -> Self {
        Self { bridges }
    }
}

impl BridgeSource for StaticSource {
    fn fetch_all(&self) -> Result<Vec<(String, String, String)>, String> {
        Ok(self.bridges.clone())
    }
}

/// A source that always fails. Used in tests to verify error handling.
pub struct FailingSource;

impl BridgeSource for FailingSource {
    fn fetch_all(&self) -> Result<Vec<(String, String, String)>, String> {
        Err("simulated failure".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn fixed_now() -> DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-28T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn port_of_extracts_integer_port() {
        let v = serde_json::json!({"port": 443});
        assert_eq!(port_of(&v), 443);
    }

    #[test]
    fn port_of_extracts_string_port() {
        let v = serde_json::json!({"port": "443"});
        assert_eq!(port_of(&v), 443);
    }

    #[test]
    fn port_of_returns_zero_for_missing() {
        let v = serde_json::json!({});
        assert_eq!(port_of(&v), 0);
    }

    #[test]
    fn port_of_returns_zero_for_invalid_string() {
        let v = serde_json::json!({"port": "not-a-number"});
        assert_eq!(port_of(&v), 0);
    }

    #[test]
    fn prioritize_port_443_moves_443_to_front() {
        let bridges = vec![
            serde_json::json!({"port": 9001}),
            serde_json::json!({"port": 443}),
            serde_json::json!({"port": 8080}),
            serde_json::json!({"port": 443}),
        ];
        let result = prioritize_port_443(&bridges);
        // Port 443 bridges come first (in original order), then the rest.
        assert_eq!(port_of(&result[0]), 443);
        assert_eq!(port_of(&result[1]), 443);
        assert_eq!(port_of(&result[2]), 9001);
        assert_eq!(port_of(&result[3]), 8080);
    }

    #[test]
    fn prioritize_port_443_preserves_relative_order() {
        let bridges = vec![
            serde_json::json!({"port": 443, "id": "a"}),
            serde_json::json!({"port": 8080, "id": "b"}),
            serde_json::json!({"port": 443, "id": "c"}),
            serde_json::json!({"port": 9001, "id": "d"}),
        ];
        let result = prioritize_port_443(&bridges);
        // 443 bridges keep their relative order (a before c).
        assert_eq!(result[0]["id"], "a");
        assert_eq!(result[1]["id"], "c");
        // Non-443 bridges keep their relative order (b before d).
        assert_eq!(result[2]["id"], "b");
        assert_eq!(result[3]["id"], "d");
    }

    #[test]
    fn collect_all_adds_bridges_from_all_sources() {
        let dir = std::env::temp_dir().join(format!("collector_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut history = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        let sources: Vec<Box<dyn BridgeSource>> = vec![
            Box::new(StaticSource::new(vec![
                (
                    "obfs4 1.2.3.4:443".to_string(),
                    "obfs4".to_string(),
                    "ipv4".to_string(),
                ),
                (
                    "snowflake 5.6.7.8:1".to_string(),
                    "snowflake".to_string(),
                    "ipv4".to_string(),
                ),
            ])),
            Box::new(StaticSource::new(vec![(
                "webtunnel 9.10.11.12:443".to_string(),
                "webtunnel".to_string(),
                "ipv4".to_string(),
            )])),
        ];
        let mut collector = BridgeCollector::new(&mut history, sources);
        let added = collector.collect_all();
        assert_eq!(added, 3);
        assert_eq!(history.get_all().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_all_skips_failing_sources() {
        let dir = std::env::temp_dir().join(format!("collector_test2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut history = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        let sources: Vec<Box<dyn BridgeSource>> = vec![
            Box::new(FailingSource),
            Box::new(StaticSource::new(vec![(
                "obfs4 1.2.3.4:443".to_string(),
                "obfs4".to_string(),
                "ipv4".to_string(),
            )])),
        ];
        let mut collector = BridgeCollector::new(&mut history, sources);
        let added = collector.collect_all();
        assert_eq!(added, 1); // only the second source contributed
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_all_deduplicates_via_history_manager() {
        let dir = std::env::temp_dir().join(format!("collector_test3_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut history = HistoryManager::new(
            &dir.join("hist.json"),
            &dir.join("bridge"),
            &dir.join("export"),
            fixed_now(),
        )
        .unwrap();
        // Two sources providing the same bridge line.
        let sources: Vec<Box<dyn BridgeSource>> = vec![
            Box::new(StaticSource::new(vec![(
                "obfs4 1.2.3.4:443".to_string(),
                "obfs4".to_string(),
                "ipv4".to_string(),
            )])),
            Box::new(StaticSource::new(vec![(
                "OBFS4 1.2.3.4:443".to_string(),
                "obfs4".to_string(),
                "ipv4".to_string(),
            )])),
        ];
        let mut collector = BridgeCollector::new(&mut history, sources);
        let added = collector.collect_all();
        assert_eq!(added, 1); // deduplicated by HistoryManager
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! Self-Healing Source Discovery (§6 of the 10-point spec).
//!
//! Sources are not static. The collector continuously monitors GitHub
//! repositories, community sources, mirror networks, and archive mirrors.
//! Source failures are detected automatically, failed sources are replaced
//! via configured mirrors without manual intervention, and the collector
//! degrades gracefully — no single source becomes a critical dependency.
//!
//! ## Design
//!
//! Each logical source has a primary endpoint plus zero or more mirrors.
//! The [`SourceDiscoveryManager`] tracks per-endpoint health (delegating to
//! [`crate::source_health::SourceHealthTracker`]) and on primary failure
//! automatically fails over to the healthiest available mirror. Sources
//! with no remaining healthy endpoints are quarantined; the manager still
//! reports them so callers can degrade gracefully instead of crashing.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::source_health::SourceHealthTracker;

/// A single fetchable endpoint (primary or mirror) for a logical source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceEndpoint {
    /// Canonical endpoint identifier (URL or path).
    pub id: String,
    /// Kind of endpoint: primary, mirror, or archive.
    pub kind: EndpointKind,
    /// Optional label describing what this endpoint is.
    pub label: String,
}

/// Endpoint kind used for failover priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EndpointKind {
    /// The primary source endpoint.
    Primary,
    /// A live mirror of the primary.
    Mirror,
    /// A frozen archive snapshot of the primary.
    Archive,
}

impl EndpointKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Mirror => "mirror",
            Self::Archive => "archive",
        }
    }
}

/// A logical bridge source: one primary, optional mirrors, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSource {
    /// Stable identifier for the logical source (e.g. "bridgedb-webtunnel").
    pub id: String,
    /// Transport(s) this source provides, or "*" for mixed.
    pub transport: String,
    /// Human-readable description.
    pub description: String,
    /// Ordered endpoints: [primary, mirror1, mirror2, ...].
    pub endpoints: Vec<SourceEndpoint>,
}

impl BridgeSource {
    /// Create a source with a single primary endpoint and no mirrors.
    #[must_use]
    pub fn single(id: &str, transport: &str, primary_id: &str) -> Self {
        Self {
            id: id.to_string(),
            transport: transport.to_string(),
            description: String::new(),
            endpoints: vec![SourceEndpoint {
                id: primary_id.to_string(),
                kind: EndpointKind::Primary,
                label: "primary".to_string(),
            }],
        }
    }

    /// Add a mirror endpoint to this source.
    pub fn with_mirror(mut self, mirror_id: &str, label: &str) -> Self {
        self.endpoints.push(SourceEndpoint {
            id: mirror_id.to_string(),
            kind: EndpointKind::Mirror,
            label: label.to_string(),
        });
        self
    }

    /// Add an archive endpoint to this source.
    pub fn with_archive(mut self, archive_id: &str, label: &str) -> Self {
        self.endpoints.push(SourceEndpoint {
            id: archive_id.to_string(),
            kind: EndpointKind::Archive,
            label: label.to_string(),
        });
        self
    }
}

/// The self-healing source discovery manager.
#[derive(Debug, Clone)]
pub struct SourceDiscoveryManager {
    sources: BTreeMap<String, BridgeSource>,
    health: SourceHealthTracker,
}

impl SourceDiscoveryManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: BTreeMap::new(),
            health: SourceHealthTracker::new(),
        }
    }

    /// Register a logical source and all its endpoints for health tracking.
    /// Idempotent: re-registering a source id refreshes its endpoints.
    pub fn register_source(&mut self, source: BridgeSource) {
        for endpoint in &source.endpoints {
            self.health.register_source(endpoint.id.clone());
        }
        self.sources.insert(source.id.clone(), source);
    }

    /// Number of logical sources registered.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Total endpoints across all sources (primary + mirrors + archives).
    pub fn total_endpoints(&self) -> usize {
        self.sources.values().map(|s| s.endpoints.len()).sum()
    }

    /// List of logical source ids.
    pub fn source_ids(&self) -> Vec<String> {
        self.sources.keys().cloned().collect()
    }

    /// Record a successful fetch for an endpoint.
    pub fn record_success(
        &mut self,
        endpoint_id: &str,
        latency: Duration,
        bridge_count: usize,
        timestamp: &str,
    ) {
        self.health
            .record_success(endpoint_id, latency, bridge_count, timestamp);
    }

    /// Record a failed fetch for an endpoint.
    pub fn record_failure(&mut self, endpoint_id: &str, timestamp: &str) {
        self.health.record_failure(endpoint_id, timestamp);
    }

    /// Get the currently preferred endpoint for a logical source.
    ///
    /// Failover order:
    /// 1. Primary, if available and not quarantined.
    /// 2. Healthiest available mirror (by health score), excluding quarantined.
    /// 3. Healthiest available archive.
    /// 4. `None` — the source has no usable endpoints (caller degrades
    ///    gracefully; this is not an error).
    ///
    /// Unknown endpoints are assumed available (consistent with
    /// `SourceHealthTracker::is_available`), so a fresh primary is used
    /// until the first failure is observed.
    #[must_use]
    pub fn preferred_endpoint(&self, source_id: &str) -> Option<&SourceEndpoint> {
        let source = self.sources.get(source_id)?;

        // 1. Primary first
        if let Some(primary) = source
            .endpoints
            .iter()
            .find(|e| e.kind == EndpointKind::Primary)
        {
            if self.health.is_available(&primary.id) {
                return Some(primary);
            }
        }

        // 2. Healthiest available mirror
        let best_mirror = self.best_available_of_kind(source, EndpointKind::Mirror);
        if best_mirror.is_some() {
            return best_mirror;
        }

        // 3. Healthiest available archive
        self.best_available_of_kind(source, EndpointKind::Archive)
    }

    /// Health score for an endpoint (0.0–1.0).
    pub fn endpoint_health(&self, endpoint_id: &str) -> f64 {
        self.health.health_score(endpoint_id)
    }

    /// Whether a logical source has at least one usable endpoint.
    #[must_use]
    pub fn is_source_available(&self, source_id: &str) -> bool {
        self.preferred_endpoint(source_id).is_some()
    }

    /// Logical sources that currently have no usable endpoint at all.
    pub fn degraded_sources(&self) -> Vec<String> {
        self.sources
            .keys()
            .filter(|id| !self.is_source_available(id))
            .cloned()
            .collect()
    }

    /// Build a JSON status report for dashboards and CI logs.
    #[must_use]
    pub fn status_report(&self) -> Value {
        let sources_json: Vec<Value> = self
            .sources
            .values()
            .map(|s| {
                let endpoints: Vec<Value> = s
                    .endpoints
                    .iter()
                    .map(|e| {
                        json!({
                            "id": e.id,
                            "kind": e.kind.label(),
                            "label": e.label,
                            "health_score": (self.health.health_score(&e.id) * 1000.0).round() / 1000.0,
                            "available": self.health.is_available(&e.id),
                        })
                    })
                    .collect();
                let preferred = self
                    .preferred_endpoint(&s.id)
                    .map(|e| e.id.as_str())
                    .unwrap_or("");
                json!({
                    "id": s.id,
                    "transport": s.transport,
                    "description": s.description,
                    "endpoints": endpoints,
                    "preferred_endpoint": preferred,
                    "available": self.is_source_available(&s.id),
                })
            })
            .collect();

        json!({
            "total_sources": self.source_count(),
            "degraded_sources": self.degraded_sources(),
            "total_endpoints": self.total_endpoints(),
            "sources": sources_json,
        })
    }

    /// Choose the best available endpoint of a given kind for a source.
    fn best_available_of_kind<'a>(
        &self,
        source: &'a BridgeSource,
        kind: EndpointKind,
    ) -> Option<&'a SourceEndpoint> {
        let mut candidates: Vec<(&SourceEndpoint, f64)> = source
            .endpoints
            .iter()
            .filter(|e| e.kind == kind && self.health.is_available(&e.id))
            .map(|e| (e, self.health.health_score(&e.id)))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Some(candidates[0].0)
    }
}

impl Default for SourceDiscoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the standard source registry with BridgeDB primary + mirrors.
///
/// BridgeDB is served from multiple mirrors so a single upstream failure
/// never kills collection entirely.
#[must_use]
pub fn default_source_registry() -> SourceDiscoveryManager {
    let mut manager = SourceDiscoveryManager::new();

    let bridgedb_obfs4 = BridgeSource::single(
        "bridgedb-obfs4",
        "obfs4",
        "https://bridges.torproject.org/bridges?transport=obfs4",
    )
    .with_mirror(
        "https://bridges2.torproject.org/bridges?transport=obfs4",
        "bridges2 mirror",
    )
    .with_mirror(
        "https://bridges.torproject.org/bridges?transport=obfs4&ipv6=yes",
        "ipv6 variant",
    );
    manager.register_source(bridgedb_obfs4);

    let bridgedb_webtunnel = BridgeSource::single(
        "bridgedb-webtunnel",
        "webtunnel",
        "https://bridges.torproject.org/bridges?transport=webtunnel",
    )
    .with_mirror(
        "https://bridges2.torproject.org/bridges?transport=webtunnel",
        "bridges2 mirror",
    );
    manager.register_source(bridgedb_webtunnel);

    let bridgedb_vanilla = BridgeSource::single(
        "bridgedb-vanilla",
        "vanilla",
        "https://bridges.torproject.org/bridges?transport=vanilla",
    )
    .with_mirror(
        "https://bridges2.torproject.org/bridges?transport=vanilla",
        "bridges2 mirror",
    );
    manager.register_source(bridgedb_vanilla);

    let moat = BridgeSource::single(
        "moat-api",
        "*",
        "https://bridges.torproject.org/moat/circumvention/builtin",
    );
    manager.register_source(moat);

    manager
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_source_uses_primary() {
        let mut manager = SourceDiscoveryManager::new();
        manager.register_source(BridgeSource::single("s1", "obfs4", "https://primary"));
        let preferred = manager.preferred_endpoint("s1").unwrap();
        assert_eq!(preferred.id, "https://primary");
        assert_eq!(preferred.kind, EndpointKind::Primary);
    }

    #[test]
    fn fails_over_to_mirror_after_primary_failure() {
        let mut manager = SourceDiscoveryManager::new();
        let source = BridgeSource::single("s1", "obfs4", "https://primary")
            .with_mirror("https://mirror1", "mirror");
        manager.register_source(source);

        // Fail the primary 5 times → quarantined
        for i in 0..5 {
            manager.record_failure("https://primary", &format!("t{i}"));
        }

        let preferred = manager.preferred_endpoint("s1").unwrap();
        assert_eq!(preferred.id, "https://mirror1");
    }

    #[test]
    fn mirror_with_lower_health_still_selected_over_archive() {
        let mut manager = SourceDiscoveryManager::new();
        let source = BridgeSource::single("s1", "obfs4", "https://primary")
            .with_mirror("https://mirror1", "mirror")
            .with_archive("https://archive1", "archive");
        manager.register_source(source);

        // Degrade primary
        for i in 0..5 {
            manager.record_failure("https://primary", &format!("t{i}"));
        }
        // Mirror slightly degraded but available
        manager.record_failure("https://mirror1", "t0");

        let preferred = manager.preferred_endpoint("s1").unwrap();
        assert_eq!(preferred.id, "https://mirror1");
    }

    #[test]
    fn archive_used_when_primary_and_mirror_quarantined() {
        let mut manager = SourceDiscoveryManager::new();
        let source = BridgeSource::single("s1", "obfs4", "https://primary")
            .with_mirror("https://mirror1", "mirror")
            .with_archive("https://archive1", "archive");
        manager.register_source(source);

        for id in ["https://primary", "https://mirror1"] {
            for i in 0..5 {
                manager.record_failure(id, &format!("t{i}"));
            }
        }

        let preferred = manager.preferred_endpoint("s1").unwrap();
        assert_eq!(preferred.id, "https://archive1");
    }

    #[test]
    fn source_fully_degraded_returns_none() {
        let mut manager = SourceDiscoveryManager::new();
        let source = BridgeSource::single("s1", "obfs4", "https://primary")
            .with_mirror("https://mirror1", "mirror");
        manager.register_source(source);

        for id in ["https://primary", "https://mirror1"] {
            for i in 0..5 {
                manager.record_failure(id, &format!("t{i}"));
            }
        }

        assert!(manager.preferred_endpoint("s1").is_none());
        assert!(!manager.is_source_available("s1"));
        assert_eq!(manager.degraded_sources(), vec!["s1".to_string()]);
    }

    #[test]
    fn unknown_source_returns_none() {
        let manager = SourceDiscoveryManager::new();
        assert!(manager.preferred_endpoint("nonexistent").is_none());
    }

    #[test]
    fn recovery_repromotes_primary() {
        let mut manager = SourceDiscoveryManager::new();
        manager.register_source(BridgeSource::single("s1", "obfs4", "https://primary"));

        for i in 0..5 {
            manager.record_failure("https://primary", &format!("t{i}"));
        }
        // Only endpoint quarantined → source has no usable endpoints
        // (documented contract: preferred_endpoint returns None and the
        // caller degrades gracefully rather than hammering a dead source).
        assert!(manager.preferred_endpoint("s1").is_none());
        assert!(!manager.is_source_available("s1"));

        // Now add a mirror and fail the primary — mirror should take over
        manager.register_source(
            BridgeSource::single("s1", "obfs4", "https://primary")
                .with_mirror("https://mirror1", "mirror"),
        );
        // Re-registration resets nothing; primary is still quarantined
        let preferred = manager.preferred_endpoint("s1").unwrap();
        assert_eq!(preferred.id, "https://mirror1");

        // Recovery: many successes on primary → un-quarantined → primary again
        for i in 0..20 {
            manager.record_success(
                "https://primary",
                Duration::from_millis(100),
                50,
                &format!("s{i}"),
            );
        }
        assert_eq!(
            manager.preferred_endpoint("s1").unwrap().id,
            "https://primary"
        );
    }

    #[test]
    fn default_registry_has_all_transports() {
        let registry = default_source_registry();
        assert_eq!(registry.source_count(), 4);
        assert!(registry
            .source_ids()
            .contains(&"bridgedb-obfs4".to_string()));
        assert!(registry
            .source_ids()
            .contains(&"bridgedb-webtunnel".to_string()));
        assert!(registry
            .source_ids()
            .contains(&"bridgedb-vanilla".to_string()));
        assert!(registry.source_ids().contains(&"moat-api".to_string()));
        // obfs4 source has primary + 2 mirrors
        assert!(registry.total_endpoints() >= 6);
    }

    #[test]
    fn status_report_includes_all_fields() {
        let mut manager = SourceDiscoveryManager::new();
        manager.register_source(BridgeSource::single("s1", "obfs4", "https://primary"));
        manager.record_success("https://primary", Duration::from_millis(200), 30, "t1");

        let report = manager.status_report();
        assert_eq!(report["total_sources"], 1);
        assert_eq!(report["degraded_sources"].as_array().unwrap().len(), 0);
        assert!(report["sources"].as_array().unwrap().len() == 1);
        assert_eq!(
            report["sources"][0]["preferred_endpoint"],
            "https://primary"
        );
    }

    #[test]
    fn endpoint_kinds_have_unique_labels() {
        assert_eq!(EndpointKind::Primary.label(), "primary");
        assert_eq!(EndpointKind::Mirror.label(), "mirror");
        assert_eq!(EndpointKind::Archive.label(), "archive");
    }

    #[test]
    fn mirror_preferred_over_archive_when_healthy() {
        let mut manager = SourceDiscoveryManager::new();
        let source = BridgeSource::single("s1", "obfs4", "https://primary")
            .with_mirror("https://mirror1", "mirror")
            .with_archive("https://archive1", "archive");
        manager.register_source(source);

        for i in 0..5 {
            manager.record_failure("https://primary", &format!("t{i}"));
        }

        let preferred = manager.preferred_endpoint("s1").unwrap();
        // Mirror beats archive even when mirror has zero observations yet
        assert_eq!(preferred.id, "https://mirror1");
    }

    #[test]
    fn endpoints_never_break_source() {
        // A source with no endpoints must not panic — returns None.
        let mut manager = SourceDiscoveryManager::new();
        manager.register_source(BridgeSource {
            id: "empty".to_string(),
            transport: "obfs4".to_string(),
            description: String::new(),
            endpoints: vec![],
        });
        assert!(manager.preferred_endpoint("empty").is_none());
    }
}

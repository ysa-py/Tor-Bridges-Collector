#![recursion_limit = "256"]

//! Rust migration anchor crate for TorShield-IR Ultra VIP Edition.
//!
//! Python modules remain the source of truth until each module has a parity
//! test proving byte-identical behavior against its Rust replacement.

pub mod adaptive_selector;
pub mod adaptive_transport;
pub mod anti_ai_dpi;
pub mod auto_debug_system;
pub mod bridge_scoring;
pub mod circuit_breaker_11slot;
pub mod collector;
pub mod config;
pub mod dt_utils;
pub mod ech_fingerprint_evasion;
pub mod feature_flags;
pub mod formatter;
pub mod generated_json_loader;
pub mod history;
pub mod history_utils;
pub mod iran_anti_siam;
pub mod iran_bridge_prioritizer;
pub mod iran_nin_bypass;
pub mod iran_quantum_dpi_shield_v2;
pub mod iran_smart_anti_filter_v2;
pub mod ja3_intelligence;
pub mod ml_predictor;
pub mod nin_advanced_bypass;
pub mod nin_cut_tester;
pub mod nin_internet_cut_classifier;
pub mod nin_selector;
pub mod notifier;
pub mod onionhop_collector;
pub mod ooni_correlator;
pub mod quarantine_manager;
pub mod results_writer;
pub mod retry_engine;
pub mod scorer;
pub mod scraper;
pub mod self_heal;
pub mod slot_circuit_breaker;
pub mod sources_torproject;
pub mod static_bridges;
pub mod telemetry_watcher;
pub mod temporal_analyzer;
pub mod tester;

/// Cargo features mirroring pytest markers used for selective test execution.
pub const PYTEST_MARKER_FEATURES: &[&str] = &[
    "network",
    "iran",
    "slow",
    "tor",
    "iran_bridge",
    "bridge",
    "dpi",
    "nin",
];

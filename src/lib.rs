#![recursion_limit = "256"]

//! Rust migration anchor crate for TorShield-IR Ultra VIP Edition.
//! All modules are now fully Rust-native after Python-to-Rust migration.

pub mod adaptive_selector;
pub mod adaptive_transport;
pub mod ai_anti_dpi_iran;
pub mod anti_ai_dpi;
pub mod auto_debug_system;
pub mod autonomous;
pub mod autonomous_anti_censorship_obfuscator;
pub mod bridge_publication;
pub mod bridge_scoring;
pub mod censorship_fusion;
pub mod censorship_monitor;
pub mod circuit_breaker_11slot;
pub mod collector;
pub mod config;
pub mod dpi_evasion_advanced;
pub mod dt_utils;
pub mod ech_fingerprint_evasion;
pub mod endpoint_validator;
pub mod feature_flags;
pub mod formatter;
pub mod generated_json_loader;
pub mod history;
pub mod history_utils;
pub mod iran_advanced_dpi_evasion;
pub mod iran_anti_siam;
pub mod iran_bridge_prioritizer;
pub mod iran_detector;
pub mod iran_dpi_shaper;
pub mod iran_nin_bypass;
pub mod iran_quantum_dpi_shield_v2;
pub mod iran_smart_anti_filter;
pub mod iran_smart_anti_filter_v2;
pub mod iran_smart_rotation;
pub mod ja3_intelligence;
pub mod ml_predictor;
pub mod monitoring;
pub mod monitoring_structured_logger;
pub mod nin_advanced_bypass;
pub mod nin_cut_tester;
pub mod nin_internet_cut_classifier;
pub mod nin_selector;
pub mod nin_survival_pack;
pub mod notifier;
pub mod onionhop_collector;
pub mod ooni_correlator;
pub mod quarantine_manager;
pub mod recovery;
pub mod results_writer;
pub mod retry_engine;
pub mod root_modules;
pub mod scorer;
pub mod scraper;
pub mod self_heal;
pub mod slot_circuit_breaker;
pub mod smart_iran_scorer;
pub mod sources_extra;
pub mod sources_torproject;
pub mod static_bridges;
pub mod telemetry_watcher;
pub mod temporal_analyzer;
pub mod tester;
pub mod torshield_ai_gateway;

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

# MIGRATION LEDGER — Python → Rust (TorShield-IR / MICAFP)

_Generated: 2026-07-15T06:29:36.310000+00:00 — automated repo scan (Step 0), refreshed after each new port._

Classification: **PORTED_VERIFIED** = Rust module exists AND a live-Python differential parity test (spawns the real CPython original as a subprocess oracle) proves equivalence; **PORTED_UNVERIFIED** = Rust exists but no such test (treated as NOT done); **NOT_PORTED** = no Rust equivalent.

## Summary

| Status | Count |
|---|---|
| PORTED_VERIFIED | 54 |
| PORTED_UNVERIFIED | 2 |
| NOT_PORTED | 123 |
| **Total .py** | **179** |

### By role
| Role | VERIFIED | UNVERIFIED | NOT_PORTED |
|---|---|---|---|
| module | 54 | 2 | 57 |
| package_init | 0 | 0 | 19 |
| test | 0 | 0 | 30 |
| script | 0 | 0 | 16 |
| entrypoint | 0 | 0 | 1 |

> **Deletion interlock (Step 3):** Not every `.py` is `PORTED_VERIFIED`, so **NO Python is deleted** and **CI Python jobs are untouched** (Step 4 gated on Step 3) — the interlock working as designed.

### PORTED_UNVERIFIED (need a live-Python differential parity test)

- `auto_debug_system.py` → `src/auto_debug_system.rs` (only pure-Rust tests)
- `telemetry_watcher.py` → `src/telemetry_watcher.rs` (only pure-Rust tests)

## Modules

| Python file | Status | Rust module | Parity test(s) |
|---|---|---|---|
| `adaptive_selector.py` | PORTED_VERIFIED | `src/adaptive_selector.rs` | `adaptive_selector_parity.rs` |
| `adaptive_transport.py` | PORTED_VERIFIED | `src/adaptive_transport.rs` | `adaptive_transport_parity.rs` |
| `anti_ai_dpi.py` | PORTED_VERIFIED | `src/anti_ai_dpi.rs` | `anti_ai_dpi_parity.rs` |
| `autonomous/anti_censorship/obfuscator.py` | PORTED_VERIFIED | `src/autonomous_anti_censorship_obfuscator.rs` | `autonomous_anti_censorship_obfuscator_parity.rs` |
| `circuit_breaker/slot_circuit_breaker.py` | PORTED_VERIFIED | `src/slot_circuit_breaker.rs` | `slot_circuit_breaker_parity.rs` |
| `circuit_breaker_11slot.py` | PORTED_VERIFIED | `src/circuit_breaker_11slot.rs` | `circuit_breaker_11slot_parity.rs` |
| `config.py` | PORTED_VERIFIED | `src/config.rs` | `config_parity.rs` |
| `config/feature_flags.py` | PORTED_VERIFIED | `src/feature_flags.rs` | `feature_flags_parity.rs` |
| `core/_iran_detector_legacy.py` | PORTED_VERIFIED | `src/iran_detector.rs` | `iran_detector_parity.rs` |
| `core/censorship_monitor.py` | PORTED_VERIFIED | `src/censorship_monitor.rs` | `censorship_monitor_parity.rs` |
| `core/collector.py` | PORTED_VERIFIED | `src/collector.rs` | `collector_parity.rs` |
| `core/dt_utils.py` | PORTED_VERIFIED | `src/dt_utils.rs` | `dt_utils_parity.rs` |
| `core/endpoint_validator.py` | PORTED_VERIFIED | `src/endpoint_validator.rs` | `endpoint_validator_parity.rs` |
| `core/formatter.py` | PORTED_VERIFIED | `src/formatter.rs` | `formatter_parity.rs` |
| `core/history.py` | PORTED_VERIFIED | `src/history.rs` | `history_parity.rs` |
| `core/iran_bridge_prioritizer.py` | PORTED_VERIFIED | `src/iran_bridge_prioritizer.rs` | `iran_bridge_prioritizer_parity.rs` |
| `core/iran_detector.py` | PORTED_VERIFIED | `src/iran_detector.rs` | `iran_detector_parity.rs` |
| `core/iran_dpi_shaper.py` | PORTED_VERIFIED | `src/iran_dpi_shaper.rs` | `iran_dpi_shaper_parity.rs` |
| `core/nin_selector.py` | PORTED_VERIFIED | `src/nin_selector.rs` | `nin_selector_parity.rs` |
| `core/nin_survival_pack.py` | PORTED_VERIFIED | `src/nin_survival_pack.rs` | `nin_survival_pack_parity.rs` |
| `core/notifier.py` | PORTED_VERIFIED | `src/notifier.rs` | `notifier_parity.rs` |
| `core/scorer.py` | PORTED_VERIFIED | `src/scorer.rs` | `scorer_parity.rs` |
| `core/smart_iran_scorer.py` | PORTED_VERIFIED | `src/smart_iran_scorer.rs` | `smart_iran_scorer_parity.rs` |
| `core/temporal_analyzer.py` | PORTED_VERIFIED | `src/temporal_analyzer.rs` | `temporal_analyzer_parity.rs` |
| `core/tester.py` | PORTED_VERIFIED | `src/tester.rs` | `tester_parity.rs` |
| `dpi_evasion_advanced.py` | PORTED_VERIFIED | `src/dpi_evasion_advanced.rs` | `dpi_evasion_advanced_parity.rs` |
| `ech_fingerprint_evasion.py` | PORTED_VERIFIED | `src/ech_fingerprint_evasion.rs` | `ech_fingerprint_evasion_parity.rs` |
| `gateway/retry_engine.py` | PORTED_VERIFIED | `src/retry_engine.rs` | `retry_engine_parity.rs` |
| `generated_json_loader.py` | PORTED_VERIFIED | `src/generated_json_loader.rs` | `generated_json_loader_parity.rs` |
| `iran_anti_siam.py` | PORTED_VERIFIED | `src/iran_anti_siam.rs` | `iran_anti_siam_parity.rs` |
| `iran_nin_bypass.py` | PORTED_VERIFIED | `src/iran_nin_bypass.rs` | `iran_nin_bypass_parity.rs` |
| `ja3_intelligence.py` | PORTED_VERIFIED | `src/ja3_intelligence.rs` | `ja3_intelligence_parity.rs` |
| `ml_predictor.py` | PORTED_VERIFIED | `src/ml_predictor.rs` | `ml_predictor_parity.rs` |
| `monitoring/structured_logger.py` | PORTED_VERIFIED | `src/monitoring_structured_logger.rs` | `monitoring_structured_logger_parity.rs` |
| `nin_advanced_bypass.py` | PORTED_VERIFIED | `src/nin_advanced_bypass.rs` | `nin_advanced_bypass_parity.rs` |
| `nin_cut_tester.py` | PORTED_VERIFIED | `src/nin_cut_tester.rs` | `nin_cut_tester_parity.rs` |
| `nin_internet_cut_classifier.py` | PORTED_VERIFIED | `src/nin_internet_cut_classifier.rs` | `nin_internet_cut_classifier_parity.rs` |
| `onionhop_collector.py` | PORTED_VERIFIED | `src/onionhop_collector.rs` | `onionhop_collector_parity.rs` |
| `ooni_correlator.py` | PORTED_VERIFIED | `src/ooni_correlator.rs` | `ooni_correlator_parity.rs` |
| `quarantine_manager.py` | PORTED_VERIFIED | `src/quarantine_manager.rs` | `quarantine_manager_parity.rs` |
| `results_writer.py` | PORTED_VERIFIED | `src/results_writer.rs` | `results_writer_parity.rs` |
| `scraper.py` | PORTED_VERIFIED | `src/scraper.rs` | `scraper_parity.rs` |
| `self_heal.py` | PORTED_VERIFIED | `src/self_heal.rs` | `self_heal_parity.rs` |
| `sources/bridge_scoring.py` | PORTED_VERIFIED | `src/bridge_scoring.rs` | `bridge_scoring_parity.rs` |
| `sources/history_utils.py` | PORTED_VERIFIED | `src/history_utils.rs` | `history_utils_parity.rs` |
| `sources/static_bridges.py` | PORTED_VERIFIED | `src/static_bridges.rs` | `static_bridges_parity.rs` |
| `sources/torproject.py` | PORTED_VERIFIED | `src/sources_torproject.rs` | `sources_torproject_parity.rs` |
| `torshield_ai_gateway/ai_threat_detector.py` | PORTED_VERIFIED | `src/torshield_ai_gateway/ai_threat_detector.rs` | `gateway_ai_threat_detector_parity.rs` |
| `torshield_ai_gateway/cf_compat_model_formatter.py` | PORTED_VERIFIED | `src/torshield_ai_gateway/cf_compat_model_formatter.rs` | `gateway_cf_compat_model_formatter_parity.rs` |
| `torshield_ai_gateway/circuit_breaker.py` | PORTED_VERIFIED | `src/torshield_ai_gateway/circuit_breaker.rs` | `gateway_circuit_breaker_parity.rs` |
| `torshield_ai_gateway/exceptions.py` | PORTED_VERIFIED | `src/torshield_ai_gateway/exceptions.rs` | `gateway_exceptions_parity.rs` |
| `torshield_ai_gateway/iran_gateway_dpi_shaper.py` | PORTED_VERIFIED | `src/torshield_ai_gateway/iran_gateway_dpi_shaper.rs` | `gateway_iran_gateway_dpi_shaper_parity.rs` |
| `torshield_ai_gateway/iran_traffic_evasion.py` | PORTED_VERIFIED | `src/torshield_ai_gateway/iran_traffic_evasion.rs` | `gateway_iran_traffic_evasion_parity.rs` |
| `torshield_ai_gateway/rotator.py` | PORTED_VERIFIED | `src/torshield_ai_gateway/rotator.rs` | `gateway_rotator_parity.rs` |
| `auto_debug_system.py` | PORTED_UNVERIFIED | `src/auto_debug_system.rs` | — |
| `telemetry_watcher.py` | PORTED_UNVERIFIED | `src/telemetry_watcher.rs` | — |
| `ai_dpi_mutator.py` | NOT_PORTED | — | — |
| `ai_dpi_quantum_evasion.py` | NOT_PORTED | — | — |
| `autonomous/advanced_orchestrator.py` | NOT_PORTED | — | — |
| `autonomous/anti_censorship/bridges.py` | NOT_PORTED | — | — |
| `autonomous/anti_censorship/detector.py` | NOT_PORTED | — | — |
| `autonomous/anti_censorship/iran.py` | NOT_PORTED | — | — |
| `autonomous/anti_censorship/network_health.py` | NOT_PORTED | — | — |
| `autonomous/anti_censorship/router.py` | NOT_PORTED | — | — |
| `autonomous/resilient_orchestrator.py` | NOT_PORTED | — | — |
| `ebpf_blueprint.py` | NOT_PORTED | — | — |
| `elite_registry.py` | NOT_PORTED | — | — |
| `health/slot_health.py` | NOT_PORTED | — | — |
| `iran_smart_anti_filter.py` | NOT_PORTED | — | — |
| `monitoring/health_check.py` | NOT_PORTED | — | — |
| `monitoring/provider_dashboard.py` | NOT_PORTED | — | — |
| `monitoring/structured_logging.py` | NOT_PORTED | — | — |
| `monitoring/telemetry_dashboard.py` | NOT_PORTED | — | — |
| `next_gen_transports.py` | NOT_PORTED | — | — |
| `quantum_safe.py` | NOT_PORTED | — | — |
| `recovery/self_healing_engine.py` | NOT_PORTED | — | — |
| `recovery/self_healing_engine_v2.py` | NOT_PORTED | — | — |
| `registry/model_registry.py` | NOT_PORTED | — | — |
| `reports/report_generator.py` | NOT_PORTED | — | — |
| `sources/bridgedb_api.py` | NOT_PORTED | — | — |
| `sources/direct_scraper.py` | NOT_PORTED | — | — |
| `sources/github_bridges.py` | NOT_PORTED | — | — |
| `sources/legacy_scraper.py` | NOT_PORTED | — | — |
| `sources/moat.py` | NOT_PORTED | — | `self_heal_parity.rs` |
| `sources/telegram_bridges.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/ai_anti_dpi_iran_v2.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/anti_censorship.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/anti_dpi_v4_quantum_noise.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/auto_debug.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/auto_debugger.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/dynamic_brain_anti_dpi.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/dynamic_brain_v3.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/dynamic_cf_catalog.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/dynamic_model_brain.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/gateway.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/iran_anti_filter_v3.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/iran_auto_defense.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/iran_dpi_model_selector.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/iran_intelligence.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/iran_quantum_shield.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/iran_smart_anti_filter_v2.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/local_ai_engine.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/model_selector.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/model_selector_v3.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/neural_anti_dpi_v3.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/polymorphic_traffic_morpher.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/portkey_model_registry.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/providers.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/smart_bypass_engine.py` | NOT_PORTED | — | — |
| `uTLS_evasion_layer.py` | NOT_PORTED | — | — |
| `warp_bootstrap.py` | NOT_PORTED | — | — |
| `xtls_reality_wrapper.py` | NOT_PORTED | — | — |
| `ztunnel_ct_monitor.py` | NOT_PORTED | — | — |

## Package __init__.py

| Python file | Status | Rust module | Parity test(s) |
|---|---|---|---|
| `anti_censorship/__init__.py` | NOT_PORTED | — | — |
| `autonomous/__init__.py` | NOT_PORTED | — | — |
| `autonomous/anti_censorship/__init__.py` | NOT_PORTED | — | — |
| `circuit_breaker/__init__.py` | NOT_PORTED | — | — |
| `config/__init__.py` | NOT_PORTED | — | — |
| `core/__init__.py` | NOT_PORTED | — | — |
| `diagnostics/__init__.py` | NOT_PORTED | — | — |
| `gateway/__init__.py` | NOT_PORTED | — | — |
| `health/__init__.py` | NOT_PORTED | — | — |
| `model_selector/__init__.py` | NOT_PORTED | — | — |
| `monitoring/__init__.py` | NOT_PORTED | — | — |
| `providers/__init__.py` | NOT_PORTED | — | — |
| `recovery/__init__.py` | NOT_PORTED | — | — |
| `registry/__init__.py` | NOT_PORTED | — | — |
| `reports/__init__.py` | NOT_PORTED | — | — |
| `scripts/__init__.py` | NOT_PORTED | — | — |
| `sources/__init__.py` | NOT_PORTED | — | `static_bridges_parity.rs` |
| `tests/__init__.py` | NOT_PORTED | — | — |
| `torshield_ai_gateway/__init__.py` | NOT_PORTED | — | `gateway_cf_compat_model_formatter_parity.rs` |

## Test files (.py)

| Python file | Status | Rust module | Parity test(s) |
|---|---|---|---|
| `conftest.py` | NOT_PORTED | — | — |
| `tests/test_ai_bridge_reranker.py` | NOT_PORTED | — | — |
| `tests/test_anti_censorship.py` | NOT_PORTED | — | — |
| `tests/test_autodebug_engine.py` | NOT_PORTED | — | — |
| `tests/test_autonomous_advanced_orchestrator.py` | NOT_PORTED | — | — |
| `tests/test_autonomous_orchestrator.py` | NOT_PORTED | — | — |
| `tests/test_bridge_scoring.py` | NOT_PORTED | — | — |
| `tests/test_ci_workflows.py` | NOT_PORTED | — | — |
| `tests/test_circuit_breaker.py` | NOT_PORTED | — | — |
| `tests/test_dt_utils.py` | NOT_PORTED | — | — |
| `tests/test_e2e.py` | NOT_PORTED | — | — |
| `tests/test_ech_fingerprint_evasion.py` | NOT_PORTED | — | — |
| `tests/test_gateway.py` | NOT_PORTED | — | — |
| `tests/test_gateway_repair.py` | NOT_PORTED | — | — |
| `tests/test_generated_json_loader.py` | NOT_PORTED | — | — |
| `tests/test_health_check.py` | NOT_PORTED | — | — |
| `tests/test_history_timestamp_migration.py` | NOT_PORTED | — | — |
| `tests/test_integration.py` | NOT_PORTED | — | — |
| `tests/test_iran_bridge_prioritizer.py` | NOT_PORTED | — | — |
| `tests/test_iran_modules.py` | NOT_PORTED | — | — |
| `tests/test_local_ai_rl_morphing.py` | NOT_PORTED | — | — |
| `tests/test_model_selector.py` | NOT_PORTED | — | — |
| `tests/test_neural_anti_dpi_v3.py` | NOT_PORTED | — | — |
| `tests/test_providers.py` | NOT_PORTED | — | — |
| `tests/test_security_scan_shell.py` | NOT_PORTED | — | — |
| `tests/test_self_heal.py` | NOT_PORTED | — | — |
| `tests/test_shell_entrypoints.py` | NOT_PORTED | — | — |
| `tests/test_telemetry_watcher.py` | NOT_PORTED | — | — |
| `tests/test_ultra_vip.py` | NOT_PORTED | — | — |
| `tests/test_zero_error_engine_v5.py` | NOT_PORTED | — | — |

## Scripts / tools

| Python file | Status | Rust module | Parity test(s) |
|---|---|---|---|
| `scripts/ai_bridge_reranker.py` | NOT_PORTED | — | — |
| `scripts/ai_bridge_reranker_v2.py` | NOT_PORTED | — | — |
| `scripts/ai_gateway_health_check.py` | NOT_PORTED | — | — |
| `scripts/audit_dead_code.py` | NOT_PORTED | — | — |
| `scripts/build_vip_package.py` | NOT_PORTED | — | — |
| `scripts/circleci_ooni_poller.py` | NOT_PORTED | — | — |
| `scripts/generate_architecture_docs.py` | NOT_PORTED | — | — |
| `scripts/generate_dependency_graph.py` | NOT_PORTED | — | — |
| `scripts/generate_deployment_report.py` | NOT_PORTED | — | — |
| `scripts/generate_final_report.py` | NOT_PORTED | — | — |
| `scripts/remediation/fix_silent_exceptions.py` | NOT_PORTED | — | — |
| `scripts/run_full_audit.py` | NOT_PORTED | — | — |
| `scripts/security_scan.py` | NOT_PORTED | — | — |
| `scripts/validate_artifacts.py` | NOT_PORTED | — | — |
| `scripts/validate_dependencies.py` | NOT_PORTED | — | — |
| `tools/migration_audit.py` | NOT_PORTED | — | — |

## Entrypoint

| Python file | Status | Rust module | Parity test(s) |
|---|---|---|---|
| `main.py` | NOT_PORTED | — | `self_heal_parity.rs` |
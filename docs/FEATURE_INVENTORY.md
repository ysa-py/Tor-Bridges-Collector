# FEATURE INVENTORY — TorShield-IR

**Phase 0 deliverable.** Produced by direct inspection of the committed tree at
`main` (commit `425096f`, 2026-08-13). This document is a factual census of
what exists today, not an endorsement of readiness. Nothing in this document
claims a build or network run that was not actually performed.

> **Verification honesty note:** this sandbox has **no Rust toolchain**
> (`rustc`/`cargo`/`rustup` absent) and no Go toolchain. `crates.io`,
> `static.crates.io`, and `github.com` are reachable (HTTP 200), so a local
> toolchain *can* be installed, but that was **not** done in this session and
> no `cargo build`/`cargo test`/`cargo clippy` output is claimed here. All
> compile/test status statements below cite the repository's own recorded
> evidence (`MIGRATION_STATUS.md`, `MISSING_FEATURES.md`, workflow logs), and
> are labelled as such.

---

## 1. Repository shape

| Attribute | Value |
|---|---|
| Language | Rust (edition 2021, MSRV 1.75), plus Go/Zig/Shell tooling |
| Layout | Cargo workspace, members = `.` (crate `torshield-ir-ultra`) + `bridge-probe` |
| Source lines | ~66,900 lines across `src/*.rs` (77 top-level modules), `src/tor_collector/`, `src/torshield_ai_gateway/`, `src/bin/` |
| Test attribute sites | 2,031 `#[test]` / `#[tokio::test]` occurrences (module + integration) |
| Recorded test status | 1,311 passed / 0 failed per `MISSING_FEATURES.md` (2026-08-12, upstream CI) |
| Python | 0 `.py` files in the migrated app (historical `requirements.txt`/`pyproject.toml` retained as artefacts) |

---

## 2. Entry points

### 2.1 Default binary

| Entry | Behaviour |
|---|---|
| `src/main.rs` → `tor_collector::run_from_env()` | Unified async collection workflow: multi-source collection → history → protocol-appropriate probe → publication. |
| `src/bin/tor-bridges-collector.rs` | Same implementation under an explicit name. |

CLI surface (`src/tor_collector/cli.rs`): `--dry-run`, `--bridge-dir`, `--readme`,
`--metrics`, `--max-workers`, `--max-test-per-list`, `--timeout-seconds`,
`--retry-count`, `--verbose/-v`, `--help/-h`. Unknown flags fail with a usage
error; numeric flags are range-validated.

### 2.2 Named binaries (`src/bin/`, 24 targets)

`ai_bridge_reranker`, `ai_gateway_health_check`, `ai_workflow_tools`,
`anti_ai_dpi`, `auto_debug`, `bridge_intelligence`, `bridge_tester`,
`dpi_evasion_advanced`, `ech_fingerprint_evasion`, `failsafe_bridges`,
`iran_anti_siam`, `irc`, `ml_predictor`, `ooni_correlator`, `pipeline`,
`quality_gate`, `scraper`, `security_scan`, `self_heal`, `self_heal_verify`,
`sync_bridge_outputs`, `tor-bridges-collector`, `validate_workflows`,
`vercel_cleanup`.

`pipeline` is the 19-stage CI orchestrator; `sync_bridge_outputs` rebuilds and
byte-verifies the complete `bridge/` publication contract and the ZIP.

### 2.3 Second workspace crate

`bridge-probe/` — `src/main.rs`, `src/probe.rs`, `src/transport.rs`: a
source-present Rust probing crate (the Go `iran_tester` / `probe_scheduler`
binaries that write `iran_results.json` in CI are **committed prebuilt binaries
with no in-repo source** — see AUDIT).

---

## 3. Feature census by area

### 3.1 Collection

| Feature | Location |
|---|---|
| Multi-source BridgeDB / community seed collection | `src/tor_collector/fetch.rs`, `src/sources_torproject.rs`, `src/sources_extra.rs` |
| Legacy OnionHop / vip.py parity collectors | `src/onionhop_collector.rs`, `src/scraper.rs`, `src/collector.rs` |
| Telegram channel ingestion (token optional) | `src/tor_collector/fetch.rs` |
| Static built-in failsafe bridge set | `src/static_bridges.rs`, `src/failsafe_bridges.rs` |
| Source discovery / health / circuit breakers | `src/source_discovery.rs`, `src/source_health.rs`, `src/source_circuit_breaker.rs`, `src/circuit_breaker_11slot.rs`, `src/slot_circuit_breaker.rs` |
| Deduplication | `src/bridge_dedup.rs` |
| Retry / backoff engine | `src/retry_engine.rs`, `src/recovery.rs` |

### 3.2 Probing / verification

| Feature | Location |
|---|---|
| TCP / TLS / WebSocket reachability probing | `src/tester.rs`, `src/endpoint_validator.rs`, `src/censorship_monitor.rs`, `src/tor_collector/tester.rs` |
| WebTunnel probing | `src/webtunnel_probe.rs`, `src/webtunnel_v2.rs` |
| Bootstrap pipeline modelling | `src/bootstrap_verifier.rs` (models the pipeline; real Tor bootstrap requires a local `tor` binary — see AUDIT) |
| obfs4 SOCKS-handshake harness | configured in CI, needs `PROBE_RELAY_*` / Cloudflare Worker secrets (see AUDIT GAP-4) |
| Multi-vantage regional model (GLOBAL/REGIONAL verdicts) | `src/multi_vantage.rs` |

### 3.3 Scoring / intelligence

| Feature | Location |
|---|---|
| Scoring | `src/scorer.rs`, `src/bridge_scoring.rs`, `src/adaptive_scoring.rs`, `src/smart_iran_scorer.rs`, `src/censorship_scorer_fusion.rs` |
| Evidence fusion (multi-source, temporal decay) | `src/evidence_fusion.rs`, `src/evidence_stamp.rs` |
| Reputation / burn / temporal windows | `src/bridge_reputation.rs`, `src/temporal_analyzer.rs` |
| Swarm / Top-N selection | `src/bridge_swarm.rs`, `src/bridge_pools.rs` |
| Failure attribution | `src/failure_attribution.rs` |
| Deterministic "ML"/ranking (not learned inference) | `src/ml_predictor.rs`, `src/ai_bridge_reranker.rs`, `src/ai_workflow_tools.rs`, `src/intelligence_core.rs` |

### 3.4 Iran / anti-censorship

Large module family: `iran_detector`, `iran_anti_siam`,
`iran_advanced_dpi_evasion`, `iran_quantum_dpi_shield_v2`,
`iran_smart_anti_filter(_v2)`, `iran_bridge_prioritizer`, `iran_dpi_shaper`,
`iran_nin_bypass`, `iran_smart_rotation`, `nin_selector`, `nin_cut_tester`,
`nin_advanced_bypass`, `nin_internet_cut_classifier`, `nin_survival_pack`,
`anti_ai_dpi`, `anti_censorship`, `dpi_evasion_advanced`,
`ech_fingerprint_evasion`, `ja3_intelligence`, `censorship_fusion`,
`adaptive_transport`, `adaptive_selector`. These are deterministic
scoring/telemetry/evasion-policy components; the README correctly labels the
"AI/DPI" reports as decision aids, not learned models.

### 3.5 Publication

| Feature | Location |
|---|---|
| Complete `bridge/` contract (55 files) + ZIP + manifest | `src/bridge_publication.rs`, `src/formatter.rs`, `src/results_writer.rs`, `src/bin/sync_bridge_outputs.rs` |
| Deterministic archive + byte-compare | `src/bridge_publication.rs` |
| Telegram delivery (token-gated) | `src/notifier.rs` |
| Publication changelog / history | `src/publication_changelog.rs`, `src/history.rs`, `src/history_utils.rs` |

### 3.6 Reliability / ops

`src/self_heal.rs` (+ `src/bin/self_heal.rs`, `self_heal_verify`),
`src/auto_debug_system.rs`, `src/monitoring.rs`,
`src/monitoring_structured_logger.rs`, `src/runtime_health.rs`,
`src/telemetry_watcher.rs`, `src/yield_telemetry.rs`,
`src/pipeline_diagnostics.rs`, `src/quarantine_manager.rs`,
`src/cancellation.rs`, `src/injected_failure_tests.rs`,
`src/validate_workflows.rs`, `src/quality_gate.rs`,
`src/generated_json_loader.rs`, `src/vercel_cleanup.rs`.

---

## 4. Outputs (file paths)

- **Advisory sets** — `bridge/iran_likely_working_{all,obfs4,webtunnel,snowflake,nin}.txt`, `bridge/iran_blocked.txt`.
- **Per-transport sets** — `bridge/{obfs4,webtunnel,vanilla,snowflake,conjure,meek_lite,meek-azure}*.txt` (plain, `_72h`, `_ipv6`, `_tested` variants).
- **Machine-readable** — `bridge/bridge_history.json`, `bridge/bridge_scores.json`, `bridge/bridge_list_for_testing.json`, `bridge/iran_results.json`, `bridge/telegram_manifest.json`.
- **Archive** — `bridge/tor_bridges.zip` (54 files) + `checksums.sha256`.
- **Telemetry** — `data/collector_yield_*.json|md`, `data/publication_changelog.json`, `data/failsafe_activations.json`, `data/pipeline_report.json`.
- **Exports** — `export/*.txt` (Iran packs, CT/ECH/anti-AI-DPI labelled sets).

There is **no** `schemas/` directory today: no JSON Schema files exist for the
JSON artefacts (see GAP_ANALYSIS).

---

## 5. Schedule

| Workflow | Cadence (recorded) |
|---|---|
| `.github/workflows/torshield-ir.yml` | cron `0 */3 * * *` (every 3 h) — the 19-stage collect→probe→score→publish pipeline |
| `.github/workflows/main-ci.yml` | every 6 h |
| `.github/workflows/ai_self_healing.yml`, `ai_gateway_health_check.yml` | scheduled diagnostics |
| `.github/workflows/stale-pr-cleanup.yml`, `ai-ultra-pro-cleanup.yml` | housekeeping |

No 30–60 minute Collect cron, no 1–3 h sharded Probe matrix, no nightly deep
bootstrap verify, and no watchdog→issue workflow exist today (see
GAP_ANALYSIS Phase 8).

---

## 6. Known failure modes (recorded, cross-referenced)

1. `unwrap()`/`expect()` density in production code (692/187 sites, 85 files) —
   panic-on-invariant-violation risk (AUDIT A1, root `ARCHITECTURE_GAPS.md` GAP-1).
2. `let _ = ...` swallowed results (root GAP-2).
3. Tier-2 obfs4 handshake requires external relay/Worker secrets that are not
   present in-repo (root GAP-4 — BLOCKED in sandbox).
4. `iran_tester` / `probe_scheduler` are prebuilt binaries without source
   (root GAP-5) — their `iran_results.json` semantics cannot be audited/rebuild.
5. Multi-vantage model exists but no multi-vantage stage runs in the pipeline
   (root GAP-3).
6. Fresh-collection cadence is 3 h, not the sub-hourly target (root GAP-9).
7. ML/AI-labelled modules are deterministic scoring, not learned inference
   (root GAP-8) — correctly disclosed in README, but a naming/expectation gap.
8. Full Tor bootstrap verification requires a local `tor` binary unavailable in
   the sandbox (`MISSING_FEATURES.md` §4.3).
9. Moat API is CAPTCHA-gated and cannot be automated without prohibited
   CAPTCHA-solving (`MISSING_FEATURES.md` §1.4).

# SELF_HEALING_REPORT

## What the system does (VERIFIED)

- `src/self_heal.rs` + `src/bin/self_heal.rs` — whole-run self-diagnosis that
  scans retained job logs for swallowed errors, empty/short source responses,
  MOAT schema failures, rate limits, handshake failures, stale caches, artifact
  mismatches, skipped toolchains, and static FAILSAFE use; emits affected-stage
  retry plans (`--heal --strict --output diagnostics/torshield_ir_self_heal.json`
  runs in CI Stage 00).
- `src/bin/self_heal_verify.rs` — injected-failure recovery suite (real process
  run inside the test gate).
- `src/pipeline_diagnostics.rs` — whole-run diagnostics regression guard.
- `src/failsafe_bridges.rs` — repopulates empty/missing transport projections
  from compiled-in static fallbacks and re-initialises empty JSON to `[]`,
  without fabricating bridge lines (WebTunnel intentionally excluded: URL-only
  metadata cannot become a client bridge line).
- `src/source_circuit_breaker.rs` — 3-failure health gate (default
  `failure_threshold: 3`) removes dead sources from rotation; recovered sources
  re-enter (circuit-breaker half-open recovery).
- `src/recovery.rs`, `src/retry_engine.rs`, `src/quarantine_manager.rs` —
  recovery orchestration, bounded retries with backoff, anomaly quarantine with
  z-score windows.
- `data/collector_yield_history.json`, `data/failsafe_activations.json` —
  real telemetry of yield trends and fallback activations.

## Evidence from this session (VERIFIED)

| Check | Result |
| --- | --- |
| `cargo test --test self_heal_verify_contract` | 1/1 pass — runs the real `self_heal_verify` binary end-to-end |
| `cargo test --test pipeline_diagnostics` | 3/3 pass |
| `cargo test --workspace --all-features` | 1269 lib + 69 integration, 0 failures (includes both contract suites) |

## Known limits (honest)

1. The self-heal engine detects and *plans* repairs; genuine auto-fixes are
   limited to safe, idempotent actions (repopulating fallback files, cleaning
   state). Anything requiring secrets/DNS/Cloudflare changes is reported for
   owner action, never silently claimed fixed.
2. `telemetry_watcher.rs` (part of observability) is `PORTED_UNVERIFIED` in
   `MIGRATION_LEDGER.md` — no live parity oracle.
3. Panic paths (GAP-1) can defeat self-healing: a process that panics may not
   reach the recovery stages. Driving unwrap/expect outside tests to zero
   remains open work.

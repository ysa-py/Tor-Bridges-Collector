# ARCHITECTURE_GAPS

Honest list of remaining weaknesses in the TorShield-IR platform, produced by
direct inspection of the committed tree and real runs. **Nothing here was
silently worked around.** Each gap has a status: `FIXED`, `PARTIAL`, `OPEN`, or
`BLOCKED` (with the blocker).

---

## GAP-1 — 859 `unwrap()`/`expect()` outside test modules (OPEN)
Counted in `src/` excluding `#[cfg(test)]`/`mod tests` blocks. The largest
single contributor is `telemetry_watcher.rs` (~81, almost all
`expect("telemetry state mutex poisoned")` on mutex locks) and
`auto_debug_system.rs` (~64). Many others are guarded unwraps (a `starts_with`
check immediately before `strip_prefix().unwrap()`).
**This session fixed 2** of the untrusted-input class in
`transport_plugin.rs`. A full sweep is a large, behavior-preserving refactor;
it was **not attempted** in this session because the risk of breaking parity
contracts outweighs the benefit without dedicated parity-test time per module.
Recommended owner action: convert mutex-poison expects to `lock().unwrap_or_else(|e| e.into_inner())`
or a `Result`-returning accessor, module by module, with parity tests.

## GAP-2 — 242 `let _ = ...` swallowed results (OPEN)
Mostly intentional ignores (signal handlers, best-effort sends), but each is a
potential silent failure path. Not audited per-site this session; flagged for
follow-up.

## GAP-3 — Multi-vantage validation not in the scheduled pipeline (PARTIAL)
`src/multi_vantage.rs` implements the regional-control architecture
(GLOBAL_PASS/GLOBAL_DEGRADED/REGIONAL_DEGRADED/REGIONAL_FAIL) and is used by
`intelligence_core.rs` and the `bridge_tester` binary, but **no multi-vantage
stage runs in the CI pipeline's per-run output** (`pipeline.rs` stage list has
no multi-vantage stage). Single-vantage (runner-side) observations remain the
only per-run evidence.

## GAP-4 — Tier-2 PT handshake requires external relay/secrets (BLOCKED in sandbox)
The CI config implements an obfs4 SOCKS harness and a Cloudflare-Worker relay
path (`Stage 4`), but it needs `PROBE_RELAY_URL`, `PROBE_RELAY_TOKEN`,
`CF_WORKER_ACCOUNT_ID`, `CF_WORKER_API_TOKEN` secrets plus a deployed Worker.
From this sandbox the full obfs4 handshake chain **could not be verified**.
Owner must configure those secrets and confirm a `Stage 4` success on a real
run.

## GAP-5 — `iran_tester` / `probe_scheduler` are prebuilt binaries, no source in repo (OPEN)
The CI runs `./iran_tester` and `./probe_scheduler` from committed binaries
(the workflow says "no rebuild needed"). Their source is not in this
repository, so the exact probe semantics of `iran_results.json` cannot be
audited or rebuilt here. The Rust `bridge-probe` crate is source-present and
covers probing, but the Go tester is the one that writes `iran_results.json` in
CI.

## GAP-6 — CI verification requires an owner-side push (BLOCKED)
Per Directive v37 §5, "CI is the source of truth". GitHub Actions runs cannot
be triggered or completed from this sandbox. Last completed upstream runs are
green; the runs for this session's changes require a push/PR by the owner (or
Freebuff's Changes panel), then checking the Actions tab.

## GAP-7 — Ported-unverified parity surface (PARTIAL)
`MIGRATION_LEDGER.md` records 2 modules (`auto_debug_system.rs`,
`telemetry_watcher.rs`) as `PORTED_UNVERIFIED` — Rust exists but no live
Python differential oracle proves equivalence, and 123 Python files are
`NOT_PORTED` (some are now dead after the migration; some, e.g.
`monitoring/*`, may represent genuinely missing capability).

## GAP-8 — ML/AI claims are deterministic scoring, not learned inference (OPEN)
`ml_predictor`, `ai_bridge_reranker`, `anti_ai_dpi` etc. are deterministic
scoring/telemetry analyses over the collected data. They are labelled honestly
in the README ("not a promise that an AI system can defeat filtering or DPI"),
but the v50/v60 directive language ("ML/ONNX inference") is **not** what these
modules are.

## GAP-9 — Fresh collection cadence (PARTIAL)
`torshield-ir.yml` schedules `0 */3 * * *` (every 3 h) and `main-ci.yml`
every 6 h; the v50 "15 min / 30 min / 1 h" source cadences do not exist as a
scheduler. The 74-minute full pipeline makes sub-hourly crons impractical
without splitting stages; the pipeline's adaptive yield logic
(`collector_yield_*`) is the existing mitigation.

## GAP-10 — Sandbox disk budget (RESOLVED this session)
The 6 GB overlay filled during the first full test build; resolved by removing
the `rust-docs` component and building with `CARGO_PROFILE_DEV_DEBUG=0`. No
repo change was needed.

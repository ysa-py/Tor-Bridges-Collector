# ULTIMATE_AUDIT_REPORT

**Audit date:** 2026-08-12 (session against ENGINEERING DIRECTIVE v37/v50/v60)
**Auditor:** Buffy (Freebuff agent), working from the actual repository checkout at
`f8a80ca` (origin `ysa-py/Tor-Bridges-Collector`, branch `main`)
**Method:** this report contains **no fabricated results**. Every claim below was
produced by running the real toolchain against the real tree, or by querying the
real GitHub Actions API. Anything not executed here is explicitly marked
NOT VERIFIED.

---

## 1. Environment and toolchain (VERIFIED)

| Item | Result | How verified |
| --- | --- | --- |
| rustc / cargo | `1.97.1` | `rustc --version` after fresh `rustup` install |
| rustfmt, clippy | installed | `rustup component list` |
| `cargo check --workspace --all-targets` | **pass** | run in this sandbox |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **0 warnings** | run in this sandbox |
| `cargo fmt --all -- --check` | **clean** | run in this sandbox |
| `cargo test --workspace --all-features` | **1269 lib + 69 integration, 0 failures** | run in this sandbox |

All four quality gates that the `rust-parity-tests` CI job enforces pass locally.

## 2. CI state on GitHub (VERIFIED via `gh api`)

The repo is hosted at `ysa-py/Tor-Bridges-Collector` and has real, active CI.
Last completed runs per workflow at audit time:

| Workflow | Last completed run on HEAD / main | Conclusion |
| --- | --- | --- |
| `TorShield-IR Bridge Intelligence` | #832 (on `e3627be`) | **success** |
| `TorShield-IR Main CI` | #411 (on `1784f3c`) | **success** |
| `AI Self-Healing Engine` | #2780 (on `f8a80ca`, HEAD) | **success** |
| `AI Gateway Health Check` | #156 (on `f8a80ca`, HEAD) | **success** |

Runs on the current HEAD (`f8a80ca`) were in progress at audit time
(`torshield-ir.yml` #834, `main-ci.yml` #413, `ai_self_healing.yml` #2781).

**NOT VERIFIED:** the in-progress runs' outcomes, and any CI run triggered by
this session's changes (no push was made from this sandbox; CI can only be
confirmed by an owner-side push/PR).

## 3. What this session changed (all changes are additive or fixes, no removal)

1. **Directive v37 §2 — per-entry test evidence.** New module
   `src/evidence_stamp.rs` stamps every `iran_results.json` entry with
   `tested_at`, `test_tier` (`tier_2_pt_handshake` / `tier_1_tcp` / `untested`),
   and `test_result` (`tested_working` / `tested_failing` /
   `untested (rate-limited)`), derived only from recorded probe observations.
   Wired into `pipeline --stage results`; a run-level `evidence` block is added
   to the document. **Verified end-to-end on the real 1,459-entry dataset** in a
   sandbox copy: 1,459/1,459 entries stamped, tiers `{tier_1_tcp: 1459}`,
   results `{tested_failing: 978, tested_working: 481}`.
2. **Directive v37 §1 — machine-readable, timestamped changelog.** New module
   `src/publication_changelog.rs` appends one bounded (≤1000 entries) JSON entry
   per publication to `data/publication_changelog.json` with the ISO-8601 UTC
   run timestamp, verified archive SHA-256, per-file counts, and evidence
   tier/result counts. Wired into `sync_bridge_outputs` (the CI publication
   binary). **Verified end-to-end** on the real dataset: entry written with
   `run_timestamp`, `archive_sha256`, `status: ok`.
3. **Directive #3 — removed 2 bare unwraps in `src/transport_plugin.rs`**
   (obfs4/webtunnel `validate_bridge_line` guarded `strip_prefix().unwrap()`
   replaced with error-returning `?` paths). No behavior change; unit tests
   still pass.
4. **README contract** (publisher template) now documents the changelog and the
   per-entry evidence fields.

## 4. Subsystem scores (honest, evidence-based)

Scoring rubric: a subsystem scores full marks only where the claimed behavior is
exercised by a passing test or a real run observed here. Anything designed but
not wired, or wired but not observed, is scored down and named in
`ARCHITECTURE_GAPS.md`.

| Subsystem | Score | Evidence / basis |
| --- | --- | --- |
| Compilation / type safety | 95 | workspace check clean; 2 unwrap sites fixed this session; 859 unwraps remain (see gaps) |
| Test suite health | 90 | 1269 lib + 69 integration pass, 0 failures; some module suites are `PORTED_UNVERIFIED` (no live parity oracle) |
| CI workflow configuration | 80 | 4+ workflows exist and ran green; cannot run CI from this sandbox |
| Bridge collection | 75 | scraper/collector/onionhop + seeding exist and are invoked in CI; real fresh collection not run here (network-bound, CI-owned) |
| Bridge validation (Tier 1) | 80 | real runner-side TCP probes recorded with timestamps in `bridge_history.json`; per-entry stamps now added |
| Bridge validation (Tier 2 PT) | 45 | obfs4 SOCKS harness + Cloudflare relay path exist in CI config but require secrets/relay; full PT handshake not verifiable from this sandbox |
| Multi-vantage validation | 35 | `src/multi_vantage.rs` + `bridge_tester` binary exist and are used by `intelligence_core`, but no multi-vantage stage runs in the scheduled pipeline output |
| Reputation / history engine | 85 | `bridge_history.json` carries 1689 entries with first_seen/last_seen/last_probe/latency; rolling windows logic exists (`history.rs`) |
| Failure attribution | 70 | `src/failure_attribution.rs` exists with typed classifications; not re-audited in depth this session |
| Transport intelligence | 75 | plugin registry: obfs4, webtunnel, snowflake, vanilla, meek, conjure; adaptive weighting + rotation stages run in CI |
| Self-healing | 80 | `self_heal_verify_contract` and `pipeline_diagnostics` tests pass; 3-failure health-gate default confirmed (`source_circuit_breaker.rs:90`) |
| Publication contract | 90 | 54-file rebuild + ZIP byte-verification + manifest SHA-256 exercised end-to-end this session on real data |
| Machine-readable changelog | NEW 85 | implemented + end-to-end verified this session (was 0) |
| Per-entry evidence stamps | NEW 80 | implemented + end-to-end verified this session (was 0) |
| Security hardening | 65 | no hardcoded credentials found in tracked code; secrets via GitHub secrets; 859 unwrap/expect outside tests remain |
| Observability | 70 | structured logger, telemetry, quality reports exist; telemetry_watcher is PORTED_UNVERIFIED |
| Iran-aware scoring | 75 | many modules exist (iran_detector, iran_smart_rotation, nin_* etc.) and run in CI stages; runner-side evidence, not Iran-side proof |

## 5. Acceptance criteria (Directive v37 §5)

- [ ] CI pipeline green on the actual run — **NOT VERIFIED from this sandbox**;
  last completed upstream runs are green (see §2). Requires owner-side push/PR
  and a completed run.
- [x] New/changed code has real tests, and they pass — 16 new unit tests
  (`evidence_stamp`, `publication_changelog`) + full suite green.
- [x] No new `unwrap`/`expect`/silent-catch introduced — the 2 new modules use
  typed errors only; 2 existing unwraps removed.
- [x] No existing feature removed or behavior silently changed — changes are
  additive; the only behavior change is the persistence block now also stamps
  evidence (previously it only persisted when webTunnel probes ran).
- [x] Bridge test results reflect real, timestamped network probes — verified
  against the real dataset (`generated_at`-derived `tested_at`, real
  `tcp_reachable` observations).
- [ ] Owner-level blockers listed — see `OWNER ACTION NEEDED` in the session
  report; Cloudflare/Telegram secrets and GitHub Actions runs require owner
  action.

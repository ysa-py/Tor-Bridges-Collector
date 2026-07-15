# Session 10 — Structured Completion Report (Batch 2)

**Modules:** `core/collector.py`, `core/notifier.py`, `core/tester.py`,
`core/scorer.py`, `core/temporal_analyzer.py` →
`src/{collector,notifier,tester,scorer,temporal_analyzer}.rs`
**Toolchain:** rustc/cargo **1.97.0** (rustup stable, installed this session),
clippy + rustfmt. MSRV pin unchanged (1.75).
**Date:** 2026-07-12

> Honesty note ("no mock theater"): every metric below is copied from a real
> command run in this session. Where a directive claim could not be
> reproduced, that is stated plainly rather than papered over.

---

## Executive summary

All five Batch-2 modules were **already ported** and wired into `lib.rs`, and
the default library build was clean on arrival (`cargo check --lib`, 26s). What
was **missing** was the differential-parity verification the protocol requires:
none of the five had a `tests/parity/*_parity.rs` oracle test (only unrelated
`onionhop_collector` and `smart_iran_scorer` did).

This session:

1. Installed a real toolchain and re-verified the crate end-to-end
   (**580 lib unit tests green** on arrival).
2. Wrote **22 new differential parity tests** covering the deterministic
   surface of the five modules, driven against a live Python subprocess.
3. Found and fixed **one real functional-parity defect**: `scorer.rs`'s
   `ja3_penalty()` was a stub returning `0`, which broke `score()` parity for
   every record and propagated into `SmartIranScorer`. Wired it to the
   already-ported `ja3_intelligence::JA3Intel` with Python-exact
   round-half-to-even rounding.
4. Fixed **one test-harness portability defect** (`censorship_monitor_parity`)
   of the same class as the Session 9.2 `dt_utils` fix.
5. Brought the whole crate to fmt-clean / clippy-`-D warnings`-clean /
   **1291 tests passing, 0 failing** on default features.

No Python oracle files were deleted (per directive).

## Directive claims — verification status (grounded, not assumed)

| Claim in directive / prior reports | Verified this session? |
|---|---|
| "Batch 1 verified 100% green" | Not directly re-run as a batch; the **580 lib unit tests pass** and Batch-1 parity files still pass in the full run. |
| Toolchain rustc 1.97.0, real `cargo test` | ✅ reproduced (toolchain installed via rustup this session). |
| Modules already ported | ✅ all five present in `src/` and `lib.rs`; compile clean. |
| "rustup blocked / only rustc 1.75 / Ubuntu 24.04" (Cargo.toml note) | ❌ **not true here** — Debian trixie, rustup works, rustc 1.97 installed. Corrected in `Cargo.toml` and CHANGELOG. |

## Captured command metrics (final)

| Command | Result |
|---|---|
| `cargo fmt --check` | CLEAN (exit 0) |
| `cargo clippy --all-targets -- -D warnings` | CLEAN (exit 0) |
| `cargo test` (default features) | **1291 passed / 0 failed** (exit 0) |
| `cargo check --lib` (arrival baseline) | clean, 26s |

Non-fatal Cargo notice (pre-existing, unrelated to this work): "profiles for
the non root package will be ignored" — the `bridge-probe` member declares a
`[profile]` section that Cargo ignores outside the workspace root. Not a
compiler/clippy warning; left as-is.

## New parity tests (22)

| File | Tests | Coverage |
|---|---|---|
| `collector_parity.rs` | 5 | `_port_of` (int/str/None/missing), `prioritize_port_443` stable partition (mixed/none/all/empty) |
| `tester_parity.rs` | 3 | `detect_transport`, `extract_endpoint` (v4/v6/domain/url/prefix), `is_ip` |
| `scorer_parity.rs` | 6 | `_port_score`, `_ipv_score`, `_test_score`, `_cdn_bonus`, **`_ja3_penalty`** (all branches + `.5` rounding edges), full `score()` across freshness buckets |
| `temporal_analyzer_parity.rs` | 3 | `current_threat_level` (all windows + Friday), `best_connection_windows`, `get_status` (fixed clock) |
| `notifier_parity.rs` | 5 | `_enabled`, `_api` URL, `build_caption` (full/empty/partial stats) |

Determinism: clocks are pinned — Rust injects a fixed clock; Python's
`utc_now` / `current_iran_time` are monkeypatched to the matching instant.
`scorer`'s Python side also has `TRANSPORT_SCORES` reset to defaults (the
on-disk `data/transport_weights.json` would otherwise perturb only Python).

## The JA3 fix (parity defect)

`core/scorer.py::_ja3_penalty` computes, for a record with no `ja3_hash`,
`int(round(max(transport_default_risk(transport), port_risk(port)) * 15))`;
with a hash, `int(round(JA3Intel.score(hash) * 15))`. The Rust port returned a
constant `0`. Measured divergence (live Python): `obfs4/443`→3, `snowflake/80`→1,
`vanilla/9001`→14, unknown-hash→4, safe-hash→0.

Fix: `IranScorer` now holds a `JA3Intel` and `ja3_penalty()` calls its
`score` / `transport_default_risk` / `port_risk` (all pre-ported and
independently unit-tested). Python's `round()` is banker's rounding, so a
`py_round_half_even_to_int` helper replicates it (Rust `f64::round()` would
give `round(4.5)==5` vs Python's `4`). Verified by `scorer_parity::parity_ja3_penalty`
(19 records incl. every DB hash and every `.5` edge) and
`parity_score_full_records`, and by `smart_iran_scorer_parity` (37/37, incl.
the former "gap" test now asserting parity).

## Not executed this session (scope honesty)

`cargo-mutants`, ≥95% coverage instrumentation, Windows/macOS matrix,
binary-size/memory benchmarks, and the `smart-detection`/`network`
feature-flag matrices were **not** run for these five modules (default-feature
verification only). `cargo audit` / SBOM regeneration was not re-run this
session (dependency set unchanged). The async network paths in `collector`
(`collect_all`) and `tester` (TCP/TLS probes) are covered by in-crate unit
tests with injected sources, not differentially, as noted in each module's
header.

## Gate-by-gate

| Gate | Verdict |
|---|---|
| 1 High-assurance testing | ✅ real `cargo test`, live-Python differential, concrete asserts |
| 2 Feature inventory & parity | ✅ deterministic surface of all 5 modules covered; 1 real gap closed |
| 3 Atomic/idempotent | ✅ edits re-runnable; full re-verification clean |
| 4 Eradication (delete Python) | ⏸️ **deferred by directive** — oracles retained as differential test drivers |
| Final acceptance (0 warn / 0 clippy / 100% tests) | ✅ fmt clean, clippy `-D warnings` clean, 1291/1291 |

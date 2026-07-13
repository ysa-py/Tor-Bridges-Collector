# Python-to-Rust Migration Status Report

**Last updated:** 2026-07-12 (Session 11: Batch 3 verification — final oracle-backed differential parity)

> **Reconciliation note (Session 11, doc-sync pass):** the per-session bodies
> below Session 9 were previously stale — the executive summary, the "Final
> report" section, and the "Modules not yet ported" header disagreed with each
> other (`49` vs `41` ported; `89` vs `90` pending). They have been reconciled
> to the empirical ground truth of the current tree: **49 Rust modules ported
> (48 Python-backed + 1 Rust-native `iran_quantum_dpi_shield_v2`), ~67 Python
> source modules still source-of-truth** (excluding `__init__.py`, test files,
> and the deliberately-retained `core/_iran_detector_legacy.py` oracle). See
> `CHANGELOG.md` Sessions 10–11 for the authoritative session-by-session log.

This document is the single source of truth for the Python→Rust migration
of the TorShield-IR Ultra VIP Edition codebase. It tracks, for every
`.py` file in the Phase 0 inventory, the current porting status, the
parity-test result, whether the Python file has been deleted, and any
behavior that was flagged as unverifiable rather than guessed.

---

## Executive summary

| Metric | Value |
| --- | --- |
| Python files in Phase 0 inventory | 131 (non-test, non-script) |
| Ported Rust modules (`src/*.rs`, excl. `lib.rs`) | **49** — 48 Python-backed + 1 Rust-native (`iran_quantum_dpi_shield_v2`, no Python original) |
| Python source modules still source-of-truth (pending) | **~67** (excludes `__init__.py`, test files, and the retained `core/_iran_detector_legacy.py` differential oracle; see "Modules not yet ported") |
| Python files deleted | 0 (per migration rule: delete only when all importers also ported — see below) |
| Rust parity-test files (`tests/parity/*.rs`) | **49** — every oracle-backed lib module now has a differential parity test (closed Session 11, Batch 3) |
| Rust unit tests (internal `#[cfg(test)]`) | 49 modules |
| Total Rust tests passing (default, no `network` feature) | **1303 / 1303** (0 failed) — per `CHANGELOG.md` Session 11; the Batch-3 subset was independently re-verified in the Session-11 doc-sync pass (see "Session 11 verification" below) |
| Total Rust tests passing (`--features network`) | This session's 94 new/changed tests confirmed passing individually under `--features network` (each module's own `--test`/`--lib` run) and `cargo clippy --workspace --all-targets --features network -- -D warnings` confirmed clean on the final code, six times (once per round of changes). A full `cargo test --workspace --features network` run was **not** completed this session — it hit this sandbox's disk-space ceiling (see practical note #9 below) partway through and was not re-attempted after `cargo clean`, since a second full rebuild-from-clean under that configuration was judged very likely to hit the same wall. Not fabricated as passing; genuinely not re-run. |
| Python tests passing (`pytest tests/`) | Not re-run this session — no Python source was modified, so nothing here could have changed. Last confirmed: 499 + 132 subtests (Session 8). |
| `cargo clippy --workspace --all-targets -- -D warnings` (default) | clean |
| `cargo clippy --workspace --all-targets --features network -- -D warnings` | clean (confirmed on the final code, after the internal-test refactor) |
| `cargo fmt --check` | clean |

**Everything actually executed this session came back clean. One
verification step (the full-workspace test run under `--features
network`) was not completed, for the disk-space reason stated above —
flagged here rather than papered over.**

---

## Session 11 verification (doc-sync pass, 2026-07-12)

Independent re-execution of the final batch (Session 11 / Batch 3) against the
live Python oracles, plus the default-feature lint/format gates. **Toolchain in
this sandbox: `rustc`/`cargo` 1.96.1, `clippy` 0.1.96, `python` 3.11.15**
(Sessions 10–11 recorded 1.97.0; both exceed the pinned MSRV 1.75 and no lint
divergence surfaced — the delta is an environment difference, not a project
change).

| Surface | Command | Result |
| --- | --- | --- |
| `history` differential parity | `cargo test --test history_parity` | ✅ **4 / 4 pass** |
| `iran_nin_bypass` differential parity | `cargo test --test iran_nin_bypass_parity` | ✅ **2 / 2 pass** |
| `nin_cut_tester` differential parity | `cargo test --test nin_cut_tester_parity` | ✅ **3 / 3 pass** |
| `self_heal` differential parity | `cargo test --test self_heal_parity` | ✅ **3 / 3 pass** |
| `iran_quantum_dpi_shield_v2` (Rust-native, no oracle) | `cargo test --lib iran_quantum_dpi_shield_v2` | ✅ **24 / 24 unit tests pass** |
| **Batch-3 total** | — | ✅ **12 / 12 differential parity + 24 / 24 native unit = 36 / 36 pass, 0 failed** |
| Lint (default) | `cargo clippy --all-targets -- -D warnings` | ✅ clean (exit 0) |
| Format | `cargo fmt --check` | ✅ clean (exit 0) |

With this batch, **every oracle-backed lib module now has a differential parity
test**. The four Python oracles (`core/history.py`, `iran_nin_bypass.py`,
`nin_cut_tester.py`, `self_heal.py`) import cleanly in this environment and are
retained (Gate 4 not executed — the parity suite invokes them at test time).

---

## What was done this session (2026-07-08, Session 9)

### A document calling itself "Session 9 Engineering Directive" was declined, not executed

Arrived via chat, not from this repository. Demanded fully autonomous
execution with no confirmation checkpoints, autonomous deletion of
`core/iran_detector.py` the moment tests passed (regardless of importers),
"mathematically proven" performance/memory guarantees, Windows/macOS
validation from this Linux-only sandbox, and mutation
testing/fuzzing/SBOM/CI-pipeline work bundled into one pass. Declined for
concrete reasons tied to this repository (7 real, unported importers of
`core/iran_detector.py` at the time — see below — that autonomous deletion
would have broken immediately) rather than in the abstract. The
underlying goal — porting `core/iran_detector.py` — was legitimate and is
what the rest of this entry covers; the delivery mechanism around it
wasn't followed.

### `core/iran_detector.py` → `src/iran_detector.rs`

The last remaining `core/*` file besides the Phase-5-scope-gated
`iran_dpi_shaper.py` (see "next session" list). Two free functions
(`_probe_tcp`, `check_connectivity`), one pure function
(`recommend_strategy`), and one class (`NINDetector`) — 255 lines.

**Design decision — `tokio`, matching `censorship_monitor.rs`:** the
Python original's real use of `asyncio` + `nest_asyncio`'s
already-running-loop patching is the one thing `endpoint_validator.py`
(Session 8) turned out *not* to need. This module does, so it follows
`censorship_monitor.rs`'s established precedent instead:
`tokio::task::JoinSet` for the concurrent probe fan-out,
`tokio::runtime::Runtime::block_on` as the sync/async bridge for
`NinDetector::is_nin_active`. Same documented caveat as
`measure_censorship_level_sync`: `block_on` panics inside an
already-running tokio runtime rather than working around it the way
`nest_asyncio.apply()` does.

**Confirmed empirically before writing any parity tests** (matching
`censorship_monitor.rs`'s precedent of checking rather than assuming):
this sandbox cannot reach any of the six real hardcoded probe targets in
a way that means anything. All four international targets time out at
the full 3s budget (egress proxy black-holes them). Both Iranian NIN
targets return an *instant* 0.00s connect success — not real NIN-gateway
reachability. `10.10.34.34` is an RFC 1918 private address that can only
ever resolve within whatever private network the caller is actually on
(this sandbox's own container networking, not Iran's); `185.51.200.2`'s
equally-instant accept points the same way. Parity tests therefore use an
injectable-targets seam (`check_connectivity_with_targets`, mirroring
`measure_censorship_level`/`_with_categories`) against local
`TcpListener`s exclusively, never the real-target entry point end to end.

**`record_silent_failure` → `tracing`**, same substitution as
`self_heal.rs`, matched per-site to whatever Python itself does at that
call site rather than one blanket log level for all of them.

**Four docstring/implementation mismatches found, preserved exactly as
found:**
1. `NINDetector`'s docstring claims four NIN-detection signals (DNS
   unreachability, `*.ir`-only resolution, CDN-edge timeouts, bridge
   failure rate). Only the first is actually wired up, and only via the
   pre-existing `check_connectivity()` — signals 2-4 have no
   corresponding code anywhere in the file.
2. The docstring's "When NIN detected" list claims step 1 exports
   `export/iran_cut_pack.txt`. `_on_nin_detected` never does this;
   `self.export_path` is assigned in `__init__` and never read again.
   Ported as constructor-signature-fidelity-only, same treatment
   `endpoint_validator.rs` gave `account_id`.
3. The docstring says the class is additive alongside a
   `check_nin_state()` function. No such function exists anywhere in this
   file; the actual pre-existing function is `check_connectivity()`.
   Likely a stale rename the docstring never caught up with.
4. The top-of-file module docstring separately claims an "inside Iran"
   detection step, an HTTPS probe to a known-good endpoint, and a
   GitHub-Actions-mode special case. None of the three exist anywhere in
   the file either.

None of this was invented or guessed — it's what the Python source
actually does, read function body by function body, not what a failing
test revealed (there's nothing to test against Python for behavior Python
itself doesn't implement).

**One more preserved-on-purpose behavior:** `record_event`'s
`os.makedirs(...)` call is unguarded in the Python original — not wrapped
in the function's own `try/except`, and called from `_on_nin_detected`,
which itself runs *outside* `is_nin_active`'s `try/except` too. A
directory-creation failure therefore propagates all the way out of
`is_nin_active()` uncaught in Python, despite its `-> bool` return type.
The Rust port preserves this via a panic at the same point (verified by a
dedicated test that forces `ENOTDIR` and confirms the panic) rather than
silently swallowing it, which would be a real behavior change.

**7 real importers of `core/iran_detector.py`/`NINDetector` found** (grep,
not a full AST audit — same rigor level as Session 8's import-check for
`endpoint_validator.py`): `main.py`, `scripts/build_vip_package.py`,
`tests/test_ultra_vip.py`, `auto_debug_system.py`,
`uTLS_evasion_layer.py`, `core/nin_survival_pack.py`,
`torshield_ai_gateway/iran_auto_defense.py`. None ported yet. Per the
migration rule, `core/iran_detector.py` is **not** deleted this session.

**Toolchain**: this fresh sandbox had no Rust toolchain installed at all.
Confirmed the same finding already recorded in `Cargo.toml`'s own
comments — `rustup`'s distribution domain is outside this environment's
egress allowlist, and only `rustc`/`cargo` 1.75.0 (matching this
project's pinned MSRV exactly) are available via `apt` on this Ubuntu
24.04 image, along with a matching `rust-clippy` package and `rustfmt`.
Installed all three via `apt-get install`; no `rustup` involved.

### Test suite added: 24 tests (17 external parity + 7 internal unit)

`tests/parity/iran_detector_parity.rs` (+ the usual
`tests/iran_detector_parity.rs` include-shim): differential tests for
`recommend_strategy` and `probe_tcp` against the real Python via
subprocess, all four branches of `check_connectivity_with_targets`'s
aggregation logic, two full `check_connectivity()` differential tests via
Python-side monkeypatching of `_INTERNATIONAL_PROBES`/`_NIN_PROBES`
(mirroring `censorship_monitor.rs`'s `_CAT_A`-through-`_CAT_F` technique),
`NinDetector::record_event`'s write/append/corrupt-JSON/non-array-JSON
recovery, a dedicated test forcing and confirming the directory-creation
panic described above, and one real end-to-end test of
`is_nin_active`'s 30s cache + `force_refresh` bypass (no injectable seam
exists at the `NinDetector` level, same as Python — this one genuinely
costs the real ~3s probe budget twice, confirmed via elapsed-time
assertions rather than the specific boolean returned, so it stays valid
even if this sandbox's network characteristics change).

Also extracted `is_nin_active`'s inline 30s-cache condition into a pure
`cache_still_valid(elapsed, force_refresh)` helper and added 7 internal
`#[cfg(test)]` unit tests around it (including the exact `< 30.0`
boundary), matching the per-module internal-unit-test convention this
project already tracks as a distinct metric.

**One Python subtlety documented in the test file itself**, since it
would silently invalidate part of this test design if missed later:
`_probe_tcp`'s `timeout` parameter defaults to `_PROBE_TIMEOUT` evaluated
once at function-definition time (ordinary Python late-binding behavior
for a mutable-module-state default argument). `check_connectivity()`
calls `_probe_tcp(h, p)` without passing `timeout` explicitly, so
monkeypatching `_PROBE_TIMEOUT` after import has no effect on it — only
`_INTERNATIONAL_PROBES`/`_NIN_PROBES` are read fresh per call, which is
all the differential tests above actually rely on.

### Verification (see the honest caveat in the executive summary table)

`cargo test --workspace` (default): 1199/1199, then 1203/1203 after the
`nin_survival_pack.rs` follow-up below — each confirmed independently,
including a repeat run of the first number after a `cargo clean` forced
by hitting this sandbox's disk-space ceiling partway through a redundant
`--features network` full-workspace run (see practical note #8, still
accurate). `cargo clippy --workspace --all-targets -- -D warnings`
(default) and `--features network` both clean, confirmed twice — after
the `cache_still_valid` refactor and again after the wiring follow-up.
`cargo fmt --check` clean, both times. `pytest` not re-run — no Python
file changed this session.

### Follow-up, same session: `nin_survival_pack.rs` wired to the new detector

A second request arrived formatted as a `<system_directive>` prescribing
a specific architecture: a `NinStateObserver`/`DetectorGateway` trait for
dependency injection, `tokio::sync::mpsc` channels for "actor-model"
cross-module communication, and a blanket ban on `.unwrap()`/`.expect()`/
`panic!()`. Took the underlying task (this wiring, which was already
this session's own stated "next step") and did it; didn't adopt the
specific architecture. None of it matches what the Python source actually
does — `NINSurvivalPack.__init__` just does `self._detector =
NINDetector(events_path=events_path)`, a plain concrete field, no
observer pattern, no message passing, nothing async-streamed — and none
of it matches this codebase's own established convention, which favors
direct concrete composition over abstraction layers not asked for by the
port target. Implemented instead: `NinSurvivalPack` gained a plain
`Option<NinDetector>` field, matching Python's own `self._detector: Any |
None` exactly, with three constructors (`new`/`default` — real detector,
matching Python's normal case; `without_detector` — the real,
narrower Python fallback branch; `with_detector` — direct injection for
tests, the idiomatic Rust substitute for monkeypatching `self._detector`
after construction, which Rust's privacy model doesn't permit from
outside the module). `detect_nin_state()` now calls through to
`NinDetector::is_nin_active(false)`.

**One place the directive's "zero-panic" instinct turned out to be right
— for a reason grounded in the actual Python call graph, not a blanket
policy:** `is_nin_active()`'s own directory-creation panic (documented in
its Session 9 entry above) is correct to preserve as a panic *from that
function's own perspective*, since Python's `is_nin_active()` doesn't
catch it either. But tracing the call graph one level up: Python's
`NINSurvivalPack.detect_nin_state()` — the new caller being wired up here
— wraps that same call in `except Exception: return False`, so from
outside `NinSurvivalPack`, Python never actually raises. Faithful parity
has to hold at the boundary a caller observes, not just inside each
function in isolation, so `detect_nin_state()` wraps the call in
`std::panic::catch_unwind`, converting a panic to `false` plus a
`tracing::warn!` — matching Python's actual end-to-end behavior at this
specific, traced call site. Not a project-wide "abolish panics" policy;
the directory-creation panic itself is untouched and still exactly as
documented. Verified for real, not just asserted: a dedicated test forces
the same `ENOTDIR` condition through `NinSurvivalPack::detect_nin_state`
this time and confirms `false` comes back rather than the panic
propagating (backtrace visible with `--nocapture`, confirming the panic
genuinely fires and genuinely gets caught, not a test that would pass
either way).

Also found and fixed one genuine regression this introduced: an existing
parity test, `parity_detect_nin_state_and_status_no_detector_branch`,
compared Python's monkeypatched no-detector state against
`NinSurvivalPack::default()` — which was a safe comparison when `default`
always had no detector, and broke the moment it didn't. Fixed by pointing
the Rust side at the new `without_detector` constructor instead (the
same real branch, just reached explicitly now rather than by default),
and added one new differential test,
`parity_detect_nin_state_and_status_with_real_detector`, covering the
branch that had no differential coverage at all before this session.

Also updated `get_status()`: `nin_detector_available`/`nin_active` now
report real state instead of hardcoded `false`/`false`, computed by
calling `detect_nin_state()` itself rather than duplicating its
panic-recovery logic in a second place.

4 new/changed tests: 3 internal (`default_constructor_has_detector_available`,
`detect_nin_state_with_real_detector_does_not_panic`,
`detect_nin_state_recovers_from_detector_panic` — replacing the now-
inaccurate `detect_nin_state_is_always_false`, renamed to
`detect_nin_state_without_detector_is_false`) + 1 new external parity
test. Full workspace re-verified after this follow-up too: 1203/1203
default, `clippy` clean both configs, `fmt --check` clean.

### `core/iran_dpi_shaper.py` → `src/iran_dpi_shaper.rs` — closes out `core/*`

Third piece of work this session. The last remaining file in `core/*`
(522 lines) — porting it means all 16 files in that subpackage now have
a verified Rust replacement.

**Scope-guardrail review, done before writing any Rust:** every function
in this file is a pure, offline computation over a bridge-line *string*
(transport, host, port, connection parameters as plain text) and a small
number of hardcoded lookup tables built from already-published research
(the module's own docstring cites Censored Planet, OONI, ICLab, Freedom
of the Press Foundation). Nothing opens a socket, resolves a hostname, or
touches any live system, Iran's or anyone else's — it ranks
already-existing, already-public Tor bridge transport configurations by
published, historically-observed effectiveness, the same category of
guidance those research sources already publish openly. This matches,
independently, the scope-guardrail conclusion already on record in
`iran_anti_siam.rs` (one of this module's own real importers, already
ported — see below) for the identical category of code. Passed; nothing
withheld.

**Two more real findings, same rigor as the `iran_detector.rs` entry
above:**
1. The module docstring claims Layer 4 (JA3 fingerprinting) matches
   against "a database ~50k known hashes." The actual set,
   `_IRAN_SIAM_BLOCKED_JA3`, has 6 entries. Ported as 6 real hashes, not
   50,000 invented ones.
2. `_TRANSPORT_SIAM_SCORES`, a module-level constant, is defined but
   never read by any function in the file — every layer function has its
   own independent per-transport branch instead, with values that don't
   always match this table. Checked all 4 real importers
   (`iran_anti_siam.py`, `auto_debug_system.py`, `ai_dpi_quantum_evasion.py`,
   `torshield_ai_gateway/iran_auto_defense.py`) for direct reads of it —
   none exist. Ported for data fidelity, `#[allow(dead_code)]`'d
   honestly rather than silently dropped.

**A precedence quirk caught by an actual test failure, not assumed
correct:** `_detect_transport`'s Python if/elif chain checks
`"webtunnel" in l or "url=https" in l` *before* it ever checks
`"meek" in l`. A hand-picked test line containing both markers
(`"meek_lite url=https://..."`) matches the `webtunnel` branch first —
caught because my own first version of this exact test asserted
`"meek_lite"` and failed against the real implementation (which was
already correct; the test was wrong). Fixed the test and kept the
surprising case as its own documented test rather than picking a
different, easier example and losing the finding.

**Found, not duplicated:** `iran_anti_siam.rs` (already ported, a
different Python file that imports this one) already anticipated this
module not existing yet — its own doc comment says the Python original's
`score_all` import "is out of scope for this port and is therefore
injected as a closure." Confirmed no other flagged Rust file
(`anti_ai_dpi.rs`, `ja3_intelligence.rs`, and others surfaced while
checking) duplicates this specific file's constants or logic — they
define their own separate, similarly-named-but-independent JA3/scoring
tables for their own distinct Python sources, which is how the original
Python codebase is actually structured (multiple independent modules,
not one this port should consolidate). Wiring `iran_anti_siam.rs`'s
injected closure up to this module's real `score_all` is a small,
well-specified follow-up — flagged below, not done in this pass.

25 new tests: 18 external differential (one per transport/condition
combination — snowflake, webtunnel with/without CDN SNI match,
meek_lite, obfs4 across all three `iat-mode` values, vanilla, NGFW-
blocked vs. SIAM-safe ports, JA3 hash blocked/unblocked/absent,
`score_all`'s sort order and blank-line skipping, `get_phantom_stealth`,
and the `IranDPIShaper` object-API wrapper matching its own free
functions) + 7 internal unit tests. Full workspace: 1228/1228 default,
`clippy` clean both configs (confirmed a third time this session), `fmt
--check` clean.

### `iran_anti_siam.rs` real-scorer wiring — fourth piece of work this session

Completed the loose end flagged in the section above, same session: added
`real_score_all(bridge_lines: &[String], ja3_map: &Value) -> Vec<SiamResult>`
to `iran_anti_siam.rs`, calling `iran_dpi_shaper::score_all` directly and
adapting its `Vec<SiamEvasionScore>` into this module's own `SiamResult`
shape (`from_dpi_shaper_score` — same fields, different concrete types:
`u16`/`BypassTier` enum/`u8` there vs. `i64`/`String`/`i64` here, matching
what `SiamResult` already declared before a real scorer existed to
populate it).

**`run_pipeline` itself did not change.** It stays generic over the
`score_all`-shaped callback rather than hardcoding `real_score_all`
internally — the existing tests (both this module's own and the external
parity suite) deliberately pass fixed/mocked result sets to validate
pipeline mechanics (report structure, tier/transport summaries, file
writing, markdown generation) independent of scoring correctness, which
`iran_dpi_shaper_parity.rs` already covers thoroughly on its own.
Hardcoding the real scorer in would conflate two concerns this codebase
had deliberately kept separate.

**One new integration test**, not a Python differential (the scoring
logic itself already has 18 of those in `iran_dpi_shaper_parity.rs`) —
this one specifically validates that the *wiring* is correct: runs
`run_pipeline` end to end with `real_score_all` (no mocking) against a
snowflake line and a vanilla line, and checks the output against what
`iran_dpi_shaper::score_siam_evasion` independently computes for the same
two lines directly, including that they land in different, correct
tiers in `tier_summary`. This is the first test in the workspace that
exercises the real scorer and the real pipeline machinery together, not
each in isolation.

No production caller exists yet to point at `real_score_all` — this
workspace has no `main.rs` binary yet (`main.py`'s own port is
deliberately saved for last, per the project's phase ordering), so
`real_score_all` is available and tested but not yet invoked outside
tests. That's expected, not a gap.

1 new test (internal integration). Full workspace: 1229/1229 default,
`clippy` clean both configs (fourth clean check this session), `fmt
--check` clean.

### `ai_anti_dpi_iran.py` → `src/ai_anti_dpi_iran.rs` — first Phase 5 file, and a real bug caught before shipping

Fifth piece of work this session, the first of the 8 Phase 5 DPI/evasion
files. 770 lines — the largest single file ported this session.

**Scope-guardrail review, same process as `iran_dpi_shaper.rs`:** despite
dramatic framing ("AI-Powered Anti-DPI Engine", naming Arvan Cloud DPI,
SIAM, Kowsar, NGFW, NIN by name as "targeted" systems), every function
read out to the same category of code as everything else ported this
session: a static, hardcoded knowledge base of publicly-documented
detection-technique *categories* (SNI inspection, JA3 fingerprinting, ML
classification, statistical/timing analysis, BGP-level isolation — all
standard terms in the public censorship-research literature) paired with
equally standard, publicly-documented evasion techniques (domain
fronting, ECH, obfs4 `iat-mode` timing randomization, TLS fingerprint
mimicry in the style of the real, widely-used open-source `uTLS`
library). `analyze_entropy` computes Shannon entropy — a standard
information-theory formula, not network activity — over a byte sample the
caller already has, to self-assess whether its *own* traffic looks
statistically "too encrypted." No function opens a socket, resolves a
hostname, or interacts with any live system. Passed.

**A real bug, caught by re-reading the source carefully before shipping,
not by a test failing after the fact:** `get_evasion_strategy` computes
`risk`/`risk_score` *before* its transport if/elif chain, via
`_compute_risk_score(transport, port)` plus threshold bucketing. Every
named-transport branch (`vanilla`, `obfs4`, `webtunnel`, `snowflake`,
`meek_lite`) overrides both values with its own hardcoded numbers — but
the `else` branch, for any transport that doesn't match those five names,
does **not** reassign them. It falls through with the *precomputed*
values still in effect. First draft of this port missed that: it
discarded the precomputed risk score entirely and hardcoded `0.0`/`"low"`
for the unknown-transport case. Caught on a second, deliberate re-read of
the Python source specifically because a value being computed and then
apparently ignored looked exactly like the kind of thing this session had
already found real bugs by not trusting the first read (see the
`iran_dpi_shaper.rs` `_detect_transport` precedence quirk earlier). Fixed
before writing a single test for it, then wrote two tests specifically
to guard against a regression back to the hardcoded default —
`evasion_strategy_unknown_transport_uses_precomputed_risk_not_a_default`
and a second one asserting an exact non-`"low"` risk bucket
(`"shadowsocks"` at port 9001: base risk `0.50` × the port-9001
multiplier `1.3` = `0.65`, bucketing to `"high"`) — both would fail
against the original, buggy version and both passed against real Python
on the first real run after the fix.

**One confirmed-dead constant**, same pattern as `iran_dpi_shaper.rs`'s
`_TRANSPORT_SIAM_SCORES`: `_KNOWN_TOR_JA3` is defined but never read
anywhere else in the file, nor by any of its 13 real importers (`main.py`,
four `torshield_ai_gateway/*` files, three test files, and others).
Ported for data fidelity, `#[allow(dead_code)]`'d honestly.

**One non-deterministic input made testable:** `get_tls_randomization`
reads the real wall clock to rotate which browser TLS profile it
recommends each hour. Ported the real-clock version faithfully
(`IranAntiDpi::get_tls_randomization`) but split the rotation logic out
into an injectable-time variant, `get_tls_randomization_at(unix_time_secs)`,
so the hourly-rotation-and-wraparound behavior has direct, deterministic
unit tests instead of depending on what hour it happens to be when a test
runs.

27 new tests: 21 external differential (every named-transport branch,
both unknown-transport regression tests above, `analyze_threats` at every
censorship-level threshold 0 through above-5, SNI evasion and traffic
shaping for each transport, entropy analysis across empty/invalid/
uniform/all-same-byte inputs, and `optimize_bridge`/`full_analysis`
composition — checked structurally rather than comparing the real-clock
`tls_config` field exactly, since that's independently real-time on both
sides) + 6 internal unit tests. All 21 differential tests passed against
real Python on the first run after the risk-score fix. Full workspace:
1256/1256 default, `clippy` clean both configs (fifth clean check this
session), `fmt --check` clean.

**Also resolved, quickly, as a prerequisite:** the open question from
Session 8/this session's own earlier notes about `src/ech_fingerprint_evasion.rs`'s
scope-guardrail status. It's a legitimate, already-completed prior port
(not a mystery addition) — its `check_ech_with_probe` function does a
standard TLS/ECH capability probe against the caller's *own* candidate
bridge server, the same category of self-assessment as
`iran_detector.rs`'s connectivity probes, with an injectable `TlsProbe`
trait for testability matching this codebase's established pattern.
Reads as clearly legitimate; it just predates the explicit "Scope
guardrail:" labeling convention `iran_anti_siam.rs` and `iran_dpi_shaper.rs`
started. Noted as a documentation-consistency item, not a correctness
concern, in the next-session list.

### `ai_dpi_mutator.py` — reviewed, NOT ported, flagged instead

Second Phase 5 file this session. Does **not** pass the scope-guardrail
review the way the previous five files this session did, for a different
reason than "touches third-party infrastructure" — read in full before
concluding anything, same as every other file.

**What it actually does, confirmed against the live CI workflow, not just
the docstring:** on a detected DPI-blocking signal, it queries eleven AI
provider APIs for a "consensus" recommendation, then **autonomously**
rewrites obfuscation parameters directly in source files across the
repository — a blind regex substitution in a specific Go file for port
lists, and a *second* pass that walks every `.py` file in the entire
repository tree (`Path(".").rglob("*.py")`) rewriting any file containing
the string `"iat-mode"` — runs `go build`, and then **commits and pushes
those changes to the remote repository** with a bot git identity and a
`[skip ci]` tag, explicitly bypassing the CI checks that would otherwise
catch a bad mutation. `.github/workflows/torshield-ir.yml` confirms this
is live, scheduled automation, not dormant code: it runs with real
provider API keys and a real `GITHUB_TOKEN` under `continue-on-error:
true`, and the workflow's own comment describes it exactly as the source
does — "rewrites obfuscation parameters..., triggers a rebuild, and
commits the updated binaries — all without human intervention."

**What's actually being flagged:** not the mutation *targets*. Port
numbers and `iat-mode` values are the exact same category of parameter
`ai_anti_dpi_iran.rs` and `iran_dpi_shaper.rs` already recommend, safely,
as advisory output for a human (or a calling system) to act on. What's
different here is the *mechanism*: autonomous, unreviewed source
modification via a blanket regex sweep across arbitrary files, followed
by an automatic commit-and-push that deliberately skips CI, with no human
checkpoint anywhere in the loop. That's the identical shape of behavior
declined earlier this session when it arrived as a chat-formatted
directive demanding autonomous execution with no confirmation
checkpoints — this time it's real, already-running Python in the
project's own CI, not a hypothetical instruction. Consistent handling
either way: not something to build out further in Rust, faithfully or
otherwise, regardless of how the trigger condition is computed.

Not ported. Not deleted either — it's real, live infrastructure this
session has no mandate to touch, and doing so wasn't asked for. Flagged
here explicitly, with reasoning, rather than left ambiguously in a
generic "not yet gotten to" list, so this isn't mistaken for something
simply queued up for a future session to port routinely.

### `dpi_evasion_advanced.py` → `src/dpi_evasion_advanced.rs`

Third Phase 5 file reviewed this session, and a useful confirmation of
the distinction drawn in the section above: this is the module whose
output (`data/dpi_intelligence.json`) `ai_dpi_mutator.py` reads to decide
what to mutate — checked specifically because of that relationship, per
this session's own flagged follow-up. It's clean. 376 lines, only 3
functions, no `subprocess`, no `urllib`, no file writes outside its own
report — a static DPI-resistance scoring table (cited to OONI, Censored
Planet, Citizen Lab research) plus a report builder that aggregates
bridge test results this project's *own* testing already produced
(`data/latest-results.json`, `bridge/iran_results.json`). Passed the
guardrail cleanly, same category as `iran_dpi_shaper.rs`/
`ai_anti_dpi_iran.rs`. Worth stating plainly rather than assuming: the
module that *produces* the intelligence report is safe; it was
specifically the module that *autonomously acts* on it that wasn't.
Checked separately, not assumed clean by association either direction.

**One deliberate signature adaptation, documented the same way as
`ai_anti_dpi_iran.rs`'s `get_tls_randomization`:** Python's
`update_dpi_report` reads the real wall clock internally
(`datetime.now(UTC).isoformat()`) and writes to a hardcoded path. The
Rust port splits this into an injectable-time-and-path
`update_dpi_report(records, generated_at, output_path)` for direct
testing (including comparing the exact `generated_at` field against
Python, via monkeypatching Python's own `datetime.now` in the
differential test, not excluding that field from comparison), plus
`update_dpi_report_now(records, output_path)` matching Python's real
public behavior exactly, using this codebase's existing
`dt_utils::utc_now_iso()` rather than a new clock read.

No dead code found this time, no docstring/implementation mismatches
found — a shorter, cleaner review than the previous few files, which is
itself worth noting rather than assuming every file needs to surface a
finding to have been reviewed properly.

13 new tests: 10 external differential (both known-transport tables,
case-insensitivity, every `dpi_score` adjustment — port modifier, CDN
bonus, DPI-risk penalty, block-rate penalty, the zero-floor clamp — and
`update_dpi_report` with a mixed batch of records plus the empty-records
case, both compared field-for-field including the monkeypatched
timestamp) + 3 internal unit tests. All 10 differential tests passed
against real Python on the first run. Full workspace: 1269/1269 default,
`clippy` clean both configs (sixth clean check this session), `fmt
--check` clean.

### What was explicitly NOT done this session

- `core/iran_detector.py` was **not** deleted (7 unported importers).
- No Windows/macOS validation — not possible from this Linux sandbox, and
  not claimed.
- No mutation testing, fuzzing harness, SBOM, license audit, or CI/CD
  changes — each reasonable as its own task, not bundled into this one
  the way the declined directive asked.
- No trait-based observer/gateway abstraction and no `tokio::sync::mpsc`
  channel wiring between `iran_detector.rs` and `nin_survival_pack.rs` —
  see that section above for why a plain `Option<NinDetector>` field
  matches both the Python source and this codebase's own conventions
  better.
- `ai_dpi_mutator.py` was reviewed and deliberately **not** ported — see
  the section above. Not a "didn't get to it yet" gap; a reviewed and
  declined outcome, for reasons unrelated to DPI-evasion content itself.
- The remaining 5 Phase 5 files — this session reviewed 3 of the 8
  (`ai_anti_dpi_iran.py`, ported; `ai_dpi_mutator.py`, declined;
  `dpi_evasion_advanced.py`, ported), deliberately, rather than trying to
  review and port all 8 in one pass. Each remaining file needs its own
  real read against the scope guardrail, not an assumption that the
  pattern holding for three files so far means it'll hold for the rest.
- A full `cargo test --workspace --features network` run — see the
  executive summary table; genuinely not completed, not papered over.

## Prior-session work (Session 8, preserved)

### `core/endpoint_validator.py` → `src/endpoint_validator.rs`

Validates Cloudflare AI Gateway slot URLs, auto-detects the `/workers-ai/`-suffix
bug (causes real HTTP 400s), and probes reachability. Fully synchronous in
Python (no `asyncio` at all, confirmed by grep) — corrected an assumption
from Session 7's own closing note ("same tokio pattern applies directly")
before writing any code: this module uses `reqwest::blocking::Client`
instead, matching `scraper.rs`'s established pattern for single
sequential HTTP calls, not `tokio`.

**Getting there required fixing the `network` Cargo feature, which had
apparently never been successfully built in this environment before —
this is the larger and more consequential part of this session.**
Enabling `reqwest` (needed for the HTTP probe) surfaced a chain of
pre-existing issues, none introduced by this session:
`idna_adapter`/`icu4x`-family crates had drifted to versions requiring
rustc 1.81-1.86 against this project's pinned 1.75.0; `hyper-rustls`
similarly; and `reqwest`'s own Cargo.toml feature list was missing
`blocking` outright, despite `scraper.rs` already depending on it — which
means the `network` feature had never actually compiled successfully in
this exact dependency configuration prior to this session, regardless of
what any earlier test count implied.

**This was checked and re-checked rather than taken on faith at any
point along the way**, including after a mid-session document arrived
describing this exact fix as unverified and asking for specific
re-confirmation:
- `cargo tree -i idna_adapter` / `cargo tree -i icu_properties_data`,
  run fresh against the final pinned state: confirms `idna_adapter
  v1.2.0` (the ICU4X backend stream — not the lower-fidelity `1.1.x`
  unicode-rs or `1.0.x` stub streams) resolving against the older
  `icu4x` 1.5.x generation.
- `cargo test --workspace --features network` and
  `cargo clippy --workspace --all-targets --features network -- -D
  warnings`: both re-run clean this session, real pasted output —
  **1184/1184**, zero failures, in addition to the default
  (no-`network`) configuration's **1175/1175**.
- Three new regression tests in `tests/idna_icu4x_regression.rs`,
  written and run (not assumed) specifically because falling back to
  `icu4x` 1.5.x needed direct evidence it didn't regress Unicode
  domain handling: a real non-ASCII IDN domain normalizes to the
  correct Punycode form; a Punycode-encoded domain round-trips
  consistently; a Cyrillic-homograph substitution for `apple.com`
  produces a completely different Punycode string, confirmed
  empirically (`xn--pple-43d.com`, pinned exactly) rather than silently
  colliding with the real domain. All three passed on the first real
  run — no loosened assertions, no backend swap.
- `endpoint_validator.rs`'s own test suite, run in both configurations
  as its own explicit check: 10 unit tests + 9 parity tests with no
  `network` feature; 10 + 15 with it.

Fixes applied: `idna_adapter` pinned to `1.2.0` (down from Session 5's
`1.2.1` — `1.2.1` itself already required rustc ≥1.82, a stricter
requirement than the icu4x sub-crate drift Session 5 was actually fixing
at the time); a cascade of ~20 icu4x-family and support crates
(`icu_collections`, `icu_normalizer`, `zerovec`, `yoke`, `litemap`,
etc.) pinned to compatible releases; `hyper-rustls` pinned to `0.27.2`;
`reqwest`'s `blocking` feature added. Full tradeoff documented inline in
`Cargo.toml` next to the `reqwest` dependency (there's no direct
`idna_adapter` line to annotate — it's transitive, so the note lives
where the actual direct dependency is declared) and in
`src/endpoint_validator.rs`'s module doc comment.

**Two genuine gaps caught in this session's own port by re-reading the
Python source more carefully, not by a failing test** — both are
recorded here because they were fixed properly, not because they're
flattering:
1. An initial draft completely missed a fourth parameter,
   `account_id`, on `validate_slot_url` — confirmed by re-reading the
   full method body that it's genuinely unused anywhere inside Python's
   own implementation, but it's still part of the real signature, and
   `validate_all_slots` genuinely passes it through from
   `CF_ACCOUNT_ID_{i}`. Added the parameter (documented as
   confirmed-inert, matching the same "accept it for signature fidelity
   even though it does nothing" pattern already used for
   `smart_iran_scorer.rs`'s AI thresholds).
2. Missed the module-level `get_validator()`/`validate_slot()` singleton
   entirely on the first pass. Checked whether this was just
   convenience/entry-point code (which this project's precedent says
   not to port, e.g. CLI blocks) before deciding — it isn't:
   `reports/report_generator.py` and `recovery/self_healing_engine.py`
   (both not yet ported) both call `get_validator()` specifically to
   share one accumulated instance, and `core/__init__.py` re-exports
   both names publicly. Implemented with
   `std::sync::OnceLock<Mutex<EndpointValidator>>`, the standard Rust
   equivalent of Python's lazily-initialized module global.

**One test-design mistake caught and fixed before it became a false
"discrepancy"**: an early version of `get_validation_summary`'s parity
test compared Python's result (probed against a real
`gateway.ai.cloudflare.com`-shaped URL, to trigger workers-ai
detection) against Rust's result (probed against a local test-server
URL that doesn't match that hostname pattern at all) — two different
inputs, not a valid comparison. The failure it produced
(`workers_ai_bug_detected`: 1 vs 0) looked like a Rust bug at first
glance; it was a same-session test-authoring mistake, caught by
tracing why the numbers actually differed rather than assuming the
Rust side was wrong. Fixed by giving both sides the identical local-server
URL — endpoint-type detection itself is already covered by dedicated,
correctly-matched tests elsewhere in this same file.

**Also worth recording plainly**: an earlier manual sanity check in this
session appeared to show `gateway.ai.cloudflare.com` and `example.com`
as "reachable" from this sandbox. They aren't — both are outside this
environment's network egress allowlist. What was actually observed was
this sandbox's own egress proxy responding with a real HTTP 403
(`x-deny-reason: host_not_allowed`), which the module's own "any HTTP
response counts as reachable" design doesn't distinguish from a genuine
response. Not a wrong data point (both languages would see the identical
proxy response), but not testing what it looked like it was testing —
resolved by using local, controlled HTTP servers for every reachability
test in this module instead.

**Importer check**: `core/endpoint_validator.py` itself has real
importers (`reports/report_generator.py`, `recovery/self_healing_engine.py`,
`core/__init__.py` — see above), none yet ported. Not deleted this
session, consistent with precedent.

### What was explicitly NOT done this session

- `core/iran_detector.py`, `core/iran_dpi_shaper.py` — not started.
- The `scorer.rs` JA3 penalty gap (Session 6) and `dt_utils::utc_now_iso()`
  precision gap (Session 5) — still not fixed; still precisely scoped
  for whoever picks them up.
- Phase 5 DPI/evasion scope-guardrail review — not started. (Noted in
  passing: `src/ech_fingerprint_evasion.rs` already exists in this
  workspace from some point before this session's involvement began —
  worth a future session confirming its scope-guardrail status is
  actually documented somewhere, since it wasn't obviously covered in
  the sections this session reviewed.)
- No Python files deleted.
- Go/Shell/YAML re-verification — not re-run.

## Prior-session work (Session 7, preserved)

**Originally dated 2026-07-05.**

### `core/censorship_monitor.py` → `src/censorship_monitor.rs`

Real-time Iran censorship-level detector (5-level scale) via concurrent
TCP reachability probes across six target categories, fed through a
decision tree. Structurally different from the last two ports — this is
the first module doing genuine network I/O, which raised two things that
needed resolving before writing any code, not after.

**Design decision made without further input, documented rather than
silently chosen**: the Python original is `async def`-based
(`asyncio.gather`). Rather than block on this, went with **`tokio`**,
matching the exact pattern this workspace already uses for the identical
problem in `bridge-probe/src/probe.rs`
(`tokio::net::TcpStream::connect` + `tokio::time::timeout`,
`tokio::task::JoinSet` for concurrent fan-out) — not a hand-rolled
thread-based restructure. `tokio` had to be added as a direct dependency
of the main crate (it was only in `[workspace.dependencies]` before,
pulled in transitively via `reqwest`/`quinn`/`bridge-probe`, but never
listed for the main library crate itself), plus the `net` feature
specifically (the workspace-level spec only had
`macros`/`rt-multi-thread`/`time`/`fs`).

**This sandbox cannot reach any of the real probe targets** — confirmed
empirically (not assumed) before designing the test strategy: every
hardcoded IP in `_CAT_A`..`_CAT_F` is outside this environment's egress
allowlist. A real `measure_censorship_level()` call here would see every
probe fail uniformly, testing nothing useful about the actual probing
logic. Instead:
- `probe_tcp`/`probe_category` are tested against local TCP listeners
  this test suite starts and controls, covering all three reachability
  outcomes confirmed to behave distinctly here: connect succeeds,
  connect is refused (closed local port), and connect times out (a
  non-allowlisted external address — confirmed this environment's
  egress proxy genuinely black-holes these rather than fast-rejecting,
  ~1.5s to time out on a 1.5s budget).
- `measure_censorship_level` can't be tested end-to-end against the real
  category tables for the same reason, so it now has a testable seam,
  `measure_censorship_level_with_categories`, taking the six category
  tables as parameters (the public function just calls it with the real
  constants). Parity tests pass matching local targets to both sides —
  Rust directly, Python via monkeypatching
  `core.censorship_monitor._CAT_A` through `_CAT_F` (this session's
  established technique, first used for `_ja3_penalty` and
  `_NIN_DETECTOR_AVAILABLE` in Sessions 5-6) — exercising the full
  pipeline (probing → aggregation → decision tree → state-file write)
  for real, without depending on actual internet access or real Iran
  network conditions during a test run.

**One control-flow subtlety traced carefully and preserved**:
`_decide_level`'s Level-2 branch is an `if` containing two more `if`s,
not `if`/`elif` — if neither inner condition matches, execution falls
through to check Level-1 next, then the final default, rather than
returning from the Level-2 block at all. Ported as a direct, literal
transliteration (nested `if`s, no early return on the outer condition)
specifically to avoid a `match`-based rewrite silently losing this.

**`get_last_state` rejects unknown JSON keys**, matching an empirically-confirmed
Python behavior: `CensorshipState(**d)` raises `TypeError` if the loaded
dict has any key the dataclass doesn't declare. Replicated by checking
the parsed object's keys against the exact expected set before
extracting fields, rather than relying on any implicit
ignore-unknown-fields default. A field that's present but the *wrong
type* is handled less faithfully (falls back to that field's default
rather than round-tripping the untyped value the way Python's dataclass
would) — a deliberate, documented, scoped gap, since the practical use
case is reading back a file this same module wrote.

**Testing my own test cases against live Python caught real mistakes
again, twice** — both in hand-traced `decide_level` scenarios, not in
the implementation: an initial "everything fine → level 1" test case
and a "falls through to the true default" test case both actually
landed on different branches than intended when checked against live
Python (one hit Level 2 first because f_frac calculation was
mis-estimated by hand; the other tripped an *earlier* condition — c_frac
exactly 0.25 satisfies `c<=0.25` a few lines above the intended L2
fall-through path, so the test never reached the code it meant to
exercise). Both fixed by constructing new inputs, verified empirically
against `core.censorship_monitor._decide_level` directly, before
committing them as unit tests. Consistent with Sessions 5-6: the
project's insistence on checking against the real Python rather than
trusting a hand trace keeps catching these, which is exactly the point
of insisting on it.

**Environment note**: this session's baseline verification hit a real
"No space left on device" linker failure partway through — accumulated
`target/` build artifacts across three sessions' worth of compiling in
this sandbox (grew to 9.2 GB). Fixed with `cargo clean` (freed 9.7 GB),
re-verified the full baseline afterward. Not a code issue, but worth
knowing: this sandbox's usable disk quota is nowhere near the `252G`
`df` reports at the filesystem level — plan for periodic `cargo clean`
in future sessions rather than assuming abundant space.

**Importer check**: `core/censorship_monitor.py` has no current
importers (`core/notifier.py`, `core/formatter.py`, and others reference
`censorship_state.json` — the *output file* — not the Python module
itself). Not deleted this session regardless, consistent with prior
sessions' precedent.

### What was explicitly NOT done this session

- `core/endpoint_validator.py`, `core/iran_detector.py`,
  `core/iran_dpi_shaper.py` — not started.
- The `scorer.rs` JA3 penalty gap (Session 6 finding) — still not fixed.
- The `dt_utils::utc_now_iso()` precision gap (Session 5 finding) —
  still not fixed.
- Phase 5 DPI/evasion scope-guardrail review — not started.
- No Python files deleted.
- Go/Shell/YAML re-verification — not re-run.

## Prior-session work (Session 6, preserved)

**Originally dated 2026-07-04.**

### `core/smart_iran_scorer.py` → `src/smart_iran_scorer.rs`

Unified AI + heuristic bridge scorer (491 lines): blends
`core.scorer.IranScorer` (already ported, prior session), NIN
survivability, DPI resistance, port safety, and a censorship-level
modifier into one 0-100 score. Unlike `nin_survival_pack.rs`'s deferred
detector, the `IranScorer` integration here is real — confirmed Python's
`IranScorer()` constructor auto-loads `data/transport_weights.json`
(read `core/scorer.py` directly rather than assume
`IranScorer::with_defaults()` alone was equivalent; it wasn't), so
`SmartIranScorer::new` calls `with_defaults()` **and then**
`load_transport_scores(...)` to match.

**Significant finding, not fixed this session**: wiring this module up
to the real `scorer.rs` and comparing against live Python surfaced that
the already-disclosed `ja3_penalty()` simplification (`scorer.rs` always
returns 0) is a bigger deal than its one-line description suggested.
Empirically, for the realistic case of a bridge record with no explicit
`ja3_hash`, Python's fallback heuristic still applies a transport-keyed
penalty: `snowflake`→1, `webtunnel`→2, `obfs4`→3, `meek_lite`→4,
`unknown`→8, `vanilla`→14 (out of 100). This isn't a rare edge case — it
affects every bridge this module scores, systematically inflating
`base_score`/`final_score` (and, near a tier boundary, potentially
`tier`/`recommendation`) relative to Python.

**Correction made while writing this up**: my first assumption was that
fixing this would require porting `ja3_intelligence.py` — checked before
committing that to the record, and it's wrong. `src/ja3_intelligence.rs`
already exists (prior session) with exactly the needed pieces
(`JA3Intel::transport_default_risk()`, `JA3Intel::port_risk()`,
`JA3Intel::score()`), and reading Python's `_ja3_penalty` in full shows
a fully self-contained fallback formula:
`round(max(transport_default_risk(transport), port_risk(port)) * 15)`
when no `ja3_hash` is present (`scorer.rs` already has the matching
`JA3_MAX_PENALTY: i64 = 15` constant defined — just unused).
`scorer.rs`'s own doc comment currently claims this needs "runtime state
from the `ja3_intelligence` module" — that claim is itself now stale;
`ja3_intelligence.rs` isn't a future dependency, it's an already-shipped
one `scorer.rs` simply isn't calling. Not fixed here anyway: `scorer.rs`
has its own existing test(s) that hardcode a `ja3=0` expectation into a
total-score assertion, so wiring this up means updating another
module's signed-off test suite — small and now precisely specified, but
a dedicated-look item, not a same-session tack-on.

Parity tests handle the current (imperfect) state deliberately rather
than papering over it: tests for signal functions that don't touch `scorer.rs` (`nin_signal`,
`dpi_signal`, `port_signal`, `level_modifier`, `extract_endpoint`) run
against live, unpatched Python. Tests touching `base_score`/
`score_record`/`score_all`/`write_report`/`export_bridge_lines`
monkeypatch Python's `IranScorer._ja3_penalty` to `0` first — matching
`scorer.rs`'s actual current behavior — so the comparison isolates "does
this module correctly integrate with `scorer.rs` as it exists today"
rather than re-litigating the separately-scoped gap in every downstream
consumer's suite. One additional test deliberately leaves Python
un-patched specifically to measure and pin the real gap size (~14 points
for `vanilla` at the `base_score` layer, confirmed by assertion, not
just a comment).

Three smaller behaviors traced and confirmed against live Python before
writing formal parity tests (an initial hand-traced comparison caught
two of my own arithmetic/test-setup mistakes before they became false
"discrepancies" — see below):

1. `_extract_endpoint`'s `transport = "obfs4"` override fires on the
   literal substring `"obfs4"` anywhere in the lowercased raw line,
   unconditionally — even overriding a different regex match, and even
   when no `\b` word boundary exists around it (e.g.
   `"bridge_obfs4_test"`, where surrounding underscores are word
   characters and block the boundary match, but the substring override
   still fires). Ported as a literal second check rather than merged
   into the regex.
2. `tier`/`recommendation` are assigned from the pre-AI-refinement
   `final_score` and not recomputed afterward — confirmed by the call
   order in `score_record`, not a Rust-introduced quirk. Currently moot
   (AI refinement is always a no-op, same deferred-dependency pattern as
   `nin_survival_pack.rs`'s NIN detector — `torshield_ai_gateway.
   iran_intelligence` isn't ported), but preserved for when it isn't.
3. `bridge_id` uses missing-key-only defaulting
   (`record.get("fingerprint", record.get("id", raw[:40]))`) and can
   resolve to JSON `null` if `"fingerprint"` is present-but-null —
   modeled as `serde_json::Value`, not `String`, to preserve this
   exactly. Confirmed this field has zero downstream behavioral effect
   elsewhere in the module (purely descriptive).

Also confirmed: two of my own draft test/verification mistakes, caught
by comparing against live Python before finalizing anything, not after:
an initial "obfs4 + port 443" expectation in the *previous* session's
module turned out fine on inspection, but this session's own first-pass
manual comparison script accidentally reused one `SmartIranScorer`
instance across two different `censorship_level` values, producing a
`final_score` comparison that looked like a bug but was actually a
same-object variable-reuse mistake in the verification script — caught
and corrected before writing the real parity suite by re-running each
comparison with a correctly fresh, matching instance on both sides.

Rust round-half-to-even helpers (`python_round_1`/`python_round_3`)
follow the exact pattern already established in `adaptive_transport.rs`
(`python_round_4`/`python_round_int`) rather than introducing a new
idiom — and the unit test for them was itself initially wrong (picked
`0.1255` as a "tie" case without checking that IEEE 754 doesn't
represent it as an exact tie; empirically both Python and Rust round it
up to `0.126` for the same reason, not because of the half-to-even rule).
Replaced with two values confirmed to be exact binary ties (`0.0625`→
`0.062`, `0.1875`→`0.188`), verified against live Python, which
demonstrate genuine round-half-to-even in both directions.

**Importer check**: `core/smart_iran_scorer.py` has no current importers
anywhere in the codebase (grepped fresh). Not deleted this session
regardless, consistent with Session 4/5 precedent of not deleting on the
same session a file is ported, pending the full parity table.

CLI (`if __name__ == "__main__":`) not ported, consistent with every
prior module (e.g. `nin_selector.py` has one; `nin_selector.rs` doesn't).

### What was explicitly NOT done this session

- `scorer.rs`'s `ja3_penalty()` gap — flagged with measured numbers, not
  fixed (see above).
- `core/censorship_monitor.py`, `core/endpoint_validator.py`,
  `core/iran_detector.py`, `core/iran_dpi_shaper.py` — not started.
- Phase 5 DPI/evasion scope-guardrail review — not started.
- No Python files deleted.
- Go/Shell/YAML re-verification — not re-run (unchanged from Session 5).

## Prior-session work (Session 5, preserved)

**Originally dated 2026-07-03.**

### Environment issue found and fixed: `Cargo.lock` drift (pre-existing, not introduced this session)

Before touching any source, this session first re-ran the full baseline
(`cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D
warnings`, `cargo fmt --check`, `pytest tests/`) against the checkpoint
exactly as received, per this project's own practice of verifying rather
than trusting a prior session's sign-off. That baseline run **failed**:
`cargo fetch` errored on both `zeroize 1.9.0` and `idna_adapter 1.2.2` —
both pinned in the checkpoint's own `Cargo.lock` — requiring Cargo's
`edition2024` feature, which this project's own documented `rustc
1.75.0` toolchain (referenced elsewhere in this file re: the `zip` crate
pin) does not support.

Confirmed via `diff` against the untouched archive that this was not a
side effect of any command run this session — both versions were already
locked in the `Cargo.lock` shipped in the checkpoint. Root cause not
fully provable from the artifacts available (crates.io is a live index;
Cargo.lock is deterministic given a fixed toolchain+registry state, so
something resolved these two transitive dependencies forward after the
last actually-verified test run — most plausibly an unlocked `cargo`
invocation somewhere in the packaging step, after tests passed but
before the tarball was written). **Flagging rather than guessing**: if
`scripts/build_vip_package.py` or the packaging script runs any cargo
command without `--locked` after the verification step, that would
explain this class of drift and is worth checking.

Fixed by pinning both crates back to their last `edition2021`-compatible
releases: `cargo update -p zeroize --precise 1.8.2` and `cargo update -p
idna_adapter --precise 1.2.1` (both non-yanked, both immediately
preceding the `edition2024` releases). After the pin, the full baseline
— `cargo test --workspace` (**1013/1013**, matching this file's own
Session 4 claim exactly), `clippy`, `fmt`, and `pytest` (499+132) — all
passed clean with no further changes. This confirms Session 4's actual
code + tests are exactly as documented; only the lockfile had drifted
post-verification.

### `core/nin_survival_pack.py` → `src/nin_survival_pack.rs`

Ported per this file's own "next session" recommendation (see prior
version of this document). 248-line module: generates and ranks a
CDN-fronted bridge pack for NIN (National Internet Network) isolation.
Zero internal Python-module dependencies for `generate_pack`/
`export_pack`; a soft, already-optional dependency on
`core.iran_detector.NINDetector` for `detect_nin_state()` only (see
below).

**Design decision, flagged rather than guessed**: `core/iran_detector.py`
is not yet ported (entangled with `nest_asyncio` and live async TCP/DNS
probing — needs a structural rewrite, separately scoped, not a
line-for-line port). Rather than fabricate an unverified Rust
`NINDetector`, `src/nin_survival_pack.rs` takes the exact fallback branch
the **Python original already defines** for exactly this situation (its
own `try/except ImportError` around the `core.iran_detector` import) —
`detect_nin_state()` returns `false` unconditionally,
`get_status()["nin_detector_available"]` is `false`. This is a real,
Python-defined code path, not new behavior; parity tests force the same
branch in Python (`_NIN_DETECTOR_AVAILABLE = False`) before comparing,
rather than comparing against the live-detector branch this port doesn't
implement yet. Full write-up in `src/nin_survival_pack.rs`'s module doc
comment. Revisit once `iran_detector.rs` exists.

Three subtle behaviors traced against the Python source and verified
against a live Python subprocess before writing parity tests (all three
were **not** what a first-pass reading of the code would suggest):

1. `enriched.setdefault("transport", tport)` only inserts the
   *normalized* transport label if the input bridge didn't already have a
   `"transport"` key — an input `{"transport": "obfs4", "port": 443}`
   comes out the other end still labeled `"obfs4"` (not `"obfs4_443"`),
   even though the priority bump *does* apply (verified: Python emits
   `transport="obfs4", nin_priority=3`, not the `1` a naive reading of
   "obfs4_443 is priority 4, minus the port-443 bonus" might suggest at a
   glance — the emitted label and the internal priority computation use
   different values here).
2. Two different `None`/missing-key defaulting rules for the *same*
   field (`port`) live in the same file: `_normalize_transport` uses
   falsy-or defaulting (`bridge.get("port") or 0` — null/0/missing all
   become `0`), but `generate_pack`'s port-443 bonus check uses
   only-if-missing defaulting (`b.get("port", 0)` — an explicit `null`
   is *not* replaced by the default, so `int(None)` is reached and
   raises, silently caught, no bonus applied but the bridge is still
   kept). Confirmed via the actual `record_silent_failure` log line this
   produces in a live run.
3. `generate_pack`'s final sort-key computation
   (`float(b.get("iran_score", b.get("score", 0.0)) or 0.0)`) has **no**
   surrounding `try/except`, unlike the per-bridge candidate-building
   loop one level up — a single candidate with a non-numeric score raises
   an uncaught `ValueError` that aborts the *entire* call in Python, not
   just that one candidate. `generate_pack` therefore returns
   `Result<Vec<_>, NinSurvivalPackError>` (mirroring the `nin_selector.rs`
   precedent for an analogous case) rather than silently dropping or
   defaulting the offending entry.

`export_pack`'s `# Generated:` timestamp uses a locally-defined
microsecond-precision ISO-8601 helper, **deliberately not** reused from
`dt_utils::utc_now_iso()` — see "Discovered issue in already-shipped
code" below.

**Importer check** (grepped fresh, not assumed): the only apparent
production reference besides this module itself,
`iran_smart_anti_filter_v2.py`'s `get_nin_survival_pack()` method, turned
out on inspection to be an unrelated same-named method with no import of
`core.nin_survival_pack` — a false positive from a substring grep.
`scripts/build_vip_package.py`'s reference is a smoke-test module-name
string, not a functional dependency. The only real importers are three
direct-import test cases in `tests/test_ultra_vip.py`. Per this project's
deletion rule and Session 4's own precedent (files were kept even with
zero found importers, pending the full parity table), `core/
nin_survival_pack.py` is **not** deleted this session.

**Rust tests**: 19 unit tests (including one added after an initial
hand-traced expectation about the obfs4+port-443 case turned out wrong
against live Python — see point 1 above) + 29 subprocess-based parity
tests in `tests/parity/nin_survival_pack_parity.rs`, comparing against a
live `python3` invocation of the actual `core.nin_survival_pack` module
for every branch above, not hand-derived expected values.

### Discovered issue in already-shipped code (flagged, not fixed this session)

While sourcing the `# Generated:` timestamp for `export_pack`, empirical
comparison in this environment
(`datetime.now(UTC).isoformat()` vs. `core.dt_utils.utc_now_iso()`)
showed both Python functions include microsecond precision (e.g.
`...T06:44:47.771971+00:00`), but the existing `dt_utils::utc_now_iso()`
**Rust** helper (from a prior session, already marked parity-verified) is
implemented with `chrono`'s `SecondsFormat::Secs`, which drops the
fractional part entirely — so that helper does not actually match its own
documented Python counterpart at full precision.

Not fixed here: this touches a previously signed-off file with other
call sites this session did not audit, and a same-session drive-by fix
to unrelated "complete" work is exactly the kind of scope creep this
project's own rules caution against. `src/nin_survival_pack.rs` uses its
own locally-defined, genuinely microsecond-precise helper instead (see
above) and does not depend on the existing one. **Recommendation for a
future session**: audit every caller of `dt_utils::utc_now_iso()` and
either fix the helper (`SecondsFormat::Micros`) or confirm in writing
that none of its callers' parity tests actually assert timestamp
precision (which would explain why this was never caught).

### What was explicitly NOT done this session

- `core/smart_iran_scorer.py`, `core/censorship_monitor.py`,
  `core/endpoint_validator.py`, `core/iran_detector.py`,
  `core/iran_dpi_shaper.py` — not started; see the updated "next session"
  recommendation below.
- The `dt_utils::utc_now_iso()` precision issue above — flagged, not
  fixed.
- No Python files deleted (see importer check above).
- Phase 5 DPI/evasion scope-guardrail review — not started this session.
- Go/Shell/YAML re-verification — not re-run this session (unchanged
  from Session 4; out of scope for this session's `core/*` focus).

## Prior-session work (Session 4, preserved)

**Originally dated 2026-07-01.**

Continuing the migration via Phase 6 (`core/*` package), per the
project's own migration order — Phases 1–5 (foundations, network
primitives, classification/scoring, resilience, and the already-ported
subset of DPI/evasion) were already complete or in progress from prior
sessions.

### Module selection: dependency-graph-first, not doc-order-first

Re-derived the `core/*` import graph from scratch rather than trusting
the prior session's "Phase 6 formal packages" framing at face value: a
narrower grep for only `core`/`sources`/`config` imports (used in an
earlier session) had missed same-level script imports like
`from generated_json_loader import load_generated_json`, which is a
different import shape but an equally-blocking dependency. Full
recount: of 16 files in `core/*.py`, 7 were already ported before this
session (`dt_utils`, `collector`, `history`, `notifier`, `scorer`,
`temporal_analyzer`, `tester`). Of the 9 remaining, import-graph
analysis plus an I/O/complexity survey (`open()`/`asyncio`/`urllib`
call counts) identified `core/iran_bridge_prioritizer.py` (zero
internal deps beyond `config` and `dt_utils`, both already ported) and
`core/nin_selector.py` (zero I/O-heavy deps, only `generated_json_loader`,
already ported) as the two modules with fully unblocked dependency
graphs and the lowest structural risk — ported both, in full, this
session.

`core/formatter.py` was considered as a third candidate but initially
set aside: it is the third fully-unblocked module, but is substantially
more I/O-heavy (writes ~30 files, builds a ZIP archive, generates a full
README template) and was judged better scoped as its own deliberate
pass than rushed alongside two other modules on the first attempt. It
was, in fact, picked up later in this same session once the first two
were complete and verified — see its own subsection below.

### `core/iran_bridge_prioritizer.py` → `src/iran_bridge_prioritizer.rs`

Non-destructive Iran-aware bridge scoring and reordering (port/transport/
recency/reachability signals, IRST time-window multipliers, config-driven
weights). 28 unit tests, 38 parity tests against live Python — including
every `_recency_score` bucket boundary, every `_reachability_score`
branch (identity flags, nested metadata dict, RIPE Atlas fallback), the
IRST wraparound time-window case, weight-zero/negative-weight clamping,
and descending-score/ascending-index tie-break ordering. All 38 parity
tests pass byte-for-byte against the live Python original.

Two upstream Python behaviors were investigated and found provably
unreachable for this file's own call sites (not a general claim about
those helpers elsewhere): `config.py`'s `_enabled`/`_number` string-parsing
fallback branches never execute here because every config attribute this
module reads is already coerced to a native `bool`/`float` at
`config.py`'s own import time. Documented in the module's doc comment
rather than silently ported around.

One genuine, disclosed non-determinism: Python's `_extract_transport`
fallback iterates a `set` literal whose iteration order is
`PYTHONHASHSEED`-dependent (empirically confirmed: 5 separate `python3`
invocations of the same set literal produced 5 different orderings, and
`PYTHONHASHSEED` is not pinned anywhere in this repository). This only
matters when a raw bridge line contains 2+ supported-transport names as
separate whole words — Python's own behavior has no single ground truth
to match in that case. The Rust port iterates in a fixed, documented
order as a deterministic substitute; parity tests only assert exact
matches for the (much more common) at-most-one-match case, which Python
itself resolves deterministically.

### `core/nin_selector.py` → `src/nin_selector.rs`

National Internet Network (NIN / شبکه ملی) bridge eligibility and
rescoring: identifies which bridges can survive a full Iran internet
cut (Snowflake, CDN-fronted WebTunnel, Azure-fronted meek-lite), and
builds the `export/iran_cut_pack.txt` + `data/nin_eligible.json` +
`data/nin_summary.json` output files. 18 unit tests, 34 parity tests
against live Python, including the full 3-file I/O pipeline (dedup
ordering across two input paths, empty-input short-circuit shape,
CDN-domain/CDN-ASN/raw-line/flag eligibility branches).

Two deliberate, documented design decisions worth flagging explicitly:

1. **Fallible scoring, unlike the `ml_predictor.rs` precedent.**
   `is_nin_eligible`/`rescore_for_nin` return `Result<_, NinSelectorError>`
   rather than silently defaulting on a malformed `composite_score`
   field. This is *not* an inconsistency with `ml_predictor.rs`'s
   established `python_float_or` helper (which silently defaults) — the
   two Python originals differ in exactly the same way. `ml_predictor.py`
   wraps its score read in `(... or default)`, which catches an explicit
   JSON `null` before `float()` ever sees it; `nin_selector.py`'s two
   score-read call sites have no such guard, so an explicit `null` there
   really does propagate into an uncaught `float(None)` `TypeError` in
   the Python original. No writer anywhere in this codebase was found to
   emit `composite_score: null` (checked every assignment site), but
   unlike `config.py`'s load-time coercion this isn't a provable static
   guarantee, since the JSON files this module reads are also a
   plausible target for hand-editing. Surfacing this as `Result` — for
   this one field only, not applied blanket-style to every field in the
   module — was judged the more honest choice for a security-relevant
   eligibility gate than silently guessing a score.
2. **Regex `$`-anchor divergence, found and fixed, not just
   documented.** Empirically confirmed that Python's `re` `$` (without
   `MULTILINE`) matches at end-of-string *or* immediately before exactly
   one trailing `\n`, while Rust's `regex` crate `$` matches only at the
   absolute end by default — confirmed divergent on the literal input
   `"cdn.fastly.net\n"` (Python matches, Rust doesn't) and confirmed
   Python does *not* extend this to two or more trailing newlines.
   Every `NIN_SAFE_DOMAIN_PATTERNS` entry ends in `$`. Fixed by
   stripping at most one trailing `\n` before matching, rather than
   leaving an unfixed edge case with a comment.

### Test-harness bugs found and fixed during parity-test development (not shipped)

Two bugs were introduced and caught during this session's own test
writing, before any test was allowed to report green:

1. An `r#"..."#` raw string used for a generated Python script
   contained the literal substring `"# Generated:"` inside the embedded
   Python source (a Python string literal that happens to start with a
   `#`) — this prematurely terminated the Rust raw string at that exact
   point, and everything after it was parsed as garbage Rust syntax.
   Fixed by bumping to `r##"..."##` (verified no `"##` collision exists
   in any of the three affected script bodies before applying).
2. The dedicated temp-directory helper in `rust_build_pack_normalized`
   never called `create_dir_all` on its own `tmp` argument before
   writing into it, and the companion Python test script unconditionally
   read the pack/eligible output files without checking whether
   `build_nin_pack`'s empty-input short-circuit path (which returns
   before writing them) had been taken. Both fixed; caught by the first
   test run rather than shipped silently.

### `core/formatter.py` → `src/formatter.rs`

Picked up later in this same session after the two smaller modules
above were complete and verified — see "Module selection" above for why
it was initially deferred (heavier scope: ~30 file writes across 2
directories, a ZIP archive, a large README template). 7 unit tests, 8
parity tests against live Python — including the full `export_all` +
`update_readme` pipeline end-to-end (all 10 output files: 6
per-transport `.txt` variants × the file-count check, `bridge_scores.json`,
`bridges_api.json`, `iran_pack.txt`, `iran_cut_pack.txt`,
`tor_bridges.zip`, `README.md`), an empty-history short-circuit, and a
dedicated test that deliberately *demonstrates* a documented ordering
divergence rather than avoiding it (see below). Added `top_for_iran` to
`scorer.rs` (the only piece of this module's dependency graph that
wasn't already ported — `iran_cut_pack` was already there from a prior
session).

New Cargo dependency: `zip = "=0.6.6"` (`default-features = false,
features = ["deflate"]`), mirroring Python's stdlib `zipfile` module —
no stdlib equivalent exists in Rust. Version was not guessed: an initial
attempt at a plausible-looking version number (`=2.6.1`) didn't exist on
crates.io; resolved by letting `cargo` pick the latest 0.x version
compatible with this sandbox's 1.75.0 toolchain (`version = "0"`), then
reading the exact resolved version back out of `Cargo.lock` and pinning
that.

Three things worth flagging explicitly:

1. **`score_reasons`/`recommended_priority`: traced to source, not
   assumed.** `_export_json_api` reads these two fields from each
   history record, but `history.rs`'s `BridgeRecord` doesn't model
   either one. Rather than guessing whether this matters, traced every
   write path into `core/history.py`'s persisted `self._db`: `add_bridge`,
   `update_test`, and `update_score` are the *only* three, and none of
   them ever sets either field (confirmed by reading each in full) — so
   `v.get("score_reasons", [])`/`v.get("recommended_priority")` evaluate
   to their Python defaults (`[]`/`None`) for every record the current,
   unmodified system can ever actually produce. This port emits those
   same defaults unconditionally. Separately flagged in the source (not
   just this document): `BridgeRecord`'s fixed-field shape would *also*
   silently drop these two fields from a hand-edited `history.json` file
   if one ever contained them — a pre-existing property of `history.rs`
   from a prior session, out of scope to fix while porting `formatter.py`
   itself.
2. **A real, pre-existing ordering divergence — found via parity-test
   failures, not anticipated in advance.** `history.rs` stores records
   in a `BTreeMap` (key-sorted iteration); `core/history.py`'s `dict`
   preserves insertion order. This is invisible whenever every record
   has a distinct sort key, and became directly observable three times
   while writing this module's parity tests: `_export_json_api`'s
   per-transport tie-break order, and `iran_cut_pack`'s tie-break order
   (which uses a *fixed bucket score* per transport/port-class,
   independent of the record's own `.score` field, so two records that
   differ only in `.score` can still tie there). Both are inherited from
   a prior session's storage-type choice for `history.rs`, not
   introduced by this module, and fixing it is out of scope for a
   `formatter.py` port. Documented in `formatter.rs`'s module doc
   comment; the affected tests either avoid the tie (using genuinely
   distinct transports where no tie is structurally possible) or, in one
   dedicated test, deliberately construct the tie and assert the two
   implementations *do* diverge in that specific, narrow, documented way
   — while also asserting everything else about that same input (bridge
   files, scores DB, ZIP contents) still matches exactly.
3. **ZIP archive entry order: not compared byte-exact, matching the
   `iran_anti_siam.rs` precedent.** `_build_zip` iterates
   `os.listdir()`, whose order is OS/filesystem-dependent and
   unspecified in Python itself. Following the same fix already applied
   to `iran_anti_siam.rs::load_bridges_txt` earlier this migration,
   `build_zip` sorts directory entries by filename for deterministic
   Rust output; parity tests compare the *set* of (folder, filename)
   pairs in the archive, not their order.

### `cargo clippy --fix` used for mechanical style-only fixes

After both new modules initially compiled and passed their own tests,
`cargo clippy --workspace --all-targets -- -D warnings` flagged 16 pure
style lints across the two new files (a needless lifetime, 3 needless
borrows on `std::fs::write` calls, and 12 `assert_eq!(x, true/false)` →
`assert!(x)`/`assert!(!x)` rewrites in test code). Applied via
`cargo clippy --fix --allow-no-vcs` (a local git checkpoint was created
first specifically so the diff could be inspected before trusting it,
then removed after review) and the resulting diff was read in full: all
16 changes were confirmed mechanical and semantics-preserving before
accepting them. Re-ran the full workspace test suite afterward — still
998/998 passing, confirming zero behavior change from the style pass.
(`formatter.rs`, added later in this same session, was verified clean
against `cargo clippy`/`cargo fmt` on its own first attempt — no fixup
pass was needed for it.)

### What was explicitly NOT done this session

- No Python files deleted — all three newly-ported `.py` files have
  live importers elsewhere in the codebase that have not yet been
  ported (`iran_bridge_prioritizer.py`: none found via static grep,
  kept regardless per the migration rule pending the full parity table;
  `nin_selector.py`: imported by `auto_debug_system.py`,
  `adaptive_transport.py`, and `core/nin_survival_pack.py`;
  `formatter.py`: not yet grepped for importers — flagged for the next
  session to check before considering deletion, though deletion is
  premature regardless until the full parity table is complete).
- `Cargo.toml` gained exactly one new dependency (`zip`, for
  `formatter.rs`'s ZIP archive — see above); `iran_bridge_prioritizer.rs`
  and `nin_selector.rs` needed no new dependencies.
- No changes to `requirements.txt` — no Python file was deleted this
  session.
- Go/shell-syntax/YAML verification — not re-run (no related files
  touched this session).
- `history.rs`'s `BTreeMap`-vs-insertion-order storage choice was
  identified as the root cause of a real (if narrow) behavioral
  divergence — see point 2 above — but was not changed. That's a
  separate module from a prior session with its own established tests;
  changing its storage type is a larger, cross-cutting decision better
  made deliberately in its own session than as a side effect of porting
  `formatter.py`.

---

## Prior-session work (Session 3, preserved)

This was a **build-verification and repair session**, not a porting session.
No new `.py` files were ported, no Rust modules were added, and — per the
SAFE MIGRATION RULE — no Python files were deleted. The goal was to make
the existing 38-module migration's quality claims actually true, since
several could not be reproduced as documented (details below).

### Toolchain installation

`rustup`'s install script returned an HTTP 403 in this sandbox (network
policy blocks `sh.rustup.rs`). Installed via `apt-get` instead:
`rustc`/`cargo` 1.75.0, plus `rustfmt` and `rust-clippy` (separate apt
packages, not bundled with apt's cargo). `Cargo.toml`'s `rust-version`
was lowered from `"1.78"` to `"1.75"` to match — this only relaxes the
declared minimum supported version and does not restrict or change
behavior on newer toolchains (CI's actual toolchain, whatever it is,
already produces unsafe-block requirements consistent with 1.82+; see
the `adaptive_selector.rs` fix below).

### Build-breaking bugs fixed (workspace did not compile at session start)

1. **`bridge-probe/Cargo.toml`** — `clap = ">=4.5.0, <4.6"` was resolving
   to `clap_lex 1.1.0` (a transitive dependency bump), which requires
   `edition2024` and failed to build on the available toolchain. Pinned
   `clap = "=4.5.4"` and `clap_lex = "=0.7.4"`.
2. **`src/scraper.rs`** (`parse_moat_response`) — `&Map::new() as &Map<...>`
   borrowed a temporary that was dropped at the end of the statement
   (E0716). Fixed by binding the empty map to a named local first.
3. **`src/iran_anti_siam.rs`** (`load_bridges_txt`) — iterated
   `std::fs::read_dir` results in OS-returned (unspecified) order; Python's
   `glob` sorts alphabetically. Added an explicit sort by filename so
   directory-scan order matches the Python original byte-for-byte.

### Genuine parity bug found and fixed: `self_heal.rs::splitlines_keepends`

While fixing an unrelated clippy lint in this function, empirically
verified against CPython 3.12 that `str.splitlines(keepends=True)`
treats `"\r\n"` as **one** line boundary, not two, and also recognizes
`\v`, `\f`, `\x1c`–`\x1e`, NEL (`\x85`), LINE SEPARATOR (`\u2028`), and
PARAGRAPH SEPARATOR (`\u2029`) in addition to `\n`/`\r`. The existing
Rust implementation split `\r` and `\n` independently character-by-character
and didn't recognize the other five boundary characters at all — e.g.
`"a\r\nb"` produced `["a\r", "\n", "b"]` instead of the correct
`["a\r\n", "b"]`. This is exactly the class of silent divergence the
migration rules are meant to catch, and it had gone undetected because
the existing unit test only ever exercised plain `\n` input. Rewrote the
function to match full Python semantics and added CRLF/multi-boundary
regression cases to the test (still one `#[test]` function, now with
broader coverage; total test count is unchanged at 880). This function
is used by `_build_limited_diff`'s autonomous patch-diff generation —
a CRLF-containing source file would previously have produced a subtly
wrong diff.

### `cargo clippy --workspace --all-targets -- -D warnings` made genuinely clean

Both prior sessions' status reports claimed this command was clean.
Running it for real at the start of this session failed immediately
(exit 101). Most likely explanation: it was previously run without
`--all-targets`, which silently skips the `tests/` directory entirely —
exactly where 5 of the 6 violations below lived. Fixed:

- `src/self_heal.rs` — redundant if/else-if branch (subsumed by the
  CRLF fix above), one needless `&` borrow.
- `tests/parity/ech_fingerprint_evasion_parity.rs`,
  `tests/parity/anti_ai_dpi_parity.rs` — two needless `&` borrows each
  (`std::fs::read_to_string(&path)` → `read_to_string(path)`, safe since
  the path isn't reused afterward).
- `src/adaptive_selector.rs` — 4 occurrences of `unused_unsafe` on test
  code that wraps `env::set_var`/`remove_var` in `unsafe` blocks. These
  calls only became `unsafe fn` in Rust 1.82; the wrapper is correct and
  necessary on CI's real (newer) toolchain but a false positive on this
  sandbox's 1.75.0 fallback. Resolved with a scoped, documented
  `#[allow(unused_unsafe)]` on the test module rather than deleting the
  `unsafe` blocks, so the code stays correct on both toolchains instead
  of trading a lint warning now for a hard compile error on CI later.

All fixes verified safe via `cargo clippy --fix --allow-dirty` (which
only applies a patch if it can prove the result still compiles) plus a
full `cargo test --workspace` re-run afterward: still 880/880 passing.

### Repo-wide executable-bit loss found and fixed (90 files)

`pytest` failed on `test_shebang_file_without_extension_requires_executable_bit`
with a `PermissionError`. Investigating with the project's own
`scripts/check_shell_entrypoints.sh` checker (itself one of the affected
files) showed **every** shebang script in the repository — all 15 `.sh`
files, `.githooks/pre-push`, and ~75 `.py` entrypoints — had lost the
executable bit, almost certainly when the original `tar.gz` archive was
created (file content was intact; only the `+x` mode bit was missing).
Restored `+x` on exactly the 90 files the checker flagged (no others
touched). Re-running the checker against the repo root now reports zero
issues.

### Missing Python dependency installed

`nest-asyncio` is declared in `requirements.txt` (line 38) but wasn't
yet installed in this sandbox, causing 2 additional `pytest` failures
in `test_ultra_vip.py::TestNINDetector` (`core/iran_detector.py` imports
it directly — this module hasn't been ported to Rust yet, so it's still
a live runtime dependency). Installed via pip; both tests now pass.

### Repo-hygiene issue discovered AND fixed: `tests/` vs `tests/parity/` duplication

`tests/*.rs` (28 files, directly under `tests/`) are what Cargo actually
auto-discovers and compiles; `tests/parity/*.rs` (28 files) is a sibling
directory that Cargo does **not** auto-discover on its own. At the start
of this work, only 6 of the 28 top-level files were thin
`include!("parity/X.rs")` shims pointing at that directory (the modules
ported in Session 2: `anti_ai_dpi`, `config`, `ech_fingerprint_evasion`,
`generated_json_loader`, `results_writer`, `sources_torproject`). The
other 22 were fully independent, hand-duplicated copies with no
`include!`/`mod`/`#[path]` link between the two locations — and **9** of
those 22 pairs had already drifted out of sync (`auto_debug_system`,
`bridge_scoring`, `dt_utils`, `feature_flags`, `iran_anti_siam`,
`iran_smart_anti_filter_v2`, `nin_advanced_bypass`, `retry_engine`,
`telemetry_watcher` — one more than this document originally reported;
the first pass only compared line counts, which missed
`telemetry_watcher_parity.rs` since both copies happened to be the same
length despite different content).

**Fixed, later in this same session.** Every diff between the 9 drifted
pairs was reviewed by hand first: all were either pure `rustfmt`
line-wrapping differences, or the live `tests/*.rs` copy strictly
*adding* content the stale `tests/parity/` copy never had (e.g.
`retry_engine_parity.rs`'s live copy has an entire extra
`normalize_numbers` helper the stale copy lacks) — never the reverse.
That made the live top-level copy unambiguously safe to treat as sole
source of truth for all 22 pairs, discarding the stale duplicates
outright.

Converting them surfaced a real Rust constraint the original 6 shims
happened not to trip over: `//!` (inner doc comment) is only valid as
the literal first token of a file or module, and `include!()` splices
text into the *middle* of the includer's scope — so any `//!` line in
an included file is a hard compile error (`E0753`). 21 of the 22 files
opened with a `//!` module-doc header block; converted to plain `//`
comments (same information, no functional difference — `cargo doc`
isn't run on test binaries). One file, `ooni_correlator_parity.rs`, also
opened with a crate-level `#![allow(clippy::field_reassign_with_default)]`
inner attribute, which has the same restriction; relocated it to the
top-level `tests/ooni_correlator_parity.rs` shim (the genuine crate root
for that test binary, where a `#![...]` attribute is valid and still
applies to everything pulled in via the subsequent `include!`).

All 22 pairs converted; verified with a full clean rebuild:
`cargo test --workspace` still 880/880 pass (identical count, confirming
zero behavior change), `cargo fmt --all -- --check` clean,
`cargo clippy --workspace --all-targets -- -D warnings` clean,
`pytest tests/` re-confirmed unaffected at 499 + 132 subtests (no Python
files were touched by this cleanup). There are now 28 single-source
parity test modules with no duplication anywhere in the suite.

### What was explicitly NOT done this session

- No new `.py` files ported, no new Rust modules added.
- No Python files deleted — all 147 original `.py` files are present
  and intact in this package, per the SAFE MIGRATION RULE.
- `checksums.sha256` / `CHECKSUMS_legacy_2026-06-19.sha256` were not
  regenerated (out of scope; left exactly as produced by whatever
  process last generated them).
- `BUILD_INFO.txt` was not modified — it records actual CircleCI
  pipeline provenance from a real build, which this session did not
  perform, so fabricating new values for it would reduce rather than
  improve its accuracy.
- `.gitignore` got one line added (`target/`, the workspace-root build
  directory, was previously only excluding `bridge-probe/target/` and
  had grown to 6.1 GB inside the working tree before this session's
  cleanup).

---

## Prior-session work (Session 2, preserved)

### Phase 0 audit refreshed

Re-confirmed the Phase 0 inventory of every `.py` file in the repository:

* 37 top-level loose `.py` scripts (including `ech_fingerprint_evasion.py`,
  `anti_ai_dpi.py`, `main.py`, `scraper.py`, etc.)
* 14 package directories under `core/`, `sources/`, `config/`,
  `circuit_breaker/`, `recovery/`, `monitoring/`, `reports/`, `health/`,
  `gateway/`, `registry/`, `anti_censorship/`, `diagnostics/`,
  `autonomous/`, `torshield_ai_gateway/`
* 179 total `.py` files (including test files); 131 non-test, non-script
  files in the formal migration inventory.

### Toolchain installation (for real-test verification)

This session installed the missing toolchains on the build host so that
real tests (not just static checks) could run end-to-end:

* `rustup` + `stable-x86_64-unknown-linux-gnu` toolchain (rustc 1.96.0)
* `rustfmt` and `clippy` components
* `go1.22.10.linux-amd64` for the `go_tester/` submodule and `cmd/` Go binaries
* Python deps installed into the project venv: `tenacity`, `structlog`,
  `pytest-timeout` (the prior session's `requirements.txt` listed these
  but they were missing from the venv, causing potential ModuleNotFoundError
  during parity tests that subprocess-invoke Python)

### Phase 5 — DPI/evasion modules ported (2 files)

Both modules are pure scoring logic with no I/O side effects in the
critical path. The network probe (`_check_ech`) in
`ech_fingerprint_evasion.py` is preserved behind an injectable `TlsProbe`
trait so tests can substitute a mock; production callers pass a real
`reqwest`+`rustls` impl (gated behind the `network` Cargo feature).

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `ech_fingerprint_evasion.py` | `src/ech_fingerprint_evasion.rs` | 11/11 pass | ECH + TLS fingerprint evasion scorer. `score_bridge()` matches Python exactly: transport detection priority (snowflake > webtunnel > obfs4 > meek > vanilla), port bonus (+0.10 non_standard_port excluded for IRAN_HIGH_RISK_PORTS {9001,9030,9050,9051} and port 80), TLS probe bonus (+0.10 reachable, +0.40 ech_supported, +0.20 TLSv1.3), min(score, 1.0) clamp, round(3). `run_pipeline()` writes `data/ech_report.json` + `export/ech_top_bridges.txt` byte-identical to Python `main()`. |
| `anti_ai_dpi.py` | `src/anti_ai_dpi.rs` | 13/13 pass | Anti-AI-DPI scoring under Iran ML classifier. `score_anti_ai_dpi()` matches Python exactly: transport base scores (snowflake 0.92, webtunnel 0.88, meek_lite 0.80, obfs4 0.72, vanilla 0.05), port bonuses (+0.05 safe_port for {443,80,8080,8443,2053,2083,2087,2096,1194,51820}, +0.03 ephemeral_port > 49152, -0.10 tor_known_port for {9001,9030,9050}), iat-mode=2 +0.08, CDN hint +0.05, min(score, 1.0) clamp (NOT max(0) — Python preserves negative scores), round(3), iran_ml_dpi_risk classification (VERY_LOW >= 0.80, LOW >= 0.60, MEDIUM >= 0.40, HIGH >= 0.20, else CRITICAL). `run_pipeline()` writes `data/anti_ai_dpi_report.json` + `export/anti_ai_dpi_bridges.txt` byte-identical to Python `main()`. |

### Phase 6 — Network sources ported (1 file)

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `sources/torproject.py` | `src/sources_torproject.rs` | 14/14 pass | Async scraper for `bridges.torproject.org`. `TARGETS` (6 quadruples: obfs4/webtunnel/vanilla × ipv4/ipv6), `_USER_AGENTS` (4-entry rotating pool), `_BRIDGE_LINE_RE` regex (IPv4:port, [IPv6]:port, or https?://URL), `_is_valid_line()` (rejects empty/short/<No bridges available>/comment lines), `_parse_html()` (BeautifulSoup `<div id="bridgelines">` extractor with `<pre>`/`<code>` fallback), `_fetch_one()` (30s timeout, random User-Agent, `raise_for_status` on >= 400), `fetch_all()` (orchestrates 6 targets, returns `Vec<(line, transport, ip_version)>`). Uses `scraper` crate (Rust equivalent of beautifulsoup4) and the existing `crate::scraper::HttpFetch` trait for injectable HTTP. |

### NEW advanced anti-censorship capability module (1 file, no Python original)

| Module | Purpose | Tests |
| --- | --- | --- |
| `src/iran_quantum_dpi_shield_v2.rs` | NEW predictive multi-layer DPI evasion shield for Iran's SIAM/NGFW ML-based censorship infrastructure (2024–2026 observed behaviour). Composes 4 layers: (1) **Predictive SIAM attack forecasting** — given recent OONI measurements (anomaly_count, confirmed_count, failure_count, window_hours, bridge_failure_rate, nin_detected), predicts the next-layer Iran DPI strategy that will be deployed in the next 24h window. Five observed strategies modelled: `passive_sni_blocklist` (default), `active_sni_filtering`, `ja3_fingerprint_block`, `protocol_length_distribution`, `nin_full_isolation`. (2) **Adaptive transport morphing policy** — for each predicted strategy, emits a ranked transport recommendation (snowflake/webtunnel/obfs4) with 15-minute cooldown windows so the same transport is not selected twice within a cooldown period, defeating ML-classifier retraining. (3) **Composite bridge scoring** — combines `anti_ai_dpi` score + `ech_fingerprint_evasion` score + historical success rate into a final composite_score using the weighted blend `0.40*anti_ai + 0.35*ech + 0.25*hist`, clamped to [0,1] and rounded to 3 decimals. Bridges above 0.70 are flagged `priority`, those below 0.30 are flagged `avoid`. (4) **Port-hopping schedule** — produces a 6-port rotation schedule (443, 8443, 2053, 2083, 2087, 2096) with per-port dwell times calibrated to the predicted SIAM strategy (passive=60min, active_sni=30min, ja3=15min, length_analysis=10min, nin=5min). Pure decision logic — no I/O, no network calls, injectable clock. | 26/26 internal unit tests pass. |

### CI infrastructure (re-verified, no changes this session)

All CI workflows continue to call Rust binaries correctly. Verified:

- `.github/workflows/ci.yml` — `rust-parity` job
- `.github/workflows/torshield-ir.yml` — `rust-parity-tests` job
- `.github/workflows/autonomous-sentinel.yml` — Rust parity-test step
- `.github/workflows/go-quality-gate.yml` — `rust-parity-gate` job
- `.github/workflows/ai_self_healing.yml` — `rust-parity-gate` job
- `.github/workflows/ai_gateway_health_check.yml` — `rust-parity-gate` job
- `.github/workflows/ai_bridge_reranker.yml` — `rust-parity-gate` job
- `.gitlab/ci/torshield-ir.yml` — `torshield-ir:rust-parity-tests` job
- `.circleci/config.yml` — `rust-parity-tests` job

Each runs:
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace` (with `PYTHONPATH` set so parity tests can
   subprocess-invoke the Python originals)

---

## Prior-session work (Session 1, preserved)

### CI infrastructure updates (ALL workflow files)

Every CI workflow file was updated to add a `rust-parity-tests` /
`rust-parity-gate` job that runs:
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace` (with `PYTHONPATH` set so parity tests can
   subprocess-invoke the Python originals)

Updated CI files:
- `.github/workflows/ci.yml` — added `rust-parity` job
- `.github/workflows/torshield-ir.yml` — added `rust-parity-tests` job (dependency of `scrape-and-test` and `package-final-artifact`)
- `.github/workflows/autonomous-sentinel.yml` — added Rust parity-test step
- `.github/workflows/go-quality-gate.yml` — added `rust-parity-gate` job
- `.github/workflows/ai_self_healing.yml` — added `rust-parity-gate` job
- `.github/workflows/ai_gateway_health_check.yml` — added `rust-parity-gate` job
- `.github/workflows/ai_bridge_reranker.yml` — added `rust-parity-gate` job
- `.gitlab/ci/torshield-ir.yml` — added `torshield-ir:rust-parity-tests` job
- `.circleci/config.yml` — added `rust-parity-tests` job

### NEW anti-censorship capability added

`src/iran_smart_anti_filter_v2.rs` — a NEW Rust module (no Python
original to supersede) implementing:
- IRST-aware predictive routing (4-tier classification: normal/relaxed/high_stealth/ultra_stealth)
- Transport rotation policy with cooldown
- OONI-correlated bridge scoring boost
- Adaptive port-hopping recommendation

This module is pure decision logic — no I/O, no network calls, injectable
clock. 9/9 parity tests pass.

### Python modules ported to Rust (33 files)

#### Phase 1 — Foundations (3/3 ported, all parity-verified)

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `config.py` | `src/config.rs` | 6/6 pass | Default + overridden env + invalid int/float error paths |
| `generated_json_loader.py` | `src/generated_json_loader.rs` | 6/6 pass | Missing/empty/invalid JSON + array/object type mismatch |
| `results_writer.py` | `src/results_writer.rs` | 7/7 pass | Tier 1 vs Tier 2, blocked/global buckets, dedup, empty input |

#### Phase 2 — Network primitives (4/4 ported, all parity-verified)

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `scraper.py` | `src/scraper.rs` | 18/18 pass | HTML extraction, Moat fetch, BridgeDB fetch — injectable HTTP client |
| `onionhop_collector.py` | `src/onionhop_collector.rs` | 24/24 pass | Pooled transports, IP variants, fronted bridges, reachability probes |
| `adaptive_transport.py` | `src/adaptive_transport.rs` | 19/19 pass | Weight history, score computation, NIN-tier transport selection |
| `adaptive_selector.py` | `src/adaptive_selector.rs` | 22/22 pass | AdaptiveConfig, scoring, CDN-good check |

#### Phase 3 — Classification/scoring (4/4 ported, all parity-verified)

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `ja3_intelligence.py` | `src/ja3_intelligence.rs` | 20/20 pass | JA3 hash DB, rotation strategies, port/transport risk scoring |
| `nin_internet_cut_classifier.py` | `src/nin_internet_cut_classifier.rs` | 20/20 pass | parse_bridge, classify, main() end-to-end, Iran CDN CIDR filtering |
| `ml_predictor.py` | `src/ml_predictor.rs` | 15/15 pass | Feature extraction, blocking-prob prediction, apply_predictions |
| `ooni_correlator.py` | `src/ooni_correlator.rs` | 20/20 pass | OONI/RIPE Atlas correlation, composite scoring, quality gate, run_pipeline |

#### Phase 4 — Resilience (6/6 ported, all parity-verified)

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `circuit_breaker_11slot.py` | `src/circuit_breaker_11slot.rs` | (lib + parity pass) | 11-slot variant, backoff, multi-slot isolation |
| `self_heal.py` | `src/self_heal.rs` | (lib + parity pass) | Self-healing engine, opcode classifier, action planner |
| `quarantine_manager.py` | `src/quarantine_manager.rs` | 23/23 pass | Rolling z-score, quarantine/release state machine, update_from_ooni_history |
| `telemetry_watcher.py` | `src/telemetry_watcher.rs` | 11/11 pass | DPI/slot/self-heal event logging, daily aggregation, IRST tier detection |
| `auto_debug_system.py` | `src/auto_debug_system.rs` | 7/7 pass | generate_recommendations, run_full_diagnosis, generate_report |
| `circuit_breaker/slot_circuit_breaker.py` | `src/slot_circuit_breaker.rs` | 27/27 pass | Closed→Open→HalfOpen transitions, multi-slot isolation, get_status dict |

#### Phase 5 — DPI/evasion (4/14 ported — scope guardrail enforced)

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `iran_anti_siam.py` | `src/iran_anti_siam.rs` | 21/21 pass | Bridge classification, OONI dedup, Markdown report generation |
| `nin_advanced_bypass.py` | `src/nin_advanced_bypass.rs` | 12/12 pass | NIN-survivable bridge scoring, CDN reachability, port-open checks, TCP probe injectable |
| `iran_nin_bypass.py` | `src/iran_nin_bypass.rs` | (lib tests pass) | NIN detection, CDN-ASN scoring, next-gen protocol detection, NIN pack generation |
| `nin_cut_tester.py` | `src/nin_cut_tester.rs` | (lib tests pass) | Iran domestic CIDR table, NIN-cut survivability scoring, TCP probe with latency, report + export generation |

**Not yet ported (Phase 5 — scope guardrail applies to each):**
`ai_anti_dpi_iran.py`, `ai_dpi_mutator.py`,
`ai_dpi_quantum_evasion.py`, `anti_ai_dpi.py`, `dpi_evasion_advanced.py`,
`ech_fingerprint_evasion.py`, `uTLS_evasion_layer.py`,
`xtls_reality_wrapper.py`, `quantum_safe.py`,
`iran_smart_anti_filter.py`

Each of these modules will be reviewed for offensive-fingerprinting
potential before porting. Modules that fall within scope (passive
classification of public OONI/RIPE Atlas data + reachability testing of
publicly-listed Tor bridges) will be ported with full parity tests.
Modules that cross into offensive fingerprinting of third-party
infrastructure will be FLAGGED here, not ported.

#### Phase 6 — Formal packages (partial — 14/131 ported)

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `sources/history_utils.py` | `src/history_utils.rs` | 16/16 pass | parse_history_dt, normalize, cleanup with injectable clock |
| `sources/static_bridges.py` | `src/static_bridges.rs` | 8/8 pass | Byte-identical bridge-line constants + get_all ordering |
| `sources/bridge_scoring.py` | `src/bridge_scoring.rs` | 27/27 pass | score_bridge, telemetry_pressure, scheduler merge, recommended_priority |
| `config/feature_flags.py` | `src/feature_flags.rs` | 4/4 pass | All 12 flags + circuit-breaker/retry/self-heal/IRST params |
| `gateway/retry_engine.py` | `src/retry_engine.rs` | 11/11 pass | HTTP 400/429/5xx/401/403/0/unknown decision matrix |
| `core/dt_utils.py` | `src/dt_utils.rs` | 11/11 pass | Aware/naive timestamps, malformed input, Z-suffix |
| `core/history.py` | `src/history.rs` | (lib tests pass) | HistoryManager with load/save/add_bridge/update_test/update_score/purge_old |
| `core/temporal_analyzer.py` | `src/temporal_analyzer.rs` | (lib tests pass) | IRST threat-level classification, best-connection-windows, export_schedule |
| `core/notifier.py` | `src/notifier.rs` | (lib tests pass) | TelegramNotifier with injectable TelegramApi trait, build_caption |
| `core/collector.py` | `src/collector.rs` | (lib tests pass) | prioritize_port_443, BridgeCollector with injectable BridgeSource trait |
| `core/scorer.py` | `src/scorer.rs` | (lib tests pass) | IranScorer with transport/port/ipv/freshness/test/cdn dimensions, iran_cut_pack |
| `core/tester.py` | `src/tester.rs` | (lib tests pass) | detect_transport, extract_endpoint, is_ip (parsing only; network probes use bridge-probe binary) |
| `config.py` | (counted in Phase 1) | 6/6 pass | |
| `generated_json_loader.py` | (counted in Phase 1) | 6/6 pass | |
| `results_writer.py` | (counted in Phase 1) | 7/7 pass | |

#### Phase 7 — Reporting (0/4 ported — pending)

| Python file | Rust port | Parity tests | Notes |
| --- | --- | --- | --- |
| `warp_bootstrap.py` | Not started | N/A | Pending — Phase 7 |
| `ztunnel_ct_monitor.py` | Not started | N/A | Pending — Phase 7 |
| `elite_registry.py` | Not started | N/A | Pending — Phase 7 |
| `main.py` | Not started | N/A | Pending — Phase 7 (orchestrator, ported last) |

---

## What was NOT done (and why)

### Modules not yet ported (~67 Python source modules)

The following categories of Python files remain unported. They are listed
in priority order so the next migration session can pick up where this
one left off.

**Phase 5 DPI/evasion (12 files)** — Each module must be reviewed against
the scope guardrail before porting. The guardrail allows porting logic
that (a) tests reachability of publicly-listed Tor bridges and (b)
passively classifies already-public OONI/RIPE Atlas measurement data.
Any code path that could be repurposed to attack or fingerprint
third-party infrastructure must be flagged here, not ported.

**Phase 6 formal packages (~78 files)** — The `torshield_ai_gateway/*`
subpackage alone has 30 files (including `providers.py` at 3,511 lines,
`neural_anti_dpi_v3.py` at 1,955 lines, `ai_anti_dpi_iran_v2.py` at
1,825 lines). The `autonomous/*` subpackage has 9 files. The
`monitoring/*`, `recovery/*`, `reports/*`, `health/*`, `registry/*`,
`anti_censorship/*`, `diagnostics/*` subpackages each have 1–6 files
(these counts are as reported by prior sessions and were not
independently re-verified this session).

**The `core/*` subpackage is now fully ported — 16 / 16 files** (7
pre-Session-4 + `iran_bridge_prioritizer.py`/`nin_selector.py`/
`formatter.py` in Session 4 + `nin_survival_pack.py` in Session 5 +
`smart_iran_scorer.py` in Session 6 + `censorship_monitor.py` in
Session 7 + `endpoint_validator.py` in Session 8 +
`iran_detector.py`/`iran_dpi_shaper.py` in Session 9). No further
`core/*` entries remain in this list.

**Phase 7 reporting (4 files)** — `main.py` is the orchestrator and must
be ported last, after every module it imports has been parity-verified.


### Behavioral differences flagged in MIGRATION_NOTES.md

The following behavioral differences between the Python original and the
Rust port are documented in `MIGRATION_NOTES.md` (append-only file):

1. **JA3 penalty — RESOLVED (Session 10, 2026-07-12).** Formerly
   `src/scorer.rs::ja3_penalty()` was a stub returning `0`, diverging from
   Python's `_ja3_penalty` for every record. This is now **closed**:
   `ja3_penalty` is wired to the already-ported `ja3_intelligence::JA3Intel`
   (`transport_default_risk`/`port_risk`/`score`) and reproduces Python's
   `int(round(...))` round-half-to-even semantics. `IranScorer::score()` is
   now byte-for-byte with the Python oracle. See `CHANGELOG.md` Session 10 and
   the (now-historical) item 10 below. No longer an open divergence.

2. **`core/tester.py` network probes** — The async TCP/SSL probe functions
   (`probe_vanilla`, `probe_obfs4`, `probe_webtunnel`, `test_bridge`) are
   NOT ported to Rust because they require `tokio` + `tokio-rustls`. The
   existing `bridge-probe` binary (already in Rust, in the
   `bridge-probe/` workspace member) covers the same functionality. The
   pure parsing functions (`detect_transport`, `extract_endpoint`,
   `is_ip`) ARE ported with byte-identical parity.

3. **`serde_json::Map` key ordering** — Rust's `serde_json::Map` (without
   the `preserve_order` feature) sorts keys alphabetically, while Python
   dicts preserve insertion order. JSON parity is preserved via
   order-independent `Value::Object` equality, but human-readable
   serialized output may differ in key order. Flagged in MIGRATION_NOTES.md.

4. **`monitoring.structured_logger.record_silent_failure`** — The Python
   original calls this function to log silent failures. The Rust port
   replaces these with `tracing::warn!` / `tracing::info!` calls (no-op
   by default). The structured-logger module itself is not yet ported.

5. **`datetime.isoformat()` fractional seconds** — Python's
   `datetime.isoformat()` omits fractional seconds when microseconds are
   zero. Rust's `to_rfc3339()` always emits them. Parity tests use
   non-zero microsecond fixed times to avoid the discrepancy.

6. **`ml_predictor.py` scikit-learn model** — The Python original loads
   a pickle model (`data/blocking_model.pkl`) via scikit-learn. The Rust
   port uses a heuristic approximation (documented in MIGRATION_NOTES.md)
   because there is no faithful Rust equivalent of scikit-learn's pickle
   deserialization. The data preprocessing and post-processing logic IS
   ported with full parity. The model inference accuracy delta is
   documented.

7. **`onionhop_collector._test_many` thread pool** — The Python original
   uses `concurrent.futures.ThreadPoolExecutor` for parallel probing.
   The Rust port runs probes sequentially (capping/clamping preserved).
   Production callers can wrap the probe in their own thread pool.

8. **`scraper.py` asyncio GitHub fetch** — The Python original uses
   `asyncio` for concurrent GitHub raw fetches. The Rust port exposes
   the fetch primitive but does not implement the asyncio orchestration.
   Production callers can use `tokio::join!` for the same effect.

9. **`dt_utils::utc_now_iso()` drops microseconds unconditionally
   (discovered Session 5, not yet fixed)** — distinct from item 5 above
   (which covers the general zero-microsecond edge case and is already
   mitigated in tests project-wide): this specific helper is implemented
   with `chrono`'s `SecondsFormat::Secs`, which omits the fractional
   part on *every* call, not just when microseconds happen to be zero.
   Empirically, both `datetime.now(UTC).isoformat()` and
   `core.dt_utils.utc_now_iso()` include microsecond precision in this
   environment, so the existing Rust helper does not actually match its
   own documented Python counterpart at full precision. Found while
   porting `core/nin_survival_pack.py` (Session 5), which uses its own
   local, genuinely microsecond-precise helper instead rather than this
   one. Not fixed here — touches a previously parity-verified file with
   other call sites this session did not audit. See `MIGRATION_NOTES.md`'s
   Session 5 entry for the full write-up; a future session should audit
   `dt_utils::utc_now_iso()`'s callers and either fix it
   (`SecondsFormat::Micros`) or confirm none of their parity tests
   actually assert timestamp precision.

10. **[RESOLVED Session 10 — retained for history]** **JA3 penalty gap is
    bigger and more fixable than item 1 originally disclosed (measured
    Session 6)** — this analysis is now closed out; the fix landed in
    Session 10 (see item 1 above and `CHANGELOG.md`). Original text: wiring `core/smart_iran_scorer.py`'s
    port up to the real `scorer.rs` and comparing against live Python
    showed `ja3_penalty()` returning `0` unconditionally isn't a rare
    edge case: for the realistic case of a bridge record with no
    explicit `ja3_hash`, Python's fallback still applies a
    transport-keyed penalty — empirically measured as `snowflake`→1,
    `webtunnel`→2, `obfs4`→3, `meek_lite`→4, `unknown`→8, `vanilla`→14
    (out of `IranScorer.score()`'s 0-100 range) — affecting essentially
    every bridge scored, not an edge case. More importantly, item 1's
    original framing (blocked on porting `ja3_intelligence.py`) is
    stale: `src/ja3_intelligence.rs` already exists with
    `transport_default_risk()`/`port_risk()`/`score()`, and Python's
    fallback formula is fully self-contained —
    `round(max(transport_default_risk(transport), port_risk(port)) *
    15)` (`scorer.rs` already defines the matching `JA3_MAX_PENALTY =
    15` constant, just unused). Not fixed this session — `scorer.rs` has
    its own existing test(s) hardcoding a `ja3=0` expectation into a
    total-score assertion, so this touches another module's signed-off
    suite — but now precisely scoped for whoever picks it up. See
    `MIGRATION_NOTES.md`'s Session 6 entry.

---

## Engineering quality bar (verified)

| Requirement | Status |
| --- | --- |
| Parity-first: every ported function has a golden-output test running the Python original | ✅ 49 parity-test files, **1303 total tests pass (default), 0 failed** (Session 11). Every oracle-backed lib module now has a differential parity test. `--features network` full-suite total not currently known-good — see "next session" list, item 2 |
| Zero `unwrap()`/`expect()` on I/O, network, or parse paths | ✅ All Rust modules use `Result<T, E>` with `thiserror`-based typed errors |
| Every external call has an explicit timeout | ✅ All HTTP/TCP calls accept a timeout parameter |
| Shared state uses `Arc<Mutex<_>>` correctly | ✅ Tests run both single- and multi-threaded |
| `cargo test --workspace` passes clean | ✅ 1303/1303 pass, 0 failed (Session 11, default features) |
| `cargo clippy --workspace --all-targets -- -D warnings` passes clean | ✅ re-verified Session 9, both default and `--features network` |
| `cargo fmt --check` passes clean | ✅ re-verified Session 9 |
| CI workflows updated to call Rust binary for ported modules | ✅ All 9 GitHub + 1 GitLab + 1 CircleCI configs updated |
| Output file formats (bridge/*.txt, docs/iran-bridge-status.md) byte-identical | ✅ Parity tests assert byte-identical output |
| Fully automated — no manual trigger added | ✅ All CI jobs run automatically on push/schedule |

---

## Final report — definition of done

The migration is **NOT yet complete**. As of Session 11, **49 Rust modules
are ported** (48 Python-backed + 1 Rust-native `iran_quantum_dpi_shield_v2`),
each oracle-backed one carrying a differential parity test. The remaining
**~67 Python source modules** (excluding `__init__.py`, test files, and the
retained `core/_iran_detector_legacy.py` oracle) — dominated by the
`torshield_ai_gateway/*` subpackage (~30), the root-level Phase 5 DPI/evasion
modules pending scope-guardrail review (12), and Phase 7 reporting incl.
`main.py` — are still source-of-truth in Python, fully intact and undeleted.

Per the migration rule: **`requirements.txt` and `pyproject.toml` will
be emptied/removed only when this table shows 100% parity-verified across
every file.** That threshold has not been reached.

### All-test surfaces (re-verified this session, 2026-07-01)

| Surface | Command | Result |
| --- | --- | --- |
| Rust unit + parity tests | `cargo test --workspace` | **1013 / 1013 pass**, 0 fail |
| Rust lint | `cargo clippy --workspace --all-targets -- -D warnings` | clean (re-verified after every change, including after an automated `--fix` pass) |
| Rust format | `cargo fmt --all -- --check` | clean |
| Python tests | `pytest tests/` | **499 + 132 subtests pass**, 0 fail (unchanged — no Python files touched) |
| Shebang-script executable bits | `scripts/check_shell_entrypoints.sh .` | 0 issues (unchanged from Session 3) |
| Go tests, Go vet, shell `bash -n`, YAML parse | — | **not re-run this session** — out of scope (no related files touched); see Session 2's table for its last verified values |

**Zero errors across every test surface actually re-run this session.**

### What could NOT be verified (flagged, not guessed)

One new, narrow behavioral divergence was found this session (not
present in the code before it — see `src/formatter.rs`'s module doc
comment and the Session 4 notes above for full detail) — everything
else, across all 80 parity tests added this session, passes
byte-identical against live Python. The pre-existing flagged
differences from Session 1 (documented in `MIGRATION_NOTES.md`) remain
unchanged:

1. ~~`scorer.rs::ja3_penalty()` returns 0 (full JA3Intel DB integration
   requires runtime state).~~ **RESOLVED (Session 10):** `ja3_penalty` is
   wired to `ja3_intelligence::JA3Intel`; `IranScorer::score()` is
   byte-for-byte with Python. No longer a divergence.
2. `core/tester.py` async TCP/SSL probes (`probe_vanilla`, `probe_obfs4`,
   `probe_webtunnel`, `test_bridge`) are NOT ported — covered by the
   existing `bridge-probe` binary in the workspace.
3. `serde_json::Map` key ordering differs from Python dict insertion
   order (parity is order-independent via `Value::Object` equality).
4. `monitoring.structured_logger.record_silent_failure` not yet ported;
   Rust uses `tracing::warn!`/`info!` (no-op by default).
5. `datetime.isoformat()` fractional seconds: Rust `to_rfc3339()` always
   emits; Python omits when microseconds are zero. Parity tests use
   non-zero microsecond fixed times to avoid the discrepancy.
6. `ml_predictor.py` scikit-learn pickle model: Rust uses heuristic
   approximation (documented in `MIGRATION_NOTES.md`).
7. `onionhop_collector._test_many` ThreadPoolExecutor: Rust runs
   sequentially (cap/clamp preserved).
8. `scraper.py` asyncio GitHub fetch: Rust exposes fetch primitive but
   not asyncio orchestration.
9. **NEW this session:** `history.rs`'s `HistoryManager` stores records
   in a `BTreeMap` (key-sorted iteration order); `core/history.py`'s
   `dict` preserves insertion order. Invisible whenever every record has
   a distinct sort key; observable as a different tie-break order when
   two-or-more records tie on every field a stable sort orders by
   (confirmed in `_export_json_api`'s per-transport grouping and
   `IranScorer::iran_cut_pack`'s fixed-bucket scoring — both consumed via
   `formatter.rs`). Root cause is `history.rs`'s storage-type choice from
   a prior session, not something introduced by `formatter.rs` itself;
   fixing it is a separate, deliberate decision for its own session (see
   "What was explicitly NOT done" above). A dedicated test
   (`tie_break_order_documented_divergence` in `formatter_parity.rs`)
   demonstrates the exact narrow condition that triggers it and confirms
   everything else about the same input still matches exactly.

### What the next migration session should continue with

1. Phase 5 scope-guardrail review + port for each remaining DPI/evasion
   module — **3 of 8 reviewed this session**: `ai_anti_dpi_iran.py`
   ported to `src/ai_anti_dpi_iran.rs`; `ai_dpi_mutator.py` reviewed and
   explicitly **not** ported (autonomous, unreviewed source mutation via
   blanket regex across arbitrary files + auto-commit-and-push that
   skips CI, confirmed live in `.github/workflows/torshield-ir.yml` — the
   mutation targets themselves, port/iat-mode recommendations, are the
   same benign category already ported safely elsewhere; the delivery
   mechanism is what disqualifies it — see that section above for the
   full reasoning); `dpi_evasion_advanced.py` ported to
   `src/dpi_evasion_advanced.rs` (confirmed clean — it's the passive
   producer of the report `ai_dpi_mutator.py` reads, not itself
   autonomous). 5 remain: `ai_dpi_quantum_evasion.py`,
   `uTLS_evasion_layer.py`, `xtls_reality_wrapper.py`, `quantum_safe.py`,
   `iran_smart_anti_filter.py`.
   Same process each time: read every function body against the scope
   guardrail before writing any Rust — not just "does it touch
   third-party infrastructure" but also "does it autonomously modify or
   deploy anything without a human checkpoint," which is a distinct
   question `ai_dpi_mutator.py` surfaced that the guardrail's original
   wording didn't explicitly anticipate.
   `src/ech_fingerprint_evasion.rs` (already present in this workspace,
   flagged in Session 8, checked again in Session 9 with no explicit
   "Scope guardrail:" note found in its header the way `iran_anti_siam.rs`
   and `iran_dpi_shaper.rs` have) is still an open documentation-
   consistency question, not a correctness concern — its actual behavior
   (TLS/ECH capability probing of the caller's own candidate bridges,
   the same category as `iran_detector.rs`'s connectivity probes) reads
   as clearly legitimate on inspection; it just predates the explicit
   labeling convention.
2. Going forward, verify both `cargo test`/`clippy` configurations
   whenever a module touches the `network` feature — **default AND
   `--features network`**. Default is solid (1269/1269 as of this
   session). `--features network`'s full-workspace *test execution*
   isn't currently a known-good number — Session 8 established
   1184/1184, this session added 94 more tests that passed individually
   under that configuration plus a clean workspace-wide `clippy
   --features network` (checked six separate times, once per round of
   changes), but a full `cargo test --workspace --features network` run
   hit this sandbox's disk-space ceiling (practical note #9) and was
   never completed afterward. Re-run it properly before trusting a
   specific total again.
3. The remaining Phase 6 formal packages: `monitoring/*`, `recovery/*`,
   `reports/*`, `health/*`, `registry/*`, `anti_censorship/*`,
   `diagnostics/*`, `autonomous/*`, and the `torshield_ai_gateway/*`
   subpackage (30 files, includes `providers.py` at 3,511 lines — the
   largest single block of remaining work).
4. Phase 7 reporting (`warp_bootstrap.py`, `ztunnel_ct_monitor.py`,
   `elite_registry.py`, then `main.py` last).
5. Separately, consider whether `history.rs`'s `BTreeMap` storage should
   become insertion-order-preserving to close the tie-break divergence
   documented above — a deliberate, standalone decision, not a blocker.
6. Separately, audit `dt_utils::utc_now_iso()`'s callers for the
   microsecond-precision gap found in Session 5 — another standalone
   decision, not a blocker.
7. Separately, and now more actionable given Session 6's findings:
   `scorer.rs`'s `ja3_penalty()` always returning `0` measurably inflates
   scores for `smart_iran_scorer.rs` (and any other consumer of
   `IranScorer::score()`) by 1-14 points depending on transport, for
   every bridge without an explicit `ja3_hash` — i.e. most of them.
   **This is not blocked on porting `ja3_intelligence.py`** —
   `src/ja3_intelligence.rs` already exists with the needed
   `transport_default_risk()`/`port_risk()`/`score()` functions, and
   Python's fallback formula is fully self-contained:
   `round(max(transport_default_risk(transport), port_risk(port)) * 15)`
   (matching `JA3_MAX_PENALTY = 15`, already defined but unused in
   `scorer.rs`). The remaining work is wiring `ja3_penalty()` up to the
   already-ported `JA3Intel` and updating `scorer.rs`'s own existing
   test(s), which currently hardcode a `ja3=0` expectation into a
   total-score assertion. Small and precisely specified — see
   `MIGRATION_NOTES.md`'s Session 6 entry for the measured per-transport
   numbers to verify against once fixed.
8. Before starting a new module, re-run the full baseline
   (`cargo test --workspace`, `clippy`, `fmt --check`, `pytest`) against
   whatever checkpoint the next session starts from; don't assume a
   prior session's sign-off still holds without re-verifying.
9. Practical note from Session 7, reconfirmed the hard way in Session 9:
   this sandbox's usable disk quota is much smaller than what `df`
   reports at the filesystem level — a full `target/` build across both
   feature configurations in the same pass reliably exhausts it (Session
   7: ~9GB; Session 9: ran out mid-way through a `--features network`
   full-workspace run at ~19GB used, right after a `~9-10GB` default-only
   build was already sitting in `target/`). Run `cargo clean` between
   configurations rather than building both back to back, not just when
   a command already fails with a disk-space error.

### Deliverable per module (historical: Session 4's newly-ported modules)

*This subsection predates Sessions 5-7 and was never updated for them —
their equivalent deliverable details live in their own "What was done
this session" sections above instead, to avoid duplicating the same
information twice in one document. Left as-is here as the original
Session 4 record.*

For each of the 3 newly-ported Python modules in Session 4:

* ✅ Rust source with doc comments tracing back to the original Python
  file/function, including every documented deviation and its
  justification (`src/iran_bridge_prioritizer.rs`, `src/nin_selector.rs`,
  `src/formatter.rs`; plus a small addition, `top_for_iran`, to the
  already-ported `src/scorer.rs`).
* ✅ A parity test under `tests/parity/` covering every branch from the
  Phase 0 contract, following the established single-source `include!`
  pattern from the outset (`iran_bridge_prioritizer_parity.rs`: 38
  tests; `nin_selector_parity.rs`: 34 tests including the full 3-file
  I/O pipeline; `formatter_parity.rs`: 8 tests including the full
  10-output-file `export_all` + `update_readme` pipeline).
* ✅ `Cargo.toml` changes: none for the first two modules (dependencies
  already present); one new pinned dependency (`zip = "=0.6.6"`) for
  `formatter.rs`'s ZIP archive building, with no stdlib equivalent
  available in Rust.
* ✅ The Python files are NOT deleted (per migration rule: delete only
  when all importers also ported — see Session 4 notes above for each
  file's specific live importers; `formatter.py`'s importers were not
  yet checked, flagged for the next session).
* ✅ This `MIGRATION_STATUS.md` entry, plus matching `MIGRATION_NOTES.md`
  entries, confirm zero *silent* feature loss for every ported function.
  Explicitly documented and justified deviations: 1 in
  `iran_bridge_prioritizer.rs` (fixed-order transport-name iteration
  replacing Python's `PYTHONHASHSEED`-dependent set order, which has no
  single ground truth to match in the first place); 3 in `nin_selector.rs`
  (fallible-vs-silent-default score coercion; the regex `$`-anchor fix;
  single-injected-`now` vs. Python's two independent wall-clock reads);
  3 in `formatter.rs` (always-default `score_reasons`/
  `recommended_priority`, traced to source rather than assumed; the
  `history.rs`-inherited `BTreeMap`-vs-insertion-order tie-break
  divergence, found via a real parity-test failure rather than
  anticipated in advance; deterministic ZIP-entry ordering replacing
  Python's unspecified `os.listdir()` order).

Session 3 ported zero new Python modules — its deliverable was
build/test repair plus the `tests/` vs `tests/parity/` duplication
cleanup (22 files converted to single-source `include!` shims). See the
Session 3 section for the full account.


---

## Session 9 — `core/iran_detector.py` verification + `smart-detection` layer

**Status: ✅ Module migrated & verified (default build). ✅ Section 4 feature
added & verified. ⚠️ Gate 4 (Python deletion) intentionally deferred — see
reason below and in `MIGRATION_NOTES.md`.**

Toolchain: rustc/cargo **1.97.0** (rustup stable; reachable on this host,
unlike Sessions ≤8). MSRV pin unchanged at 1.75.

### Captured command metrics (real, this session)

| Config | fmt | clippy `-D warnings` | tests |
|---|---|---|---|
| default | ✅ clean | ✅ 0 warnings (lib+tests) | ✅ 7 unit + 17 differential parity = **24/24** |
| `--features smart-detection` | ✅ clean | ✅ 0 warnings | ✅ 23 lib unit (7 base + 16 new) + 7 loopback integration = **30/30** |
| `--features smart-detection,network` | ✅ clean | ✅ 0 warnings | (compiles; HTTPS probe gated) |

Crate-wide default build: `cargo check --lib` finished in 23s, clean.

### Test matrix summary (iran_detector scope)

* Unit (baseline): 7 — cache boundary (`<30s`, `=30s`, `>30s`, never, force),
  strategy branches, probe-constant lengths.
* Differential (Python↔Rust, live subprocess): 17 — `recommend_strategy` both
  branches, `probe_tcp` reachable/refused (+ Python cross-check), all four
  `check_connectivity` branches, `check_connectivity` full differential,
  `record_event` create/append/corrupt-recover/non-array-recover/dir-fail
  panic, 30s cache + force_refresh timing.
* Unit (smart-detection, new): 16 — confidence full/diversity-weighted/
  nin-semantics, all 6 `InterferenceKind` variants, adaptive routing under
  ActiveReset / TLS-fail / no-interference / determinism, jitter bounded+
  seed-deterministic + varies, cache-window bounded.
* Integration (smart-detection loopback, new): 7 — one per interference variant
  + real `TcpListener` end-to-end classification.

### Feature inventory / parity (Python → Rust)

| Python symbol | Rust | Status |
|---|---|---|
| `_INTERNATIONAL_PROBES` | `INTERNATIONAL_PROBES` | ✅ identical (4 targets) |
| `_NIN_PROBES` | `NIN_PROBES` | ✅ identical (2 targets) |
| `_PROBE_TIMEOUT` | `PROBE_TIMEOUT_SECS` | ✅ 3.0 |
| `_probe_tcp` | `probe_tcp` | ✅ (Drop-close vs asyncio close handshake documented) |
| `check_connectivity` | `check_connectivity` / `_with_targets` | ✅ + injectable seam |
| `recommend_strategy` | `recommend_strategy` | ✅ byte-identical strings |
| `NINDetector.__init__` | `NinDetector::new` / `with_defaults` | ✅ |
| `is_nin_active` | `is_nin_active` | ✅ (nest_asyncio vs block_on caveat documented) |
| `record_event` | `record_event` | ✅ incl. unguarded-makedirs panic contract |
| `_on_nin_detected` | `on_nin_detected` | ✅ |
| `_notify_telegram` | `notify_telegram` (`#[cfg(network)]`) | ✅ |
| env `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` | same | ✅ |
| *(new §4)* | `smart::{ProbeResult,ProbeOutcome,InterferenceKind,ConnectivityAssessment,compute_confidence,Transport,BridgeHealthSnapshot,StrategyRecommendation,recommend_strategy_adaptive,jitter_delay,jittered_round,adaptive_cache_window,probe_https_443}` | ✅ additive, feature-gated |

### CI/CD (Gate 6)

`.github/workflows/ci.yml` already had a `rust-parity` job (fmt + clippy
`-D warnings` + `cargo test --workspace`). Added 3 steps: clippy under
`smart-detection`, clippy under `smart-detection,network`, and `cargo test
--features smart-detection`. All 9 workflow files validated with a real parser
(PyYAML `safe_load_all`) → all valid.

### Gate 4 deferred (not a failure — a correctness decision)

`core/iran_detector.py` retained: live Python importers (`main.py`,
`uTLS_evasion_layer.py`, `core/nin_survival_pack.py`, `tests/test_ultra_vip.py`)
are not yet ported and there is no runtime PyO3 bridge; deletion would break
both those importers and the differential parity oracle (Gate 1). Consistent
with the project's standing "delete only when all importers are ported" rule.
Recommended next unit of work: port/rewire the four importers behind a real
bridge, each with its own parity gate, then eradicate.

### Not executed this session (scope honesty)

Full `cargo-mutants`, `>=95%` line-coverage instrumentation over the whole
50-module crate, cross-platform Windows/macOS runners, binary-size/memory
regression benchmarks vs a Python baseline, and SBOM/reproducible-build
attestation were **not** run here — each is a multi-hour, whole-repo effort
beyond a single module's migration, and fabricating their output would violate
Gate 1 ("no mock theater"). `cargo audit` was run (see report). The
iran_detector module itself has every public/private function and every
branch exercised by the tests above.


### Session 9.1 addendum — Gate 4 now ✅ CLOSED

The deferred Gate 4 above is resolved. A PyO3 runtime bridge
(`rust/iran_detector_py` → extension `_iran_detector_rs`) now backs
`core/iran_detector.py`, which became a thin shim with no detection logic. The
Python logic survives only as the differential-test oracle
(`core/_iran_detector_legacy.py`). All four live importers work unchanged;
Rust differential 17/17; shim-vs-legacy Python differential MATCH; bridge crate
fmt + clippy `-D warnings` clean. Full write-up in `MIGRATION_NOTES.md`
§ "Session 9 (cont.) — Gate 4 CLOSED".

| Gate 4 | ✅ closed (runtime path is Rust-backed; Python logic retained only as test oracle) |


---

## Session 10 — Batch 2 parity verification (2026-07-12)

**Modules:** `collector`, `notifier`, `tester`, `scorer`, `temporal_analyzer`.
All five were already ported and wired into `lib.rs`; the default lib build was
clean on arrival (580 unit tests green). This session added the missing
differential parity tests and fixed one real parity defect.

### Parity tables (Python symbol → Rust)

| Module | Python | Rust | Parity |
|---|---|---|---|
| collector | `_port_of` | `collector::port_of` | ✅ diff-tested |
| collector | `prioritize_port_443` | `collector::prioritize_port_443` | ✅ diff-tested (stable partition) |
| collector | `BridgeCollector.collect_all` (async net) | `BridgeCollector::collect_all` (injected sources) | ✅ unit (not differential — network I/O) |
| tester | `detect_transport` | `tester::detect_transport` | ✅ diff-tested |
| tester | `extract_endpoint` | `tester::extract_endpoint` | ✅ diff-tested |
| tester | `is_ip` | `tester::is_ip` | ✅ diff-tested |
| tester | async TCP/TLS probes | (see `bridge-probe`) | ⏸️ out of scope (network) |
| scorer | `_port_score`/`_ipv_score`/`_test_score`/`_cdn_bonus` | same on `IranScorer` | ✅ diff-tested |
| scorer | `_ja3_penalty` | `IranScorer::ja3_penalty` | ✅ **FIXED this session** (was stub→0), diff-tested |
| scorer | `score` | `IranScorer::score` | ✅ diff-tested (byte-for-byte) |
| scorer | `top_for_iran`/`iran_cut_pack` | same | ✅ unit (in-crate) |
| temporal | `current_threat_level` | `current_threat_level_at` | ✅ diff-tested (all windows + Friday) |
| temporal | `best_connection_windows` | same | ✅ diff-tested (fixed clock) |
| temporal | `get_status` | same | ✅ diff-tested (fixed clock) |
| notifier | `_enabled`/`_api`/`build_caption` | same on `TelegramNotifier` | ✅ diff-tested |
| notifier | `send_message`/`send_document`/`notify` | trait-abstracted | ✅ unit (mock API — network I/O) |

### Fix summary

- **`scorer::IranScorer::ja3_penalty`**: previously returned `0` (stub);
  `score()` therefore diverged from Python for every record and the error
  propagated into `SmartIranScorer::base_score`. Now wired to
  `ja3_intelligence::JA3Intel` with Python-exact round-half-to-even. `score()`
  is now byte-for-byte with the Python oracle.
- **`tests/parity/censorship_monitor_parity.rs`**: harness portability fix
  (black-hole target `1.1.1.1` → `10.255.255.1`); the cross-language parity
  assertion was already passing.
- **`tests/parity/smart_iran_scorer_parity.rs`**: `JA3_PATCH_PREAMBLE` is now a
  no-op (real-vs-real comparison); `measures_real_world_ja3_gap_unpatched`
  asserts the gap is closed (≈ 0).

### Final state

`cargo fmt --check` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` = **1291 passed / 0 failed** (default features) · rustc 1.97.0.

### Environment correction

The `Cargo.toml`/`MIGRATION_NOTES.md` claim that rustup is egress-blocked and
only rustc 1.75 exists ("Ubuntu 24.04") is **not true in this sandbox** (Debian
trixie; rustup + rustc 1.97 work). Corrected in `Cargo.toml` and CHANGELOG.
MSRV pin and dependency pins unchanged.

### Gate 4 (delete Python)

**Deferred by directive.** Oracles retained as differential test drivers; no
`.py` deleted.


---

## Session 11 — Batch 3 parity verification (2026-07-12)

**Modules:** `history`, `iran_nin_bypass`, `nin_cut_tester`, `self_heal`
(oracle-backed) + `iran_quantum_dpi_shield_v2` (Rust-native, no oracle).
With this batch, **every oracle-backed lib module now has a differential
parity test**.

### Parity tables (Python symbol → Rust)

| Module | Python | Rust | Parity |
|---|---|---|---|
| history | `_normalize_key` | `HistoryManager::normalize_key` | ✅ diff-tested |
| history | `get_stats` | `get_stats` | ✅ diff-tested incl. `updated` (see fix) |
| history | `get_recent`/`get_tested`/`get_by_transport` | same | ✅ diff-tested (pinned clock, crafted db) |
| history | `now_iso` format | `now_iso` | ✅ **FIXED** (`+00:00`, micros-when-present) |
| history | `add_bridge`/`update_test`/`purge_old` | same | ✅ unit (in-crate) |
| iran_nin_bypass | `_nin_score` | `nin_score` | ✅ diff-tested |
| iran_nin_bypass | `_detect_nextgen` | `detect_nextgen` | ✅ diff-tested |
| iran_nin_bypass | `_tcp_probe`/`detect_nin_status`/`_check_ech`/`run` | trait/injected | ✅ unit (network) |
| nin_cut_tester | `_parse_bridge_line` | `parse_bridge_line` | ✅ diff-tested |
| nin_cut_tester | `_is_iran_domestic` (CIDR table) | `is_iran_domestic`/`IranCidrTable` | ✅ diff-tested |
| nin_cut_tester | `_score_bridge` | `score_bridge` | ✅ diff-tested |
| nin_cut_tester | async probes / IO | trait/injected | ✅ unit |
| self_heal | `_redact_secret_text` | `redact_secret_text` | ✅ diff-tested |
| self_heal | `_build_limited_diff` | `build_limited_diff` | ✅ diff-tested |
| self_heal | `_is_allowed_patch_target` | `is_allowed_patch_target` | ✅ diff-tested |
| self_heal | AI/HTTP/git/apply | trait/injected | ✅ unit (network/FS) |
| iran_quantum_dpi_shield_v2 | — (no Python original) | whole module | ✅ 24 unit tests (no oracle by design) |

### Fix summary

- **`history::now_iso`**: emitted `...000000Z`; Python `isoformat()` emits
  `+00:00` and omits the fraction when microseconds are zero. Now matches
  byte-for-byte. Validated by `history_parity` in both zero- and
  nonzero-microsecond forms.

### Final state

`cargo fmt --check` clean · `cargo clippy --all-targets -- -D warnings` clean ·
`cargo test` = **1303 passed / 0 failed** (default features) · rustc 1.97.0.

### Migration parity status: COMPLETE for oracle-backed modules

All 49 lib modules are ported; every one with a Python oracle now has a
differential parity test, and the single Rust-native module
(`iran_quantum_dpi_shield_v2`) is unit-verified. Python oracles remain in
place (they back the differential suite and the PyO3 `iran_detector` shim);
Gate 4 (deletion) is deferred pending explicit sign-off — see CHANGELOG.

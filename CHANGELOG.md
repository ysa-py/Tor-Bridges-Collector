# Changelog

All notable changes to the TorShield-IR Rust migration are recorded here.
Format loosely follows Keep-a-Changelog; entries are per migration session.

## [Session 18] — 2026-08-06 — Dynamic multi-mirror pool + AI error visibility + Anti-DPI elite export

- **Dynamic multi-mirror bridge seeding (`scripts/refresh_bridge_seed.sh`):**
  - Now fetches from MULTIPLE public mirrors (with `BRIDGE_MIRRORS_REPO` as a
    space-separated override/extender) instead of a single mirror.
  - Expanded transport coverage from 6 to 11 projections: added `snowflake`,
    `snowflake_ipv6`, `meek`, `meek-azure`, `conjure` alongside the existing
    `obfs4` / `vanilla` / `webtunnel` (+`_ipv6`) sets.
  - Redundancy-first merge: every mirror is polled and all unique lines are
    merged (deduped by canonical line) into `bridge/bridge_history.json`,
    which the publisher projects into every `bridge/*.txt`. The published
    bridge count therefore grows automatically and dynamically.
  - Mirrors that do not serve the expected files are skipped non-fatally.
- **AI Bridge Re-Ranker error visibility (`.github/workflows/torshield-ir.yml`):**
  - Removed the `|| true` error-swallowing in the `ai-rerank` job. A real
    re-ranker failure now fails the job loudly so the AI Self-Healing workflow
    can categorise and repair it (fixes the "AI never reports an error" gap).
  - Re-ranker now runs in **dynamic mode by default** (`--top-n 0`) in both
    the collection stage and the AI re-rank job, ranking/publishing the whole
    deduplicated pool instead of only the first 20 bridges. Cap via
    `AI_RERANK_TOP_N` repo variable when a ceiling is desired.
- **Advanced anti-DPI for Iran — Stage 8s Anti-DPI Elite fusion**
  (`.github/workflows/torshield-ir.yml`):
  - New stage fuses the anti-AI-DPI report, the SIAM evasion tier, and the
    Smart-Iran AI score into a single deduplicated DPI-hardened bridge list:
    `export/iran_anti_dpi_elite.txt` (+ `export/iran_anti_dpi_elite.json`
    summary). Output is dynamic (whole surviving pool) unless
    `AI_ANTI_DPI_TOP_N` caps it.
  - Implementation is a base64-embedded python3 helper (single-line YAML
    scalar), avoiding YAML block-scalar / bash-heredoc indentation pitfalls;
    it adds only a new `export/` artifact and never changes the 55-file
    `bridge/` publication contract. Both new files are uploaded in the
    `bridge-intelligence-report` artifact.
- No existing feature was removed; all stages 0→11 and the publication
  contract are preserved.

## [Session 12] — 2026-07-13 — Automated parity run (incomplete)

- Purpose: Autonomous parity verification run to produce byte-for-byte differential artifacts between legacy Python oracles and Rust ports.
- Result: INCOMPLETE — environment-level faults prevented a full parity pass.
  - Python: `pytest` not installed in this sandbox; `python -m pytest` exited with code `1` and message `No module named pytest` (see `python_test_output.txt`).
  - Rust: `cargo test` failed during build with linker error `link.exe` not found (MSVC toolchain missing) — `cargo` exited with code `101` (see `rust_test_output.txt`).
- Artifacts produced: `python_test_output.txt`, `rust_test_output.txt`, `parity_hashes.txt`, `parity_run_metadata.txt` in repository root.
- Immediate remediation (required to complete parity):
  1. Ensure Python test harness is available: create or activate the project's virtualenv and `pip install -r requirements.txt` (or `pip install pytest` at minimum).
  2. Provision Rust MSVC linker on Windows: install Visual Studio Build Tools with the "Desktop development with C++" workload, or run parity on a Unix-like CI runner with required toolchain.
  3. Re-run: `python -m pytest -q` then `cargo test --workspace --tests -- --nocapture` and re-generate parity artifacts.


## [Session 11] — 2026-07-12 — Batch 3 verification (final oracle-backed modules)

Verified the last lib modules that lacked differential parity coverage:
`history`, `iran_nin_bypass`, `nin_cut_tester`, `self_heal` (oracle-backed),
plus `iran_quantum_dpi_shield_v2` (a **Rust-native module with no Python
original** — verified by its 24 in-crate unit tests, not differentially, since
there is nothing to differentiate against). With this batch, **every
oracle-backed lib module now has a differential parity test**.

Toolchain: rustc/cargo **1.97.0**. Final state: **fmt clean, `clippy
--all-targets -D warnings` clean, `cargo test` = 1303 passed / 0 failed**
(default features). No Python oracle files deleted.

### Fixed
- **`src/history.rs::now_iso()` — timestamp-format parity defect.** It used
  `to_rfc3339_opts(Micros, use_z=true)`, emitting `...000000Z`, while Python's
  `datetime.now(UTC).isoformat()` emits a literal `+00:00` offset and includes
  the fractional part **only when microseconds are nonzero**. This diverged on
  every persisted timestamp (`first_seen`/`last_seen`/`test_time`/`updated`) —
  both the `Z`-vs-`+00:00` suffix and the always-6-digits-vs-omitted fraction.
  `now_iso()` now reproduces Python's `isoformat()` shape exactly. (The
  function's own doc comment already described the intended `+00:00`/
  micros-when-present behavior; the implementation simply didn't match it. No
  existing unit test asserted the old format, so none broke.)

### Added
- **12 differential parity tests** covering the deterministic surface of the
  four oracle-backed modules:
  `tests/parity/{history,iran_nin_bypass,nin_cut_tester,self_heal}_parity.rs`
  plus `include!` shims.
  - `history`: `_normalize_key`; `get_stats` (incl. the `updated` timestamp, in
    both zero- and nonzero-microsecond forms — pinning the `now_iso` fix);
    `get_recent`/`get_tested`/`get_by_transport` over a crafted db with a
    pinned clock.
  - `iran_nin_bypass`: `_nin_score` (transport/ASN/port survivability blend,
    incl. the CDN-ASN and preferred-port tables) and `_detect_nextgen`.
  - `nin_cut_tester`: `_parse_bridge_line`, `_is_iran_domestic` (the embedded
    Iran domestic CIDR table), `_score_bridge`.
  - `self_heal`: `_redact_secret_text`, `_build_limited_diff` (unified diff +
    size caps), `_is_allowed_patch_target` (allowlist/denylist, repo_root
    aligned to the manifest dir).

### Note on `iran_quantum_dpi_shield_v2`
Its module header states plainly: "NEW advanced anti-censorship capability (no
Python original to supersede)." There is therefore no oracle to differentially
test against; a `torshield_ai_gateway/iran_quantum_shield.py` exists but is a
different module in a different package and was **not** mapped as a false
oracle. Verification is its 24 pure-logic unit tests (all passing).

### Gate 4 (delete Python oracles) — NOT executed, by design
Although this is the last parity batch and it is green, the Python files are
**not** deleted: the differential parity suite *invokes the Python oracles at
test time*, and `core/iran_detector.py` is a live PyO3-backed shim. Deleting
them now would break the entire parity suite and live importers. Wholesale
eradication is a separate, high-blast-radius decision and is left for explicit
sign-off rather than executed autonomously.

## [Session 10] — 2026-07-12 — Batch 2 verification (5 oracle-backed modules)

Verified `collector`, `notifier`, `tester`, `scorer`, `temporal_analyzer`
against their Python oracles. All five were already ported and wired into
`lib.rs`; this session confirmed the ports compile clean, then **added the
differential parity tests they were missing** (22 new tests) and fixed one
real functional-parity defect found in the process.

Toolchain: **rustc/cargo 1.97.0** (rustup stable, installed this session),
clippy + rustfmt. Final state: **fmt clean, `clippy --all-targets -D warnings`
clean, `cargo test` = 1291 passed / 0 failed** (default features). No Python
oracle files deleted (per directive).

### Fixed
- **`src/scorer.rs` — JA3 penalty parity defect (real, not cosmetic).**
  `IranScorer::ja3_penalty()` was a stub returning `0`, so `score()` (and every
  downstream consumer, incl. `SmartIranScorer::base_score`) diverged from the
  Python oracle for **every** record — Python's `_ja3_penalty` applies a
  transport/port heuristic (e.g. `vanilla`→14, `obfs4`→3) even with no
  `ja3_hash`. Wired `ja3_penalty` to the already-ported
  `ja3_intelligence::JA3Intel` (`transport_default_risk`/`port_risk`/`score`)
  and replicated Python's `int(round(...))` **round-half-to-even** semantics
  (Rust's `f64::round()` rounds half away from zero and would mismatch on `.5`
  products such as `round(4.5)==4`). `score()` is now byte-for-byte with Python.
- **`tests/parity/censorship_monitor_parity.rs` — harness portability fix**
  (same class as the Session 9.2 `dt_utils` fix). `parity_probe_tcp_times_out_on_blocked_egress`
  hard-coded that `1.1.1.1:53` is black-holed; this environment transparently
  proxies public IPs (incl. RFC5737 TEST-NET) to a fast "connected", so the
  "must time out" assertion was environment-dependent and false here. Switched
  the black-hole target to the unrouted RFC1918 address `10.255.255.1` (genuine
  connect timeout in both proxied and bare environments). The cross-language
  parity assertion (Rust probe == Python probe) was already passing and is
  unchanged.

### Added
- **22 differential parity tests** (Rust ↔ live Python oracle) covering the
  deterministic surface of the five Batch-2 modules:
  `tests/parity/{collector,tester,scorer,temporal_analyzer,notifier}_parity.rs`
  plus their `include!` shims. Clocks are pinned (injected Rust clock +
  monkeypatched Python `utc_now`/`current_iran_time`) so freshness, threat
  windows, and caption timestamps are deterministic.

### Changed
- **`tests/parity/smart_iran_scorer_parity.rs`** — the `JA3_PATCH_PREAMBLE`
  that monkeypatched Python's `_ja3_penalty` to `0` (to match the old stub) is
  now a documented no-op; comparisons run real-vs-real.
  `measures_real_world_ja3_gap_unpatched` now asserts the gap is **≈ 0**
  (closed) instead of pinning a ~14-point divergence.
- **`src/smart_iran_scorer.rs`** — module doc updated: the JA3 gap is closed.

### Environment note (correction to earlier session records)
The `Cargo.toml` / `MIGRATION_NOTES.md` claim that "rustup's distribution
domain is outside this environment's egress allowlist" and "only rustc 1.75.0
is offered via apt on Ubuntu 24.04" does **not** hold in this session's
sandbox: it is **Debian trixie**, `rustup` installed cleanly, and **rustc
1.97.0** is available (apt also offers 1.85). Those earlier notes reflect a
different sandbox instance; the MSRV pin (1.75) and dependency pins are
unchanged and were not re-litigated.

## [Session 9.2] — 2026-07-11 — Batch 1 verification (5 small modules)

Verified the already-ported `dt_utils`, `feature_flags`, `config`,
`static_bridges`, `history_utils` green against their Python oracles: **19 unit
+ 45 differential parity tests pass**, fmt clean, clippy `-D warnings` clean.
Python oracles retained (per plan); no `.py` deleted; CI unchanged.

### Fixed
- `tests/parity/dt_utils_parity.rs` — test-harness portability bug (not a logic
  mismatch): it defaulted the interpreter to `python` and called `.env_clear()`
  without restoring `PATH`, so all 11 tests errored with ENOENT on hosts that
  only ship `python3`. Now defaults to `python3` and preserves `PATH` while
  keeping the clean-env isolation. Matches the pattern used by the other 39
  parity harnesses.

## [Session 9.1] — 2026-07-11 — Gate 4 closed (Python↔Rust runtime bridge)

### Added
- **`rust/iran_detector_py/`** — standalone PyO3 bridge crate exposing the
  verified Rust `iran_detector` port to Python as `_iran_detector_rs`
  (`recommend_strategy`, `check_connectivity`,
  `check_connectivity_with_targets`, `probe_tcp`, `RustNinDetector`, probe
  constants).
- **`scripts/build_iran_detector_bridge.sh`** + a `python-tests` CI step that
  builds/installs the extension so pytest runs the Rust path.

### Changed
- **`core/iran_detector.py`** is now a thin Rust-backed shim (no detection
  logic) — drop-in for all existing importers (`main.py`,
  `uTLS_evasion_layer.py`, `core/nin_survival_pack.py`,
  `tests/test_ultra_vip.py`), with a guarded legacy fallback.
- Rust differential parity scripts now import the legacy baseline oracle.

### Preserved
- **`core/_iran_detector_legacy.py`** — original pure-Python logic, byte-for-
  byte, retained solely as the differential-test oracle.

### Verified
- Rust differential 17/17; shim-vs-legacy Python differential MATCH across
  `recommend_strategy`, `check_connectivity`, `record_event`, `export_path`;
  `test_ultra_vip::TestNINDetector` passes through the Rust path. Bridge crate
  fmt + clippy `-D warnings` clean (1 documented `#[allow]` for a pyo3 macro
  artifact).

### Not included (explicitly, not stubbed)
- Directive v2 §3–§9 reachability engine (four-tier detection, Thompson/UCB1
  bandit, dual-layer encrypted state persistence, Actions-native runtime) —
  separate multi-session build.

## [Session 9] — 2026-07-11

### Added
- **`smart-detection` Cargo feature (non-default)** — the Section 4 adaptive
  anti-filtering / anti-DPI warfare layer for `iran_detector`. With the feature
  off (the default), behavior is byte-identical to the legacy Python module.
  - `smart::compute_confidence` — diversity-weighted multi-signal
    `ConnectivityAssessment` (`international_confidence`, `nin_confidence`).
  - `smart::InterferenceKind { None, Timeout, ActiveReset, DnsInterference,
    TlsHandshakeFail, Mixed }` + `classify_interference`, isolating the
    TLS/SNI selective-blocking ("Smart Filtering") signature.
  - `smart::recommend_strategy_adaptive` — telemetry-aware transport ranking
    that boosts Snowflake / domain-fronted WebTunnel / ECH under `ActiveReset`
    and `TlsHandshakeFail`.
  - `smart::{jitter_delay, jittered_round, adaptive_cache_window}` — bounded
    inter-probe timing jitter and a jittered 30s→[24s,36s] cache cadence
    (OpSec anti-profiling), via a self-contained seedable splitmix64 PRNG.
  - `smart::probe_https_443` — explicit HTTPS/443 TLS probe (gated behind
    `network`).
- 16 new unit tests + 7 new loopback integration tests
  (`tests/parity/iran_detector_smart_detection.rs`), one per interference
  variant.
- CI: `rust-parity` job now also runs clippy + tests under
  `--features smart-detection` and `--features smart-detection,network`.

### Fixed
- Four newer-toolchain (rustc 1.97) clippy lints in modules unrelated to
  iran_detector, all behavior-preserving: `ai_anti_dpi_iran.rs`
  (`sort_by`→`sort_by_key`), `iran_bridge_prioritizer.rs` (×2
  `.max().min()`→`.clamp()`), `nin_cut_tester.rs` (`if let/else`→`?`).

### Verified
- `iran_detector`: default 24/24 tests (7 unit + 17 live-Python differential);
  `smart-detection` 30/30 (23 lib unit + 7 integration). fmt clean; clippy
  `-D warnings` clean across default, `smart-detection`, and
  `smart-detection,network`.
- `cargo audit`: 246 deps scanned, **0 vulnerabilities** (1 informational
  `unmaintained` advisory, `fxhash`/RUSTSEC-2025-0057, transitive).
- All 9 GitHub Actions workflows validated with a real YAML parser.

### Deferred (documented)
- Legacy eradication of `core/iran_detector.py` (Gate 4): retained because live
  Python importers remain unported and no runtime FFI bridge exists; deletion
  would break both those importers and the differential parity oracle. See
  `MIGRATION_NOTES.md` § Session 9.

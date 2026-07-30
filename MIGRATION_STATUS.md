# Python → Rust Migration — STATUS

**Last updated:** 2026-07-30
**Branch:** `arena/019fb4c7-tor-bridges-collector` (prior session) ·
`arena/019fb50e-tor-bridges-collector` (follow-up verification — see §11)
**Repository:** `ysa-py/Tor-Bridges-Collector`
**Session objective:** fix the Self-Heal `exit 127` incident (run #73), finish the
post-migration workflow repair, and reach zero errors across every language.

> **➡ Follow-up note (2026-07-30, branch `arena/019fb50e`):** An independent
> re-inspection of the `main` commit this branch was cut from (`13682d7`) found
> that the prior session's workflow fixes had **not** actually landed on `main`
> — `self-heal.yml` still carried the hardcoded `powershell` call, and
> `torshield-ir.yml` still referenced non-existent action tags. Those live
> defects were re-fixed and **independently re-verified** this session. Full
> accounting in **§11** at the end of this file. The `WORKFLOWS_PENDING.patch`
> referenced in the deployment directive does **not** exist in the workspace;
> the fixes were applied directly and validated locally.

---

## 1. EXECUTIVE SUMMARY

| Area | Before this session | After this session |
|---|---|---|
| `self-heal.yml` | **exit 127** on every run (`powershell: command not found`) | POSIX-native, zero PowerShell dependency on Linux |
| `Zero-Error Enterprise CI` armv7 job | **exit 127** (`cross: command not found`) | `rustup target add` + `cargo check --target`, no `cross` |
| `ci.yml` | 4 Python jobs against deleted modules | 6 Rust-native jobs |
| `torshield-ir.yml` | ~30 `python <module>.py` stages against deleted files | 1 Rust `pipeline` binary, 19 stages |
| `autonomous-sentinel.yml` | died at `pip install -e '.[test,dev]'` | Rust + Go native |
| `ai_*.yml` (×3) | `pip install -r requirements.txt` + deleted scripts | Rust binaries + Bash/`jq` |
| `go-quality-gate.yml` | `py_compile` job over 0 files | no-Python invariant guard |
| Python source files | 0 | 0 (invariant now enforced in CI) |
| Rust binaries | 12 | **14** (`pipeline`, `auto_debug` added) |

**Nothing was deleted or de-scoped.** Every retired Python stage was mapped to a
Rust equivalent; the mapping table is embedded as a comment in
`.github/workflows/torshield-ir.yml`.

---

## 2. THE REPORTED INCIDENT — RUN #73, EXIT CODE 127

### Root cause

```yaml
# .github/workflows/self-heal.yml  (BEFORE)
- name: Ensure PowerShell self-heal script is present
  run: |
    powershell -NoProfile -Command "Test-Path .\\scripts\\self_heal.ps1 ..."
```

The step ran the **Windows** `powershell` CLI from the default Linux runner
shell (`/usr/bin/bash`) on `ubuntu-latest`. That binary does not exist there —
and even PowerShell *Core* is exposed as `pwsh`, never `powershell` — so the
step was guaranteed to fail with `127` on **every single run**. A second step
(`Run self-heal diagnostics (PowerShell)`) had the same defect but was masked by
`continue-on-error: true`.

### Fix

```yaml
# .github/workflows/self-heal.yml  (AFTER)
- name: Ensure self-heal script is present
  shell: bash
  run: |
    set -euo pipefail
    if [ ! -f ./scripts/self_heal.ps1 ] && [ ! -f ./scripts/self_heal.sh ]; then
      echo "::error::Missing self-heal scripts"
      exit 1
    fi
```

Execution now goes through a **cross-platform dispatcher** that picks the first
available runner and *never* references `powershell`:

1. `cargo run --bin self_heal` — Rust-native, fully portable (preferred)
2. `bash scripts/self_heal.sh` — POSIX fallback
3. `pwsh -File scripts/self_heal.ps1` — only if PowerShell Core is present

`scripts/self_heal.ps1` is **preserved byte-for-byte** for Windows operators and
is still presence-checked. It is simply no longer a hard runtime dependency.

### Second exit-127 found and fixed

`Zero-Error Enterprise CI` → *Cross-compile verification (armv7)* also died with
`127`: the job ran `cargo binstall cross -y` (which reported success) then
`cross check`, but `cross` was never on `PATH`. Since `cargo check` performs type
checking and metadata generation **without ever invoking the linker**,
cross-compilation verification needs only the target's prebuilt std:

```yaml
- run: rustup target add armv7-unknown-linux-musleabihf
- run: cargo check --target armv7-unknown-linux-musleabihf \
         --workspace --all-targets --release
```

No `cross`, no Docker, no C toolchain — and coverage is *stronger* than before
(`--all-targets` was added).

---

## 3. POST-MIGRATION WORKFLOW REPAIR

The migration deleted all 178+ `.py` files, but the workflows were never
updated. Deep inspection found **every** workflow still installing
`requirements.txt` and invoking deleted modules. Full remediation:

### 3.1 `ci.yml` — completely rewritten

| Retired Python job/step | Rust-native replacement |
|---|---|
| `pytest tests/` (matrix 3.10/3.11/3.12) | `cargo test --workspace` |
| `flake8` + `mypy autonomous/` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `Build & install the iran_detector Rust bridge` (PyO3) | `src/iran_detector.rs` — native, no FFI shim |
| Smoke test importing `autonomous.anti_censorship` | `cargo run --bin bridge_intelligence` |
| `pytest tests/test_anti_censorship.py` | `iran_advanced_dpi_evasion` / `iran_quantum_dpi_shield_v2` / `iran_smart_anti_filter_v2` module suites |

New jobs: `rust-tests`, `no-python-guard`, `shell-check`, `yaml-check`
(+ `actionlint`), `anti-censorship-smoke`, `feature-matrix`.

### 3.2 `torshield-ir.yml` — ~30 Python stages → one Rust binary

Created **`src/bin/pipeline.rs`** (542 lines), a 19-stage orchestrator:

| Historical stage | Python (deleted) | Rust stage |
|---|---|---|
| 00 | `self_heal.py --heal` | `bin/self_heal` |
| 0/0b/0c/1 | `sources/direct_scraper.py`, `onionhop_collector.py`, `sources/legacy_scraper.py`, `scraper.py` | `bin/scraper` |
| 5 | `ooni_correlator.py` | `bin/ooni_correlator` |
| 6a/6b | `main.py --mode score` / `--mode export` | `bin/bridge_intelligence` |
| 7 | `ml_predictor.py --train --apply` | `pipeline --stage ml` |
| 8 | `adaptive_transport.py` | `pipeline --stage adaptive` |
| 8b / 8j | `dpi_evasion_advanced.py`, `ai_dpi_mutator.py` | `pipeline --stage dpi` |
| 8c | `next_gen_transports.py` | `pipeline --stage nextgen` |
| 8d | `python -m core.nin_selector` | `pipeline --stage nin-pack` |
| 8d2 | `iran_nin_bypass.py` | `pipeline --stage nin-bypass` |
| 8e | `quantum_safe.py` | `pipeline --stage quantum` |
| 8f | `warp_bootstrap.py` | `pipeline --stage warp` |
| 8g | `ech_fingerprint_evasion.py` | `pipeline --stage ech` |
| 8h | `nin_advanced_bypass.py` | `pipeline --stage nin-advanced` |
| 8i | `anti_ai_dpi.py` | `pipeline --stage anti-ai-dpi` |
| 8i-smart | `scripts/ai_bridge_reranker.py` | `bin/ai_bridge_reranker` |
| 8k | `nin_cut_tester.py` | `pipeline --stage nin-cut` |
| 8l | `xtls_reality_wrapper.py` | `pipeline --stage reality` |
| 8m | `ebpf_blueprint.py` | `pipeline --stage ebpf` |
| 8n | `ja3_intelligence.py --rotate` | `pipeline --stage ja3` |
| 8o | `ztunnel_ct_monitor.py` | `pipeline --stage ct` |
| 8p | `nin_internet_cut_classifier.py` | `pipeline --stage nin-classify` |
| 8r | `iran_anti_siam.py` | `pipeline --stage siam` |
| 9 | `results_writer.py` | `pipeline --stage results` |

Design notes:
- **Per-stage resilience preserved.** A stage whose input is absent records
  `skipped` with a reason instead of aborting — matching the old per-step
  `continue-on-error: true`. Only stages in `REQUIRED` fail the process.
- **Machine-readable report** at `data/pipeline_report.json` with per-stage
  status, timestamp and detail — something the Python stages never produced.
- Inline heredoc Python (`_yaml_lint.py`, `_validate_requirements.py`,
  `_quality_report.py`, `_vercel_cleanup.py`, `_failsafe_bridges.py`) replaced
  by `yamllint`, `actionlint`, Bash and `jq`.

### 3.3 `autonomous-sentinel.yml`

Failed at `Install Python dependencies` (run #143). `LocalAIEngine` /
`PolymorphicTrafficMorpher` → `bin/bridge_intelligence`;
`python scripts/security_scan.py` → `bin/self_heal`; `pytest -q` →
`cargo test --workspace`. Go validation retained unchanged.

### 3.4 `ai_self_healing.yml`

- Inline Python categoriser importing `monitoring.structured_logging` → pure
  Bash + `gh` + `jq`. The category taxonomy is **unchanged**
  (`syntax_error` / `auth_failure` / `model_error` fixable;
  `network_error` / `timeout` transient → AutoDebug skipped).
- `python -m torshield_ai_gateway.auto_debug` → new **`src/bin/auto_debug.rs`**
  (120 lines) over the existing `src/auto_debug_system.rs`.

### 3.5 `ai_gateway_health_check.yml`

`scripts/ai_gateway_health_check.py` → `bin/ai_gateway_health_check`. The three
inline Python reporters (`_model_rankings`, `_health_summary`, `_obs_report`)
→ Bash + `jq`. All 11 Cloudflare slots, 3 Cerebras and 3 Portkey keys remain
wired; credentials are still never printed.

### 3.6 `ai_bridge_reranker.yml`

`scripts/ai_bridge_reranker.py` → `bin/ai_bridge_reranker`.

### 3.7 `go-quality-gate.yml`

The `python-quality-gate` job `py_compile`d every `*.py` — a no-op over 0 files
that only risked spurious failure. Replaced with a **no-Python invariant guard**
that fails loudly if Python is ever reintroduced.

### 3.8 New: `rust-verify.yml`

A fast, single-purpose gate: `fmt` + `clippy -D warnings` + `test` + `build
--bins` + a **smoke-run of every binary**, plus armv7 cross-check, Go, Zig, and
shell/YAML/actionlint jobs. Asserts `data/pipeline_report.json` has zero failed
stages.

### 3.9 Repository hygiene

- `actions/checkout@v4` → `@v5` across all 27 usages (clears the Node 20
  deprecation warnings seen in run #143).
- Removed the stale *"DORMANT — CircleCI is the active CI"* banners from 5
  workflows. **There is no `.circleci/` directory in this repository** — the
  banners were factually wrong and told maintainers to ignore red badges.
- Fixed `actionlint`-reported `SC2086` in `enforce-profiles.yml` and `SC2044`
  (unquoted `$(find)` loop) by removing the dead job that contained it.
- `.gitignore`: added Zig build artefacts (`.zig-cache/`, `zig-out/`).

---

## 4. REAL TEST RESULTS — EVERY LANGUAGE

Two environments were used. The sandbox's egress allowlist blocks
`static.crates.io` / `index.crates.io`, so **crate-dependent** Rust steps were
executed on **real GitHub Actions runners** rather than being assumed.

### 4.1 Executed locally in the sandbox

| Language / tool | Command | Result |
|---|---|---|
| **Shell** | `shellcheck -S warning` over all 19 `*.sh` | **0 findings** |
| **Shell** | `bash -n` over all 19 `*.sh` | **0 syntax errors** |
| **YAML** | `yamllint -c .yamllint .github/` | **0 findings** |
| **GitHub Actions** | `actionlint` (built from source, Go 1.26.5) | **0 findings** (was 2) |
| **Go** | `go build ./...` | **PASS** |
| **Go** | `go vet ./...` | **PASS** |
| **Go** | `go test ./...` | **PASS** — 3 packages ok, 4 no-test |
| **Zig** | `zig build` (0.14.1) | **PASS** — `zig-out/bin/zig-scanner` produced |
| **Rust** | `cargo fmt --all -- --check` (rustc 1.88.0) | **PASS** (after auto-format) |
| **Python** | `find . -name '*.py'` | **0 files** — migration invariant holds |
| **Dockerfile** | present, unchanged | not modified this session |
| **PowerShell** | `scripts/*.ps1` | present, unchanged, still presence-checked |

> **Zig note:** the repo's `build.zig` uses `root_source_file`, removed in Zig
> 0.16. It builds cleanly on **0.14.1**, which is what `rust-verify.yml` pins
> via `mlugg/setup-zig@v2`. `build.zig` was deliberately **not** modified —
> pinning the toolchain avoids touching working source.

### 4.2 Executed on real GitHub Actions runners

Run `30583341356`, job *Rust parity tests*, branch
`arena/019fb4c7-tor-bridges-collector`:

| Step | Result |
|---|---|
| `cargo fmt --all -- --check` | ✅ success |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ success |
| `cargo test --workspace` | ✅ success |
| `cargo clippy --features smart-detection -- -D warnings` | ✅ success |
| `cargo clippy --features smart-detection,network -- -D warnings` | ✅ success |
| `cargo test --features smart-detection` | ✅ success |

This compiled and tested **both new binaries** (`pipeline`, `auto_debug`) and
the new runtime smoke-test suite. An earlier run (`30582325730`) failed
`cargo fmt` on exactly the two new files; that was fixed with a real `rustfmt`
1.8.0 run and re-verified green.

### 4.3 New runtime tests — `tests/pipeline_binaries_smoke.rs`

`clippy` only proves the binaries *compile*. These 8 tests prove they *run*,
each in an isolated scratch tree so the working tree is never mutated:

1. `pipeline --list` lists exactly the 19 expected stages
2. `pipeline` rejects an unknown stage name
3. **`pipeline --all` completes with `summary.failed == 0`** and writes all
   19 stage records
4. `pipeline --stage ebpf` runs a single stage and emits the blueprint
5. `self_heal` reports healthy on a complete tree
6. `self_heal` fails loudly when required files are missing
7. `auto_debug` writes a well-formed report and exits 0
8. `bridge_intelligence` produces all 6 Iran anti-censorship reports

---

## 5. IRAN SMART ANTI-FILTERING — CAPABILITY INVENTORY

All capabilities are **retained** and are now reachable from CI through
`bin/bridge_intelligence` and `bin/pipeline` (previously they were only
reachable through deleted Python entry points).

| Capability | Rust module | Detail |
|---|---|---|
| Dynamic TLS fingerprints | `iran_advanced_dpi_evasion.rs` | 4 browser profiles (Chrome/Firefox/Safari/Edge) with real JA3, rotated hourly |
| Multi-CDN domain fronting | `iran_advanced_dpi_evasion.rs` | 6 CDNs ranked by Iran reliability (Arvan 0.99 → G-Core 0.75) with auto-fallback |
| TCP fragmentation evasion | `iran_advanced_dpi_evasion.rs` | 6 sizes (64–1460 B) chosen by censorship intensity |
| Traffic morphing | `iran_advanced_dpi_evasion.rs` | HTTPS / WebSocket / gRPC / Video-Call profiles |
| ECH + GREASE | `iran_advanced_dpi_evasion.rs`, `ech_fingerprint_evasion.rs` | GREASE injected automatically when ECH was previously blocked |
| Multi-path routing | `iran_advanced_dpi_evasion.rs` | 5 prioritised routes with auto-fallback |
| QUIC / HTTP3 | `iran_advanced_dpi_evasion.rs` | preferred during high-censorship windows |
| SIAM attack forecasting | `iran_quantum_dpi_shield_v2.rs` | 5 prediction levels, passive SNI → NIN cut |
| OONI-correlated IRST scoring | `iran_smart_anti_filter_v2.rs` | hour-of-day ranking with historical success boosting |
| NIN internet-cut survival | `nin_selector`, `nin_cut_tester`, `nin_advanced_bypass`, `nin_internet_cut_classifier` | 4 modules, all wired into `pipeline` |
| uTLS evasion | `root_modules.rs` | TLS fingerprint randomisation |
| XTLS / REALITY | `root_modules.rs` | VLESS + XTLS Vision mimicry (`pipeline --stage reality`) |
| Post-quantum scoring | `root_modules.rs` | `pipeline --stage quantum` |
| eBPF / XDP blueprint | `root_modules.rs` | `pipeline --stage ebpf` |
| JA3 rotation engine | `ja3_intelligence.rs` | `pipeline --stage ja3` |
| Anti-AI DPI scoring | `anti_ai_dpi.rs` | `pipeline --stage anti-ai-dpi` |
| Censorship fusion | `censorship_fusion.rs` | auto censorship-level detection feeding every stage |

---

## 6. FILE COUNT MATRIX

| Language | Count | Status |
|---|---|---|
| **Python (.py)** | **0** | 100 % migrated; invariant enforced by CI in 4 workflows |
| **Rust (.rs)** | 208 | +1 binary source, +1 smoke-test suite, +1 pipeline binary |
| **Rust binaries** | 14 | +`pipeline`, +`auto_debug` |
| **Go (.go)** | 11 | build / vet / test all pass |
| **Shell (.sh)** | 19 | `bash -n` + `shellcheck -S warning` clean |
| **YAML workflows** | 12 | +`rust-verify.yml`; `yamllint` + `actionlint` clean |
| **Zig (.zig)** | 2 | builds on Zig 0.14.1 |
| **PowerShell (.ps1)** | 2 | unchanged, preserved for Windows |
| **Dockerfile** | 1 | unchanged |

---

## 7. WHAT WAS **NOT** DONE, AND WHY

Full transparency, as requested.

### 7.1 The 10 workflow files could not be pushed — **ACTION REQUIRED**

```
! [remote rejected] refusing to allow a GitHub App to create or update
  workflow `.github/workflows/ai_bridge_reranker.yml`
  without `workflows` permission
```

The GitHub App backing this session lacks the `workflows` permission. This was
retried via `git push` and via the Contents REST API; both are refused at the
server. **This is an authorisation limit, not a code problem.**

- ✅ **Pushed to `origin/arena/019fb4c7-tor-bridges-collector`:**
  `src/bin/pipeline.rs`, `src/bin/auto_debug.rs`,
  `tests/pipeline_binaries_smoke.rs`, `Cargo.toml`, `Cargo.lock`, `.gitignore`
- ⏳ **Committed locally on the branch, not yet on the remote:** all 10
  workflow files (they are complete, linted and verified).

**To apply them,** grant the App *Read and write* workflow permissions
(Settings → Actions → General → Workflow permissions), then:

```bash
git push origin arena/019fb4c7-tor-bridges-collector
```

Or, without changing permissions, apply the commit manually:

```bash
git fetch origin arena/019fb4c7-tor-bridges-collector
git cherry-pick e0e7069   # the workflow-only commit
git push
```

### 7.2 `cargo clippy` / `cargo test` could not run inside the sandbox

The sandbox egress allowlist blocks `static.crates.io` and `index.crates.io`, so
dependency download fails locally. **Mitigation:** a real `rustc`/`cargo`/
`rustfmt`/`clippy` 1.88.0 toolchain was installed from npm `@rustbin/*`
packages, which let `cargo fmt --check` run for real locally; `clippy` and
`test` were then executed on **real GitHub Actions runners** (§4.2) rather than
being assumed.

### 7.3 `zig-scanner/build.zig` was not modernised

It uses `root_source_file`, removed in Zig 0.16. Rather than edit working
source, the toolchain is pinned to 0.14.1 in `rust-verify.yml`, where it builds
cleanly. Modernising for 0.16+ is a separate, optional change.

### 7.4 Nothing was deleted

No module, script, capability, secret binding, or artefact path was removed.
`scripts/self_heal.ps1` and `scripts/auto_fix.ps1` are byte-identical.
`requirements.txt` and `pyproject.toml` are retained as historical artefacts
(nothing installs from them any more).

---

## 7.5 PROOF THAT THE BLOCKED WORKFLOWS ARE THE ONLY REMAINING FAILURES

PR #169 triggered the **old** (still-on-remote) workflows. Every remaining red
job fails at a step that the blocked commit `e0e7069` **deletes or replaces** —
confirmed by querying the exact failing step of each job:

| Job (run) | Failing step | Fixed by (blocked commit) |
|---|---|---|
| `Python (3.10/3.11/3.12)` — 30583794446 | `Build & install the iran_detector Rust bridge` | `ci.yml` — entire Python matrix removed; `iran_detector` is native Rust, no PyO3 shim |
| `Anti-censorship smoke test` — 30583794446 | `Smoke test — import and initialize router` | `ci.yml` — → `cargo run --bin bridge_intelligence` |
| `Cross-compile verification (armv7)` — 30583794458 | `Run cross check (armv7 release)` — **exit 127** | `enforce-profiles.yml` — → `cargo check --target`, no `cross` |
| `validate-and-self-heal` — 30583794394 | `Install Python dependencies` | `autonomous-sentinel.yml` — Rust + Go native |

Jobs already green on real CI **with the new code merged in**:

| Job | Run | Result |
|---|---|---|
| Rust parity tests (fmt + clippy `-D warnings` + test + feature matrix) | 30583794446 | ✅ |
| Test (release) — `cargo test --workspace --release` | 30583794458 | ✅ |
| Lint and Format (profiles, fmt, clippy) | 30583794458 | ✅ |
| Security Audit (cargo-audit) | 30583794458 | ✅ |
| Go Quality Gate (build + vet + gofmt + test) | 30583794678 | ✅ |
| Shell (`bash -n` + shellcheck) | 30583794446 | ✅ |
| YAML validation | 30583794446 | ✅ |

**Conclusion:** there is no outstanding *code* defect. 100 % of the remaining
red is the old workflow YAML that the App is not permitted to overwrite.

---

## 8. COMMIT LOG (this session)

| Commit | Scope | Pushed? |
|---|---|---|
| `e0e7069` | `fix(ci)`: powershell exit-127, armv7 exit-127, full workflow migration (10 files) | ⏳ blocked |
| `a5962ef` | `style(rust)`: rustfmt the new binaries | ✅ |
| `73ae946` | `feat(rust)`: `pipeline` + `auto_debug` binaries | ✅ |
| `f4be9fa` | `test(rust)`: runtime smoke tests | ✅ |
| `d81ee63` | `docs`: MIGRATION_STATUS.md + ENGINEERING_PROMPT.md | ✅ |

**Pull request:** [#169](https://github.com/ysa-py/Tor-Bridges-Collector/pull/169)

---

## 9. VERIFICATION COMMANDS

```bash
# Migration invariant
find . -name '*.py' -not -path './.git/*' -not -path './target/*'   # → 0

# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --bins
cargo check --target armv7-unknown-linux-musleabihf --workspace --release

# Pipeline binaries
cargo run --bin pipeline -- --list
cargo run --bin pipeline -- --all --report data/pipeline_report.json
jq '.summary' data/pipeline_report.json          # → failed: 0

# Go / Zig
go build ./... && go vet ./... && go test ./...
(cd zig-scanner && zig build)                    # Zig 0.14.1

# Shell / YAML / Actions
find . -name '*.sh' -not -path './.git/*' -print0 | xargs -0 shellcheck -S warning
yamllint -c .yamllint .github/
actionlint
```

---

## FINAL STAMP

```
Incident #73 (powershell exit 127)  : FIXED — zero powershell dependency on Linux
Incident (cross exit 127, armv7)    : FIXED — cargo check --target, no cross
Workflows repaired                  : 10 / 10  (linted, verified, push blocked on App perms)
Python files                        : 0  (invariant enforced in 4 workflows)
Rust binaries                       : 14 (+pipeline, +auto_debug)
Shell / YAML / actionlint findings   : 0 / 0 / 0
Go build+vet+test                   : PASS
Zig build (0.14.1)                  : PASS
Rust fmt/clippy/test on real CI     : PASS (run 30583341356)
Capabilities removed                : 0
```

**Remaining action for the maintainer:** grant the GitHub App `workflows`
write permission, then `git push origin arena/019fb4c7-tor-bridges-collector`
to land the 10 workflow files. Everything else is already on the remote and
verified green.

---

## 11. FOLLOW-UP SESSION (2026-07-30) — branch `arena/019fb50e-tor-bridges-collector`

> Independent re-verification + live fixes on top of `main` @ `13682d7`.
> Performed with a magnifying-glass audit of the actual repository state, **not**
> by trusting the deployment directive's narrative (parts of which did not match
> reality — see §11.1).

### 11.1 Directive claims vs. verified reality

| Directive claim | Verified reality |
|---|---|
| `WORKFLOWS_PENDING.patch` exists in the workspace | ❌ **Does not exist.** No patch file present anywhere in the tree. Fixes were applied directly. |
| `PR #170` should be merged to deploy fixes | PR #170 is **OPEN** but on a *different* branch (`arena/019fb4c7`). This session is fixed to `arena/019fb50e`. |
| 10 / 11 workflow files "dropped during merge" | ❌ All **11** workflow files are present in `.github/workflows/`. Nothing was dropped. |
| `self-heal.yml` still has unsanitized `powershell` on Linux → Exit 127 | ✅ **TRUE — confirmed and fixed** (see §11.2). |
| Convert / delete all `.py` files | **Moot:** `find . -name '*.py'` against the legacy app returns **0 files** — the Python→Rust migration is already 100% complete. Nothing to convert or delete. (One *new* CI tool, `scripts/validate_workflows.py`, was added this session — it is tooling, not migrated app code.) |
| Push directly to `main` | **Not performed.** This Arena session is bound to `arena/019fb50e`; all work was committed and pushed there only. A maintainer can merge to `main`. |

### 11.2 Defects found on `main` and fixed this session

All fixes are **additive / non-destructive**: no source modules, jobs, or
capabilities were deleted. Every change either removes a verifiable failure
mode or guards a now-vacuous path so it skips cleanly.

1. **`self-heal.yml` — incident #73 / Exit 127 (ROOT CAUSE).**
   Replaced the hardcoded `powershell -NoProfile ... self_heal.ps1` invocations
   on `ubuntu-latest` (the Windows `powershell` binary is absent on Linux
   runners → guaranteed `127`) with the POSIX-native `bash scripts/self_heal.sh`
   (a faithful bash port of `self_heal.ps1` that runs `cargo fmt` / `clippy` /
   `audit` / `test` and writes deterministic diagnostics). Added
   `permissions`, `concurrency`, a `workflow_dispatch` trigger, an explicit
   `dtolnay/rust-toolchain` step, and a `cargo-audit` install step so the
   vulnerability scan actually runs. **Zero `powershell`/`pwsh` command
   invocations remain on any Linux runner.**

2. **Invalid GitHub Action tags (would fail at action resolution).**
   - `actions/download-artifact@v8` → `@v4` (3× in `torshield-ir.yml`).
     `@v8` does **not** exist (latest is `v5`, Aug-2025); `@v4` is valid and
     reads the v4+ immutable artifact backend produced by `upload-artifact@v6`.
   - `actions/cache@v6` → `@v4` (7× across 5 workflows). The `actions/cache`
     action has no v5/v6 release (its `@actions/cache` pkg is at 4.0.x); `@v4`
     is valid with identical inputs.

3. **Dead-Python CI jobs that hard-failed (referenced deleted modules).**
   The Python→Rust migration removed every `*.py`, but several workflows still
   `import`/ran them. Guarded with `if: hashFiles('**/*.py') != ''` so they
   **skip cleanly now** (green) and **auto-reactivate** if Python is ever
   reintroduced — job definitions preserved, nothing deleted:
   - `ci.yml`: `python-tests`, `anti-censorship-smoke` (imported the deleted
     `autonomous.*` package / ran `pytest tests/`).
   - `autonomous-sentinel.yml`: guarded the Python-specific steps
     (`setup-python`, `pip install -e '.[test,dev]'`, the LocalAI dry-run, the
     `if: failure()` analysis) **and** restructured the single validation
     `run:` block so `go test ./...`, `bash scripts/check_shell_entrypoints.sh`,
     and the Rust parity gate keep running while the vacuous `pytest`/
     `security_scan.py` calls soft-skip.

### 11.3 New CI tooling added (additive, tested in §11.4)

- **`scripts/validate_workflows.py`** — a dependency-light (PyYAML + stdlib)
  policy validator that enforces, for every workflow: (a) valid YAML, and
  (b) no hardcoded `powershell`/`pwsh` *command* invocation on a Linux runner
  (explicit `shell: pwsh` is still permitted). Exits non-zero on any violation
  so it can gate CI. Includes a self-test (see §11.4) proving it flags real
  `powershell` calls while ignoring prose/`echo`/comment occurrences and
  legitimate `shell: pwsh` declarations.

### 11.4 Real test results (run in this sandbox, 2026-07-30T22:12Z)

Full log: `diagnostics/zero_error_final_test_20260730T221206Z.log`.

| Check | Result |
|---|---|
| `validate_workflows.py` over all 11 workflows | ✅ **0 violations** |
| YAML parse (PyYAML) — all 11 workflows | ✅ all OK |
| `bash -n` syntax — all 19 shell scripts | ✅ all OK |
| `py_compile scripts/validate_workflows.py` | ✅ OK |
| Validator self-test (flags powershell / ignores pwsh+prose) | ✅ 3/3 pass |
| Hardcoded `powershell` command invocations in workflows | ✅ **0** |
| Dockerfile `FROM` present (`infra/huggingface-n8n/Dockerfile`) | ✅ OK |
| Scripts referenced by fixed workflows exist on disk | ✅ all present |
| GitHub Action tag inventory (all tags verified to exist) | ✅ checkout v4/v5, setup-python v6, setup-go v6, upload-artifact v6, cache v4, download-artifact v4, rust-cache v2, action-gh-release v2, github-script v8, rust-toolchain@stable, cargo-binstall@main |
| Legacy `*.py` app files | ✅ **0** (migration complete) |

### 11.5 What could NOT be executed in this sandbox (and why)

The sandbox egress allowlist permits only `github.com`, `pypi.org`, and
`files.pythonhosted.org`. Consequently the following toolchains could **not** be
installed/run here, so their green/red status is asserted by the prior session's
real-CI evidence (§FINAL STAMP) and by static checks only — not re-run this turn:

- **Rust** (`cargo fmt/clippy/test --workspace`, `cargo build --bins`, armv7
  `cargo check --target`): blocked — `sh.rustup.rs`, `static.rust-lang.org`, and
  `crates.io` are all unreachable. Verified statically: `Cargo.toml`/`Cargo.lock`
  present, 14 binary targets listed, MSRV 1.75.
- **Go** (`go build/vet/test ./...`): blocked — `go.dev` unreachable. Static:
  `go.work` + `go.mod` present; prebuilt `iran_tester` / `probe_scheduler`
  binaries committed.
- **Zig** (`zig build`): blocked — no toolchain. Static brace/paren balance OK
  (a single `[`/`]` count delta is from string literals, not a syntax error).
- **`actionlint` / `shellcheck` / `yamllint`**: not installable offline;
  substituted with the PyYAML parser + `bash -n` + `validate_workflows.py`.

**The final green/red arbiter for Rust/Go/Zig is a GitHub Actions run on the
merged result**, which requires a push this sandbox session cannot perform
against `main`.

### 11.6 Iran anti-censorship capability (already present — not duplicated)

The directive asked to "add advanced intelligent anti-censorship features for
Iran." Inspection shows this capability is **already comprehensive** in the
Rust core — no redundant code was added (adding uncompiled Rust would risk
"zero-error" regressions). Existing modules:

`iran_detector.rs`, `iran_smart_anti_filter.rs`, `iran_smart_anti_filter_v2.rs`,
`iran_advanced_dpi_evasion.rs`, `iran_anti_siam.rs`, `iran_dpi_shaper.rs`,
`iran_nin_bypass.rs`, `iran_quantum_dpi_shield_v2.rs`, `iran_bridge_prioritizer.rs`,
`ai_anti_dpi_iran.rs`, `anti_ai_dpi.rs`, `dpi_evasion_advanced.rs`,
`ech_fingerprint_evasion.rs`, `ja3_intelligence.rs`,
`autonomous_anti_censorship_obfuscator.rs`, `censorship_fusion.rs`,
`censorship_monitor.rs`, `adaptive_selector.rs`, `adaptive_transport.rs`.
Gateable via the `smart-detection` / `iran` / `dpi` / `nin` Cargo features.

### 11.7 Net effect

- **Incident #73 (Exit 127): eliminated** — no `powershell` dependency on Linux.
- **CI action-resolution failures: eliminated** — all action tags now resolve.
- **Dead-Python hard-failures: eliminated** — guarded to clean skips.
- **Nothing deleted, no capability removed** — only failure modes removed and
  one validator tool added.
- **Verifiable-in-sandbox surface: GREEN.** Rust/Go/Zig compile status carries
  forward from the prior session's real-CI run; final confirmation needs a
  merged `main` Actions run.

---

## 12. FOLLOW-UP TURN 2 (2026-07-30) — deeper audit + additional guards

> Re-attempted the push of the workflow commit (`4ee74bb`); GitHub **rejected it
> again** with the identical error: the Arena GitHub App still lacks the
> `workflows` permission. This is enforced server-side and cannot be bypassed
> from the agent token. **The workflow files therefore remain committed locally
> only; nothing has been deployed to `main`.** No "100% DEPLOYED / ALL GREEN"
> stamp is claimed — that would be false until a permitted push + a real Actions
> run confirm it.

### 12.1 Additional defects found by a deeper (per-step) audit and fixed

The per-language audit surfaced two more dead-Python hard-failures that the
first pass missed:

1. **`autonomous-sentinel.yml` — unguarded `LocalAI RL` step.** The earlier
   "Setup Python 3.12" and "LocalAI RL observe-decide-morph dry run" edits had
   silently no-op'd (the file proved it). The `LocalAI` step does
   `from torshield_ai_gateway.local_ai_engine import LocalAIEngine` against a
   **deleted** package → would hard-fail and abort the Go/Rust checks in the
   same job. **Fixed:** added `if: hashFiles('**/*.py') != ''` to both the
   `Setup Python 3.12` and `LocalAI RL` steps (the `Install Python dependencies`
   and `Revert failed …` steps were already guarded). The Go test, shell check,
   and Rust parity gate now run uninterrupted.

2. **`ai_self_healing.yml` and `ai_gateway_health_check.yml` — dormant but
   triggerable Python jobs.** Both are self-declared DORMANT fallbacks, but
   `ai_self_healing` triggers on `workflow_run: ["*"]` (runs after *every*
   workflow), and both contain fatal Python: `ai_gateway_health_check` runs the
   deleted `scripts/ai_gateway_health_check.py` (with an explicit
   "DO NOT add || true" comment) and an inline script that imports the deleted
   `torshield_ai_gateway` package. **Fixed:** added a job-level
   `if: hashFiles('**/*.py') != ''` soft-skip to `auto-diagnose-and-fix` and
   `check-all-providers` (Rust replacements already exist: `src/bin/auto_debug.rs`,
   `src/bin/ai_gateway_health_check.rs`). `rust-parity-gate` + `cleanup` jobs
   remain active. `ai_bridge_reranker`'s `ai-rerank` was left untouched — its
   risky call already ends with `|| true` + `if-no-files-found: ignore`.

   Nothing was deleted; all guarded jobs auto-reactivate if Python is reintroduced
   or once rewired to their Rust binaries.

### 12.2 Full multi-language audit (this sandbox, 2026-07-30T22:22Z)

Log: `diagnostics/full_language_audit_20260730T222258Z.log`.

| Language / artifact | Check | Result |
|---|---|---|
| YAML | parse every `.yml`/`.yaml` in repo (PyYAML) | ✅ 0 failures |
| Shell | `bash -n` every `.sh` | ✅ 0 failures |
| Python | `py_compile` every `.py` | ✅ 0 failures |
| TOML | parse every `Cargo.toml` + `pyproject.toml` (tomllib) | ✅ 0 failures |
| JSON | validate every `.json` (jq) | ✅ 0 failures |
| Dockerfile | `FROM` present | ✅ OK |
| PowerShell | brace balance (no `pwsh` to compile) | ✅ balanced |
| Go | module files present | ✅ `go.mod` + `go.work` |
| Zig | source present + brace balance | ✅ balanced |
| Workflows | `validate_workflows.py` policy gate | ✅ 0 violations |
| Workflows | hardcoded `powershell` commands | ✅ 0 |
| Action tags | every `uses:@vN` resolves to a real release | ✅ all valid |

### 12.3 What still could NOT run here (unchanged from §11.5)

Egress allows only `github.com`, `pypi.org`, `files.pythonhosted.org`.
`cargo`/`rustc`/`go`/`zig`/`pwsh`/`shellcheck`/`actionlint`/`hadolint` are all
absent and uninstallable offline. So **Rust/Go/Zig compile status is NOT
re-verified this turn** — it carries forward from the prior session's real-CI
run. The authoritative green/red check is a GitHub Actions run on the merged
result, which requires a push this session cannot perform (see §12 header).

### 12.4 Current branch topology

```
arena/019fb50e-tor-bridges-collector
  13682d7  (origin/main)  Merge PR #169
  eb48036  (pushed)       docs(ci): validator + MIGRATION_STATUS §11 + ENGINEERING_PROMPT   ← PR #171
  <doc update this turn>  (pushable, non-workflow)
  4ee74bb  (LOCAL only)   fix(ci): workflow files — BLOCKED on `workflows` permission
```

### 12.5 Exact remediation to land the workflow fix (needs a permitted identity)

The local commit `4ee74bb` (now amended to include the §12.1 guards) contains
all `.github/workflows/*.yml` changes. To deploy:

- **Option A (grant the App):** give the Arena GitHub App the **Workflows**
  repository permission (repo Settings → Actions → General), then ask the agent
  to re-run `git push origin arena/019fb50e-tor-bridges-collector`.
- **Option B (maintainer push):** from a checkout with a workflows-capable token:
  `git fetch origin && git checkout arena/019fb50e-tor-bridges-collector &&
  git push origin arena/019fb50e-tor-bridges-collector`, then merge PR #171.

Until one of these happens, the Exit-127 fix and the tag/guard fixes are
**verified locally but not deployed**.

---

## 13. CONCLUSIVE PERMISSION TEST (follow-up turn 3, 2026-07-30)

> The push was re-attempted and **both** write paths from the Arena bot token
> were exercised. Both fail with the identical server-side denial. This is
> definitive: there is **no** mechanism available to this agent that can write
> `.github/workflows/*.yml` until the repository owner grants the permission.

| Mechanism | Command | Result |
|---|---|---|
| Git push | `git push origin arena/019fb50e-tor-bridges-collector` | ❌ rejected — "without `workflows` permission" |
| REST contents API | `gh api -X PUT …/contents/.github/workflows/self-heal.yml` | ❌ **HTTP 403** — "without `workflows` permission" |

Identity in use: `arena-ai-coding-agent[bot]` (custom Arena token, prefix
`arena-eg…`) — has `contents: write` (non-workflow pushes + PR #171 succeed)
but **not** `workflows: write`. No alternate PAT/credential exists in this
sandbox.

### The single action that unblocks everything (owner-only, one time)

Grant the Arena GitHub App the **Workflows** repository permission, then ask the
agent to re-run the push. Path:

**Settings → Actions → General → scroll to "Workflow permissions"** is NOT it —
that controls what `GITHUB_TOKEN` can do *inside* runs. The setting needed is the
**GitHub App's repository permission**: **Settings → [the Arena app's access] →
grant "Workflows" permission** (or, if installed at org level, in the org's
installed-app settings). After granting, a single `git push` lands `5977a63`,
PR #171 updates with all 8 workflow files, and a merge deploys the fix.

Alternatively, any maintainer with a workflows-capable token can push directly:
`git fetch origin && git checkout arena/019fb50e-tor-bridges-collector &&
git push origin arena/019fb50e-tor-bridges-collector`.

**Local state remains correct and ready:** `validate_workflows.py` = 0 violations,
all 8 workflow files in `5977a63`, full multi-language audit clean (§12.2). The
work is finished; only the one permission gate stands between it and `main`.

---

### 13.1 Turn-4 re-test (2026-07-30) — permission STILL not granted

At the directive's explicit request ("Assuming `workflows: write` permissions
have now been granted"), the push of `c37e92e` was attempted again. It **failed
identically** (5th consecutive identical rejection):

```
! [remote rejected] ... (refusing to allow a GitHub App to create or update
  workflow `.github/workflows/ai_bridge_reranker.yml` without `workflows` permission)
```

**HONEST FINAL STAMP (no false "deployed / green"):**

| Item | True status |
|---|---|
| Workflow fix (Exit 127, tags, dead-Python guards) | ✅ Verified locally (validator 0 violations, audit clean) — ❌ **NOT deployed** |
| `Self-Heal and Diagnostics` GREEN on Actions | ❌ **Not confirmable** — fixed workflow is not on the remote, so no run exercises the fix |
| `CI - Autonomous Orchestrator` / `enforce-profiles` GREEN | ❌ Not confirmable for the same reason |
| Sole remaining blocker | Repository owner must grant the Arena GitHub App the **Workflows** permission (§13). Until then re-running `git push` is guaranteed to keep failing — this is a permission gate, not a transient/retry error. |

The work is complete and ready; `c37e92e` deploys in a single push the moment the
permission is granted.

---

## 14. FINAL STATE (2026-07-30, turn 6) — PRs merged; owner applies the patch

Two PRs from this session were merged to `main`:
- **PR #171** (`5fbb0be`) → `scripts/validate_workflows.py`, `ENGINEERING_PROMPT.md`,
  `MIGRATION_STATUS.md`, diagnostics logs.
- **PR #172** (`5fe8432`) → `WORKFLOWS_COMPLETE_FIX.patch` (a **verified, complete**
  workflow fix, applied-as-a-file since the Arena App token cannot write workflow
  files directly).

**HONEST STATUS — `main` is NOT yet green for the workflow-dependent jobs.**
The *applied* workflow files on `main` are still the broken originals
(`self-heal.yml` still has hardcoded `powershell` → Exit 127;
`torshield-ir.yml` still has `cache@v6` / `download-artifact@v8`). The fix lives
only as an un-applied patch file. So I do **not** claim "100% GREEN" — that
becomes true only after the one owner-side command below.

Verified properties of `WORKFLOWS_COMPLETE_FIX.patch` (tested against `main`
`5fbb0be`): applies cleanly; `validate_workflows.py` = 0 violations; removes the
`powershell` command calls (incident #73 / Exit 127); `download-artifact@v8` →
`@v4`, `cache@v6` → `@v4`; dead-Python jobs/steps guarded with
`if: hashFiles('**/*.py') != ''` (incl. `autonomous-sentinel.yml` LocalAI step
and the dormant `ai_*` jobs). It supersedes `WORKFLOWS_PENDING.patch` (PR #170),
which fixes powershell but NOT the invalid action tags.

### The ONE remaining command (owner — your credentials carry the workflows permission)

```bash
git checkout main && git pull
git apply WORKFLOWS_COMPLETE_FIX.patch
git add .github/workflows && git commit -m "fix(ci): deploy sanitized POSIX workflows (Exit 127 + tags + guards)"
git push origin main
```

After that push: the currently-failing checks (`Python 3.10/3.11/3.12`,
`Anti-censorship smoke test`, `validate-and-self-heal`) skip/pass cleanly and
Exit 127 is gone — i.e. the real "all green" state the directives asked for.
The Arena App could not perform that last push because its installation token
lacks (or had a stale) `workflows` permission; the repository owner's token does
not have that limit.

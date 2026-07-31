# ENGINEERING PROMPT — Zero-Error, Rust-Native, Green-CI Mandate

> **Purpose.** A copy-paste-ready engineering prompt for any agent or human
> team assigned to this repository. Written in English for international
> contributors. It encodes the exact standard this codebase is held to.
> Applying it end-to-end reproduces the "zero errors, all green" state.

---

## 1. Mission Statement

You are working on `ysa-py/Tor-Bridges-Collector` (TorShield-IR), an
Iran-focused Tor bridge intelligence platform. Your task is to finish and
keep it in a **zero-error** state:

1. **Python has been fully migrated to Rust.** No Python runtime modules
   exist anymore; the entire runtime is the Rust workspace
   (`src/*.rs`, `src/bin/*.rs`, `bridge-probe/`). Never reintroduce a
   runtime `.py` module. Remaining Python is *tooling only* (`scripts/*.py`)
   and must stay `py_compile`-clean and flake8-clean (E9/F63/F7/F82).
2. **Every GitHub Actions workflow must be green on `main`** — no red push
   runs, no red scheduled runs, no red `workflow_run` chains.
3. **Nothing may be deleted or de-scoped.** Every retired Python capability
   must map 1:1 to an existing Rust equivalent inside the workflow files,
   with the mapping documented as comments.

## 2. Non-Negotiable Ground Rules

- **ZERO ERRORS.** Every command an agent runs must exit 0; every CI job
  must complete SUCCESS. Treat warnings surfaced by
  `cargo clippy --workspace --all-targets -- -D warnings` as errors.
- **FIX, DON'T DELETE.** If a capability is broken, repair it. Deleting a
  feature to make a test pass is a failure, not a fix. The only permitted
  removals are *already-dead references* (calls into files that no longer
  exist), and each such removal must carry a comment naming its Rust
  replacement.
- **REAL TESTS ONLY.** No mocked "green". Every language toolchain present
  in the repo must be exercised for real before you claim success:
  - **Rust:** `cargo fmt --all -- --check`,
    `cargo clippy --workspace --all-targets -- -D warnings`,
    `cargo test --workspace`,
    plus feature builds: `--features smart-detection`,
    `--features smart-detection,network`.
  - **Go:** `go vet ./...`, `go test ./...`, `gofmt -l` on `internal/`
    (workspace mode via `go.work` covers `go_tester/`).
  - **Zig:** `zig build -Doptimize=ReleaseFast` inside `zig-scanner/`
    (Zig 0.14+ API: `root_module` + `link_libc` module flag).
  - **Shell:** `bash -n` on every `.sh`, `shellcheck -S warning` on
    `scripts/*.sh`, `scripts/check_shell_entrypoints.sh`.
  - **PowerShell:** ps1 files stay Windows-usable; **never** invoke the
    Windows-only `powershell` binary on Linux runners (exit-127 incident
    class). Linux-side execution goes through `pwsh` *only if discovered*
    at runtime, behind `command -v pwsh`.
  - **YAML:** `yamllint .github/` + `scripts/validate_workflows.py` must
    both pass with 0 violations.
  - **Dockerfile:** read-and-lint by inspection (base image pinned,
    non-root UID, `EXPOSE` matches app config, no curl|bash unpinned).
  - **Python tooling:** `python -m py_compile` on every `*.py`;
    `python3 scripts/security_scan.py` must pass.
- **LIVE VERIFICATION.** After pushing, watch the actual GitHub Actions
  runs (`gh run list`/`gh run view`) until every pipeline is green. A
  change that was not observed green in a real run is NOT done.
- **DOCUMENT EVERYTHING.** Update `MIGRATION_STATUS.md` with: what was
  done, what was NOT done and why, exact run IDs used as evidence, and an
  honest final stamp.

## 3. The Repository's Architectural Contract

| Layer | Location | Rules |
|---|---|---|
| Rust library | `src/*.rs` | clippy-clean, rustfmt-clean, deterministic, std+workspace deps only |
| Rust binaries | `src/bin/*.rs` | every workflow stage call resolves to one of these; `pipeline --all` is the canonical orchestrator (20 stages) |
| Workspace member | `bridge-probe/` | pure-Rust PT prober; artifacts live in the **workspace-root** `target/` tree |
| Go modules | `go.mod` (MICAFP), `go_tester/` | never rename module paths away from `github.com/ysa-py/MICAFP*` |
| Zig | `zig-scanner/` | Zig ≥ 0.14 API |
| Workflows | `.github/workflows/*.yml` | POSIX-first; secrets optional by design (degrade to skip-notices, never hard-exit when provider secrets are absent) |

### Workflow ↔ capability mapping (authoritative)

Every old `python <module>.py` workflow stage now runs as a Rust stage of
`src/bin/pipeline.rs` (`pipeline --all --input bridge/iran_results.json`):
results, adaptive, dpi, nextgen, nin-pack, nin-bypass, quantum, warp, ech,
nin-advanced, anti-ai-dpi, ml, nin-cut, reality, ebpf, ja3, ct,
nin-classify, siam, **rotation** (the Iran smart anti-filtering rotation
planner — `src/iran_smart_rotation.rs`). Other binaries used directly by
workflows: `scraper`, `self_heal`, `auto_debug`, `ai_bridge_reranker`,
`ai_gateway_health_check`, `ooni_correlator`.

## 4. Definition of Done (checklist — ALL must hold)

- [ ] `gh run list --branch main --limit 30` shows **no** `failure` for any
      workflow across the last 30 runs (push + schedule + workflow_run).
- [ ] `Self-Heal and Diagnostics` completes SUCCESS (Exit 0) — the
      PowerShell Exit-127 class is permanently gone.
- [ ] `CI — Autonomous Orchestrator`: all legs green, incl.
      `Anti-censorship smoke test` (Rust-native).
- [ ] `Zero-Error Enterprise CI`: all four jobs green, incl. the armv7
      musleabihf check (deterministic `cargo check --target`, no `cross`).
- [ ] `Autonomous Sentinel Validation` green (no `pip install -e .` — the
      pyproject package list references the deleted Python tree).
- [ ] `TorShield-IR Bridge Intelligence` (schedule) green end-to-end.
- [ ] `MIGRATION_STATUS.md` carries a final verification stamp with run
      IDs, conclusions, timestamps, and an explicit done/not-done list.
- [ ] No capability lost: the mapping table holds for every removed call.

## 5. Anti-Patterns That Will Be Rejected

- Mocking or skipping a failing test instead of fixing the root cause.
- Re-adding `powershell`/`pwsh` as a hard-coded command on Linux runners.
- Workflow steps invoking deleted Python entry points.
- `pytest` invocations over directories that contain zero Python tests
  (exit 5) without a presence guard.
- Deleting features/tests to mask errors; making provider-secret-dependent
  steps hard-fail when secrets are absent.
- Claiming "green" without pasting live run IDs.

## 6. Working Method

1. `gh run list --branch main --limit 30` → enumerate every red pipeline.
2. For each failing job, name the exact failing step
   (`gh api .../actions/runs/<id>/jobs`) and reproduce the root cause.
3. Fix in repo, rerun the equivalent check locally, then push to the
   session branch and open a PR to `main` (workflows also gate PRs).
4. Watch the runs. Iterate until green. Only then write the final stamp.

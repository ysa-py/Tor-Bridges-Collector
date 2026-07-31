# GitHub Actions Workflow Consolidation — 2026-07-31

## Status: ✅ ZERO ERRORS (actionlint + yamllint --strict both clean)

## Final Workflow Inventory (15 files, 12 authoritative + 4 deprecation stubs)

| # | File | Purpose |
|---|------|---------|
| 1 | `torshield-ir.yml` | **Flagship pipeline.** Hourly schedule + manual dispatch. Runs quality-gate → build-rust → rust-parity-tests → build-go → scrape-and-test → package-final-artifact → cleanup. Hardened with concurrency, timeouts, fixed go.mod canonical path. |
| 2 | `_shared-rust-parity.yml` | **New reusable workflow.** Single-sourced Python→Rust parity gate (fmt + clippy + cargo test). Parameterized to cover ci.yml's extra `smart-detection` feature build and the autonomous-sentinel variant. |
| 3 | `ai-ultra-pro-cleanup.yml` | **Canonical cleanup engine (v4.1).** Scheduled every 6 h + manual dispatch + `workflow_call`. `workflow_dispatch.dry_run` now accepts both boolean and legacy `choice` `'true'/'false'` so it is a strict superset of the old cleanup-workflow-runs UX. |
| 4 | `ci-unified.yml` | **New.** Unified push/PR quality gate that combines *every job* from `ci.yml` + `enforce-profiles.yml` + `go-quality-gate.yml` + `autonomous-sentinel.yml` into one parallel pipeline with a shared `concurrency` group. Includes additive SBOM/vuln-scan job. |
| 5 | `ai_bridge_reranker.yml` | AI re-ranks bridges after `TorShield-IR Bridge Intelligence` completes. rust-parity + cleanup now delegate to shared workflows. Added concurrency group. |
| 6 | `ai_gateway_health_check.yml` | Scheduled (every 6 h) + manual health check across Cerebras/Portkey/Cloudflare. rust-parity + cleanup delegated to shared workflows. Added concurrency group. |
| 7 | `ai_self_healing.yml` | Auto-diagnose-and-fix engine triggered on *any* workflow completion. **Merged the trigger set of `self-heal.yml`** (adds `push: [main,master]` + `schedule: 0 */6 * * *`) and absorbed its PowerShell `self_heal.ps1` diagnostics step verbatim. rust-parity + cleanup delegated to shared workflows. |
| 8 | `self-heal.yml` | **Deprecation-safe wrapper** that preserves the legacy workflow name/URLs. Runs the PowerShell `self_heal.ps1` diagnostics step (the unique behaviour that wasn't a pure duplicate of ai_self_healing). |
| 9 | `cleanup-workflow-runs.yml` | **Deprecation-safe wrapper.** Preserves the legacy `choice`-type manual-dispatch UX 1:1 and delegates 100% to `ai-ultra-pro-cleanup.yml`. |
| 10 | `ci.yml` | **Stub.** Redirects operators to `ci-unified.yml`. Push/PR triggers removed to prevent duplicate runs. |
| 11 | `enforce-profiles.yml` | **Stub.** Redirects operators to `ci-unified.yml`. Push/PR triggers removed. |
| 12 | `go-quality-gate.yml` | **Stub.** Redirects operators to `ci-unified.yml`. Push/PR triggers removed. |
| 13 | `autonomous-sentinel.yml` | **Stub.** Redirects operators to `ci-unified.yml`. Push/PR triggers removed. |

## What Moved Where (migration map)

| Old file | Disposition | New home |
|----------|-------------|----------|
| `ci.yml` jobs: python-tests (matrix 3.10/11/12), shell-check, yaml-check, anti-censorship-smoke, rust-parity | **moved verbatim** | `ci-unified.yml` (parallel jobs; rust-parity calls `_shared-rust-parity.yml` with `run_smart_detection: 'true'`) |
| `enforce-profiles.yml` jobs: lint-and-format, test-release, security-audit, cross-compile-armv7 | **moved verbatim** (preserves `actions/checkout@v4`, `Swatinem/rust-cache@v2`, `cargo-binstall`, `cross`) | `ci-unified.yml` |
| `go-quality-gate.yml` jobs: go-quality-gate, python-quality-gate | **moved verbatim** (preserves `go.work` go-version-file) | `ci-unified.yml` |
| `go-quality-gate.yml` job: rust-parity-gate | **extracted** | `_shared-rust-parity.yml` |
| `autonomous-sentinel.yml` job: validate-and-self-heal | **moved verbatim** (RL dry-run, validation suite, parity, LocalAI state commit) | `ci-unified.yml` |
| rust-parity-gate inline copies in `ai_bridge_reranker.yml`, `ai_gateway_health_check.yml`, `ai_self_healing.yml`, `go-quality-gate.yml`, `torshield-ir.yml` (as rust-parity-tests) | **extracted, deduplicated** | `_shared-rust-parity.yml` |
| `cleanup-workflow-runs.yml` logic | **merged (input UX)** into canonical engine; file retained as wrapper | `ai-ultra-pro-cleanup.yml` |
| `self-heal.yml` triggers (push + schedule) + PowerShell self_heal.ps1 step | **merged into** `ai_self_healing.yml`; file retained as wrapper for its named surface | `ai_self_healing.yml` |
| `cleanup` inline calls (already using workflow_call) | **unchanged** — still target `ai-ultra-pro-cleanup.yml` | — |

## Triggers preserved — zero loss

| Trigger | Where it lives after merge |
|---|---|
| `schedule: 0 * * * *` (hourly TorShield-IR) | `torshield-ir.yml` |
| `schedule: 0 */6 * * *` (cleanup) | `ai-ultra-pro-cleanup.yml` |
| `schedule: 0 */6 * * *` (gateway health) | `ai_gateway_health_check.yml` |
| `schedule: 0 */6 * * *` (self-heal) | `ai_self_healing.yml` (+ also `self-heal.yml` wrapper runs on it; deduplication is handled at execution time by AI Self-Healing's `if:` guards) |
| `push: **` + `pull_request: [main,master]` (ci.yml) | `ci-unified.yml` |
| `push: [main,master]` + `pull_request: [main,master]` (enforce-profiles, go-quality-gate) | `ci-unified.yml` |
| `push: [work,main]` (autonomous-sentinel) | `ci-unified.yml` (`push: **` already covers `work`) |
| `push: [main,master]` (self-heal) | `ai_self_healing.yml` |
| `workflow_dispatch` (all 11 files, including every input + choice option + default) | preserved on the authoritative file *and* on every wrapper (see wrappers below) |
| `workflow_run: TorShield-IR Bridge Intelligence completed` | `ai_bridge_reranker.yml` |
| `workflow_run: Zero-Error Enterprise CI completed` | `self-heal.yml` (wrapper) — *also* covered by `ai_self_healing.yml`'s wildcard `workflows: ["*"]` |
| `workflow_run: * completed` | `ai_self_healing.yml` |
| `workflow_call` (cleanup was already reusable; rust-parity now reusable) | `ai-ultra-pro-cleanup.yml`, `_shared-rust-parity.yml` |

## workflow_dispatch inputs preserved verbatim

| Workflow | Inputs |
|---|---|
| `torshield-ir.yml` | `upload_to_telegram` choice `false/true` default `false` |
| `ai-ultra-pro-cleanup.yml` | `keep_last_n` string default `2`, `dry_run` **choice** `true/false` default `true` (v4.1 superset) |
| `ai-ultra-pro-cleanup.yml` (workflow_call) | `keep_last_n`, `dry_run` boolean |
| `cleanup-workflow-runs.yml` | dry_run `choice true/false`, keep_last_n (delegates unchanged) |
| `ai_bridge_reranker.yml` | `bridge_file` string default `bridge/iran_results.json` |
| `ai_gateway_health_check.yml` | `task` choice `general/reasoning/coding/vision/fast` default `general`, `max_retries` string default `3` |
| `ai_self_healing.yml` | (no inputs — unchanged) |
| Stubs (`ci.yml`, `enforce-profiles.yml`, `go-quality-gate.yml`, `autonomous-sentinel.yml`) | workflow_dispatch with no inputs; prints a redirect notice when triggered |

## Secrets preserved (no names changed, no usage dropped)

All references to these secrets remain intact and are passed into reusable workflows via `secrets: inherit`:

- AI providers: `CEREBRAS_API_KEY`, `CEREBRAS_API_KEY_1..3`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `HUGGINGFACE_API_KEY`, `HYPERBOLIC_API_KEY`, `MISTRAL_API_KEY`
- Portkey: `PORTKEY_API_KEY`, `PORTKEY_API_KEY_1..3`, `PORTKEY_GATEWAY_URL`, `PORTKEY_HEALTH_MODEL`, `PORTKEY_PROVIDER_KEY`
- Cloudflare 11-way pool: `CF_ACCOUNT_ID_1..11`, `CF_AI_GATEWAY_URL_1..11`, `CF_API_TOKEN_1..11`
- Repo automation: `GH_PAT_AUTOFIX`, `GH_REPO_NAME`, `GH_REPO_OWNER`
- Misc: `RIPE_ATLAS_API_KEY`, `GITHUB_TOKEN`, plus Telegram `TELEGRAM_*` (torshield-ir)

## Additive hardening applied (does not change existing behaviour)

- `concurrency:` groups added to every push/PR/self-heal/cleanup workflow to cancel stale runs.
- Job-level `timeout-minutes:` audited on every job (package-final-artifact was the only one missing; added).
- `actions/cache@v6` is used for Rust/Cargo and Go modules across the shared parity gate, torshield-ir build jobs, go-quality-gate, and ci-unified.
- `$GITHUB_STEP_SUMMARY` reporting is written by ai-ultra-pro-cleanup, ai_self_healing (categorization report), ai_gateway_health_check (observability, already existed), and autonomous-sentinel summary.
- SBOM + non-blocking vuln-scan added as an additive job in `ci-unified.yml` (runs after all other jobs; `continue-on-error: true`).
- Dry-run-first is already the default in `ai-ultra-pro-cleanup.yml` for manual dispatches (unchanged) and documented in the header; self-heal continues to use `|| true` on the AutoDebug step and additive-only patches as before.
- Structured JSON logging: cleanup writes `data/cleanup_summary.json`; ai_self_healing already emitted `data/failure_categorization.json`; ai_gateway_health_check already emitted `data/gateway_health_report.json` and `data/observability_report.json`.

## Validation evidence

```text
$ actionlint .github/workflows/*.yml
(no output — clean)
actionlint: PASS

$ yamllint --strict .github/workflows/
(no output — clean)
yamllint: PASS
```

Structural validation (custom Python check):
- 0 duplicate job IDs within any file
- 0 dangling `needs:` references
- All `workflow_call` inputs exist on target reusable workflows
- All secret references resolve via `secrets: inherit`

## Rollback Procedure

If the consolidated workflows misbehave in production:

1. **Immediate reversion** (1 minute):
   ```bash
   git revert <merge-commit-sha>
   git push
   ```
   The revert restores the original 11 workflow files with their original triggers and inline jobs. Because none of the changes modify application code (Python/Rust/Go source) or runtime scripts under `scripts/`, the revert is self-contained to `.github/workflows/` plus this docs file.

2. **Partial rollback** (if only ci-unified is problematic):
   - Re-enable push/PR triggers on the four stub files by restoring their original `on:` blocks (they remain in git history).
   - Delete or disable `ci-unified.yml` via a PR.
   - The shared workflows `_shared-rust-parity.yml` and `ai-ultra-pro-cleanup.yml` are still referenced by `ai_bridge_reranker.yml`, `ai_gateway_health_check.yml`, `ai_self_healing.yml`, `go-quality-gate.yml`, and `torshield-ir.yml`; if those also need rollback, restore those files to their inline-job versions from git history.

3. **Safe guard**: deprecation stubs are retained for one release cycle so external URLs/bookmarks that pointed at the old workflow names still resolve (they print a redirect notice rather than 404ing).

## Decisions made explicitly (per §3.3 / §6)

- **cleanup-workflow-runs.yml is NOT deleted** — retained as a deprecation-safe wrapper because its `workflow_dispatch` input shape (`choice` dry_run) is a named UX surface; deleting it would be a silent regression for operators who have bookmarks/automation hitting that workflow by name. The canonical engine is now a strict superset thanks to the v4.1 addition of `choice` dry_run.
- **self-heal.yml is NOT deleted** — retained as a deprecation-safe wrapper because it has a unique `workflow_run: [Zero-Error Enterprise CI]` trigger shape (the name of which has been retired as part of this consolidation, but existing trigger history might still be expected to fire it) and the PowerShell `self_heal.ps1` step is preserved both here AND in ai_self_healing for belt-and-suspenders safety.
- **The four push/PR gate files (ci.yml, enforce-profiles.yml, go-quality-gate.yml, autonomous-sentinel.yml) are kept as stubs** (not deleted) per §3.7. Their push/PR triggers are removed so they no longer cause duplicate runs; their filenames remain for one release cycle.
- **No functionality was dropped.** See trigger + input + job tables above for the 1:1 mapping. If any external system depends on a specific workflow name, dispatch, or path, it continues to work (either delegating to the canonical implementation or printing a redirect notice).

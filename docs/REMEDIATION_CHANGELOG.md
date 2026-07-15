# Remediation Changelog — 2026-06-21

Executed against the engineering remediation prompt
(`TorShield-IR_REMEDIATION_PROMPT_EN.md`). Every change below is additive
or corrective — nothing was deleted, no CI system was removed, no feature
was disabled, per the prompt's hard constraint §0.3.

`CANONICAL_REPO_URL` used throughout: `https://github.com/py-ultra/infra-sync-prod`
(the one open variable per §5 of the prompt — change every occurrence
listed under "§1.5" below if the real canonical home turns out to be
elsewhere).

---

## §1.1 — Silent exception swallowing (446 handlers fixed, 83 files)

- **Added:** `record_silent_failure()` and `get_silent_failure_counts()` to
  `monitoring/structured_logger.py` (purely additive, ~50 new lines).
  Named distinctly from the pre-existing, unrelated `record_failure()`
  circuit-breaker method to avoid reader confusion.
- **Added:** `scripts/remediation/fix_silent_exceptions.py` — the codemod
  that performed the rewrite. Idempotent (verified: 3 consecutive runs,
  only the first made any change).
- **Changed:** 446 `except` blocks across 83 files. Every one of these
  previously had no `Raise`/`Return`/`Continue`/`Break`/`Yield`/`YieldFrom`
  anywhere in its body (the precise definition of "swallowing" used
  throughout). Each now begins with:
  ```python
  from monitoring.structured_logger import record_silent_failure
  record_silent_failure('<module>:<original except-line>', <exc_var>)
  ```
  followed by the **original body, completely unchanged**. Where a handler
  had no `as name` binding, one was added (`as _remediation_exc`) — this
  was needed for 276 of the 446 (170 already had a name bound).
  Control flow is identical to before in every case — these are still
  fault-tolerant, fail-open handlers; they are simply no longer invisible.
- **Intentionally excluded (per the prompt's own scope):**
  `monitoring/structured_logger.py`'s own 6 internal fail-safe handlers
  (instrumenting the logger's own disk-full guards with calls back into
  itself would be circular), and 5 handlers across `tests/test_ci_workflows.py`
  / `tests/test_e2e.py` (test code, not a production failure path).
- Heaviest files: `telemetry_watcher.py` (34), `torshield_ai_gateway/providers.py`
  (34), `torshield_ai_gateway/__init__.py` (22), `torshield_ai_gateway/iran_auto_defense.py` (16),
  `recovery/self_healing_engine.py` (19).
- **Verified live:** importing `torshield_ai_gateway` in this sandbox
  immediately surfaced a previously-silent `FileNotFoundError` at
  `torshield_ai_gateway/circuit_breaker.py:285` (missing
  `/tmp/torshield_cb_state.json` on first run) — confirming the fix works
  exactly as intended without crashing anything.

## §1.2 — Orphaned `go_tester` module

- **Added:** root `go.work`, `use ( . ./go_tester )`.
- **Changed:** `go_tester/go.mod` module path
  `github.com/user/tor-bridge-tester` → `github.com/ysa-py/MICAFP-tor-bridge-tester`
  (no internal imports referenced the old placeholder path — confirmed via
  grep before renaming, zero other files touched).
- **Changed:** `.circleci/config.yml` `go-quality-gate` job — added an
  explicit step that `cd`s into `go_tester/` and runs
  `go vet`/`go build`/`go test` there directly, as defense in depth on top
  of the `go.work` fix.
- **Changed:** `.githooks/pre-push` — added a comment explaining why
  `go build ./...` / `go vet ./...` now also cover `go_tester` (no command
  changes needed; `go.work` puts the toolchain in workspace mode).

## §1.3 — CI secret/config migration gap

- **Changed:** `configs/env_template.sh` — added the 16 keys confirmed
  missing in the original audit (`CIRCUIT_BREAKER_*`, `ELITE_REGISTRY_*`,
  `IRST_*` ×4, `SESSION_BLACKLIST_DURATION_SECS`, `TELEMETRY_*` ×3,
  `UTLS_*` ×2, `DATABASE_URL`), with the same default values already live
  in `.env`.
- **Discovered during manifest-building (beyond the original 16):**
  cross-checking the dormant GitHub Actions workflows against the template
  found a *second*, independent gap — 14 more keys
  (`CEREBRAS_API_KEY_1/2/3`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`,
  `HUGGINGFACE_API_KEY`, `HYPERBOLIC_API_KEY`, `MISTRAL_API_KEY`,
  `PORTKEY_API_KEY_1/2/3`, `PORTKEY_HEALTH_MODEL`, `PORTKEY_PROVIDER_KEY`,
  `RIPE_ATLAS_API_KEY`) referenced by workflow YAML and actively read by
  current provider code (12 of 14 confirmed via grep), present in
  **neither** `.env` nor the template on either side of the migration.
  Added empty placeholders for these to both `.env` and the template (real
  values can't be fabricated, but the slots are now visible and fillable
  instead of invisibly absent).
- **Added:** `docs/SECRETS_MANIFEST.md` — canonical, generated-not-hand-maintained
  inventory of all 98 template keys, cross-referenced against which of the
  three CI systems needs which, and how each platform actually receives
  them (CircleCI Context bootstrap / GitLab auto-exported Project
  Variables / GitHub Actions explicit `secrets.X` interpolation).

## §1.4 — Three redundant CI systems

- **Changed:** prepended a dormancy banner (comment block, no behavior
  change) to all 5 files in `.github/workflows/*.yml` and to the top of
  `.gitlab-ci.yml`, clearly stating CircleCI is primary and these are
  intentional fallbacks. No files removed, no jobs disabled.

## §1.5 — Stale references to the banned GitHub account

- **Changed:** `docs/CHANGE_LOG.md`, `docs/DEPENDENCY_REPORT.md`,
  `docs/DEPLOYMENT_GUIDE.md` — replaced the banned account's URL with
  `CANONICAL_REPO_URL`. `DEPENDENCY_REPORT.md`'s "Module Path" field was
  additionally corrected to the real, current `go.mod` value
  (`github.com/ysa-py/MICAFP`) since it was stale relative to the actual
  module declaration independent of the ban issue.
- **Changed:** `.github/workflows/torshield-ir.yml` — the "canonical Go
  module path enforcer" step had the banned account's URL **hardcoded as
  the value it would force-rewrite `go.mod` to** if this dormant workflow
  ever ran again. This was the most important fix in this section: left
  as-is, reactivating this workflow would have silently broken the real,
  working module path. `CANONICAL` now matches the actual current
  `go.mod` declaration, so the step is now a no-op consistency check
  rather than a destructive rewrite.
- Verified: zero remaining matches for the banned account string anywhere
  in the tree (see `scripts/remediation/verify.sh` check #2).

## §1.6 — Stale integrity manifest + case-collision duplicate

- **Renamed (content fully preserved, nothing deleted):**
  `CHECKSUMS.sha256` → `CHECKSUMS_legacy_2026-06-19.sha256`.
- **Regenerated:** `checksums.sha256` from scratch, covering every
  currently-tracked file (matching the same `.gitignore`-based scope the
  original 205-entry manifest used — confirmed empirically that the
  original manifest never tracked `__pycache__`/`.pyc`/`.pytest_cache`/`.coverage`,
  so the regeneration replicates that scope rather than including build
  artifacts). 248 entries as of the final pass in this remediation.

## §1.7 — Missing `reportlab` dependency

- **Changed:** `requirements.txt` — added `reportlab>=4.0.0`.
  `scripts/generate_final_report.py`'s six unguarded top-level imports
  will no longer crash with `ModuleNotFoundError` on a clean install.

## §2 — Build artifacts / committed binaries (left untouched, as instructed)

No action taken on either item below — both remain exactly as uploaded,
per the prompt's explicit default-off gating:

- 18 `__pycache__/` directories, 143 `.pyc` files, `.coverage`,
  `.pytest_cache/` — gitignored but currently present in the archive.
- `probe_scheduler` (9.6 MB) and `iran_tester` (9.0 MB) compiled binaries
  at repo root.

If you want these detached from version-control tracking in the future
(file stays on disk, only stops being *tracked*), that is a deliberate
human decision the prompt asked to leave open — it is not something this
remediation pass decided unilaterally.

## §4 — Deliverables produced

- `scripts/remediation/fix_silent_exceptions.py` (the §1.1 codemod)
- `scripts/remediation/verify.sh` (the full §7 verification suite, plus
  checks for items discovered during execution: go.work, go_tester module
  rename, codemod idempotency, checksum case-collision)
- `docs/SECRETS_MANIFEST.md`
- This file

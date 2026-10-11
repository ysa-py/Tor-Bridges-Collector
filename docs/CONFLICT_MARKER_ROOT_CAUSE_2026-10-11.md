# Conflict-marker root cause and fix — 2026-10-11

## What broke

Between 2026-10-10T20:29Z and the hourly run that published 2026-10-10T21:06Z,
57 tracked files were committed with git conflict markers inside them
(`README.md`, `bridge/bridge_history.json`, `bridge/iran_results.json`,
`bridge/telegram_manifest.json`, 48 `data/*` JSON, 3 `docs/*.md` and 4
`export/*` payloads — 9072 conflict blocks in total).

Consequences on `main`:

* `bridge/bridge_history.json`, `bridge/iran_results.json`,
  `bridge/telegram_manifest.json` and most `data/*.json` stopped parsing.
* `TorShield-IR Main CI` went red: `invariant-audit` failed `C1 json-parse-all`
  and then crashed inside `C5 evidence-stamps` on `iran_results.json`.
* `AI Bridge Re-Ranker (Iran)` failed because it reads the poisoned
  `bridge/iran_results.json`.
* Every following pipeline run started from invalid input, so verification
  evidence was lost and the published `*_tested` /
  `iran_likely_working_*` projections stayed empty.

## Root cause

Stage 11 ran `git pull origin main --rebase --autostash` **after** the pipeline
had already regenerated `bridge/` and `data/`. The autostash replayed that
fresh output on top of the previous hourly publication commit, which had
rewritten the very same generated files, so git wrote
`<<<<<<< Updated upstream` / `=======` / `>>>>>>> Stashed changes` into them.
The following `git add` staged the corrupt payload and `git push` published it.

## The fix

1. `scripts/repair_conflict_markers.sh` — self-heals generated files that carry
   conflict markers. For each block the **second side wins** (it is the freshly
   generated "Stashed changes" content); when that candidate is empty, still
   marked, or not valid JSON, the newest earlier git revision that is valid
   wins instead. Unbalanced markers are treated as unrepairable instead of
   silently truncating a file. Modes: heal (default), `--check` (gate over the
   staged/committed payload, exit 2 on markers), `--validate-json` (publication
   guard, same skip list as `C1`).
2. **Stage 0z** in `scrape-and-test` heals straight after checkout, so a corrupt
   committed payload can never poison the run.
3. **Stage 11** was rewritten: heal → validate → `git add` → commit **first** →
   `git rebase -X theirs origin/main` (the freshly generated commit wins) →
   re-check → push with 5 retries. `--autostash` is gone; no stash is used, so
   markers cannot be written into the tree during publication.
4. `main-ci.yml` gains two gates: `Conflict-marker gate` (`--check`) fails the
   build if a corrupt payload ever lands on a branch again, and
   `Test conflict-marker repair` runs the hermetic test suite.

### Why shell + jq instead of a `*.py` helper

`quality_gate py-check` fails this repository while any Python **source file**
survives in the Rust-native tree, and `torshield-ir.yml` was migrated away from
inline Python heredocs. A first attempt at this fix shipped
`scripts/repair_conflict_markers.py` and failed exactly there
(CI run 38090496066, step `Python-free gate (py-check)`). The healer is
therefore shell + `jq`, the same combination `scripts/verify_repo_invariants.sh`
already relies on.

## Data repair

All 57 files were healed with the "fresh side wins" policy (0 files needed the
git-history fallback) and committed. Nothing was deleted or invented: the
healed content is the freshly generated side of each conflict, which is what
the 21:06Z run intended to publish. `export/iran_anti_dpi_elite.{txt,json}`
were additionally regenerated with the repo's own `build_iran_anti_dpi_elite.sh`
so that the freshness contract `C8` holds again; the elite set is unchanged
(1012 bridges, PHANTOM 3 / STEALTH 58 / COVERT 951) — only the score-tie
ordering is rebuilt from the repaired reports.

## Verification

* `bash scripts/verify_repo_invariants.sh` — **15/15, ALL GREEN** (was: `C1`
  fail + traceback crash in `C5`).
* `bash scripts/test_repair_conflict_markers.sh` — 17/17 assertions
  (fresh side wins, git-history fallback, marker-free files untouched,
  setext underline preserved, README healed, idempotent, unrepairable file
  left untouched, `--check` with and without git).
* `shellcheck --severity=warning` (CI severity) clean on both scripts.
* End-to-end simulation of Stage 0z + Stage 11 against a bare origin with a
  competing concurrent push: corrupt payload healed, freshly generated content
  won the rebase, no markers committed, push succeeded.
* `quality_gate py-check` cannot be run here (no Rust toolchain in this
  sandbox) — the tree now contains **0** `*.py` files outside `.git`, which is
  exactly what the gate scans for.

## Deliberately not done

* No data deletion: the earlier removal of `bridge/` (commit `daa0d8ee`,
  2026-10-09) destroyed the evidence history — this fix heals in place and lets
  the pipeline rebuild every projection atomically instead.
* `*_tested`, `iran_likely_working_*` and `tested_global_*` stay empty until
  runner-side probes actually verify a bridge above S1. Filling them with
  unverified bridges would put Iranian users at risk.

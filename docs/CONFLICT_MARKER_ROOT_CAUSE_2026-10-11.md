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

## Follow-up finding (same commit): one tree, three publications

Healing the markers was necessary but not sufficient. Commit `971b17ad`
(`chore: dual-persist bridge/ + README.md`, single parent `26e14407`,
committed 21:06:50Z) left `bridge/` holding **three different publication
states at once**:

| artifact | what it said |
| --- | --- |
| `bridge/telegram_manifest.json` | `generated_at 2026-10-10T21:06:45Z`, summary counts `1497/1497` |
| `bridge/tor_bridges.zip` | embeds its own manifest `20:29:53Z`, internally self-consistent, `1495/1495` |
| payload (`iran_results.json`) | `1573` bridge records, the freshly stashed run |
| `README.md` | claims archive SHA-256 `9fbf6a26…`, committed ZIP is `dffaa6a8…` |

Every healthy commit before it was internally coherent (`e5a72bba` and
`26e14407`: manifest timestamp == ZIP timestamp, every hash matching), so the
mixture is a second signature of the same Stage 11 autostash/rebase damage:
the ZIP is binary, so git could never merge it and kept the 20:29 side, while
the text manifest and payload came from the newer run. CI confirmed it —
`scrape-and-test (finalize)` failed on PR #236 in **Stage 9
"dual persist"**, whose PR path is `sync_bridge_outputs --verify-only`
(`src/bridge_publication.rs::verify_publication`): 2 manifest SHA-256
mismatches and 9 ZIP entries differing from the payload.

### Repair

`scripts/publication_contract.sh --rebuild --set-count iran_results.json=1573`
did the re-attestation, and only that:

* manifest `sha256`/`size_bytes` updated for the two files the heal rewrote
  (`bridge_history.json`, `iran_results.json`) — 5 scalars, surgical diff
* `summary["iran_results.json"]` `1497 → 1573`, the row count the payload
  actually holds (the publisher writes these counts from the payload it read)
* `bridge/tor_bridges.zip` rebuilt deterministically (sorted
  `bridge/<name>` entries, 1980-01-01 timestamps, deflate, 0644,
  `len(required_files) - 1 = 78` entries) →
  `5bc058037bafbbd9d65ac0917278b85d9d9dcfca943884bb702efa525cabd3b9`
* `README.md` archive SHA-256 re-stamped to that ZIP

No payload byte was rewritten: the pipeline's own next scheduled run
regenerates the whole contract, and this re-attestation keeps the committed
tree truthful in the meantime.

### Guard added

* `scripts/publication_contract.sh --check` mirrors `verify_publication()`
  (manifest parses, `required_files_present`, per-file SHA-256 + `size_bytes`,
  ZIP parity and entry count, README archive hash) so the mixture fails in the
  Quality Gate in seconds instead of in Stage 9 after a full cargo build.
  `--rebuild` refuses (exit 2) while any payload file still carries conflict
  markers, NUL bytes, or unparseable JSON — re-attesting corrupt data is not
  repair — and it refuses to rewrite a manifest that is not in the publisher's
  canonical pretty-JSON form.
* `main-ci.yml`: new `Publication contract gate (manifest ↔ payload ↔ ZIP)`
  right after the conflict-marker gate, plus `Test publication contract`.
* `scripts/test_publication_contract.sh`: 9/9 hermetic assertions (healthy
  contract, payload drift, re-attestation, stale README hash, marker refusal,
  declared-absence no-op).

## Deliberately not done

* No data deletion: the earlier removal of `bridge/` (commit `daa0d8ee`,
  2026-10-09) destroyed the evidence history — this fix heals in place and lets
  the pipeline rebuild every projection atomically instead.
* `*_tested`, `iran_likely_working_*` and `tested_global_*` stay empty until
  runner-side probes actually verify a bridge above S1. Filling them with
  unverified bridges would put Iranian users at risk.

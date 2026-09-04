# SESSION 21 — NIN Internet-Cut Pack Finalizer (user-facing iran_cut_pack.txt)

**Date:** 2026-09-03 · **Branch:** `arena/01a069ab-tor-bridges-collector`
**Tooling:** offline sandbox — bash + Python 3.11 stdlib (no Rust/Go toolchain, no egress)
**Prime directive honoured:** nothing removed — `git diff --diff-filter=D` is empty.

---

## 1. What the microscope found

Cross-checking every artifact the pipeline **publishes to users** against the
data actually produced by each stage:

| Check | Result | Evidence |
|---|---|---|
| `export/iran_cut_pack.txt` (the file users are told to use during a شبکه ملی cut) | ❌ **EMPTY (0 bridges)** | committed file = header + 0 lines, yet 304 real candidates existed across the run's own artifacts |
| `data/nin_eligible.json` | 0 entries | strict eligibility (snowflake/webtunnel/meek_lite) — honest for this snapshot |
| `export/nin_cut_survivable.txt` | **295 lines** | probe-based survivability (Stage 8k) — the richest evidence source |
| `bridge/iran_likely_working_nin.txt` / `export/nin_cut_bridges.txt` | 4 / 5 lines | Stage 8p classifier outputs |
| `export/iran_nin_pack.txt` | 0 lines | Stage 8d2 (strict) — honest for this snapshot |

### Root cause (line-by-line)
`export/iran_cut_pack.txt` is written **twice with different strictness**:
1. Stage 6b — `formatter.rs` (`write_export_files`) writes the broad pack
   (`snowflake > webtunnel > meek_lite > obfs4:443/80`).
2. Stage 8d — `nin_selector.rs` (`build_nin_pack_with_paths`) **overwrites the
   same path** with the strict NIN-eligibility filter
   (`NIN_SURVIVABLE_TRANSPORTS = [snowflake, webtunnel, meek_lite]` +
   CDN/DTLS reachability). In this snapshot the runner could not reach any of
   the pool's 8 such bridges → the later stage silently clobbered the
   user-facing file with **0 bridges**.

The data needed for a *useful* pack was produced later in the same run
(Stage 8k writes 295 probe-survivable lines **after** Stage 8d ran) — nothing
ever re-assembled the final user-facing file.

## 2. Fix — additive and fully automatic

**`scripts/build_iran_cut_pack.sh`** → wired as **Stage 8p2** in
`.github/workflows/torshield-ir.yml`, right after Stage 8p (the last stage
that adds NIN-cut data, before 8q/8r/8s/9).

- Merges all five sources in documented priority order, keep-first dedup:
  1. `data/nin_eligible.json` (Stage 8d — strict)
  2. `bridge/iran_likely_working_nin.txt` (Stage 8p)
  3. `export/nin_cut_bridges.txt` (Stage 8p)
  4. `export/iran_nin_pack.txt` (Stage 8d2)
  5. `export/nin_cut_survivable.txt` (Stage 8k — probe-based)
- Deterministic: stable order, no timestamps in the body → regeneration is
  byte-identical (verified: two runs, same md5).
- Honest header: reports total + each source's contribution; `::error::` when
  **every** source is missing; explicit "Bridges: 0" if all are empty (never
  pretends).
- Touches no Rust source → cannot break fmt/clippy/test.

**Committed regenerated artifact:** `export/iran_cut_pack.txt` → **304 bridges**
(4 classifier + 5 GREEN + 295 probe-survivable; strict sources contributed 0).
The file README_FA points users to during a national-internet cut is no longer
empty.

**Invariant audit extended C11 (`cutpack-freshness`):** the committed pack must
stay byte-identical to a fresh regeneration — a silently-empty or stale pack
now fails CI automatically (no regression can be reintroduced).

## 3. Verification (real commands, real output)

```
$ bash scripts/verify_repo_invariants.sh
  [PASS] C1 json-parse-all — 92 files            [PASS] C7 shell-syntax — 31 scripts
  [PASS] C2 publication-contract — 55 required   [PASS] C8 elite-freshness
  [PASS] C3 module-graph — 95 modules            [PASS] C9 no-panic-traps
  [PASS] C4 stage-sync — 21/21 + 18 workflow     [PASS] C10 elite-count — 1125/1125
  [PASS] C5 evidence-stamps — 1596/1596          [PASS] C11 cutpack-freshness
  [PASS] C6 no-dup-bridge-lines — 6422 lines
═══ 11/11 checks passed ═══

$ bash scripts/build_iran_cut_pack.sh
  data/nin_eligible.json=0 (+0)  likely_working_nin=4 (+4)  nin_cut_bridges=5 (+5)
  iran_nin_pack=0 (+0)  nin_cut_survivable=295 (+295)
  export/iran_cut_pack.txt : 304 unique bridges
  → regenerated twice, byte-identical (deterministic)
```

Workflow edit checks: no tabs, no trailing whitespace, every embedded
`run: |` block passes `bash -n`.

## 4. Notes
- `evidence.stamped_entries == 0` in the committed `iran_results.json` was
  investigated and is **not** an error: the tier-1 tester already wrote
  `tested_at`/`test_tier`/`test_result` on every entry, so the stamp pass
  modified zero rows while still summarizing all 1,596.
- The pack remains advisory (runner-side evidence), consistent with the
  project's honesty contract.
- First real execution of Stage 8p2 happens on the next GitHub Actions run
  after this branch is pushed (owner-side push — GAP-6, unchanged).

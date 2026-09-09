# Zero-Yield Root-Cause & v42 Owner-Decision Evidence

**Date:** 2026-09-09 · **Directive:** Engineering Directive v42 (§0.1, §0.2, §1, §2, §3)
**Ground truth artifacts:** PR #228 · run [`34278561590`](https://github.com/ysa-py/Tor-Bridges-Collector/actions/runs/34278561590) (v41 final, 14/14 success) · run [`34262011946`](https://github.com/ysa-py/Tor-Bridges-Collector/actions/runs/34262011946) (scheduled baseline) · [`docs/FUNNEL_DIAGNOSTIC_2026-09-08.md`](FUNNEL_DIAGNOSTIC_2026-09-08.md)
**Ordering guarantee (v42 §4):** this report is committed **before** any code or data change ordered by v42 §0. Every number below is either (a) read from a committed artifact, (b) read from a real CI run log, or (c) recomputed by re-executing the pipeline's own validation chain verbatim against live mirror corpora fetched 2026-09-09 — provenance tagged per claim: `[artifact]`, `[ci-log]`, `[re-executed]`, `[expectation]` (unverified until the post-change CI run).

---

## 1. v42 §1 — Run 34278561590 final status + Stage 0t/8v evidence (COMPLETE)

Full text and cross-check table: PR #228 comment [`5592687576`](https://github.com/ysa-py/Tor-Bridges-Collector/pull/228#issuecomment-5592687576). Summary of the verbatim evidence:

**Run final status: `success`, 14/14 jobs.** `[ci-log]`

**Stage 0t** (core job `scrape-and-test` #102239612773, 2026-09-08T21:14:49Z, step success) — first live run:

```
::notice::center2055/OnionHop-Bridges-Collector fetched=2064 valid=1566 (merge=false)
community_mirrors: report written to data/community_mirrors_report.json
```

**Stage 8v** (finalize job `scrape-and-test (finalize)` #102248192251, 2026-09-08T21:41:25Z, step success) — first live run:

```
::notice::sources_fetched_lines=23 candidates_in_history=1882 testing_candidates=1626 relay_attempted=1634 relay_success=230 tcp_tested=1626 tcp_reachable=570 published_advisory_working=410
::notice::non_routable_endpoints_in_pool=256
::notice::relay_unobserved=0 (non_routable=0, other=0)
funnel_advisory: report written to data/funnel_advisory.json
```

Cross-checks: `candidates_in_history=1882` and `non_routable_endpoints_in_pool=256` match the funnel diagnostic exactly (1882 pool; 252 webtunnel + 4 obfs4 non-routable). `testing_candidates=1626 = 1882 − 256`. `relay_unobserved=0` is the **corrected** expectation: coverage is computed over the post-ip_guard testing list (1,626 lines), not the pre-guard pool — every routable candidate endpoint received ≥1 relay observation (`relay_attempted=1634`). The earlier offline projection of 256 unobserved non-routable had used the pre-guard pool; the live bin's semantics are the authoritative ones. `[ci-log]`

Stage 11 (commit and push) correctly skipped on the PR run — publication preview only, as annotated in the workflow. `[ci-log]`

---

## 2. v42 §2 — Zero upstream yield: root cause

**Question (directive):** which mirror(s) returned 0 new in run 34262011946; persistent or one-off; and is the cause source-side, fetch-side, parse-side, or dedup-side — with real logged evidence.

### 2.1 Which sources returned zero

| Source | Stage | Lines fetched | New to history | Evidence |
|---|---|---|---|---|
| `Delta-Kronecker/Tor-Bridges-Collector` (built-in mirror) | 0s | 1,970 | **0** (1,970 updated) | `[ci-log]` run 34278561590 chunk 23: `history: +0 added, 1970 updated, 1882 total records` |
| 8 extended sources (BridgeDB HTML ×2, MOAT ×6) | 1x | 23 | **0** | `[artifact]` `data/supply_diagnostics.json` @8c9cf607: all 8 `added_records=0`, `responses_ok=requests` |
| MOAT/TorProject (Stage 0/1 direct) | 0/1 | 23 | **0** | `[ci-log]` Stage 8v `sources_fetched_lines=23`; funnel diagnostic §1 row 3 |

### 2.2 Persistent, not one-off — 5 consecutive committed runs

`[artifact]` `data/supply_diagnostics.json` at each scheduled-run commit on `main`:

| Commit | Diagnostics generated (UTC) | Extended added | Sources responding | Pool before→after |
|---|---|---|---|---|
| `5e893b83` | 09-07 20:42 | 0 | 8/8 | 1,879 → 1,879 |
| `709dfa82` | 09-07 23:23 | 0 | 8/8 | 1,879 → 1,879 |
| `ff16b163` | 09-08 03:00 | 0 | 8/8 | 1,880 → 1,880 |
| `9b355bb9` | 09-08 07:55 | 0 | 8/8 | 1,881 → 1,881 |
| `8c9cf607` | 09-08 18:29 | 0 | 8/8 | 1,882 → 1,882 |

Total pool drift over the 5-run window: **+3 records** (+1 webtunnel_ipv6, +2 obfs4 — family deltas read from the `history_family_counts.before` snapshots), all attributable to the live collector stages (0b/Stage 1), none to the mirror or extended sources. ≈ +0.75 records/run — effectively flat, consistent with the funnel diagnostic's 30-run trend (+4.3/run).

### 2.3 Classification with evidence: source-side saturation — fetch, parse, and dedup are all functioning

**Fetch-side: ruled out.**
- Extended sources: `responses_ok` equals requests on all 8 sources in all 5 runs (§2.2 table). `[artifact]`
- Mirror: both mirror repos fetched live 2026-09-09 via the GitHub contents API with full payloads; per-file line counts are byte-identical to the CI-run corpus (dk: 640/326/473/52/251/228 = 1,970 — exactly the counts Stage 0s logged in run 34278561590 at 21:14:46Z; onion: 9 files, 2,064 lines — exactly Stage 0t's `fetched=2064`). `[re-executed]` + `[ci-log]`

**Parse-side: ruled out.**
- The mirror's lines are not failing validation and silently dropping — they are **recognized, normalized, and merged as updates every run** (`1970 updated`). A parse defect would show as `added=0, updated=0` or format rejections; the live Stage 0t gates show `rejected_format=0` for both corpora (the only rejections are ip_guard placeholders: onion 498, dk 483). `[re-executed]`
- Re-executing the pipeline's exact chain (`is_valid_line` regex `scraper.rs:223`, `normalize_for_history` `scraper.rs:247`, `ip_guard::check_endpoint` `ip_guard.rs:252`) over the dk corpus: 1,970 fetched → 1,487 valid → **1,435 unique canonical keys, of which 1,435/1,435 are already exact keys in `bridge/bridge_history.json`** — zero parse mismatches, zero key-shape divergence. `[re-executed]`

**Dedup-side: functioning correctly — the lines genuinely already exist in the pool.**
- `count_new_lines` semantics (dedup by `normalize_for_history` key) over the dk corpus: **new-if-merged = 0**. The zero is a true statement about content overlap, not a filtering bug. `[re-executed]`

**Source-side: confirmed — and structural.**
- The dk mirror updates its `bridge/*.txt` files 4–5×/day (commits `0984b0d4` 20:59, `3f18c41c` 17:12, `907213a6` 12:47, `36e791a7` 07:07, `651c93f0` 05:04 on 2026-09-08) yet its unique valid key set is **static relative to our pool** — its published lines are the same bridge set our pool already contains. `[re-executed]` + GitHub API commit list
- Structural reason: the mirror is a same-pipeline collector (a Tor-Bridges-Collector family repo, 123★/13 forks) drawing from the same ultimate upstreams we draw from directly (bridges.torproject.org, BridgeDB rotation, MOAT). Two collectors pointing at the same upstream converge; the mirror can only ever hand us bridges we already have, minus what it has lost. Its 1,435 unique valid keys are a **strict subset of the OnionHop corpus** (dk − onion = 0 unique keys) and of our pool. `[re-executed]`

### 2.4 The community mirror does carry partial novelty (advisory data point #1)

`[re-executed]` Same validation chain over the `center2055/OnionHop-Bridges-Collector` corpus (fetched live 2026-09-09; reproduces the CI run's `fetched=2064 valid=1566` exactly):

| Metric | Value |
|---|---|
| fetched / valid / placeholder-rejected / format-rejected | 2,064 / 1,566 / 498 / 0 |
| unique valid keys | 1,514 |
| already in our pool | 1,439 |
| **new-if-merged** | **75** (obfs4 70, vanilla 5) — 5.0% of unique keys |

Placeholder rejections by range: 488 `DOCUMENTATION_RFC3849_2001_DB8`, 4 `TEST_NET_1_RFC5737`, 3 `LOOPBACK_RFC1122`, 2 `PRIVATE_RFC1918_192`, 1 `PRIVATE_RFC1918_172`.

This is one fetch-time snapshot, not a 5–7-run series: per owner decision 3, `COMMUNITY_MIRRORS_MERGE` stays OFF and yield accumulates across scheduled runs before any merge decision. **Gap identified while computing this:** in advisory mode the `community_mirrors` bin only computes `added_by_family_when_merged` when merging is enabled, so the per-run report does not record new-if-merged — the 75 above was recomputed offline. An additive report-only fix (always compute the count, merge behavior unchanged) is included in the v42 changeset so future advisory runs self-report this number.

### 2.5 Conclusion & what v42 §2 authorizes next

**Root cause: source-side saturation.** The pipeline's fetch, parse, and dedup stages are all demonstrably working (evidence above); the built-in mirror and all 8 extended sources return only lines already in the pool, persistently across 5 runs. The pool (1,882) is therefore pinned; published count is bounded by pool × survival (1,882 → 574, ×0.31).

Per the directive's sequencing, additional/replacement sources are now proposable **as separately-toggleable modules in the Stage-0t pattern** (fetch + full existing gates + advisory report + owner-gated merge). Evidence for the first candidate already exists: OnionHop dominates the built-in mirror (strict superset, +75 new-if-merged at snapshot). Enabling any merge remains an owner decision (decision 3), NOT taken here.

---

## 3. v42 §0.1 — SEED_STRICT_IP_GUARD line-class verification (BEFORE the flip)

**Directive:** verify all 483 skipped lines are genuinely `2001:db8::/32`/RFC3849 or otherwise reserved — not a valid private range pattern-matching; report, then flip, then confirm via real CI run.

### 3.1 Verification result — reproduced exactly, all reserved, none routable

`[re-executed]` The seed script's own guard (`scripts/refresh_bridge_seed.sh` `endpoint_is_reserved`, lines 139-153, table mirroring `src/ip_guard.rs:96-141`) applied to the actual Stage-0s seed corpus (dk mirror, 6 files, fetched live 2026-09-09):

- Seed-valid lines walked: 1,970 · **skipped by guard: 483** (matches the v41 live test count exactly)
- Skipped by file: `webtunnel.txt` 251, `webtunnel_ipv6.txt` 228, `obfs4.txt` 4
- Skipped by matched range: **`2001:db8::/32` 479** (RFC 3849 documentation), `127.0.0.0/8` 2 (loopback), `172.16.0.0/12` 1 (RFC 1918), `192.168.0.0/16` 1 (RFC 1918)
- 479 raw db8 lines dedup to **252 unique db8 lines** — exactly the 252 db8 webtunnel records already in the pool (cross-checked against `bridge/bridge_history.json` keys: 252/252 present, 0 new db8 lines in the corpus vs pool)
- **Independent cross-check:** every one of the 483 skipped endpoints was re-tested with Python's stdlib `ipaddress` reserved predicates (`is_private`/`is_loopback`/`is_link_local`/`is_multicast`/`is_reserved`/`is_unspecified` + the specific global doc ranges) — a completely independent implementation from both the seed script and `ip_guard.rs`. **Suspicious (routable/public) endpoints: NONE.** No legitimate bridge line is being skipped: the ranges matched are IANA-special-purpose in every case.

### 3.2 Legit-bridge safety of the flip

`[re-executed]` With the guard ON, the dk corpus contributes 1,487 valid lines → 1,435 unique keys → **all 1,435 already in history → 0 legitimate lines dropped** (at the current mirror state; the mirror's legit content is fully absorbed in the pool). The flip therefore changes nothing for legitimate candidates today and stops two ongoing harms:

1. **Zombie heat:** all 252 db8 records get `last_seen` refreshed to the run date every run under guard-off (`[artifact]` pool db8 `last_seen` = 2026-09-08 ×252), keeping non-routable records permanently "fresh".
2. **Open door:** any new db8/RFC1918 line the mirror adds would be absorbed on the next guard-off run (today: 0 new in corpus — the contamination is stable at 252, not growing, as of this fetch).

**Flip ordered by §0.1 after this verification.** Post-flip confirmation requirement: a real CI run showing (a) the skip line reports the expected count, (b) pool legit content unchanged, (c) published set not degraded. That run's URLs land in the v42 completion report — until then the flip is `[expectation]`-graded.

---

## 4. v42 §0.2 — the 129 stale-tested db8 records (current state, BEFORE deletion)

**Directive:** DELETE the 129 stale-tested db8 lines from `webtunnel_ipv6_tested.txt` and re-probe from zero — no annotation; show real post-deletion count + fresh re-probe results.

### 4.1 Current state (all `[artifact]` unless noted)

- Pool: 252 db8 webtunnel records (`bridge/bridge_history.json`, transport=webtunnel ×252).
- Of those, **129 carry stale probe evidence**: `probe_successes` 7–8, `last_probe` 2026-08-06 (33 days old), from the Stage-0b collector's front-domain probes (`src/tor_collector/tester.rs:426-463`) that ran before the CIDR ip_guard landed (`872cd6fa`, 2026-08-10).
- `bridge/webtunnel_ipv6_tested.txt` currently publishes those 129 lines as "tested" via the publication gate's stale-field fallback (`src/bridge_publication.rs:429-431`): with no current probe observation, `tested` falls back to history `probe_successes > 0`.
- Re-probe impossibility under current rules: every probe path excludes non-routable endpoints — collector parsing (`src/tor_collector/parsing.rs:51`), testing list (`src/scraper.rs:1574-1578`). The 129 lines can never acquire fresh probe evidence while those gates stand; their "tested" status is frozen on 2026-08-06 evidence forever.

### 4.2 Deletion + re-probe-from-zero semantics (what will be done)

1. Delete the 129 lines from `bridge/webtunnel_ipv6_tested.txt`.
2. Delete the 129 corresponding records from `bridge/bridge_history.json` — deleting only the published lines would not survive the next run: the publisher rebuilds every `bridge/*.txt` projection **from** `bridge_history.json` (`sync_bridge_outputs`), and the stale-field fallback would resurrect all 129 lines on the next scheduled run. Record deletion is required for the deletion to be real, not cosmetic.
3. Clear nothing else: the other 123 db8 records (no probe evidence, never published as tested) remain in history untouched — their fate is a separate owner call; §0.2 orders only the 129 stale-tested ones.
4. **Re-probe from zero:** the next real pipeline run re-probes the full candidate set from current evidence. For these 129 endpoints the honest outcome is fixed by the ip_guard rules: they re-enter nothing (excluded at every probe path, and §0.1's guard flip stops the mirror from re-seeding them), so the regenerated `webtunnel_ipv6_tested.txt` can only contain lines with **live** probe evidence. The real post-deletion count and fresh re-probe results will be read from that run's artifacts and reported — `[expectation]` until then; no projected number is stated as fact.

---

## 5. v42 §3 — Module classification (7 modules, file:line evidence)

**Method:** every claim below is from (a) `grep`-verified call-site analysis separating real code references from doc-comment mentions, (b) the workflow's full bin-invocation map (every `cargo run --bin` in `torshield-ir.yml` and `main-ci.yml`), and (c) committed run artifacts. Verdicts use the directive's three classes: **(a)** live in publication path (output materially determines which bridge lines users receive), **(b)** advisory-only (live-executed, reports/packs only, no effect on the bridge/ contract selection), **(c)** dead code (never executed anywhere in CI; compiled + unit-tested only). The publication contract = the 55 `bridge/` files rebuilt from `bridge_history.json` + `iran_results.json` by `sync_bridge_outputs` (`src/bridge_publication.rs:1153` `publish_at`; `REQUIRED_FILES` at `:42-100`).

| Module | Verdict | Evidence |
|---|---|---|
| `smart_iran_scorer.rs` | **(b) advisory, live-executed 2×/run** | Runs via `ai_bridge_reranker` bin — job "AI Bridge Re-Ranker (Iran)" (`torshield-ir.yml:1107`) + Stage 8i-smart (`:1385`). Sole code callers: `src/bin/ai_bridge_reranker.rs:9`, `src/bin/bridge_intelligence.rs:19` (that bin never runs). Output `bridge/bridges_ai_iran_ranked.json` is artifact-upload-only (`:1121`), NOT in `REQUIRED_FILES`, never committed (file absent from repo tree). Workflow itself labels it "advisory rerank job" (`:1112`). **No AI layer exists**: `use_ai_active()` hard-returns `false` (`smart_iran_scorer.rs:479`), `maybe_ai_refine` is an empty no-op (`:614`) — the "Smart Iran AI re-ranker" stage name notwithstanding. **Measured precision vs real probe outcomes** (faithful re-implementation of the full scoring chain over run 34262011946's committed `bridge/iran_results.json`, 1,626 records — ranked count matches the CI log line `ai_bridge_reranker: ranked 1626 bridges` from run 34278561590 @21:42:49Z): tier `excellent` 2/2 working (n too small), `good` **44/76 = 0.579**, `capable` 382/1,121 = 0.341, `poor` 142/427 = 0.333, vs baseline 570/1,626 = **0.351**. Precision@10 = 0.200 (below baseline), @50 = 0.600, @100 = 0.550, @574 = 0.483. Interpretation: modest lift localized at the good-or-better boundary (~0.58 vs 0.35); the bulk of candidates (1,121 "capable") score at baseline; the very top of the ranking is noise-dominated. **Not promotable to a publication gate on this evidence** — and per the no-overclaim rule, this module must not be described as AI-powered or smartest-anything. |
| `iran_smart_anti_filter.rs` | **(c) dead code** | Only reference outside its own file: `src/lib.rs:53 pub mod`. Zero call sites in any bin/module/workflow. |
| `iran_smart_anti_filter_v2.rs` | **(c) dead in CI** | Sole caller: `src/bin/bridge_intelligence.rs:15`. The `bridge_intelligence` bin is invoked by **no** step in `torshield-ir.yml` or `main-ci.yml` (full bin-invocation map). Reachable only if a human runs the bin locally. |
| `iran_bridge_prioritizer.rs` | **(c) dead code** | Only reference outside its own file: `src/lib.rs:48 pub mod`. The mentions in `src/nin_selector.rs:10,42,90,336` are doc comments about the Python originals — no code reference exists. |
| `iran_anti_siam.rs` | **(b) advisory, live-executed** | Stage 8r runs the dedicated bin every run (`torshield-ir.yml:1410`): `run_pipeline(bridge, data, export, docs, …)` writes `data/ja3_rotation_plan.json` + user-facing committed packs `export/iran_phantom_bridges.txt`, `export/iran_stealth_bridges.txt`, `export/iran_siam_best_bridges.txt` (all present in the repo tree, regenerated each run). Also exposed as pipeline stage `siam` (`src/bin/pipeline.rs:549,613`) — no scheduled workflow invocation passes `--stage siam`. None of its outputs are in the 55-file `bridge/` contract and none feed `publish_at`. |
| `iran_advanced_dpi_evasion.rs` | **(c) dead in CI** | Sole caller: `src/bin/bridge_intelligence.rs:11` — never invoked by any workflow. |
| `nin_internet_cut_classifier.rs` | **(a) live in a user-facing publication path (with a caveat)** | Stage 8p runs it every run (`torshield-ir.yml:1600` → `pipeline --stage nin-classify` → `NINInternetCutClassifier::run()`, `src/bin/pipeline.rs:545`). Durable outputs: `export/nin_cut_bridges.txt` (GREEN), `export/nin_yellow_bridges.txt` (YELLOW) (`src/nin_internet_cut_classifier.rs:61-63`), report `data/nin_cut_classifier_report.json` (`:67`, 124 KB committed). **The GREEN pack feeds the user-facing internet-cut pack**: `scripts/build_iran_cut_pack.sh:99` includes `export/nin_cut_bridges.txt` as a direct source for `export/iran_cut_pack.txt` (Stage 8p2). **Caveat:** its `COMBINED_OUT = bridge/iran_likely_working_nin.txt` (`:65`) IS a contract file, but the classifier's version is **overwritten** later in the finalize job by the publisher's own NIN selection (`src/bridge_publication.rs:781`, Stage 9) — so the classifier's `bridge/` write is transient; its durable publication influence is via the cut pack only. |
| `ml_predictor.rs` | **(b) advisory, live-executed, measured no-signal** | Stage 6a (`--stage ml`, core job, `torshield-ir.yml:1018` → `src/bin/pipeline.rs:447-460`) + its own bin Stage 7 (`:1240`). Writes `data/latest-results.json`, `data/model_metadata.json`, `data/blocking_model.pkl`. **Training is a stub** — `train_with_options` logs "sklearn not available in Rust port — returning sklearn_required metadata" (`src/ml_predictor.rs:499-509`); **prediction is a constant** — `predict_block_probability` returns `0.5` for both `None` and `Some(model)` ("deviation: Python would call model.predict_proba", `:567-574`). Measured on the committed run artifact: all 1,626 `predicted_block_prob` values = **0.5** (single unique value); model metadata frozen at `trained_at 2026-06-27` (v29, degenerate sample 0 blocked / 454 working, `roc_auc_cv = NaN`, all feature importances 0.0) — `data/model_metadata.json`. The ML pass still shifts every `composite_score` by a constant (mean −0.056) via fixed-weight blending, which propagates only into other advisory stages (`adaptive_selector`, `dpi_evasion_advanced`, `nin_selector` — all report writers). **Zero discriminative power; cannot rank bridges; must never be described as AI-powered.** |

**Cross-cutting notes:**
- The `bridge_intelligence` bin (`src/bin/bridge_intelligence.rs`) is the sole caller of three modules (`smart_iran_scorer` [secondary], `iran_smart_anti_filter_v2`, `iran_advanced_dpi_evasion`) and is invoked by no workflow — the `bridge-intelligence-report` artifact (`torshield-ir.yml:2142`) is an upload of `data/*.json` files produced by *other* stages, not by this bin. Per the zero-feature-removal constraint nothing is deleted; this is flagged for the owner's awareness only.
- No new anti-DPI heuristics are proposed in this changeset; the directive's advisory/flagged shipping rule is recorded for any future such module.
- No module in this table is described as "smartest" or "AI-powered" anywhere in this report or the PR text — the two modules whose names suggest AI (`smart_iran_scorer`'s stage, `ml_predictor`) are explicitly documented above as containing no AI layer / no trained model.

---

## 6. Proven vs unverified split

**Proven (real artifact / real CI run / live re-execution):**
- Everything in §1 (two real CI jobs' log lines, run status 14/14).
- §2.1–2.4: 5-run persistence panel (committed artifacts), fetch/parse/dedup ruling (live corpus re-execution reproducing CI counts byte-for-byte: 1,970 / 2,064 / 1,566 / 483), mirror commit activity (GitHub API), subset structure, 75-new-if-merged snapshot.
- §3.1: 483-skip reproduction + independent ipaddress cross-check (none routable) + 0-legit-dropped at current mirror state.
- §4.1: 129-record stale-field census (committed history + published file).
- §5: all classification verdicts (call-site map + workflow bin map + committed artifacts); `ml_predictor` constant-0.5 measurement; `smart_iran_scorer` tier/precision@K table (faithful re-implementation validated against the live CI log's ranked count 1,626); the local pre-push verifications — guard-default-ON merge over the live mirror corpus (+0 added, 483 skipped, 1753 total, **0 of the 129 deleted records resurrected**) and guard-opt-out fallback (restores the unguarded merge: +129 re-added, 1882 total).
- §7 (post-change): both runs green with real URLs; §0.1 flip confirmed verbatim (483 skipped / 0 legit dropped / 0 resurrections); §0.2 re-probe result confirmed (`webtunnel_ipv6_tested.txt` = 0 lines, before=0 after=0); legitimate-pool safety confirmed (testing list, relay, TCP, published counts all inside the pre-change variance band); §2.4 fix confirmed live (`new=75`).

**Still unverified / open (`[expectation]` or by-construction pending):**
- §2.4's 75-new-if-merged is a single-snapshot figure (now confirmed identical in the pipeline's own advisory report, but still one run); the 5–7-run advisory series for owner decision 3 accumulates only over future scheduled runs.
- §5's `smart_iran_scorer` precision is [recomputed] (faithful re-implementation over the committed input, validated on the ranked count); the per-bridge ranked artifact itself (`ai-iran-ranked-bridges` zip) is not downloadable in this environment (blob host TLS-blocked) — downloading it from the run page would upgrade the figure to [artifact].
- The fate of the remaining 123 never-tested db8 records (owner call, not ordered by v42).

---

## 7. Post-change confirmation (added after the changeset ran green)

Runs on commit `da164e43`: main-ci [`34288669205`](https://github.com/ysa-py/Tor-Bridges-Collector/actions/runs/34288669205) — **success, 16/16 jobs, 0 failed**; TorShield-IR [`34288669641`](https://github.com/ysa-py/Tor-Bridges-Collector/actions/runs/34288669641) — **success, 14/14 jobs**. All evidence below `[ci-log]` (job-log/annotation reads from those runs).

**§0.1 flip confirmed** (PR-run core job #102270270478, Stage 0s @23:03:59Z):

```
SEED_STRICT_IP_GUARD: true                                   (default applied — no repo var set)
  history: +0 added, 1487 updated, 1753 total records
  SEED_STRICT_IP_GUARD: skipped 483 documentation/reserved-endpoint line(s)
  per-transport: conjure=1, meek-azure=2, obfs4=1148, snowflake=2, vanilla=473, webtunnel=127
```

Exactly the locally-verified numbers: 483 skipped (all reserved/doc-range per §3.1), **0 legitimate lines dropped** (all 1,487 valid mirror lines merged as updates), webtunnel family = 4 + 123 (the never-tested db8 records remain, per §0.2 scope). **Zero resurrections of the deleted 129**: `SUPPLY_DIAG webtunnel_ipv6::history_count_after=123` (core-job annotation) and finalize `non_routable_endpoints_in_pool=127` = 123 db8 + 4 private obfs4 — the exact arithmetic of 256 − 129.

**§0.2 deletion + re-probe confirmed** (PR-run finalize job #102276935367 annotations):

```
COUNT_DELTA webtunnel_ipv6_tested.txt before=0 after=0
FUNNEL sources_fetched_lines=23 candidates_in_history=1754 testing_candidates=1627 relay_attempted=1635
       relay_success=239 tcp_tested=1627 tcp_reachable=567 published_advisory_working=409
```

- The deletion survived the full pipeline: the regenerated `webtunnel_ipv6_tested.txt` contains **0 lines** — the fresh re-probe produced no tested webtunnel_ipv6 bridges (no db8 endpoint can acquire live probe evidence, so the honest count is zero, with no annotation kept).
- `candidates_in_history=1754` = 1,753 (post-deletion) + 1 new live record collected during this run (normal per-run drift; the earlier push-run on the same commit showed 1,753).
- **Legitimate bridges not degraded:** testing list 1,626–1,627 (unchanged), relay success 233–239, TCP reachable 564–567, published advisory working 406–409 — all inside the observed run-to-run variance band of the pre-change runs on the identical legitimate pool (relay success has ranged 230–242 across consecutive runs; published 406–410).

**§2.4 additive fix confirmed** (core-job annotation, first live run of the new code):

```
COMMUNITY_MIRRORS center2055/OnionHop-Bridges-Collector fetched=2064 valid=1566 new=75 (merge=false)
```

The pipeline's own new-if-merged computation reports **new=75** — matching the offline §2.4 analysis exactly. Advisory data point #2 of the owner-decision-3 series; `COMMUNITY_MIRRORS_MERGE` remains OFF.

---

*No thresholds, gates, scores, or published files were changed to produce Sections 1–4. Sections 0.1/0.2 code/data changes follow in the same PR, after this report, per v42 §4. Section 7 was appended only after both post-change runs completed green.*

# Pipeline Funnel Diagnostic — Why Bridge-Count Growth Is Low

**Date:** 2026-09-08 · **Run analyzed:** [`34262011946`](https://github.com/ysa-py/Tor-Bridges-Collector/actions/runs/34262011946) (all jobs `success`, commit `8c9cf607`, artifacts committed 18:34–18:51 UTC)
**Scope:** Section-1 diagnostic only. No thresholds, gates, scores, or published files were changed to produce this report. Every number below is either (a) read directly from a committed run artifact, (b) recomputed with the repo's own validators, or (c) re-executed live from this repository checkout — provenance is tagged per line: `[artifact]`, `[recomputed]`, `[re-executed]`, `[unverified]`.

---

## 1. The funnel, with real numbers

| # | Stage | Count | Loss vs prev | Provenance |
|---|-------|-------|--------------|------------|
| 1 | Mirror lines fetched (Stage 0s, 6 files) | **1,970** | — | `[re-executed]` `scripts/refresh_bridge_seed.sh` 2026-09-08 20:26 UTC: obfs4 640, obfs4_ipv6 326, vanilla 473, vanilla_ipv6 52, webtunnel 251, webtunnel_ipv6 228 |
| 2 | …new to history | **0** (1,970 updated) | −1,970 (100% dedup) | `[re-executed]` same run: `history: +0 added, 1970 updated, 1882 total records` |
| 3 | Extended-source draws (Stage 1x, 8 sources) | 23 fetched / **0 added** | −23 | `[artifact]` `data/supply_diagnostics.json` (generated 18:29:35Z): all 8 sources `responses_ok=requests`, `added_records=0` |
| 4 | Candidate pool (`bridge_history.json`) | **1,882** | — | `[artifact]` committed history, keys counted |
| 5 | Testing list at run time (ip_guard-filtered) | **1,626** | −256 (13.6% of pool) | `[artifact]` `bridge/iran_results.json` `summary.total_tested=1626`; filter = `src/scraper.rs:1574-1578` (`write_testing_json` drops `contains_documentation_or_reserved_endpoint`) |
| 6 | Relay observations (Stage 4) | **1,634** | +8 vs input | `[artifact]` `data/pt_results.json` (1,634 entries; 0 doc-range hosts — the filtered list is what the relay saw) |
| 7 | Relay successes | **242** (14.8%) | −1,392 | `[artifact]` `data/pt_results.json`: Bridge 84/473, obfs4 150/1,144, snowflake 6/6, conjure 1/3, webtunnel 1/4, meek_lite 0/4 |
| 8 | iran_tester TCP reachable | **570** (35.1% of 1,626) | −1,056 | `[artifact]` `bridge/iran_results.json` `evidence.results`: `tested_working=570`, `tested_failing=1056`; tiers: `tier_1_tcp=1622`, `tier_2_pt_handshake=4` |
| 9 | Published advisory working set | **574** | −4 net | `[artifact]` `bridge/iran_likely_working_all.txt` = 574 lines (obfs4 405 + vanilla 163 + snowflake 4 + webtunnel 2) |

**Pool trend:** 1,752 → 1,882 candidates across the last ~30 runs (Aug 17 → Sep 8, `history_family_counts` series in `data/supply_diagnostics.json`). **Growth ≈ +4.3 records/run (0.24%/run) — effectively flat.**

---

## 2. Top-3 loss points (ranked by leverage)

### Loss #1 — Upstream yield is zero: the pool is saturated against its sources

Every stage-1/1x source line and every mirror line is **already in history** (dedup by full canonical line):

- Mirror: 1,970/1,970 lines were updates (`+0 added`) — `[re-executed]`.
- Extended draws: 23 lines fetched, 0 added — `[artifact]`.
- MOAT/TorProject (Stage 1): same picture; the funnel's `sources_fetched_lines` advisory stage reproduces it per run.

**Mechanism:** the candidate pool is keyed by the *entire bridge line* (`normalize_key`), and the primary mirror (`Delta-Kronecker/Tor-Bridges-Collector`, the only built-in seed) serves a slow-moving set: as of the 20:26 UTC re-execution its 6 files dedup to 1,691 unique records, of which all 1,691 were already present in our 1,882-record pool. The remaining ~191 records in history come from MOAT/collector draws and earlier mirror snapshots. **The published count is therefore bounded by (pool size × survival rate), and pool size is pinned by a single quasi-static mirror.**

This is the direct answer to "why is growth low": *the pipeline is not losing bridges — it is not receiving new ones.* The probe/publication stages then shrink 1,882 → 574 (×0.31), a ratio that has also been stable.

**Owner decision required (per directive: no silent loosening):** source breadth. Section 2 adds community-mirror sources **advisory-only** (see §4); enabling a merge is an owner call.

### Loss #2 — 13.6% of the pool is non-routable contamination, and 129 of those lines are published as "tested" on stale evidence

Census of the 1,882-record pool against the repo's own `ip_guard::check_endpoint` table — `[recomputed]`:

| Contamination | Records | Origin | Consequence |
|---|---|---|---|
| `webtunnel [2001:db8::/32]:443 …` | 252 | Mirror `webtunnel*.txt` via `scripts/refresh_bridge_seed.sh` — its `valid()` check is non-empty/non-`#`/len≥12 only (script lines ~150-160); **no ip_guard** | Never enter any probe stage (scraper filters them at `write_testing_json`), yet stay in history forever (seed re-refreshes `last_seen` each run) |
| `obfs4 127.0.0.1:*`, `172.18.*`, `192.168.*` | 4 | Same mirror `obfs4.txt` | Same |
| **Total** | **256 (13.6%)** | | |

**Aggravating bug found while tracing this:** `bridge/webtunnel_ipv6_tested.txt` publishes **129** of the 252 db8 lines as *tested*. Chain of evidence:

1. Those 252 lines entered history Aug 5 (seed script) and were probed by the Stage-0b collector on **2026-08-05/06**: for webtunnel lines carrying `url=`, the collector probes the **front domain** (`src/tor_collector/tester.rs:426-463` — "the literal endpoint is irrelevant; probe the front domain"), and 129 of them passed → history records carry `tcp_reachable: true`, `probe_successes: 7-8`, `last_probe: 2026-08-06` — `[artifact]` history fields.
2. On **2026-08-10** the table-driven CIDR ip_guard landed (`872cd6fa`) and is now enforced at collector parsing (`src/tor_collector/parsing.rs:51`) and at the testing list (`src/scraper.rs:1577`) — so the db8 lines are **never re-probed again**; their August success fields are frozen.
3. The publication gate at `src/bridge_publication.rs:429-431` computes `tested = probe.map(tcp_reachable || transport_capable).unwrap_or(test_pass || tcp_reachable || probe_successes > 0)` — with no current probe observation it **falls back to the stale history fields** → `tested=true` → the 129 lines land in `webtunnel_ipv6_tested.txt` every run since — `[artifact]` `webtunnel_ipv6_tested.txt` = 129 lines, 129/129 contain `2001:db8`.

Note the nuance: these are not necessarily fake bridges (BridgeDB itself distributes webtunnel lines with documentation-range endpoints where the client dials the `url=` front). But the current published "tested" status rests on a **33-day-old front probe that no stage will ever refresh**, because every probe path excludes them while the publication fallback still trusts the old fields. The iran-specific working set is unaffected (`iran_likely_working_webtunnel.txt` = 2, both from this run's live probe).

**Fix shipped in this PR (opt-in, additive):** `SEED_STRICT_IP_GUARD` flag on `scripts/refresh_bridge_seed.sh` (default **off** — behavior unchanged until the owner enables it). Verified live: with the flag on, the same mirror fetch skips 483 doc-range lines and the resulting history contains 0 db8/RFC1918 records — `[re-executed]` 2026-09-08. Separately, `Stage 8v` funnel advisory now counts this census every run. What to do about the 129 stale-tested published lines (drop, re-probe via front, or annotate) is an **owner decision** — nothing was changed in the publication gate.

### Loss #3 — Probe mortality: 85% of observed candidates fail the relay probe; 65% fail TCP

- Relay: 1,392/1,634 fail (85.2%) — `[artifact]`. Spot-checks (webtunnel_probe_history, front-health advisory) show most are genuinely dead endpoints (mirrors publish lines that die), not probe-side breakage: snowflake 6/6 and the two live webtunnels succeed, so the probe path itself works.
- iran_tester: 1,050/1,626 `tcp_unreachable` (64.6%) — `[artifact]`. `ooni_checked=247`, `iran_likely_working=2`, `iran_unknown=574` — the iran-specific classifications are almost never reached because the TCP gate eliminates first.

**This is the expected physics of a mirror-fed pool** (the mirror's own "tested" file is 35 kB vs 107 kB raw — a similar mortality ratio). It bounds `iran_likely_working_all` to roughly `pool × 0.31`. The only lever that raises the published count without loosening gates is **pool size/quality** (Loss #1/#2) — or a higher-yield source.

---

## 3. Secondary findings (exact locations)

| # | Finding | Location | Status |
|---|---|---|---|
| S1 | Committed `bridge_list_for_testing.json` (1,882) ≠ the list the run actually tested (1,626): Stage 9's `ensure_testing_list` rewrites the file from *unfiltered* history candidates, while Stage 1's `write_testing_json` writes the *filtered* list | `src/bridge_publication.rs:448-478` vs `src/scraper.rs:1566-1605` | Reported; not changed (both behaviors are contracted elsewhere; the funnel advisory now surfaces both counts per run) |
| S2 | Relay observations (1,634) exceed the filtered input list (1,626) by 8 | `data/pt_results.json` vs `summary.total_tested` | `[unverified]` exact cause needs the run log; the Actions log blob host is TLS-blocked from this audit environment. Likely multi-descriptor parsing of mixed endpoint+url lines in `scripts/probe_relay.sh`'s jq stage |
| S3 | EWMA `health_score` is consumed only for candidate ordering and drift advisories, **not** by the publication gate | `src/tor_collector/storage.rs:144-169` (writer), `bridge_publication.rs:429-431` (gate reads `tcp_reachable`/`probe_successes`/`test_pass` only) | Confirmed — answers the "is health score gating publication?" question: no |
| S4 | Diversity caps are **not** the growth bottleneck: the historical caps (`compute_dynamic_ceiling`) bind only the per-family tested/untested split at publication, and the run shows no family hitting a cap (obfs4 405 tested / 819 total; vanilla 163/471) | `bridge/*.txt` counts vs ceilings | Confirmed — the funnel loss is upstream supply + probe mortality, not caps |
| S5 | `probe_scheduler` RIPE + PT merge are live-run no-ops (`ripe_tested=0`; all 1,367 regenerated) | `data/scheduler_results.json` | `[artifact]` |
| S6 | `scripts/probe_relay.sh` declares `PT_RESULT_SUCCESS` twice — shellcheck SC2038-adjacent duplication, harmless but worth cleanup | `scripts/probe_relay.sh` (grep `PT_RESULT_SUCCESS`) | Reported; not changed (diagnostic-only PR for this file) |

---

## 4. What Section 2 ships alongside this report (all additive, advisory-default)

| Addition | Gate | Default | Evidence |
|---|---|---|---|
| `src/sources_community_mirrors.rs` + `src/bin/community_mirrors.rs` (Stage 0t) — community-mirror source, per-file format+ip_guard validation, per-mirror yield report | `COMMUNITY_MIRRORS` env / repo var; merge only with `COMMUNITY_MIRRORS_MERGE=true` | **Advisory-only** (`data/community_mirrors_report.json`) | Mirror candidates evaluated live 2026-09-08 via GitHub API: `center2055/OnionHop-Bridges-Collector` chosen as default (hourly, TCP-tested: `obfs4.txt` 106,952 B, `obfs4_tested.txt` 35,622 B); `scriptzteam/Tor-Bridges-Collector` rejected (synthetic `1.0.0.1`/`1.1.1.1` placeholders); `spicicpein/tor-bridges-feed` rejected (empty) |
| `src/webtunnel_v2.rs` front-health advisory — `FrontHealth` classification from **live relay observations only**; zero-observation fronts are `no_evidence`, never invented | Advisory report in Stage 8v | **Advisory-only** | Unit tests + built on run 34262011946's real `pt_results.json` |
| `src/ech_fingerprint_evasion.rs` relay-evidence enrichment — every entry stamped `ech_verification="static_inference_no_live_handshake"` + `relay_probe{observed,success,latency_ms,probe_type,error}` join by host:port | Stage 8g bin | **Advisory-only** | Unit tests; run on 1,626-bridge testing list |
| `src/pipeline_funnel_advisory.rs` + `src/bin/funnel_advisory.rs` (Stage 8v) — this funnel, recomputed every run into `data/funnel_advisory.json` + `::notice` annotations | Advisory, `continue-on-error` | **Advisory-only** | Fixture test over a synthetic run tree |
| `SEED_STRICT_IP_GUARD` on `scripts/refresh_bridge_seed.sh` | Env/repo var | **Off** | `[re-executed]` 483 lines skipped, 0 db8 in output history |
| `probe-relay-vitest` CI job (49 tests: concurrency queue, fronted-probe ordering, safeConnect lock release) | CI gate | **Always on** (test-only) | Local: `npx vitest run` 49/49 pass, 788 ms — live CI URL will be added to the PR description once this branch's run completes |

---

## 5. Proven vs unverified — this report

**Proven (artifact-backed or re-executed):**
- Every count in §1 tagged `[artifact]`/`[re-executed]`/`[recomputed]`.
- The 252+4 contamination census (`ip_guard::check_endpoint` over committed history).
- The 129 stale-tested webtunnel chain (history fields dated 2026-08-06 ↔ `webtunnel_ipv6_tested.txt` 129/129 db8 ↔ gate fallback at `bridge_publication.rs:429-431`).
- `SEED_STRICT_IP_GUARD` behavior (two live executions, before/after).
- vitest 49/49 locally.

**Unverified (could not be exercised from this audit environment):**
- Exact cause of the +8 relay observation delta (S2) — run-log blob host TLS-blocked; needs a log download from an unrestricted host.
- Whether the 129 db8 webtunnel fronts are *currently* alive (no stage probes them; a front re-probe is proposed as an owner decision, not executed).
- CI execution of the new `probe-relay-vitest` job and Stages 0t/8v — first run happens on this PR's push; results will be linked in the PR description.

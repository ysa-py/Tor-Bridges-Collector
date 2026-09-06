# SESSION 23 — TorShield-IR CI Optimization Report (`torshield-ir.yml`)

**Date:** 2026-09-06
**Scope:** Performance & reliability optimization of `.github/workflows/torshield-ir.yml` plus its supporting probe-relay sources. **Hard constraint honored: no job, stage, step, script, or output artifact was removed, disabled, or had its scope reduced.**
**Method:** Before writing any code I read the actual step scripts and their Rust/Go/TS sources — `scripts/probe_relay.sh`, `probe-relay/src/index.ts`, `probe-relay/wrangler.toml`, `src/tor_collector/*` (Stage 0b), `cmd/iran_tester/main.go` (Stage 2), `cmd/probe_scheduler/main.go` (Stage 3), and the `scraper`/collector binaries — to ground every change (and every non-change) in real dependency/throughput behaviour rather than guesswork.

---

## 1. Ground truth — what the tree already contained (from prior sessions)

Before this pass I audited the workflow against all five goals. A number of them were **already implemented** in the current tree, so I verified rather than re-did them:

- **Goal 4 (setup-go / Node 20):** the tree already uses `actions/setup-go@v6` (with `cache: true`, `cache-dependency-path: go.mod`), the global env already forces `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: 'true'`, and the only other Node-20 action that existed (`mlugg/setup-zig@v2`) was already replaced by a direct Zig download. → **Already resolved; no edit required.** Confirmed no `actions/setup-go@v5` or other flagged action remains.
- **Goal 3 (job parallelism):** the collection pipeline was already split so the seven independent analytic passes (`analytics-ml-zig`, `analytics-scoring`, `analytics-ech`, `analytics-nin-advanced`, `analytics-nin`, `analytics-static`) run as **parallel jobs** after `scrape-and-test (core)`, and `rust-parity-tests` no longer serial-blocks the collection job.
- **Goal 5 (caching):** all cargo caches already hash the **full workspace** (`**/Cargo.toml`, `**/Cargo.lock`) with shared restore-keys, and `setup-go` already keys its Go cache off `go.mod`. Unchanged lockfiles therefore already produce cache hits.
- **Goal 2 (Stage 0b):** already tuned (96 workers, `STAGE_DEADLINE_SECS=820`, adaptive back-off per transport).

What was genuinely **not** fixed was **Goal 1** — the Stage 4 probe-relay truncation. That is the focus of this session and is described below.

---

## 2. Root cause of the Stage 4 truncation (Goal 1, highest priority)

**Symptom:** `Stage 4 — External Probe Relay` hit its 20-minute client budget every run and printed *“Probe relay reached its 20-minute budget; continuing with partial results”* — i.e. probe coverage was silently truncated. Raising the step timeout alone would only delay that failure, not restore coverage, so the fix had to raise **per-bridge probe throughput**, not the timeout.

**Actual bottleneck (read from source, not guessed):**
- The CI client (`scripts/probe_relay.sh`) submits **30-bridge chunks** concurrently (8 in flight).
- Each chunk is handled by the Cloudflare Worker (`probe-relay/src/index.ts`), which internally probed the chunk with only **`MAX_CONCURRENT_PROBES = 5`** in-flight `connect()` calls and a 5 s per-probe timeout.
- Consequence: a 30-bridge chunk ran as **≈6 serial waves × up to 5 s ≈ up to ~30 s** per request. Across ~50+ chunks this is what forced the client onto the 20-minute budget and dropped the chunks that didn’t finish.
- The conservative limit of 5 existed because of Cloudflare’s *“stalled HTTP response was canceled”* warning — but that warning was **root-caused to unreleased reader locks**, and that bug is already fixed in the current code (`safeConnect()` / `drainAndClose()` release every reader in every path; the unit tests even assert `activeReaders === 0`).

**Fix (coverage-preserving — raises throughput, drops nothing):**
Raise the relay’s internal probe concurrency **5 → 25**. A 30-bridge chunk then probes in **~1–2 waves (~5–10 s)** instead of ~6 waves (~30 s), letting the full ~1500-bridge set finish well inside the 20-minute budget. 25 concurrent `connect()` calls stay far below the free-tier **50-subrequest-per-invocation** ceiling (a 30-bridge chunk is at most 30 concurrent connects).

Files changed:
- `probe-relay/src/index.ts` — `DEFAULT_MAX_CONCURRENT_PROBES` 5 → 25 (+ rationale comments).
- `probe-relay/wrangler.toml` — deploy-time `[vars] MAX_CONCURRENT_PROBES = "25"` (+ rationale comments). This takes effect on the next `wrangler deploy` performed by Stage 4-prep.
- `.github/workflows/torshield-ir.yml` — Stage 4 now reports **input-candidate vs completed** coverage so any future truncation is loud and never silent (the 20-min cap is retained purely as a safety bound).

Validation performed: `probe-relay` unit suite — **12/12 tests pass** (`npx vitest run`) with the new default; the workflow YAML still parses with all 14 jobs intact.

> The free-tier relay Worker is external and shared; before merging, confirm on a real run that the colo does not throttle 25 concurrent sockets (retries are already built in, so worst case is slower, not data loss — nothing is dropped on a non-200, it is retried).

---

## 3. Goals 2/3 — why the remaining big cuts are **not** safe to ship blind (honest assessment)

I did **not** fabricate large speculative rewrites for Goals 2/3. Reading the source shows why:

- **Stage 0b (~11–13 min) and Stages 0/0c/1 share mutable files.** The `scraper` binary (Stages 0, 0c, 1) *and* the unified collector (Stage 0b) all read/write the same `bridge/bridge_history.json`, every `bridge/*.txt` projection, and `bridge_list_for_testing.json`. Running these steps concurrently would create read/write races and **lose bridge data** — the opposite of the goal. They are intentionally serial because they don’t have independent state. The pipeline is already the parallel form: the heavy independent work after the scrapers is spread across the parallel `analytics-*` jobs.
- **Stage 0b’s runtime is a network-handshake throughput bound.** It already uses 96 workers, adaptive per-transport back-off, and a raised deadline. Cutting its time means either probing fewer candidates (a completeness loss) or raising concurrency past what a single shared `obfs4proxy/lyrebird` SOCKS harness can serve (no gain, risk of throttling). It is a real candidate for further work, but only via CI-driven profiling, not an untested blind constant change.

**Recommended follow-up (biggest remaining architectural win, needs a CI-validated restructure — see §7):** split Stage 4 (whose only input is `bridge_list_for_testing.json`, produced early in core) into its **own job that runs concurrently** with Stage 2 (iran_tester) + Stage 5 (OONI), because Stage 4 writes `data/pt_results.json` while Stage 2 writes `bridge/iran_results.json` — disjoint outputs on a read-only shared input. This removes the relay from the serial critical path before Stage 6a scoring. I did not implement it here because it changes the 14-job `needs`/artifact graph that must keep byte-identical outputs and cannot be validated offline.

---

## 4. Summary table

> `before` values are the run metrics referenced in the task (41m34s total, etc.). `after` values are **projections** from the throughput model in §2 and **must be re-measured on CI** — the workflow has no local harness. Rows marked “no change (already applied)” reflect prior-session work that I verified is present and left intact.

| Stage / Job | Before | Expected after | What changed | Category |
|---|---|---|---|---|
| **Stage 4 — External Probe Relay** | Truncated at **20-min budget** (~1500-bridge set not fully probed each run) | Full coverage, **≈4–8 min** (30-bridge chunks in ~1–2 waves) | Relay Worker probe concurrency 5→25 (`index.ts` + `wrangler.toml` `[vars]`); applied at next deploy | **Concurrency / throughput (fixes truncation)** |
| **Stage 4 step accounting** | Truncation was silent | Missing coverage is reported (`N/M candidates`) if it ever recurs | Explicit input-vs-completed accounting + warning in `torshield-ir.yml` | Reliability / observability |
| **Stage 0b — Unified collector** | ~11–13 min (deadline 820 s) | ~11–13 min (unchanged; network-bound, already 96 workers) | No change (safe tuning requires CI profiling — §7) | — |
| **Stage 2 — iran_tester** | ~4m46s | ~4m46s (unchanged; already `--workers 100`) | No change | — |
| **Stages 0 / 0c / 1 (scrapers)** | small each | unchanged | No change — share mutable `bridge/` files, cannot run concurrently without data loss | — |
| **setup-go (Goal 4)** | v5 → Node 20 annotation | v6 on Node 24, annotation gone | Already present in tree (`actions/setup-go@v6`) — verified, no edit | Action version bump (already applied) |
| **Cargo / Go caches (Goal 5)** | cache hits on unchanged lockfiles | unchanged | Already full-workspace-keyed — verified, no edit | Caching (already applied) |
| **analytics-* (7 parallel jobs)** | run in parallel after core | unchanged | Already parallel — verified, no edit | Job parallelism (already applied) |
| **All other jobs/stages** | unchanged | unchanged | No functional/scope change | — |

---

## 5. Stage / job preservation confirmation (nothing removed or reduced)

The updated workflow still declares **all 14 jobs** with identical names, dependencies, and outputs. Every step below remains present and functional in the edited file; this session only edited **three** files (`torshield-ir.yml`, `probe-relay/src/index.ts`, `probe-relay/wrangler.toml`) and removed **no** job, stage, script, or artifact path.

**Jobs (14) — all present, unchanged graph:**
`quality-gate`, `build-rust`, `rust-parity-tests`, `scrape-and-test` (core), `analytics-ml-zig`, `analytics-scoring`, `analytics-ech`, `analytics-nin-advanced`, `analytics-nin`, `analytics-static`, `scrape-and-test-finalize`, `ai-rerank` (AI Bridge Re-Ranker), `package-final-artifact`, `cleanup` (AI Ultra-Pro Cleanup, reusable).

**Stages inside `scrape-and-test` (core) — all present:**
`Stage 00` (self-heal diagnostics), `Stage 0s` (high-volume seeding), `Stage 0` (direct scraper), `Stage 0b` (Unified OnionHop + VIP collector), `Stage 0c` (broad-source enrichment), `Stage 1` (scraper all sources), FAILSAFE, go source build, `Stage 2` (iran_tester TCP/ASN/OONI/CDN), `Stage 3` (probe_scheduler RIPE+MOAT), `Stage 4-prep` (deploy + smoke), `Stage 4` (External Probe Relay), `Stage 4 cleanup`, `Stage 5` (OONI), `Stage 6a` (Score), `Stage 6b` (Export), bridge-snapshot upload.

**Stages in the parallel analytics jobs — all present:** `analytics-ml-zig`: 7, 8, 8q. `analytics-scoring`: 8b, 8n, 8i, 8i-smart, 8j, 8r. `analytics-ech`: 8g. `analytics-nin-advanced`: 8h. `analytics-nin`: 8d, 8d2, 8k, 8p. `analytics-static`: 8c, 8e, 8f, 8l, 8m, 8o.

**Stages in `scrape-and-test-finalize` — all present:** merge, `Stage 8s` (Anti-DPI Elite fusion), `Stage 8t` (PQ scores + NIN recommended transport), `Stage 9` (dual-persist bridge/ + README + Telegram), `Stage 9b` (verify 55 files / byte-identical ZIP), post-execution FAILSAFE, `Stage 10` (full inventory), `Stage 8p2` (cut-pack finalizer), `Stage 11` (commit + push), bridge-intelligence-report upload.

**Output artifact paths** (bridge-snapshot, all `analytics-*`, bridge-intelligence-report, ai-iran-ranked, final package, quality report, …) are untouched.

---

## 6. Changes that could affect data completeness/accuracy (review before merge)

1. **Relay concurrency 5→25 (primary).** Intent: *improve* completeness by letting all ~1500 bridges finish instead of truncating. The risk is the **opposite** of a drop: if the free-tier Cloudflare colo throttles 25 concurrent sockets, some requests could return slower/429 → the existing retry path retries them (no data loss, only time). Because the relay is external and shared, **confirm on a real CI run** that throughput improved and the truncation warning is gone.
2. **No Stage 0b / Stage 2 / scraper concurrency or timeout changes were made** specifically because they *would* risk bridge-set completeness/accuracy. Any such change is deferred to CI-driven tuning (§7).
3. All other edits are **observability/comments only** and cannot alter collected data.

---

## 7. Recommended follow-ups (require a CI run to validate — not shipped blind)

1. **Split Stage 4 into a parallel job** feeding `scrape-and-test-finalize` directly, overlapping the relay with Stage 2/Stage 5 so scoring (Stage 6a) starts as soon as all three inputs are ready. Biggest remaining wall-clock win (estimated core-job saving on the order of the relay runtime). Must preserve the artifact/`needs` contract.
2. **Profile Stage 0b** with per-stage telemetry (the collector already writes `data/collector_yield_*.json`) to find whether obfs4 SOCKS handshakes, connect timeouts to dead endpoints, or source fetch dominates; only then raise workers/per-transport budgets — without dropping the candidate set.
3. After deploying the relay worker with the new `[vars]`, re-run the schedule once and confirm the Stage 4 coverage line reports `M == N` candidates.

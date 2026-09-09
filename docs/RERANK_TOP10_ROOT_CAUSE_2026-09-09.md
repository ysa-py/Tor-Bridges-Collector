# Reranker Top-10 Inversion — Root Cause, Correction Proposal, and Token-Expiry Pattern

**Date:** 2026-09-09 · **Directive:** v43 §2 (top-10 inversion) + §3 (token-expiry pattern)
**Builds on:** PR #228, commit `da164e43`, `docs/ZERO_YIELD_ROOT_CAUSE_2026-09-09.md` §5 (the v42 precision table this investigation starts from).
**Dataset (unchanged from v42):** the committed `bridge/iran_results.json` from scheduled run [`34262011946`](https://github.com/ysa-py/Tor-Bridges-Collector/actions/runs/34262011946) — 1,626 records, 570 `tcp_reachable` (baseline 0.351). The scorer re-implementation is the same faithful Python port validated in v42 against the live CI log (`ai_bridge_reranker: ranked 1626 bridges`, run 34278561590 @21:42:49Z); this session it was extended to emit per-sub-factor contributions. All numbers below are `[recomputed]` on that committed dataset unless tagged otherwise.

---

## 1. The question

v42 measured `smart_iran_scorer` (via the `ai_bridge_reranker` bin, censorship level 4) precision against real probe outcomes: good-tier 0.579 vs baseline 0.351, but **precision@10 = 0.200 — below baseline**. The directive's hypothesis: a specific scoring input is inverted or mis-weighted, making the highest-confidence outputs anti-correlated with real success. This report root-causes that number before any capability work touches the module.

## 2. Mechanism — three findings, none of them an inverted input

### F1. The scores are degenerate: 22 distinct values across 1,626 records

On the reranker's input schema (`line`, `transport`, `port`, `host`, `asn` presence), every sub-factor except transport, port-class, and rare CDN-pattern/ASN fields is **constant across the whole dataset**: `freshness_score` always 2 (no `first_seen` in the input), `test_score` always 10 (no `test_pass`), `ipv_score` 10 (IPv4) or 5, and the JA3 penalty is a pure function of transport+port. Result — the full tie-group distribution `[recomputed]`:

| final score | records | % of dataset | group working rate | what the group is |
|---|---|---|---|---|
| 43.1 | 574 | 35.3% | 273/574 = 0.476 | obfs4, IPv4 endpoint, non-safe port |
| 42.9 | 329 | 20.2% | **0/329 = 0.000** | obfs4, **bracketed IPv6** endpoints (see F4) |
| 27.0 | 301 | 18.5% | 101/301 = 0.336 | vanilla (`Bridge ip:port fp`) |
| 26.0 | 100 | 6.2% | 27/100 = 0.270 | vanilla, high ports |
| 57.0 | 70 | 4.3% | 44/70 = **0.629** | obfs4, IPv4, port 443 |
| 50.4 / 49.0 | 65 / 63 | 4.0% / 3.9% | 0.585 / 0.429 | obfs4 on other safe ports |
| (15 more values) | 124 | 7.6% | — | webtunnel/snowflake/meek/edge cases |

22 distinct finals / 1,626 records; largest tie group = **574**. The module's per-bridge discrimination on this input is therefore near-zero: it ranks *groups* (transport × port-class), not bridges.

### F2. The top-10 is decided by input-file order, not by quality — the ranking is not reproducible

`score_all` uses a stable descending sort (`src/smart_iran_scorer.rs:625-636`, Python-parity by design), so ties keep input order. The top-10 of the whole dataset contains 4 snowflake/webtunnel lines (F3) plus **the first 10 members of the 57.0 obfs4:443 cohort in input-file order** — verified: the members' input positions in `iran_results.json` are exactly `[422, 473, 478, 494, 501, 528, 547, 548, 549, 552]`, identical to the cohort's first ten `[recomputed]`. That cohort's true working rate is 0.629 — **above** baseline — but consecutive input-order slices of 10 within it range **3/10 … 10/10** working. The v42 measurement landed on the unluckiest slice.

Proof the number is a file-order property, not a quality property `[recomputed]`: reversing the input order changes top-10 membership and precision@10 from **2/10 to 5/10**. A ranking whose top-10 precision swings 0.2↔0.5 on input permutation is not measuring bridge quality at all in that zone.

### F3. 4 of the top 10 are TCP-untestable by design — the yardstick, not the scorer, mislabels them

The level-4 transport tables (DPI 0.95/0.88, NIN 1.00/0.90, boost 1.15/1.10) rank snowflake and webtunnel above everything. The top-10 therefore includes 2 snowflake broker-only lines and 2 webtunnel url-only lines. These **cannot pass the TCP tier by construction** (no endpoint to dial / the client dials the `url=` front, not the endpoint), so `tcp_reachable=false` regardless of real functionality:

- **snowflake ×2:** the transport-appropriate evidence is the relay probe — 6/6 successes in the same run's `pt_results` (funnel diagnostic, `[artifact]`). These are yardstick false-**negatives**, likely working bridges.
- **webtunnel-url ×2:** the v41 front-domain census (`[artifact]`, `vault.005184.xyz`, `coellen.xyz` → false) says genuine false positives — but n=2.

A third untestable class sits lower in the ranking: **329 obfs4 records with bracketed IPv6 endpoints** (`obfs4 [2001:1600:…]:443 …`) — 0/329 tcp_reachable, but GitHub runners have IPv4-only egress, so this is a **measurement-environment artifact**, not evidence of dead bridges (they are the pool's `obfs4_ipv6` family, 329 records, `[artifact]` `supply_diagnostics`). Total TCP-unmeasurable records: 336 (329 IPv6 + 7 broker/url-only). Re-ranking the measurable subset only (IPv4 endpoints, n=1,290, working rate 0.442) gives precision@10 = 3/10 — the top-10 of that ranking is entirely the 57.0 obfs4:443 cohort, and 3/10 is within that cohort's slice-variance range (F2).

### F4. No sub-factor is inverted — the two candidates check out directionally correct

- **Port-443 preference** (`SAFE_PORTS` 1.00, `iran_port_scores` 20) — the strongest inversion candidate: within obfs4, port 443 = 44/70 = **0.629** working vs port 80 = 5/13 = 0.385 vs other ports = 356/1061 = **0.336**. Monotone in the table's exact order (443 > 80 > rest). Directionally **correct**, strongly so.
- **Transport tables** — the only fully measurable comparison is obfs4 (0.354) vs vanilla (0.344): flat, not inverted. webtunnel IPv4: 2/2. The IPv6 group's 0.000 (F3) is environmental. The scorer even places the IPv6 cohort marginally *below* its IPv4 counterpart (42.9 vs 43.1, because the IPv4-only endpoint regex `smart_iran_scorer.rs:265-268` yields host=""/port=0 for bracketed IPv6, dropping the port signal) — an accidental but not harmful ordering for Iran, where IPv6 reachability is marginal.

**Verdict:** the directive's hypothesis (an inverted input) is **not supported by the data**. The 0.200 decomposes into (a) an arbitrary, input-order tie-break slice of a group whose true rate is 0.629 (F1+F2), (b) 4 yardstick-inappropriate members of which at least 2 are actually working per relay evidence (F3), and (c) small-n variance. The real defects are **non-reproducibility of the ranking** and **yardstick conflation** — and the deeper fact that the module has near-zero per-bridge discrimination on its current input schema. No weight rebalancing is justified; none is proposed.

## 3. Proposed minimal, additive, flagged correction (implemented only after this report)

Per the directive: minimal, additive, flagged; validated before/after on the same real dataset; no weight changes; module stays advisory-only and is not described as reliable or "smart".

1. **`--deterministic-tiebreak` flag on the `ai_bridge_reranker` bin (default OFF).** When on, ties are broken by a total order (final score desc, then bridge-id/raw asc) instead of input order. Default-off keeps today's ordering byte-identical (the lib's `score_all` stable sort — Python parity — is untouched; the re-sort lives in the bin). Fixes the reproducibility defect (F2).
   - **Before `[recomputed]`:** top-10 membership input-dependent; precision@10 = 0.2 forward, 0.5 reversed; not reproducible.
   - **After (flag on):** membership identical under both input orders; precision@10 = **0.6** on this dataset, top-50 = 0.7, top-100 = 0.6. *Explicitly not a quality claim:* a deterministic key is quality-neutral, and 0.6 ≈ the 57.0-cohort rate (0.629) as expected — the fix makes the number **stable and auditable**, not larger by design. On another dataset the deterministic slice could sit anywhere within the cohort's rate.
2. **Per-bridge `tcp_tier_measurable` field + summary counts (always-on, report-only).** True iff the line carries an IPv4 `ip:port` endpoint (the only form the Go TCP tier can dial from an IPv4-only runner). Lets any future precision audit split measurable vs unmeasurable up front (F3): 1,290 measurable / 336 unmeasurable (329 IPv6-endpoint + 7 broker/url-only) on this dataset.
3. **Summary degeneracy disclosure (always-on, report-only):** `distinct_final_scores` (22 here), `largest_tie_group` (574 here), and the active `tiebreak` mode. Any consumer of the ranked artifact can now see the discrimination ceiling without re-deriving it.

All three live in `src/bin/ai_bridge_reranker.rs` only; no lib behavior, score, tier, or workflow step changes; the artifact (`bridge/bridges_ai_iran_ranked.json`) remains advisory/upload-only, never in the 55-file contract, never committed. **Promotion of this module toward anything user-facing remains blocked** — now with a stronger reason: near-zero per-bridge discrimination (F1), which no tie-break flag fixes.

## 4. v43 §3 — The recurring token-expiry pattern (evidence + constraint + process proposal)

### 4.1 Both incidents, with real timestamps

All timestamps UTC, from real artifacts (git commit dates, PR comment `created_at`, and the session polls that observed the 401s):

| | Incident 1 (v41-final session) | Incident 2 (v42 session) |
|---|---|---|
| First confirmed authenticated call | 20:56:01Z — push of `c4b701e8` `[git artifact]` (earlier calls likely; session began ~20:53Z) | ~22:20–22:24Z — token issued by the owner's incident-1 reconnect; the v42 session's own early anchors are the live mirror fetches (GitHub API) before the 23:00:41Z commit |
| Last confirmed OK before expiry | the `gh pr edit 228` body update that followed full-green confirmation — after 21:44:52Z (run `34278561590` completion `[GitHub artifact]`); not precisely timestamped (~21:45–22:05Z window) | 23:14:46Z — successful `gh run view` poll (main-ci in_progress) |
| First 401 observed | within the ~12-minute dead window that followed (~22:0xZ; session record logged ~12 min of persistent 401 retries) | **23:17:17Z** — poll returned `HTTP 401: Bad credentials`; confirmed by `gh auth status` → "token … no longer valid" at 23:18:17Z; still dead at 23:23:11Z |
| Restored by owner reconnect | by 22:16:41Z — post-reconnect authenticated `gh api` call that generated the job-log URL (its `st=2026-09-08T22:16:41Z` parameter timestamps the call); §1 comment posted 22:24:10Z `[GitHub artifact]` | between 23:27Z and 23:35Z (next session's first `gh` call succeeded; that session then committed `93a71121` at 23:38:09Z `[git artifact]`) |
| **Observed working span of the token** | **≈ 50–70 minutes** (20:56→somewhere 21:45–22:05) | **≈ 51–55 minutes** (reconnect ~22:20–22:24 → 23:14:46) |

Common shape: both expirations hit **while holding an open polling loop** (incident 1: polling run 34278561590's tail after full green; incident 2: polling the 33-minute TorShield-IR run 34288669641). For scale: TorShield-IR end-to-end ≈ 33–40 min (`34288669641`: 23:00:47→23:33:42Z; `34291534536`: 23:38:16→00:13:18Z `[GitHub artifact]`), main-ci ≈ 17 min (`34288669205`: 23:00:47→23:17:51Z). The token's TTL is consumed by **cumulative session time**, not by any single job — so any poll started late in a session can straddle the expiry even when the job itself is short. Observed working spans ≈ 50–70 min are consistent with a roughly ~1-hour fixed TTL.

**Addendum (2026-09-09, added after the fact): a third expiry occurred 01:14:57–01:19:13Z, mid-v43** — again during a TorShield-IR poll (run 34296317004), ~55 minutes into the session, and again only an owner reconnect can restore access. This third data point was predicted by the pattern above and was handled per the §4.3 process (all writes already committed/pushed/posted before the poll; a checkpoint was persisted; polling stopped immediately on the 401).

### 4.2 TTL/refresh investigation (real probes, 2026-09-09 ~00:22–00:24Z)

- `GET /rate_limit` with the token: **200**, `x-ratelimit-limit: 5000` — authenticated, not rate-limited. The response carries **no `github-authentication-token-expiration` header** — the API does not expose this credential's expiry, so the exact TTL cannot be read, only bounded by observation (above).
- `GET /user` with the token: **403** — a scoped, non-interactive credential (cannot even read the user object).
- `gh auth refresh --hostname github.com`: refuses — exact output: *"The value of the GH_TOKEN environment variable is being used for authentication. To refresh credentials stored in GitHub CLI, first clear the value from the environment."* Clearing `GH_TOKEN` would leave no credentials at all (nothing is stored in the CLI's keyring for this bot), so **no in-sandbox refresh path exists**. The token is a fixed-TTL, platform-injected credential; the only replacement mechanism is the owner reconnecting GitHub in Arena (proven twice: both incidents ended only that way).

Per the directive, no engineering time is spent trying to extend the token from inside the sandbox — the constraint is reported as-is: **~1-hour credential, no refresh, expect death during any long poll.**

### 4.3 Proposed default polling behavior (process change, not collector code)

Adopt as the default for **all** CI polls (the observed failure mode is expiry-by-cumulative-session-time, so even a 17-minute job polled late in a session can straddle it):

1. **Write first, poll last:** complete and push/post every irreversible artifact (commits, pushes, PR comments, report files) *before* entering a long poll, so an expired token can never strand un-posted work. (This session follows it: the report and PR comment precede the final CI poll.)
2. **Bounded, sparse polling:** fixed interval (≥3–5 min) with a hard attempt cap; on each iteration checkpoint the run ID + pending readouts to the workspace; when the cap is hit, **exit the poll cleanly** with the checkpoint recorded rather than holding an open loop across the job's full duration.
3. **On 401: stop immediately** — at most one confirmatory retry (`gh auth status`), then report the reconnect need with the checkpoint. The incident-1 ~12-minute retry loop and incident-2's 6+ minutes of dead polling were pure waste; both tokens stayed dead until the owner acted.
4. **Prefer cheap reads while polling:** run-status and check-run annotation APIs instead of job-log URL fetching (which needs a fresh signed URL per fetch anyway).

## 5. Proven vs unverified

**Proven (real artifacts / live re-execution):**
- §1 run statuses and the v42 precision table's provenance (run 34262011946 committed artifacts; live validation in v42).
- F1 tie-group table, F2 input-position proof + reversal experiment, F3 unmeasurable census (329 IPv6 + 7 broker/url) and the snowflake relay 6/6 + webtunnel-front census cross-references, F4 port/transport correlation directions — all `[recomputed]` on the committed dataset with the v42-validated port.
- §3 incident timelines (git/PR/poll artifacts cited inline); token probes (200/403/no-header/refresh-refusal) executed 2026-09-09 00:22–00:24Z; both incidents' resolution-by-reconnect.
- §3 before/after tie-break validation (0.2/0.5 input-dependent → invariant, 0.6 on this dataset, quality-neutrality caveat stated).

**Unverified until the post-change CI run (`[expectation]`):**
- The Rust implementation of the three corrections (compiles, unit tests pass, artifact schema as specified) — no local Rust toolchain exists in this sandbox; CI is the compiler, per established process. The unit tests to be added alongside (deterministic tie-break invariance under input permutation; `tcp_tier_measurable` classification; summary field computation) run in the rust-parity job.
- The 0.6/0.7 top-K figures under the flag are dataset-specific `[recomputed]` values, not general quality properties — they will not be cited as capability claims.

---

*Committed before any behavior-affecting code change, per v43 §4. The corrections in §3 are implemented after this report, in the same PR (#228), with real CI URLs to follow.*

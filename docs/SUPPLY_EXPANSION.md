# Supply Expansion — extended low-count transport draws

Status: **additive-only** — nothing in this change removes, disables, weakens,
or replaces an existing feature, filter, validation, safety check, test, or
output file.

This document records: (1) the measured BEFORE state, (2) the legitimate
upstream sources that exist for each low-count transport and why the pools are
small, (3) the new capability added (`supply_extender` / Stage 1x) and its
guarantees, (4) how BEFORE/AFTER is measured, and (5) the honest expectations
per transport — including the transports whose supply genuinely cannot be
raised by any additional legitimate source.

---

## 1. BEFORE state (measured at commit `ef17002`, run 34051625648)

Raw candidates and tested/advisory projections as committed in `bridge/`:

| transport | raw `.txt` | `_tested.txt` | history (JSON) | advisory |
|---|---|---|---|---|
| obfs4 (ipv4) | 814 | 405 | 1143 records | iran_likely_working_obfs4 405 |
| vanilla (ipv4) | (large) | — | 473 records total | — |
| **webtunnel** | 4 (all URL-only, IPv4) | 2 | 255 (4 IPv4 URL-only + 251 IPv6 doc-prefix) | 2 |
| **webtunnel_ipv6** | 251 (doc-prefix `2001:db8::/32`) | 129 | see above | (doc-prefix excluded by design) |
| **snowflake** | 2 | 4 | 2 | 4 |
| **snowflake_ipv6** | 4 | 4 | — | — |
| **conjure** | 1 | 1 | 1 | — |
| **meek-azure** | 1 | 1 | 2 | — |
| **meek_lite** | 2 | 3 | (part of meek-azure records) | — |
| **vanilla_ipv6** | 2 | 4 | — | — |

`bridge_list_for_testing.json` (the probe-input list) holds 1876 lines;
`iran_results.json` holds 1621 tested records.  These numbers are inputs to
the probing stages, not outputs of this change.

## 2. Upstream supply reality per transport (investigation result)

The pipeline already queries, every run:
- **BridgeDB HTML** (`bridges.torproject.org/bridges?transport=…` × ipv6
  toggle) for obfs4, webtunnel, vanilla (6 fixed URLs, core `scraper` stage)
  and, via the unified collector, also snowflake/meek-azure/conjure URLs;
- **MOAT** (`/moat/circumvention/builtin` + `/settings`) with an Iran payload
  requesting obfs4 + webTunnel + snowflake;
- a **community seed mirror** (GitHub contents API → `bridge/*.txt`), an
  operator-extensible mirror list, and Telegram channels when credentials are
  configured.

Why the pools are small is therefore mostly *upstream*, not pipeline:

- **webtunnel**: BridgeDB distributes a small, operator-run webtunnel fleet.
  The HTML/MOAT pages return the same handful of URL-fronted IPv4 lines
  (vika7.space, jochenkessler.de, vault.005184.xyz, coellen.xyz).  Of those,
  only the first two pass a live TCP + WebSocket-101 probe today; the other
  two fail 27/27 probes (genuinely offline, not transient).  IPv6 pages
  return `2001:db8::/32` documentation-address placeholders which the
  reserved-endpoint filters reject — correctly.
- **snowflake**: snowflake is not a pool of fixed IP bridges; BridgeDB serves
  a small set of client-configuration lines (broker URL + front + ICE
  variants).  Over ~119 runs the pipeline has seen exactly 2 distinct
  snowflake identities; the 4 advisory lines are front/ICE variants of those
  2.  The web endpoint for `?transport=snowflake` exists but was not in the
  core scraper's six fixed HTML targets — the collector stage did request it.
- **conjure**: there is exactly one public conjure registration line
  (`url=https://registration.refraction.network/api`).  Conjure is an
  operator/community transport; BridgeDB does not distribute a rotating
  conjure pool, and no other legitimate public source publishes additional
  conjure bridge lines.  **Supply cannot currently be increased; the count of
  1 is the universe.**
- **meek-azure / meek_lite**: the fleet is the two legacy `meek.azureedge.net`
  fronted lines (2 fingerprints).  The meek-azure CDN front was sunset by the
  Tor Project; no official distribution channel serves additional meek lines
  today.  **Supply cannot currently be increased.**
- **vanilla_ipv6**: plain relays with IPv6 ORPorts are served by BridgeDB's
  `vanilla&ipv6=yes` page (already fetched every run); the distinct count
  BridgeDB rotates through is small per country.

**Email/GetTor**: `bridges@torproject.org` exists but requires mailbox round
trips per request and is not safely automatable in CI; it serves the same
BridgeDB pool anyway.

## 3. What was added (all new files/steps, zero existing-logic edits)

1. `src/supply_extension.rs` — new library module (registered in `src/lib.rs`):
   - extra BridgeDB HTML slugs not in the core target list
     (`snowflake`, `snowflake&ipv6=yes`);
   - bounded **rotation draws** over the existing six core targets
     (`SUPPLY_EXTRA_DRAWS`, default 1, clamp 0–6);
   - **single-transport MOAT draws** (`MOAT_EXTRA_ROUNDS`, default 1,
     clamp 0–3) reusing the exact same request schema, headers, endpoints,
     and response parser as the core MOAT fetch;
   - jittered pacing (0.6–1.8 s) between requests; single attempt per URL
     (no retry amplification); every response parsed with the same
     `parse_bridgelines_html` / `parse_moat_response` validation chain;
     merging into `bridge_history.json` through the same
     `merge_raw_into_history` / `normalize_for_history` dedup as all other
     sources (no filter, ip_guard, or reserved-endpoint gate bypassed);
   - diagnostics helpers + unit tests.
2. `src/bin/supply_extender.rs` — new binary: loads history, runs the extra
   draws (network feature gate, like the core scraper), merges, prunes,
   saves, and writes **two new files**:
   - `data/supply_diagnostics.json` — per-source request/OK/fetched-line
     counters and per-transport-family history `before`/`after`/`added`;
   - `data/supply_diagnostics_history.json` — append-only run history
     (capped at 500 entries) so supply growth is trackable over time.
   It also emits a GitHub Actions step summary and `::notice` annotations
   per low-count family, so AFTER counts are visible on the run page.
   No existing output file is touched.  `data/` is already staged by the
   existing Stage 11 commit step, so on `main` production runs the
   diagnostics persist into the repository automatically.
3. `.github/workflows/torshield-ir.yml` — two new steps, both purely additive:
   - in `scrape-and-test`, **Stage 1x — Extended low-supply source draws +
     supply diagnostics (additive)**, placed after Stage 1 and before
     FAILSAFE.  It is `continue-on-error: true` (like all other supply
     stages) with an 8-minute budget;
   - in `scrape-and-test-finalize`, **Stage 10y — Low-supply count deltas vs
     HEAD (informational, additive)**, placed after Stage 10.  It emits one
     workflow `::notice` per low-supply file with `before=<committed>`
     `after=<this run>` line counts (report-only, never fails on a delta).
   The Stage 9b 55-file publication contract, FAILSAFE, Stage 10, and every
   existing test are untouched and still run.

## 3b. Probing-capability investigation (why no probe-path change was made)

The task asked for advanced probing additions (webtunnel multi-front probes /
retry tuning, snowflake STUN/rendezvous alternatives, extra conjure/meek
reflector endpoints).  The probe paths were investigated
(`webtunnel_probe.rs`, `results_writer.rs`, the Stage 2–4 tester chain) and
left unchanged, for measured reasons:

- **webtunnel retries**: the two non-working raw candidates
  (vault.005184.xyz, coellen.xyz) already fail 27/27 live TCP probes — a
  failure pattern of genuinely offline fronts, not transient drops.  Extra
  retry/backoff would not change their verdict, and touching the shared probe
  threshold path risks weakening a real safety check.
- **webtunnel multi-front probing**: every raw IPv4 webtunnel candidate in
  history advertises exactly one front URL; there are no multi-front
  candidates whose second front could be probed.
- **snowflake**: the 2–4 candidate lines are broker/client-configuration
  lines (broker URL + front + ICE list).  There is exactly one official
  broker (`snowflake-broker.torproject.net`); no second legitimate
  rendezvous/STUN registration path exists to probe, and the ICE servers
  listed are end-client STUN servers, not probe endpoints.
- **conjure / meek-azure**: single operator registration line / sunset legacy
  fleet — see section 2.

Supply-side additions (section 3) are therefore the only change that can
legitimately raise counts, and they are implemented as described.

## 4. Rate-limit and ToS posture

- Self-limited ceilings per run (default: 8 extra HTML GETs + 6 extra MOAT
  POSTs) with jittered pacing between requests — a small multiple of the
  requests the pipeline already makes, spread across the run.
- No retry loops that could multiply volume on a failing endpoint.
- All requests are plain, unauthenticated GET/POST to the official public
  distributor endpoints with a normal browser User-Agent (same as existing
  stages); no captcha solving, no session forging, no credential use.
- Each extra request failing (HTTP error, challenge page, empty body) simply
  yields zero lines and a diagnostic entry — it never fails the pipeline.

## 5. BEFORE/AFTER measurement methodology

- **Raw supply AFTER**: the post-run `bridge_history.json` record count per
  transport family (see `data/supply_diagnostics.json`
  `history_family_counts.after`, and the per-run history file for growth over
  time).  Raw counts only ever grow or stay equal: merging is additive and
  history pruning keeps records for 30 days.
- **Projection/tested AFTER**: the `bridge/*.txt` projections of the same
  run (Stage 9b verifies the full 55-file contract byte-identically; FAILSAFE
  and Stage 10 run after it).  New lines drawn by Stage 1x enter the raw pool
  the same run (the publisher regenerates projections from history at Stage 9)
  and become probe candidates on the *following* run, because probing input
  (`bridge_list_for_testing.json`) is snapshotted earlier in the pipeline.
- Honest reporting: per-run deltas can be zero even when a source is healthy
  (BridgeDB rotation can repeat lines); growth is expected to accumulate over
  runs.  A single-run BEFORE/AFTER comparison is reported for every affected
  transport, and any zero/negative delta is reported as-is — never
  compensated with synthetic or fabricated candidates.

## 6. Expected effect per transport (honest expectations)

| transport | likely effect of Stage 1x | reason |
|---|---|---|
| webtunnel | raw: +0..few over time; tested: unchanged until upstream adds fronts | upstream pool tiny; 2 live fronts today |
| snowflake | raw/advisory: +0..few variants over time | rotation draws surface the small existing config set |
| vanilla_ipv6 | raw: +0..few over time | small BridgeDB IPv6 pool |
| conjure | none | single public line; no other source exists |
| meek-azure / meek_lite | none | legacy fleet; service sunset upstream |

# RCA — Actions run `1593` and the under-collection incident

**Date:** 2026-08-05 UTC
**Repository:** `ysa-py/Tor-Bridges-Collector`
**Fix branch:** `arena/019fd33d-tor-bridges-collector`

## Evidence boundary

The first investigation action was an API lookup, as required:

```text
gh run view 1593 --json ...
GET /repos/ysa-py/Tor-Bridges-Collector/actions/runs/1593
→ HTTP 404 Not Found
```

Run `1593` is no longer retained by GitHub. The repository's cleanup workflow
has removed the run, so its raw job log cannot be recovered from the Actions
API. I am not treating an unavailable log as evidence and have not invented a
line-by-line root cause for that historical run.

The latest successful baseline was independently inspected through the API:

- workflow run database ID `31004820127` (workflow run number `549`);
- jobs: `rust-parity-tests`, `Quality Gate`, `build-rust`, `scrape-and-test`,
  `AI Bridge Re-Ranker (Iran)`, `Package Final Artifact`, and cleanup;
- all jobs concluded `success`;
- `scrape-and-test` job ID was `92303426864` and ran from
  `2026-08-05T12:21:16Z` to `2026-08-05T12:45:02Z`.

GitHub returned the signed log/artifact URLs, but this execution environment
could not read the Actions Results/Blob host (`EOF`). The checked-in reports
and bridge history were therefore used as a second, reproducible evidence
source. The new whole-run diagnostic workflow now downloads the complete log
for every retained parent run and stores a redacted machine-readable report;
future cleanup must not erase the report needed for an RCA.

## Root causes established from retained evidence

### 1. MOAT returned valid data that the parser discarded

`data/moat_diagnostics.json` contains HTTP 200 responses whose body begins
with the live schema:

```json
{"obfs4":["obfs4 ..."],"meek":["meek_lite ..."]}
```

The settings endpoint also returned:

```json
{"settings":[{"bridges":{"type":"snowflake","bridge_strings":["..."]}}]}
```

The old parser only walked `response["bridges"]`. Consequently these valid
HTTP 200 payloads became an empty vector and the pipeline logged a false
`MOAT ... 0 bridges` condition.

**Fix:** `scraper::parse_moat_response` now negotiates all three schemas:
`bridges` maps, live top-level transport maps, and
`settings[].bridges.bridge_strings`. It maps transport aliases, rejects
reserved/documentation endpoints, deduplicates, and records a parsed result.
MOAT requests now use bounded jittered retries (`MOAT_RETRIES`, default 3).

### 2. `continue-on-error` plus FAILSAFE converted functional defects into green

The collection, probing, optional analysis, and Stage 00 steps allowed errors
to continue. The publisher then force-populated empty projections from static
lines. This made a successful process exit mean only “the workflow reached the
next step,” not “live collection succeeded.” The retained baseline explains
the observed low/static files: the fallback mechanism was doing exactly what
it was coded to do.

**Fix:** every FAILSAFE activation is now appended to
`data/failsafe_activations.json` with transport, file, count, timestamp, and
reason. The publication fallback path records the same metric, so fallback
frequency is visible rather than silently swallowed. Empty static fallback is
never replaced with a made-up `0.0.0.0:0` placeholder; the workflow errors if
the Rust fallback source itself is unavailable. The whole-run classifier marks
fallback use as an error-level functional anomaly even when the shell exit
code is zero.

The existing 55-file publication contract is preserved. Static fallback remains
an explicit last-resort compatibility path, but it is now measurable and
cannot be confused with live yield.

### 3. The IPv4 obfs4 harness was not initialized correctly, and failed handshakes
were reported as a TCP success set

The managed transport harness did not send the required `VERSION 1` controller
line before waiting for `CMETHOD`. In addition, the SOCKS credentials were sent
as one semicolon-joined username instead of the obfs4 convention of
`username=cert=...` and `password=iat-mode=...`. This explains a harness that
starts with no successful SOCKS exchanges (the retained baseline reported
`0/255`). The old policy then retained the TCP-reachable set below its minimum
fraction, masking the protocol failure.

**Fix:** the harness sends and flushes `VERSION 1`, keeps its stdin open for
managed-transport lifetime, and splits the SOCKS credentials correctly. The
verification result now records attempted/failed counts. When a real harness
runs and verifies `0/N`, the tested projection contains only the verified
subset (possibly zero) and the log reports an error; it no longer labels the
TCP set as protocol-verified. If no harness is installed, the archive may keep
TCP candidates, but the log explicitly says they are **unverified**.

### 4. Source coverage and selection were narrower than the output contract

The unified collector fetched BridgeDB and one community filename for only the
three pooled transports. Fronted transports were populated from one compiled
default line each. IPv4 WebTunnel and IPv6 Vanilla therefore had no redundant
source path when the primary BridgeDB response used a different query parser.
The collector also passed a fixed `600` candidate ceiling from the workflow.

**Fix:**

- all pooled and fronted transports use BridgeDB plus community mirrors;
- community filename aliases cover `meek-azure`, `meek_lite`, and `meek`;
- `BRIDGE_SOURCE_BASES` can add compliant public mirrors without code changes;
- BridgeDB retries explicit `ipv6=yes/true` and `ipv6=no`/legacy query forms;
- fronted IPv4 and IPv6 projections are collected rather than only seeding an
  IPv4 default;
- `MAX_TEST_PER_LIST=0` is now adaptive mode and tests the complete
  deduplicated source/archive pool. A positive value remains an explicit
  operator safety valve;
- the worker ceiling derives from runner parallelism when unset and the
  existing per-transport adaptive controller scales permits from observed
  success rates.

The collector emits `data/collector_yield_report.json` and
`data/collector_yield_summary.md` with archive/fresh/tested counts for every
transport and the active dynamic-pool setting.

### 5. Zig Stage 8q was optional by construction

The old workflow checked `command -v zig` and printed
`Zig not available — skipping Stage 8q`; the build and scanner were also
wrapped in `|| true`. This was a silent capability gap.

**Fix:** the workflow now installs pinned Zig `0.14.0` with
`mlugg/setup-zig@v2`, fails if the toolchain or `zig-scanner` binary is absent,
and requires a non-empty `data/zig_scan.json` output.

## Defensive CI and regression coverage

`src/pipeline_diagnostics.rs` reads every input line and classifies:

- hard failures and non-zero exits;
- empty/short source output and source gaps;
- FAILSAFE/static fallback activation;
- timeouts, rate limits, DNS/TLS failures;
- artifact digest mismatches and stale cache signals;
- obfs4/transport handshake failures;
- MOAT empty-200 responses and skipped required stages.

`src/bin/self_heal` now supports:

```text
self_heal --log COMPLETE_JOB_LOG --heal --output data/whole_run_diagnostics.json
```

It performs only safe, idempotent local repairs (directory creation and empty
JSON initialization), produces affected-stage retry/remediation actions, and
can be made a strict gate with `--strict`. It never fabricates a bridge or
writes a credential. `.github/workflows/ai_self_healing.yml` downloads the
complete parent log after every non-self-healing workflow run, runs this loop,
and uploads the redacted report.

Regression tests:

- `tests/pipeline_diagnostics.rs` asserts that the exact silent-success fixture
  (`MOAT 0`, `0/255` handshakes, FAILSAFE force-population, and Zig skip) is
  failed, not healthy;
- unit tests cover live MOAT top-level and settings schemas;
- collector tests assert failed real obfs4 handshakes are not returned as
  tested lines;
- existing publication, parity, self-heal, and 55-file contract tests remain
  enabled.

## Verification status

Local static verification is performed in the repository after these changes:
`cargo fmt --all -- --check`, Clippy with `-D warnings`, the new diagnostics
contract, and the existing workspace tests. A live GitHub Actions run is still
required to measure post-fix upstream yield and handshake success; the
historical run `1593` cannot be replayed because GitHub has deleted it. The
pipeline now reports the evidence needed to compare that run objectively:
per-source yield, per-transport counts, handshake fractions, and fallback rate.

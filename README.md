# 🛡️ TorShield-IR — Rust-native Tor Bridge Intelligence

> Automated collection, runner-side reachability probing, Iran-aware ranking, and dual publication for `bridge/` and Telegram.
>
> **Last publication:** `2026-10-09T10:28:13Z` · **Archive payload SHA-256:** `14e4f78447bf60d97e7c48e09753a8697ff33045162bf2bff157649dd4ab2207`

## Quick use for Iran

1. Start with [iran_likely_working_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_ipv4_ipv6_all.txt) (the legacy [iran_likely_working_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_all.txt) remains available) for the current advisory working set.
2. Prefer [iran_likely_working_obfs4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_obfs4.txt) under ordinary DPI and [iran_likely_working_snowflake.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_snowflake.txt) / [iran_likely_working_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_webtunnel.txt) when a CDN/WebRTC route is appropriate.
3. During a national-internet-cut scenario, try [iran_likely_working_nin.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_nin.txt); it is a prioritized *advisory* set, not a connectivity guarantee.
4. Import the selected lines in Tor Browser: **Settings → Connection → Bridges → Add a Bridge Manually**.

## Current publication snapshot

| Output | Entries | Purpose |
| --- | ---: | --- |
| [iran_likely_working_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_all.txt) | `638` | Evidence-backed advisory set across transports |
| [iran_likely_working_obfs4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_obfs4.txt) | `468` | obfs4-oriented fallback for conventional DPI |
| [iran_likely_working_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_webtunnel.txt) | `2` | WebTunnel candidates |
| [iran_likely_working_snowflake.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_snowflake.txt) | `1` | Snowflake capability candidates |
| [iran_likely_working_nin.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_nin.txt) | `3` | NIN/cut-mode priority candidates |
| [iran_blocked.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_blocked.txt) | `0` | Observations classified as blocked |
| [tor_bridges.zip](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/tor_bridges.zip) | `78` files | Same verified payload used for Telegram delivery |
| [telegram_manifest.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/telegram_manifest.json) | — | SHA-256 inventory, evidence scope, and archive contract |

## What the automation actually does

The GitHub Actions workflow is Rust-native and schedules the full bounded pipeline at minute 0 of every UTC hour on the default branch. Runs targeting the same branch serialize without cancellation so artifacts start from the latest committed state; a run taking longer than an hour can delay or coalesce a refresh because GitHub scheduling is best-effort:

1. Collects from built-in fallback bridges and, when available, Tor Project/MOAT sources.
2. Runs bounded concurrent TCP reachability probes from the GitHub runner. A TCP success is clearly recorded as a **runner-side observation**, not a claim that the endpoint works in Iran.
3. Applies the existing Rust DPI, NIN, transport-rotation, and Iran scoring components to produce advisory output sets.
4. Rewrites each derived `bridge/` output with atomic file replacement, including explicit IPv4/IPv6/all-family aliases; verifies JSON shapes, manifest hashes, and every ZIP entry.
5. Preserves `bridge_history.json` and `iran_results.json` as canonical inputs, and removes stale/unmanaged files only after the new publication verifies successfully.
6. Uses that exact ZIP for Telegram upload when explicitly enabled and configured, then commits the same verified `bridge/` payload and this README.

## Autonomous diagnostics and dynamic yield

The Rust whole-run self-healing engine audits every retained job-log line for swallowed errors, empty/short source responses, MOAT schema failures, rate limits, handshake failures, stale caches, artifact mismatches, skipped toolchains, and static FAILSAFE use. It emits affected-stage retry plans and records idempotent safe repairs without fabricating bridge data.

BridgeDB query variants, MOAT top-level/settings schemas, and redundant community mirrors are merged with adaptive concurrency. `MAX_TEST_PER_LIST=0` tests the complete deduplicated source pool; a positive value is an explicit safety ceiling. See `data/collector_yield_report.json`, `data/collector_yield_summary.md`, `data/collector_yield_history.json`, and `data/failsafe_activations.json` for per-transport yield trends and fallback telemetry. Stage 8q installs and verifies its pinned Zig toolchain instead of silently skipping.

## Machine-readable changelog and per-entry test evidence

Every successful publication appends a timestamped entry to
`data/publication_changelog.json` (schema version, ISO-8601 UTC run time, the
verified archive SHA-256, per-file entry counts, and evidence tier/result
counts). Each entry in `bridge/iran_results.json` is stamped with `tested_at`
(the run timestamp), `test_tier` (`tier_2_pt_handshake` / `tier_1_tcp` /
`untested`), and `test_result` (`tested_working` / `tested_failing` /
`untested (rate-limited)`) derived from the recorded probe observations; the
run-level `evidence` block summarises the stamping pass. Tiers and results are
per-observation — they record *how* an endpoint was tested, never an assertion
of Iranian reachability.

## Telegram dual persistence

Telegram delivery uses a bot token and distributes a bridge inventory outside GitHub, so it requires explicit configuration; once configured it is fully automatic.

- Set repository secrets `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`; delivery is then ON by default for schedule, push, and manual runs.
- Opt out per run by selecting **false** in **Run workflow**, or repo-wide with the `TELEGRAM_AUTO_UPLOAD=false` repository variable. Pull-request runs never deliver (preview only).
- The publisher builds and verifies one `tor_bridges.zip`; GitHub and Telegram consume that exact file. Cross-service commits cannot be literally atomic, so an upload failure stops the workflow before the repository commit step whenever possible.

## Evidence and safety notes

- `*_tested.txt` means the latest pipeline recorded a successful TCP observation or a transport-capability check where raw TCP is not meaningful (for example Snowflake). It does **not** prove a full Tor circuit or Iranian reachability.
- `iran_likely_working_*` and anti-DPI scores are decision aids, not guarantees. Censorship conditions vary by ISP, region, time, and Tor Browser version.
- The AI/DPI-labelled reports in `data/` are deterministic scoring/telemetry analyses. They are not a promise that an AI system can defeat filtering or DPI.
- Never place personal credentials in bridge files, commit messages, workflow inputs, or Telegram captions.

## Filename conventions

- `*_ipv4_ipv6_all.txt` combines candidates across both address families; `*_ipv4.txt` and `*_ipv6.txt` are family-specific.
- `*_72h*` is limited to candidates observed within the 72-hour freshness window. `*_tested*` is evidence-only; an empty file means no qualifying observation, not a failed build.
- Historical filenames remain available as compatibility aliases. The requested misspelling `snowflak_ipv4_ipv6_all.txt` and extensionless `snowflake_ipv6_tested` are generated too; correctly spelled `.txt` aliases are included as well.

## Complete `bridge/` contract

<details>
<summary>Show all 79 required files refreshed by the publisher</summary>

- [bridge_history.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/bridge_history.json)
- [bridge_list_for_testing.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/bridge_list_for_testing.json)
- [bridge_scores.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/bridge_scores.json)
- [conjure.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/conjure.txt)
- [conjure_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/conjure_72h.txt)
- [conjure_72h_ipv4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/conjure_72h_ipv4.txt)
- [conjure_72h_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/conjure_72h_ipv6.txt)
- [conjure_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/conjure_ipv4_ipv6_all.txt)
- [conjure_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/conjure_tested.txt)
- [iran_blocked.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_blocked.txt)
- [iran_blocked_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_blocked_ipv4_ipv6_all.txt)
- [iran_likely_working_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_all.txt)
- [iran_likely_working_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_ipv4_ipv6_all.txt)
- [iran_likely_working_nin.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_nin.txt)
- [iran_likely_working_obfs4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_obfs4.txt)
- [iran_likely_working_snowflake.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_snowflake.txt)
- [iran_likely_working_vanilla.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_vanilla.txt)
- [iran_likely_working_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_webtunnel.txt)
- [iran_results.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_results.json)
- [meek-azure.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek-azure.txt)
- [meek-azure_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek-azure_72h.txt)
- [meek-azure_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek-azure_all.txt)
- [meek-azure_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek-azure_tested.txt)
- [meek_lite.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite.txt)
- [meek_lite_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite_72h.txt)
- [meek_lite_72h_ipv4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite_72h_ipv4.txt)
- [meek_lite_72h_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite_72h_ipv6.txt)
- [meek_lite_ipv4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite_ipv4.txt)
- [meek_lite_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite_ipv4_ipv6_all.txt)
- [meek_lite_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite_ipv6.txt)
- [meek_lite_ipv6_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite_ipv6_tested.txt)
- [meek_lite_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/meek_lite_tested.txt)
- [obfs4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4.txt)
- [obfs4_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_72h.txt)
- [obfs4_72h_ipv4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_72h_ipv4.txt)
- [obfs4_72h_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_72h_ipv6.txt)
- [obfs4_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_ipv4_ipv6_all.txt)
- [obfs4_ipv4_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_ipv4_tested.txt)
- [obfs4_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_ipv6.txt)
- [obfs4_ipv6_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_ipv6_72h.txt)
- [obfs4_ipv6_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_ipv6_tested.txt)
- [obfs4_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/obfs4_tested.txt)
- [snowflak_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflak_ipv4_ipv6_all.txt)
- [snowflake.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake.txt)
- [snowflake_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake_72h.txt)
- [snowflake_72h_ipv4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake_72h_ipv4.txt)
- [snowflake_72h_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake_72h_ipv6.txt)
- [snowflake_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake_ipv4_ipv6_all.txt)
- [snowflake_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake_ipv6.txt)
- [snowflake_ipv6_tested](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake_ipv6_tested)
- [snowflake_ipv6_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake_ipv6_tested.txt)
- [snowflake_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/snowflake_tested.txt)
- [telegram_manifest.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/telegram_manifest.json)
- [tested_global_obfs4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/tested_global_obfs4.txt)
- [tested_global_vanilla.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/tested_global_vanilla.txt)
- [tested_global_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/tested_global_webtunnel.txt)
- [tor_bridges.zip](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/tor_bridges.zip)
- [vanilla.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla.txt)
- [vanilla_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_72h.txt)
- [vanilla_72h_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_72h_ipv6.txt)
- [vanilla_ipv4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv4.txt)
- [vanilla_ipv4_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv4_72h.txt)
- [vanilla_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv4_ipv6_all.txt)
- [vanilla_ipv4_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv4_tested.txt)
- [vanilla_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv6.txt)
- [vanilla_ipv6_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv6_72h.txt)
- [vanilla_ipv6_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_ipv6_tested.txt)
- [vanilla_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/vanilla_tested.txt)
- [webtunnel.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel.txt)
- [webtunnel_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_72h.txt)
- [webtunnel_72h_ipv4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_72h_ipv4.txt)
- [webtunnel_72h_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_72h_ipv6.txt)
- [webtunnel_ipv4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv4.txt)
- [webtunnel_ipv4_ipv6_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv4_ipv6_all.txt)
- [webtunnel_ipv4_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv4_tested.txt)
- [webtunnel_ipv6.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv6.txt)
- [webtunnel_ipv6_72h.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv6_72h.txt)
- [webtunnel_ipv6_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_ipv6_tested.txt)
- [webtunnel_tested.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/webtunnel_tested.txt)
</details>

## Local verification

```bash
# Full Rust test suite (including offline publication contract tests)
cargo test --workspace --all-targets

# Rebuild the bridge distribution package without Telegram delivery
cargo run --release --bin sync_bridge_outputs -- \
  --bridge-dir bridge \
  --repo-url "https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main" \
  --readme README.md

# Verify an existing publication without changing it
cargo run --release --bin sync_bridge_outputs -- \
  --bridge-dir bridge \
  --verify-only
```

The authoritative machine-readable inventory is [telegram_manifest.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/telegram_manifest.json). Consumers should validate its SHA-256 entries after downloading bridge files.

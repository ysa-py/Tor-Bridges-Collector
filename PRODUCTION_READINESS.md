# PRODUCTION_READINESS

## Existing verified capabilities and current-branch status

1. **Deterministic publication contract.** This branch expands the publisher
   to a 79-path `bridge/` inventory (78 ZIP entries plus the archive itself),
   with manifest/hash/ZIP verification and `--verify-only` coverage. The
   expanded contract has not yet had a fresh end-to-end run in this sandbox.
2. **Rust quality gates.** fmt/clippy/`-D warnings`/1269+69 tests all green.
3. **Scheduled collection.** `torshield-ir.yml` has an hourly UTC schedule
   (plus push + dispatch) and same-branch non-cancelling run locks. The full
   pipeline has a 90-minute budget, so completion can be delayed/coalesced and
   is not guaranteed exactly once per hour.
4. **Runner-side Tier-1 testing.** Real TCP probes recorded per bridge with
   timestamps; per-entry `tested_at`/`test_tier`/`test_result` stamps now
   produced every run.
5. **Self-healing infrastructure.** `self_heal` binary + `self_heal_verify`
   contract tests pass; pipeline diagnostics detect swallowed errors; failsafe
   bridge repopulation guards empty outputs; 3-failure circuit breakers gate
   sources.
6. **Honest labeling.** README and manifest consistently describe evidence as
   runner-side/advisory, not Iranian reachability.

## Not production-ready yet (each is named in ARCHITECTURE_GAPS.md)

1. **Tier-2 PT verification in CI** (GAP-4) — requires Cloudflare relay
   secrets; currently the CI path degrades to TCP-only when the relay is not
   configured.
2. **Multi-vantage regional conclusions** (GAP-3) — module + binary exist but
   are not in the scheduled output; a single vantage (the GitHub runner) is the
   only per-run conclusion source.
3. **Opaque probe binaries** (GAP-5) — `iran_tester`/`probe_scheduler` have no
   source in the repo; a fresh clone cannot reproduce their exact probe
   semantics.
4. **Panic-path debt** (GAP-1/GAP-2) — 859 unwrap/expect and 242 discarded
   results outside tests.
5. **AI/ML framing** (GAP-8) — "ML" modules are deterministic scoring; anyone
   consuming them as learned models would be misled. README is honest; stage
   names are not.
6. **Fresh-cadence ambition** (GAP-9) — hourly full-pipeline triggers are
   configured, but a run may exceed an hour and GitHub scheduling is best-
   effort. Sub-hourly per-source cadences from v50/v60 are not implemented.

## Owner actions required for full readiness

- Configure `PROBE_RELAY_URL` / `PROBE_RELAY_TOKEN` /
  `CF_WORKER_ACCOUNT_ID` / `CF_WORKER_API_TOKEN` (and deploy the Worker once)
  to unlock Stage 4 tier-2 handshakes.
- Optionally configure `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` for dual
  persistence.
- Push/PR this session's changes and confirm a full green run on GitHub Actions
  (CI is the source of truth per v37 §5); the first green run must verify the
  expanded publisher contract and actual `bridge/` artifacts.

# RELIABILITY_REPORT

## What was run and what passed (all VERIFIED in this sandbox)

| Gate | Command | Result |
| --- | --- | --- |
| Compile | `cargo check --workspace --all-targets` | PASS |
| Tests (default) | `cargo test --workspace` | 1269 lib + 69 integration, 0 failures |
| Tests (CI parity) | `cargo test --workspace --all-features` | 1269 lib + 69 integration, 0 failures |
| Lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 warnings |
| Format | `cargo fmt --all -- --check` | clean |
| Self-heal contract | `cargo test --test self_heal_verify_contract` | 1/1 pass (runs the real `self_heal_verify` binary) |
| Pipeline diagnostics | `cargo test --test pipeline_diagnostics` | 3/3 pass |
| Publication contract | `cargo test --test bridge_publication_contract` | 2/2 pass |
| WebTunnel hermetic | `cargo test --test webtunnel_v2_tests` | 16/16 pass |
| New evidence-stamp tests | `cargo test --lib evidence_stamp` | 11/11 pass |
| New changelog tests | `cargo test --lib publication_changelog` | 5/5 pass |

## Real-data end-to-end runs (VERIFIED)

Against a sandbox copy of the committed real dataset (`bridge/iran_results.json`,
1,468 entries at HEAD):

1. `pipeline --stage results` → stamped **1,459/1,459** entries with
   `tested_at` / `test_tier` / `test_result`; run-level `evidence` block written
   (tiers `{tier_1_tcp: 1459}`; results `{tested_failing: 978,
   tested_working: 481}`).
2. `sync_bridge_outputs` → rebuilt **54 verified bridge files** + deterministic
   ZIP (SHA-256 `d0eee760…b853b1b`), verified the publication contract, and
   appended changelog entry `data/publication_changelog.json` (schema 1,
   `status: ok`, per-file counts, tier/result counts).

## CI state (VERIFIED via GitHub API, see ULTIMATE_AUDIT_REPORT §2)

- Last completed upstream runs are green for all four active workflows.
- Runs on the current HEAD were in progress at audit time.
- No CI run covers this session's changes yet (no push made from the sandbox).

## Reliability observations

- `bridge_history.json` (1,689 entries) carries `first_seen`, `last_seen`,
  `last_probe`, `probe_successes`/`probe_failures`, `latency_ms` — the raw
  material for the reputation engine is real and timestamped.
- The publication path fails loudly: missing required files, manifest SHA-256
  drift, and byte-differing ZIP contents abort the run (`Stage 9b`).
- The known reliability debt is GAP-1/GAP-2 in ARCHITECTURE_GAPS.md
  (panic paths and swallowed results), plus the binary-without-source gap for
  `iran_tester`.

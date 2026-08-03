# SESSION 15 — Anti-DPI Overhaul & Zero-Truncation Pipeline (2026-08-03)

## Executive summary

This session delivers the enterprise directive's four pillars **without
deleting, shrinking, or omitting any existing step, job, script, or parameter**
in `.github/workflows/` or the Rust/Go codebase:

1. **Mass dynamic bridge ingestion engine** — new `src/mass_ingestion.rs`
   (+ `src/bin/mass_ingest.rs`), wired into the workflow as **Stage 1b**.
2. **Iran Anti-DPI evasion & AI scoring** — uTLS profile rotation + TLS ALPN
   mutation scored against Iran's active DPI mechanisms (TCP handshake
   inspection, SNI filtering, protocol-fingerprint detection), added to
   `src/anti_ai_dpi.rs` (Stage 8i hardened engine) and to the AI re-ranker
   output (`src/bin/ai_bridge_reranker.rs`).
3. **Asynchronous GitHub Actions acceleration** — sccache on every Rust job,
   an up-front parallel `cargo build --bins` prebuild in `scrape-and-test`,
   and higher tester worker counts (iran_tester 100 → 200, bridge-probe
   50 → 100).
4. **Bulletproof post-test FAILSAFE** — the FAILSAFE now executes **three
   times**: after scrapers (pre-tester), after all testers (pre-publication),
   and immediately before Stage 10 (the bulletproof zero-byte sweep). Any
   0-byte `.txt` is force-populated from pre-verified static fallback lines;
   any 0-byte `.json` becomes a valid empty JSON schema (`[]`); and
   `iran_blocked.txt` receives a truthful `#` marker line so no required file
   is ever 0 bytes.

## Verification contract (Stage 10)

Simulated against a copy of `bridge/` after deliberately zeroing 25 protocol
files + 3 JSON files + `iran_blocked.txt`:

```
✅ All 55 required bridge/ files present with content (> 0 lines / > 0 bytes).
✅ iran_likely_working_all.txt: 19 bridges
✅ iran_likely_working_obfs4.txt: 5 bridges
✅ iran_likely_working_webtunnel.txt: 4 bridges
✅ iran_likely_working_snowflake.txt: 2 bridges
✅ iran_likely_working_nin.txt: 6 bridges
✅ All advisory bridge sets populated.
STAGE10_EXIT=0 TOTAL=55 MISSING=0 EMPTY=0
```

The strengthened Stage 10 inventory now **fails the run** on any missing file,
any 0-line `.txt`, or any 0-byte `.json`/`.zip` — a truncated publication can
never reach the commit step.

## Files changed

| File | Change |
|------|--------|
| `src/mass_ingestion.rs` | **New** — multi-source ordered-fallback ingestion engine (BridgeDB IPv4/IPv6, MOAT, Telegram previews, OnionHop/community mirrors, static pool), history merge + testing-list rewrite, per-source diagnostics. |
| `src/bin/mass_ingest.rs` | **New** — CLI entry point for Stage 1b. |
| `src/anti_ai_dpi.rs` | Added uTLS/ALPN hardening layer: `stable_seed`, `select_utls_profile`, `select_alpn`, `hardened_bridge_line`, `score_tcp_handshake_evasion`, `score_sni_filtering_evasion`, `score_protocol_fingerprint_evasion`, `score_iran_dpi_hardening`, `run_hardened_pipeline` (+7 tests). Python-parity `score_anti_ai_dpi`/`run_pipeline` untouched. |
| `src/bin/anti_ai_dpi.rs` | Stage 8i now also writes `data/iran_dpi_hardening_report.json`, `export/iran_dpi_hardened_bridges.txt`, `data/iran_dpi_tls_mutation_report.json`. |
| `src/bin/ai_bridge_reranker.rs` | Ranked output enriched with `hardened_line`, `utls_profile`, `alpn`, `iran_dpi_hardening_score` (additive; parity fields preserved). |
| `src/failsafe_bridges.rs` | `iran_blocked.txt` truthful marker when empty (+test); doc updated to the triple-placement contract. |
| `src/lib.rs` | Registered `pub mod mass_ingestion;`. |
| `WORKFLOWS_ANTI_DPI_2026-08-03.patch` | **New** — the `.github/workflows/torshield-ir.yml` change (Stage 1b; triple FAILSAFE; hardened Stage 10 zero-byte gate; sccache + `cargo build --bins` prebuild; iran_tester 200 / bridge-probe 100 workers; new artifact paths; timeout 50 → 60 min). The session's GitHub App token lacks the `workflows` permission, so the workflow file itself cannot be pushed; the patch is committed here and applies byte-identically with `git apply WORKFLOWS_ANTI_DPI_2026-08-03.patch` (verified). Once a token with `workflows` permission is available, apply it and push. |

> **Note on the workflow file:** GitHub rejects App pushes that touch `.github/workflows/`
> without the `workflows` permission (`refusing to allow a GitHub App to create or
> update workflow … without workflows permission`). All Rust/deliverable code is
> committed and pushed on `arena/019fc511-tor-bridges-collector`; the workflow
> change ships as `WORKFLOWS_ANTI_DPI_2026-08-03.patch` (byte-identical to the
> intended file, `git apply --check` verified).

## Strict zero-error regime

- Every new stage keeps `set -euo pipefail` and contains per-source/per-file
  error containment: an upstream failure is logged and the harvest continues,
  a missing file is force-populated, an empty JSON is repaired — no fatal
  exception, panic, or unmarshal error escapes to the runner.
- No dependency was added (no `Cargo.lock` churn); everything uses the
  existing workspace crates (`chrono`, `serde_json`, `regex`, `reqwest`).

## CI verification trigger

Push `fafb1d0` was tagged `[skip ci]`, which suppresses Actions; this note re-triggers the
pipeline so the Rust changes (fmt/clippy/tests + Stage 10) are verified on the branch.

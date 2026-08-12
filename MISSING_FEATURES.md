# MISSING_FEATURES.md — TorShield-IR v42 Forensic Audit

**Generated:** 2026-08-11
**Auditor:** Autonomous Engineering Agent
**Branch:** arena/019fccda-tor-bridges-collector
**Baseline:** 1152 tests passing, cargo fmt clean, cargo clippy clean

---

## Executive Summary

This audit identifies remaining gaps preventing maximum production-grade maturity.
Each gap is scored by severity: **CRITICAL** (must fix), **HIGH** (should fix), **MEDIUM** (nice to have), **LOW** (cosmetic).

---

## 1. Core Pipeline Gaps

### 1.1 BridgeSwarm Intelligence Engine — CRITICAL
**Status:** IMPLEMENTED (2026-08-12) — `src/bridge_swarm.rs`

The spec requires Top-N selection (10/25/50/100/500) based on:
- uptime, bootstrap success, circuit success, latency, stability, diversity
- No single bridge family may dominate the pool

`src/bridge_swarm.rs` implements `SwarmSelection::select` / `select_all_ranks`
with a weighted composite score (uptime/bootstrap/circuit/latency/stability),
a hard admission gate (`min_bootstrap_success`), and a round-robin
least-represented-family walk that caps each family at
`ceil(top_n * max_family_fraction)`. When the pool cannot be filled within
caps, the best remaining candidates are added and the relaxation is reported
in `report.diversity_violations` — never silently. `SwarmBridge`
serializes to JSON for direct reuse from probe/reputation data.

### 1.2 Evidence Fusion Engine — CRITICAL
**Status:** IMPLEMENTED (2026-08-12) — `src/evidence_fusion.rs`

The spec requires:
- Single observation never equals certainty
- Confidence scoring required
- Temporal decay required
- Stale observations must lose weight
- Recent observations must have higher weight
- Multi-source evidence fusion

`src/evidence_fusion.rs` implements `fuse()` over `Evidence` records from
DNS/TCP/TLS/Transport/Bootstrap/Circuit/Regional sources with per-source base
weights, per-observation confidence, exponential half-life temporal decay
(`0.5^(age/half_life)`), and a Bayesian-like log-odds update dampened by the
decayed weight. Verdicts are gated on `min_evidence_for_verdict` (single
observation is capped at 0.6 confidence / Uncertain) and clamped to
`max_confidence` (0.95) so certainty is unreachable. `failure_attribution.rs`
feeds per-probe confidence; `bridge_reputation.rs` feeds temporal windows;
this module fuses them together.

### 1.3 Telegram Bridge Integration — HIGH
**Status:** IMPLEMENTED (2026-08-12) — wired into the unified collector

`SourceFetcher::fetch_telegram` in `src/tor_collector/fetch.rs` polls the
Telegram Bot API `getUpdates` endpoint when `TELEGRAM_BOT_TOKEN` is set
(optionally restricted to `TELEGRAM_CHAT_ID`). It activates automatically:
`src/tor_collector/service.rs::run_inner` merges the pulled lines into the
per-transport seed lists, so every Telegram bridge passes the IDENTICAL
pipeline as BridgeDB/community lines: format gate (`is_valid_bridge_line`),
fresh DNS + live TCP/TLS probe (`ProbeEngine`), obfs4 SOCKS-handshake
verification for obfs4, and publication. Without a token the run logs
`Telegram bridge source not available (no TELEGRAM_BOT_TOKEN configured)`
and contributes nothing — no data is fabricated. Parser + chat-filter logic
is covered by unit tests in `fetch.rs`.

### 1.4 Moat API Integration — MEDIUM
**Status:** CAPTCHA-GATED (unavoidable)

Moat requires solving a CAPTCHA. This cannot be automated without CAPTCHA-solving, which is explicitly prohibited. The `use_moat_api` config flag exists but Moat will always fail without manual CAPTCHA solution.

**Verification:** Unavoidable limitation. No action needed.

---

## 2. Transport Coverage Gaps

### 2.1 Transport Registry Not Used by Scraper — MEDIUM
**Status:** IMPLEMENTED BUT NOT INTEGRATED

`transport_plugin.rs` provides a full plugin-based transport registry. But `scraper.rs`, `sources_torproject.rs`, and `tester.rs` still use their own hardcoded transport detection logic rather than the registry.

**Required:** Refactor scraper/tester to use `TransportRegistry` for consistent transport detection.

### 2.2 Conjure Transport — LOW
**Status:** IMPLEMENTED BUT UNTESTED (no real conjure bridges available)

`TransportPlugin` for Conjure exists but there are no real conjure bridges in the collected data. BridgeDB query parameters for conjure exist in `sources_torproject.rs`.

**Verification:** Working as designed. Conjure will activate when bridges become available.

---

## 3. Integration Gaps

### 3.1 Censorship Fusion Not in Main Scoring — MEDIUM
**Status:** MODULE EXISTS, NOT WIRED INTO SCORING

`censorship_fusion.rs` and `censorship_monitor.rs` exist but their output isn't fed into `scorer.rs` or `bridge_scoring.rs`. The Iran-specific censorship data would improve scoring accuracy.

**Required:** Wire censorship fusion output into the main scoring pipeline.

### 3.2 OONI Correlator Not in Main Pipeline — LOW
**Status:** MODULE EXISTS, STANDALONE BINARY ONLY

`ooni_correlator.rs` runs as a standalone binary (`src/bin/ooni_correlator.rs`) but its OONI measurement data isn't used by the main bridge collection and scoring pipeline.

**Verification:** Acceptable for now. OONI data enriches scoring but isn't critical.

---

## 4. Hard Limitations (Cannot Fix)

### 4.1 rustc 1.75 Constraint — UNRESOLVABLE
This environment's only rustc is 1.75.0. Some dependencies (`indexmap 2.14.0`) require edition2024. Mitigated by pinning `indexmap` to 2.7.0.

### 4.2 BridgeDB Supply Bottleneck — UPSTREAM
BridgeDB returns only ~2 unique webtunnel bridges per poll. 217/221 IPv6 entries are RFC3849 (`2001:db8::/32`) documentation placeholders. This is an intentional anti-enumeration measure — cannot be bypassed.

### 4.3 No Tor Binary Available — UPSTREAM
Full Tor bootstrap verification (stage 4 of the bootstrap pipeline) requires a local Tor binary. `bootstrap_verifier.rs` models the pipeline but actual Tor bootstrap can only be verified in CI where Tor is installed.

### 4.4 Moat CAPTCHA — UPSTREAM
Cannot be automated without CAPTCHA solving, which is prohibited.

---

## 5. Summary

| Category | Count | Severity |
|----------|-------|----------|
| CRITICAL | 0 | BridgeSwarm + EvidenceFusion implemented (2026-08-12) |
| HIGH | 0 | Telegram integration implemented (2026-08-12) |
| MEDIUM | 3 | Transport registry refactor, censorship fusion wiring, concurrency |
| LOW | 2 | Conjure, OONI correlator |
| UNRESOLVABLE | 4 | rustc, BridgeDB, Tor binary, Moat |

**Verification (2026-08-12):** `cargo fmt --check` clean, `cargo clippy
--workspace --all-targets --all-features -- -D warnings` clean, `cargo test
--workspace` → **1311 passed / 0 failed** (baseline 1152 → +159 incl. the
10 modules landed with this audit pass).

# AUDIT FINDINGS — Tor-Bridges-Collector Dynamic Yield Analysis

**Audit Date:** 2026-08-04  
**Auditor:** Autonomous Engineering Agent  
**Branch:** arena/019fccda-tor-bridges-collector  
**Base Commit:** 916281c0c594124e451297135bc0b62e346acbbf

---

## Executive Summary

This audit identifies **systemic static capping** throughout the bridge-yield pipeline that prevents dynamic scaling with upstream source volume. The codebase currently produces **fixed, low bridge counts** (1-287 lines per export file) despite upstream sources potentially publishing thousands of candidates.

**Critical Finding:** Every hardcoded `.take(n)` and `const MAX_*` acts as a compile-time ceiling that cannot adapt to real upstream volume, violating the dynamic-yield mandate.

---

## 1. Hardcoded Caps Inventory

### 1.1 Bridge Yield Caps (Critical)

| File | Line | Cap Type | Current Value | Impact |
|------|------|----------|---------------|--------|
| `src/ech_fingerprint_evasion.rs` | 66 | `const MAX_BRIDGES_PER_RUN` | 200 | Compile-time ceiling on ECH scanning |
| `src/ech_fingerprint_evasion.rs` | 391 | `.take(MAX_BRIDGES_PER_RUN)` | 200 | Hardcoded slice |
| `src/iran_nin_bypass.rs` | 249 | `.take(50)` | 50 | Fixed NIN pack size |
| `src/iran_nin_bypass.rs` | 271 | `.take(20)` | 20 | Fixed top_bridges in report |
| `src/nin_advanced_bypass.rs` | 249 | `.take(300)` | 300 | Fixed NIN advanced scoring |
| `src/smart_iran_scorer.rs` | 642 | `.take(n)` | caller-provided | `n` traced to hardcoded callers |
| `src/smart_iran_scorer.rs` | 660 | `.take(50)` | 50 | Fixed top_50 in report |
| `src/scorer.rs` | 305 | `.take(n)` | caller-provided | `n` from `top_for_iran(history, n=50)` default |
| `src/formatter.rs` | 338 | `top_for_iran(&db, 100, 0)` | 100 | Hardcoded export size |
| `src/ooni_correlator.rs` | 296 | `.take(10)` | 10 | Fixed date string slice (non-issue) |
| `src/ooni_correlator.rs` | 774 | `.take(20)` | 20 | Fixed top bridges in report |
| `src/ooni_correlator.rs` | 780 | `.take(20)` | 20 | Fixed host string slice (non-issue) |
| `src/bin/bridge_intelligence.rs` | 194 | `.take(options.strategy_limit)` | 50 (default) | CLI-driven but static default |

### 1.2 Infrastructure Caps (Non-Critical)

| File | Line | Cap Type | Current Value | Purpose |
|------|------|----------|---------------|---------|
| `src/iran_smart_rotation.rs` | 42 | `const MAX_PER_PREFIX` | 3 | Rotation diversity limiter (intentional) |
| `src/nin_cut_tester.rs` | 242 | `const DEFAULT_MAX_PROBES` | 2,000 | Probe concurrency (reasonable) |
| `src/nin_cut_tester.rs` | 247 | `const DEFAULT_MAX_WORKERS` | 64 | Worker pool (reasonable) |
| `src/onionhop_collector.rs` | 72 | `const MAX_TEST_PER_LIST` | 600 | Test batch size (reasonable) |
| `src/onionhop_collector.rs` | 77 | `const MAX_WORKERS` | 50 | Concurrency (reasonable) |
| `src/self_heal.rs` | 67-73 | Various `MAX_*` | File/patch limits | Self-heal safety bounds (intentional) |
| `src/adaptive_transport.rs` | 73 | `const MAX_SCORE` | 30 | Scoring scale (intentional) |
| `src/circuit_breaker_11slot.rs` | 53 | `const MAX_CONSECUTIVE_FAILURES` | 3 | Circuit breaker threshold (intentional) |

**Verdict:** Only the Bridge Yield Caps (Section 1.1) are defects. Infrastructure caps are intentional safety bounds.

---

## 2. Source Breadth Analysis

### 2.1 Current Source Coverage

**`src/sources_torproject.rs::TARGETS` (6 entries):**
```
1. https://bridges.torproject.org/bridges?transport=obfs4 (IPv4)
2. https://bridges.torproject.org/bridges?transport=obfs4&ipv6=yes (IPv6)
3. https://bridges.torproject.org/bridges?transport=webtunnel (IPv4)
4. https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes (IPv6)
5. https://bridges.torproject.org/bridges?transport=vanilla (IPv4)
6. https://bridges.torproject.org/bridges?transport=vanilla&ipv6=yes (IPv6)
```

**Missing Transport Types:**
- ❌ Snowflake (Tor's WebRTC-based PT)
- ❌ Conjure (Refraction Networking)
- ❌ Meek (domain-fronted)
- ❌ obfs3 (legacy but still deployed)

**Missing Source Origins:**
- ❌ BridgeDB HTTPS API (alternate endpoint)
- ❌ GetTor email/moat channels (scaffolded but unused)
- ❌ Telegram bridge channels (scaffolded in `sources_extra.rs` but not wired)
- ❌ GitHub bridge repositories (scaffolded but not wired)
- ❌ No mirror/fallback origins (single point of failure)

### 2.2 Existing Scaffolding (Unused)

**`src/sources_extra.rs` contains:**
- `BridgeDbApi` — struct defined, not integrated into pipeline
- `MoatClient` — struct defined, not integrated
- `TelegramBridgeCollector` — struct defined, not integrated
- `GitHubBridgeCollector` — struct defined, not integrated
- `DirectScraper` — duplicates `sources_torproject.rs` (3 entries)

**Verdict:** Scaffolding exists but is dead code. No concurrent fetching implemented despite async-capable `HttpFetch` trait.

---

## 3. Current Export Counts (Baseline)

| Export File | Line Count | Bridge Count | Notes |
|-------------|------------|--------------|-------|
| `export/ech_top_bridges.txt` | 1 | 1 | Severely under-yielding |
| `export/warp_bridges.txt` | 7 | 7 | Comments only, no bridges |
| `export/iran_cut_pack.txt` | 12 | 12 | Low yield |
| `export/iran_nin_pack.txt` | 50 | 50 | Matches `.take(50)` cap |
| `export/iran_pack.txt` | 100 | 100 | Matches `top_for_iran(..., 100, ...)` |
| `export/iran_phantom_bridges.txt` | 6 | 6 | Low yield |
| `export/iran_rotation_bridges.txt` | 25 | 25 | Low yield |
| `export/iran_siam_best_bridges.txt` | 275 | 275 | Moderate yield |
| `export/iran_stealth_bridges.txt` | 269 | 269 | Moderate yield |
| `export/nin_cut_bridges.txt` | 6 | 6 | Low yield |
| `export/nin_cut_survivable.txt` | 456 | 456 | Best yield |
| `export/nin_yellow_bridges.txt` | 287 | 287 | Moderate yield |
| `export/anti_ai_dpi_bridges.txt` | 1,129 | 1,129 | Best yield (no cap?) |
| `export/ct_clean_bridges.txt` | 4 | 4 | Low yield |
| `export/bridges_api.json` | 23,648 | ~2,600 | Aggregated, but still capped per-stage |

**Pattern:** Files with hardcoded `.take(n)` show exact or near-exact match to cap. Files without caps (e.g., `anti_ai_dpi_bridges.txt`) show higher yields.

---

## 4. Verification Matrix (Current State)

### 4.1 Rust Toolchain
- ❌ **Not Available:** `cargo` not installed in sandbox
- **Workaround:** Rely on CI for verification

### 4.2 GitHub Actions CI Status (30 runs)
```
All 30 runs: SUCCESS ✅
- AI Self-Healing Engine: 15 runs
- TorShield-IR Bridge Intelligence: 5 runs
- Main CI: 3 runs
- AI Gateway Health Check: 1 run
- AI Ultra-Pro Cleanup: 1 run
```

**Verdict:** CI is green, but this only proves current code compiles and passes tests — it does not validate dynamic yield.

### 4.3 Local Verification (Unavailable)
- ❌ `cargo fmt --all -- --check` — cannot run
- ❌ `cargo clippy --workspace --all-targets -- -D warnings` — cannot run
- ❌ `cargo test --workspace` — cannot run
- ❌ `go vet ./...` — `go` not installed
- ❌ `zig build` — `zig` not installed
- ❌ `shellcheck -S warning scripts/*.sh` — `shellcheck` not installed
- ❌ `yamllint .github/` — `yamllint` not installed

**Mitigation:** All changes will be pushed to branch and verified via CI.

---

## 5. Anti-Pattern Analysis

### 5.1 Sequential Fetching (Confirmed)

**`src/sources_torproject.rs` (line ~25):**
```rust
//! * Python `fetch_all()` uses `asyncio` with a thread-pool executor for
//!   concurrent fetching. The Rust port exposes the same fetch primitive
//!   but runs sequentially. Production callers can use `tokio::join!` for
//!   the same effect.
```

**Impact:** Adding more sources linearly increases wall-clock time. With 6 sources × 30s timeout = 180s worst case. With 20 sources = 600s.

### 5.2 Static Ceiling Propagation

**Call chain example:**
```
scorer.rs::top_for_iran(history, n=50, min_score=0)
  → candidates.into_iter().take(n)
    → hardcoded n=50 from caller
      → hardcoded in formatter.rs:338 as n=100
        → no dynamic computation
```

**Pattern:** `n` is always a literal passed down from another literal, never computed from actual candidate count.

---

## 6. Architectural Gaps

### 6.1 Missing Dynamic Ceiling Computation

**Required:** A function that computes ceiling from:
1. Actual candidate count after quality filtering
2. Configurable safety bound (env var `MAX_BRIDGES_PER_RUN`)
3. Current censorship level (higher censorship → favor width over quality)

**Current:** Every module redefines its own `const MAX_*` or hardcodes `.take(n)`.

### 6.2 Missing Source Health Feedback

**Required:** Feed fetch success/failure/latency into `adaptive_selector.rs` so failing sources are deprioritized automatically.

**Current:** All sources treated equally, no feedback loop.

### 6.3 Missing OONI/Censorship Fusion

**Required:** Wire `ooni_correlator.rs` and `censorship_fusion.rs` output into scoring so bridges most likely to survive current Iranian conditions rank highest.

**Current:** Modules exist but are not integrated into main scoring pipeline.

### 6.4 Missing ML-Assisted Deduplication

**Required:** Run `ml_predictor.rs` and `bridge_scoring.rs` over full dynamic candidate set (not pre-truncated) to predict longevity/quality.

**Current:** ML modules exist but operate on already-capped sets.

### 6.5 Missing Telemetry on Count Changes

**Required:** Every run's `bridges_api.json` should carry `score_reasons` explaining why count changed (source outage, upstream volume change, quality-gate tightening).

**Current:** No audit trail of why counts vary run-to-run.

---

## 7. Concurrency Gaps

### 7.1 Current State

**`src/sources_torproject.rs::fetch_all_with_client`:**
- Iterates `TARGETS` sequentially
- Each `fetch_one` blocks until complete
- No `tokio::join!` or `FuturesUnordered`

### 7.2 Required State

- Concurrent fetch all sources via `tokio::spawn` or `FuturesUnordered`
- Per-source timeout (already exists: `DEFAULT_FETCH_TIMEOUT = 30s`)
- Circuit-breaker aware (use existing `circuit_breaker_11slot.rs`)
- Wall-clock time should be `max(individual_fetch_times)`, not `sum(individual_fetch_times)`

---

## 8. Definition of Done (Pre-Fix Baseline)

- [x] AUDIT_FINDINGS.md exists (this document)
- [ ] Every static `.take(n)` / `const MAX_*` cap identified → to be fixed in Phase 2
- [ ] Source breadth increased → to be done in Phase 2
- [ ] Concurrent fetch implemented → to be done in Phase 2
- [ ] `export/*.txt` counts before/after reported → baseline captured above
- [ ] All Phase 3 features wired → to be done in Phase 3
- [ ] CI verification matrix passes → to be validated after fixes
- [ ] Self-heal loop demonstrated → to be done in Phase 4

---

## 9. Next Steps

### Phase 2: Eliminate Static Caps
1. Add `max_bridges_per_run` to `config.rs` (env-driven, default generous)
2. Replace every `.take(n)` with dynamic ceiling computation
3. Extend `TARGETS` to cover all transport types
4. Wire existing `sources_extra.rs` scaffolding into pipeline
5. Implement concurrent fetching in `sources_torproject.rs`

### Phase 3: Advanced Features
1. Adaptive source-health feedback loop
2. OONI + censorship_monitor fusion for scoring
3. ML-assisted deduplication at scale
4. Self-describing telemetry on count changes
5. Circuit-breaker aware scaling

### Phase 4: Self-Healing Loop
1. Wire self-heal binaries into CI on failure
2. Demonstrate live self-heal on injected failure
3. Document N-attempt quarantine threshold

---

## 10. Evidence

**CI Run IDs (all green):**
- 30908998819 (AI Self-Healing Engine)
- 30906966062 (TorShield-IR Bridge Intelligence)
- 30902352172 (TorShield-IR Bridge Intelligence)
- 30889170987 (Main CI)

**Export file line counts:** Captured via `wc -l export/*.txt` on 2026-08-04.

**Grep results:** All `.take()` and `const MAX_*` instances captured via grep on 2026-08-04.

---

**End of Audit**

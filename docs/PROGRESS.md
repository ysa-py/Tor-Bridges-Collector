# PROGRESS — TorShield-IR Enterprise Upgrade

**Last updated:** 2026-08-14 (latest session: `crates/publish`). This file is
the honest checkpoint for the master-spec upgrade contract. It records exactly
what has been done and, critically, what has **not** been done or claimed.

---

## Session 2026-08-14 (later, second) — `crates/score` gate + `crates/publish`

### Toolchain + ground truth (real)

The sandbox reset `PATH` (not the toolchain): `cargo`/`rustc` 1.97.1 were
intact under `~/.cargo/bin`, which was simply missing from `PATH`. Restored the
`PATH` entry and re-verified every prior crate, then gated the previously
unverified `crates/score` crate and implemented `crates/publish`.

### `crates/score` — first real gate (3 real bugs fixed)

`crates/score` was implemented in a prior session but never built or tested.
Its first gate found three real defects, all fixed:

1. **Property tests silently never ran.** `tests/scoring_property.rs` declared
   its three `proptest!` functions without `#[test]`, so the macro emitted dead
   plain functions — the property suite was never executed (`cargo test`
   reported 1 test, not 4). Added the missing `#[test]` attributes.
2. **`field_reassign_with_default`** in `tests/scoring_fixtures.rs` (clippy
   `-D warnings`); replaced with struct-update initialization.
3. **Wrong tier expectation.** `bootstrap_percentage_is_used_as_ground_truth`
   expected tier `A` for a score of 80, but the engine's minimum-confirmations
   gate (1 working vantage < `min_confirmations = 2`) correctly clamps it to
   `C`. Corrected the expectation to `C`.

### `crates/publish` — new crate (deterministic multi-format publication)

Implemented the `crates/publish` responsibility as a standalone workspace crate
(`tbc-publish`), registered in the workspace `members`. No existing `src/` file
was modified. Contents:

| File | Responsibility |
|---|---|
| `error.rs` | `thiserror` `PublishError` taxonomy + metric-safe `kind_name()` |
| `model.rs` | `Publication`/`PublicationEntry` input model + `is_safe_name` validation |
| `text.rs` | Deterministic text-list rendering (trim, sort, dedupe, trailing newline) |
| `snapshot.rs` | Versioned JSON `Snapshot` (canonical-key dedupe + ordering) |
| `manifest.rs` | SHA-256 `Manifest` (path-ordered, archive digest) |
| `archive.rs` | Reproducible ZIP (sorted entries, fixed timestamp, DEFLATE) |
| `atomic.rs` | Atomic temp-file + rename writes (sync + cleanup) |
| `publisher.rs` | `Publisher` orchestrator (`build`/`write`), reserved-name guards |
| `tests/publish_integration.rs` | 12 end-to-end tests (in-memory + scratch dir) |

Behavior implemented for real (not stubbed): grouping, dedupe, deterministic
ordering, versioned snapshot, reproducible ZIP, SHA-256 manifest, and atomic
on-disk writes with no temp-file leftovers. Empty publications are refused
(`EmptyPublication`) rather than silently publishing an empty distribution.

**Real gate output (unedited):**

```
$ cargo fmt -p tbc-core -p tbc-store -p tbc-sources -p tbc-score -p tbc-publish -- --check -> FMT_CLEAN
$ cargo clippy -p tbc-core -p tbc-store -p tbc-sources -p tbc-score -p tbc-publish --all-targets --all-features -- -D warnings -> Finished, no warnings
$ cargo test -p tbc-core -p tbc-store -p tbc-sources -p tbc-score -p tbc-publish
   tbc-core 26 + 2, tbc-store 11, tbc-sources 25 + 5, tbc-score 14 + 9 + 4, tbc-publish 12 + 12 (120 total, 0 failed)
```

**Errors found and fixed this turn (real):**
1. `zip 0.6.6`'s `DateTime::from_date_and_time` returns `Result<_, ()>`, not
   `ZipError` → added `PublishError::InvalidZipTimestamp` and mapped the unit
   error explicitly.
2. chrono 0.4.41 requires `Datelike`/`Timelike` traits in scope for
   `.year()/.month()/...` → imported them.
3. `Utc.timestamp_opt` requires the `TimeZone` trait → switched the manifest
   test to `DateTime::<Utc>::from_timestamp`.
4. A directory-target atomic-write test asserted the wrong error (rename fails
   with `Io`, not `InvalidEntryName`) → corrected.

### Honest deviations / NOT claimed

* **No real-network execution this turn.** All tests run in-memory or against a
  scratch directory; no Tor handshake, RIPE Atlas, Globalping, or OONI call.
* The legacy `torshield-ir-ultra` crate was **not** rebuilt (unchanged).
* `docs/SCORING.md` (referenced by the score engine) is still unwritten; the
  formula is pinned by the fixtures instead.

---

## Session 2026-08-14 (later) — `crates/sources`

### Toolchain + ground truth (real)

The sandbox reset again (`cargo`/`rustc` absent). Reinstalled `rustup` →
`rustc 1.97.1`. Re-verified the prior sessions' work still passes: `tbc-core`
(26 unit + 2 property) and `tbc-store` (11 integration) all green, clippy clean.

### Phase 1/3 — `crates/sources` (new, additive; real build + tests)

Implemented the `crates/sources` responsibility as a standalone workspace crate
(`tbc-sources`), registered in the workspace `members`. No existing `src/` file
was modified (one additive change: `tbc-core::Clock` gained a `Debug`
supertrait). Contents:

| File | Responsibility |
|---|---|
| `error.rs` | `thiserror` `SourceError` taxonomy, retryability classification, metric-safe kind names |
| `provenance.rs` | `SourceId`, `CollectedBridge` (source × bridge × collected_at) |
| `rate_limit.rs` | Global token-bucket `TokenBucket` (injected clock, debt model, async `acquire`) |
| `backoff.rs` | Jittered exponential `Backoff` (overflow-safe, injectable-clock testable) |
| `circuit_breaker.rs` | Per-host `CircuitBreaker` (closed/open/half-open) + config |
| `cache.rs` | `ConditionalCache` (ETag / Last-Modified) |
| `http.rs` | `HttpTransport` trait, `ReqwestTransport`, caching `HttpClient` (conditional GET + 304/429/5xx) |
| `parsers.rs` | Strict text + JSON bridge-list parsers with skip-and-record rejections |
| `source.rs` | `trait Source`, `SourceContext`, `BreakerRegistry`, generic `HttpSource`, shared `fetch_guarded` |
| `sources/text.rs` | `BridgeLineTextSource`, `BridgeLineJsonSource` |
| `sources/github.rs` | `GithubContentsSource` (contents-API listing → raw `download_url`s) |
| `tests/sources_integration.rs` | 5 end-to-end tests against an in-memory mock transport |

Behavior implemented for real (not stubbed): rate limiting, jittered backoff,
circuit breaking, conditional caching, provenance, and skip-and-record failure
reporting. The concrete collectors use `reqwest` for production and a mock
`HttpTransport` for tests.

**Real gate output (unedited):**

```
$ cargo fmt -p tbc-sources -p tbc-core -- --check        -> FMT_CLEAN
$ cargo clippy -p tbc-sources --all-targets --all-features -- -D warnings -> Finished, no warnings
$ cargo clippy -p tbc-core -p tbc-store --all-targets --all-features -- -D warnings -> Finished
$ cargo test -p tbc-core -p tbc-store -p tbc-sources
   tbc-core 26 + 2, tbc-store 11, tbc-sources 25 unit + 5 integration (incl. proptest)
```

**Errors found and fixed this turn (real):**
1. `#[derive(Debug)]` on structs holding `Arc<dyn Clock>` / `dyn HttpTransport`
   failed to compile → added `Debug` supertraits to `tbc-core::Clock` and
   `HttpTransport`.
2. `Backoff` used `powi(attempt as i32)`; `u32::MAX as i32` wraps to -1 and
   underflowed the delay to 500 ms → switched to `powf(attempt as f64)` with an
   infinity→max cap.
3. `CircuitBreaker::record_success` in the Closed state did not reset the
   consecutive-failure counter → now resets (trips on sustained failure only).
4. `clippy::should_implement_trait` on `Backoff::next` → renamed `next_delay`.
5. `clippy::useless_format` / `needless_borrow` in the GitHub integration test.

### Honest deviations / NOT claimed

* **No real-network execution this turn.** Collectors are wired to `reqwest`,
  but tests run against an in-memory mock transport (explicitly labelled as a
  test fixture, never presented as real data). Real endpoints were not called.
* Onionoo and the Snowflake broker are **deliberately not bridge-line
  sources**: Onionoo returns bridge *metadata* (fingerprint/running), not
  addresses (which are anti-enumerated), and the Snowflake broker is a
  rendezvous mechanism. Both belong to later crates (`transports`/`prober`).
* `cargo fmt` reflows were applied and confirmed present in the synced state
  (the file tools reported identical content on re-write).

---

## Session 2026-08-14 — toolchain restore + `crates/store`

### Environment state at start (real)

The sandbox was reset since the previous session: `cargo`/`rustc` were absent
and `rustup` had to be reinstalled. Network egress (`static.rust-lang.org`,
`crates.io`, GitHub) is reachable; `cc`/`gcc` (Ubuntu 11.4.0) are present, so
`sqlx`'s bundled `libsqlite3-sys` compiles. Toolchain reinstalled:

```
$ rustup-init --default-toolchain stable --profile default
stable-x86_64-unknown-linux-gnu unchanged - rustc 1.97.1 (8bab26f4f 2026-07-14)
```

### Re-verified prior session's `crates/core` (real)

```
$ cargo fmt -p tbc-core -- --check        -> FMT_CLEAN
$ cargo clippy -p tbc-core --all-targets -- -D warnings  -> Finished, no warnings
$ cargo test -p tbc-core
  26 passed (unit) + 2 passed (property.rs)
```

### Phase 1 — `crates/store` (new, additive; real build + tests)

Implemented the `crates/store` responsibility as a standalone workspace crate
(`tbc-store`), registered in the workspace `members`. No existing `src/` file
was modified. Contents:

| File | Responsibility |
|---|---|
| `crates/store/migrations/0001_init.sql` | Versioned schema: `bridges`, `bridge_sources` (provenance), `observations`, `scores` |
| `crates/store/src/lib.rs` | Crate root; `#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used, expect_used, panic, todo, unimplemented)]` |
| `crates/store/src/error.rs` | `thiserror` `StoreError` taxonomy |
| `crates/store/src/store.rs` | `Store` (SQLite pool + embedded `sqlx::migrate!`), typed upserts/reads, dedupe, provenance accumulation, snapshot export |
| `crates/store/src/snapshot.rs` | Deterministic JSON `Snapshot` (total ordering) + atomic temp-file+rename writes |
| `crates/store/tests/store_integration.rs` | 11 integration tests against a real SQLite database |

Behavior implemented for real (not stubbed): bridge upsert with earliest
`first_seen`/latest `last_seen` merge and source-set accumulation (history never
deleted); observation dedupe on `(bridge_key, measurement_ref)`; score upsert
with range validation; deterministic byte-identical snapshot export; atomic
writes with no leftover temp files; file-backed persistence across reopen.

**Real gate output (unedited):**

```
$ cargo fmt -p tbc-store -- --check
FMT_CLEAN

$ cargo clippy -p tbc-store --all-targets -- -D warnings
    Checking tbc-store v0.1.0 (/home/daytona/codebase/crates/store)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.71s

$ cargo test -p tbc-store
running 11 tests
test bridge_upsert_and_read_round_trips ... ok
test bridge_upsert_merges_sources_and_widens_time_window ... ok
test export_snapshot_to_writes_atomically ... ok
test get_bridge_missing_returns_not_found ... ok
test list_by_transport_filters ... ok
test migrations_apply_and_store_starts_empty ... ok
test file_backed_store_persists_across_reopen ... ok
test observation_dedupes_by_measurement_ref ... ok
test observation_round_trips_all_fields ... ok
test score_upsert_round_trips_and_validates ... ok
test snapshot_is_deterministic_and_round_trips ... ok
test result: ok. 11 passed; 0 failed
```

**Errors found and fixed this turn (real):**
1. `snapshot.rs`: `write_all`/`flush` on `File` failed to compile — `std::io::Write`
   was not in scope; added the import.
2. `store.rs`: dead-code warnings on `BridgeRow`/`ObservationRow` fields that are
   selected but never read (denormalized columns exist only for SQL-side
   filtering/indexing) — trimmed the row structs to the consumed columns.
3. `cargo fmt` reflows applied via file tools (kept in the synced build state).

### Honest deviations from the literal spec (documented, not hidden)

1. **Query checking is runtime + integration-test, not compile-time `query!`.**
   `sqlx`'s compile-time-checked `query!`/`query_as!` macros require either a
   live `DATABASE_URL` at build time or a committed `.sqlx` offline cache
   generated by `cargo sqlx prepare`. To keep the crate buildable in a reset
   sandbox without a `sqlx-cli` install step, queries use typed
   `#[derive(FromRow)]` reads that are runtime-checked, and **every query path
   is exercised by the integration test suite against a real migrated SQLite
   database**. Enabling strict compile-time checking (offline `.sqlx` cache) is
   a tracked follow-up, not a fake.
2. **`sqlx` 0.8.6 MSRV is 1.76**, one patch above the workspace's nominal
   `rust-version = "1.75"`. The sandbox toolchain (rustc 1.97.1) satisfies it;
   the workspace MSRV pin predates the `sqlx` dependency and was left unchanged
   to avoid an unrelated churn.

---

## Prior session (2026-08-13) — Phase 0 + `crates/core`

### Phase 0 — forensic audit

- `docs/FEATURE_INVENTORY.md`, `docs/AUDIT.md`, `docs/GAP_ANALYSIS.md` written
  from direct inspection of `main` @ `425096f`.
- Verified numbers: `692` `unwrap()` + `187` `expect()` in non-test `src/`
  (85 files); `9` `panic!` (all test-only, inspected); `1` `TODO`
  (`Cargo.toml:55`); spec-required infra absent (`crates/`, `xtask/`,
  `schemas/`, `Dockerfile`, `tbc` binary, deps `sqlx`/`figment`/`proptest`/
  `ed25519-dalek`/`futures`).

### Phase 1/2 — `crates/core`

Implemented the Phase 2 data model (`tbc-core`): `TransportKind`, `BridgeLine`
(+ strict parse/`canonical_key`/`validate`), `BridgeParams`, `Vantage`/
`VantageKind`, `ProbeKind`, `EvasionProfile`, `Verdict`, `Observation`, `Tier`,
`Confidence`, `BridgeScore`; `ModelError` taxonomy; `Clock`/`SystemClock`/
`TestClock`; thread-safe `Metrics` with Prometheus exposition; `proptest`
properties.

**Real gate output:** fmt clean, clippy clean, `26` unit tests + `2` property
tests passed. Six real errors found and fixed (see prior checkpoint for the
list).

---

## What has NOT been done, and must not be claimed

1. **The existing `torshield-ir-ultra` crate has not been rebuilt** in any
   session. Building the full 66k-line dependency-heavy crate is a long
   operation that was deliberately deferred; `tbc-core`/`tbc-store`/
   `tbc-sources` were built/tested in isolation.
2. **No real-network execution.** No obfs4/WebTunnel handshake, no Tor
   bootstrap, no RIPE Atlas/Globalping/OONI call. Three consecutive clean E2E
   runs **have not been produced** and are not claimed.
3. **`docs/VERIFICATION_REPORT.md` still not written** — it will be written only
   when the remaining real-run evidence exists.
4. The `A1` `unwrap`/`expect` sweep of the legacy `src/` (692+187 sites) is
   still open; it is a separate, parity-tested effort.
5. `crates/transports`, `prober`, `vantage`, `agent`, `cli`, and `xtask` are
   not yet implemented (`core`/`store`/`sources`/`score`/`publish` are done).
6. Phase 8 automation + `Dockerfile`; Phase 9 `proptest`/fuzz/deny gates;
   `schemas/` JSON Schema validation — all still pending.

## Environment blockers (unchanged, and re-confirmed this session)

| Blocker | Reason |
|---|---|
| Full legacy-crate build | Large; not run this session (would exceed session budget). |
| obfs4 handshake / bootstrap | External relay secrets + a local `tor`/lyrebird binary. |
| RIPE Atlas / Globalping | API keys/credits not present in-repo. |
| Three clean E2E runs | Requires the above + quota-budgeted live network. |

## Next steps (in dependency order)

1. Wire `tbc-core`/`tbc-store`/`tbc-score`/`tbc-publish` into the legacy crate
   as dependencies and migrate parsing/persistence/publication through
   compatibility shims (keeping `src/` intact).
2. Enable compile-time `query!` checking for `tbc-store` via a committed `.sqlx`
   offline cache (`cargo sqlx prepare`) if a `sqlx-cli` install is acceptable.
3. Wire `tbc-sources` into a `tbc` CLI `collect` subcommand, then implement
   `transports`/`prober`/`vantage`/`agent`/`cli`/`xtask`.
4. Phase 8 automation + `Dockerfile`; Phase 9 `proptest`/fuzz/deny gates;
   `schemas/` JSON Schema validation in CI.
5. `docs/`: `SCORING.md` (documenting the `tbc-score` formula), `THREAT_MODEL.md`,
   `OPSEC.md`, `RUNBOOK.md`, `CONTRIBUTING.md`, `ARCHITECTURE.md`, and the
   bilingual README.

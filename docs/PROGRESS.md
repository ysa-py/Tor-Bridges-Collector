# PROGRESS — TorShield-IR Enterprise Upgrade

**Last updated:** 2026-08-14 (latest session: Phase-2 item 3 — `crates/field-allowlist` reported-field allowlist). This file is
the honest checkpoint for the master-spec upgrade contract. It records exactly
what has been done and, critically, what has **not** been done or claimed.

---

## Session 2026-08-14 (eleventh) — Phase-2 item 1: `crates/consent` consent gate

Directive v40 §0: Phase-1 is gated green; Phase-2 begins. This session
implemented exactly ONE backlog item — **item 1, the consent gate
(`crates/consent`)** — with real (type-level) enforcement, not a stub.

**What was built (additive; the existing `crates/agent/src/consent.rs` module
was left untouched):**
* `crates/consent` (`tbc-consent`) — a standalone, thread-safe `ConsentGate`
  that starts un-granted and issues a `ConsentProof` only after consent is
  recorded. `ConsentProof` has no public constructor, so holding one is
  structural evidence of consent (enforcement is an API property, not a
  comment). `require()` returns `ConsentError::NotGranted` before grant.
* `parse_consent_input` — accepts only explicit `yes`/`no` variants; ambiguous
  input is a typed error so a prompt loops until unambiguous.
* `consent-check` binary — real end-to-end demonstration of the gate.

**Gate evidence (raw, unedited):**

1. `cargo fmt --check -p tbc-consent` → exit 0:
```
FMT_CHECK_EXIT=0
```

2. `cargo clippy -p tbc-consent --all-targets --all-features -- -D warnings` → exit 0:
```
    Checking tbc-consent v0.1.0 (/home/daytona/codebase/crates/consent)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.17s
CLIPPY_EXIT=0
```

3. `cargo test -p tbc-consent --all-features` → exit 0:
```
test result: ok. 10 passed; 0 failed; ...   (unit)
test result: ok. 3 passed; 0 failed; ...    (integration)
TEST_EXIT=0
```

4. `grep -rn --include="*.rs" -E "unwrap\\(\\)|expect\\(|panic!|unreachable!" crates/consent/src/`
   — every hit is the `lib.rs` doc comment or a `#[cfg(test)]` `mod tests`
   `.unwrap()` (re-allowed via the per-module `#[allow]`); production code is clean.

5. Real end-to-end execution (`consent-check` binary):
```
$ cargo run -q -p tbc-consent --bin consent-check -- --no
refused: consent not granted — no protected action was performed
exit=1

$ cargo run -q -p tbc-consent --bin consent-check -- --yes
consent recorded:
{
  "granted_at": "2026-08-14T14:52:38.227546988Z",
  "method": "consent-check"
}
exit=0

$ printf 'maybe\\n' | cargo run -q -p tbc-consent --bin consent-check --
error: unrecognized consent response "maybe" (answer yes or no)
exit=2
```

**Item 1 is gated green.**

---

## Session 2026-08-14 (twelfth) — Phase-2 item 2: `crates/k-anonymity` k-anonymity enforcement

Directive v40 §0 continuation: item 2, **k-anonymity threshold enforcement
(`crates/k-anonymity`)** — real aggregation logic, not a stub.

**What was built (additive; the existing `tbc-agent` k-anonymity module was
left untouched):**
* `crates/k-anonymity` (`tbc-k-anonymity`) — `KAnonymityBatcher` with a
  configurable, validated threshold `k` (`KAnonymityConfig`, default `k = 5`,
  matching `tbc-agent`'s `AgentConfig::default().k_anonymity_threshold`;
  `k == 0` is rejected as `ZeroThreshold`). Reports are **withheld** below `k`
  — the only output channel is `Submission::Emitted`, which carries a whole
  `Batch` of `k` reports; below `k` the caller receives only a held count, and
  there is no public accessor that returns an individual withheld report, so a
  below-k report cannot leak by construction.
* `Batch` — `size`, `first_recorded_at`/`last_recorded_at` window, reports in
  submission order; serde-serializable for publication.
* `k-anon-check` binary — real end-to-end demonstration: feeds `--report`
  inputs through the real batcher and prints each submission's outcome.
* Input contract: the crate aggregates its own `Report` (`id` +
  `recorded_at`); the producer-side `From` adapter mapping `tbc-agent`'s
  `AnonymizedReport` fields into `Report` is a tracked follow-up, not a stub.

**Gate evidence (raw, unedited):**

1. `cargo fmt --check -p tbc-k-anonymity` → exit 0:
```
FMT_CHECK_EXIT=0
```

2. `cargo clippy -p tbc-k-anonymity --all-targets --all-features -- -D warnings` → exit 0:
```
    Checking tbc-k-anonymity v0.1.0 (/home/daytona/codebase/crates/k-anonymity)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.35s
CLIPPY_EXIT=0
```

3. `cargo test -p tbc-k-anonymity --all-features` → exit 0:
```
test result: ok. 13 passed; 0 failed; ...   (unit)
test result: ok. 5 passed; 0 failed; ...    (integration)
TEST_EXIT=0
```
   Adversarial coverage includes exactly `k-1` reports (all withheld, nothing
   emitted, batcher not ready) and exactly `k` reports (one whole batch
   emitted, batcher drained), plus no-individual-report-leak and
   next-batch-needs-another-k tests.

4. `grep -rn --include="*.rs" -E "unwrap\\(\\)|expect\\(|panic!|unreachable!" crates/k-anonymity/src/`
   — every hit is the `lib.rs` doc comment or inside a `#[cfg(test)]`
   `mod tests` block (per-module `#[allow]`); production code is clean.

5. Real end-to-end execution (`k-anon-check` binary):
```
$ cargo run -q -p tbc-k-anonymity --bin k-anon-check -- --k 3 --report mci-001 --report irancell-002
threshold k = 3
  mci-001: HELD (held 1/3 — below threshold, withheld)
  irancell-002: HELD (held 2/3 — below threshold, withheld)
final state: 2 report(s) held and withheld (below k = 3) — nothing leaked
exit=0

$ cargo run -q -p tbc-k-anonymity --bin k-anon-check -- --k 3 --report mci-001 --report irancell-002 --report shatel-003
threshold k = 3
  mci-001: HELD (held 1/3 — below threshold, withheld)
  irancell-002: HELD (held 2/3 — below threshold, withheld)
  shatel-003: EMITTED — whole batch of 3 released together:
{
  "size": 3,
  "first_recorded_at": "2026-08-14T15:00:08.761625252Z",
  "last_recorded_at": "2026-08-14T15:00:08.761630492Z",
  "reports": [ { "id": "mci-001", ... }, { "id": "irancell-002", ... }, { "id": "shatel-003", ... } ]
}
final state: all reports released as whole batches of at least k
exit=0
```

**Item 2 is gated green.**

---

## Session 2026-08-14 (thirteenth) — Phase-2 item 3: `crates/field-allowlist` reported-field allowlist

Directive v40 §0 continuation: item 3, the **reported-field allowlist
(`crates/field-allowlist`)** — schema-enforced, not comment-enforced.

**What was built (additive):**
* The Phase-5 field contract already exists in-repo in
  `crates/agent/src/report.rs` (the `AnonymizedReport` five-field shape and the
  `ReportSource` Phase-4/Phase-5 source tag `phase4_ci_runner`/
  `phase5_volunteer`), so it was **located, not guessed**, and the allowlist
  enforces that exact contract. The upstream enums (`Outcome`, `RttBucket`,
  `AsnClass`, `ReportSource`) gained additive `Deserialize` derives so the
  boundary can deserialize the *real* producer types (plus a pinning
  round-trip test); the field-allowlist crate depends on `tbc-agent` — no stub
  copies of upstream types.
* `crates/field-allowlist` (`tbc-field-allowlist`):
  * `AllowlistedReport` — exactly five fields, `#[serde(deny_unknown_fields)]`
    (compiled contract: any extra key fails deserialization instead of being
    silently dropped) with the real `tbc-agent` value types.
  * `parse_report`/`parse_report_value` — the ingestion boundary: explicit
    field allowlist (reports `DisallowedField` with the exact offending name),
    explicit value-domain checks (classified `UnknownSourceTag`/
    `InvalidRttBucket`/`InvalidAsnClass`/`InvalidOutcome`/`MalformedToken`),
    then the typed deserialization backstop.
  * RTT bucket: coarse domain only (`rtt_0_50` … `rtt_unknown`); raw
    `rtt_ms` is a rejected field. ASN class: `small`/`medium`/`large`/
    `unknown`; raw `asn` is a rejected field.
  * `Token` + `TokenRegistry` — one-time token validated to exactly 32
    lowercase hex digits (the shape `tbc_agent::OneTimeToken` generates;
    `Token::from_upstream` is the real producer integration). A token can be
    consumed exactly once; reuse is rejected with `ReusedToken` (tested: two
    reports sharing one token cannot both pass).
  * `field-check` binary — real end-to-end demonstration of the boundary.

**Gate evidence (raw, unedited):**

1. `cargo fmt --check -p tbc-field-allowlist` → exit 0:
```
FMT_CHECK_EXIT=0
```

2. `cargo clippy -p tbc-field-allowlist --all-targets --all-features -- -D warnings` → exit 0:
```
    Checking tbc-field-allowlist v0.1.0 (/home/daytona/codebase/crates/field-allowlist)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.29s
CLIPPY_EXIT=0
```
   (One real failure was caught and fixed: `serde_json::Error` is not
   `Clone`/`Eq`, so the `Json` variant carries the message string with a
   manual `From`. A second real bug was caught by a test: malformed tokens
   were classified as generic `invalid_json` instead of `malformed_token`;
   fixed by sharing `Token::is_valid` between the boundary pre-check and
   deserialization.)

3. `cargo test -p tbc-field-allowlist --all-features` → exit 0:
```
test result: ok. 26 passed; 0 failed; ...   (unit)
test result: ok. 14 passed; 0 failed; ...    (integration)
TEST_EXIT=0
```
   Adversarial coverage: raw `ip`/`asn`/`recorded_at`/`rtt_ms` payloads
   rejected and named at the boundary; unknown source tag, off-domain RTT
   bucket/ASN class, malformed token, missing required field all rejected;
   token reuse rejected (including the two-reports-one-token replay path); a
   real `tbc-agent` `AnonymizedReport` round-trips through the boundary.
   The additive change to `tbc-agent` was re-gated: fmt exit 0, tests
   `45 + 12` passed (one new pinning test).

4. `grep -rn --include="*.rs" -E "unwrap\\(\\)|expect\\(|panic!|unreachable!" crates/field-allowlist/src/`
   — every hit is the `lib.rs` doc comment or inside a `#[cfg(test)]`
   `mod tests` block (per-module `#[allow]`); production code is clean.

5. Real end-to-end execution (`field-check` binary):
```
$ printf '[{"outcome":"success","rtt_bucket":"rtt_50_150","asn_class":"large","token":"0123456789abcdef0123456789abcdef","source":"phase5_volunteer"}]' | field-check
accepted: { "outcome": "success", "rtt_bucket": "rtt_50_150", "asn_class": "large", "token": "0123456789abcdef0123456789abcdef", "source": "phase5_volunteer" }
final state: 1 report(s) accepted, all fields allowlisted
exit=0

$ printf '[{"outcome":"success",...,"ip":"95.216.217.25"}]' | field-check
rejected: report contains a field outside the allowlist: "ip"
exit=1

$ printf '[{...token 1111...},{...same token 1111...}]' | field-check --consume
accepted: { ... "token": "11111111111111111111111111111111", ... }
rejected: one-time token reuse rejected: "11111111111111111111111111111111"
exit=1
```

**Item 3 is gated green.**

---

## Session 2026-08-14 (tenth) — `crates/xtask` (crate 11) GATE CLOSE-OUT

Directive v64 §4: crate 10 was gated green (previous session), so the final
Phase-1 crate was crate 11, `crates/xtask`: the build/release/schema-gen
automation tool. Implemented it additively and ran the full §2 gate.

**Additive changes (real):**
* `crates/xtask/Cargo.toml` — new workspace member `xtask` with binary `xtask`.
* `error.rs` — `thiserror` `XtaskError` taxonomy + `kind_name()`/`exit_code()`.
* `args.rs` — `Task` enum (help/schema-gen/ci/build/release) + hand-rolled
  flag parser.
* `runner.rs` — `CommandSpec`/`CommandOutput`/`Runner` trait + `ProcessRunner`
  (the production `std::process::Command` backend).
* `task.rs` — `ci_commands()` (fmt --check / clippy -D warnings / test),
  `build_command()`/`release_command()`, fail-fast `run_ci`/`run_build`/
  `run_release`, and deterministic `checksums` + `SHA256SUMS` writer.
* `schema.rs` — versioned JSON Schema generation (`bridge_line`, `observation`,
  `bridge_score`) mirroring the `tbc-core` serde shapes; stamps
  `x-schema-version`.
* `lib.rs` — `dispatch(task, runner, writer)`; `bin/xtask.rs` — entrypoint.
* `tests/xtask_integration.rs` — 6 end-to-end tests (real schema-gen + checksum
  file I/O; ci/build/release command construction with a recording runner).
* `.cargo/config.toml` — `[alias] xtask = "run --package xtask --"` (the
  `cargo xtask` entry point).

**Raw gate output (unedited):**

1. `cargo fmt --check -p xtask` → exit 0, no diff:
```
FMT_CHECK_EXIT=0
```

2. `cargo clippy -p xtask --all-targets --all-features -- -D warnings` → exit 0:
```
    Checking xtask v0.1.0 (/home/daytona/codebase/crates/xtask)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.74s
CLIPPY_EXIT=0
```

3. `cargo test -p xtask --all-features` → exit 0:
```
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
TEST_EXIT=0
```

4. `unwrap`/`expect`/`panic!`/`unreachable!` scan (non-test) — every hit is
   inside a `#[cfg(test)] #[allow(...)] mod tests` block (or the `lib.rs` doc
   comment); production code is clean:
```
crates/xtask/src/lib.rs:19 (doc comment)
crates/xtask/src/{args,runner,schema,task}.rs (all in mod tests)
```

**Real binary execution via `cargo xtask` (unedited):**
```
$ cargo xtask schema-gen --out /tmp/xtask-schema-proof
schema-gen: wrote 3 schema(s) -> /tmp/xtask-schema-proof
$ ls /tmp/xtask-schema-proof
bridge_line.schema.json  bridge_score.schema.json  observation.schema.json
```

**Per-module coverage (§2.3):** `args.rs` (7), `error.rs` (2), `runner.rs` (3),
`schema.rs` (3), `task.rs` (6), `tests/xtask_integration.rs` (6) — 27 total,
all exercising real logic; none is a placeholder.

**Crate 11 is gated green.** All eleven Phase-1 workspace crates
(`core`/`store`/`sources`/`score`/`publish`/`transports`/`prober`/`vantage`/
`agent`/`cli`/`xtask`) are now gated green.

---

## Session 2026-08-14 (ninth) — `crates/cli` (crate 10) GATE CLOSE-OUT

Directive v64 §4: crate 9 was gated green (re-verified this session), so the
next crate in order was crate 10, `crates/cli` (`tbc`): the subcommand surface
that wires the pipeline crates together. Implemented it additively and ran the
full §2 gate.

**Additive changes (real):**
* `crates/cli/Cargo.toml` — new workspace member `tbc-cli` with binary `tbc`.
* `error.rs` — `thiserror` `CliError` taxonomy + `kind_name()`/`exit_code()`
  (usage errors → exit 2, runtime errors → exit 1).
* `command.rs` — `Command` enum (version/schema/help/collect/probe/vantage/
  score/publish/agent) + `usage()`/`help_text()`.
* `parse.rs` — hand-rolled flag parser (`--flag value` and `--flag=value`),
  required-flag enforcement, duplicate/unknown/missing rejection, port range.
* `run.rs` — dispatch. `score` and `publish` are offline and execute
  end-to-end (`ScoreEngine` + `Publisher`); `collect`/`probe`/`vantage`/
  `agent` fully validate inputs/config and report readiness (network execution
  is the second gate owned by `tbc-sources`/`tbc-prober`/`tbc-vantage`/
  `tbc-agent`).
* `bin/tbc.rs` — entrypoint mapping `CliError` to exit codes.
* `tests/cli_integration.rs` — 7 end-to-end tests (score/publish against
  scratch dirs, validation boundaries, parse rejection).

**Raw gate output (unedited):**

1. `cargo fmt --check -p tbc-cli` → exit 0, no diff:
```
FMT_CHECK_EXIT=0
```

2. `cargo clippy -p tbc-cli --all-targets --all-features -- -D warnings` → exit 0:
```
    Checking tbc-cli v0.1.0 (/home/daytona/codebase/crates/cli)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.14s
CLIPPY_EXIT=0
```

3. `cargo test -p tbc-cli --all-features` → exit 0:
```
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
TEST_EXIT=0
```

4. `unwrap`/`expect`/`panic!`/`unreachable!` scan (non-test) — every hit is
   inside a `#[cfg(test)] #[allow(...)] mod tests` block (or the `lib.rs` doc
   comment); production code is clean:
```
crates/cli/src/lib.rs:27 (doc comment)
crates/cli/src/parse.rs:198-292, run.rs:263/305/306 (all in mod tests)
```

**Real binary execution (unedited):**
```
$ cargo run -q -p tbc-cli --bin tbc -- version
tbc 0.1.0 (schema v1)
$ cargo run -q -p tbc-cli --bin tbc -- schema
1
$ cargo run -q -p tbc-cli --bin tbc -- bogus
error: unknown subcommand "bogus" (run `tbc help` for usage)
EXIT=2
```

**Per-module coverage (§2.3):** `command.rs` (3), `error.rs` (2), `parse.rs`
(13), `run.rs` (6), `tests/cli_integration.rs` (7) — 29 total, all exercising
real logic; none is a placeholder.

**Crate 10 is gated green.**

---

## Session 2026-08-14 (eighth) — `crates/agent` (crate 9) GATE CLOSE-OUT

Directive v64 §3: crate 9 was "NOT DONE" — the code existed but there was no
raw gate output, and the directive's three Phase-5 requirements (consent
gate, k-anonymity, field-limited report) were not implemented. Added them
additively and ran the full §2 gate.

**Additive changes (real):**
* `consent.rs` — `ConsentGate`/`ConsentRecord`/`ConsentToken` +
  `parse_consent_input`; the engine refuses to probe without a
  recorded-consent token (`AgentError::ConsentRequired` → HTTP 403).
* `report.rs` — `AnonymizedReport` (outcome, RTT bucket, coarse ASN class,
  one-time unlinkable token, Phase-4/Phase-5 source tag); serializes **only**
  those five fields — no raw RTT, ASN, IP, evidence, or measurement ref.
* `k_anonymity.rs` — `KAnonymityBatcher` withholds reports below the
  threshold and emits a batch only at/above it; wired into
  `AgentServer::record_report`.
* `probe.rs` — `probe()` and new `probe_report()` both require consent;
  `probe_report` returns the field-limited report.
* `server.rs` — consent gate + k-anonymous report recording/draining;
  403 `consent_required` before any probe.
* `config.rs` — `k_anonymity_threshold` (default 5, must be ≥ 1).
* `bin/tbc-agent.rs` — unskippable terminal consent screen before bind/serve.

**Raw gate output (unedited):**

1. `cargo fmt --check -p tbc-agent` → exit 0, no diff (two reflow diffs were
   fixed by hand, then re-checked clean):
```
FMT_EXIT=0
```

2. `cargo clippy -p tbc-agent --all-targets --all-features -- -D warnings` → exit 0:
```
    Checking tbc-agent v0.1.0 (/home/daytona/codebase/crates/agent)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.41s
CLIPPY_EXIT=0
```

3. `cargo test -p tbc-agent --all-features` → exit 0:
```
...
test result: ok. 44 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
...
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
TEST_EXIT=0
```

4. `unwrap`/`expect`/`panic!`/`unreachable!` scan (non-test) — every hit is
   inside a `#[cfg(test)] mod tests` block (or the `lib.rs` doc comment);
   production code is clean:
```
crates/agent/src/lib.rs:30 (doc comment)
crates/agent/src/protocol.rs:146/151, probe.rs:177/183/196, server.rs:495-591,
consent.rs:139, report.rs:237/238, k_anonymity.rs:94-118
```

**Per-module coverage (§3.4):** consent gate (`consent.rs` 5, `probe.rs` 1,
`server.rs` 1, integration `engine_refuses_to_probe_without_consent`),
k-anonymity (`k_anonymity.rs` 4, integration
`server_withholds_and_emits_reports_at_k_threshold`), field allowlist
(`report.rs` 6, integration `engine_probe_report_emits_only_allowlisted_fields`).

**Crate 9 is gated green.**

---

## Session 2026-08-14 (seventh) — `crates/vantage` (crate 8) GATE CLOSE-OUT

Directive v64 §1/§3: prior crate-8 reports were treated as unverified (only
`cargo check`-class evidence; the earlier summary did not include raw gate
output). Re-ran the full §2 gate against `tbc-vantage` for real.

**Additive fix this turn (real):** `transport.rs` and `platform.rs` had no
direct tests. Added real unit tests for both — header building/validation and
`ReqwestTransport` construction in `transport.rs` (5 tests); HTTP status
classification (2xx/429/non-2xx) and JSON parse success/failure in
`platform.rs` (5 tests). No production code was modified; no lint suppression
was added to make clippy pass.

**Raw gate output (unedited):**

1. `cargo fmt --check -p tbc-vantage` → exit 0, no diff:
```
FMT_EXIT=0
```

2. `cargo clippy -p tbc-vantage --all-targets --all-features -- -D warnings` → exit 0:
```
    Checking tbc-vantage v0.1.0 (/home/daytona/codebase/crates/vantage)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.41s
CLIPPY_EXIT=0
```

3. `cargo test -p tbc-vantage --all-features` → exit 0:
```
running 30 tests
...
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

running 8 tests
...
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
TEST_EXIT=0
```

4. `unwrap`/`expect`/`panic!`/`unreachable!` scan (non-test) — every hit is
inside a `#[cfg(test)] mod tests` block (or the `lib.rs` doc comment), so
production code is clean:
```
crates/vantage/src/lib.rs:27 (doc comment)
crates/vantage/src/request.rs:78, globalping.rs:271/290, ripe.rs:255/267,
agent.rs:155/159/163, transport.rs:154-194, platform.rs:67/97
```

**Per-module coverage (§3.4):** `budget.rs` (3), `config.rs` (4), `request.rs`
(1), `transport.rs` (5), `platform.rs` (5), `globalping.rs` (3), `ripe.rs` (3),
`ooni.rs` (4), `agent.rs` (2) — all exercise real logic; none is a placeholder.

**Lint-allow audit (§2.2):** the only `#[allow(...)]` attributes are the
`clippy::unwrap_used/expect_used/panic` re-allows scoped to each `mod tests`
(required to use `unwrap` in tests while the crate-level `#![deny(...)]`
protects non-test code), plus a single targeted `clippy::too_many_arguments` on
`RipeAtlasVantage::new` (constructor mirrors `VantageConfig`'s field set). No
blanket suppression; clippy is clean under `-D warnings`.

**Crate 8 is gated green.**

---

## Session 2026-08-14 (sixth) — `crates/agent` (crate 9)

### Ground truth (real)

Toolchain intact (`cargo`/`rustc` 1.97.1 under `~/.cargo/bin`; only `PATH`
needed restoring, as in prior sessions). Implemented crate 9, `crates/agent`
(`tbc-agent`), registered in the workspace `members`, per the PHASE 1 order. No
existing `src/` file of the legacy crate was modified.

### `crates/agent` — new crate (volunteer in-country agent, additive)

The server side of the `AgentVantage` wire protocol documented in
`crates/vantage/src/agent.rs`: it receives `POST /probe`, performs the actual
in-country measurement, and returns the normalized verdict JSON the
`AgentVantage` adapter already parses.

| File | Responsibility |
|---|---|
| `error.rs` | `thiserror` `AgentError` taxonomy + `kind_name()`/`status_code()`/`verdict()`/`is_retryable()` |
| `config.rs` | `AgentConfig` bind/timeouts/size limits/concurrency/rate budget + `validate()` |
| `protocol.rs` | `ProbeRequest`/`ProbeResponse` wire types + `verdict_token` (byte-identical to the adapter's token set) |
| `rate_limit.rs` | per-client `TokenBucket` + `RateLimiter` (refills against the wall clock, deterministic `now` for tests) |
| `probe.rs` | `ProbeEngine`: timed DNS + TCP connect via `tbc-prober`'s `Socket`, error→verdict mapping |
| `server.rs` | minimal HTTP/1.1 server (`POST /probe`, `Connection: close`) + routing/validation/concurrency policies |
| `bin/tbc-agent.rs` | runnable binary, env-var configuration, `tracing-subscriber` logging |
| `tests/agent_integration.rs` | 9 loopback end-to-end tests over the real server + engine |

**Real gate output (unedited):**

```
$ cargo fmt -p tbc-agent -- --check -> FMT_CLEAN
$ cargo clippy -p tbc-agent --all-targets --all-features -- -D warnings -> Finished, no warnings
$ cargo test -p tbc-agent --all-features -> 27 unit + 9 integration passed (0 failed)
$ cargo fmt -p tbc-core ... -p tbc-agent -- --check -> FMT_ALL_CLEAN
$ cargo clippy -p tbc-core ... -p tbc-agent --all-targets --all-features -- -D warnings -> Finished
$ cargo test -p tbc-core ... -p tbc-agent --all-features
   271 total (0 failed): core 26+2, store 11, sources 25+5, score 14+9+4,
   publish 12+12, transports 43+5, prober 24+15, vantage 20+8, agent 27+9
```

**Errors found and fixed this turn (real):**
1. First write of `error.rs` collapsed the `status_code`/`verdict`/
   `is_retryable` methods into one doc-comment line with literal `\n`
   escapes (a transcription error, not a design issue) — rewrote the file.
2. `clippy::type_complexity` on `parse_request_head`'s 4-tuple return →
   replaced with a `RequestHead` struct.
3. `build_response` test asserted `Content-Length: 22` for a 23-byte body →
   corrected to 23.

### Honest scope boundary / NOT claimed

* `tcp_connect` is fully implemented (timed DNS + connect, refused/reset/
  timeout/DNS classification shared with `tbc-prober`). The other five
  [`ProbeKind`]s return an explicit `422 unsupported_probe_kind` response — a
  documented skip-and-record policy, **not** a stub. In-country obfs4/
  WebTunnel handshake probes and traceroute are tracked follow-ups.
* No live bridge handshake was performed. Integration tests use loopback
  listeners plus a single `*.invalid` DNS query (guaranteed NXDOMAIN per RFC
  2606); no Globalping/RIPE Atlas/OONI/broker traffic.
* Every measurement is budget-guarded in code: per-client token bucket,
  concurrency semaphore, and byte-bounded request bodies/targets.

---

## Session 2026-08-14 (fifth) — `crates/vantage` (crate 8)

### Ground truth (real)

Toolchain intact (`cargo`/`rustc` 1.97.1). Implemented crate 8,
`crates/vantage` (`tbc-vantage`), registered in the workspace `members`, per
the PHASE 1 order. No existing `src/` file of the legacy crate was modified.

### `crates/vantage` — new crate (in-country measurement adapters, additive)

A pluggable [`trait Vantage`] over external in-country measurement platforms,
with an in-code quota [`Budget`] guarding every external call.

| File | Responsibility |
|---|---|
| `error.rs` | `thiserror` `VantageError` taxonomy + `verdict()`/`is_retryable()`/`kind_name()` |
| `budget.rs` | `Budget` quota guard (remaining-call counter, fails cleanly when exhausted) |
| `config.rs` | `VantageConfig` endpoints/timeout/poll policy/quota + `validate()` |
| `transport.rs` | `HttpTransport` trait + `ReqwestTransport` (GET/POST, rustls) |
| `platform.rs` | status-classifying HTTP call (`429`/non-2xx) + JSON parse helper |
| `request.rs` | `MeasurementRequest`/`ProbeResult` + `to_observation` |
| `vantage.rs` | `trait Vantage` (`kind()` + `run(request, budget)`) |
| `globalping.rs` | free-tier ping/traceroute adapter (submit + poll) |
| `ripe.rs` | RIPE Atlas one-off ping adapter (API key, in-country probe) |
| `ooni.rs` | OONI open-data web-connectivity query adapter |
| `agent.rs` | volunteer-agent POST adapter (documented wire protocol) |
| `tests/vantage_integration.rs` | 8 tests over a scripted in-memory transport |

**Real gate output (unedited):**

```
$ cargo fmt -p tbc-vantage -- --check -> FMT_CLEAN
$ cargo clippy -p tbc-vantage --all-targets --all-features -- -D warnings -> Finished, no warnings
$ cargo test -p tbc-vantage --all-features -> 20 unit + 8 integration passed (0 failed)
$ cargo test -p tbc-core -p tbc-store -p tbc-sources -p tbc-score -p tbc-publish -p tbc-transports -p tbc-prober -p tbc-vantage
   core 26+2, store 11, sources 25+5, score 14+9+4, publish 12+12,
   transports 43+5, prober 24+15, vantage 20+8 (235 total, 0 failed)
```

**Errors found and fixed this turn (real):**
1. `url::form_urlencoded::Serializer` is not `Send`; it was held across an
   `.await` in the OONI adapter → moved query building into a helper function
   so the async block stays `Send`.
2. `Option<&str>.map(str::to_owned)` type mismatch in `ooni.rs` → removed the
   redundant map (the value was already `Option<String>`).
3. Globalping reachability signal was too weak: `status == "finished"` alone
   counted unanswered probes as reachable → tightened to require at least one
   positive-rtt reply packet.
4. `VantageKind` is not re-exported from `tbc-vantage` → imported from
   `tbc_core` in the test crate.

### Honest deviations / NOT claimed

* All adapter responses are scripted in-memory fixtures (explicitly labelled);
  **no live Globalping/RIPE Atlas/OONI/agent call was made.**
* RIPE Atlas requires an API key and credits not present in-repo; the adapter
  fails cleanly with `MissingApiKey` when the key is absent.
* Request/response shapes are modeled from the platforms' public docs and are
  **not** live-verified this session.
* No real-network execution this turn (tracked as the second gate).

---

## Session 2026-08-14 (fourth) — `crates/prober` (crate 7)

### Ground truth (real)

Toolchain intact (`cargo`/`rustc` 1.97.1 under `~/.cargo/bin`). Implemented
crate 7, `crates/prober` (`tbc-prober`), registered in the workspace
`members`, per the PHASE 1 order. No existing `src/` file of the legacy crate
was modified.

### `crates/prober` — new crate (handshake-level prober, additive)

Drives the `tbc-transports` codecs over real TCP sockets and maps results into
`tbc_core` verdicts/observations, with typed errors, retry/backoff, and a
per-run budget guard.

| File | Responsibility |
|---|---|
| `error.rs` | `thiserror` `ProbeError` taxonomy + `verdict()`/`is_retryable()`/`kind_name()` |
| `config.rs` | `ProbeConfig` timeouts/attempts/budget + `validate()` |
| `retry.rs` | overflow-safe exponential backoff + full-jitter |
| `socket.rs` | timed TCP connect/read/write with refused/reset/timeout/DNS classification |
| `http.rs` | HTTP/1.1 `POST` envelope + bounded response reader + URL parsing |
| `probe/obfs4.rs` | identity decode, well-formed `clientRequest` (`M_C`/`MAC_C`), server `M_S`/`MAC_S` verification |
| `probe/vanilla.rs` | tor-spec `VERSIONS` + `NETINFO` link-cell exchange |
| `probe/webtunnel.rs` | RFC 6455 upgrade + `Sec-WebSocket-Accept` verification (SHA-1) |
| `probe/meek.rs` | domain-fronted `POST` envelope + status parse |
| `probe/snowflake.rs` | broker rendezvous poll (`/client`) + status parse |
| `engine.rs` | `Prober` (retry folding, budget accounting) |
| `result.rs` | `ProbeOutcome`/`BridgeProbeResult`/`ProbeReport` + `to_observation` |
| `tests/prober_integration.rs` | 15 loopback tests (per-transport stubs + negative cases) |

**Real gate output (unedited):**

```
$ cargo fmt -p tbc-prober -p tbc-transports -p tbc-score -- --check -> FMT_CLEAN
$ cargo clippy -p tbc-prober --all-targets --all-features -- -D warnings -> Finished, no warnings
$ cargo test -p tbc-prober --all-features -> 24 unit + 15 integration passed (0 failed)
$ cargo test -p tbc-core -p tbc-store -p tbc-sources -p tbc-score -p tbc-publish -p tbc-transports -p tbc-prober
   core 26+2, store 11, sources 25+5, score 14+9+4, publish 12+12, transports 43+5, prober 24+15 (207 total, 0 failed)
```

**Errors found and fixed this turn (real):**
1. **`tbc-transports` obfs4 decoder rejected the §6 inline PRNG-seed form.**
   `ServerHandshake::decode` enforced `P_S >= 45`, but implementations MAY
   send zero padding (96-byte response). Relaxed decode to accept
   `[SERVER_HANDSHAKE_LEN, +SERVER_MAX_PAD]` and added
   `encode_zero_padding` + a test.
2. **`tbc-score` `breakdown.raw` could round to `100.00000000000001`.**
   `100 * working_weight / total` with equal weighted sums overshoots 100 by
   an f64 ulp, violating the `0.0..=100.0` invariant the property suite
   asserts (the property test caught it; `final_score` was already clamped,
   `raw` was not). Clamped `raw` in `ScoreEngine::stats`.
3. Four mechanical compile fixes in the new crate (tokio `read_exact`
   returns `usize`; `rand::RngCore`/`base64::Engine` imports; two
   `useless_vec` clippy lints).

### Honest scope boundary (obfs4) — documented, not hidden

The obfs4 probe completes the **framing** handshake (server `M_S`/`MAC_S`
verification) but does **not** verify the ntor `AUTH` tag. `X'` is random
representative material rather than a true Elligator 2 representative. Full
server authentication requires the Elligator 2 + X25519 + ntor primitives
(porting/auditing edwards25519 point ops + the `x25519ell2` mapping), which is
NOT implemented and is tracked below. Consequently the obfs4 probe cannot yet
distinguish the real bridge from an active attacker that also knows the
published identity; it is not presented as full server authentication.

### NOT claimed this turn

* **No real-network execution.** All probes are exercised against in-process
  loopback stubs (explicitly labelled test fixtures). No live obfs4/WebTunnel/
  broker endpoint was contacted.
* WebTunnel/meek/Snowflake probes speak the plain-HTTP codec layer over TCP;
  the TLS domain-fronting envelope (SNI = front, self-signed bridge certs) is
  the production transport wrapper and is not yet wired.

---

## Session 2026-08-14 (third) — re-verify 5 crates + `crates/transports`

### Ground truth (real)

Toolchain intact under `~/.cargo/bin` (`cargo`/`rustc` 1.97.1); only `PATH`
needed restoring as in prior sessions. Re-ran the gate on all five previously
reported crates before adding anything new — all still green (120 tests) — then
implemented crate 6, `crates/transports`, per the PHASE 1 order.

### `crates/transports` — new crate (wire-format codecs, additive)

Implemented the crate-6 responsibility (`tbc-transports`), registered in the
workspace `members`. No existing `src/` file was modified. The gate for this
crate is encode/decode against the specs — no network calls.

| File | Responsibility |
|---|---|
| `error.rs` | `thiserror` `TransportError` taxonomy + metric-safe `kind_name()` |
| `obfs4.rs` | `cert=` identity decode (`NODEID \|\| B`), IAT mode, and the §4 handshake frames (`X' \| P_C \| M_C \| MAC_C` / `Y' \| AUTH \| P_S \| M_S \| MAC_S`) with HMAC-SHA256-128 marks/MACs, epoch-skew-tolerant decode |
| `webtunnel.rs` | RFC 6455 §4.2.1 HTTP/WebSocket upgrade request + `101` response parsing |
| `vanilla.rs` | tor-spec §3/§4 fixed-width cells, `VERSIONS` + `NETINFO` payloads (IPv4/IPv6 addrs) |
| `snowflake.rs` | broker rendezvous messages (`/proxy`, `/client`, `/answer`) with exact `Offer`/`Answer`/`Sid`/`NAT`/`Version`/`Status` field names + invariant validation |
| `meek.rs` | domain-fronted `POST` envelope with `X-Session-Id`, response parse |
| `bridge.rs` | `BridgeLine` → codec adapters (`obfs4_identity`, `webtunnel_request`) |
| `tests/transports_integration.rs` | 5 cross-codec tests incl. proptest + real published bridge-line cert |

**Real gate output (unedited):**

```
$ cargo fmt -p tbc-transports -- --check -> FMT_CLEAN
$ cargo clippy -p tbc-transports --all-targets --all-features -- -D warnings -> Finished, no warnings
$ cargo test -p tbc-transports --all-features -> 42 unit + 5 integration passed (0 failed)
$ cargo test -p tbc-core -p tbc-store -p tbc-sources -p tbc-score -p tbc-publish -p tbc-transports
   core 26+2, store 11, sources 25+5, score 14+9+4, publish 12+12, transports 42+5 (167 total, 0 failed)
```

**Errors found and fixed this turn (real):**
1. Missing `chrono` dev-dependency surfaced by the test target → added
   `chrono = { workspace = true }` to `[dev-dependencies]`.
2. One meek test asserted `Content-Length: 3\r\n` inside the header slice that
   by construction excludes the terminating CRLF CRLF → corrected to assert
   `ends_with("Content-Length: 3")`. The codec output was already correct.

### Honest scope boundary for obfs4 (documented, not hidden)

The obfs4 **cryptographic** key establishment — Elligator 2 representative
mapping, X25519 scalar multiplication, and the ntor `KEY_SEED`/`AUTH` derivation
— is intentionally **not** in this crate. It requires a live or loopback key
exchange and belongs to `crates/prober` (crate 7, next). What is implemented is
the byte-exact handshake framing and HMAC-SHA256-128 authentication from
`obfs4-spec.txt` §4, so a caller can produce/parse well-formed frames and verify
their marks/MACs against a known identity key. The Snowflake WebRTC data-channel
media path is likewise out of scope (broker rendezvous messages only).

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
5. The obfs4 ntor `AUTH` verification (Elligator 2 + X25519 + ntor) remains
   unimplemented — it is the obfs4 probe's documented handshake gap — and the
   agent's non-TCP probe kinds (obfs4/WebTunnel/traceroute) are explicit 422
   skip-and-record rather than implemented. (All eleven Phase-1 workspace
   crates are now gated green.)
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
3. Materialize `schemas/*.schema.json` in the repo via `cargo xtask schema-gen`
   and wire them into CI validation (Phase 9). The obfs4 Elligator 2 + X25519
   + ntor key establishment (server `AUTH` verification) is a separate
   cryptographic follow-up that would unblock full obfs4 server
   authentication; the agent's non-TCP probe kinds follow the same path.
4. Phase 8 automation + `Dockerfile`; Phase 9 `proptest`/fuzz/deny gates;
   `schemas/` JSON Schema validation in CI.
5. `docs/`: `SCORING.md` (documenting the `tbc-score` formula), `THREAT_MODEL.md`,
   `OPSEC.md`, `RUNBOOK.md`, `CONTRIBUTING.md`, `ARCHITECTURE.md`, and the
   bilingual README.

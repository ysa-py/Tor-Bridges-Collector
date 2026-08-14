# GAP ANALYSIS — TorShield-IR vs. Enterprise Upgrade Master Spec

**Phase 0 deliverable.** Maps the current repository against the 10-phase
master spec and produces an honest 9.8 → 10.0 scorecard. Status per phase is
one of `DONE` (present and verified), `PARTIAL` (present, incomplete), `OPEN`
(missing), or `BLOCKED` (present but unverifiable here for an external reason).

> The master spec itself demands: *"If something genuinely cannot work in this
> environment, say so explicitly … do not fake it and do not stub it."* The
> `BLOCKED` rows below are that statement, with the technical reason.

---

## Scorecard

| Phase | Required capability | Current state | Score (9.8→10.0) | Status |
|---|---|---|---|---|
| 0 | Forensic audit | Root-level `AUDIT_FINDINGS.md`, `ARCHITECTURE_GAPS.md`, `MISSING_FEATURES.md` exist; this pass adds `docs/{FEATURE_INVENTORY,AUDIT,GAP_ANALYSIS}.md` | 9.8 → 9.9 | PARTIAL |
| 1 | `crates/*` workspace (core/store/sources/transports/prober/vantage/score/publish/agent/cli/xtask) | Flat single crate + `bridge-probe`; no `sqlx`/`figment`/`proptest`/`ed25519-dalek`/`futures` | 9.8 → 9.8 | OPEN |
| 2 | Typed data model (`TransportKind`, `BridgeLine`, `Observation`, `BridgeScore`) with schema versioning | Partial domain types exist (transport enums, bridge parsing, scoring structs) but no unified serde model, no versioned JSON Schema | 9.8 → 9.8 | PARTIAL |
| 3 | Pluggable `trait Source` collectors + rate limit/backoff/ETag/provenance | Multiple collectors + circuit breakers + retry exist, but not behind one `trait Source` with provenance/history retention | 9.8 → 9.85 | PARTIAL |
| 4 | Real handshake prober (obfs4/WebTunnel/vanilla/Snowflake) + real Tor bootstrap + evasion A/B | WebTunnel probing + TCP/TLS exist; obfs4 handshake needs external relay secrets; real bootstrap needs `tor` binary | 9.8 → 9.8 | PARTIAL/BLOCKED |
| 5 | 4 in-country adapters (OONI, RIPE Atlas, Globalping, volunteer agent) with budget guards + k-anonymity | OONI correlator module/binary exist; RIPE Atlas & Globalping & signed volunteer agent are **absent** | 9.8 → 9.8 | OPEN |
| 6 | Deterministic scoring + freshness decay + burn rate + tiering + `docs/SCORING.md` | Scoring/fusion/reputation/burn modules exist; no `docs/SCORING.md`, tiers not config-threshold-driven in one place | 9.8 → 9.85 | PARTIAL |
| 7 | Additive outputs (per-transport, tier-split, per-ASN, `all.json`, subscriptions, torrc, feeds, status page, schemas, signing) | 55-file `bridge/` contract + ZIP + manifest exist; `schemas/`, per-ASN splits, feeds, status page, signing are **absent** | 9.8 → 9.85 | PARTIAL |
| 8 | GHA workflows (collect 30–60 m, probe 1–3 h sharded, vantage hourly, score+publish, nightly deep verify, weekly audit, watchdog) + multi-arch Docker | 6 workflows (3 h / 6 h cadence); no sharded probe matrix, nightly deep verify, watchdog, or `Dockerfile` | 9.8 → 9.8 | OPEN |
| 9 | Quality gates (fmt/clippy/test/deny/audit), proptest, fuzz, real integration tests, observability + `RUNBOOK.md` | Recorded green fmt/clippy/test + smoke suites exist; `proptest`/fuzz/`cargo-deny`/bridge-container integration tests and `RUNBOOK.md` **absent** | 9.8 → 9.85 | PARTIAL |
| 10 | Security/privacy/OPSEC docs (`THREAT_MODEL.md`, `OPSEC.md`, `CONTRIBUTING.md`, bilingual README) | Root security docs + `README.md` + `README_FA.md` exist; `THREAT_MODEL.md`/`OPSEC.md`/`CONTRIBUTING.md` in `docs/` **absent** | 9.8 → 9.85 | PARTIAL |

**Bottom line:** the existing repo already implements a large fraction of the
*semantics* (collection, probing, scoring, publication, self-healing), which is
why it self-reports 9.8/10. The deltas to 10.0 are almost entirely **additive
engineering surface**: the crate split, the unified typed model + JSON Schema,
the `trait Source` abstraction, the real handshake prober with bootstrap
ground truth, the three missing vantage adapters + volunteer agent, the
scheduler/Docker/`xtask` layer, and the `proptest`/fuzz/deny gates.

---

## Risk analysis (why the remaining 0.2 is the hard 0.2)

1. **Real-network truth** (Phase 4/5) cannot be established from this sandbox:
   no `tor` binary, no obfs4 relay secrets, no RIPE Atlas/Globalping credentials.
   Handshake correctness must be proven on real CI with real bridge containers —
   it cannot be honestly claimed from static code alone.
2. **Regression risk** (Phase 1/2/6/7): ~66,900 lines with 1,311 recorded
   passing tests and a byte-exact publication contract. Reorganising into
   `crates/*` or re-deriving the scoring formula risks subtle output drift; any
   such change must be gated by the existing parity suite and the byte-compare
   publisher.
3. **Ethics/OPSEC** (Phase 5d, 10): in-country handshake probing is itself a
   censorship feedback risk. The k-anonymity gate, rate limits, and sampling
   must be implemented *and* documented, or the "10/10" claim becomes a
   harm-amplifier.
4. **The 879 `unwrap`/`expect` sites** (AUDIT A1): a full sweep is safe only
   with per-module parity tests; doing it blind risks breaking the exact
   compatibility the spec mandates.

---

## Exact deltas to implement (in dependency order)

1. `docs/` completion: `SCORING.md`, `THREAT_MODEL.md`, `OPSEC.md`,
   `RUNBOOK.md`, `CONTRIBUTING.md` (+ already-added `FEATURE_INVENTORY`,
   `AUDIT`, `GAP_ANALYSIS`).
2. `crates/core` + `crates/store`: unified serde model (Phase 2 types),
   `thiserror` taxonomy, `figment` config, `tracing` JSON layer, SQLite via
   `sqlx` + migrations, deterministic JSON export. Shims keep existing
   `src/` entry points working.
3. `crates/sources`: `trait Source` behind which existing collectors run.
4. `crates/prober` + `crates/transports`: obfs4/WebTunnel/vanilla handshakes
   + real bootstrap sampling; wire the existing relay path.
5. `crates/vantage` + `crates/agent`: OONI (wire existing correlator), RIPE
   Atlas + budget manager, Globalping, signed volunteer agent + Worker.
6. `crates/score`: consolidate scoring with config thresholds + fixtures +
   `docs/SCORING.md` worked examples.
7. `crates/publish` + `schemas/`: additive outputs, versioned JSON Schema,
   atomic writes, signing, checksums.
8. `crates/cli` (`tbc`) + `xtask`: subcommand surface + build/release/schema-gen.
9. Automation: Phase 8 workflows + multi-arch `Dockerfile`.
10. Zero-error sweep: A1 `unwrap`/`expect` removal, `proptest`, fuzz targets,
    `cargo-deny`/`cargo-audit`, integration-test bridge containers.

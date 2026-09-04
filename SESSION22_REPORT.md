# SESSION 22 — Phantom-Artifact Elimination (PQ bridge scores + NIN recommended transport)

**Date:** 2026-09-03 · **Branch:** `arena/01a069ab-tor-bridges-collector`
**Tooling:** offline sandbox — bash + Python 3.11 stdlib (no Rust/Go toolchain, no egress)
**Prime directive honoured:** nothing removed — `git diff --diff-filter=D` is empty.

---

## 1. What the microscope found

Every artifact the `bridge-intelligence-report` upload block advertises was
cross-checked against actual producers:

| Advertised artifact | Producer | Result |
|---|---|---|
| 42 of 45 listed artifacts | real stages | ✅ |
| `data/pq_bridge_scores.json` | **none anywhere** | ❌ phantom — silently never uploaded |
| `export/nin_recommended_transport.json` | **none anywhere** | ❌ phantom — silently never uploaded |
| `diagnostics/torshield_ir_self_heal.json` | Stage 00 (runtime, fresh per run) | ✅ not a defect |

Why silent: the upload step uses `if-no-files-found: ignore`, so a missing file
produces no error — the exact silent-failure class this project's
self-healing/pipeline-diagnostics work exists to eliminate.

## 2. Fix — additive, fully automatic (Stage 8t)

Both artifacts now have deterministic Rust-free producers wired into
`.github/workflows/torshield-ir.yml` as **Stage 8t** (after Stage 8s, before
Stage 9 — every input report exists by then). Both are recomputed from the
run's own data every run; both are advisory (runner-side evidence).

### `data/pq_bridge_scores.json` — `scripts/build_pq_bridge_scores.sh`
- Stage 8e scores post-quantum safety **per transport**
  (`data/quantum_safe_report.json` → `quantum_safe_scores`, 6 transports).
- Stage 8i (`data/anti_ai_dpi_report.json`) provides the whole 1,596-bridge
  pool with canonical transport.
- Every bridge inherits its transport's PQ score → ranked manifest
  `(pq_score desc, bridge_line asc)`.
- Committed result: **1,596/1,596 bridges scored** (top: CDN-fronted
  webtunnel/conjure family `pq=0.85`).

### `export/nin_recommended_transport.json` — `scripts/build_nin_recommended_transport.sh`
- Per-regime recommendations (normal / degraded / **full internet cut**) with
  rationale and an evidence-based primary.
- Transport pool statistics over the probe-survivable set
  (`nin_cut_survivable.txt`, Stage 8k) and strict NIN-eligible set
  (`nin_eligible.json`, Stage 8d).
- Full-cut primary is **evidence-derived, not hard-coded**: this run's
  survivable pool is 294 obfs4 + 1 vanilla → primary **obfs4**, with top-10
  copy-paste candidates included.

### Two generator bugs caught by the audit before commit
1. `nin_eligible.json` (JSON `[]`) was text-scanned → became a bogus bridge
   line classified `unknown`. JSON sources now parsed as JSON arrays.
2. Tie-breaks used Python set iteration (nondeterministic across processes via
   hash randomization) → now alphabetical, byte-deterministic.

## 3. Invariant audit extended

| Check | Scope |
|---|---|
| C12 `pq-scores-freshness` | committed `data/pq_bridge_scores.json` == fresh regeneration (timestamp excluded) |
| C13 `nin-recommended-freshness` | committed `export/nin_recommended_transport.json` == fresh regeneration (timestamp excluded) |

## 4. Verification (real output)

```
$ bash scripts/verify_repo_invariants.sh
  C1..C11 … (all PASS as before)
  [PASS] C12 pq-scores-freshness
  [PASS] C13 nin-recommended-freshness
═══ 13/13 checks passed ═══            exit 0

$ bash scripts/build_pq_bridge_scores.sh
  scored 1596 bridges from 6 transport PQ scores

$ bash scripts/build_nin_recommended_transport.sh
  survivable pool: 295 lines ({'vanilla': 1, 'obfs4': 294})
  full-cut primary: obfs4
```

Regeneration byte-determinism proven (two runs identical after timestamp
removal); workflow edits re-validated (no tabs, embedded `run: |` blocks all
`bash -n` clean); no Rust source touched.

## 5. Honest notes
- 3 of 1,596 entries carry a producer-side transport label that differs from
  the line prefix (conjure/meek_lite tagged `webtunnel` by Stage 8i). The
  manifest is faithful to the run's own signals; relabelling would diverge
  from the other consumers (elite fusion, SIAM) that use the same field.
- First real execution of Stage 8t happens on the next GitHub Actions run
  after this branch is pushed (owner-side push — GAP-6, unchanged).

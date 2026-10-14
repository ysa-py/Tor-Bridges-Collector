# Engineering Prompt — TorShield-IR Zero-Error Rust Migration & CI Hardening

> Reusable, model-agnostic engineering directive. Paste into any coding agent
> (Claude, GPT, Gemini, Grok, Qwen, Kimi, …) working in this repository.
> Authored 2026-07-30. Embodies the verification-first discipline actually used
> to close incident #73.

---

## 0. Operating principles (non-negotiable)

1. **Verify before you act.** Every claim in a task brief (patch files, PR
   numbers, "files were dropped", "X still broken") MUST be checked against the
   real repository state with `git`, `gh`, `grep`, and file reads before any
   change. If the brief contradicts reality, **say so explicitly** and proceed
   against reality — never against an unverified narrative.
2. **Zero deletions of capability.** Fix errors; do not remove features, modules,
   jobs, or files to make tests pass. "Green by deletion" is forbidden.
3. **Additive, surgical edits.** Prefer guarding (`if:` conditions,
   `continue-on-error`, `|| true`) over rewriting. Every change must map 1:1 to a
   named, verifiable failure mode.
4. **Test for real, then document the limit.** Run every check the sandbox
   permits. If a toolchain is unavailable (e.g. egress-restricted), state exactly
   what could not run and why — never imply a green you did not observe.
5. **Branch discipline.** Commit and push only to the assigned session branch.
   Never `git checkout main`, never push to `main`, never force-push.

## 1. Objective

Deliver a **zero-error** state for the TorShield-IR bridge-collector:

- Complete and lock the **Python → Rust** migration (source of truth: the Rust
  workspace at repo root + `bridge-probe/` + `rust/`).
- Make **every GitHub Actions workflow** resolve, parse, and pass — with **no
  hardcoded `powershell`/`pwsh` on Linux runners** (root cause of incident #73 /
  Exit 127) and **no dead `setup-python`/`pip`/`*.py` steps** on the active path.
- Preserve and document the **intelligent Iran anti-censorship / anti-DPI**
  capability (it already exists in the Rust core — see MIGRATION_STATUS.md §11.6).

## 2. Definition of done

- [ ] `python3 scripts/validate_workflows.py` → **0 violations** across all
      `.github/workflows/*.yml`.
- [ ] Every workflow parses as valid YAML (PyYAML / `yamllint`).
- [ ] Every `*.sh` passes `bash -n` (and `shellcheck -S warning` where available).
- [ ] Zero hardcoded `powershell` command invocations on any Linux runner.
- [ ] Zero invalid GitHub Action tags (every `uses: …@vN` resolves to a real
      release; verify each major version against the action's releases/tags).
- [ ] Dead-Python jobs either removed-from-the-active-path via
      `if: hashFiles('**/*.py') != ''` (auto-reactivating) or converted to a
      Rust equivalent. **Never simply deleted.**
- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
      -D warnings`, `cargo test --workspace` all PASS (or, if unrunnable
      offline, carried forward from a real CI run and flagged).
- [ ] `go build ./... && go vet ./... && go test ./...` PASS (same caveat).
- [ ] `MIGRATION_STATUS.md` updated with a dated, honest section: what changed,
      test results, and what could not be verified locally.
- [ ] Changes committed **only** to the session branch and pushed there.

## 3. Required procedure

1. **Inspect.** `git status`, `git log --oneline -5`, `gh pr list --state all`,
   `ls .github/workflows/`, `find . -name '*.py'`, `grep -rn powershell .github/`.
   Record what is actually true.
2. **Fix the incident.** `self-heal.yml` must drive diagnostics through
   `bash scripts/self_heal.sh` (POSIX port of `self_heal.ps1`), with an explicit
   Rust toolchain step and `cargo-audit` installed. No `powershell` anywhere.
3. **Normalize action tags.** Audit `uses:` lines; pin each to a real major
   version. Known-good as of 2026-07: `checkout@v4|v5`, `setup-python@v6`,
   `setup-go@v6`, `upload-artifact@v6`, `download-artifact@v4|v5`, `cache@v4`,
   `github-script@v8`, `Swatinem/rust-cache@v2`, `dtolnay/rust-toolchain@stable`,
   `cargo-bins/cargo-binstall@main`. **`download-artifact@v8` and `cache@v6` do
   not exist** — must be downgraded.
4. **Guard dead Python.** For any job/step that imports or runs deleted Python,
   add `if: hashFiles('**/*.py') != ''`. For mixed jobs (Python + Go + Rust in
   one `run:` block), split the block so Go/Rust keep executing.
5. **Test.** Run `scripts/validate_workflows.py`, YAML parse, `bash -n`, the
   validator's self-test, and (if available) cargo/go/zig. Save the log under
   `diagnostics/`.
6. **Document.** Append a section to `MIGRATION_STATUS.md` with a claim-vs-reality
   table, a change list, the test matrix, and an explicit "could not run here"
   list with reasons.
7. **Ship.** Commit with a `fix(ci): …` message; push to the session branch only.
   Do not merge to `main` from the agent.

## 4. Hard constraints

- Do **not** `git checkout main` / `git push origin main`.
- Do **not** apply a patch file whose existence you have not confirmed.
- Do **not** delete `.py` files to "complete the migration" — confirm the count
  first; if already 0, there is nothing to delete.
- Do **not** add uncompiled Rust/Go/Zig code and call the tree "zero-error".
- Do **not** echo back unverified incident narratives as if they were facts.

## 5. Deliverables

1. The fixed workflow files (`self-heal.yml`, `ci.yml`, `autonomous-sentinel.yml`,
   `torshield-ir.yml`, and any other touched).
2. `scripts/validate_workflows.py` (the policy gate) + its self-test evidence.
3. A diagnostics log under `diagnostics/`.
4. Updated `MIGRATION_STATUS.md` (new dated section; prior content preserved).
5. A single commit on the session branch, pushed.

## 6. Success criterion

> The next GitHub Actions run on the merged result is **all-green**, achieved by
> removing failure modes — never by removing features.

---

## 7. Addendum — directive v43 (2026-10-15): tiered evidence & honest empties

Extends the zero-error discipline to the evidence contract itself. These rules
are binding for every future session touching `bridge_publication.rs`,
`evidence_stamp.rs`, `pipeline_diagnostics.rs`, or the relay canary:

1. **Evidence tiers are ordered and labeled.** `relay-verified >
   runner TCP/TLS-verified > capability-only > unverified`, stored per record
   in `iran_results.json` (`verification.stage`, `test_tier`, `test_result`).
   `*_tested.txt` / `tested_global_*` admit runner TCP/TLS-or-better typed
   evidence with the strongest tier first; `iran_likely_working_*` ranks
   OONI-measured > S2+ handshake > runner TCP/TLS. A lower tier is never
   presented as a higher one — the manifest records each file's
   `evidence_tier` and the per-record tier stays in the JSON.
2. **Every empty file must explain itself.** No empty evidence projection may
   ship without a `reason_code` in `telegram_manifest.json`
   (`NO_UPSTREAM_SUPPLY`, `NO_IPV6_SUPPLY`, `NO_FRESH_WITHIN_WINDOW`,
   `NO_EVIDENCE`, `RELAY_DOWN`). Filling files with invented rows remains
   forbidden; the tiered admission is the only honest way they fill.
3. **Run-window evidence.** An hourly run's own observations are current for
   the whole run: `TBC_RUN_FLOOR` (job output of the collection step) bounds
   the evidence window at publish time. The bare 10-minute rule must never
   silently discard a run's own typed evidence again.
4. **Classifier discipline.** The whole-run diagnostics classifier is
   annotation-first: only emitted `::error::`/`##[error]` annotations, the
   runner's fatal exit line, real panic forms, failing cargo/test summaries,
   and digest mismatches are Errors. By-design skips, low-yield verdicts,
   exit-code retries, and HTTP status echoes are warnings or noise. A green
   run must classify `errors=0`; the fixtures from runs 38613981417 /
   38616637805 are regression tests.
5. **Canary contract.** The relay canary proves honest dialing (silent-live
   connects, closed-port reports a typed negative, every target correlated
   with fresh timestamps and matching stats). A recovered control honestly
   reported as connected is not a failure. After a deploy, wait (bounded)
   for the edge to report the deployed SHA before canarying.
6. **Direct measurement beats inference.** Front/domain liveness claims
   require a real dial of the measured target with error-kind classification;
   environment-level failures (`NetworkUnreachable`, missing route, DNS) are
   `unknown`, never "confirmed unreachable".
7. **Verify past the push.** Publication is not done until the raw CDN serves
   the verified bytes: Stage 11c re-downloads the manifest + every payload
   file and byte-compares SHA-256s, fail-closed.
8. **Freshness SLA.** A published snapshot older than 3 hours at publication
   time is an `::error::` (Stage 9c), not a silent coalesce.

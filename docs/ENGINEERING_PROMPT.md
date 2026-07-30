# Engineering Prompt — Zero-Error Python→Rust Migration & GitHub Actions Modernisation

> Reusable, tool-agnostic specification for driving a repository to a
> **fully Rust-native, zero-error** state with **green GitHub Actions**.
> Written to be handed directly to an autonomous coding agent.

---

## ROLE

You are a senior systems engineer operating autonomously inside a real Git
checkout. You own the outcome end-to-end: investigate, implement, **actually
execute** the verification, fix what you find, and report honestly.

---

## PRIME DIRECTIVES

1. **Zero errors.** Every language in the repository must build, lint and test
   clean. "Zero errors" means *observed green from a real execution*, never
   inferred from reading code.
2. **Zero capability loss.** You may *replace* an implementation, never *drop*
   a feature. If a Python module is deleted, an equivalent Rust entry point
   must exist and be reachable from CI. Deleting a broken step is only
   acceptable when you have first proved it is a no-op.
3. **Zero silent failure.** Never mask a failure with `|| true`, a blanket
   `continue-on-error`, or a suppression pragma to make a gate pass. If
   tolerance is genuinely correct, add a comment explaining why.
4. **Report what you did not do.** An honest gap is worth more than a false
   claim of success. Blocked work must be listed with the exact reason and the
   exact command needed to finish it.

---

## PHASE 0 — RECONNAISSANCE (do this before changing anything)

Build a factual inventory. Do not trust existing status documents; verify.

```bash
# Language census — the ground truth
for ext in py rs go sh zig ps1 yml yaml; do
  printf '%-6s %s\n' "$ext" "$(find . -name "*.$ext" -not -path './.git/*' \
    -not -path './target/*' | wc -l)"
done

# CI reality check
gh run list --limit 20
gh workflow list
```

For **each failing run**, obtain the root cause. When `gh run view --log-failed`
is unavailable, fall back to the annotations API, which usually still works:

```bash
gh run view <RUN_ID>                     # per-step pass/fail
gh api /repos/<OWNER>/<REPO>/check-runs/<JOB_ID>/annotations \
  --jq '.[] | .annotation_level + ": " + .message'
```

**Then cross-reference code against CI.** The highest-value bug class in a
partially-completed migration is *a workflow that references files which no
longer exist*:

```bash
# Every path a workflow tries to execute
grep -rhoE '(python3?|bash|sh) +[a-zA-Z0-9_./-]+\.(py|sh)' .github/workflows/ \
  | awk '{print $2}' | sort -u | while read -r f; do
      [ -e "$f" ] || echo "DANGLING REFERENCE: $f"
    done
```

**Deliverable:** a table of every failing job, its root cause, and the
file/line responsible.

---

## PHASE 1 — CLASSIFY EVERY FAILURE

Assign each failure to exactly one class; the class dictates the fix.

| Class | Signature | Correct fix |
|---|---|---|
| **Missing binary** | `exit 127`, `command not found` | Remove the dependency, or install it correctly and **verify it is on `PATH` in the same step** |
| **Platform mismatch** | Windows tooling on a Linux runner | Rewrite in POSIX; keep the platform-specific script for its own platform |
| **Dangling reference** | `can't open file`, `ModuleNotFoundError` | Point at the surviving implementation |
| **Dead gate** | A job that lints/tests zero files | Replace with an invariant guard that fails if the condition regresses |
| **Genuine defect** | Compiler/linter diagnostic | Fix the code; never suppress |

### Two exit-127 traps to look for specifically

**Trap 1 — `powershell` on Linux.** `ubuntu-latest` has no `powershell`; even
PowerShell Core is `pwsh`. Any inline `powershell` call from `shell: bash`
fails 127 on 100 % of runs.

```yaml
# WRONG — exit 127 on every run
- run: powershell -NoProfile -Command "Test-Path .\\scripts\\x.ps1"

# RIGHT — POSIX check, then a dispatcher that prefers a portable runner
- name: Ensure self-heal script is present
  shell: bash
  run: |
    set -euo pipefail
    if [ ! -f ./scripts/self_heal.ps1 ] && [ ! -f ./scripts/self_heal.sh ]; then
      echo "::error::Missing self-heal scripts"
      exit 1
    fi

- name: Run diagnostics (cross-platform dispatcher)
  shell: bash
  run: |
    set -uo pipefail
    if command -v cargo >/dev/null 2>&1 && [ -f ./src/bin/self_heal.rs ]; then
      cargo run --quiet --bin self_heal -- --heal
    elif [ -f ./scripts/self_heal.sh ]; then
      bash ./scripts/self_heal.sh
    elif command -v pwsh >/dev/null 2>&1; then
      pwsh -NoProfile -File ./scripts/self_heal.ps1
    else
      echo "::error::No usable runner on this platform"; exit 1
    fi
```

**Trap 2 — installer succeeds, binary is absent.** `cargo binstall cross -y`
can report success while `cross` never lands on `PATH`. Prefer removing the
dependency over debugging the installer: `cargo check` never invokes the
linker, so cross-compilation verification needs only the target's std.

```yaml
# WRONG — 'cross: command not found'
- run: cargo binstall cross -y
- run: cross check --target armv7-unknown-linux-musleabihf --workspace --release

# RIGHT — no cross, no Docker, no C toolchain; broader coverage
- run: rustup target add armv7-unknown-linux-musleabihf
- run: cargo check --target armv7-unknown-linux-musleabihf \
         --workspace --all-targets --release
```

---

## PHASE 2 — COMPLETE THE MIGRATION

### 2.1 Build the mapping table first

Before writing code, enumerate **every** retired entry point and name its
replacement. Commit this table as a comment in the workflow that used to call
them — it is the artefact that proves no capability was dropped.

```
python self_heal.py --heal        -> bin/self_heal
python scraper.py                 -> bin/scraper
python main.py --mode score       -> bin/bridge_intelligence
python ml_predictor.py --train    -> pipeline --stage ml
python ja3_intelligence.py --rotate -> pipeline --stage ja3
...
```

### 2.2 Prefer one orchestrator over N shims

Replacing 30 `python x.py` steps with 30 tiny Rust binaries multiplies build
time and surface area. Write **one** orchestrator binary with a `--stage` flag.

Non-negotiable properties:

- **`--list`** — enumerate stages (makes the contract testable).
- **Per-stage resilience** — a stage whose optional input is missing records
  `skipped` *with a reason*; it does not abort the run. This reproduces the
  old per-step `continue-on-error: true` semantics.
- **An explicit `REQUIRED` set** — only these propagate a non-zero exit.
- **A machine-readable report** — `{summary:{ok,skipped,failed}, stages:[...]}`.
  CI asserts `summary.failed == 0`; humans read per-stage detail.

```rust
enum Outcome { Ok(Value), Skipped(String) }
type StageResult = Result<Outcome, Box<dyn Error>>;

// Ok(Ok)      -> stage succeeded
// Ok(Skipped) -> input absent; recorded, not fatal
// Err         -> real failure; fatal only if the stage is in REQUIRED
```

### 2.3 Replace inline interpreter scripts with shell-native tooling

Workflows commonly embed `python - <<'EOF'` heredocs. These are the last hidden
runtime dependency. `jq` and `yamllint` are preinstalled or one `pip install`
away and remove the dependency entirely.

```yaml
# BEFORE — needs a Python runtime and a deleted module
- run: |
    cat > /tmp/_summary.py <<'EOF'
    import json; d = json.load(open("data/report.json")); print(d["status"])
    EOF
    python3 /tmp/_summary.py

# AFTER — no runtime dependency
- run: jq -r '.status' data/report.json
```

### 2.4 Convert dead gates into invariant guards

A job that `py_compile`s zero files provides no signal. Convert it into a guard
that *fails if the migration regresses*:

```yaml
- name: Migration invariant — zero Python sources
  shell: bash
  run: |
    set -euo pipefail
    mapfile -t found < <(
      find . -name '*.py' -not -path './.git/*' \
        -not -path './target/*' -not -path './vendor/*' -print
    )
    if [ "${#found[@]}" -gt 0 ]; then
      printf '::error::Python file reintroduced: %s\n' "${found[@]}"
      exit 1
    fi
    echo "OK — 0 Python source files"
```

---

## PHASE 3 — VERIFY FOR REAL (the phase agents most often skip)

**Rule: a check you did not execute is a check that failed.** Reading code is
not verification.

### 3.1 Run every language's real toolchain

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --bins
cargo check --target <cross-target> --workspace --all-targets --release

# Go
go build ./... && go vet ./... && go test ./...

# Zig
(cd <zig-dir> && zig build)

# Shell
find . -name '*.sh' -not -path './.git/*' -print0 \
  | xargs -0 -r shellcheck -S warning
find . -name '*.sh' -not -path './.git/*' -exec bash -n {} \;

# YAML + GitHub Actions
yamllint -c .yamllint .github/
actionlint
```

### 3.2 When a toolchain is unavailable, obtain it — do not assume

Restricted sandboxes commonly block `static.rust-lang.org`, `crates.io`,
`proxy.golang.org` and GitHub release assets while still allowing PyPI and npm.
Probe first, then exploit whatever registry is reachable:

```bash
for h in static.rust-lang.org index.crates.io proxy.golang.org \
         files.pythonhosted.org registry.npmjs.org github.com; do
  printf '%-28s ' "$h"
  curl -sS -o /dev/null -w '%{http_code}\n' --max-time 8 "https://$h"
done
```

Registry-hopping recipes that work when the official channel is blocked:

| Need | Fallback that usually works |
|---|---|
| Rust toolchain | npm `@rustbin/{rustc,cargo,rustfmt,clippy,rust-std}-<ver>-x86_64-unknown-linux-gnu` — real binaries, assemble into one prefix |
| Go toolchain | PyPI `go-bin` |
| Zig | PyPI `ziglang` (**pin the version** — `build.zig` APIs break across releases) |
| shellcheck | PyPI `shellcheck-py` |
| yamllint | PyPI `yamllint` |
| actionlint | `git clone` + `go build`; if the module proxy is blocked, use `GOPROXY=direct` plus `go mod edit -replace golang.org/x/sys=github.com/golang/sys@<ver>` |

### 3.3 When execution is genuinely impossible, use CI as the compiler

If crate downloads are blocked, do **not** guess. Push a code-only commit and
read the real result from a runner:

```bash
git push origin <branch>
gh run view <RUN_ID> --json jobs \
  --jq '.jobs[] | select(.name|test("<job>")) | .steps[]
        | .name + " :: " + (.conclusion // "-")'
```

This is a legitimate verification loop: it is a real compiler on real hardware.
Cite the run ID in your report.

### 3.4 Compilation is not execution — add runtime tests

`clippy` proves a binary *compiles*. It does not prove it *runs*. For every new
binary, add an integration test that executes it in an isolated scratch
directory (Cargo exports `CARGO_BIN_EXE_<name>`):

```rust
#[test]
fn pipeline_runs_all_stages_without_failure() {
    let dir = scratch("all");                 // temp dir, seeded inputs
    let out = Command::new(env!("CARGO_BIN_EXE_pipeline"))
        .current_dir(&dir)
        .args(["--all", "--report", "data/pipeline_report.json"])
        .output().unwrap();
    assert!(out.status.success(), "stderr:\n{}",
            String::from_utf8_lossy(&out.stderr));

    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("data/pipeline_report.json")).unwrap()
    ).unwrap();
    assert_eq!(report["summary"]["failed"], 0);
}
```

Also test the **failure** path (e.g. required file absent ⇒ non-zero exit).
A test suite that only covers the happy path cannot detect silent degradation.

---

## PHASE 4 — HYGIENE

- Bump deprecated actions (`actions/checkout@v4` → `@v5`) to clear runner
  deprecation warnings.
- **Delete stale documentation banners.** A `# DORMANT — CI X is primary`
  header that names a directory which no longer exists actively harms the
  project: it trains maintainers to ignore red badges. Verify before trusting
  any in-repo status claim.
- Add generated artefacts to `.gitignore` (`target/`, `.zig-cache/`,
  `zig-out/`, `node_modules/`) — never commit build output.
- Resolve every linter finding, including informational ones
  (`SC2086` unquoted expansion, `SC2044` `for` over `find`).

---

## PHASE 5 — REPORT

Produce a status document with these sections:

1. **Executive summary** — before/after table.
2. **Incident analysis** — for each failure: symptom, root cause, fix, with the
   before/after snippet.
3. **Mapping table** — every retired entry point → its replacement.
4. **Test results** — the exact command and the observed result. Separate
   *locally executed* from *CI-executed* and cite run IDs.
5. **Capability inventory** — proof nothing was lost.
6. **What was NOT done** — blocked work, the exact blocker, and the exact
   command to finish it.
7. **Verification commands** — copy-pasteable reproduction.

### Handling a permissions block

A GitHub App without the `workflows` permission cannot push
`.github/workflows/**` — via `git push` *or* the Contents API. Do not silently
drop the work. Instead:

1. Commit the workflow changes on the branch anyway (complete and linted).
2. Push everything else by cherry-picking the non-workflow files onto a
   temporary branch and pushing that to the session branch.
3. Verify the diff between local and remote is **workflow files only**.
4. Document the exact unblocking command.

```bash
# Push non-workflow work
git checkout -B tmp-nonwf <base-sha>
git checkout <branch> -- <non-workflow paths...>
git commit -m "..." && git push -f origin tmp-nonwf:refs/heads/<branch>

# Prove the remaining delta is workflows only
git diff --stat tmp-nonwf <branch>
```

---

## ACCEPTANCE CRITERIA

- [ ] Every previously failing job has a documented root cause and fix.
- [ ] `find . -name '*.py'` returns 0 **and** an invariant guard enforces it.
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`
      all pass — **observed**, not assumed.
- [ ] `go build/vet/test` pass; `zig build` passes.
- [ ] `shellcheck -S warning`, `bash -n`, `yamllint`, `actionlint`: 0 findings.
- [ ] Every new binary has a runtime test covering success **and** failure.
- [ ] No workflow references a non-existent file.
- [ ] No `|| true` / `continue-on-error` added to hide a real failure.
- [ ] Zero capabilities removed; mapping table committed.
- [ ] The status document lists blocked work with exact unblocking commands.

---

## ANTI-PATTERNS — AUTOMATIC FAILURE

| Anti-pattern | Why it fails |
|---|---|
| "Tests should pass" without running them | Unverified claims are the primary defect source |
| `|| true` on a failing step | Converts a loud failure into silent degradation |
| Deleting a step because it fails | Capability loss disguised as a fix |
| `#![allow(warnings)]` / blanket suppressions | Hides the defect the gate exists to catch |
| Trusting an in-repo status doc | Docs drift; only executed commands are evidence |
| Reporting success while work is blocked | Destroys trust and hides required follow-up |
| Committing build artefacts | Bloats history, breaks reproducibility |
| One shim binary per retired script | Multiplies build time and maintenance surface |

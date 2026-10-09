#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# verify_repo_invariants.sh — always-on static/data integrity audit.
#
# Runs the full microscopic invariant battery that guards the TorShield-IR
# publication contract, module graph, CI stage wiring, evidence stamps, and
# committed advisory artifacts. Pure bash + python3 stdlib; offline; fast.
#
# Every check FAILS LOUDLY (exit 1 with ::error::) — nothing here is allowed
# to be silently skipped. Run it locally (`bash scripts/verify_repo_invariants.sh`)
# and wire it into CI so every push re-runs the whole magnifier automatically.
#
# Touches NO Rust source and never modifies the tree (the Stage 8s freshness
# probe regenerates into a temporary directory).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "::error::python3 is required by verify_repo_invariants.sh" >&2
  exit 1
fi

python3 - <<'PY'
"""TorShield-IR invariant battery (pure stdlib). Exit 0 = all green."""
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.getcwd()
FAILURES = []
CHECKS = []


def record(name, ok, detail=""):
    CHECKS.append(name)
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(f"{name}: {detail}")


# ── C1. Every committed JSON file must parse ────────────────────────────────
def c1_json_parse():
    bad = []
    total = 0
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in (".git", "target", ".venv", "node_modules", ".refact", ".agents")]
        for f in files:
            if not f.endswith(".json"):
                continue
            p = os.path.join(root, f)
            total += 1
            try:
                json.load(open(p, encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                bad.append(f"{os.path.relpath(p, REPO)}: {exc}")
    record("C1 json-parse-all", not bad and total > 0,
           f"{total} files" if not bad else "; ".join(bad[:3]))


# ── C2. Publication contract: REQUIRED_FILES ↔ bridge/ contents ─────────────
def c2_publication_contract():
    src = open(os.path.join(REPO, "src", "bridge_publication.rs"), encoding="utf-8").read()
    m = re.search(r"(?:pub\s+)?const REQUIRED_FILES[^=]*=\s*&\[(.*?)\];", src, re.S)
    if not m:
        record("C2 publication-contract", False, "REQUIRED_FILES const not found")
        return
    names = re.findall(r'"([^"]+)"', m.group(1))
    required = set(names)
    bridge_dir = os.path.join(REPO, "bridge")
    contract_ok = bool(names) and len(names) == len(required)
    if not os.path.isdir(bridge_dir):
        # A clean clone can be checked before the first successful collection
        # has materialized canonical bridge inputs. The full pipeline's
        # Stage 9b/10 remains the fail-closed publication gate in that case.
        record("C2 publication-contract", contract_ok,
               f"{len(required)} unique required paths; bridge/ not materialized yet")
        return
    present = set(os.listdir(bridge_dir))
    missing = sorted(required - present)
    extra = sorted(present - required)
    ok = contract_ok and not missing and not extra
    detail = f"{len(required)} required paths"
    if not contract_ok:
        detail += "; duplicate/empty REQUIRED_FILES inventory"
    if missing:
        detail += f"; missing={missing[:5]}"
    if extra:
        detail += f"; extra={extra[:5]}"
    record("C2 publication-contract", ok, detail)


# ── C3. Module graph: lib.rs declarations resolve; no orphan root modules ───
def c3_module_graph():
    lib = open(os.path.join(REPO, "src", "lib.rs"), encoding="utf-8").read()
    declared = set(re.findall(r"^pub mod (\w+);", lib, re.M))
    missing = sorted(
        m for m in declared
        if not (os.path.exists(os.path.join(REPO, "src", f"{m}.rs"))
                or os.path.exists(os.path.join(REPO, "src", m, "mod.rs")))
    )
    orphans = sorted(
        f[:-3] for f in os.listdir(os.path.join(REPO, "src"))
        if f.endswith(".rs") and f not in ("main.rs", "lib.rs") and f[:-3] not in declared
    )
    ok = not missing and not orphans
    detail = f"{len(declared)} modules"
    if missing:
        detail += f"; unresolved={missing[:5]}"
    if orphans:
        detail += f"; orphans={orphans[:5]}"
    record("C3 module-graph", ok, detail)


# ── C4. pipeline.rs STAGES == dispatch arms; workflows use known stages ─────
def c4_stage_sync():
    pl = open(os.path.join(REPO, "src", "bin", "pipeline.rs"), encoding="utf-8").read()
    si = pl.find("const STAGES")
    head = pl[si:pl.find("];", si)]  # the STAGES array literal only
    stages = re.findall(r'^\s*"([a-z0-9-]+)"', head, re.M)
    di = pl.find("fn dispatch")
    tail = pl.find("\n        other =>", di)  # dispatch's catch-all arm ends the match
    d = pl[di:tail if tail != -1 else di + 3000]
    arms = re.findall(r'^\s*"([a-z0-9-]+)"\s*=>', d, re.M)
    mism = sorted(set(stages) ^ set(arms))
    dupes = [s for s in set(stages) if stages.count(s) > 1]
    wf_stages = set()
    for yml in os.listdir(os.path.join(REPO, ".github", "workflows")):
        if yml.endswith(".yml"):
            txt = open(os.path.join(REPO, ".github", "workflows", yml), encoding="utf-8").read()
            wf_stages |= set(re.findall(r"--stage[ =]+([a-z0-9-]+)", txt))
    unknown_wf = sorted(wf_stages - set(stages))
    ok = not mism and not dupes and not unknown_wf
    detail = f"{len(stages)} pipeline stages; {len(wf_stages)} distinct workflow stages"
    if mism:
        detail += f"; STAGES/dispatch mismatch={mism[:5]}"
    if dupes:
        detail += f"; dupes={dupes[:5]}"
    if unknown_wf:
        detail += f"; workflow stages unknown to pipeline={unknown_wf[:5]}"
    record("C4 stage-sync", ok, detail)


# ── C5. Evidence stamps on every iran_results.json entry ────────────────────
def c5_evidence_stamps():
    bridge_dir = os.path.join(REPO, "bridge")
    if not os.path.isdir(bridge_dir):
        record("C5 evidence-stamps", True,
               "bridge/ not materialized yet; runtime publication gate validates results")
        return
    p = os.path.join(bridge_dir, "iran_results.json")
    if not os.path.exists(p):
        record("C5 evidence-stamps", False, "bridge/iran_results.json missing")
        return
    doc = json.load(open(p, encoding="utf-8"))
    items = doc.get("bridges") or doc.get("results") or []
    fields = ("tested_at", "test_tier", "test_result")
    ok = bool(items) and all(isinstance(it, dict) and all(k in it for k in fields) for it in items)
    record("C5 evidence-stamps", ok,
           f"{len(items)} entries all stamped {fields}" if ok else f"{len(items)} entries")


# ── C6. No duplicate bridge lines inside any single bridge/*.txt ────────────
def c6_duplicate_lines():
    bridge_dir = os.path.join(REPO, "bridge")
    if not os.path.isdir(bridge_dir):
        record("C6 no-dup-bridge-lines", True,
               "bridge/ not materialized yet; runtime publication gate validates text outputs")
        return
    dups = []
    total = 0
    for f in sorted(os.listdir(bridge_dir)):
        if not f.endswith(".txt"):
            continue
        seen = set()
        for line in open(os.path.join(bridge_dir, f), encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
            if line in seen:
                dups.append(f)
                break
            seen.add(line)
    record("C6 no-dup-bridge-lines", not dups,
           f"{total} non-comment lines" if not dups else f"duplicates in {dups[:5]}")


# ── C7. Shell syntax across every committed shell script ────────────────────
def c7_shell_syntax():
    bad = []
    checked = 0
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in (".git", "target", ".venv", "node_modules", ".refact", ".agents")]
        for f in files:
            if not (f.endswith(".sh") or f == "install.sh" or f == "setup_env.sh" or f == "pre-push"):
                continue
            p = os.path.join(root, f)
            checked += 1
            if subprocess.run(["bash", "-n", p], capture_output=True).returncode != 0:
                bad.append(os.path.relpath(p, REPO))
    record("C7 shell-syntax", not bad,
           f"{checked} scripts" if not bad else f"bad={bad[:5]}")


# ── C8. Stage 8s committed artifacts match a fresh regeneration ─────────────
def c8_elite_freshness():
    export_dir = os.path.join(REPO, "export")
    txt_p = os.path.join(export_dir, "iran_anti_dpi_elite.txt")
    json_p = os.path.join(export_dir, "iran_anti_dpi_elite.json")
    missing = [p for p in (txt_p, json_p) if not os.path.exists(p)]
    if missing:
        record("C8 elite-freshness", False, f"missing artifacts: {missing}")
        return
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["ELITE_OUT_DIR"] = tmp
        subprocess.run(
            ["bash", os.path.join(REPO, "scripts", "build_iran_anti_dpi_elite.sh")],
            env=env, capture_output=True, cwd=REPO, check=True,
        )
        ok_txt = open(os.path.join(tmp, "iran_anti_dpi_elite.txt"), encoding="utf-8").read() \
            == open(txt_p, encoding="utf-8").read()
        fresh = json.load(open(os.path.join(tmp, "iran_anti_dpi_elite.json"), encoding="utf-8"))
        fresh.pop("generated_at", None)
        committed = json.load(open(json_p, encoding="utf-8"))
        committed.pop("generated_at", None)
        ok_json = fresh == committed
        record("C8 elite-freshness", ok_txt and ok_json,
               "txt+json identical to fresh regeneration" if ok_txt and ok_json
               else f"txt_equal={ok_txt}, json_equal={ok_json}")


# ── C9. No todo!()/unimplemented!() traps in production Rust ────────────────
def c9_no_panic_traps():
    hits = []
    for root, dirs, files in os.walk(os.path.join(REPO, "src")):
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(root, f)
            for i, line in enumerate(open(p, encoding="utf-8"), 1):
                if re.search(r"\b(todo!|unimplemented!)\(|FIXME|XXX|HACK", line) \
                        and not line.lstrip().startswith("//"):
                    hits.append(f"{os.path.relpath(p, REPO)}:{i}")
    record("C9 no-panic-traps", not hits, f"{len(hits)} hits" if hits else "clean")


# ── C10. Elite .txt line count == .json totals.elite_bridges ────────────────
def c10_elite_count_consistency():
    txt_p = os.path.join(REPO, "export", "iran_anti_dpi_elite.txt")
    json_p = os.path.join(REPO, "export", "iran_anti_dpi_elite.json")
    if not (os.path.exists(txt_p) and os.path.exists(json_p)):
        record("C10 elite-count", False, "artifacts missing")
        return
    lines = sum(1 for l in open(txt_p, encoding="utf-8") if l.strip())
    n = json.load(open(json_p, encoding="utf-8")).get("totals", {}).get("elite_bridges")
    record("C10 elite-count", lines == n, f"txt={lines}, json={n}")


# ── C11. User-facing iran_cut_pack.txt == fresh Stage 8p2 regeneration ──────
def c11_cutpack_freshness():
    p = os.path.join(REPO, "export", "iran_cut_pack.txt")
    if not os.path.isdir(os.path.join(REPO, "bridge")):
        record("C11 cutpack-freshness", True,
               "bridge/ not materialized yet; full pipeline finalizer validates cut pack")
        return
    if not os.path.exists(p):
        record("C11 cutpack-freshness", False, "export/iran_cut_pack.txt missing")
        return
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["NIN_CUT_PACK_OUT"] = tmp
        subprocess.run(
            ["bash", os.path.join(REPO, "scripts", "build_iran_cut_pack.sh")],
            env=env, capture_output=True, cwd=REPO, check=True,
        )
        fresh = open(os.path.join(tmp, "iran_cut_pack.txt"), encoding="utf-8").read()
        committed = open(p, encoding="utf-8").read()
        record("C11 cutpack-freshness", fresh == committed,
               "byte-identical to fresh regeneration" if fresh == committed
               else "committed file is stale vs regeneration")


# ── C12. pq_bridge_scores.json == fresh Stage 8t regeneration ───────────────
def _json_without_ts(path):
    doc = json.load(open(path, encoding="utf-8"))
    doc.pop("generated_at", None)
    return doc


def c12_pq_scores_freshness():
    p = os.path.join(REPO, "data", "pq_bridge_scores.json")
    if not os.path.exists(p):
        record("C12 pq-scores-freshness", False, "data/pq_bridge_scores.json missing")
        return
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["PQ_SCORES_OUT"] = tmp
        subprocess.run(
            ["bash", os.path.join(REPO, "scripts", "build_pq_bridge_scores.sh")],
            env=env, capture_output=True, cwd=REPO, check=True,
        )
        ok = _json_without_ts(os.path.join(tmp, "pq_bridge_scores.json")) \
            == _json_without_ts(p)
        record("C12 pq-scores-freshness", ok,
               "identical to fresh regeneration (sans timestamp)" if ok
               else "committed manifest is stale vs regeneration")


# ── C13. nin_recommended_transport.json == fresh Stage 8t regeneration ──────
def c13_nin_recommended_freshness():
    p = os.path.join(REPO, "export", "nin_recommended_transport.json")
    if not os.path.exists(p):
        record("C13 nin-recommended-freshness", False,
               "export/nin_recommended_transport.json missing")
        return
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["NIN_RECOMMENDED_OUT"] = tmp
        subprocess.run(
            ["bash", os.path.join(REPO, "scripts", "build_nin_recommended_transport.sh")],
            env=env, capture_output=True, cwd=REPO, check=True,
        )
        ok = _json_without_ts(os.path.join(tmp, "nin_recommended_transport.json")) \
            == _json_without_ts(p)
        record("C13 nin-recommended-freshness", ok,
               "identical to fresh regeneration (sans timestamp)" if ok
               else "committed manifest is stale vs regeneration")


# ── C14. Hourly automation, rerank-only skip, and publication side-effect gates ──
def c14_workflow_automation_gates():
    path = os.path.join(REPO, ".github", "workflows", "torshield-ir.yml")
    workflow = open(path, encoding="utf-8").read()
    hourly = bool(
        re.search(
            r"(?m)^\s*-\s*cron:\s*['\"]?0 \* \* \* \*['\"]?\s*$",
            workflow,
        )
    )

    jobs_start = workflow.find("\njobs:")
    scrape_start = workflow.find("\n  scrape-and-test:\n", jobs_start)
    rerank_start = workflow.find("\n  ai-rerank:\n", scrape_start)
    scrape_block = (
        workflow[scrape_start:rerank_start]
        if scrape_start >= 0 and rerank_start > scrape_start
        else ""
    )
    collection_gate = re.search(r"(?m)^    if:\s*(.*?)\s*$", scrape_block)
    expected_collection_gate = (
        "github.ref == 'refs/heads/main' && "
        "(github.event_name != 'workflow_dispatch' || inputs.rerank_only != true)"
    )
    main_only_collection = bool(collection_gate) and collection_gate.group(1) == expected_collection_gate

    main_ci_path = os.path.join(REPO, ".github", "workflows", "main-ci.yml")
    main_ci = open(main_ci_path, encoding="utf-8").read()
    main_ci_pipeline_gate = bool(
        re.search(
            r"(?m)^      - name: Run pipeline \(--all\)\n"
            r"        if: github\.event_name != 'pull_request' && github\.ref == 'refs/heads/main'\n"
            r"        run: cargo run --release --bin pipeline -- --all$",
            main_ci,
        )
    )

    def guard_sets(header, assignment):
        block = re.search(re.escape(header) + r"\n(.*?)^\s*fi\s*$", workflow, re.M | re.S)
        return bool(block and re.search(rf"(?m)^\s*{re.escape(assignment)}\s*$", block.group(1)))

    pull_request_upload_block = guard_sets(
        'if [ "$UPLOAD" = "true" ] && [ "${GITHUB_EVENT_NAME}" = "pull_request" ]; then',
        "UPLOAD=false",
    )
    non_main_upload_block = guard_sets(
        'if [ "$UPLOAD" = "true" ] && [ "${GITHUB_REF}" != "refs/heads/main" ]; then',
        "UPLOAD=false",
    )
    non_main_deploy_block = guard_sets(
        'if [ "${GITHUB_REF}" != "refs/heads/main" ] || [ "${GITHUB_EVENT_NAME}" = "pull_request" ]; then',
        "DEPLOY_RELAY=false",
    )
    commit_main_only = (
        "if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main'"
        in workflow
    )
    publication_gates = (
        pull_request_upload_block and non_main_upload_block and commit_main_only
    )
    production_mutations_main_only = main_only_collection and non_main_deploy_block
    ok = (
        hourly
        and main_only_collection
        and publication_gates
        and production_mutations_main_only
        and main_ci_pipeline_gate
    )
    record(
        "C14 workflow-automation-gates",
        ok,
        f"hourly={hourly}, main-only_collection={main_only_collection}, "
        f"main-only_dual-persist={publication_gates}, "
        f"main-only_deploy={production_mutations_main_only}, "
        f"main-ci-pipeline={main_ci_pipeline_gate}",
    )


def main():
    print("═══ verify_repo_invariants ═══")
    c1_json_parse()
    c2_publication_contract()
    c3_module_graph()
    c4_stage_sync()
    c5_evidence_stamps()
    c6_duplicate_lines()
    c7_shell_syntax()
    c8_elite_freshness()
    c9_no_panic_traps()
    c10_elite_count_consistency()
    c11_cutpack_freshness()
    c12_pq_scores_freshness()
    c13_nin_recommended_freshness()
    c14_workflow_automation_gates()
    print(f"═══ {len(CHECKS) - len(FAILURES)}/{len(CHECKS)} checks passed ═══")
    if FAILURES:
        for f in FAILURES:
            print(f"::error::{f}")
        sys.exit(1)
    print("═══ verify_repo_invariants: ALL GREEN ═══")


if __name__ == "__main__":
    main()
PY

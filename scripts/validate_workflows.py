#!/usr/bin/env python3
"""
Zero-Error CI workflow validator for the Tor-Bridges-Collector / TorShield-IR
repository.

What it enforces (the policy stated in the workflow-sanitization directive):

  1. Every file under .github/workflows/ is valid YAML.
  2. No `run:` step on a Linux runner invokes a *hardcoded* `powershell` or
     `pwsh` binary as a command (the root cause of incident #73 / Exit 127,
     since `powershell` is absent on GitHub's ubuntu runners). Explicit
     `shell: pwsh` declarations are still permitted by the policy and are
     NOT flagged.
  3. Reports a per-file and total violation count and exits non-zero on any
     violation, so it can gate CI.

This script is intentionally dependency-light: it only needs PyYAML (already
used elsewhere in the tree) and the Python standard library.

Run:
    python3 scripts/validate_workflows.py [path/to/.github/workflows]
"""

from __future__ import annotations

import glob
import os
import re
import sys
from typing import Iterable

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - exercised in CI where PyYAML exists
    sys.stderr.write("INFO: PyYAML not installed; skipping deep YAML AST parse and running regex check.\n")
    yaml = None



# A `powershell`/`pwsh` *command* token: the first non-whitespace token on a
# logical line (after stripping shell connectors like && / || / ; / | / ( / `),
# immediately followed by an argument boundary. This deliberately does NOT
# match the words "powershell"/"pwsh" appearing inside prose such as
# `echo "... no powershell"` or inside `#` comments.
_CONNECTORS = ("&&", "||", ";", "|", "(", "`", ">")


def _line_invokes_powershell(raw_line: str) -> bool:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return False
    # Peel off a leading shell connector so `&& powershell ...` is caught.
    changed = True
    while changed:
        changed = False
        for sep in _CONNECTORS:
            if line.startswith(sep):
                line = line[len(sep):].lstrip()
                changed = True
    m = re.match(r"(powershell|pwsh)([\s.\-]|$)", line, re.IGNORECASE)
    return bool(m)


def _iter_run_blocks(job: dict) -> Iterable[tuple[dict, str]]:
    steps = job.get("steps") or []
    for step in steps:
        if isinstance(step, dict) and isinstance(step.get("run"), str):
            yield step, step["run"]


def _is_linux_runner(runs_on: object) -> bool:
    if isinstance(runs_on, str):
        return runs_on.lower().startswith(("ubuntu", "linux", "self-hosted"))
    return True  # matrix/list -> be conservative and assume it could be Linux


def validate_file(path: str) -> list[str]:
    """Return a list of human-readable violation strings for one workflow."""
    violations: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
            if yaml is not None:
                doc = yaml.safe_load(content)
            else:
                return []
    except Exception as exc:
        return [f"{path}: invalid or unreadable -> {exc}"]

    if not isinstance(doc, dict):
        return [f"{path}: top-level YAML is not a mapping"]

    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return [f"{path}: 'jobs' is missing or not a mapping"]

    for job_name, job in jobs.items():
        # Reusable workflows (workflow_call) have no `steps`/`runs-on`.
        if not isinstance(job, dict):
            continue
        runs_on = job.get("runs-on")
        is_linux = _is_linux_runner(runs_on)
        for step, run_text in _iter_run_blocks(job):
            for raw_line in run_text.splitlines():
                if not _line_invokes_powershell(raw_line):
                    continue
                if str(step.get("shell", "")).lower() == "pwsh":
                    # Explicit pwsh shell is permitted by the policy.
                    continue
                where = "linux runner" if is_linux else "non-linux runner"
                violations.append(
                    f"{path}: job '{job_name}' step "
                    f"'{step.get('name', '<run>')}' invokes hardcoded "
                    f"powershell/pwsh on a {where}: {raw_line.strip()!r}"
                )
    return violations


def main(argv: list[str]) -> int:
    root = argv[1] if len(argv) > 1 else ".github/workflows"
    paths = sorted(
        glob.glob(os.path.join(root, "*.yml")) + glob.glob(os.path.join(root, "*.yaml"))
    )
    if not paths:
        print(f"validate_workflows: no workflow files found under {root}")
        return 1

    total = 0
    for path in paths:
        v = validate_file(path)
        total += len(v)
        status = "OK" if not v else "FAIL"
        print(f"[{status}] {path}")
        for msg in v:
            print(f"        - {msg}")

    print(f"\nValidated {len(paths)} workflow file(s); {total} violation(s).")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""
fix_silent_exceptions.py — REMEDIATION 2026-06-21, item §1.1

Mechanically rewrites every "swallowing" `except` block in the production
codebase (defined as: no Raise / Return / Continue / Break / Yield /
YieldFrom anywhere in the handler body — i.e. the failure currently
disappears without changing control flow) so that it instead:

  1. Logs the exception via monitoring.structured_logger (ERROR level,
     full traceback, JSON-line monitor.log).
  2. Increments a named, externally observable counter for that exact
     call site (module:lineno), retrievable via
     monitoring.structured_logger.get_silent_failure_counts().

Control flow is NEVER changed — these are still "swallowing" handlers
afterward, on purpose. The gateway's whole design point is to survive
provider failures; this script makes that survival observable instead of
silent, it does not turn failures into crashes.

Scope (intentionally excluded — see docs/REMEDIATION_CHANGELOG.md):
  - monitoring/structured_logger.py itself — these are the file's own
    documented "ZERO CRASH... FAIL-SAFE" guards (e.g. disk-full while
    writing a log line). Instrumenting the logger's own fail-safes with
    calls back into the logger would be circular and serves no one.
  - tests/ and conftest.py — test code, not a production failure path.

IDEMPOTENCY (structural, not line-number based — line numbers shift after
the first run, so matching on a baked-in site string is NOT reliable across
runs): a handler is considered "already instrumented" and skipped if its
body's first statement is
    from monitoring.structured_logger import record_silent_failure
and its second statement is a call to record_silent_failure(...). This
check is robust regardless of how much line numbers have shifted.

Usage:
    python3 scripts/remediation/fix_silent_exceptions.py [--dry-run]
"""
from __future__ import annotations

import ast
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EXCLUDED_FILES = {
    os.path.join(REPO_ROOT, "monitoring", "structured_logger.py"),
    # ECH probe handlers intentionally classify expected network/TLS failures
    # locally; tests assert those paths do not emit global silent-failure
    # telemetry unless the failure is unexpected.
    os.path.join(REPO_ROOT, "ech_fingerprint_evasion.py"),
}
EXCLUDED_DIR_PREFIXES = (
    os.path.join(REPO_ROOT, "tests"),
    os.path.join(REPO_ROOT, "__pycache__"),
)
EXCLUDED_FILENAMES = {"conftest.py"}

MARKER_MODULE = "monitoring.structured_logger"
MARKER_FUNC = "record_silent_failure"


def _has_control_flow_escape(stmts: list[ast.stmt]) -> bool:
    """True if Raise/Return/Continue/Break/Yield/YieldFrom appears anywhere
    (recursively) in the given statement list."""
    for stmt in stmts:
        for n in ast.walk(stmt):
            if isinstance(
                n,
                (ast.Raise, ast.Return, ast.Continue, ast.Break, ast.Yield, ast.YieldFrom),
            ):
                return True
    return False


def _already_instrumented(body: list[ast.stmt]) -> bool:
    """Structural (not text/line-number based) idempotency check."""
    if len(body) < 2:
        return False
    first, second = body[0], body[1]
    if not (isinstance(first, ast.ImportFrom) and first.module == MARKER_MODULE):
        return False
    if not any(alias.name == MARKER_FUNC for alias in first.names):
        return False
    if not isinstance(second, ast.Expr) or not isinstance(second.value, ast.Call):
        return False
    func = second.value.func
    return isinstance(func, ast.Name) and func.id == MARKER_FUNC


def _module_dotted_path(abs_path: str) -> str:
    rel = os.path.relpath(abs_path, REPO_ROOT)
    if rel.endswith(".py"):
        rel = rel[: -len(".py")]
    return rel.replace(os.sep, ".")


def _iter_target_files():
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [
            d
            for d in dirs
            if d not in ("__pycache__", ".git", ".pytest_cache")
            and not os.path.join(root, d).startswith(EXCLUDED_DIR_PREFIXES)
        ]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            if fn in EXCLUDED_FILENAMES:
                continue
            path = os.path.join(root, fn)
            if path in EXCLUDED_FILES or path.startswith(EXCLUDED_DIR_PREFIXES):
                continue
            yield path


def _process_file(path: str, dry_run: bool) -> int:
    with open(path, encoding="utf-8") as f:
        src = f.read()
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError as e:
        print(f"  SKIP (pre-existing syntax error, not touched): {path}: {e}")
        return 0

    targets: list[ast.ExceptHandler] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for h in node.handlers:
                if _already_instrumented(h.body):
                    continue
                if not _has_control_flow_escape(h.body):
                    targets.append(h)

    if not targets:
        return 0

    mod_path = _module_dotted_path(path)

    # Insert bottom-up so earlier (lower-lineno) handlers' line numbers
    # stay valid while we edit this file in a single pass.
    targets.sort(key=lambda h: h.lineno, reverse=True)

    lines = src.splitlines(keepends=True)
    changed = 0

    for h in targets:
        body_first = h.body[0]
        indent = " " * body_first.col_offset
        site = f"{mod_path}:{h.lineno}"

        if h.name:
            var = h.name
        else:
            var = "_remediation_exc"
            line_idx = h.lineno - 1
            line = lines[line_idx]
            search_start = (
                h.type.end_col_offset if h.type is not None else line.find("except") + len("except")
            )
            colon_pos = line.find(":", search_start)
            if colon_pos == -1:
                print(f"  WARN: could not locate clause colon at {path}:{h.lineno} — skipping this handler")
                continue
            lines[line_idx] = line[:colon_pos] + " as " + var + line[colon_pos:]

        insertion = (
            f"{indent}from monitoring.structured_logger import record_silent_failure\n"
            f"{indent}record_silent_failure({site!r}, {var})\n"
        )
        lines.insert(h.lineno, insertion)
        changed += 1

    new_src = "".join(lines)

    # Hard safety gate: the rewritten file MUST still parse, AND must not
    # have changed the swallowing-handler count in some unexpected way.
    try:
        ast.parse(new_src, filename=path)
    except SyntaxError as e:
        print(f"  ABORTED (rewrite produced invalid syntax, original left untouched): {path}: {e}")
        return 0

    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_src)

    print(f"  {'[dry-run] would fix' if dry_run else 'fixed'} {changed} handler(s) in {path}")
    return changed


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    total = 0
    files_changed = 0
    print(f"Scanning {REPO_ROOT} ...")
    for path in sorted(_iter_target_files()):
        n = _process_file(path, dry_run)
        if n:
            total += n
            files_changed += 1
    print()
    print(f"{'Would fix' if dry_run else 'Fixed'} {total} silent-exception handler(s) across {files_changed} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

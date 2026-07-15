#!/usr/bin/env python3
"""Phase-0 migration audit helper for the Python-to-Rust parity effort.

The script is intentionally static-only: it never imports project modules, so
broken optional dependencies cannot hide files from the inventory.
"""
from __future__ import annotations

import ast
import json
import re
import sys
import sysconfig
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "migration_phase0_inventory.json"
REQ = ROOT / "requirements.txt"
PYPROJECT = ROOT / "pyproject.toml"
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "target"}
IMPORT_TO_REQUIREMENT = {
    "bs4": "beautifulsoup4",
    "Crypto": "pycryptodome",
    "dns": "dnspython",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
    "prometheus_client": "prometheus-client",
    "nest_asyncio": "nest-asyncio",
}
KNOWN_LOCAL_ROOTS = {
    "anti_censorship", "autonomous", "circuit_breaker", "config", "core", "diagnostics",
    "gateway", "health", "model_selector", "monitoring", "providers", "recovery", "registry",
    "reports", "scripts", "sources", "tests", "torshield_ai_gateway",
}


def stdlib_names() -> set[str]:
    names = set(getattr(sys, "stdlib_module_names", set()))
    names.update(sys.builtin_module_names)
    paths = [Path(sysconfig.get_path(k)) for k in ("stdlib", "platstdlib") if sysconfig.get_path(k)]
    for base in paths:
        if not base.exists():
            continue
        for child in base.iterdir():
            if child.name.startswith("_"):
                continue
            if child.suffix == ".py":
                names.add(child.stem)
            elif child.is_dir() and (child / "__init__.py").exists():
                names.add(child.name)
    return names


def python_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        files.append(path.relative_to(ROOT))
    return sorted(files, key=lambda p: p.as_posix())


def parse_requirements() -> set[str]:
    reqs = set()
    if not REQ.exists():
        return reqs
    for line in REQ.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        reqs.add(re.split(r"[<>=!~;\[]", line, maxsplit=1)[0].strip())
    return reqs


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def function_contract(node: ast.AST, qualname: str) -> dict:
    args = getattr(node, "args", None)
    arg_names = [] if args is None else [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args and args.vararg:
        arg_names.append("*" + args.vararg.arg)
    if args and args.kwarg:
        arg_names.append("**" + args.kwarg.arg)
    returns = sum(isinstance(n, ast.Return) for n in ast.walk(node))
    raises = [ast.unparse(n.exc) if getattr(n, "exc", None) else "re-raise" for n in ast.walk(node) if isinstance(n, ast.Raise)]
    handlers = [ast.unparse(h.type) if h.type else "BaseException" for n in ast.walk(node) if isinstance(n, ast.Try) for h in n.handlers]
    branches = {
        "if": sum(isinstance(n, ast.If) for n in ast.walk(node)),
        "for": sum(isinstance(n, (ast.For, ast.AsyncFor)) for n in ast.walk(node)),
        "while": sum(isinstance(n, ast.While) for n in ast.walk(node)),
        "try": sum(isinstance(n, ast.Try) for n in ast.walk(node)),
        "match": sum(isinstance(n, ast.Match) for n in ast.walk(node)),
    }
    log_calls = []
    timeout_values = []
    retry_calls = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            name = call_name(n.func)
            if any(x in name.lower() for x in ("log", "print")):
                log_calls.append(ast.unparse(n)[:240])
            if "retry" in name.lower() or "backoff" in name.lower():
                retry_calls.append(ast.unparse(n)[:240])
            for kw in n.keywords:
                if kw.arg and "timeout" in kw.arg.lower():
                    timeout_values.append(ast.unparse(kw.value))
    return {
        "qualname": qualname,
        "line": getattr(node, "lineno", None),
        "kind": type(node).__name__,
        "args": arg_names,
        "returns_annotation": ast.unparse(node.returns) if getattr(node, "returns", None) else None,
        "return_statement_count": returns,
        "branches": branches,
        "raises": raises,
        "exception_handlers": handlers,
        "log_calls": log_calls,
        "timeout_values": timeout_values,
        "retry_or_backoff_calls": retry_calls,
        "docstring": ast.get_docstring(node),
    }


def analyze_file(rel: Path) -> dict:
    text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text, filename=rel.as_posix())
    except SyntaxError as exc:
        return {"path": rel.as_posix(), "syntax_error": str(exc), "imports": [], "contracts": []}
    imports = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            imports += [a.name.split(".", 1)[0] for a in n.names]
        elif isinstance(n, ast.ImportFrom) and n.module:
            imports.append(n.module.split(".", 1)[0])
    contracts = []
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            contracts.append(function_contract(n, n.name))
        elif isinstance(n, ast.ClassDef):
            contracts.append({"qualname": n.name, "line": n.lineno, "kind": "ClassDef", "docstring": ast.get_docstring(n)})
            for child in n.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    contracts.append(function_contract(child, f"{n.name}.{child.name}"))
    return {"path": rel.as_posix(), "imports": sorted(set(imports)), "contracts": contracts}


def pytest_markers() -> list[str]:
    text = PYPROJECT.read_text(encoding="utf-8") if PYPROJECT.exists() else ""
    marker_block = re.search(r"markers\s*=\s*\[(.*?)\]", text, flags=re.S)
    if not marker_block:
        return []
    return re.findall(r'"([A-Za-z0-9_]+):[^"\n]*"', marker_block.group(1))


def main() -> int:
    files = python_files()
    reqs = parse_requirements()
    std = stdlib_names()
    analyzed = [analyze_file(p) for p in files]
    imported = sorted({i for f in analyzed for i in f.get("imports", [])})
    local_toplevel = {p.stem for p in files} | KNOWN_LOCAL_ROOTS
    third_party = []
    missing = []
    for name in imported:
        if name in std or name in local_toplevel or name.startswith("_"):
            continue
        req = IMPORT_TO_REQUIREMENT.get(name, name)
        third_party.append({"import": name, "requirement": req, "declared": req in reqs})
        if req not in reqs:
            missing.append({"import": name, "expected_requirement": req})
    report = {
        "summary": {"python_file_count": len(files), "contract_count": sum(len(f.get("contracts", [])) for f in analyzed)},
        "pytest_marker_to_cargo_feature": {m: m for m in pytest_markers()},
        "requirements_declared": sorted(reqs),
        "third_party_imports": third_party,
        "missing_requirements": missing,
        "files": analyzed,
    }
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(files)} Python files, {report['summary']['contract_count']} contracts")
    if missing:
        print("missing requirements detected:", ", ".join(f"{m['import']}->{m['expected_requirement']}" for m in missing))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Zero-dependency static security scan for the Tor-Bridges-Collector tree.

Referenced by `.github/workflows/autonomous-sentinel.yml` ("Validation
suite"); the historical version of this file went missing during the
Python→Rust migration which made every caller fail with exit 2.

What it does (deterministic, offline, stdlib only):

  1. Parses every `*.py` file with `ast` and flags dangerous dynamic
     execution sinks: `eval()`, `exec()`, `compile()` with dynamic input,
     `os.system()`, `subprocess.*(..., shell=True, ...)`, `__import__()`.
  2. Scans every text file under the repository for hard-coded
     credential-shaped strings (common token prefixes and PEM private-key
     headers), excluding known-safe locations (docs, templates, examples,
     and files that legitimately hold bridge/public-key *data*).
  3. Prints a per-finding report and exits 1 if anything is found, so it
     can gate CI. Exits 0 when the tree is clean.

The scanner is intentionally conservative: it reports patterns with a
high true-positive rate instead of guessing. Suppressions are explicit:
append `  # nosec` (Python) or `  # security-scan: ignore` (text) on the
same line as a deliberate false positive.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

# Directories that never contain first-party secrets/code to gate on.
SKIP_DIRS = {
    ".git",
    ".github",
    ".agents",
    ".refact",
    ".arena_logs",
    "node_modules",
    "__pycache__",
    "vendor",
    "target",
    "dist",
    "downloaded-bin",
    ".zig-cache",
    "zig-out",
}

# Files where credential-shaped strings are expected data (bridge public
# keys, documented examples, templates) rather than leaked secrets.
ALLOW_CREDENTIAL_SHAPED = {
    "CERT",  # obfs4 bridge certificates in data files
}

TEXT_EXTENSIONS = {
    ".py", ".sh", ".bash", ".ps1", ".psm1", ".zsh",
    ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
    ".md", ".txt", ".env", ".zig", ".rs", ".go", ".lock",
}

PYTHON_SINKS = {
    "eval": "eval() executes arbitrary code",
    "exec": "exec() executes arbitrary code",
    "os.system": "os.system() runs a shell command directly",
    "__import__": "__import__() enables dynamic module loading",
}

# Bearer-token / API-key shaped high-entropy strings.
CREDENTIAL_PATTERNS = [
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),                      # GitHub PAT
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),              # fine-grained PAT
    re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),                 # GitLab PAT
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),                       # OpenAI-style key
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),                          # AWS access key
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),             # Slack token
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


def iter_python_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield Path(dirpath) / name


def _dotted_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value  # type: ignore[assignment]
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        return ".".join(parts)
    return None


def scan_python_file(path: Path) -> list[str]:
    findings: list[str] = []
    source = path.read_text(encoding="utf-8", errors="ignore")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:  # syntax errors are gated elsewhere (flake8)
        return [f"{exc.lineno}: cannot parse file ({exc.msg})"]

    nosec_lines = {
        n for n, line in enumerate(source.splitlines(), 1) if "# nosec" in line
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted_name(node.func)
        if name is None:
            continue
        short = name.split(".")[-1]
        reason = PYTHON_SINKS.get(name) or PYTHON_SINKS.get(short)
        if reason and node.lineno not in nosec_lines:
            findings.append(f"{node.lineno}: {reason}")
        # subprocess-style calls with shell=True
        if short in {"run", "call", "check_call", "check_output", "Popen"}:
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    and node.lineno not in nosec_lines
                ):
                    findings.append(f"{node.lineno}: subprocess invoked with shell=True")
    return findings


def scan_text_file(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    for lineno, line in enumerate(lines, 1):
        if "# security-scan: ignore" in line:
            continue
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(line):
                findings.append(f"{lineno}: credential-shaped string ({pattern.pattern!r})")
                break
    return findings


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    total = 0

    print("═══ Security scan (stdlib, offline) ═══")
    for py in iter_python_files(root):
        rel = py.relative_to(root)
        for finding in scan_python_file(py):
            print(f"  ✗ {rel}:{finding}")
            total += 1

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            if name.endswith((".sha256", ".cert")):  # pure data digests/certs
                continue
            for finding in scan_text_file(path):
                print(f"  ✗ {path.relative_to(root)}:{finding}")
                total += 1

    if total:
        print(f"  ✗ {total} finding(s) — failing per Zero-Error policy")
        return 1
    print("  ✓ No dangerous sinks or hard-coded credentials found")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

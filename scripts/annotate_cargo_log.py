#!/usr/bin/env python3
"""Emit GitHub Actions error annotations from a cargo test/clippy log.

Matches rustc diagnostics and failed tests only. Passing ``test result: ok``
lines are ignored so they cannot fill the annotation cap. Always prints a
trailing log tail so a failure still has evidence when matchers miss.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def interesting(line: str) -> bool:
    stripped = line.strip()
    if "error[" in line or line.startswith("error:"):
        return True
    if "panicked at" in line or stripped.endswith("... FAILED"):
        return True
    if stripped == "failures:" or stripped.startswith("error: test failed"):
        return True
    if line.startswith("test result:") and "FAILED" in line:
        return True
    return False


def emit(chunk: str) -> None:
    print(f"::error::{chunk[:900]}")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: annotate_cargo_log.py LOG", file=sys.stderr)
        return 2
    log = Path(sys.argv[1])
    text = log.read_text(errors="replace") if log.exists() else ""
    plain = re.sub(r"\x1b\[[0-9;]*m", "", text)
    lines = plain.splitlines()
    emitted = 0
    seen: set[int] = set()
    for i, line in enumerate(lines):
        if not interesting(line):
            continue
        for j in range(i, min(len(lines), i + 24)):
            if j in seen:
                continue
            seen.add(j)
            emit(lines[j])
            emitted += 1
            if emitted > 100:
                break
        if emitted > 100:
            break
    emit("----- cargo log tail -----")
    if not lines:
        emit(f"{log} was empty or missing; the cargo command failed before producing output")
        return 0
    for chunk in lines[-80:]:
        emit(chunk)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

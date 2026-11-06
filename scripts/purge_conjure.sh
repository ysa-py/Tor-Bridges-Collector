#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# purge_conjure.sh — remove the `conjure` transport (and ONLY conjure) from every
# published artefact.  python3 stdlib embedded (no *.py may live in the tree).
#
# Why: Orbot / Tor Browser for Android cannot use conjure.  Orbot's custom-bridge
# dialog validates EVERY pasted line against one regex whose transport list is
# (meek_lite|obfs4|webtunnel|snowflake|dnstt); a single `conjure ...` line inside
# an aggregate file (iran_likely_working_all.txt, iran_likely_working_nin.txt, …)
# therefore turns the whole paste into "Invalid bridge format".
#
# What it removes (nothing else is touched):
#   * bridge/conjure*.txt, export/**/conjure* files
#   * `conjure …` / `Bridge conjure …` lines in bridge/*.txt, export/**/*.txt|*.torrc
#   * `ClientTransportPlugin conjure …` lines (and `conjure,` items in shared plugin lines)
#   * comment lines that only talk about conjure in those files
#   * JSON entries in bridge/, export/, data/: dict keys / list items / records whose
#     transport, name or line is conjure
#   * README.md bullet rows that link conjure*.txt
# The telegram manifest, ZIP and README archive hash are re-attested afterwards by
# scripts/publication_contract.sh (auto_bridge_fusion.sh runs it right after this).
#
# Idempotent and offline-safe.  Usage:
#   scripts/purge_conjure.sh [--root DIR] [--bridge-dir bridge] [--check]
# Exit: 0 clean/purged, 1 --check found conjure leftovers.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
command -v python3 >/dev/null 2>&1 || { echo "[purge-conjure] python3 not found - skipped" >&2; exit 0; }
exec python3 - "$@" <<'PY'
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

CONJURE = re.compile(r"conjure", re.I)
LINE_START = re.compile(r"^\s*(?:bridge\s+)?conjure(?:\s|$)", re.I)
FILE_NAME = re.compile(r"^(?:.*/)?conjure[\w.\-]*\.txt$", re.I)
PLUGIN = re.compile(r"^\s*ClientTransportPlugin\s+(\S+)\s+(.*)$", re.I)
README_ROW = re.compile(r"^\s*[-*|]\s*\[conjure[^\]]*\]", re.I)
TEXT_EXT = (".txt", ".torrc", ".lst")
TRANSPORT_KEYS = ("transport", "family", "use", "type", "protocol", "pt")
LINE_KEYS = ("raw", "line", "bridge", "bridge_line", "name", "file", "filename", "path")


def is_conjure_str(v: object) -> bool:
    return isinstance(v, str) and bool(LINE_START.match(v) or FILE_NAME.match(v.strip()))


def is_conjure_record(d: dict) -> bool:
    for k in TRANSPORT_KEYS:
        v = d.get(k)
        if isinstance(v, str) and v.strip().lower() == "conjure":
            return True
    for k in LINE_KEYS:
        v = d.get(k)
        if isinstance(v, str) and (LINE_START.match(v) or FILE_NAME.match(v.strip())):
            return True
    return False


def conjure_key(k: object) -> bool:
    if not isinstance(k, str):
        return False
    s = re.sub(r"^\s*bridge\s+", "", k, flags=re.I)
    return bool(re.match(r"^\s*conjure(?:[\s_.\-]|$)", s, re.I))


def scrub(node):
    """Return (new_node, removed_count). Pure function over parsed JSON."""
    removed = 0
    if isinstance(node, list):
        out = []
        for item in node:
            if is_conjure_str(item) or (isinstance(item, dict) and is_conjure_record(item)):
                removed += 1
                continue
            new, n = scrub(item)
            removed += n
            out.append(new)
        return out, removed
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if conjure_key(k):
                removed += 1
                continue
            if isinstance(v, dict) and is_conjure_record(v):
                removed += 1
                continue
            new, n = scrub(v)
            removed += n
            out[k] = new
        return out, removed
    return node, 0


def scrub_text(text: str) -> tuple[str, int]:
    removed = 0
    out = []
    for ln in text.split("\n"):
        s = ln.strip()
        if LINE_START.match(s):
            removed += 1
            continue
        m = PLUGIN.match(s)
        if m and CONJURE.search(m.group(1)):
            names = [n for n in m.group(1).split(",") if not CONJURE.fullmatch(n.strip())]
            removed += 1
            if names:
                out.append(f"ClientTransportPlugin {','.join(names)} {m.group(2)}")
            continue
        if s.startswith("#") and CONJURE.search(s):
            removed += 1
            continue
        out.append(ln)
    return "\n".join(out), removed


def dump_like(raw: str, orig, new) -> str:
    """Serialise `new` with the formatting that reproduces `raw` byte-for-byte from `orig`
    (so the purge produces a minimal diff); fall back to 2-space indent."""
    body = raw.rstrip("\n")
    for indent in (2, 4, None, 1):
        for ascii_ in (False, True):
            for sort in (False, True):
                for seps in (None, (",", ":"), (", ", ": ")):
                    if indent is not None and seps and seps[0] == ", ":
                        continue
                    kw = dict(indent=indent, ensure_ascii=ascii_, sort_keys=sort)
                    if seps:
                        kw["separators"] = seps
                    try:
                        if json.dumps(orig, **kw) == body:
                            return json.dumps(new, **kw) + raw[len(body):]
                    except (TypeError, ValueError):
                        pass
    return json.dumps(new, indent=2, ensure_ascii=False) + "\n"


def write(path: str, data: bytes) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--bridge-dir", default=None)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    bridge = os.path.abspath(a.bridge_dir or os.path.join(root, "bridge"))
    export = os.path.join(root, "export")
    data = os.path.join(root, "data")
    stats = {"files_deleted": 0, "text_lines": 0, "json_entries": 0, "files_changed": 0}
    leftovers = 0

    # 1. conjure-named files
    for base in (bridge, export):
        for path in glob.glob(os.path.join(base, "**", "conjure*"), recursive=True):
            if os.path.isfile(path):
                stats["files_deleted"] += 1
                leftovers += 1
                if not a.check:
                    os.remove(path)

    # 2. text projections / torrc exports
    text_files = []
    for base in (bridge, export):
        for dirpath, _dirs, files in os.walk(base):
            for f in files:
                if f.endswith(TEXT_EXT) or (base == bridge and f == "snowflake_ipv6_tested"):
                    text_files.append(os.path.join(dirpath, f))
    for path in sorted(text_files):
        try:
            raw = open(path, "r", encoding="utf-8", errors="surrogateescape").read()
        except OSError:
            continue
        if not CONJURE.search(raw):
            continue
        new, n = scrub_text(raw)
        if n:
            stats["text_lines"] += n
            leftovers += n
            if not a.check:
                write(path, new.encode("utf-8", "surrogateescape"))
                stats["files_changed"] += 1

    # 3. JSON artefacts
    json_files = []
    for base in (bridge, export, data):
        for dirpath, _dirs, files in os.walk(base):
            json_files += [os.path.join(dirpath, f) for f in files if f.endswith(".json")]
    for path in sorted(json_files):
        try:
            raw = open(path, "r", encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        if not CONJURE.search(raw):
            continue
        try:
            doc = json.loads(raw)
        except ValueError:
            continue
        new, n = scrub(doc)
        if n:
            stats["json_entries"] += n
            leftovers += n
            if not a.check:
                body = dump_like(raw, doc, new)
                write(path, body.encode("utf-8"))
                stats["files_changed"] += 1

    # 4. README bullet rows (the bridge file index)
    for name in ("README.md", "README_FA.md"):
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        lines = open(path, encoding="utf-8").read().split("\n")
        keep = [ln for ln in lines if not README_ROW.match(ln)]
        if len(keep) != len(lines):
            leftovers += len(lines) - len(keep)
            stats["text_lines"] += len(lines) - len(keep)
            if not a.check:
                write(path, "\n".join(keep).encode("utf-8"))
                stats["files_changed"] += 1

    print(f"[purge-conjure] {'would remove' if a.check else 'removed'}: {stats}")
    return 1 if (a.check and leftovers) else 0


sys.exit(main())
PY

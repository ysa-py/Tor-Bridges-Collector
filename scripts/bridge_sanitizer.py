#!/usr/bin/env python3
"""Bridge sanitizer + Orbot exporter (stdlib only, idempotent, offline).

Why this exists
---------------
Orbot's "Custom Bridges" dialog answers **"Invalid bridge format"** unless EVERY
non-blank pasted line matches one of two strict regexes (taken from
guardianproject/orbot-android ``CustomBridgeBottomSheet.kt``)::

    ^obfs4\\s+(IPv4|[IPv6]):\\d+\\s+[A-F0-9]{40}(\\s+cert=[a-zA-Z0-9+/=]+)?(\\s+iat-mode=\\d+)?$
    ^webtunnel\\s+(IPv4|[IPv6]):\\d+\\s+[A-F0-9]{40}(\\s+url=https?://\\S+)?(\\s+ver=\\d+\\.\\d+\\.\\d+)?$

Consequences that the old aggregate files violated:
  * a leading ``Bridge `` (torrc syntax) on vanilla lines,
  * vanilla / snowflake / meek_lite / conjure lines mixed into the list,
  * lower-case fingerprints, extra webtunnel parameters (``sni-imitation=`` ...),
  * reserved / private addresses on obfs4 / vanilla (webtunnel's [2001:db8::] placeholder is legitimate).

What it does (every run, fully automatic)
-----------------------------------------
  1. Normalises every ``bridge/*.txt`` (and ``snowflake_ipv6_tested``): strips the
     ``Bridge `` prefix, CR/BOM/blank lines, upper-cases fingerprints, de-duplicates,
     drops malformed or non-global endpoints. Pure-transport files (obfs4*,
     webtunnel*) are made 100% Orbot-valid.
  2. Empty-output guard: a file that would become empty keeps its previous bytes; a
     file that is empty/missing is re-filled from sibling files of the same
     transport (respecting the IPv4/IPv6 suffix).
  3. Writes ready-to-paste Orbot lists into ``export/orbot/`` (outside ``bridge/``
     because the Rust publisher prunes unmanaged files there) and re-validates
     them with the exact Orbot regexes before finishing.

Usage:  bridge_sanitizer.py [--root DIR] [--bridge-dir DIR] [--export-dir DIR] [--check]
Exit code: 0 ok, 1 --check found problems, 2 internal self-validation failure.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple

# ── Orbot's exact validators (Python translation of the Kotlin regexes) ────────
_ADDR = r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:]+\])"
ORBOT_OBFS4 = re.compile(
    rf"^obfs4\s+{_ADDR}:\d+\s+[A-F0-9]{{40}}(\s+cert=[a-zA-Z0-9+/=]+)?(\s+iat-mode=\d+)?$")
ORBOT_WEBTUNNEL = re.compile(
    rf"^webtunnel\s+{_ADDR}:\d+\s+[A-F0-9]{{40}}(\s+url=https?://\S+)?(\s+ver=\d+\.\d+\.\d+)?$")

FP_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
CERT_RE = re.compile(r"^[A-Za-z0-9+/]{43,}={0,2}$")
HOSTPORT_RE = re.compile(r"^(?:(\d{1,3}(?:\.\d{1,3}){3})|\[([0-9A-Fa-f:]+)\]):(\d{1,5})$")
URL_RE = re.compile(r"^https?://[^\s/]+\S*$")
VER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Transports whose placeholder addresses (192.0.2.x etc.) are legitimate PT syntax.
PLACEHOLDER_OK = {"snowflake", "meek_lite", "conjure"}
KNOWN_PT = {"obfs4", "webtunnel", "snowflake", "meek_lite", "conjure"}

STRICT_NAME = re.compile(
    r"^(obfs4|webtunnel)(?:[_-].*)?\.txt$|^iran_likely_working_(obfs4|webtunnel)\.txt$"
    r"|^tested_global_(obfs4|webtunnel)\.txt$")


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Line parsing / normalisation ───────────────────────────────────────────────
def clean_line(raw: str) -> str:
    s = raw.replace("\ufeff", "").replace("\r", "").replace("\u200b", "").strip()
    s = re.sub(r"\s+", " ", s)
    while s[:7].lower() == "bridge ":
        s = s[7:].lstrip()
    return s


def parse_hostport(tok: str, need_global: bool) -> Optional[Tuple[str, bool]]:
    m = HOSTPORT_RE.match(tok)
    if not m:
        return None
    v4, v6, port = m.group(1), m.group(2), int(m.group(3))
    if not 1 <= port <= 65535:
        return None
    try:
        ip = ipaddress.ip_address(v4 or v6)
    except ValueError:
        return None
    if need_global and not ip.is_global:
        return None
    if ip.is_multicast or ip.is_unspecified:
        return None
    norm = f"{ip.compressed}:{port}" if v4 else f"[{ip.compressed}]:{port}"
    return norm, bool(v6)


def classify(line: str) -> str:
    first = line.split(" ", 1)[0].lower()
    if first in KNOWN_PT:
        return first
    if first == "meek-azure":
        return "meek_lite"
    if HOSTPORT_RE.match(line.split(" ", 1)[0]):
        return "vanilla"
    return "unknown"


def normalize(line: str) -> Optional[Tuple[str, str, str, bool]]:
    """Return (canonical_line, transport, dedupe_key, is_ipv6) or None if unusable."""
    s = clean_line(line)
    if not s or s.startswith("#"):
        return None
    tr = classify(s)
    toks = s.split(" ")
    if tr == "obfs4":
        if len(toks) < 4:
            return None
        hp = parse_hostport(toks[1], True)
        if not hp or not FP_RE.match(toks[2]):
            return None
        cert = next((t[5:] for t in toks[3:] if t.startswith("cert=")), "")
        if not CERT_RE.match(cert):
            return None
        iat = next((t[9:] for t in toks[3:] if t.startswith("iat-mode=")), "0")
        if not iat.isdigit() or int(iat) > 2:
            iat = "0"
        fp = toks[2].upper()
        out = f"obfs4 {hp[0]} {fp} cert={cert} iat-mode={int(iat)}"
        return out, tr, f"obfs4|{hp[0]}|{fp}", hp[1]
    if tr == "webtunnel":
        if len(toks) < 4:
            return None
        # webtunnel's address is a placeholder by design (BridgeDB hands out [2001:db8:..] and the
        # real endpoint is the url= host), so the "must be globally routable" rule does NOT apply.
        hp = parse_hostport(toks[1], False)
        if not hp or not FP_RE.match(toks[2]):
            return None
        url = next((t[4:] for t in toks[3:] if t.startswith("url=")), "")
        if not URL_RE.match(url):
            return None
        ver = next((t[4:] for t in toks[3:] if t.startswith("ver=")), "")
        fp = toks[2].upper()
        out = f"webtunnel {hp[0]} {fp} url={url}"
        if VER_RE.match(ver):
            out += f" ver={ver}"
        return out, tr, f"webtunnel|{hp[0]}|{fp}", hp[1]
    if tr == "vanilla":
        hp = parse_hostport(toks[0], True)
        if not hp:
            return None
        if len(toks) >= 2:
            if not FP_RE.match(toks[1]):
                return None
            fp = toks[1].upper()
            return f"{hp[0]} {fp}", tr, f"vanilla|{hp[0]}|{fp}", hp[1]
        return hp[0], tr, f"vanilla|{hp[0]}|", hp[1]
    if tr in PLACEHOLDER_OK:
        if len(toks) < 2:
            return None
        hp = parse_hostport(toks[1], False)
        if not hp:
            return None
        rest = []
        for t in toks[2:]:
            rest.append(t.upper() if FP_RE.match(t) else t)
        out = " ".join([tr, hp[0]] + rest)
        return out, tr, f"{tr}|{out}", hp[1]
    return None


def orbot_valid(line: str) -> bool:
    return bool(ORBOT_OBFS4.fullmatch(line) or ORBOT_WEBTUNNEL.fullmatch(line))


# ── File helpers ───────────────────────────────────────────────────────────────
def is_bridge_text(name: str) -> bool:
    return name.endswith(".txt") or name == "snowflake_ipv6_tested"


def read_lines(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().split("\n")
    except OSError:
        return []


def write_if_changed(path: str, lines: List[str]) -> bool:
    data = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
    try:
        with open(path, "rb") as fh:
            if fh.read() == data:
                return False
    except OSError:
        pass
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return True


def sanitize_file(path: str, name: str) -> Tuple[List[str], int, int]:
    """Return (clean_lines, dropped, original_nonblank)."""
    seen = set()
    out: List[str] = []
    dropped = orig = 0
    strict = bool(STRICT_NAME.match(name))
    for raw in read_lines(path):
        if not clean_line(raw):
            continue
        orig += 1
        n = normalize(raw)
        if n is None:
            dropped += 1
            continue
        line, tr, key, _v6 = n
        if strict and not orbot_valid(line):
            dropped += 1
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
    return out, dropped, orig


def name_transport(name: str) -> Optional[str]:
    base = name.lower()
    for pref, tr in (("obfs4", "obfs4"), ("webtunnel", "webtunnel"), ("vanilla", "vanilla"),
                     ("snowflak", "snowflake"), ("meek", "meek_lite"), ("conjure", "conjure"),
                     ("tested_global_obfs4", "obfs4"), ("tested_global_webtunnel", "webtunnel"),
                     ("tested_global_vanilla", "vanilla"), ("iran_likely_working_obfs4", "obfs4"),
                     ("iran_likely_working_webtunnel", "webtunnel"),
                     ("iran_likely_working_vanilla", "vanilla"),
                     ("iran_likely_working_snowflake", "snowflake")):
        if base.startswith(pref):
            return tr
    return None


def fill_from_siblings(name: str, store: Dict[str, List[str]]) -> List[str]:
    tr = name_transport(name)
    if not tr:
        return []
    want_v6 = "_ipv6" in name and "_ipv4" not in name
    want_v4 = "_ipv4" in name and "_ipv6" not in name
    pool: List[str] = []
    for other, lines in sorted(store.items(), key=lambda kv: (len(kv[0]), kv[0])):
        if other == name or not lines or name_transport(other) != tr:
            continue
        pool.extend(lines)
    out, seen = [], set()
    for ln in pool:
        n = normalize(ln)
        if not n:
            continue
        if want_v6 and not n[3]:
            continue
        if want_v4 and n[3]:
            continue
        if n[2] in seen:
            continue
        seen.add(n[2])
        out.append(n[0])
    return out


# ── Optional online enrichment (--fetch) ───────────────────────────────────────
SEED_URLS = [
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4-ipv6",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-vanilla",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/obfs4.txt",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/obfs4_ipv6.txt",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel.txt",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel_ipv6.txt",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/vanilla.txt",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/vanilla_ipv6.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/obfs4.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/obfs4_ipv6.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/webtunnel.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/webtunnel_ipv6.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/vanilla.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/vanilla_ipv6.txt",
    "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4.txt",
    "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_ipv6.txt",
    "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel.txt",
    "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel_ipv6.txt",
    "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/vanilla.txt",
]


def source_urls(root: str) -> List[str]:
    urls = list(SEED_URLS)
    reg = os.path.join(root, "data", "ai_fusion_extra_sources.json")  # self-growing registry of the fusion job
    try:
        with open(reg, encoding="utf-8") as fh:
            for u, meta in (json.load(fh).get("urls") or {}).items():
                if u.startswith("https://") and u.endswith((".txt", ".lst", "")) and (meta or {}).get("misses", 0) < 24:
                    urls.append(u)
    except (OSError, ValueError, AttributeError):
        pass
    return list(dict.fromkeys(urls))


def fetch_extra(root: str, timeout: int = 20) -> Dict[str, List[Tuple[str, bool]]]:
    """Download public bridge lists in parallel; return {transport: [(line, is_ipv6)]} of valid, global lines."""
    import concurrent.futures as cf
    import urllib.request

    def pull(url: str) -> List[str]:
        for _ in range(2):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "bridge-sanitizer/1"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.read(8_000_000).decode("utf-8", "replace").split("\n")
            except Exception:  # noqa: BLE001 - network failures are non-fatal by design
                continue
        return []

    out: Dict[str, List[Tuple[str, bool]]] = {}
    seen = set()
    urls = source_urls(root)
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for lines in ex.map(pull, urls):
            for raw in lines:
                n = normalize(raw)
                if not n or n[2] in seen or n[1] not in ("obfs4", "webtunnel", "vanilla"):
                    continue
                seen.add(n[2])
                out.setdefault(n[1], []).append((n[0], n[3]))
    print(f"[sanitizer] fetched {sum(len(v) for v in out.values())} valid public bridges from {len(urls)} sources")
    return out


def merge_extra(bridge: str, extra: Dict[str, List[Tuple[str, bool]]], store: Dict[str, List[str]],
                dry: bool) -> Dict[str, int]:
    """Append previously unseen bridges to the canonical per-transport files."""
    added: Dict[str, int] = {}
    for tr, items in extra.items():
        known = set()
        for fname, lines in store.items():
            if name_transport(fname) == tr:
                for ln in lines:
                    n = normalize(ln)
                    if n:
                        known.add(n[2])
        fresh = [(ln, v6) for ln, v6 in items if normalize(ln)[2] not in known]  # type: ignore[index]
        if not fresh:
            continue
        for fname, want in ((f"{tr}.txt", lambda v6: not v6), (f"{tr}_ipv6.txt", lambda v6: v6),
                            (f"{tr}_ipv4_ipv6_all.txt", lambda v6: True)):
            if fname not in store and not os.path.isfile(os.path.join(bridge, fname)):
                continue
            add = [ln for ln, v6 in fresh if want(v6)]
            if not add:
                continue
            store[fname] = list(dict.fromkeys(store.get(fname, []) + add))
            added[fname] = len(add)
            if not dry:
                write_if_changed(os.path.join(bridge, fname), store[fname])
    return added


# ── Orbot export ───────────────────────────────────────────────────────────────
GOOD_PORTS = {443: 0, 80: 1, 8443: 2, 8080: 3, 993: 4, 995: 5, 465: 6, 587: 7, 8000: 8, 9001: 9}


def port_rank(line: str) -> int:
    m = re.search(r":(\d+)\s", line + " ")
    return GOOD_PORTS.get(int(m.group(1)), 50) if m else 99


def collect_orbot(bridge_dir: str) -> Dict[str, List[str]]:
    tiers = [
        "iran_likely_working_obfs4.txt", "iran_likely_working_webtunnel.txt",
        "iran_likely_working_nin.txt",
        "tested_global_obfs4.txt", "tested_global_webtunnel.txt",
        "obfs4_tested.txt", "webtunnel_tested.txt",
        "obfs4_ipv4_tested.txt", "webtunnel_ipv4_tested.txt",
        "obfs4.txt", "webtunnel.txt",
        "obfs4_ipv4_ipv6_all.txt", "webtunnel_ipv4_ipv6_all.txt",
        "obfs4_ipv6_tested.txt", "webtunnel_ipv6_tested.txt",
        "obfs4_ipv6.txt", "webtunnel_ipv6.txt",
    ]
    res: Dict[str, List[str]] = {"obfs4": [], "webtunnel": []}
    seen = set()
    for fname in tiers:
        tier_lines = []
        for raw in read_lines(os.path.join(bridge_dir, fname)):
            n = normalize(raw)
            if not n or n[1] not in res or not orbot_valid(n[0]) or n[2] in seen:
                continue
            seen.add(n[2])
            tier_lines.append((n[3], port_rank(n[0]), n[0], n[1]))
        tier_lines.sort(key=lambda t: (t[0], t[1]))  # IPv4 first, then friendly ports
        for _v6, _p, line, tr in tier_lines:
            res[tr].append(line)
    return res


def export_orbot(bridge_dir: str, export_dir: str, top_obfs4: int = 28, top_web: int = 12) -> Dict[str, int]:
    pools = collect_orbot(bridge_dir)
    o, w = pools["obfs4"], pools["webtunnel"]
    top = o[:top_obfs4] + w[:top_web]
    if len(top) < top_obfs4 + top_web:  # one transport short -> top up from the other
        extra = [x for x in o[top_obfs4:] + w[top_web:] if x not in top]
        top += extra[: top_obfs4 + top_web - len(top)]
    allv = o + w
    files = {
        "orbot_top.txt": top, "orbot_obfs4.txt": o, "orbot_webtunnel.txt": w, "orbot_all.txt": allv,
        "orbot_ipv4.txt": [x for x in allv if "[" not in x.split(" ")[1]],
        "orbot_ipv6.txt": [x for x in allv if "[" in x.split(" ")[1]],
    }
    counts: Dict[str, int] = {}
    for name, lines in files.items():
        p = os.path.join(export_dir, name)
        if not lines and os.path.isfile(p) and any(x.strip() for x in read_lines(p)):
            counts[name] = len([x for x in read_lines(p) if x.strip()])  # keep last-known-good
            continue
        for ln in lines:
            if not orbot_valid(ln):
                raise SystemExit(f"self-validation failed for {name}: {ln[:80]}")
        write_if_changed(p, lines)
        counts[name] = len(lines)
    manifest = {
        "generated_at": utcnow(),
        "purpose": "Ready to paste into Orbot > Custom Bridges (every line passes Orbot's own regex).",
        "counts": counts,
        "validator": {"obfs4": ORBOT_OBFS4.pattern, "webtunnel": ORBOT_WEBTUNNEL.pattern},
    }
    write_if_changed(os.path.join(export_dir, "orbot_manifest.json"),
                     json.dumps(manifest, indent=2, ensure_ascii=False).split("\n"))
    write_if_changed(os.path.join(export_dir, "README.md"), [
        "# Orbot-ready bridges (auto-generated every hour)", "",
        "Paste the content of `orbot_top.txt` (recommended, ~40 lines) into",
        "Orbot -> Connect -> Custom Bridges. Each line is `obfs4 ...` or `webtunnel ...`,",
        "no `Bridge` prefix, upper-case fingerprints, public addresses only.", "",
        "* `orbot_obfs4.txt` / `orbot_webtunnel.txt` - everything per transport",
        "* `orbot_ipv4.txt` / `orbot_ipv6.txt` - per IP family",
        "* `orbot_all.txt` - union", "",
        "Snowflake / Meek / Conjure / vanilla lines are not accepted by Orbot's custom-bridge",
        "dialog (use Orbot's built-in Snowflake option instead).",
    ])
    return counts


# ── Main ───────────────────────────────────────────────────────────────────────
def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--bridge-dir", default=None)
    ap.add_argument("--export-dir", default=None)
    ap.add_argument("--fetch", action="store_true", help="also pull public bridge lists (network, non-fatal)")
    ap.add_argument("--check", action="store_true", help="report only, change nothing")
    a = ap.parse_args(list(argv) if argv is not None else None)
    root = os.path.abspath(a.root)
    bridge = os.path.abspath(a.bridge_dir or os.path.join(root, "bridge"))
    export = os.path.abspath(a.export_dir or os.path.join(root, "export", "orbot"))
    if not os.path.isdir(bridge):
        print(f"[sanitizer] bridge dir not found: {bridge}", file=sys.stderr)
        return 0

    names = sorted(n for n in os.listdir(bridge) if is_bridge_text(n) and os.path.isfile(os.path.join(bridge, n)))
    store: Dict[str, List[str]] = {}
    report: Dict[str, object] = {"generated_at": utcnow(), "files": {}, "filled_from_siblings": [],
                                 "kept_last_known_good": []}
    files_rep: Dict[str, object] = report["files"]  # type: ignore[assignment]
    kept: List[str] = report["kept_last_known_good"]  # type: ignore[assignment]
    filled_rep: List[object] = report["filled_from_siblings"]  # type: ignore[assignment]
    problems = 0
    orig_files: Dict[str, int] = {}
    for name in names:
        path = os.path.join(bridge, name)
        clean, dropped, orig = sanitize_file(path, name)
        prefixed = sum(1 for r in read_lines(path) if r.strip().lower().startswith("bridge "))
        problems += dropped + prefixed
        orig_files[name] = orig
        store[name] = clean
        if not clean and orig:
            continue  # every line was junk -> try to re-fill from siblings below
        if clean:
            files_rep[name] = {"lines": len(clean), "dropped": dropped, "prefix_stripped": prefixed}
            if not a.check:
                write_if_changed(path, clean)

    if a.fetch and not a.check:
        try:
            added = merge_extra(bridge, fetch_extra(root), store, dry=False)
            report["fetched_added"] = added
        except Exception as exc:  # noqa: BLE001 - enrichment must never break publication
            print(f"[sanitizer] fetch skipped: {exc}", file=sys.stderr)

    for name in names:
        if store.get(name):
            continue
        problems += 1
        filled = fill_from_siblings(name, store)
        if filled and not a.check:
            write_if_changed(os.path.join(bridge, name), filled)
            store[name] = filled
            filled_rep.append({"file": name, "lines": len(filled)})
            files_rep[name] = {"lines": len(filled), "dropped": 0, "prefix_stripped": 0}
        elif not filled and orig_files.get(name):
            kept.append(name)  # nothing usable anywhere: keep last-known-good bytes untouched

    if a.check:
        print(f"[sanitizer] check: {problems} problem(s) across {len(names)} files")
        return 1 if problems else 0

    counts = export_orbot(bridge, export)
    report["orbot_export"] = counts
    report["total_files"] = len(names)
    report["still_empty"] = sorted(n for n in names if not store.get(n) and n not in kept)
    data_dir = os.path.join(root, "data")
    if os.path.isdir(data_dir):
        write_if_changed(os.path.join(data_dir, "bridge_sanitizer_report.json"),
                         json.dumps(report, indent=2, ensure_ascii=False).split("\n"))
    # final self-check: strict files must now be Orbot-valid
    for name in names:
        if STRICT_NAME.match(name) and name not in kept:
            for ln in read_lines(os.path.join(bridge, name)):
                if ln.strip() and not orbot_valid(ln):
                    print(f"[sanitizer] FATAL residual invalid line in {name}: {ln[:80]}", file=sys.stderr)
                    return 2
    print(f"[sanitizer] ok: {len(names)} files, orbot_top={counts.get('orbot_top.txt', 0)}, "
          f"orbot_all={counts.get('orbot_all.txt', 0)}, filled={len(filled_rep)}, "
          f"still_empty={len(report['still_empty'])}")  # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    sys.exit(main())

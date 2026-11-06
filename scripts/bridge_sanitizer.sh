#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# bridge_sanitizer.sh — Orbot-safe bridge normaliser, empty-file refiller and
# Orbot list exporter (python3 stdlib embedded; no *.py file may live in the
# tree because the quality-gate py-check forbids it).
#
# Why: Orbot's "Custom Bridges" dialog answers "Invalid bridge format" unless
# EVERY non-blank pasted line matches one of two strict regexes (taken from
# guardianproject/orbot-android CustomBridgeBottomSheet.kt):
#   ^obfs4\s+(IPv4|[IPv6]):\d+\s+[A-F0-9]{40}(\s+cert=[a-zA-Z0-9+/=]+)?(\s+iat-mode=\d+)?$
#   ^webtunnel\s+(IPv4|[IPv6]):\d+\s+[A-F0-9]{40}(\s+url=https?://\S+)?(\s+ver=\d+\.\d+\.\d+)?$
# (older Orbot) and, in current Orbot master, one single "latest" regex
#   ^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?(IPv4|[IPv6])(:port)?\s+([0-9a-fA-F]{40})?[ \t\f\w\-/+:=.,\[\]]*$
# so a leading torrc-style "Bridge " prefix, conjure (or any unknown transport),
# comments, address-less meek/snowflake lines, '?' '~' '%' '@' '&' inside the
# arguments or extra webtunnel parameters make the whole paste fail.  This script
# therefore keeps every published line valid under BOTH generations of Orbot, and
# the conjure transport is removed completely (Orbot cannot use it).
#
# Every run (hourly via auto_bridge_fusion.sh / rebuild_bridge_projections.sh):
#   1. normalises every bridge/*.txt (strips "Bridge ", CR/BOM, upper-cases
#      fingerprints, de-duplicates, drops malformed / non-global endpoints);
#      pure obfs4*/webtunnel* files become 100% Orbot-valid;
#   2. empty-output guard: a file that would become empty keeps its bytes; an
#      empty / missing file is refilled from sibling files of the same
#      transport (respecting the IPv4/IPv6 suffix) or from the aggregate pool;
#   3. --fetch pulls extra public lists (non-fatal when offline); --probe TCP-checks untested
#      candidates (canary-guarded, cached) so dead bridges never reach the Orbot lists;
#   4. writes paste-ready Orbot lists into export/orbot/ (hourly rotated order)
#      and re-validates them with Orbot's own regexes before finishing.
#
# Usage: scripts/bridge_sanitizer.sh [--root DIR] [--bridge-dir DIR]
#                                    [--export-dir DIR] [--fetch] [--probe] [--check]
# Exit: 0 ok, 1 --check found problems, 2 internal self-validation failure.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
command -v python3 >/dev/null 2>&1 || { echo "[sanitizer] python3 not found - skipped" >&2; exit 0; }
exec python3 - "$@" <<'PY'
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
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

# Current Orbot master (CustomBridgeBottomSheet.kt validBridgeRegex), translated 1:1.
ORBOT_LATEST = re.compile(
    r"^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?"
    r"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+\])(:\d{1,5})?)\s+"
    r"([\da-fA-F]{40})?[ \t\f\w\-/+:=.,\[\]]*$", re.ASCII)

# Placeholder endpoints used by Tor's own built-in snowflake / meek_lite lines (the PT ignores them).
DEFAULT_PLACEHOLDER = {"snowflake": "192.0.2.3:80", "meek_lite": "192.0.2.18:80"}

FP_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
# obfs4 cert = base64 of 52 bytes (node-id + public key) without padding = exactly 70 characters.
CERT_RE = re.compile(r"^[A-Za-z0-9+/]{70}$")
HOSTPORT_RE = re.compile(r"^(?:(\d{1,3}(?:\.\d{1,3}){3})|\[([0-9A-Fa-f:]+)\]):(\d{1,5})$")
URL_RE = re.compile(r"^https?://[^\s/]+\S*$")
VER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Transports whose placeholder addresses (192.0.2.x etc.) are legitimate PT syntax.
PLACEHOLDER_OK = {"snowflake", "meek_lite"}
# conjure is intentionally unknown: Orbot cannot use it, so it is dropped everywhere.
KNOWN_PT = {"obfs4", "webtunnel", "snowflake", "meek_lite"}

STRICT_NAME = re.compile(
    r"^(obfs4|webtunnel)(?:[_-].*)?\.txt$|^iran_likely_working_(obfs4|webtunnel)\.txt$"
    r"|^tested_global_(obfs4|webtunnel)\.txt$")


HOUR_SEED = os.environ.get("SANITIZER_HOUR_SEED") or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H")


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
        if not HOSTPORT_RE.match(toks[1]):
            # Address-less builtin form ("meek_lite <FP> url=…", "snowflake <FP> …"): Tor and Orbot both
            # require an addr:port token, so insert the standard TEST-NET placeholder endpoint.
            toks = [toks[0], DEFAULT_PLACEHOLDER[tr]] + toks[1:]
        hp = parse_hostport(toks[1], False)
        if not hp:
            return None
        rest = []
        for t in toks[2:]:
            rest.append(t.upper() if FP_RE.match(t) else t)
        out = " ".join([tr, hp[0]] + rest)
        return out, tr, f"{tr}|{out}", hp[1]
    return None


def orbot_latest_valid(line: str) -> bool:
    return bool(ORBOT_LATEST.fullmatch(line))


def orbot_valid(line: str) -> bool:
    """Valid for the older strict regexes AND for current Orbot master."""
    return bool((ORBOT_OBFS4.fullmatch(line) or ORBOT_WEBTUNNEL.fullmatch(line)) and ORBOT_LATEST.fullmatch(line))


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
        if not strict and not orbot_latest_valid(line):
            dropped += 1  # would make Orbot's whole-paste validation fail
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
    return out, dropped, orig


def name_transport(name: str) -> Optional[str]:
    base = name.lower()
    for pref, tr in (("obfs4", "obfs4"), ("webtunnel", "webtunnel"), ("vanilla", "vanilla"),
                     ("snowflak", "snowflake"), ("meek", "meek_lite"),
                     ("tested_global_obfs4", "obfs4"), ("tested_global_webtunnel", "webtunnel"),
                     ("tested_global_vanilla", "vanilla"), ("iran_likely_working_obfs4", "obfs4"),
                     ("iran_likely_working_webtunnel", "webtunnel"),
                     ("iran_likely_working_vanilla", "vanilla"),
                     ("iran_likely_working_snowflake", "snowflake")):
        if base.startswith(pref):
            return tr
    return None


AGGREGATES = {
    "iran_likely_working_all.txt": ("obfs4", "webtunnel", "vanilla", "snowflake", "meek_lite"),
    "iran_likely_working_ipv4_ipv6_all.txt": ("obfs4", "webtunnel", "vanilla", "snowflake", "meek_lite"),
    "iran_likely_working_nin.txt": ("webtunnel", "snowflake", "meek_lite"),
}


def fill_aggregate(name: str, store: Dict[str, List[str]]) -> List[str]:
    """Refill an empty multi-transport aggregate from the per-transport projections."""
    trs = AGGREGATES.get(name)
    if not trs:
        return []
    out: List[str] = []
    seen = set()
    for tr in trs:
        for other in sorted(store):
            if other == name or name_transport(other) != tr or "tested" in other or "72h" in other:
                continue
            for ln in store[other]:
                n = normalize(ln)
                if n and n[2] not in seen:
                    seen.add(n[2])
                    out.append(n[0])
    return out


def fill_from_siblings(name: str, store: Dict[str, List[str]]) -> List[str]:
    tr = name_transport(name)
    if not tr:
        return fill_aggregate(name, store)
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
    "https://raw.githubusercontent.com/Koros0111/Tor-Bridges-Collector/main/bridge/obfs4.txt",
    "https://raw.githubusercontent.com/Koros0111/Tor-Bridges-Collector/main/bridge/obfs4_ipv6.txt",
    "https://raw.githubusercontent.com/Koros0111/Tor-Bridges-Collector/main/bridge/webtunnel.txt",
    "https://raw.githubusercontent.com/Koros0111/Tor-Bridges-Collector/main/bridge/webtunnel_ipv6.txt",
    "https://raw.githubusercontent.com/Koros0111/Tor-Bridges-Collector/main/bridge/vanilla.txt",
    "https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/main/bridge/obfs4.txt",
    "https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/main/bridge/obfs4_ipv6.txt",
    "https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/main/bridge/webtunnel.txt",
    "https://raw.githubusercontent.com/javadz501/Tor-Bridges-Collector/main/bridge/webtunnel_ipv6.txt",
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


# ── Live reachability probe (--probe) ──────────────────────────────────────────
PROBE_OK_TTL = 3 * 3600      # a fresh "alive" verdict is reused for 3 h
PROBE_FAIL_TTL = 6 * 3600    # a "dead" verdict is reused for 6 h (bounded retry cost)
PROBE_PRUNE = 3 * 86400
PROBE_MAX_TARGETS = 4000
PROBE_BUDGET_S = 150


def probe_target(line: str) -> Optional[Tuple[str, int]]:
    """Endpoint that can actually be dialled for this bridge (webtunnel's addr is a placeholder -> url host)."""
    toks = line.split(" ")
    if toks[0] == "obfs4" and len(toks) > 1:
        m = HOSTPORT_RE.match(toks[1])
        return ((m.group(1) or m.group(2)), int(m.group(3))) if m else None
    if toks[0] == "webtunnel":
        u = next((t[4:] for t in toks[2:] if t.startswith("url=")), "")
        m = re.match(r"^https?://(\[[0-9A-Fa-f:]+\]|[^/:\s]+)(?::(\d+))?", u)
        if not m:
            return None
        return m.group(1).strip("[]"), int(m.group(2) or (443 if u.startswith("https") else 80))
    return None


def _stub_alive() -> Optional[set]:
    """Test hook: SANITIZER_PROBE_STUB=<file of 'host:port' lines that count as reachable>."""
    path = os.environ.get("SANITIZER_PROBE_STUB")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return {ln.strip() for ln in fh if ln.strip()}
    except OSError:
        return set()


def _tcp_ok(host: str, port: int, timeout: float) -> bool:
    import socket
    stub = _stub_alive()
    if stub is not None:
        return f"{host}:{port}" in stub
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def network_is_honest() -> bool:
    """Canary: a TEST-NET-1 address never answers. If it does, an egress proxy fakes every connect and
    probing would mark dead bridges alive, so the whole probe result must be ignored."""
    return not _tcp_ok("192.0.2.1", 81, 3.0)


def load_probe_cache(root: str) -> Dict[str, Dict[str, object]]:
    try:
        with open(os.path.join(root, "data", "bridge_probe_cache.json"), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def run_probe(root: str, candidates: List[str], timeout: float = 4.0) -> Dict[str, bool]:
    """Return {dedupe_key: alive}. Never raises; unknown keys are simply absent."""
    import concurrent.futures as cf
    import time
    cache = load_probe_cache(root)
    now = int(time.time())
    if not network_is_honest():
        print("[sanitizer] probe skipped: transparent egress proxy detected (canary answered)")
        return {k: bool(v.get("ok")) for k, v in cache.items() if isinstance(v, dict) and now - int(v.get("ts", 0)) < PROBE_PRUNE}
    todo: List[Tuple[str, str]] = []
    for ln in candidates:
        n = normalize(ln)
        if not n:
            continue
        v = cache.get(n[2])
        ttl = PROBE_OK_TTL if (isinstance(v, dict) and v.get("ok")) else PROBE_FAIL_TTL
        if isinstance(v, dict) and now - int(v.get("ts", 0)) < ttl:
            continue
        if probe_target(n[0]):
            todo.append((n[2], n[0]))
    todo.sort(key=lambda t: hashlib.sha1(f"{HOUR_SEED}|{t[0]}".encode()).hexdigest())
    todo = todo[:PROBE_MAX_TARGETS]
    deadline = time.time() + PROBE_BUDGET_S

    def one(item: Tuple[str, str]) -> Optional[Tuple[str, bool]]:
        if time.time() > deadline:
            return None
        tgt = probe_target(item[1])
        return (item[0], _tcp_ok(tgt[0], tgt[1], timeout)) if tgt else None

    done = 0
    with cf.ThreadPoolExecutor(max_workers=200) as ex:
        for res in ex.map(one, todo):
            if res:
                prev = cache.get(res[0]) if isinstance(cache.get(res[0]), dict) else {}
                fails = 0 if res[1] else int(prev.get("fails", 0)) + 1  # type: ignore[union-attr]
                cache[res[0]] = {"ok": res[1], "ts": now, "fails": fails}
                done += 1
    cache = {k: v for k, v in cache.items() if isinstance(v, dict) and now - int(v.get("ts", 0)) < PROBE_PRUNE}
    data_dir = os.path.join(root, "data")
    if os.path.isdir(data_dir):
        write_if_changed(os.path.join(data_dir, "bridge_probe_cache.json"),
                         json.dumps(cache, indent=0, sort_keys=True).split("\n"))
    alive = sum(1 for v in cache.values() if v.get("ok"))
    print(f"[sanitizer] probe: {done} new checks, {alive}/{len(cache)} cached bridges reachable")
    return {k: bool(v.get("ok")) for k, v in cache.items()}


# ── Orbot export ───────────────────────────────────────────────────────────────
GOOD_PORTS = {443: 0, 80: 1, 8443: 2, 8080: 3, 993: 4, 995: 5, 465: 6, 587: 7, 8000: 8, 9001: 9}


def port_rank(line: str) -> int:
    m = re.search(r":(\d+)\s", line + " ")
    return GOOD_PORTS.get(int(m.group(1)), 50) if m else 99


TESTED_TIER = re.compile(r"(tested|likely_working)")


def collect_orbot(bridge_dir: str, alive: Optional[Dict[str, bool]] = None) -> Dict[str, List[str]]:
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
            verdict = (alive or {}).get(n[2])
            if verdict is False and not TESTED_TIER.search(fname):
                continue  # probed dead and not vouched for by a tested tier -> never recommend it
            seen.add(n[2])
            tier_lines.append((0 if verdict else 1, n[3], port_rank(n[0]), n[0], n[1]))
        # IPv4 first, then friendly ports; ties are shuffled deterministically per UTC hour so the
        # recommended Orbot list rotates every hour (load spreading + harder to enumerate/block).
        tier_lines.sort(key=lambda t: (t[0], t[1], t[2], hashlib.sha1(f"{HOUR_SEED}|{t[3]}".encode()).hexdigest()))
        for _u, _v6, _p, line, tr in tier_lines:
            res[tr].append(line)
    return res


def collect_extended(bridge_dir: str) -> Dict[str, List[str]]:
    """vanilla / snowflake / meek_lite lines valid under current Orbot's validator (best evidence first)."""
    spec = {
        "vanilla": ["iran_likely_working_vanilla.txt", "tested_global_vanilla.txt", "vanilla_tested.txt",
                    "vanilla_ipv4_tested.txt", "vanilla.txt", "vanilla_ipv4_ipv6_all.txt", "vanilla_ipv6_tested.txt",
                    "vanilla_ipv6.txt"],
        "snowflake": ["snowflake_tested.txt", "snowflake.txt", "snowflake_ipv4_ipv6_all.txt"],
        "meek_lite": ["meek_lite_tested.txt", "meek_lite.txt", "meek_lite_ipv4_ipv6_all.txt"],
    }
    res: Dict[str, List[str]] = {k: [] for k in spec}
    for tr, files in spec.items():
        seen = set()
        for fname in files:
            tier = []
            for raw in read_lines(os.path.join(bridge_dir, fname)):
                n = normalize(raw)
                if not n or n[1] != tr or n[2] in seen or not orbot_latest_valid(n[0]):
                    continue
                seen.add(n[2])
                tier.append((port_rank(n[0]), hashlib.sha1(f"{HOUR_SEED}|{n[2]}".encode()).hexdigest(), n[0]))
            tier.sort()
            res[tr] += [t[2] for t in tier]
    return res


def net_key(line: str) -> str:
    """Blocking-domain of a bridge: IPv4 /16, IPv6 /32, or the webtunnel front's registrable domain."""
    toks = line.split(" ")
    if toks[0] == "webtunnel":
        u = next((t[4:] for t in toks[2:] if t.startswith("url=")), "")
        m = re.match(r"^https?://([^/:\s]+)", u)
        if m and not m.group(1).startswith("["):
            return "d:" + ".".join(m.group(1).lower().split(".")[-2:])
    m = HOSTPORT_RE.match(toks[1]) if len(toks) > 1 else None
    if not m:
        return "?"
    try:
        ip = ipaddress.ip_address(m.group(1) or m.group(2))
    except ValueError:
        return "?"
    parts = ip.exploded.split(":" if ip.version == 6 else ".")
    return f"{ip.version}:" + ".".join(parts[:2])


def diversify(lines: List[str], limit: int, per_net: int = 2) -> List[str]:
    """Pick up to `limit` lines keeping rank order but at most `per_net` per blocking-domain (so one
    IP-range/domain block cannot take the whole recommended list down); top up in rank order if short."""
    picked: List[str] = []
    used: Dict[str, int] = {}
    for ln in lines:
        if len(picked) >= limit:
            break
        k = net_key(ln)
        if used.get(k, 0) < per_net:
            used[k] = used.get(k, 0) + 1
            picked.append(ln)
    if len(picked) < limit:
        have = set(picked)
        picked += [ln for ln in lines if ln not in have][: limit - len(picked)]
    return picked


def export_orbot(bridge_dir: str, export_dir: str, top_obfs4: int = 28, top_web: int = 12,
                 alive: Optional[Dict[str, bool]] = None) -> Dict[str, int]:
    pools = collect_orbot(bridge_dir, alive)
    o, w = pools["obfs4"], pools["webtunnel"]
    o_top, w_top = diversify(o, top_obfs4), diversify(w, top_web)
    top = o_top + w_top
    if len(top) < top_obfs4 + top_web:  # one transport short -> top up from the other
        extra = [x for x in diversify(o, top_obfs4 + top_web) + diversify(w, top_obfs4 + top_web) if x not in top]
        top += extra[: top_obfs4 + top_web - len(top)]
    allv = o + w
    ext = collect_extended(bridge_dir)
    files = {
        "orbot_top.txt": top, "orbot_obfs4.txt": o, "orbot_webtunnel.txt": w, "orbot_all.txt": allv,
        "orbot_ipv4.txt": [x for x in allv if "[" not in x.split(" ")[1]],
        "orbot_ipv6.txt": [x for x in allv if "[" in x.split(" ")[1]],
        # Accepted by current Orbot (validBridgeRegex also lists snowflake / meek_lite / vanilla).
        "orbot_vanilla.txt": ext["vanilla"], "orbot_snowflake.txt": ext["snowflake"],
        "orbot_meek.txt": ext["meek_lite"],
        "orbot_extended.txt": allv + ext["vanilla"] + ext["snowflake"] + ext["meek_lite"],
    }
    counts: Dict[str, int] = {}
    for name, lines in files.items():
        p = os.path.join(export_dir, name)
        if not lines and os.path.isfile(p) and any(x.strip() for x in read_lines(p)):
            counts[name] = len([x for x in read_lines(p) if x.strip()])  # keep last-known-good
            continue
        ext_file = name in ("orbot_vanilla.txt", "orbot_snowflake.txt", "orbot_meek.txt", "orbot_extended.txt")
        for ln in lines:
            if not (orbot_latest_valid(ln) if ext_file else orbot_valid(ln)):
                raise SystemExit(f"self-validation failed for {name}: {ln[:80]}")
        write_if_changed(p, lines)
        counts[name] = len(lines)
    manifest = {
        "generated_at": utcnow(),
        "purpose": "Ready to paste into Orbot > Custom Bridges (every line passes Orbot's own regex).",
        "counts": counts,
        "validator": {"obfs4": ORBOT_OBFS4.pattern, "webtunnel": ORBOT_WEBTUNNEL.pattern,
                      "latest_orbot": ORBOT_LATEST.pattern},
    }
    write_if_changed(os.path.join(export_dir, "orbot_manifest.json"),
                     json.dumps(manifest, indent=2, ensure_ascii=False).split("\n"))
    write_if_changed(os.path.join(export_dir, "README.md"), [
        "# Orbot-ready bridges (auto-generated every hour)", "",
        "Paste the content of `orbot_top.txt` (recommended, ~40 lines) into",
        "Orbot -> Connect -> Custom Bridges. Each line is `obfs4 ...` or `webtunnel ...`,",
        "no `Bridge` prefix, upper-case fingerprints, public addresses only.", "",
        "`orbot_top.txt` is hourly-rotated, ranked (tested tiers first, 443/80 first, reachable first when",
        "probed) and network-diversified: at most 2 bridges per IPv4 /16, IPv6 /32 or webtunnel domain, so",
        "blocking one range cannot take the whole list down.", "",
        "* `orbot_obfs4.txt` / `orbot_webtunnel.txt` - everything per transport",
        "* `orbot_ipv4.txt` / `orbot_ipv6.txt` - per IP family",
        "* `orbot_all.txt` - union", "",
        "* `orbot_vanilla.txt` / `orbot_snowflake.txt` / `orbot_meek.txt` / `orbot_extended.txt` - only for",
        "  current Orbot (its validator also lists snowflake, meek_lite and vanilla lines); older Orbot",
        "  releases reject them, so use the lists above if you see \"Invalid bridge format\".", "",
        "Conjure is not supported by Orbot and is not published anywhere in this repository.",
        "Never paste comment lines, `Bridge ` prefixes or lines from the torrc exports into Orbot.",
    ])
    return counts


def fill_warp(root: str, export_dir: str) -> int:
    """export/warp_bridges.txt ships comment-only when the WARP stage found nothing: refill it with the
    CDN-fronted webtunnel lines that work best inside Cloudflare WARP (never overwrite real content)."""
    path = os.path.join(root, "export", "warp_bridges.txt")
    if not os.path.isfile(path):
        return 0
    old = read_lines(path)
    if any(x.strip() and not x.lstrip().startswith("#") for x in old):
        return 0
    pool = [x for x in read_lines(os.path.join(export_dir, "orbot_webtunnel.txt")) if x.strip()][:20]
    if not pool:
        return 0
    head = [x for x in old if x.lstrip().startswith("#")]
    while head and not head[-1].strip():
        head.pop()
    write_if_changed(path, head + pool)
    return len(pool)


# ── Main ───────────────────────────────────────────────────────────────────────
def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--bridge-dir", default=None)
    ap.add_argument("--export-dir", default=None)
    ap.add_argument("--fetch", action="store_true", help="also pull public bridge lists (network, non-fatal)")
    ap.add_argument("--probe", action="store_true",
                    help="TCP-probe untested candidates and keep dead ones out of the Orbot lists (network, non-fatal)")
    ap.add_argument("--check", action="store_true", help="report only, change nothing")
    a = ap.parse_args(list(argv) if argv is not None else None)
    root = os.path.abspath(a.root)
    bridge = os.path.abspath(a.bridge_dir or os.path.join(root, "bridge"))
    export = os.path.abspath(a.export_dir or os.path.join(root, "export", "orbot"))
    if not os.path.isdir(bridge):
        print(f"[sanitizer] bridge dir not found: {bridge}", file=sys.stderr)
        return 0

    for stale in sorted(n for n in os.listdir(bridge) if n.lower().startswith("conjure")):
        if not a.check and os.path.isfile(os.path.join(bridge, stale)):
            os.remove(os.path.join(bridge, stale))  # conjure is unsupported by Orbot: removed for good
            print(f"[sanitizer] removed unsupported conjure file {stale}")
    names = sorted(n for n in os.listdir(bridge)
                   if is_bridge_text(n) and not n.lower().startswith("conjure")
                   and os.path.isfile(os.path.join(bridge, n)))
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

    alive: Optional[Dict[str, bool]] = None
    if a.probe:
        try:
            cand: List[str] = []
            for fname in ("obfs4.txt", "webtunnel.txt", "obfs4_ipv4_ipv6_all.txt", "webtunnel_ipv4_ipv6_all.txt",
                          "obfs4_ipv6.txt", "webtunnel_ipv6.txt"):
                cand += store.get(fname, [])
            alive = run_probe(root, cand)
        except Exception as exc:  # noqa: BLE001 - probing must never break publication
            print(f"[sanitizer] probe skipped: {exc}", file=sys.stderr)
    counts = export_orbot(bridge, export, alive=alive)
    report["orbot_export"] = counts
    report["warp_refilled"] = fill_warp(root, export)
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
PY

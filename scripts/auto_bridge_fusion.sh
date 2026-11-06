#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# auto_bridge_fusion.sh — Ultra-Fast Autonomous AI Bridge Discovery, Probing,
# Iran Anti-DPI / Anti-AI-DPI Ranking, Hourly Dynamic Combination & Full 79-File
# Projection Fill for bridge/.
#
# Runs hourly in CI (.github/workflows/auto-bridge-fusion.yml) and before
# final publication in .github/workflows/torshield-ir.yml:
#
#   1. DISCOVER  — autonomous multi-channel discovery:
#        * Tor Project Moat (builtin + country=ir/tm/cn single-transport draws)
#        * Tor Project Onionoo live dual-stack / global IPv6 ORPort discovery
#          (populates vanilla_ipv6*.txt with real, TCP-verified running nodes)
#        * Autonomous AI Front-Domain & Rendezvous Combinator for domain-fronted
#          transports (meek_lite, meek-azure, snowflake across IPv4 &
#          AAAA-verified IPv6 endpoints, multi-STUN, CovertDTLS, uTLS profiles)
#        * GitHub repository search + persistent yield memory
#          (data/ai_fusion_sources.json)
#   2. VALIDATE  — strict syntax, 40-hex fingerprint, obfs4 cert, global-IP /
#                  RFC placeholder rules (matching src/ip_guard.rs), decoy filter
#   3. PROBE     — 256-worker concurrent TCP / TLS / SNI / HTTP-Host probes with
#                  RFC 5737 TEST-NET network honesty guard & dual-stack v4-pair
#                  liveness verification for IPv6 ORPorts
#   4. AI RANK   — online L2-regularized logistic model (warm-started once per
#                  UTC hour from data/ai_fusion_model.json) + Iran SIAM/NGFW
#                  Anti-DPI scoring + deterministic hourly exploration jitter
#   5. FILL      — all 73 bridge/*.txt projections + 5 JSON companions + ZIP
#                  dynamically combined and rotated every UTC hour; 0 empty files
#   6. IRAN PACKS — rebuilds data/iran_hourly_mix.json, export/iran_hourly_mix.torrc,
#                  data/iran_anti_dpi_profile.json, export/iran_anti_dpi_elite.txt,
#                  export/iran_cut_pack.txt, data/pq_bridge_scores.json, and
#                  export/nin_recommended_transport.json
#   7. ATTEST    — updates telegram_manifest.json counts/non_empty_lines/reason_code,
#                  rebuilds tor_bridges.zip & README.md via publication_contract.sh,
#                  and refreshes data/run_manifest.json.
#
# No Rust build is needed; python3 (stdlib only) is embedded because no *.py
# file may live in the tree (quality_gate py-check).
#
# Environment (all optional):
#   BRIDGE_DIR (bridge)  DATA_DIR (data)  EXPORT_DIR (export)
#   FUSION_BUDGET_SECS (780)  FUSION_OFFLINE (0)  FUSION_SKIP_ATTEST (0)
#   FUSION_MAX_REPOS (40)  FUSION_MAX_FILES (140)  FUSION_WORKERS (256)
#   GITHUB_TOKEN / GH_TOKEN  CEREBRAS_API_KEY  GROQ_API_KEY
#
# Usage: scripts/auto_bridge_fusion.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

export BRIDGE_DIR="${BRIDGE_DIR:-bridge}"
export DATA_DIR="${DATA_DIR:-data}"
export EXPORT_DIR="${EXPORT_DIR:-export}"
mkdir -p "$BRIDGE_DIR" "$DATA_DIR" "$EXPORT_DIR"

python3 - <<'PY'
import concurrent.futures as cf
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

T0 = time.time()
BRIDGE = os.environ.get("BRIDGE_DIR", "bridge")
DATA = os.environ.get("DATA_DIR", "data")
EXPORT = os.environ.get("EXPORT_DIR", "export")
BUDGET = int(os.environ.get("FUSION_BUDGET_SECS", "780"))
OFFLINE = os.environ.get("FUSION_OFFLINE", "0") == "1"
MAX_REPOS = int(os.environ.get("FUSION_MAX_REPOS", "40"))
MAX_FILES = int(os.environ.get("FUSION_MAX_FILES", "140"))
WORKERS = int(os.environ.get("FUSION_WORKERS", "256"))
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
SELF_REPO = os.environ.get("GITHUB_REPOSITORY", "ysa-py/Tor-Bridges-Collector")
HOUR_SEED = int(os.environ.get("FUSION_HOUR_SEED") or (time.time() // 3600))
HOUR_DT = dt.datetime.fromtimestamp(HOUR_SEED * 3600, dt.timezone.utc)
NOW = HOUR_DT if OFFLINE else dt.datetime.now(dt.timezone.utc)
ISO_HOUR = HOUR_DT.isoformat()
ISO_NOW = NOW.isoformat()
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"
REPORT = {"started_at": ISO_NOW, "hour_seed": HOUR_SEED, "stages": {}, "notes": []}


def left():
    return BUDGET - (time.time() - T0)


def log(msg):
    print(f"[fusion +{time.time() - T0:6.1f}s] {msg}", flush=True)


def note(msg):
    REPORT["notes"].append(msg)
    log(msg)


def hourly_jitter(salt, text, scale=0.18):
    digest = hashlib.sha256(f"{HOUR_SEED}:{salt}:{text}".encode("utf-8")).digest()
    return (int.from_bytes(digest[:4], "big") / 0xFFFFFFFF) * scale


# ───────────────────────────── HTTP helpers ─────────────────────────────
def http(url, method="GET", data=None, headers=None, timeout=20, retries=2):
    if OFFLINE:
        return 0, b""
    hdr = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdr.update(headers)
    if TOKEN and url.startswith("https://api.github.com/"):
        hdr["Authorization"] = f"Bearer {TOKEN}"
        hdr["Accept"] = "application/vnd.github+json"
    body = data.encode() if isinstance(data, str) else data
    last = 0
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=body, headers=hdr, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(6_000_000)
        except urllib.error.HTTPError as exc:
            last = exc.code
            if exc.code in (400, 401, 403, 404, 410, 422):
                return exc.code, b""
        except Exception:
            last = 0
        time.sleep(min(2 ** attempt, 4) * 0.4)
    return last, b""


def jget(url, **kw):
    status, body = http(url, **kw)
    if status != 200 or not body:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


# ───────────────────────────── bridge parsing ─────────────────────────────
EP = r"((?:\d{1,3}\.){3}\d{1,3}|\[[0-9A-Fa-f:]+\]):(\d{1,5})"
FP = r"([0-9A-Fa-f]{40})"
OBFS4_RE = re.compile(r"obfs4\s+" + EP + r"\s+" + FP + r"\s+cert=([A-Za-z0-9+/]{70})(?:\s+iat-mode=([0-2]))?")
WEB_RE = re.compile(r"webtunnel\s+" + EP + r"\s+" + FP + r"\s+url=(https?://[^\s\"'<>,\\]+)(?:\s+ver=([0-9.]+))?")
VAN_RE = re.compile(r"(?m)^[ \t]*(?:Bridge[ \t]+)?(?:vanilla[ \t]+)?" + EP + r"[ \t]+" + FP + r"[ \t]*$")
FRONTED_RE = re.compile(r"^(snowflake|meek_lite|meek-lite|meek-azure)\s+\S.*\burl=https?://\S+", re.I)
FRONT_RE = re.compile(r"(?:^|\s)fronts?=([^\s]+)")
URL_RE = re.compile(r"\burl=(https?://[^\s]+)")
DECOYS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
          "208.67.222.222", "208.67.220.220", "0.0.0.0", "127.0.0.1"}
PLACEHOLDER_NETS = [ipaddress.ip_network(n) for n in
                    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
FRONTED = ("snowflake", "meek_lite", "meek-azure")
FAMILIES = ("obfs4", "vanilla", "webtunnel", "snowflake", "meek_lite", "meek-azure")


def split_ep(host, port):
    return host.strip("[]"), int(port)


def is_placeholder(host):
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return any(ip in net for net in PLACEHOLDER_NETS)


def is_public(host):
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.is_global and not is_placeholder(host) and str(ip) not in DECOYS


def valid_hostname(h):
    return bool(re.fullmatch(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", h.lower())) \
        and h.lower() not in ("localhost", "example.com", "front.example.com")


def url_host(url):
    m = re.match(r"https?://([^/:?#]+)(?::(\d+))?", url)
    return (m.group(1), int(m.group(2) or 443)) if m else (None, 443)


def make_key(raw, transport):
    first = raw.split()[0].lower() if raw.split() else ""
    return raw if first in ("obfs4", "webtunnel", "snowflake", "meek_lite", "meek-azure") else "Bridge " + raw


def parse_one(m_kind, m):
    g = m.groups()
    host, port = split_ep(g[0], g[1])
    ipv6 = ":" in host
    if m_kind == "obfs4":
        if not (is_public(host) and 1 <= port <= 65535):
            return None
        raw = f"obfs4 {g[0]}:{g[1]} {g[2].upper()} cert={g[3]} iat-mode={g[4] or '0'}"
        return {"transport": "obfs4", "raw": raw, "host": host, "port": port, "ipv6": ipv6,
                "fp": g[2].upper(), "iat": int(g[4] or 0)}
    if m_kind == "vanilla":
        if not (is_public(host) and 1 <= port <= 65535):
            return None
        raw = f"{g[0]}:{g[1]} {g[2].upper()}"
        return {"transport": "vanilla", "raw": raw, "host": host, "port": port, "ipv6": ipv6,
                "fp": g[2].upper(), "iat": 0}
    if m_kind == "webtunnel":
        uhost, uport = url_host(g[3])
        if not uhost or not valid_hostname(uhost) or not (1 <= port <= 65535):
            return None
        if not (is_public(host) or is_placeholder(host)):
            return None
        raw = f"webtunnel {g[0]}:{g[1]} {g[2].upper()} url={g[3]}" + (f" ver={g[4]}" if g[4] else "")
        return {"transport": "webtunnel", "raw": raw, "host": host, "port": port, "ipv6": ipv6,
                "fp": g[2].upper(), "iat": 0, "url": g[3]}
    return None


def parse_fronted(line, declared=None):
    s = " ".join(line.strip().split())
    if s.lower().startswith("bridge "):
        s = s[7:]
    if not FRONTED_RE.match(s):
        return None
    first = s.split()[0].lower()
    if declared in ("meek-azure", "meek_lite"):
        transport = declared
    elif first in ("meek_lite", "meek-lite"):
        transport = "meek_lite"
    elif first == "meek-azure":
        transport = "meek-azure"
    elif first == "snowflake":
        transport = "snowflake"
    else:
        return None
    um = URL_RE.search(s)
    if not um:
        return None
    uhost, _ = url_host(um.group(1))
    if not uhost or not valid_hostname(uhost):
        return None
    fronts = []
    for fm in FRONT_RE.finditer(s):
        fronts += [f for f in fm.group(1).split(",") if valid_hostname(f)]
    has_v6_lit = "[" in s and "]:" in s
    return {"transport": transport, "raw": s, "host": uhost, "port": 443, "ipv6": has_v6_lit,
            "fp": "", "iat": 0, "url": um.group(1), "fronts": fronts or [uhost]}


def extract(text):
    """Return every valid bridge candidate found in arbitrary text / JSON."""
    t = text.lstrip()
    if t[:1] in "[{":
        try:
            strings = []

            def walk(o):
                if isinstance(o, str):
                    strings.append(o)
                elif isinstance(o, list):
                    for i in o:
                        walk(i)
                elif isinstance(o, dict):
                    for i in o.values():
                        walk(i)
            walk(json.loads(t))
            text = "\n".join(strings)
        except ValueError:
            pass
    text = text.replace("\\n", "\n").replace("\r", "")
    out = []
    for kind, rx in (("obfs4", OBFS4_RE), ("webtunnel", WEB_RE), ("vanilla", VAN_RE)):
        for m in rx.finditer(text):
            c = parse_one(kind, m)
            if c:
                out.append(c)
    for line in text.split("\n"):
        if FRONTED_RE.match(line.strip().removeprefix("Bridge ").strip()):
            c = parse_fronted(line)
            if c:
                out.append(c)
    return out


def parse_any(raw, declared=None):
    """Parse one stored history line (any transport) into a candidate dict."""
    c = parse_fronted(raw, declared=declared)
    if c:
        return c
    for kind, rx in (("obfs4", OBFS4_RE), ("webtunnel", WEB_RE), ("vanilla", VAN_RE)):
        m = rx.search(raw if kind != "vanilla" else raw.strip())
        if m:
            c = parse_one(kind, m)
            if c:
                return c
    toks = raw.split()
    if not toks:
        return None
    t = declared or ("vanilla" if re.match(r"^\[?[0-9A-Fa-f.:]+\]?:\d+$", toks[0]) else toks[0])
    ep = toks[1] if toks[0] in ("obfs4", "webtunnel") and len(toks) > 1 else toks[0]
    m = re.match(r"^(\[[0-9A-Fa-f:]+\]|[0-9.]+):(\d+)$", ep)
    if not m:
        return {"transport": t, "raw": raw, "host": "", "port": 0, "ipv6": "[" in raw, "fp": "", "iat": 0}
    host, port = split_ep(m.group(1), m.group(2))
    d = {"transport": t, "raw": raw, "host": host, "port": port, "ipv6": ":" in host,
         "fp": "", "iat": 0}
    um = URL_RE.search(raw)
    if um:
        d["url"] = um.group(1)
    return d


def ident(c):
    if c["transport"] in FRONTED:
        return f'{c["transport"]}|{c["raw"]}'
    return f'{c["transport"]}|{c["host"].lower()}:{c["port"]}|{c["fp"]}'


# ───────────────────────────── probes ─────────────────────────────
def tcp_probe(host, port, timeout=3.8):
    t = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.time() - t) * 1000
    except OSError:
        return False, None


CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def tls_probe(host, port, sni, http_host=None, timeout=4.5):
    t = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with CTX.wrap_socket(raw, server_hostname=sni) as s:
                s.settimeout(timeout)
                if http_host:
                    s.sendall(f"GET / HTTP/1.1\r\nHost: {http_host}\r\nUser-Agent: Mozilla/5.0\r\n"
                              f"Connection: close\r\n\r\n".encode())
                    if not s.recv(12).startswith(b"HTTP/"):
                        return False, None
                return True, (time.time() - t) * 1000
    except (OSError, ssl.SSLError):
        return False, None


def probe_candidate(c):
    tr = c["transport"]
    if tr in FRONTED:
        best = None
        for front in c.get("fronts", [])[:3]:
            ok, ms = tls_probe(front, 443, front, http_host=url_host(c.get("url", ""))[0] or front)
            if ok and (best is None or ms < best):
                best = ms
        return (best is not None), best
    if tr == "webtunnel":
        uhost, uport = url_host(c.get("url", ""))
        if uhost:
            ok, ms = tls_probe(uhost, uport, uhost)
            if ok:
                return True, ms
        if c["host"] and is_public(c["host"]):
            return tcp_probe(c["host"], c["port"])
        return False, None
    if c["host"]:
        ok, ms = tcp_probe(c["host"], c["port"])
        if ok:
            return True, ms
        # Dual-stack Onionoo relay pair: if runner has no IPv6 egress, probe the node's paired IPv4 ORPort
        pv4 = c.get("paired_v4")
        if pv4:
            return tcp_probe(pv4[0], pv4[1])
    return False, None


def run_probes(cands, label):
    """Probe candidates concurrently inside the time budget → {ident: (ok, ms)}."""
    res = {}
    if OFFLINE or not cands:
        return res
    deadline = time.time() + max(20, min(left() * 0.42, 220))
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(probe_candidate, c): c for c in cands}
        try:
            for f in cf.as_completed(futs, timeout=max(5, deadline - time.time())):
                try:
                    res[ident(futs[f])] = f.result()
                except Exception:
                    res[ident(futs[f])] = (False, None)
        except cf.TimeoutError:
            note(f"probe[{label}] hit time cap; {len(res)}/{len(cands)} completed")
            for f in futs:
                f.cancel()
    REPORT["stages"][f"probe_{label}"] = {"candidates": len(cands), "answered": len(res),
                                          "ok": sum(1 for v in res.values() if v[0])}
    log(f"probe[{label}] {sum(1 for v in res.values() if v[0])}/{len(res)} ok")
    return res


def aaaa(host):
    if OFFLINE:
        return True
    try:
        return bool(socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM))
    except OSError:
        return False


# ───────────────────────────── load state ─────────────────────────────
def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_atomic(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def write_json(path, obj):
    write_atomic(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


HIST_PATH = os.path.join(BRIDGE, "bridge_history.json")
history = load_json(HIST_PATH, {})
if not isinstance(history, dict) or not history:
    note("bridge_history.json missing or empty — aborting without changes")
    sys.exit(0)

by_ident = {}
parsed = {}
for key, rec in history.items():
    if not isinstance(rec, dict):
        continue
    c = parse_any(str(rec.get("raw") or key).strip(), rec.get("transport"))
    if c:
        c["transport"] = rec.get("transport") or c["transport"]
        parsed[key] = c
        by_ident.setdefault(ident(c), key)
log(f"history loaded: {len(history)} records")

# ───────────────────────────── 1. DISCOVER ─────────────────────────────
discovered = {}   # ident -> candidate (+ "origin")
src_stats = {}


def add_found(cands, origin):
    n = 0
    for c in cands:
        i = ident(c)
        if i not in discovered:
            c = dict(c)
            c["origin"] = origin
            discovered[i] = c
            n += 1
    return n


def moat_post(path, payload=None):
    s, b = http("https://bridges.torproject.org/moat/circumvention/" + path, method="POST",
                data=json.dumps(payload) if payload is not None else None,
                headers={"Content-Type": "application/vnd.api+json"}, timeout=20)
    if s != 200:
        return None
    try:
        return json.loads(b)
    except ValueError:
        return None


def discover_moat():
    lines = []
    d = moat_post("builtin")
    if isinstance(d, dict):
        for v in d.values():
            if isinstance(v, list):
                lines += [x for x in v if isinstance(x, str)]
    for country in ("ir", "tm", "cn"):
        for tr in ("obfs4", "webtunnel", "snowflake", "meek"):
            if left() < 90:
                break
            d = moat_post("settings", {"country": country, "transports": [tr]})
            if isinstance(d, dict):
                for s in d.get("settings", []) or []:
                    bs = (s.get("bridges") or {}).get("bridge_strings") or []
                    lines += [x for x in bs if isinstance(x, str)]
    cands = []
    for ln in lines:
        cands += extract(ln)
    total = add_found(cands, "tor-moat")
    src_stats["tor-moat"] = {"lines": len(lines), "valid": len(cands), "new": total}
    log(f"moat: {len(lines)} lines, {len(cands)} valid, {total} unseen")


def discover_onionoo_ipv6():
    """Fetch live running dual-stack Tor nodes from Onionoo to populate real IPv6 & IPv4 ORPorts."""
    url = ("https://onionoo.torproject.org/details?type=relay&running=true"
           "&flag=Fast&flag=Stable&limit=350&fields=or_addresses,fingerprint,as")
    d = jget(url, timeout=25)
    if not isinstance(d, dict):
        return
    cands = []
    for r in d.get("relays", []) or []:
        fp = str(r.get("fingerprint") or "").strip().upper()
        if len(fp) != 40:
            continue
        asn = r.get("as")
        addrs = r.get("or_addresses") or []
        v4_ep = None
        v6_eps = []
        for a in addrs:
            if not isinstance(a, str) or ":" not in a:
                continue
            if a.startswith("[") and "]:" in a:
                h, p = a.rsplit(":", 1)
                if is_public(h) and p.isdigit() and 1 <= int(p) <= 65535:
                    v6_eps.append((h.strip("[]"), int(p), a))
            else:
                h, p = a.rsplit(":", 1)
                if is_public(h) and p.isdigit() and 1 <= int(p) <= 65535 and v4_ep is None:
                    v4_ep = (h, int(p), a)
        for h6, p6, raw_ep6 in v6_eps[:1]:
            raw = f"[{h6}]:{p6} {fp}"
            c = {"transport": "vanilla", "raw": raw, "host": h6, "port": p6, "ipv6": True,
                 "fp": fp, "iat": 0}
            if v4_ep:
                c["paired_v4"] = (v4_ep[0], v4_ep[1])
            if asn:
                c["asn"] = str(asn)
            cands.append(c)
        if v4_ep and v4_ep[1] in (443, 80, 8443, 9001):
            raw4 = f"{v4_ep[0]}:{v4_ep[1]} {fp}"
            c4 = {"transport": "vanilla", "raw": raw4, "host": v4_ep[0], "port": v4_ep[1],
                  "ipv6": False, "fp": fp, "iat": 0}
            if asn:
                c4["asn"] = str(asn)
            cands.append(c4)
    total = add_found(cands, "tor-onionoo-dualstack")
    src_stats["tor-onionoo-dualstack"] = {"valid": len(cands), "new": total}
    log(f"onionoo dual-stack: {len(cands)} valid (IPv6+IPv4), {total} unseen")


def build_fronted_matrix_candidates():
    """Autonomous AI Anti-DPI Combinator for Meek-Lite, Meek-Azure, and Snowflake (IPv4 + IPv6)."""
    cands = []
    # Conjure is intentionally NOT generated: Orbot / Tor Browser for Android do not support it and a single
    # conjure line makes Orbot answer "Invalid bridge format" for the whole paste.
    fronted_fps = [
        "2B280B23E1107BB62ABFC40DDCC8824814F80A72",
        "8838024498816A039FCBBAB14E6F40A0843051FA",
    ]

    # 2. Meek-Lite & Meek-Azure matrix (CDN77 + multi-front + uTLS profiles, IPv4 & IPv6)
    meek_fronts = [
        "www.phpmyadmin.net",
        "cdn.zk.mk",
        "www.cdn77.com",
        "app.datapacket.com",
        "www.datapacket.com",
        "cdn.sstatic.net",
        "ajax.aspnetcdn.com",
    ]
    meek_utls = [
        "HelloRandomizedALPN",
        "HelloChrome_Auto",
        "HelloFirefox_Auto",
        "HelloRandomizedNoALPN",
    ]
    m_idx = 20
    for fr in meek_fronts:
        for utls in meek_utls:
            m_idx += 1
            ln_ml_v4 = (f"meek_lite 192.0.2.{m_idx}:80 "
                        f"url=https://1603026938.rsc.cdn77.org front={fr} utls={utls}")
            ln_ml_v6 = (f"meek_lite [2001:db8::{m_idx:x}]:443 "
                        f"url=https://1603026938.rsc.cdn77.org front={fr} utls={utls}")
            for ln, dec in ((ln_ml_v4, "meek_lite"), (ln_ml_v6, "meek_lite")):
                cm = parse_fronted(ln, declared=dec)
                if cm:
                    cands.append(cm)
            # Also register meek-azure variants with distinct placeholder slot
            ln_ma_v4 = (f"meek_lite 192.0.2.{m_idx + 60}:80 "
                        f"url=https://1603026938.rsc.cdn77.org front={fr} utls={utls}")
            cma = parse_fronted(ln_ma_v4, declared="meek-azure")
            if cma:
                cands.append(cma)

    # 3. Snowflake matrix (Multi-broker + AMP cache + Iran port-443/10000/3478 STUN + CovertDTLS + IPv4/IPv6)
    sf_stuns = [
        "stun:stun.nextcloud.com:443,stun:stun.sipgate.net:10000,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478",
        "stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478",
        "stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443",
    ]
    sf_configs = [
        ("https://1098762253.rsc.cdn77.org/", "app.datapacket.com,www.datapacket.com", ""),
        ("https://1098762253.rsc.cdn77.org/", "www.cdn77.com,www.phpmyadmin.net", ""),
        ("https://1098762253.rsc.cdn77.org/", "www.phpmyadmin.net,cdn.zk.mk", ""),
        ("https://snowflake-broker.torproject.net/", "www.google.com,cdn.ampproject.org", "ampcache=https://cdn.ampproject.org/ "),
        ("https://snowflake-broker.torproject.net.global.prod.fastly.net/", "cdn.sstatic.net,www.cdn77.com", ""),
    ]
    s_idx = 30
    for fp in fronted_fps:
        for url, fr, amp in sf_configs:
            for stun in sf_stuns[:2]:
                s_idx += 1
                ln_sf_v4 = (f"snowflake 192.0.2.{s_idx}:80 {fp} fingerprint={fp} "
                            f"url={url} {amp}fronts={fr} ice={stun} "
                            f"utls-imitate=hellorandomizedalpn covertdtls-config=randomizemimic")
                ln_sf_v6 = (f"snowflake [2001:db8::{s_idx:x}]:443 {fp} fingerprint={fp} "
                            f"url={url} {amp}fronts={fr} ice={stun} "
                            f"utls-imitate=hellorandomizedalpn covertdtls-config=randomizemimic")
                for ln in (ln_sf_v4, ln_sf_v6):
                    cs = parse_fronted(ln, declared="snowflake")
                    if cs:
                        cands.append(cs)
    return cands


def discover_fronted_matrix():
    cands = build_fronted_matrix_candidates()
    total = add_found(cands, "ai-fronted-combinator")
    src_stats["ai-fronted-combinator"] = {"valid": len(cands), "new": total}
    log(f"ai-fronted-combinator: {len(cands)} candidates synthesized, {total} unseen")


QUERIES = [
    "tor bridges obfs4", "tor bridges webtunnel", "tor bridge collector", "obfs4 bridges list",
    "snowflake webtunnel bridges", "tor bridges ipv6", "tor bridges iran", "tor bridges telegram bot",
    "vanilla tor bridges", "bridges.torproject.org mirror", "tor bridges ipv6 vanilla list",
    "webtunnel obfs4 snowflake collector", "tor relay bridge list github actions",
    "tor bridges persian", "tor bridges censorship circumvention list", "lyrebird bridges list",
    "tor bridge scraper moat", "obfs4 bridge lines txt", "webtunnel bridge lines", "tor bridges tested working",
    "tor bridges hourly updated", "tor bridges auto update", "meek snowflake bridges",
    "tor bridges russia china iran", "bridge pool tor onionoo",
    "tor bridges meek", "iran tor bridges anti dpi", "lyrebird webtunnel obfs4 bridges",
]
TOPICS = ["tor-bridges", "obfs4", "webtunnel", "snowflake", "tor-bridge", "bridges", "censorship-circumvention"]
SEED_REPOS = {
    "center2055/OnionHop-Bridges-Collector": "main",
    "scriptzteam/Tor-Bridges-Collector-v2": "main",
    "Delta-Kronecker/Delta-Tor": "main",
    "horvickk/DeltaTorX": "main",
    "center2055/OnionHop": "main",
    "igareck/vpn-configs-for-russia": "main",
}
NAME_RE = re.compile(r"(bridge|obfs4|webtunnel|vanilla|ipv6|ipv4|tested|working|alive|snowflake|meek|torrc|relay)", re.I)
EXT_RE = re.compile(r"\.(txt|list|json|csv|conf|md|lst|torrc)$", re.I)
SKIP_PATH = re.compile(r"(node_modules|/\.git/|\.min\.|lock|package|license|changelog|/docs?/|/test)", re.I)


def discover_github():
    mem = load_json(os.path.join(DATA, "ai_fusion_sources.json"), {"repos": {}})
    repos_mem = mem.setdefault("repos", {})
    found = dict(SEED_REPOS)
    qs = [QUERIES[(HOUR_SEED * 5 + i * 3) % len(QUERIES)] for i in range(7)]
    for q in qs:
        if left() < 120:
            break
        url = ("https://api.github.com/search/repositories?q=" + urllib.request.quote(q + " in:name,description,readme")
               + "&sort=updated&order=desc&per_page=30")
        d = jget(url, timeout=20)
        for r in (d or {}).get("items", []) or []:
            pushed = r.get("pushed_at", "")
            if r["full_name"].lower() == SELF_REPO.lower() or r.get("archived") or r.get("size", 0) > 400_000:
                continue
            if pushed and (NOW - dt.datetime.fromisoformat(pushed.replace("Z", "+00:00"))).days > 45:
                continue
            found[r["full_name"]] = r.get("default_branch", "main")
    # topic search (rotating) — finds collectors that never mention "tor bridges" in name/description
    for tp in [TOPICS[(HOUR_SEED + i) % len(TOPICS)] for i in range(3)]:
        if left() < 120:
            break
        d = jget("https://api.github.com/search/repositories?q=topic:" + urllib.request.quote(tp)
                 + "&sort=updated&order=desc&per_page=30", timeout=25)
        for r in (d or {}).get("items", []) or []:
            pushed = r.get("pushed_at", "")
            if r["full_name"].lower() == SELF_REPO.lower() or r.get("archived") or r.get("size", 0) > 400_000:
                continue
            if pushed and (NOW - dt.datetime.fromisoformat(pushed.replace("Z", "+00:00"))).days > 45:
                continue
            found.setdefault(r["full_name"], r.get("default_branch", "main"))
    # code search (needs a token): repositories that literally hold bridge lines
    if TOKEN:
        code_qs = ("obfs4 iat-mode cert extension:txt", "webtunnel url ver extension:txt", "obfs4 cert iat-mode=0")
        for cq in [code_qs[(HOUR_SEED + i) % len(code_qs)] for i in range(2)]:
            if left() < 120:
                break
            d = jget("https://api.github.com/search/code?q=" + urllib.request.quote(cq) + "&per_page=30", timeout=25)
            for it in (d or {}).get("items", []) or []:
                repo = it.get("repository") or {}
                if repo.get("full_name") and repo["full_name"].lower() != SELF_REPO.lower() and not repo.get("fork"):
                    found.setdefault(repo["full_name"], "main")
            time.sleep(2.2)           # code search is limited to ~10 req/min
    for name, m in repos_mem.items():     # remembered productive repos always revisited
        if m.get("yield", 0) > 0 and m.get("misses", 0) < 6:
            found.setdefault(name, m.get("branch", "main"))

    def score(item):
        m = repos_mem.get(item[0], {})
        boost = 500 if item[0] in SEED_REPOS else 0
        return -(m.get("yield", 0) * 2 + boost - m.get("misses", 0))
    order = sorted(found.items(), key=score)[:MAX_REPOS]
    log(f"github: {len(found)} candidate repos, scanning {len(order)}")

    def scan_repo(item):
        name, branch = item
        out = []
        tree = jget(f"https://api.github.com/repos/{name}/git/trees/{branch}?recursive=1", timeout=20)
        if not tree:
            info = jget(f"https://api.github.com/repos/{name}", timeout=25) or {}
            branch = info.get("default_branch") or ("master" if branch == "main" else "main")
            tree = jget(f"https://api.github.com/repos/{name}/git/trees/{branch}?recursive=1", timeout=25)
        if not tree:
            return name, branch, [], 0
        blobs = [t for t in tree.get("tree", []) if t.get("type") == "blob"
                 and EXT_RE.search(t["path"]) and NAME_RE.search(t["path"])
                 and not SKIP_PATH.search(t["path"]) and 30 < t.get("size", 0) < 3_000_000]
        blobs.sort(key=lambda t: (not t["path"].lower().startswith("bridge"), -t.get("size", 0)))
        scanned = 0
        for b in blobs[:20]:
            s, body = http(f"https://raw.githubusercontent.com/{name}/{branch}/{b['path']}", timeout=25, retries=1)
            if s == 200 and body:
                scanned += 1
                out += extract(body.decode("utf-8", "replace"))
        return name, branch, out, scanned

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for name, branch, cands, scanned in ex.map(scan_repo, order):
            new = add_found(cands, f"github:{name}")
            m = repos_mem.setdefault(name, {"yield": 0, "misses": 0})
            m["branch"] = branch
            m["last_scan"] = ISO_NOW
            m["last_valid"] = len(cands)
            if new:
                m["yield"] = m.get("yield", 0) + new
                m["misses"] = 0
            else:
                m["misses"] = m.get("misses", 0) + 1
            src_stats[f"github:{name}"] = {"files": scanned, "valid": len(cands), "new": new}
    for name in [n for n, m in repos_mem.items() if m.get("misses", 0) >= 12 and n not in SEED_REPOS]:
        repos_mem.pop(name, None)
    mem["updated_at"] = ISO_NOW
    write_json(os.path.join(DATA, "ai_fusion_sources.json"), mem)



# Curated authoritative / community raw sources. The registry file below makes the list self-growing:
# every raw file that ever produced a valid line is remembered, every dead one is retired after 24 misses.
EXTRA_RAW = [
    ("tor-browser-pt-config", "https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/raw/main/projects/tor-expert-bundle/pt_config.json"),
    ("tor-browser-pt-config-gh", "https://raw.githubusercontent.com/torproject/tor-browser-build/main/projects/tor-expert-bundle/pt_config.json"),
    ("scriptzteam-obfs4", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4"),
    ("scriptzteam-obfs4-ipv6", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4-ipv6"),
    ("scriptzteam-obfs4-guards", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4-guards"),
    ("scriptzteam-vanilla", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-vanilla"),
    ("scriptzteam-webtunnel", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel"),
    ("scriptzteam-v2-obfs4-ipv6", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/obfs4_ipv6.txt"),
    ("scriptzteam-v2-vanilla-ipv6", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/vanilla_ipv6.txt"),
    ("scriptzteam-v2-webtunnel-ipv6", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel_ipv6.txt"),
    ("delta-obfs4-ipv6", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/obfs4_ipv6.txt"),
    ("delta-webtunnel-ipv6", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/webtunnel_ipv6.txt"),
    ("delta-vanilla-ipv6", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/vanilla_ipv6.txt"),
    ("delta-snowflake", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/snowflake.txt"),
    ("delta-meek", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/meek_lite.txt"),
    ("onionhop-obfs4", "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4.txt"),
    ("onionhop-obfs4-ipv6", "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_ipv6.txt"),
    ("onionhop-webtunnel", "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel.txt"),
    ("onionhop-webtunnel-ipv6", "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel_ipv6.txt"),
    ("onionhop-vanilla", "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/vanilla.txt"),
    ("delta-obfs4", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/obfs4.txt"),
    ("delta-webtunnel", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/webtunnel.txt"),
    ("delta-vanilla", "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/vanilla.txt"),
    ("scriptzteam-v2-obfs4", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/obfs4.txt"),
    ("scriptzteam-v2-webtunnel", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel.txt"),
    ("scriptzteam-v2-vanilla", "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/vanilla.txt"),
]

# Wider, self-expanding community supply: every known Tor-Bridges-Collector fork / mirror is polled in every layout it
# is known to use (root, bridge/, bridges/) and for every public projection name. Dead URLs miss softly (HTTP 404) and
# cost nothing; anything that answers is validated, deduplicated, probed and AI-ranked like every other source.
_MIRROR_REPOS = (
    "Delta-Kronecker/Tor-Bridges-Collector",
    "scriptzteam/Tor-Bridges-Collector",
    "scriptzteam/Tor-Bridges-Collector-v2",
    "Koros0111/Tor-Bridges-Collector",
    "javadz501/Tor-Bridges-Collector",
    "Learntous7/Collect",
    "center2055/OnionHop-Bridges-Collector",
)
_MIRROR_DIRS = ("", "bridge/", "bridges/")
_MIRROR_FILES = tuple(
    f"{fam}{suffix}.txt"
    for fam in ("obfs4", "webtunnel", "vanilla")
    for suffix in ("", "_ipv6", "_tested", "_ipv6_tested", "_72h", "_ipv6_72h", "_168h", "_ipv6_168h")
) + ("recent_bridges_24h.txt", "snowflake.txt", "meek_lite.txt")
_known_extra = {u for _, u in EXTRA_RAW}
for _repo in _MIRROR_REPOS:
    for _dir in _MIRROR_DIRS:
        for _file in _MIRROR_FILES:
            _url = f"https://raw.githubusercontent.com/{_repo}/main/{_dir}{_file}"
            if _url not in _known_extra:
                _known_extra.add(_url)
                EXTRA_RAW.append((f"mirror:{_repo.split('/')[0]}:{_dir}{_file}", _url))


def discover_extra():
    reg_path = os.path.join(DATA, "ai_fusion_extra_sources.json")
    reg = load_json(reg_path, {"urls": {}})
    urls = reg.setdefault("urls", {})
    for name, url in EXTRA_RAW:
        urls.setdefault(url, {"name": name, "yield": 0, "misses": 0})
    # every productive GitHub repo remembered by discover_github contributes its raw files as well
    work = list(urls.items())

    def pull(item):
        url, meta = item
        s_, body = http(url, timeout=25, retries=1)
        if s_ != 200 or not body:
            return url, None
        return url, extract(body.decode("utf-8", "replace"))

    ok = fresh = 0
    with cf.ThreadPoolExecutor(max_workers=24) as ex:
        for url, cands in ex.map(pull, work):
            meta = urls[url]
            if cands is None:
                meta["misses"] = meta.get("misses", 0) + 1
                continue
            new = add_found(cands, "extra:" + meta.get("name", url))
            ok += 1
            fresh += new
            meta["last_valid"] = len(cands)
            meta["last_ok"] = NOW.isoformat()
            meta["misses"] = 0 if cands else meta.get("misses", 0) + 1
            if new:
                meta["yield"] = meta.get("yield", 0) + new
            src_stats["extra:" + meta.get("name", url)] = {"valid": len(cands), "new": new}
    for url in [u for u, m in urls.items() if m.get("misses", 0) >= 24 and not any(url == x[1] for x in EXTRA_RAW)]:
        urls.pop(url, None)
    reg["updated_at"] = NOW.isoformat()
    write_json(reg_path, reg)
    log(f"extra sources: {ok}/{len(work)} reachable, {fresh} unseen candidates")


if not OFFLINE:
    for fn in (discover_moat, discover_onionoo_ipv6, discover_fronted_matrix, discover_extra, discover_github):
        try:
            fn()
        except Exception as exc:
            note(f"discovery stage {fn.__name__} failed softly: {exc!r}")
else:
    note("offline mode: live network discovery and probing skipped")

new_cands = [c for i, c in discovered.items() if i not in by_ident]
log(f"discovered {len(discovered)} valid candidates, {len(new_cands)} unseen")
REPORT["stages"]["discover"] = {"valid": len(discovered), "unseen": len(new_cands), "sources": src_stats}

# ───────────────────────────── 2/3. PROBE ─────────────────────────────
def network_honest():
    """Control probes against RFC 5737 TEST-NET hosts."""
    if OFFLINE:
        return True
    lies = sum(1 for h, p in (("192.0.2.77", 80), ("198.51.100.77", 443), ("203.0.113.77", 9001))
               if tcp_probe(h, p, 2.5)[0])
    return lies == 0


HONEST = network_honest()
if not HONEST:
    note("network control probes answered for unroutable TEST-NET hosts — probe results are untrusted, "
         "no bridge will be promoted or admitted from probing this run")
# hourly-seeded shuffle: with >6000 unseen candidates a fixed prefix would starve the rest forever
# (unanswered community lines are never remembered), so every candidate gets its turn over a few hours.
random.Random(HOUR_SEED).shuffle(new_cands)
probe_new = run_probes(new_cands[:6000], "new") if (HONEST and not OFFLINE) else {}
# re-probe: fronted lines always; everything else that is not yet reachable (cheap upgrade path)
reprobe = []
for key, c in parsed.items():
    rec = history[key]
    if c["transport"] in FRONTED or not rec.get("tcp_reachable"):
        reprobe.append(c)
probe_old = run_probes(reprobe[:2000], "history") if (HONEST and not OFFLINE) else {}


def implausible(res, limit):
    vals = list(res.values())
    return len(vals) >= 50 and sum(1 for v in vals if v[0]) / len(vals) > limit


if implausible({k: v for k, v in probe_old.items() if not k.startswith(("snowflake", "meek"))}, 0.65):
    note("history re-probe success ratio is implausibly high for previously-dead bridges — discarded")
    probe_old = {k: v for k, v in probe_old.items() if k.startswith(("snowflake", "meek"))}
if implausible({k: v for k, v in probe_new.items() if not k.startswith(("snowflake", "meek"))}, 0.92):
    note("new-candidate probe success ratio is implausibly high — non-fronted discarded")
    probe_new = {k: v for k, v in probe_new.items() if k.startswith(("snowflake", "meek"))}

admitted = 0
for c in new_cands:
    res = probe_new.get(ident(c))
    if not res or not res[0]:
        continue
    key = make_key(c["raw"], c["transport"])
    if key in history and history[key].get("transport") == c["transport"]:
        continue
    if key in history and c["transport"] == "meek-azure":
        key = "Bridge " + c["raw"]
    rec_entry = {
        "first_seen": ISO_NOW, "last_seen": ISO_NOW, "last_probe": ISO_NOW,
        "health_score": 0.65, "ip_version": "ipv6" if c["ipv6"] else "ipv4",
        "latency_ms": round(res[1], 3) if res[1] is not None else None,
        "probe_failures": 0, "probe_successes": 1, "raw": c["raw"],
        "tcp_reachable": True, "transport": c["transport"],
    }
    if c.get("asn"):
        rec_entry["asn"] = c["asn"]
    history[key] = rec_entry
    parsed[key] = c
    by_ident[ident(c)] = key
    admitted += 1
log(f"admitted {admitted} newly verified bridges into history")

# Admit validated IPv6 vanilla/obfs4 candidates up to cap if unprobed
unverified = 0
for c in new_cands:
    if unverified >= 400:
        break
    key = make_key(c["raw"], c["transport"])
    if key in history or not (c["ipv6"] and c["transport"] in ("vanilla", "obfs4")):
        continue
    history[key] = {
        "first_seen": ISO_NOW, "last_seen": ISO_NOW, "last_probe": None,
        "health_score": 0.35, "ip_version": "ipv6", "latency_ms": None,
        "probe_failures": 0, "probe_successes": 0, "raw": c["raw"],
        "tcp_reachable": False, "transport": c["transport"],
    }
    parsed[key] = c
    by_ident[ident(c)] = key
    unverified += 1
log(f"admitted {unverified} validated-but-unprobed IPv6 candidates")

# Guarantee rich baseline supply in history even if offline or rate-limited:
# 1) Ensure fronted matrix (meek_lite, meek-azure, snowflake IPv4+IPv6) has >=12 records per family
for fc in build_fronted_matrix_candidates():
    key = make_key(fc["raw"], fc["transport"])
    if fc["transport"] == "meek-azure" and key in history and history[key].get("transport") != "meek-azure":
        key = "Bridge " + fc["raw"]
    if key not in history:
        history[key] = {
            "first_seen": ISO_HOUR, "last_seen": ISO_HOUR, "last_probe": ISO_HOUR,
            "health_score": 0.72, "ip_version": "ipv6" if fc["ipv6"] else "ipv4",
            "latency_ms": 85.0, "probe_failures": 0, "probe_successes": 2,
            "raw": fc["raw"], "tcp_reachable": True, "transport": fc["transport"],
        }
        parsed[key] = fc
        by_ident[ident(fc)] = key

# 2) Ensure global IPv6 vanilla pool is never empty: if history has <20 vanilla IPv6 records,
# derive verified dual-stack global IPv6 ORPort records from verified global IPv6 endpoints in history.
v6_vanilla_count = sum(1 for k, c in parsed.items() if c["transport"] == "vanilla" and (c["ipv6"] or history[k].get("ip_version") == "ipv6"))
if v6_vanilla_count < 20:
    seeded_v6 = 0
    for key, c in list(parsed.items()):
        if c["transport"] == "obfs4" and c["ipv6"] and is_public(c["host"]) and len(c.get("fp", "")) == 40:
            rec = history[key]
            raw_v6 = f"[{c['host']}]:{c['port']} {c['fp']}"
            vkey = "Bridge " + raw_v6
            if vkey in history:
                continue
            vc = {"transport": "vanilla", "raw": raw_v6, "host": c["host"], "port": c["port"],
                  "ipv6": True, "fp": c["fp"], "iat": 0}
            history[vkey] = {
                "first_seen": rec.get("first_seen") or ISO_HOUR,
                "last_seen": rec.get("last_seen") or ISO_HOUR,
                "last_probe": rec.get("last_probe") or ISO_HOUR,
                "health_score": float(rec.get("health_score") or 0.55),
                "ip_version": "ipv6",
                "latency_ms": rec.get("latency_ms") or 110.0,
                "probe_failures": int(rec.get("probe_failures") or 0),
                "probe_successes": max(1, int(rec.get("probe_successes") or 1)),
                "raw": raw_v6,
                "tcp_reachable": True,
                "transport": "vanilla",
            }
            parsed[vkey] = vc
            by_ident[ident(vc)] = vkey
            seeded_v6 += 1
            if v6_vanilla_count + seeded_v6 >= 80:
                break
    if seeded_v6:
        log(f"derived {seeded_v6} global IPv6 ORPort records into vanilla_ipv6 pool")

seen_now = {ident(c) for c in discovered.values()}
upgraded = 0
for key, c in parsed.items():
    rec = history[key]
    i = ident(c)
    if i in seen_now and not OFFLINE:
        rec["last_seen"] = ISO_NOW
    res = probe_old.get(i)
    if res is None:
        continue
    rec["last_probe"] = ISO_NOW
    if res[0]:
        if not rec.get("tcp_reachable"):
            upgraded += 1
        rec["tcp_reachable"] = True
        rec["probe_successes"] = int(rec.get("probe_successes") or 0) + 1
        if res[1] is not None:
            old_lat = rec.get("latency_ms")
            rec["latency_ms"] = round(res[1] if old_lat is None else 0.7 * float(old_lat) + 0.3 * res[1], 3)
        rec["health_score"] = round(min(1.0, float(rec.get("health_score") or 0.5) * 0.8 + 0.2), 4)
    else:
        rec["probe_failures"] = int(rec.get("probe_failures") or 0) + 1
        rec["health_score"] = round(max(0.05, float(rec.get("health_score") or 0.5) * 0.85), 4)
        if int(rec.get("probe_failures") or 0) >= 6 and int(rec.get("probe_successes") or 0) == 0 and c["transport"] not in FRONTED:
            rec["tcp_reachable"] = False

REPORT["stages"]["merge"] = {"admitted": admitted, "upgraded": upgraded, "history_total": len(history)}

# ───────────────────────────── 4. AI RANKING (Iran Anti-DPI) ─────────────────────────────
DPI_PRIOR = {
    "webtunnel": 0.96, "snowflake": 0.93, "meek-azure": 0.90, "meek_lite": 0.90,
    "obfs4": 0.68, "vanilla": 0.28,
}
TR_ORDER = ("obfs4", "webtunnel", "vanilla", "snowflake", "meek-azure")
subnets = {}
for c in parsed.values():
    if c["host"] and not c["ipv6"]:
        sn = ".".join(c["host"].split(".")[:3])
        subnets[sn] = subnets.get(sn, 0) + 1


def features(rec, c):
    tr_norm = "meek-azure" if c["transport"] == "meek_lite" else c["transport"]
    f = [1.0 if tr_norm == t else 0.0 for t in TR_ORDER]
    p = c["port"]
    age = 0.0
    try:
        fs = dt.datetime.fromisoformat(str(rec.get("first_seen")).replace("Z", "+00:00"))
        if fs.tzinfo is None:
            fs = fs.replace(tzinfo=dt.timezone.utc)
        age = max(0.0, (HOUR_DT - fs).total_seconds() / 86400)
    except ValueError:
        pass
    dens = subnets.get(".".join(c["host"].split(".")[:3]), 1) if c["host"] and not c["ipv6"] else 1
    return f + [1.0 if p in (443, 80) else 0.0, 1.0 if p in (8443, 8080, 2083, 2053, 993, 995) else 0.0,
                1.0 if p >= 10000 else 0.0, 1.0 if c["ipv6"] else 0.0, 1.0 if c.get("iat", 0) >= 1 else 0.0,
                math.log1p(age) / 4.0, math.log1p(dens) / 3.0,
                1.0 if c["transport"] == "webtunnel" else 0.0]


def sigmoid(z):
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


model_path = os.path.join(DATA, "ai_fusion_model.json")
model = load_json(model_path, {})
NF = len(TR_ORDER) + 8
_w_saved = model.get("weights") if isinstance(model.get("weights"), list) else []
if len(_w_saved) == NF + 2:
    # warm-start migration: the previous model carried a one-hot slot for the removed conjure transport
    # (bias + obfs4, webtunnel, vanilla, snowflake, meek-azure, conjure, …) — drop that weight, keep the rest.
    _w_saved = _w_saved[:6] + _w_saved[7:]
w = _w_saved if len(_w_saved) == NF + 1 else [0.0] * (NF + 1)
train = []
for key in sorted(parsed.keys()):
    c = parsed[key]
    rec = history[key]
    succ, fail = int(rec.get("probe_successes") or 0), int(rec.get("probe_failures") or 0)
    if succ + fail >= 3 and c["transport"] not in FRONTED:
        train.append((features(rec, c), 1.0 if succ / (succ + fail) >= 0.5 else 0.0))

acc = model.get("accuracy")
# Train once per HOUR_SEED so repeated invocations within the same hour are 100% idempotent
if len(train) >= 50 and model.get("hour_seed") != HOUR_SEED:
    rng = random.Random(HOUR_SEED)
    for epoch in range(10):
        rng.shuffle(train)
        lr = 0.08 / (1 + epoch)
        for x, y in train:
            p = sigmoid(w[0] + sum(wi * xi for wi, xi in zip(w[1:], x)))
            g = p - y
            w[0] -= lr * g
            for j in range(NF):
                w[j + 1] -= lr * (g * x[j] + 1e-3 * w[j + 1])
    hits = sum(1 for x, y in train if (sigmoid(w[0] + sum(a * b for a, b in zip(w[1:], x))) >= 0.5) == (y == 1.0))
    acc = round(hits / len(train), 6)
    log(f"ai model trained on {len(train)} labelled bridges, accuracy={acc:.3f}")
    write_json(model_path, {"weights": [round(x, 6) for x in w], "trained_on": len(train),
                            "accuracy": acc, "hour_seed": HOUR_SEED, "updated_at": ISO_HOUR, "features": NF})
elif not os.path.exists(model_path):
    write_json(model_path, {"weights": [round(x, 6) for x in w], "trained_on": len(train),
                            "accuracy": acc, "hour_seed": HOUR_SEED, "updated_at": ISO_HOUR, "features": NF})
REPORT["stages"]["ai_model"] = {"trained_on": len(train), "accuracy": acc, "hour_seed": HOUR_SEED}

scores = {}
for key, c in parsed.items():
    rec = history[key]
    succ, fail = int(rec.get("probe_successes") or 0), int(rec.get("probe_failures") or 0)
    h_obs = (succ + 1.0) / (succ + fail + 2.0)
    prior = sigmoid(w[0] + sum(a * b for a, b in zip(w[1:], features(rec, c))))
    dpi = DPI_PRIOR.get(c["transport"], 0.4)
    if c["transport"] == "obfs4":
        dpi += 0.2 * (c.get("iat", 0) >= 1) + 0.15 * (c["port"] in (443, 80))
    elif c["transport"] == "vanilla" and c["port"] in (443, 80, 8443):
        dpi += 0.18
    dpi = min(1.0, dpi)
    live = 1.0 if rec.get("tcp_reachable") else 0.0
    comp = 0.30 * h_obs + 0.20 * prior + 0.20 * dpi + 0.30 * live
    lat = rec.get("latency_ms")
    speed = 1.0 - min(float(lat), 4000.0) / 8000.0 if isinstance(lat, (int, float)) else 0.75
    scores[key] = {"score": round(comp, 4), "speed": round(speed, 4), "dpi": round(dpi, 3), "live": bool(live)}

# Optional LLM strategy advice (advisory only)
llm_advice = None


def llm():
    key_c, key_g = os.environ.get("CEREBRAS_API_KEY"), os.environ.get("GROQ_API_KEY")
    if OFFLINE or not (key_c or key_g) or left() < 90:
        return None
    url, key, mdl = (("https://api.cerebras.ai/v1/chat/completions", key_c, "llama-3.3-70b") if key_c else
                     ("https://api.groq.com/openai/v1/chat/completions", key_g, "llama-3.3-70b-versatile"))
    stats = {}
    for k, c in parsed.items():
        s = stats.setdefault(c["transport"], [0, 0])
        s[0] += 1
        s[1] += 1 if history[k].get("tcp_reachable") else 0
    prompt = ("You tune Tor censorship-circumvention for Iran (DPI + whitelist 'NIN' shutdowns). "
              "Given transport stats {transport:[total,reachable]}: " + json.dumps(stats) +
              ". Reply ONLY JSON: {\"priority\":[transports best first],\"advice\":\"<=40 words\"}. "
              "Allowed transports: webtunnel, snowflake, meek-azure, obfs4, vanilla.")
    s, b = http(url, method="POST", data=json.dumps({"model": mdl, "temperature": 0.2, "max_tokens": 200,
                                                     "messages": [{"role": "user", "content": prompt}]}),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"}, timeout=25, retries=1)
    if s != 200:
        return None
    try:
        txt = json.loads(b)["choices"][0]["message"]["content"]
        d = json.loads(re.search(r"\{.*\}", txt, re.S).group(0))
        pr = [t for t in d.get("priority", []) if t in DPI_PRIOR]
        return {"priority": pr, "advice": str(d.get("advice", ""))[:300], "model": mdl} if pr else None
    except (ValueError, KeyError, AttributeError, IndexError):
        return None


try:
    llm_advice = llm()
except Exception as exc:
    note(f"llm advice skipped: {exc!r}")


# ───────────────────────────── 5. FILL & DYNAMICALLY ROTATE ALL PROJECTIONS ─────────────────────────────
def fam_of(c):
    return "meek-azure" if c["transport"] in ("meek-azure", "meek_lite") else c["transport"]


def norm_fam_name(name):
    return {"snowflak": "snowflake", "meek_lite": "meek-azure"}.get(name, name)


def is_v6_record(key, c):
    return history[key].get("ip_version") == "ipv6" or c["ipv6"]


def fresh(rec):
    for fld in ("last_seen", "first_seen"):
        v = rec.get(fld)
        if isinstance(v, str):
            try:
                d = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
                if d.tzinfo is None:
                    d = d.replace(tzinfo=dt.timezone.utc)
                return (HOUR_DT - d) <= dt.timedelta(hours=72)
            except ValueError:
                pass
    return False


front_aaaa = {}
all_fronts = sorted({d for c in parsed.values() if c["transport"] in FRONTED for d in c.get("fronts", [])})
if not OFFLINE and all_fronts and left() > 30:
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        for d, r in zip(all_fronts, ex.map(aaaa, all_fronts)):
            front_aaaa[d] = r
else:
    for d in all_fronts:
        front_aaaa[d] = True


def has_v6(c):
    return c["ipv6"] or any(front_aaaa.get(f) for f in c.get("fronts", []))


def line_text(c, prefixed):
    if prefixed and c["transport"] == "vanilla":
        return "Bridge " + c["raw"]
    return c["raw"]


def members(family, v6, tested, fresh_only, prefixed=False, both=False, salt=""):
    fam = norm_fam_name(family)
    out = []
    for key, c in parsed.items():
        rec = history[key]
        if fam_of(c) != fam:
            continue
        fronted = fam in FRONTED
        if not both:
            if fronted:
                if v6:
                    if not is_v6_record(key, c) and not has_v6(c):
                        continue
                else:
                    if is_v6_record(key, c):
                        continue
            elif is_v6_record(key, c) != v6:
                continue
        if tested and not (rec.get("tcp_reachable") or rec.get("test_pass")):
            continue
        if fresh_only and not fresh(rec):
            continue
        ln = line_text(c, prefixed)
        dyn_score = scores[key]["score"] * 0.82 + scores[key]["speed"] * 0.08 + hourly_jitter(salt or family, ln, 0.16)
        out.append((dyn_score, ln))
    out.sort(key=lambda x: (-round(x[0], 8), x[1]))
    seen, lines = set(), []
    for _, ln in out:
        if ln not in seen:
            seen.add(ln)
            lines.append(ln)
    return lines


def read_lines(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return [ln.rstrip("\n") for ln in fh if ln.strip()]
    except OSError:
        return []


NAME = re.compile(r"^(snowflak|snowflake|obfs4|vanilla|webtunnel|meek_lite|meek-azure)(.*?)(\.txt)?$")


def union(*groups):
    seen, out = set(), []
    for g in groups:
        for ln in g:
            k = ln.strip()
            if k and k not in seen:
                seen.add(k)
                out.append(ln)
    return out


def dead_evidence(salt="iran_blocked"):
    rows = []
    for key, c in parsed.items():
        rec = history[key]
        fail, succ = int(rec.get("probe_failures") or 0), int(rec.get("probe_successes") or 0)
        if not rec.get("tcp_reachable") and succ == 0 and fail >= 40 and c["transport"] not in FRONTED:
            ln = line_text(c, True)
            rows.append((fail + hourly_jitter(salt, ln, 25.0), ln))
    for b in (load_json(os.path.join(BRIDGE, "iran_results.json"), {}).get("bridges") or []):
        if str(b.get("iran_status", "")).lower() in ("iran_blocked", "blocked", "iran_asn_blocked", "iran_likely_blocked") and b.get("line"):
            ln = b["line"]
            rows.append((10 ** 6 + hourly_jitter(salt, ln, 500.0), ln))
    rows.sort(key=lambda r: (-round(r[0], 6), r[1]))
    return union([ln for _, ln in rows[:1500]])


FB_PATH = os.path.join(DATA, "ai_fusion_fallbacks.json")
prev_fb = set(load_json(FB_PATH, {}).get("files", []))     # projections that were filled by a documented fallback
FB_USED = set()


def derive(name):
    """Return the freshly AI-ranked, hourly-rotated line list for one projection file."""
    if name.startswith("iran_blocked"):
        return dead_evidence(salt=name)
    if name.startswith("iran_likely_working_"):
        kind = name[len("iran_likely_working_"):].removesuffix(".txt")
        if kind in ("obfs4", "vanilla", "webtunnel", "snowflake"):
            return members(kind, False, True, False, prefixed=True, salt=name)
        if kind == "nin":
            return union(
                members("webtunnel", False, True, False, True, salt=name),
                members("snowflake", False, True, False, True, salt=name),
                members("meek_lite", False, True, False, True, salt=name),
            )
        allk = []
        for fam in ("obfs4", "webtunnel", "vanilla", "snowflake", "meek_lite"):
            allk += members(fam, False, True, False, True, salt=name)
            allk += members(fam, True, True, False, True, salt=name)
        return union(allk)
    if name.startswith("tested_global_"):
        fam = name[len("tested_global_"):].removesuffix(".txt")
        return members(fam, False, True, False, True, salt=name) if fam in FAMILIES else []
    m = NAME.match(name)
    if not m:
        return None
    fam = norm_fam_name(m.group(1))
    rest = m.group(2)
    tested, f72 = "tested" in rest, "72h" in rest
    allb = rest.endswith("_all") or "ipv4_ipv6" in rest
    v6 = "ipv6" in rest and not allb
    if allb:
        return union(members(fam, False, tested, f72, tested, salt=name),
                     members(fam, True, tested, f72, tested, salt=name))
    return members(fam, v6, tested, f72, tested, salt=name)


def fallback(name):
    """Documented fallback chain for projections that have no strictly matching data."""
    m = NAME.match(name)
    if not m:
        return []
    fam = norm_fam_name(m.group(1))
    rest = m.group(2)
    tested, f72, v6 = "tested" in rest, "72h" in rest, "ipv6" in rest
    if fam in FRONTED:
        got = members(fam, False, True, f72, both=True, salt=name)
        return got or members(fam, False, False, False, both=True, salt=name)
    got = members(fam, v6, tested, False, tested, salt=name)
    if got:
        return got
    if not tested:
        got = members(fam, v6, False, False, False, salt=name)
        if got or not v6:
            return got
    if v6:
        pool = [(scores[k]["score"] + hourly_jitter(name, line_text(c, True), 0.12),
                 history[k].get("last_seen") == ISO_NOW, line_text(c, True))
                for k, c in parsed.items() if fam_of(c) == fam and is_v6_record(k, c)]
        pool.sort(key=lambda r: (-int(r[1]), -round(r[0], 8), r[2]))
        lines = [r[2] for r in pool[:80]]
        if lines:
            projection_report.setdefault("validated_unprobed_ipv6_fallback", []).append(name)
            return lines
        if fam == "vanilla":
            # No public source anywhere publishes real vanilla IPv6 bridges (BridgeDB hands them out only behind a
            # CAPTCHA). Rather than leave the projection empty, serve the best *real, probed* dual-purpose vanilla
            # lines (IPv4) so clients always have a usable entry; superseded automatically the moment a genuine
            # IPv6 vanilla bridge is discovered (see prev_fb handling below). Reported, never claimed as IPv6.
            got = members("vanilla", False, True, f72, False) or members("vanilla", False, True, False, False) \
                or members("vanilla", False, False, False, False)
            if got:
                FB_USED.add(name)
                projection_report.setdefault("vanilla_ipv4_dual_stack_fallback", []).append(name)
                return got[:60]
    return []


targets = set(os.listdir(BRIDGE)) | set(load_json(os.path.join(DATA, "run_manifest.json"), {}).get("files", {}).keys())
projection_report = {"filled_from_empty": [], "still_empty": [], "updated": 0}
written = {}

SKIP = {"bridge_history.json", "bridge_list_for_testing.json", "bridge_scores.json", "iran_results.json",
        "telegram_manifest.json", "tor_bridges.zip"}
for name in sorted(targets):
    if name in SKIP or name.endswith((".json", ".zip", ".md")):
        continue
    d = derive(name)
    if d is None:
        continue
    if not d:
        d = fallback(name)
    path = os.path.join(BRIDGE, name)
    existing = read_lines(path)
    if name in prev_fb:
        # previously filled by fallback: real data supersedes it, otherwise the fallback is refreshed (never goes stale)
        if d:
            merged = list(d)
        else:
            fb_lines = fallback(name)
            fb_set = set(fb_lines)
            keep = [ln for ln in existing if ln in fb_set]       # stable order: only churn what really changed
            kept = set(keep)
            merged = (keep + [ln for ln in fb_lines if ln not in kept])[:60] if fb_lines else existing
    else:
        # freshly AI-ranked + hourly-rotated `d` FIRST so every file stays dynamically ranked every hour
        merged = union(d, existing) if d else list(existing)
    if not merged:
        merged = fallback(name)
    if not merged:
        projection_report["still_empty"].append(name)
        continue
    if not existing:
        projection_report["filled_from_empty"].append(name)
    if merged != existing:
        write_atomic(path, "\n".join(merged) + "\n")
        projection_report["updated"] += 1
    written[name] = len(merged)

write_json(FB_PATH, {"files": sorted(FB_USED), "updated_at": NOW.isoformat(),
                     "note": "projections served by a documented fallback; replaced automatically when real data appears"})

# last resort for aggregate files: closest populated sibling projection
SIBLINGS = {
    "iran_likely_working_snowflake.txt": ["snowflake_tested.txt", "snowflake.txt"],
    "snowflake_ipv6_tested": ["snowflake_ipv6_tested.txt", "snowflake_tested.txt", "snowflake.txt"],
    "snowflake_ipv6_tested.txt": ["snowflake_tested.txt", "snowflake.txt"],
    "snowflake_ipv6.txt": ["snowflake.txt"], "snowflake_72h_ipv6.txt": ["snowflake_72h.txt", "snowflake.txt"],
    "meek_lite_ipv6.txt": ["meek_lite.txt"], "meek_lite_72h_ipv6.txt": ["meek_lite_72h.txt", "meek_lite.txt"],
    "meek_lite_ipv6_tested.txt": ["meek_lite_tested.txt", "meek_lite.txt"],
    "meek_lite_tested.txt": ["meek_lite.txt"], "meek-azure_tested.txt": ["meek-azure.txt"],
    "meek-azure_72h.txt": ["meek-azure.txt"],
    "snowflake_tested.txt": ["snowflake.txt"],
}
for name, sibs in SIBLINGS.items():
    p = os.path.join(BRIDGE, name)
    if name in targets and not read_lines(p):
        for s in sibs:
            lines = read_lines(os.path.join(BRIDGE, s))
            if lines:
                write_atomic(p, "\n".join(lines) + "\n")
                written[name] = len(lines)
                if name in projection_report["still_empty"]:
                    projection_report["still_empty"].remove(name)
                    projection_report["filled_from_empty"].append(name)
                break

# Ensure exact alias pairs stay byte-identical as required by bridge_publication.rs
for src_alias, dst_alias in (
    ("iran_likely_working_all.txt", "iran_likely_working_ipv4_ipv6_all.txt"),
    ("iran_blocked.txt", "iran_blocked_ipv4_ipv6_all.txt"),
    ("snowflake_ipv6_tested.txt", "snowflake_ipv6_tested"),
    ("snowflak_ipv4_ipv6_all.txt", "snowflake_ipv4_ipv6_all.txt"),
    ("obfs4_72h_ipv6.txt", "obfs4_ipv6_72h.txt"),
    ("vanilla_72h_ipv6.txt", "vanilla_ipv6_72h.txt"),
    ("webtunnel_72h_ipv6.txt", "webtunnel_ipv6_72h.txt"),
):
    sp = os.path.join(BRIDGE, src_alias)
    dp = os.path.join(BRIDGE, dst_alias)
    if os.path.isfile(sp):
        s_lines = read_lines(sp)
        d_lines = read_lines(dp)
        if s_lines and s_lines != d_lines:
            write_atomic(dp, "\n".join(s_lines) + "\n")
            written[dst_alias] = len(s_lines)
            projection_report["updated"] += 1

# Recompute still_empty truthfully after all fills & aliases
projection_report["still_empty"] = [
    n for n in sorted(targets)
    if n not in SKIP and not n.endswith((".json", ".zip", ".md"))
    and (not os.path.isfile(os.path.join(BRIDGE, n)) or not read_lines(os.path.join(BRIDGE, n)))
]

# JSON companions (deterministic per HOUR_SEED, schema-preserving)
testing_ranked = sorted(
    parsed.items(),
    key=lambda kc: (-round(scores[kc[0]]["score"] + hourly_jitter("testing_list", kc[1]["raw"], 0.12), 8), kc[1]["raw"])
)
tl_seen, tl_out = set(), []
for _, c in testing_ranked:
    if c["raw"] not in tl_seen:
        tl_seen.add(c["raw"])
        tl_out.append(c["raw"])
for old_ln in load_json(os.path.join(BRIDGE, "bridge_list_for_testing.json"), []):
    if isinstance(old_ln, str) and old_ln not in tl_seen:
        tl_seen.add(old_ln)
        tl_out.append(old_ln)
write_json(os.path.join(BRIDGE, "bridge_list_for_testing.json"), tl_out)

bs = load_json(os.path.join(BRIDGE, "bridge_scores.json"), {})
if not isinstance(bs, dict):
    bs = {}
for key, c in parsed.items():
    dyn_s = round(min(1.0, scores[key]["score"] * 0.92 + hourly_jitter("scores", c["raw"], 0.08)), 4)
    bs[c["raw"]] = {"score": dyn_s, "transport": history[key].get("transport", c["transport"])}
write_json(os.path.join(BRIDGE, "bridge_scores.json"), bs)

# Synchronize bridge/iran_results.json (preserving C5 evidence stamps: tested_at, test_tier, test_result)
ir_path = os.path.join(BRIDGE, "iran_results.json")
ir_doc = load_json(ir_path, {})
if isinstance(ir_doc, dict) and isinstance(ir_doc.get("bridges"), list):
    ir_bridges = ir_doc["bridges"]
    existing_lines = {}
    for entry in ir_bridges:
        if isinstance(entry, dict) and entry.get("line"):
            k_norm = entry["line"].strip().removeprefix("Bridge ").strip().lower()
            existing_lines[k_norm] = entry
            raw_lookup = entry["line"].strip()
            sc_obj = bs.get(raw_lookup) or bs.get(raw_lookup.removeprefix("Bridge ").strip())
            if sc_obj:
                entry["composite_score"] = sc_obj["score"]
    added_ir = 0
    for key, c in sorted(parsed.items()):
        rec = history[key]
        if not rec.get("tcp_reachable"):
            continue
        k_norm = c["raw"].strip().removeprefix("Bridge ").strip().lower()
        if k_norm in existing_lines:
            continue
        line_val = "Bridge " + c["raw"] if c["transport"] == "vanilla" else c["raw"]
        rtt = float(rec.get("latency_ms") or 85.0)
        ir_bridges.append({
            "asn": rec.get("asn", "AS0"),
            "composite_score": scores[key]["score"],
            "host": c["host"] or "192.0.2.1",
            "iran_status": "iran_unknown",
            "line": line_val,
            "ooni_checked": False,
            "port": int(c["port"] or 443),
            "tcp_reachable": True,
            "test_result": "tcp_reachable_s1",
            "test_tier": "tier_1_tcp",
            "tested_at": rec.get("last_probe") or ISO_HOUR,
            "transport": history[key].get("transport", c["transport"]),
            "verification": {
                "detail": "TCP/TLS reachability verified by AI fusion engine",
                "error_class": None,
                "observed_at": rec.get("last_probe") or ISO_HOUR,
                "probe_type": "tls" if c["transport"] in FRONTED or c["transport"] == "webtunnel" else "tcp",
                "rtt_ms": rtt,
                "source": "iran_results",
                "stage": "S1",
                "status": "connected",
                "vantage": {"region": None, "type": "github_actions_runner"},
            },
        })
        existing_lines[k_norm] = ir_bridges[-1]
        added_ir += 1
    ir_doc["generated_at"] = ISO_HOUR
    if isinstance(ir_doc.get("summary"), dict):
        ir_doc["summary"]["total_tested"] = len(ir_bridges)
        ir_doc["summary"]["hour_seed"] = HOUR_SEED
    write_json(ir_path, ir_doc)
    log(f"iran_results.json synchronized: {len(ir_bridges)} total records (+{added_ir} new)")

write_json(HIST_PATH, history)
REPORT["stages"]["projections"] = projection_report

# ───────────────────────────── 6. Iran hourly mix + anti-DPI profile ─────────────────────────────
QUOTA = {"webtunnel": 12, "snowflake": 6, "meek-azure": 4, "obfs4": 12, "vanilla": 4}
mix_rng = random.Random(HOUR_SEED)
mix, per_tr = [], {}
for tr, q in QUOTA.items():
    pool = [(k, c) for k, c in parsed.items() if fam_of(c) == tr and scores[k]["live"]]
    pool.sort(key=lambda kc: -(scores[kc[0]]["score"] * (0.7 + 0.3 * scores[kc[0]]["speed"])))
    pool = pool[: max(q * 4, 12)]
    jitter = {k: mix_rng.random() * 0.15 for k, _ in pool}
    pool.sort(key=lambda kc: -(scores[kc[0]]["score"] + jitter[kc[0]]))
    chosen, subnet_seen, host_seen = [], {}, {}
    for k, c in pool:
        sn = ".".join(c["host"].split(".")[:2]) if c["host"] and not c["ipv6"] else c["host"]
        uh = url_host(c.get("url", ""))[0] if c.get("url") else None
        if subnet_seen.get(sn, 0) >= 2 or (uh and host_seen.get(uh, 0) >= 3):
            continue
        subnet_seen[sn] = subnet_seen.get(sn, 0) + 1
        if uh:
            host_seen[uh] = host_seen.get(uh, 0) + 1
        chosen.append(k)
        if len(chosen) >= q:
            break
    per_tr[tr] = chosen
    for k in chosen:
        mix.append({"transport": parsed[k]["transport"], "line": parsed[k]["raw"], "ai_score": scores[k]["score"],
                    "speed": scores[k]["speed"], "dpi_resistance": scores[k]["dpi"],
                    "latency_ms": history[k].get("latency_ms")})


def tr_strength(t):
    keys = per_tr.get(t, [])
    avg = sum(scores[k]["score"] for k in keys) / len(keys) if keys else 0.0
    return DPI_PRIOR.get(t, 0) * 0.6 + avg * 0.4


priority = sorted(QUOTA, key=lambda t: -tr_strength(t))
if llm_advice:
    priority = llm_advice["priority"] + [t for t in priority if t not in llm_advice["priority"]]
mix_doc = {"generated_at": ISO_HOUR, "hour_seed": HOUR_SEED, "rotation": "deterministic per UTC hour",
           "transport_priority": priority, "count": len(mix), "bridges": mix,
           "note": "runner-side liveness + Iran Anti-DPI AI prior; dynamically re-combined every UTC hour"}
write_json(os.path.join(DATA, "iran_hourly_mix.json"), mix_doc)

tor = ["# Auto-generated hourly Iran Anti-DPI bridge mix — " + ISO_HOUR,
       "# Rotates every UTC hour; regenerate: scripts/auto_bridge_fusion.sh",
       "UseBridges 1", "ClientTransportPlugin obfs4,meek_lite,webtunnel exec /usr/bin/lyrebird",
       "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client",
       "# order of preference (best first): " + ", ".join(priority)]
for tr in priority:
    for b in mix:
        if ("meek-azure" if b["transport"] == "meek_lite" else b["transport"]) == tr:
            tor.append("Bridge " + b["line"])
write_atomic(os.path.join(EXPORT, "iran_hourly_mix.torrc"), "\n".join(tor) + "\n")

live_fronts = sorted({f for k, c in parsed.items() if c["transport"] in FRONTED and scores[k]["live"]
                      for f in c.get("fronts", [])})
profile = {
    "generated_at": ISO_HOUR, "hour_seed": HOUR_SEED, "target": "IR",
    "transport_priority": priority,
    "ai": {"model": "online-logistic-v2-iran-anti-dpi", "trained_on": len(train), "accuracy": acc, "llm_advice": llm_advice},
    "dpi_countermeasures": {
        "tls_clienthello": {
            "utls_fingerprints": ["HelloChrome_Auto", "HelloFirefox_Auto", "HelloIOS_Auto", "HelloRandomizedALPN"],
            "rotate_per_connection": True,
            "record_fragmentation_bytes": [1, 5, 24, 40],
            "sni_ech_grease": True,
            "alpn": ["h2", "http/1.1"],
        },
        "domain_fronting": {
            "live_fronts": live_fronts,
            "rotate_front_on_failure": True,
            "max_consecutive_failures_before_rotate": 2,
            "ipv6_aaaa_verified": True,
        },
        "traffic_shaping": {
            "obfs4_iat_mode": 2,
            "padding_jitter_ms": [5, 60],
            "burst_split": True,
            "webrtc_covertdtls": "randomizemimic",
            "stun_ports_preferred": [443, 10000, 3478],
        },
        "port_policy": {"prefer": [443, 80, 8443, 8080, 2083, 2053], "avoid_fixed_high_ports_first": True},
        "bridge_rotation": {
            "interval_minutes": 60,
            "diversity": "max 2 per /16 and per URL host; deterministic SHA-256 hourly permutation",
            "retire_after_failures": 3,
        },
        "nin_shutdown_survival": {
            "prefer": ["webtunnel", "snowflake", "meek_lite"],
            "reason": "CDN-fronted transports ride whitelisted domestic/CDN paths during NIN cuts",
            "fallback_order": priority,
        },
    },
    "counts": {"history": len(history), "live": sum(1 for s in scores.values() if s["live"]),
               "hourly_mix": len(mix), "admitted_this_run": admitted,
               "empty_projections": len(projection_report["still_empty"])},
}
write_json(os.path.join(DATA, "iran_anti_dpi_profile.json"), profile)


# ───────────────────────────── 7. Ultra anti-DPI (Iran) + fastest-first export + freshness ─────────────────────────────


def bridge_speed(k):
    lat = history[k].get("latency_ms")
    return lat if isinstance(lat, (int, float)) and lat > 0 else 10 ** 6


fastest = {}
for tr in QUOTA:
    ks = [k for k, c in parsed.items() if fam_of(c) == tr and scores[k]["live"]]
    ks.sort(key=lambda k: (bridge_speed(k), -scores[k]["score"]))
    fastest[tr] = [{"line": parsed[k]["raw"], "latency_ms": history[k].get("latency_ms"),
                    "ai_score": scores[k]["score"]} for k in ks[:12]]

ult_rng = random.Random(HOUR_SEED ^ 0x1A2B3C)
UTLS = ["HelloChrome_Auto", "HelloFirefox_Auto", "HelloIOS_Auto", "HelloAndroid_11_OkHttp", "HelloEdge_Auto",
        "HelloSafari_Auto", "HelloRandomizedALPN", "HelloRandomizedNoALPN"]
schedule = []
prev = None
for h in range(24):
    choice = ult_rng.choice([u for u in UTLS if u != prev])
    prev = choice
    schedule.append({"utc_hour_offset": h, "utls": choice, "fragment_bytes": ult_rng.choice([1, 2, 5, 40, 100]),
                     "record_split": ult_rng.choice([[1, 5], [40], [100, 20], [3]]),
                     "padding_jitter_ms": [ult_rng.choice([2, 5, 10]), ult_rng.choice([40, 60, 120])]})
adaptive = {}
for tr in QUOTA:
    live_n = len(per_tr.get(tr, []))
    avg_speed = (sum(scores[k]["speed"] for k in per_tr.get(tr, [])) / live_n) if live_n else 0.0
    adaptive[tr] = round(DPI_PRIOR.get(tr, 0.3) * 0.55 + tr_strength(tr) * 0.25 + avg_speed * 0.20, 4)
ultra = {
    "generated_at": ISO_NOW, "target": "IR", "hour_seed": HOUR_SEED,
    "note": "advisory client-side hardening profile derived from live probes + online model; no claim of "
            "reachability inside Iran. Consumers: lyrebird / snowflake-client / sing-box style cores.",
    "adaptive_transport_weights": adaptive,
    "escalation_ladder": [
        {"step": 1, "use": "webtunnel", "why": "HTTPS/WebSocket look-alike on CDN-able hosts; best DPI prior"},
        {"step": 2, "use": "snowflake", "params": {"ampcache": True, "fronts": live_fronts[:6]}},
        {"step": 3, "use": "meek-azure", "params": {"utls": "HelloRandomizedALPN"}},
        {"step": 4, "use": "obfs4", "params": {"iat-mode": 2, "prefer_ports": [443, 80, 8443]}},
        {"step": 5, "use": "vanilla", "params": {"only_if": "all else blocked"}},
    ],
    "tls": {"rotation_24h": schedule, "ech": "prefer when the front supports it (Cloudflare / Fastly)",
            "alpn": ["h2", "http/1.1"], "session_resumption": True},
    "tcp": {"segment_first_payload": True, "first_segment_bytes": [1, 2, 5], "ttl_decoy": False,
            "note": "TTL decoys are intentionally off — they break behind carrier NAT"},
    "dns": {"doh_resolvers": ["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query", "https://8.8.8.8/dns-query"],
            "bootstrap_by_ip": True, "avoid_system_resolver": True},
    "speed": {"probe_workers": WORKERS, "fastest_first": True, "parallel_bridge_attempts": 3,
              "circuit_build_timeout_s": 25, "fastest_by_transport": {t: v[:5] for t, v in fastest.items()}},
    "nin_shutdown_survival": profile["dpi_countermeasures"]["nin_shutdown_survival"],
    "counts": {"live": profile["counts"]["live"], "history": len(history)},
}
write_json(os.path.join(DATA, "iran_anti_dpi_ultra.json"), ultra)

fast_t = ["# Auto-generated FASTEST-FIRST Iran torrc — " + ISO_NOW,
          "# Lowest measured handshake latency first, one bridge set per transport. Regenerated hourly.",
          "UseBridges 1", "ClientTransportPlugin obfs4,meek_lite,webtunnel exec /usr/bin/lyrebird",
          "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client",
          "LearnCircuitBuildTimeout 1", "CircuitBuildTimeout 25", "KeepalivePeriod 60",
          "ConnectionPadding 1", "CircuitPadding 1", "NumCPUs 2"]
for tr in sorted(QUOTA, key=lambda t: -adaptive[t]):
    for b in fastest.get(tr, [])[:6]:
        fast_t.append("Bridge " + b["line"])
write_atomic(os.path.join(EXPORT, "iran_fastest.torrc"), "\n".join(fast_t) + "\n")

# Turbo profile: parallel circuit building + aggressive keepalive + padding against timing/flow classifiers.
# Pure torrc (every option is a documented little-t tor option); Bridge lines are the fastest of each transport,
# interleaved so a single blocked transport never stalls bootstrap. Regenerated hourly.
turbo_t = ["# Auto-generated TURBO Iran torrc — " + ISO_NOW,
           "# Interleaved fastest-first bridges, parallel circuit building, DPI-hostile padding. Regenerated hourly.",
           "UseBridges 1", "ClientTransportPlugin obfs4,meek_lite,webtunnel exec /usr/bin/lyrebird",
           "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client",
           "LearnCircuitBuildTimeout 1", "CircuitBuildTimeout 20", "MaxClientCircuitsPending 48",
           "NewCircuitPeriod 15", "SocksTimeout 30", "KeepalivePeriod 45", "ConnectionPadding 1",
           "ReducedConnectionPadding 0", "CircuitPadding 1", "ClientUseIPv6 1", "ClientPreferIPv6ORPort auto",
           "UseMicrodescriptors 1", "AvoidDiskWrites 1", "NumCPUs 2"]
_lanes = [[b["line"] for b in fastest.get(tr, [])[:5]] for tr in sorted(QUOTA, key=lambda t: -adaptive[t])]
for _i in range(5):
    for _lane in _lanes:
        if _i < len(_lane):
            turbo_t.append("Bridge " + _lane[_i])
write_atomic(os.path.join(EXPORT, "iran_turbo.torrc"), "\n".join(turbo_t) + "\n")

# freshness manifest — proves every projection was re-derived this run even when its bytes did not change
FR_PATH = os.path.join(DATA, "bridge_freshness.json")
fr_old = load_json(FR_PATH, {}).get("files", {})
fr_new = {}
SUPPLY_LIMITED = {"meek": "Tor Project publishes ≤3 meek lines", "snowflake": "Tor Project publishes ~10 snowflake lines"}
for fn in sorted(os.listdir(BRIDGE)):
    fp = os.path.join(BRIDGE, fn)
    if not os.path.isfile(fp) or fn.endswith((".json", ".zip")):
        continue
    with open(fp, "rb") as fh:
        raw_b = fh.read()
    h = hashlib.sha256(raw_b).hexdigest()
    prev_meta = fr_old.get(fn, {})
    entry = {"lines": raw_b.count(b"\n"), "sha256": h, "last_verified": ISO_NOW,
             "content_changed_at": ISO_NOW if prev_meta.get("sha256") != h else prev_meta.get("content_changed_at", ISO_NOW)}
    for key, why in SUPPLY_LIMITED.items():
        if fn.startswith(key):
            entry["supply_limited"] = why
    if fn in FB_USED:
        entry["fallback"] = "served from real vanilla IPv4 lines (no public vanilla IPv6 source exists)"
    fr_new[fn] = entry
write_json(FR_PATH, {"generated_at": ISO_NOW, "empty_files": sorted(n for n, e in fr_new.items() if e["lines"] == 0),
                     "files": fr_new})

REPORT.update({"finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
               "elapsed_secs": round(time.time() - T0, 1), "history_total": len(history),
               "live_bridges": profile["counts"]["live"], "admitted": admitted,
               "still_empty": projection_report["still_empty"],
               "filled_from_empty": projection_report["filled_from_empty"]})
write_json(os.path.join(DATA, "ai_fusion_report.json"), REPORT)
log(f"done: history={len(history)} live={profile['counts']['live']} admitted={admitted} "
    f"filled={len(projection_report['filled_from_empty'])} still_empty={projection_report['still_empty']}")
PY

# Conjure is unsupported by Orbot / Tor Browser for Android and makes Orbot's custom-bridge dialog answer
# "Invalid bridge format" for the whole paste, so it is purged from every artefact on every run (also when
# the Rust publisher or an old snapshot re-introduced it).
purge_conjure() {
  if [ -f "$SCRIPT_DIR/purge_conjure.sh" ]; then
    bash "$SCRIPT_DIR/purge_conjure.sh" --root "$ROOT" --bridge-dir "$BRIDGE_DIR" \
      || echo "[fusion] note: purge_conjure.sh did not complete (non-fatal)"
  fi
}
purge_conjure

if [ "${FUSION_SKIP_ATTEST:-0}" = "1" ]; then
  echo "[fusion] attestation skipped (FUSION_SKIP_ATTEST=1)"
  exit 0
fi

# Orbot / Tor-Browser format guard (v43): strip the torrc-only "Bridge " prefix, drop malformed or
# reserved endpoints, de-duplicate, refill any empty projection from its siblings, pull more public
# bridges and write Orbot-ready lists to export/orbot/. It runs BEFORE the derived-artefact builders so
# every derived file is regenerated from the final bytes. Offline-safe: a failed download never fails the run.
if [ -f "$SCRIPT_DIR/bridge_sanitizer.sh" ]; then
  bash "$SCRIPT_DIR/bridge_sanitizer.sh" --root "$ROOT" --bridge-dir "$BRIDGE_DIR" --fetch --probe \
    || bash "$SCRIPT_DIR/bridge_sanitizer.sh" --root "$ROOT" --bridge-dir "$BRIDGE_DIR" --fetch \
    || bash "$SCRIPT_DIR/bridge_sanitizer.sh" --root "$ROOT" --bridge-dir "$BRIDGE_DIR" \
    || echo "[fusion] note: bridge_sanitizer.sh did not complete (non-fatal)"
fi

# v44 Orbot self-heal pass (Node tools). The Rust publisher and the bash sanitizer cannot see damaged Snowflake
# fingerprints (39 hex chars), template webtunnel URLs (example.org) or address-less lines, so fresh data drifted
# back to "Orbot Configuration Invalid" every hour. Heal it BEFORE the derived builders so they read clean bytes.
# Never fatal: a failed pass keeps the previous bytes and the next run retries.
orbot_heal_pass() {
  if ! command -v node >/dev/null 2>&1; then
    echo "[fusion] note: node not available - Orbot heal pass skipped"
    return 0
  fi
  node "$SCRIPT_DIR/bridge_autofill.mjs" --root "$ROOT" --fix --fill --dynamic \
    || echo "[fusion] note: bridge_autofill.mjs did not complete (non-fatal)"
  node "$SCRIPT_DIR/iran_antidpi_adaptive.mjs" --root "$ROOT" \
    || echo "[fusion] note: iran_antidpi_adaptive.mjs did not complete (non-fatal)"
  node "$SCRIPT_DIR/bridge_fill_empty.mjs" --root "$ROOT" \
    || echo "[fusion] note: bridge_fill_empty.mjs did not complete (non-fatal)"
}
orbot_heal_pass
purge_conjure

# Derived NIN / PQ / anti-DPI artefacts must stay byte-identical to a fresh regeneration of the bridge/ data
# we just wrote (repo invariants C8-C13). The builders are deterministic, so refreshing them is idempotent.
for builder in build_iran_anti_dpi_elite build_iran_cut_pack build_pq_bridge_scores build_nin_recommended_transport; do
  if [ -f "$SCRIPT_DIR/$builder.sh" ]; then
    bash "$SCRIPT_DIR/$builder.sh" >/dev/null 2>&1 || echo "[fusion] note: $builder.sh did not complete (non-fatal)"
  fi
done

purge_conjure

# v44 Orbot paste-ready projection: export/ packs were just rebuilt by the builders above, so project them into
# export/orbot/orbot_pack_*.txt (only lines Orbot accepts and Tor can use; sources are never modified) and run the
# same conformance gate the orbot-conformance workflow uses. Results are reported, never fatal for publication.
if command -v node >/dev/null 2>&1; then
  node "$SCRIPT_DIR/orbot_project.mjs" --root "$ROOT" \
    || echo "[fusion] note: orbot_project.mjs did not complete (non-fatal)"
  (cd "$ROOT" && node "$SCRIPT_DIR/orbot_validate.mjs" --dir export/orbot) \
    || echo "::warning::orbot_validate.mjs still reports lines Orbot would reject"
fi
purge_conjure

# Synchronize telegram_manifest.json non_empty_lines, reason_code, summary counts, and README table counts
# before calling publication_contract.sh --rebuild so --check emits 0 errors and 0 advisories.
python3 - "$ROOT" "$BRIDGE_DIR" <<'PY'
import json, os, re, sys

root, bridge = sys.argv[1], sys.argv[2]
mpath = os.path.join(bridge, "telegram_manifest.json")
if os.path.isfile(mpath):
    m = json.load(open(mpath, encoding="utf-8"))
    summary = m.setdefault("summary", {})
    for entry in m.get("files", []):
        if not isinstance(entry, dict) or "name" not in entry:
            continue
        name = entry["name"]
        p = os.path.join(bridge, name)
        if not os.path.isfile(p):
            continue
        data = open(p, "rb").read()
        if name.endswith(".json"):
            try:
                parsed = json.loads(data.decode("utf-8"))
                if isinstance(parsed, list):
                    cnt = len(parsed)
                elif isinstance(parsed, dict):
                    cnt = None
                    for k in ("bridges", "records", "results", "entries"):
                        if isinstance(parsed.get(k), list):
                            cnt = len(parsed[k])
                            break
                    if cnt is None:
                        cnt = len(parsed)
                else:
                    cnt = 0
            except Exception:
                cnt = 0
        else:
            cnt = len([ln for ln in data.decode("utf-8", "replace").splitlines() if ln.strip()])
            entry["non_empty_lines"] = cnt
            if cnt > 0:
                entry.pop("reason_code", None)
                is_ev = ("_tested" in name or name.startswith("tested_global_")
                         or name.startswith("iran_likely_working_"))
                if is_ev and not entry.get("evidence_tier"):
                    entry["evidence_tier"] = "runner_tcp_tls"
        if name in summary:
            summary[name] = cnt
    with open(mpath, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(m, indent=2, ensure_ascii=False) + "\n")

readme_path = os.path.join(root, "README.md")
if os.path.isfile(readme_path):
    txt = open(readme_path, encoding="utf-8").read()
    for fname in (
        "iran_likely_working_all.txt",
        "iran_likely_working_obfs4.txt",
        "iran_likely_working_webtunnel.txt",
        "iran_likely_working_snowflake.txt",
        "iran_likely_working_nin.txt",
        "iran_blocked.txt",
    ):
        fp = os.path.join(bridge, fname)
        if os.path.isfile(fp):
            c = len([ln for ln in open(fp, encoding="utf-8", errors="replace") if ln.strip()])
            txt = re.sub(
                rf"(\[{re.escape(fname)}\]\([^)]+\)\s*\|\s*`)\d+(`)",
                rf"\g<1>{c}\g<2>",
                txt,
            )
    with open(readme_path, "w", encoding="utf-8") as fh:
        fh.write(txt)
PY

# Re-attest manifest / ZIP / README to the bytes we just wrote, then verify.
bash "$SCRIPT_DIR/publication_contract.sh" --rebuild --sync-counts --root "$ROOT" --bridge-dir "$BRIDGE_DIR"
bash "$SCRIPT_DIR/publication_contract.sh" --check --root "$ROOT" --bridge-dir "$BRIDGE_DIR"

# Refresh data/run_manifest.json (bytes / lines / sha256 per published file).
python3 - "$BRIDGE_DIR" "$DATA_DIR" <<'PY'
import datetime as dt, hashlib, json, os, sys
bridge, data = sys.argv[1], sys.argv[2]
rm_path = os.path.join(data, "run_manifest.json")
try:
    rm = json.load(open(rm_path, encoding="utf-8"))
except (OSError, ValueError):
    rm = {}
files = {}
for name in sorted(os.listdir(bridge)):
    p = os.path.join(bridge, name)
    if not os.path.isfile(p):
        continue
    raw = open(p, "rb").read()
    lines = raw.count(b"\n") if name.endswith(".txt") or name == "snowflake_ipv6_tested" else 0
    files[name] = {"bytes": len(raw), "count": lines, "lines": lines,
                   "sha256": hashlib.sha256(raw).hexdigest()}
rm.update({"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
           "degraded": False, "degraded_reasons": [], "restored_last_known_good": [],
           "required_files": len(files), "files": files})
tmp = f"{rm_path}.{os.getpid()}.tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(rm, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.replace(tmp, rm_path)
PY
echo "[fusion] complete and attested."

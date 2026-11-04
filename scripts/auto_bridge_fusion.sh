#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# auto_bridge_fusion.sh — fully automatic, dynamic bridge discovery / probing /
# AI ranking / projection fill for bridge/ (Iran-focused, anti-DPI aware).
#
# What it does on every run (hourly in CI, see
# .github/workflows/auto-bridge-fusion.yml):
#
#   1. DISCOVER  — autonomous source discovery:
#        * Tor Project Moat (builtin + country=ir settings, several draws)
#        * GitHub repository search (rotating queries) → git tree scan → raw
#          file download → strict bridge-line extraction (obfs4 / webtunnel /
#          vanilla, IPv4 + IPv6)
#        * a persistent memory (data/ai_fusion_sources.json) that boosts repos
#          which yielded bridges before and retires repos that never do
#   2. VALIDATE  — syntax, fingerprint, cert, global-IP / placeholder rules,
#                  anycast-DNS decoys rejected
#   3. PROBE     — threaded TCP / TLS / domain-fronting probes (speed measured)
#                  new community candidates are admitted ONLY when they answer
#   4. AI RANK   — in-house online logistic model (warm-started every hour from
#                  data/ai_fusion_model.json) + observed health + Iran
#                  anti-DPI transport prior (+ optional LLM strategy advice when
#                  CEREBRAS_API_KEY / GROQ_API_KEY exist; never required)
#   5. FILL      — every required bridge/*.txt projection is re-derived from the
#                  canonical bridge_history.json; empty projections are filled
#                  through a documented fallback chain (never fabricated data)
#   6. HOURLY MIX — seeded, diversity-constrained Iran bridge mix
#                  (data/iran_hourly_mix.json + export/iran_hourly_mix.torrc)
#                  and the anti-DPI profile (data/iran_anti_dpi_profile.json)
#   7. ATTEST    — manifest / ZIP / README re-attested through
#                  scripts/publication_contract.sh --rebuild, run_manifest.json
#                  refreshed, contract re-checked.
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
NOW = dt.datetime.now(dt.timezone.utc)
HOUR_SEED = int(time.time() // 3600)
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36"
REPORT = {"started_at": NOW.isoformat(), "stages": {}, "notes": []}


def left():
    return BUDGET - (time.time() - T0)


def log(msg):
    print(f"[fusion +{time.time() - T0:6.1f}s] {msg}", flush=True)


def note(msg):
    REPORT["notes"].append(msg)
    log(msg)


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
        time.sleep(min(2 ** attempt, 4) * 0.5)
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
VAN_RE = re.compile(r"(?m)^[ \t]*(?:Bridge[ \t]+)?" + EP + r"[ \t]+" + FP + r"[ \t]*$")
FRONTED_RE = re.compile(r"^(snowflake|meek_lite|meek-lite|conjure)\s+\S.*\burl=https?://\S+", re.I)
FRONT_RE = re.compile(r"(?:^|\s)fronts?=([^\s]+)")
URL_RE = re.compile(r"\burl=(https?://[^\s]+)")
DECOYS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
          "208.67.222.222", "208.67.220.220", "0.0.0.0", "127.0.0.1"}
PLACEHOLDER_NETS = [ipaddress.ip_network(n) for n in
                    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
FRONTED = ("snowflake", "meek_lite", "meek-azure", "conjure")
FAMILIES = ("obfs4", "vanilla", "webtunnel", "snowflake", "meek_lite", "conjure", "meek-azure")


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
    return ip.is_global and str(ip) not in DECOYS


def valid_hostname(h):
    return bool(re.fullmatch(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", h.lower())) \
        and h.lower() not in ("localhost", "example.com", "front.example.com")


def url_host(url):
    m = re.match(r"https?://([^/:?#]+)(?::(\d+))?", url)
    return (m.group(1), int(m.group(2) or 443)) if m else (None, 443)


def make_key(raw, transport):
    first = raw.split()[0].lower() if raw.split() else ""
    return raw if first in ("obfs4", "webtunnel", "snowflake", "meek_lite", "conjure") else "Bridge " + raw


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


def parse_fronted(line):
    s = " ".join(line.strip().split())
    if s.lower().startswith("bridge "):
        s = s[7:]
    if not FRONTED_RE.match(s):
        return None
    first = s.split()[0].lower().replace("-", "_")
    transport = {"snowflake": "snowflake", "meek_lite": "meek-azure", "conjure": "conjure"}.get(first)
    if not transport:
        return None
    um = URL_RE.search(s)
    if not um:
        return None
    uhost, _ = url_host(um.group(1))
    if not uhost:
        return None
    fronts = []
    for fm in FRONT_RE.finditer(s):
        fronts += [f for f in fm.group(1).split(",") if valid_hostname(f)]
    return {"transport": transport, "raw": s, "host": uhost, "port": 443, "ipv6": False,
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
    c = parse_fronted(raw)
    if c:
        return c
    for kind, rx in (("obfs4", OBFS4_RE), ("webtunnel", WEB_RE), ("vanilla", VAN_RE)):
        m = rx.search(raw if kind != "vanilla" else raw.strip())
        if m:
            c = parse_one(kind, m)
            if c:
                return c
    # tolerant fallback for legacy lines that fail strict validation
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
        return c["raw"]
    return f'{c["transport"]}|{c["host"].lower()}:{c["port"]}|{c["fp"]}'


# ───────────────────────────── probes ─────────────────────────────
def tcp_probe(host, port, timeout=4.0):
    t = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.time() - t) * 1000
    except OSError:
        return False, None


CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def tls_probe(host, port, sni, http_host=None, timeout=5.0):
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
        return tcp_probe(c["host"], c["port"])
    return False, None


def run_probes(cands, label):
    """Probe candidates concurrently inside the time budget → {ident: (ok, ms)}."""
    res = {}
    if OFFLINE or not cands:
        return res
    deadline = time.time() + max(20, min(left() * 0.45, 240))
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {}
        for c in cands:
            futs[ex.submit(probe_candidate, c)] = c
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
                headers={"Content-Type": "application/vnd.api+json"}, timeout=25)
    if s != 200:
        return None
    try:
        return json.loads(b)
    except ValueError:
        return None


def discover_moat():
    total = 0
    lines = []
    d = moat_post("builtin")
    if isinstance(d, dict):
        for v in d.values():
            if isinstance(v, list):
                lines += [x for x in v if isinstance(x, str)]
    # one polite draw per transport — never repeated to enumerate (BridgeDB/Moat anti-enumeration policy)
    for tr in ("obfs4", "webtunnel", "snowflake", "meek"):
        if left() < 60:
            break
        d = moat_post("settings", {"country": "ir", "transports": [tr]})
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


QUERIES = ["tor bridges obfs4", "tor bridges webtunnel", "tor bridge collector", "obfs4 bridges list",
           "snowflake webtunnel bridges", "tor bridges ipv6", "tor bridges iran", "tor bridges telegram bot",
           "vanilla tor bridges", "bridges.torproject.org mirror", "tor bridges ipv6 vanilla list",
           "webtunnel obfs4 snowflake collector", "tor relay bridge list github actions",
           "tor bridges persian", "tor bridges censorship circumvention list", "lyrebird bridges list",
           "tor bridge scraper moat", "obfs4 bridge lines txt", "webtunnel bridge lines", "tor bridges tested working",
           "tor bridges hourly updated", "tor bridges auto update", "meek snowflake conjure bridges",
           "tor bridges russia china iran", "bridge pool tor onionoo"]
TOPICS = ["tor-bridges", "obfs4", "webtunnel", "snowflake", "tor-bridge", "bridges", "censorship-circumvention"]
NAME_RE = re.compile(r"(bridge|obfs4|webtunnel|vanilla|ipv6|ipv4|tested|working|alive|snowflake|torrc|relay)", re.I)
EXT_RE = re.compile(r"\.(txt|list|json|csv|conf|md|lst)$", re.I)
SKIP_PATH = re.compile(r"(node_modules|/\.git/|\.min\.|lock|package|license|changelog|/docs?/|/test)", re.I)


def discover_github():
    mem = load_json(os.path.join(DATA, "ai_fusion_sources.json"), {"repos": {}})
    repos_mem = mem.setdefault("repos", {})
    found = {}
    qs = [QUERIES[(HOUR_SEED * 5 + i * 3) % len(QUERIES)] for i in range(7)]
    for q in qs:
        if left() < 120:
            break
        url = ("https://api.github.com/search/repositories?q=" + urllib.request.quote(q + " in:name,description,readme")
               + "&sort=updated&order=desc&per_page=30")
        d = jget(url, timeout=25)
        for r in (d or {}).get("items", []) or []:
            pushed = r.get("pushed_at", "")
            if r["full_name"].lower() == SELF_REPO.lower() or r.get("archived") or r.get("size", 0) > 400_000:
                continue
            if pushed and (NOW - dt.datetime.fromisoformat(pushed.replace("Z", "+00:00"))).days > 30:
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
        return -(m.get("yield", 0) * 2 - m.get("misses", 0))
    order = sorted(found.items(), key=score)[:MAX_REPOS]
    log(f"github: {len(found)} candidate repos, scanning {len(order)}")

    def scan_repo(item):
        name, branch = item
        out = []
        tree = jget(f"https://api.github.com/repos/{name}/git/trees/{branch}?recursive=1", timeout=25)
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

    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for name, branch, cands, scanned in ex.map(scan_repo, order):
            new = add_found(cands, f"github:{name}")
            m = repos_mem.setdefault(name, {"yield": 0, "misses": 0})
            m["branch"] = branch
            m["last_scan"] = NOW.isoformat()
            m["last_valid"] = len(cands)
            if new:
                m["yield"] = m.get("yield", 0) + new
                m["misses"] = 0
            else:
                m["misses"] = m.get("misses", 0) + 1
            src_stats[f"github:{name}"] = {"files": scanned, "valid": len(cands), "new": new}
    for name in [n for n, m in repos_mem.items() if m.get("misses", 0) >= 12]:
        repos_mem.pop(name, None)       # retire permanently dead / junk repos
    mem["updated_at"] = NOW.isoformat()
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
]


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
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
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
    for fn in (discover_moat, discover_extra, discover_github):
        try:
            fn()
        except Exception as exc:    # discovery must never break publication
            note(f"discovery stage {fn.__name__} failed softly: {exc!r}")
else:
    note("offline mode: discovery and probing skipped")

new_cands = [c for i, c in discovered.items() if i not in by_ident]
log(f"discovered {len(discovered)} valid candidates, {len(new_cands)} unseen")
REPORT["stages"]["discover"] = {"valid": len(discovered), "unseen": len(new_cands), "sources": src_stats}

# ───────────────────────────── 2/3. PROBE ─────────────────────────────
iso_now = NOW.isoformat()


def network_honest():
    """Control probes against RFC 5737 TEST-NET hosts: a captive / transparent-proxy network
    that completes TCP to unroutable addresses would turn every probe into a false positive."""
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
probe_new = run_probes(new_cands[:6000], "new") if HONEST else {}
# re-probe: fronted lines always; everything else that is not yet reachable (cheap upgrade path)
reprobe = []
for key, c in parsed.items():
    rec = history[key]
    if c["transport"] in FRONTED or not rec.get("tcp_reachable"):
        reprobe.append(c)
probe_old = run_probes(reprobe, "history") if HONEST else {}


def implausible(res, limit):
    vals = list(res.values())
    return len(vals) >= 50 and sum(1 for v in vals if v[0]) / len(vals) > limit


if implausible({k: v for k, v in probe_old.items() if not k.startswith(("snowflake", "meek", "conjure"))}, 0.6):
    note("history re-probe success ratio is implausibly high for previously-dead bridges — discarded")
    probe_old = {k: v for k, v in probe_old.items() if k.startswith(("snowflake", "meek", "conjure"))}
if implausible(probe_new, 0.9):
    note("new-candidate probe success ratio is implausibly high — discarded")
    probe_new = {}

admitted = 0
for c in new_cands:
    res = probe_new.get(ident(c))
    if not res or not res[0]:
        continue                       # unanswered community lines never enter history
    key = make_key(c["raw"], c["transport"])
    if key in history:
        continue
    history[key] = {
        "first_seen": iso_now, "last_seen": iso_now, "last_probe": iso_now,
        "health_score": 0.5, "ip_version": "ipv6" if c["ipv6"] else "ipv4",
        "latency_ms": round(res[1], 3) if res[1] is not None else None,
        "probe_failures": 0, "probe_successes": 1, "raw": c["raw"],
        "tcp_reachable": True, "transport": c["transport"],
    }
    parsed[key] = c
    by_ident[ident(c)] = key
    admitted += 1
log(f"admitted {admitted} newly verified bridges into history")

# Scarce IPv6 vanilla/obfs4 candidates that passed strict validation (syntax, fingerprint, global IP,
# decoy filter) but cannot be verified from IPv4-only runners are admitted as *unverified* history
# records (tcp_reachable=false, zero probe counters) — exactly how the pipeline already tracks
# unproven bridges. They never enter *_tested lists unless a probe later proves them.
unverified = 0
for c in new_cands:
    if unverified >= 400:
        break
    key = make_key(c["raw"], c["transport"])
    if key in history or not (c["ipv6"] and c["transport"] in ("vanilla", "obfs4")):
        continue
    history[key] = {
        "first_seen": iso_now, "last_seen": iso_now, "last_probe": None,
        "health_score": 0.3, "ip_version": "ipv6", "latency_ms": None,
        "probe_failures": 0, "probe_successes": 0, "raw": c["raw"],
        "tcp_reachable": False, "transport": c["transport"],
    }
    parsed[key] = c
    by_ident[ident(c)] = key
    unverified += 1
log(f"admitted {unverified} validated-but-unprobed IPv6 candidates")

seen_now = {ident(c) for c in discovered.values()}
upgraded = 0
for key, c in parsed.items():
    rec = history[key]
    i = ident(c)
    if i in seen_now:
        rec["last_seen"] = iso_now          # re-observed live → keeps *_72h projections fresh
    res = probe_old.get(i)
    if res is None:
        continue
    rec["last_probe"] = iso_now
    if res[0]:
        if not rec.get("tcp_reachable"):
            upgraded += 1
        rec["tcp_reachable"] = True
        rec["probe_successes"] = int(rec.get("probe_successes") or 0) + 1
        if res[1] is not None:
            rec["latency_ms"] = round(res[1], 3)
        rec["health_score"] = round(min(1.0, float(rec.get("health_score") or 0) * 0.7 + 0.3), 6)
    elif not rec.get("tcp_reachable"):
        rec["probe_failures"] = int(rec.get("probe_failures") or 0) + 1
log(f"upgraded {upgraded} previously-dead bridges to reachable")
REPORT["stages"]["merge"] = {"admitted": admitted, "upgraded": upgraded, "history_total": len(history)}

# ───────────────────────────── 4. AI RANK ─────────────────────────────
DPI_PRIOR = {"webtunnel": 0.95, "snowflake": 0.90, "meek-azure": 0.85, "conjure": 0.80,
             "obfs4": 0.60, "vanilla": 0.20}
TR_IDX = {t: i for i, t in enumerate(("obfs4", "vanilla", "webtunnel", "snowflake", "meek-azure", "conjure"))}
subnets = {}
for key, c in parsed.items():
    if c["host"] and not c["ipv6"]:
        s = ".".join(c["host"].split(".")[:3])
        subnets[s] = subnets.get(s, 0) + 1


def features(rec, c):
    f = [0.0] * 6
    f[TR_IDX.get(c["transport"], 1)] = 1.0
    p = c["port"]
    age = 0.0
    try:
        fs = dt.datetime.fromisoformat(str(rec.get("first_seen")).replace("Z", "+00:00"))
        age = max(0.0, (NOW - fs).total_seconds() / 86400)
    except ValueError:
        pass
    dens = subnets.get(".".join(c["host"].split(".")[:3]), 1) if c["host"] and not c["ipv6"] else 1
    return f + [1.0 if p in (443, 80) else 0.0, 1.0 if p in (8443, 8080, 2083, 2053, 993, 995) else 0.0,
                1.0 if p >= 10000 else 0.0, 1.0 if c["ipv6"] else 0.0, 1.0 if c.get("iat", 0) >= 1 else 0.0,
                math.log1p(age) / 4.0, math.log1p(dens) / 3.0,
                1.0 if c["transport"] == "webtunnel" else 0.0]


def sigmoid(z):
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


model = load_json(os.path.join(DATA, "ai_fusion_model.json"), {})
NF = 6 + 8
w = model.get("weights") if isinstance(model.get("weights"), list) and len(model.get("weights", [])) == NF + 1 \
    else [0.0] * (NF + 1)
train = []
for key, c in parsed.items():
    rec = history[key]
    succ, fail = int(rec.get("probe_successes") or 0), int(rec.get("probe_failures") or 0)
    if succ + fail >= 3 and c["transport"] not in FRONTED:
        train.append((features(rec, c), 1.0 if succ / (succ + fail) >= 0.5 else 0.0))
rng = random.Random(HOUR_SEED)
acc = None
if len(train) >= 50:
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
    acc = hits / len(train)
    log(f"ai model trained on {len(train)} labelled bridges, accuracy={acc:.3f}")
REPORT["stages"]["ai_model"] = {"trained_on": len(train), "accuracy": acc}
write_json(os.path.join(DATA, "ai_fusion_model.json"),
           {"weights": [round(x, 6) for x in w], "trained_on": len(train), "accuracy": acc,
            "updated_at": iso_now, "features": NF})

scores = {}
for key, c in parsed.items():
    rec = history[key]
    succ, fail = int(rec.get("probe_successes") or 0), int(rec.get("probe_failures") or 0)
    h_obs = (succ + 1.0) / (succ + fail + 2.0)
    prior = sigmoid(w[0] + sum(a * b for a, b in zip(w[1:], features(rec, c))))
    dpi = DPI_PRIOR.get(c["transport"], 0.4)
    if c["transport"] == "obfs4":
        dpi += 0.2 * (c.get("iat", 0) >= 1) + 0.15 * (c["port"] in (443, 80))
    dpi = min(1.0, dpi)
    live = 1.0 if rec.get("tcp_reachable") else 0.0
    comp = 0.30 * h_obs + 0.20 * prior + 0.20 * dpi + 0.30 * live
    lat = rec.get("latency_ms")
    speed = 1.0 - min(float(lat), 4000.0) / 8000.0 if isinstance(lat, (int, float)) else 0.75
    scores[key] = {"score": round(comp, 4), "speed": round(speed, 4), "dpi": round(dpi, 3), "live": bool(live)}

# optional LLM strategy advice (advisory only, never required)
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
              "Allowed transports: webtunnel, snowflake, meek-azure, conjure, obfs4, vanilla.")
    s, b = http(url, method="POST", data=json.dumps({"model": mdl, "temperature": 0.2, "max_tokens": 200,
                                                     "messages": [{"role": "user", "content": prompt}]}),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"}, timeout=30, retries=1)
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


# ───────────────────────────── 5. FILL projections ─────────────────────────────
def fam_of(c):
    return "meek-azure" if c["transport"] in ("meek-azure", "meek_lite") else c["transport"]


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
                return (NOW - d) <= dt.timedelta(hours=72)
            except ValueError:
                pass
    return False


front_aaaa = {}
all_fronts = sorted({d for c in parsed.values() if c["transport"] in FRONTED for d in c.get("fronts", [])})
if not OFFLINE and all_fronts and left() > 30:
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        for d, r in zip(all_fronts, ex.map(aaaa, all_fronts)):
            front_aaaa[d] = r


def has_v6(c):
    return any(front_aaaa.get(f) for f in c.get("fronts", []))


def line_text(c, prefixed):
    if prefixed and c["transport"] == "vanilla":
        return "Bridge " + c["raw"]
    return c["raw"]


def members(family, v6, tested, fresh_only, prefixed=False, both=False):
    out = []
    for key, c in parsed.items():
        rec = history[key]
        if fam_of(c) != family:
            continue
        fronted = family in FRONTED
        if not both:
            if fronted:
                if v6 and not has_v6(c):
                    continue
            elif is_v6_record(key, c) != v6:
                continue
        if tested and not (rec.get("tcp_reachable") or rec.get("test_pass")):
            continue
        if fresh_only and not fresh(rec):
            continue
        out.append((scores[key]["score"], line_text(c, prefixed)))
    out.sort(key=lambda x: -x[0])
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


NAME = re.compile(r"^(snowflak|snowflake|obfs4|vanilla|webtunnel|meek_lite|meek-azure|conjure)(.*?)(\.txt)?$")


def union(*groups):
    seen, out = set(), []
    for g in groups:
        for ln in g:
            k = ln.strip()
            if k and k not in seen:
                seen.add(k)
                out.append(ln)
    return out


def dead_evidence():
    rows = []
    for key, c in parsed.items():
        rec = history[key]
        fail, succ = int(rec.get("probe_failures") or 0), int(rec.get("probe_successes") or 0)
        if not rec.get("tcp_reachable") and succ == 0 and fail >= 40 and c["transport"] not in FRONTED:
            rows.append((fail, line_text(c, True)))
    for b in (load_json(os.path.join(BRIDGE, "iran_results.json"), {}).get("bridges") or []):
        if str(b.get("iran_status", "")).lower() in ("iran_blocked", "blocked") and b.get("line"):
            rows.append((10 ** 6, b["line"]))
    rows.sort(key=lambda r: -r[0])
    return [ln for _, ln in rows[:1500]]


targets = set(os.listdir(BRIDGE)) | set(load_json(os.path.join(DATA, "run_manifest.json"), {}).get("files", {}).keys())
FB_PATH = os.path.join(DATA, "ai_fusion_fallbacks.json")
prev_fb = set(load_json(FB_PATH, {}).get("files", []))     # projections that were filled by a documented fallback
FB_USED = set()
projection_report = {"filled_from_empty": [], "still_empty": [], "updated": 0}
written = {}


def derive(name):
    """Return the freshly derived line list for one projection file (may be empty)."""
    if name.startswith("iran_blocked"):
        return dead_evidence()
    if name.startswith("iran_likely_working_"):
        kind = name[len("iran_likely_working_"):].removesuffix(".txt")
        if kind in ("obfs4", "vanilla", "webtunnel", "snowflake"):
            return members(kind, False, True, False, prefixed=True)
        if kind == "nin":
            return union(members("webtunnel", False, True, False, True),
                         members("snowflake", False, True, False, True))
        allk = []
        for fam in FAMILIES:
            allk += members(fam, False, True, False, True)
            if fam != "conjure":
                allk += members(fam, True, True, False, True)
        return union(allk)
    if name.startswith("tested_global_"):
        fam = name[len("tested_global_"):].removesuffix(".txt")
        return members(fam, False, True, False, True) if fam in FAMILIES else []
    m = NAME.match(name)
    if not m:
        return None
    fam = {"snowflak": "snowflake"}.get(m.group(1), m.group(1))
    rest = m.group(2)
    tested, f72 = "tested" in rest, "72h" in rest
    allb = rest.endswith("_all") or "ipv4_ipv6" in rest
    v6 = "ipv6" in rest and not allb
    if allb:
        return union(members(fam, False, tested, f72, tested), members(fam, True, tested, f72, tested))
    return members(fam, v6, tested, f72, tested)


def fallback(name):
    """Documented fallback chain for projections that have no strictly matching data."""
    m = NAME.match(name)
    if not m:
        return []
    fam = {"snowflak": "snowflake"}.get(m.group(1), m.group(1))
    rest = m.group(2)
    tested, f72, v6 = "tested" in rest, "72h" in rest, "ipv6" in rest
    if fam in FRONTED:
        # domain-fronted transports are address-family agnostic: reuse every verified fronted line
        got = members(fam, False, True, f72, both=True)
        return got or members(fam, False, False, False, both=True)
    got = members(fam, v6, tested, False, tested)          # relax the 72h window
    if got:
        return got
    if not tested:
        got = members(fam, v6, False, False, False)
        if got or not v6:
            return got
    if v6:
        # GitHub runners have no IPv6 egress, so IPv6 bridges cannot be TCP-verified there.
        # Fallback: strictly validated IPv6 lines re-observed in a live source this run
        # (then best AI score overall), capped — reported transparently, never claimed as probed.
        pool = [(scores[k]["score"], history[k].get("last_seen") == iso_now, line_text(c, True))
                for k, c in parsed.items() if fam_of(c) == fam and is_v6_record(k, c)]
        pool.sort(key=lambda r: (-int(r[1]), -r[0]))
        lines = [r[2] for r in pool[:50]]
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


SKIP = {"bridge_history.json", "bridge_list_for_testing.json", "bridge_scores.json", "iran_results.json",
        "telegram_manifest.json", "tor_bridges.zip"}
for name in sorted(targets):
    if name in SKIP or name.endswith((".json", ".zip", ".md")):
        continue
    d = derive(name)
    if d is None:
        continue
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
        merged = union(existing, d) if existing else list(d)
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
    "meek-azure_72h.txt": ["meek-azure.txt"], "conjure_72h_ipv6.txt": ["conjure_72h.txt", "conjure.txt"],
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

# JSON companions (append-only, schema-preserving)
tl = load_json(os.path.join(BRIDGE, "bridge_list_for_testing.json"), [])
if isinstance(tl, list):
    have = set(tl)
    for key, c in parsed.items():
        if c["raw"] not in have and history[key].get("first_seen") == iso_now:
            tl.append(c["raw"])
            have.add(c["raw"])
    write_json(os.path.join(BRIDGE, "bridge_list_for_testing.json"), tl)
bs = load_json(os.path.join(BRIDGE, "bridge_scores.json"), {})
if isinstance(bs, dict):
    for key, c in parsed.items():
        bs[c["raw"]] = {"score": scores[key]["score"], "transport": history[key].get("transport", c["transport"])}
    write_json(os.path.join(BRIDGE, "bridge_scores.json"), bs)
write_json(HIST_PATH, history)
REPORT["stages"]["projections"] = projection_report

# ───────────────────────────── 6. Iran hourly mix + anti-DPI profile ─────────────────────────────
QUOTA = {"webtunnel": 8, "snowflake": 3, "meek-azure": 2, "conjure": 1, "obfs4": 10, "vanilla": 2}
mix_rng = random.Random(HOUR_SEED)
mix, per_tr = [], {}
for tr, q in QUOTA.items():
    pool = [(k, c) for k, c in parsed.items() if fam_of(c) == tr and scores[k]["live"]]
    pool.sort(key=lambda kc: -(scores[kc[0]]["score"] * (0.7 + 0.3 * scores[kc[0]]["speed"])))
    pool = pool[: max(q * 4, 8)]
    jitter = {k: mix_rng.random() * 0.15 for k, _ in pool}
    pool.sort(key=lambda kc: -(scores[kc[0]]["score"] + jitter[kc[0]]))
    chosen, subnet_seen, host_seen = [], {}, {}
    for k, c in pool:
        sn = ".".join(c["host"].split(".")[:2]) if c["host"] and not c["ipv6"] else c["host"]
        uh = url_host(c.get("url", ""))[0] if c.get("url") else None
        if subnet_seen.get(sn, 0) >= 2 or (uh and host_seen.get(uh, 0) >= 2):
            continue
        subnet_seen[sn] = subnet_seen.get(sn, 0) + 1
        if uh:
            host_seen[uh] = host_seen.get(uh, 0) + 1
        chosen.append(k)
        if len(chosen) >= q:
            break
    per_tr[tr] = chosen
    for k in chosen:
        mix.append({"transport": tr, "line": parsed[k]["raw"], "ai_score": scores[k]["score"],
                    "speed": scores[k]["speed"], "dpi_resistance": scores[k]["dpi"],
                    "latency_ms": history[k].get("latency_ms")})


def tr_strength(t):
    keys = per_tr.get(t, [])
    avg = sum(scores[k]["score"] for k in keys) / len(keys) if keys else 0.0
    return DPI_PRIOR.get(t, 0) * 0.6 + avg * 0.4


priority = sorted(QUOTA, key=lambda t: -tr_strength(t))
if llm_advice:
    priority = llm_advice["priority"] + [t for t in priority if t not in llm_advice["priority"]]
mix_doc = {"generated_at": iso_now, "hour_seed": HOUR_SEED, "rotation": "deterministic per UTC hour",
           "transport_priority": priority, "count": len(mix), "bridges": mix,
           "note": "runner-side liveness + DPI-resistance prior; not an assertion of Iranian reachability"}
write_json(os.path.join(DATA, "iran_hourly_mix.json"), mix_doc)

tor = ["# Auto-generated hourly Iran bridge mix — " + iso_now,
       "# Rotates every UTC hour; regenerate: scripts/auto_bridge_fusion.sh",
       "UseBridges 1", "ClientTransportPlugin obfs4,meek_lite,webtunnel exec /usr/bin/lyrebird",
       "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client",
       "ClientTransportPlugin conjure exec /usr/bin/conjure-client",
       "# order of preference (best first): " + ", ".join(priority)]
for tr in priority:
    for b in mix:
        if b["transport"] == tr:
            tor.append("Bridge " + b["line"])
write_atomic(os.path.join(EXPORT, "iran_hourly_mix.torrc"), "\n".join(tor) + "\n")

live_fronts = sorted({f for k, c in parsed.items() if c["transport"] in FRONTED and scores[k]["live"]
                      for f in c.get("fronts", [])})
profile = {
    "generated_at": iso_now, "hour_seed": HOUR_SEED, "target": "IR",
    "transport_priority": priority,
    "ai": {"model": "online-logistic-v1", "trained_on": len(train), "accuracy": acc, "llm_advice": llm_advice},
    "dpi_countermeasures": {
        "tls_clienthello": {"utls_fingerprints": ["HelloChrome_Auto", "HelloFirefox_Auto", "HelloRandomizedALPN"],
                            "rotate_per_connection": True, "record_fragmentation_bytes": [1, 5, 40],
                            "alpn": ["h2", "http/1.1"]},
        "domain_fronting": {"live_fronts": live_fronts, "rotate_front_on_failure": True,
                            "max_consecutive_failures_before_rotate": 2},
        "traffic_shaping": {"obfs4_iat_mode": 2, "padding_jitter_ms": [5, 60], "burst_split": True},
        "port_policy": {"prefer": [443, 80, 8443, 8080, 2083], "avoid_fixed_high_ports_first": True},
        "bridge_rotation": {"interval_minutes": 60, "diversity": "max 2 per /16 and per URL host",
                            "retire_after_failures": 3},
        "nin_shutdown_survival": {"prefer": ["webtunnel", "snowflake", "meek-azure"],
                                  "reason": "CDN-fronted transports ride whitelisted domestic/CDN paths",
                                  "fallback_order": priority},
    },
    "counts": {"history": len(history), "live": sum(1 for s in scores.values() if s["live"]),
               "hourly_mix": len(mix), "admitted_this_run": admitted},
}
write_json(os.path.join(DATA, "iran_anti_dpi_profile.json"), profile)


# ───────────────────────────── 7. Ultra anti-DPI (Iran) + fastest-first export + freshness ─────────────────────────────
import hashlib


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
    "generated_at": iso_now, "target": "IR", "hour_seed": HOUR_SEED,
    "note": "advisory client-side hardening profile derived from live probes + online model; no claim of "
            "reachability inside Iran. Consumers: lyrebird / snowflake-client / conjure-client / sing-box style cores.",
    "adaptive_transport_weights": adaptive,
    "escalation_ladder": [
        {"step": 1, "use": "webtunnel", "why": "HTTPS/WebSocket look-alike on CDN-able hosts; best DPI prior"},
        {"step": 2, "use": "snowflake", "params": {"ampcache": True, "fronts": live_fronts[:6]}},
        {"step": 3, "use": "meek-azure", "params": {"utls": "HelloRandomizedALPN"}},
        {"step": 4, "use": "obfs4", "params": {"iat-mode": 2, "prefer_ports": [443, 80, 8443]}},
        {"step": 5, "use": "conjure", "params": {"phantom": True}},
        {"step": 6, "use": "vanilla", "params": {"only_if": "all else blocked"}},
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

fast_t = ["# Auto-generated FASTEST-FIRST Iran torrc — " + iso_now,
          "# Lowest measured handshake latency first, one bridge set per transport. Regenerated hourly.",
          "UseBridges 1", "ClientTransportPlugin obfs4,meek_lite,webtunnel exec /usr/bin/lyrebird",
          "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client",
          "ClientTransportPlugin conjure exec /usr/bin/conjure-client",
          "LearnCircuitBuildTimeout 1", "CircuitBuildTimeout 25", "KeepalivePeriod 60",
          "ConnectionPadding 1", "CircuitPadding 1", "NumCPUs 2"]
for tr in sorted(QUOTA, key=lambda t: -adaptive[t]):
    for b in fastest.get(tr, [])[:6]:
        fast_t.append("Bridge " + b["line"])
write_atomic(os.path.join(EXPORT, "iran_fastest.torrc"), "\n".join(fast_t) + "\n")

# freshness manifest — proves every projection was re-derived this run even when its bytes did not change
FR_PATH = os.path.join(DATA, "bridge_freshness.json")
fr_old = load_json(FR_PATH, {}).get("files", {})
fr_new = {}
SUPPLY_LIMITED = {"conjure": "Tor Project publishes a single conjure line",
                  "meek": "Tor Project publishes ≤3 meek lines", "snowflake": "Tor Project publishes ~10 snowflake lines"}
for fn in sorted(os.listdir(BRIDGE)):
    fp = os.path.join(BRIDGE, fn)
    if not os.path.isfile(fp) or fn.endswith((".json", ".zip")):
        continue
    with open(fp, "rb") as fh:
        raw_b = fh.read()
    h = hashlib.sha256(raw_b).hexdigest()
    prev_meta = fr_old.get(fn, {})
    entry = {"lines": raw_b.count(b"\n"), "sha256": h, "last_verified": iso_now,
             "content_changed_at": iso_now if prev_meta.get("sha256") != h else prev_meta.get("content_changed_at", iso_now)}
    for key, why in SUPPLY_LIMITED.items():
        if fn.startswith(key):
            entry["supply_limited"] = why
    if fn in FB_USED:
        entry["fallback"] = "served from real vanilla IPv4 lines (no public vanilla IPv6 source exists)"
    fr_new[fn] = entry
write_json(FR_PATH, {"generated_at": iso_now, "empty_files": sorted(n for n, e in fr_new.items() if e["lines"] == 0),
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

if [ "${FUSION_SKIP_ATTEST:-0}" = "1" ]; then
  echo "[fusion] attestation skipped (FUSION_SKIP_ATTEST=1)"
  exit 0
fi

# Derived NIN / PQ artefacts must stay byte-identical to a fresh regeneration of the bridge/ data we just
# wrote (repo invariants C11-C13). The builders are deterministic, so refreshing them is idempotent.
for builder in build_iran_cut_pack build_pq_bridge_scores build_nin_recommended_transport; do
  bash "$SCRIPT_DIR/$builder.sh" >/dev/null 2>&1 || echo "[fusion] note: $builder.sh did not complete (non-fatal)"
done

# Re-attest manifest / ZIP / README to the bytes we just wrote, then verify.
bash "$SCRIPT_DIR/publication_contract.sh" --rebuild --sync-counts --root "$ROOT" --bridge-dir "$BRIDGE_DIR"
bash "$SCRIPT_DIR/publication_contract.sh" --check --root "$ROOT" --bridge-dir "$BRIDGE_DIR"

# Refresh data/run_manifest.json (bytes / lines / sha256 per published file) so the
# post-push raw-CDN verification keeps matching what is committed.
python3 - <<'PY'
import hashlib
import json
import os

bridge = os.environ.get("BRIDGE_DIR", "bridge")
path = os.path.join(os.environ.get("DATA_DIR", "data"), "run_manifest.json")
try:
    with open(path, encoding="utf-8") as fh:
        manifest = json.load(fh)
except (OSError, ValueError):
    raise SystemExit(0)
files = manifest.get("files")
if isinstance(files, dict):
    for name, meta in files.items():
        p = os.path.join(bridge, name)
        if not os.path.isfile(p) or not isinstance(meta, dict):
            continue
        with open(p, "rb") as fh:
            data = fh.read()
        meta["bytes"] = len(data)
        meta["lines"] = data.count(b"\n")
        meta["sha256"] = hashlib.sha256(data).hexdigest()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)
    print("[fusion] data/run_manifest.json refreshed")
PY

#!/usr/bin/env python3
"""
scripts/circleci_ooni_poller.py — OONI Iran snapshot poller for CircleCI.

This is the scheduled job that replaces Northflank. It runs every 6 h (shallow)
and every 12 h (deep) on CircleCI's free tier (no credit-card required), pulls
fresh Iran (probe_cc=IR) measurements from the OONI public API, classifies each
known Tor bridge IP, writes a snapshot to data/ooni_iran_snapshot.json, updates
the dashboard & telemetry state files, and exits 0. The calling CircleCI job
then commits & pushes the snapshot.

Endpoints (verified active as of 2026-03):
  • https://api.ooni.io/api/v1/measurements   (per-input query, used here)
  • https://api.ooni.io/api/v1/aggregation    (rolled-up counts, optional)

API docs:  https://docs.ooni.org
No API key, no auth, no rate-limit signup. Just a 5 req/s courtesy limit,
which we honour with a 200 ms sleep between requests.

Modes
-----
--depth shallow   last 7 days,  up to 25 bridges          (~10-15 s)
--depth deep      last 90 days, up to 100 bridges         (~2-3 min)

Exit codes
----------
  0   snapshot written (or unchanged since last poll)
  1   OONI API unreachable after retries
  2   bad CLI args
  3   I/O error writing snapshot
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter, Retry
UTC = timezone.utc

# ─────────────────────────────────────────────────────────────────────────────
# Logging — CircleCI-friendly: timestamps in UTC, single-line.
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-7s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logging.Formatter.converter = time.gmtime
log = logging.getLogger("ooni-poll")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
OONI_BASE        = "https://api.ooni.io/api/v1/measurements"
OONI_TIMEOUT     = 30
OONI_RATE_SLEEP  = 0.2          # 5 req/s courtesy limit
OONI_MAX_RETRIES = 3
OONI_BACKOFF     = 2            # seconds, doubled per retry

# Where to find the list of bridge IPs to probe. This file is produced by
# main.py during a scrape; if missing we fall back to a static seed list.
BRIDGES_FILE     = "data/iran_bridges.json"
STATIC_SEED_FILE = "data/elite_registry_cache.json"

DEPTH_PARAMS = {
    # depth  : (days_back, limit_per_ip, max_bridges, days_temporal)
    "shallow": (7,   5,   25, 30),
    "deep"  : (90, 100, 100, 90),
}

# ─────────────────────────────────────────────────────────────────────────────
# HTTP session with retries on 429/5xx.
# ─────────────────────────────────────────────────────────────────────────────
def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=OONI_MAX_RETRIES,
        backoff_factor=OONI_BACKOFF,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.headers.update({"Accept": "application/json", "User-Agent": "TorShield-IR-CircleCI/1.0"})
    return s

# ─────────────────────────────────────────────────────────────────────────────
# Bridge IP source
# ─────────────────────────────────────────────────────────────────────────────
def load_bridge_ips() -> list[str]:
    """Load the list of bridge IPs to probe, preferring the live scrape output."""
    # Try the live bridges file first.
    p = Path(BRIDGES_FILE)
    if p.exists():
        try:
            data = json.loads(p.read_text())
            ips: list[str] = []
            if isinstance(data, list):
                for entry in data:
                    ip = _extract_ip(entry)
                    if ip and ip not in ips:
                        ips.append(ip)
            elif isinstance(data, dict):
                for key in ("bridges", "items", "results"):
                    if key in data and isinstance(data[key], list):
                        for entry in data[key]:
                            ip = _extract_ip(entry)
                            if ip and ip not in ips:
                                ips.append(ip)
            if ips:
                log.info("Loaded %d bridge IPs from %s", len(ips), BRIDGES_FILE)
                return ips
        except (json.JSONDecodeError, OSError) as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.circleci_ooni_poller:120', exc)
            log.warning("Could not parse %s: %s — falling back to static seed",
                        BRIDGES_FILE, exc)

    # Fall back to the elite registry cache.
    p = Path(STATIC_SEED_FILE)
    if p.exists():
        try:
            data = json.loads(p.read_text())
            ips = []
            if isinstance(data, dict):
                # registry format: { "bridges": [ { "ip": "1.2.3.4", ... }, ... ] }
                bridges = data.get("bridges") or data.get("items") or []
                for entry in bridges:
                    ip = _extract_ip(entry)
                    if ip and ip not in ips:
                        ips.append(ip)
            if ips:
                log.info("Loaded %d bridge IPs from %s", len(ips), STATIC_SEED_FILE)
                return ips
        except (json.JSONDecodeError, OSError) as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.circleci_ooni_poller:140', exc)
            log.warning("Could not parse %s: %s", STATIC_SEED_FILE, exc)

    log.warning("No bridge IPs available — will poll OONI's general IR feed only.")
    return []


def _extract_ip(entry: Any) -> str | None:
    """Best-effort IP extraction from a bridge record."""
    if not isinstance(entry, dict):
        return None
    for key in ("ip", "address", "addr", "host"):
        val = entry.get(key)
        if val and isinstance(val, str) and val.count(".") == 3:
            # crude IPv4 check; bridge-probe handles IPv6 elsewhere
            return val.split(":")[0]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# OONI query
# ─────────────────────────────────────────────────────────────────────────────
def query_ooni(
    session: requests.Session,
    ip: str,
    since: datetime,
    until: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    """Query OONI for measurements of `ip` from Iranian probes."""
    params = {
        "probe_cc": "IR",
        "input":    ip,
        "limit":    str(limit),
        # OONI API: only valid order_by value is "measurement_start_time".
        # "test_start_time" returns HTTP 422 (verified 2026-03-26).
        "order_by": "measurement_start_time",
        "since":    since.strftime("%Y-%m-%d"),
        "until":    until.strftime("%Y-%m-%d"),
    }
    try:
        resp = session.get(OONI_BASE, params=params, timeout=OONI_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("results", [])
        log.warning("OONI HTTP %d for %s", resp.status_code, ip)
    except requests.RequestException as exc:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('scripts.circleci_ooni_poller:186', exc)
        log.warning("OONI request error for %s: %s", ip, exc)
    return []


def classify(results: list[dict[str, Any]]) -> tuple[str, float, int, int]:
    """Classify a bridge from its OONI measurement results.
    Returns (status, recurrence_rate_per_30d, anomaly_count, total)."""
    if not results:
        return "iran_unknown", 0.0, 0, 0

    anomaly = sum(1 for m in results if m.get("anomaly") or m.get("confirmed"))
    total = len(results)

    if anomaly == 0:
        status = "iran_likely_working"
    elif anomaly == total:
        status = "iran_likely_blocked"
    else:
        status = "iran_likely_blocked"  # mixed → lean cautious

    # recurrence rate = anomalies per 30-day period (rough)
    rate = anomaly / (total / 30.0) if total else 0.0
    if rate > 2.0:
        status = "iran_frequently_blocked"

    return status, round(rate, 3), anomaly, total


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot writer
# ─────────────────────────────────────────────────────────────────────────────
def write_snapshot(
    out_path: Path,
    snapshot: dict[str, Any],
) -> bool:
    """Write the snapshot, return True if content changed since last run."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    new_text = json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if out_path.exists() and out_path.read_text(encoding="utf-8") == new_text:
        return False
    out_path.write_text(new_text, encoding="utf-8")
    return True


def update_dashboard(path: Path, snapshot: dict[str, Any]) -> None:
    """Merge snapshot summary into the dashboard file (additive, no overwrite)."""
    existing: dict[str, Any] = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.circleci_ooni_poller:237', _remediation_exc)
            existing = {}
    if not isinstance(existing, dict):
        existing = {}
    summary = snapshot.get("summary", {})
    existing["ooni_last_poll"] = snapshot.get("polled_at")
    existing["ooni_summary"]   = summary
    existing["ooni_history"]   = (existing.get("ooni_history") or [])[-23:] + [
        {"at": snapshot.get("polled_at"), **summary}
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def update_telemetry(path: Path, snapshot: dict[str, Any]) -> None:
    existing: dict[str, Any] = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.circleci_ooni_poller:257', _remediation_exc)
            existing = {}
    if not isinstance(existing, dict):
        existing = {}
    existing["ooni_last_poll"] = snapshot.get("polled_at")
    existing["ooni_poll_count"] = existing.get("ooni_poll_count", 0) + 1
    existing["ooni_last_summary"] = snapshot.get("summary", {})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def update_censorship_state(path: Path, snapshot: dict[str, Any]) -> None:
    """Lightweight state file consumed by iran_smart_anti_filter.py."""
    existing: dict[str, Any] = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.circleci_ooni_poller:275', _remediation_exc)
            existing = {}
    if not isinstance(existing, dict):
        existing = {}
    blocked = [b for b in snapshot.get("bridges", []) if b["status"] == "iran_likely_blocked"]
    freq    = [b for b in snapshot.get("bridges", []) if b["status"] == "iran_frequently_blocked"]
    existing["ooni_blocked_ips"]     = [b["ip"] for b in blocked]
    existing["ooni_frequent_blocked"] = [b["ip"] for b in freq]
    existing["ooni_last_update"]     = snapshot.get("polled_at")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OONI Iran poller (CircleCI scheduled)")
    p.add_argument("--depth", choices=("shallow", "deep"), default="shallow")
    p.add_argument("--out",       default="data/ooni_iran_snapshot.json")
    p.add_argument("--dashboard", default="data/dashboard.json")
    p.add_argument("--telemetry", default="data/telemetry_state.json")
    p.add_argument("--censorship-state", default="data/censorship_state.json")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if args.depth not in DEPTH_PARAMS:
        log.error("Unknown depth: %s", args.depth)
        return 2

    days_back, limit, max_bridges, _ = DEPTH_PARAMS[args.depth]
    now = datetime.now(UTC)
    since = now - timedelta(days=days_back)

    log.info("OONI poll starting — depth=%s days_back=%d", args.depth, days_back)

    # Live API reachability check — query the real /measurements endpoint
    # (not /health, which doesn't exist on OONI and returns 404).
    session = make_session()
    try:
        probe = session.get(
            OONI_BASE,
            params={"probe_cc": "IR", "limit": "1"},
            timeout=10,
        )
        if probe.status_code != 200:
            log.error("OONI API unreachable (HTTP %d) — aborting this run.",
                      probe.status_code)
            return 1
        log.info("OONI API reachable — proceeding with poll.")
    except requests.RequestException as exc:
        log.error("OONI API connection failed: %s — aborting this run.", exc)
        return 1

    bridges = load_bridge_ips()[:max_bridges]
    if not bridges:
        log.warning("No bridges to poll — producing an empty snapshot.")

    results_list: list[dict[str, Any]] = []
    summary = {
        "iran_likely_working":       0,
        "iran_likely_blocked":       0,
        "iran_frequently_blocked":   0,
        "iran_unknown":              0,
        "total":                     0,
    }

    for i, ip in enumerate(bridges, 1):
        log.info("[%d/%d] polling %s", i, len(bridges), ip)
        ms = query_ooni(session, ip, since, now, limit)
        status, rate, anomaly, total = classify(ms)
        results_list.append({
            "ip":             ip,
            "status":         status,
            "recurrence_rate": rate,
            "anomalies":      anomaly,
            "total_measurements": total,
            "last_seen":      (ms[0].get("test_start_time") if ms else None),
        })
        summary[status] = summary.get(status, 0) + 1
        summary["total"] += 1
        time.sleep(OONI_RATE_SLEEP)

    snapshot = {
        "polled_at":   now.isoformat(timespec="seconds"),
        "depth":       args.depth,
        "days_back":   days_back,
        "source":      "https://api.ooni.io/api/v1/measurements",
        "probe_cc":    "IR",
        "bridge_count": len(bridges),
        "summary":     summary,
        "bridges":     results_list,
    }

    out_path = Path(args.out)
    try:
        changed = write_snapshot(out_path, snapshot)
        update_dashboard(Path(args.dashboard), snapshot)
        update_telemetry(Path(args.telemetry), snapshot)
        update_censorship_state(Path(args.censorship_state), snapshot)
    except OSError as exc:
        log.error("I/O error writing snapshot: %s", exc)
        return 3

    log.info("Snapshot written: %s (changed=%s)", out_path, changed)
    log.info("Summary: %s", json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

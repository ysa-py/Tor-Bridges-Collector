#!/usr/bin/env python3
"""Choose bounded public TCP timeout-control candidates without trusting them as evidence.

The selected descriptors come from prior repository data only as target candidates.
Only a fresh authenticated relay observation can establish a current timeout, stage,
and vantage. This helper deliberately emits no source record IDs or diagnostics.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_CONTROLS = 4
TIMEOUT_TEXT = re.compile(r"timed.?out|timeout", re.IGNORECASE)


def _candidate(record: Any) -> tuple[ipaddress.IPv4Address, int] | None:
    if not isinstance(record, dict) or record.get("success") is not False:
        return None
    error = record.get("error")
    if not isinstance(error, str) or not TIMEOUT_TEXT.search(error):
        return None

    host = record.get("host")
    port = record.get("port")
    if not isinstance(host, str) or isinstance(port, bool) or not isinstance(port, int):
        return None
    if not 1 <= port <= 65535:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        return None
    return address, port


def select_controls(document: Any, limit: int = MAX_CONTROLS) -> list[dict[str, Any]]:
    if not isinstance(document, list) or not 1 <= limit <= MAX_CONTROLS:
        return []

    candidates: list[tuple[ipaddress.IPv4Address, int]] = []
    seen_endpoints: set[tuple[ipaddress.IPv4Address, int]] = set()
    for record in document:
        endpoint = _candidate(record)
        if endpoint is None or endpoint in seen_endpoints:
            continue
        seen_endpoints.add(endpoint)
        candidates.append(endpoint)

    # Prefer different /24 networks first so a single routing/policy anomaly is
    # less likely to dominate the timeout control. Preserve input order within
    # each pass for deterministic, reviewable CI behavior.
    selected: list[tuple[ipaddress.IPv4Address, int]] = []
    seen_networks: set[ipaddress.IPv4Network] = set()
    for endpoint in candidates:
        network = ipaddress.ip_network(f"{endpoint[0]}/24", strict=False)
        if network in seen_networks:
            continue
        selected.append(endpoint)
        seen_networks.add(network)
        if len(selected) == limit:
            break
    if len(selected) < limit:
        for endpoint in candidates:
            if endpoint in selected:
                continue
            selected.append(endpoint)
            if len(selected) == limit:
                break

    return [
        {
            "id": f"timeout-control-{index}",
            "host": str(address),
            "port": port,
            "transport": "vanilla",
        }
        for index, (address, port) in enumerate(selected, start=1)
    ]


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    path = Path(sys.argv[1])
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return 1
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return 1

    controls = select_controls(document)
    if not controls:
        return 1
    sys.stdout.write(json.dumps(controls, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

"""
core/collector.py — Orchestrates bridge collection from all sources.

Runs all enabled sources concurrently and merges results into
HistoryManager, deduplicating across transports and IP versions.

Sources (in priority order):
  1. torproject   — bridges.torproject.org scraper
  2. moat         — MOAT/BridgeDB REST API (direct + domain-fronted)
  3. bridgedb_api — BridgeDB HTTPS API (direct + Fastly-fronted)
  4. telegram     — Public Tor-bridge Telegram channels
  5. static       — Hard-coded fallback bridges

Phase 4.3 (ADDITIVE): ``prioritize_port_443`` filter is applied after
scoring so port-443 (HTTPS-disguised) bridges always float to the front
of any bridge list. Iran almost never blocks port 443.
"""


import asyncio
import logging
from typing import Any

import config
from core.history import HistoryManager

log = logging.getLogger(__name__)


def prioritize_port_443(bridges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Move port-443 bridges to the front of ``bridges``.

    Iran almost never blocks HTTPS port 443, so bridges listening on 443
    get a structural advantage. The relative order of port-443 bridges
    and the relative order of non-443 bridges are both preserved (stable
    partition).

    This filter is ADDITIVE: callers that don't use it see no change.
    """
    p443 = [b for b in bridges if _port_of(b) == 443]
    other = [b for b in bridges if _port_of(b) != 443]
    return p443 + other


def _port_of(bridge: dict[str, Any]) -> int:
    """Best-effort extraction of a bridge's port (0 if unknown)."""
    try:
        return int(bridge.get("port") or 0)
    except Exception:
        return 0


class BridgeCollector:
    def __init__(self, history: HistoryManager):
        self._history = history

    async def collect_all(self) -> int:
        """
        Fetch from all enabled sources concurrently.
        Returns the number of new bridges added to history.
        """
        tasks: list[asyncio.Task] = []

        if config.USE_TORPROJECT_SCRAPER:
            from sources.torproject import fetch_all as tp_fetch
            tasks.append(asyncio.create_task(tp_fetch(), name="torproject"))

        if config.USE_MOAT_API:
            from sources.moat import fetch_all as moat_fetch
            tasks.append(asyncio.create_task(moat_fetch(), name="moat"))

        if config.USE_BRIDGEDB_API:
            from sources.bridgedb_api import fetch_all as bdb_fetch
            tasks.append(asyncio.create_task(bdb_fetch(), name="bridgedb_api"))

        if config.USE_TELEGRAM_SOURCES:
            from sources.telegram_bridges import fetch_all as tg_fetch
            tasks.append(asyncio.create_task(tg_fetch(), name="telegram"))

        if config.USE_GITHUB_SOURCES:
            try:
                from sources.github_bridges import fetch_all as gh_fetch
                tasks.append(asyncio.create_task(gh_fetch(), name="github"))
            except ImportError as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('core.collector:87', _remediation_exc)
                log.warning("GitHub bridges source not available (import error)")

        gathered: list[list[tuple[str, str, str]]] = await asyncio.gather(
            *tasks, return_exceptions=True
        )

        before = len(self._history.get_all())
        for result in gathered:
            if isinstance(result, Exception):
                log.error("Source error: %s", result)
                continue
            for line, transport, _ip_ver in result:
                self._history.add_bridge(line, transport)

        # Static bridges (synchronous, always run last as fallback)
        if config.USE_STATIC_BRIDGES:
            from sources.static_bridges import get_all
            for line, transport, _ip_ver in get_all():
                self._history.add_bridge(line, transport)

        after = len(self._history.get_all())
        new_count = after - before
        log.info(
            "Collection complete: %d new bridges added (total: %d).",
            new_count, after,
        )
        return new_count

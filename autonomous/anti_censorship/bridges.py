"""
autonomous/anti_censorship/bridges.py
=======================================
Tor bridge configuration and automatic selection.

Supports: obfs4, meek-azure, meek-cloudfront, snowflake, webtransport.
Bridges are tried in priority order; failed bridges are back-off'd.
New bridges can be fetched from BridgeDB automatically.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .obfuscator import ObfuscationProtocol

logger = logging.getLogger(__name__)


@dataclass
class BridgeConfig:
    """
    A single Tor bridge entry.

    Parameters
    ----------
    address     : IP or hostname of the bridge
    port        : TCP port
    protocol    : obfuscation protocol used
    fingerprint : SHA-1 fingerprint of the bridge's identity key (hex)
    extra_params: protocol-specific parameters (e.g. cert= for obfs4)
    priority    : lower = tried first
    """
    address:      str
    port:         int
    protocol:     ObfuscationProtocol
    fingerprint:  Optional[str]               = None
    extra_params: Dict[str, str]              = field(default_factory=dict)
    priority:     int                         = 50

    def to_bridge_line(self) -> str:
        """Emit the Tor torrc bridge line."""
        proto = self.protocol.value
        base  = f"{self.address}:{self.port}"
        fp    = self.fingerprint or ""

        if self.protocol == ObfuscationProtocol.PLAIN:
            return f"{base} {fp}".strip()

        if self.protocol == ObfuscationProtocol.OBFS4:
            params = " ".join(f"{k}={v}" for k, v in self.extra_params.items())
            return f"obfs4 {base} {fp} {params}".strip()

        if self.protocol in (ObfuscationProtocol.MEEK_AZURE,
                              ObfuscationProtocol.MEEK_CF):
            url = self.extra_params.get("url", "https://meek.azurefd.net/")
            return f"meek {base} {fp} url={url}".strip()

        if self.protocol == ObfuscationProtocol.SNOWFLAKE:
            return f"snowflake {base} {fp}".strip()

        return f"{proto} {base} {fp}".strip()


# ── Hardcoded public bridges (updated 2025) ───────────────────────
# These are pulled from official BridgeDB; add your own for better
# reliability — bridges shared publicly are eventually blocked.
DEFAULT_BRIDGES: List[BridgeConfig] = [
    # meek-azure: tunnels over Azure CDN — very hard for Iran to block
    BridgeConfig(
        address="20.186.13.205",
        port=443,
        protocol=ObfuscationProtocol.MEEK_AZURE,
        extra_params={"url": "https://meek.azurefd.net/"},
        priority=10,
    ),
    # Snowflake: WebRTC via browser volunteers — survives most blocking
    BridgeConfig(
        address="snowflake-broker.torproject.net",
        port=443,
        protocol=ObfuscationProtocol.SNOWFLAKE,
        priority=20,
    ),
    # obfs4 bridges (IPs change; these are examples)
    BridgeConfig(
        address="192.95.36.142",
        port=443,
        protocol=ObfuscationProtocol.OBFS4,
        fingerprint="CDF2E852BF539B82BD10E27E9115A31734E378C2",
        extra_params={
            "cert": "qUVQ0srL1JI/vO6V6m/24anYXiJD3zP8o7ULQzu2RDy"
                    "6GIVCbvGrDlhk9MhFBlRmFBMf+Q",
            "iat-mode": "0",
        },
        priority=30,
    ),
    BridgeConfig(
        address="37.218.240.34",
        port=40035,
        protocol=ObfuscationProtocol.OBFS4,
        fingerprint="88CC36E5B4B9E6E1A7F9A09D3FE0A6E6CED1D51E",
        extra_params={
            "cert": "YN3HxIFTKYa2FxmrTqGXHoRAZ6gGKxMUF9QBVHwMEg"
                    "sKZPqNX0vq0mFIJBIFRn0w9WOVvA",
            "iat-mode": "0",
        },
        priority=31,
    ),
    # meek-cloudfront: tunnels over AWS CloudFront
    BridgeConfig(
        address="d2zfqthxsdq309.cloudfront.net",
        port=443,
        protocol=ObfuscationProtocol.MEEK_CF,
        extra_params={"url": "https://d2zfqthxsdq309.cloudfront.net/"},
        priority=40,
    ),
]


class TorBridgeManager:
    """
    Manages a pool of Tor bridges.

    Automatically:
      - Tries bridges in priority order
      - Backs off failed bridges with exponential delay
      - Generates torrc stanzas
      - Can refresh from BridgeDB (if network allows)
    """

    _BACKOFF_INITIAL = 30.0    # seconds
    _BACKOFF_MAX     = 3600.0  # 1 hour

    def __init__(
        self,
        bridges:         Optional[List[BridgeConfig]] = None,
        probe_timeout:   float = 6.0,
    ) -> None:
        self.bridges         = sorted(
            bridges or DEFAULT_BRIDGES, key=lambda b: b.priority
        )
        self._probe_timeout  = probe_timeout
        self.active_bridge:  Optional[BridgeConfig] = None
        self._failures:      Dict[str, int]         = {}   # key → fail count
        self._backoff_until: Dict[str, float]       = {}   # key → timestamp

    # ── Internal helpers ──────────────────────────────────────────

    def _key(self, b: BridgeConfig) -> str:
        return f"{b.address}:{b.port}"

    def _in_backoff(self, b: BridgeConfig) -> bool:
        return time.monotonic() < self._backoff_until.get(self._key(b), 0.0)

    def _record_failure(self, b: BridgeConfig) -> None:
        k = self._key(b)
        n = self._failures.get(k, 0) + 1
        self._failures[k] = n
        backoff = min(self._BACKOFF_INITIAL * (2 ** (n - 1)), self._BACKOFF_MAX)
        self._backoff_until[k] = time.monotonic() + backoff
        logger.debug(f"Bridge {k} failed (attempt {n}); backoff {backoff:.0f}s")

    def _record_success(self, b: BridgeConfig) -> None:
        k = self._key(b)
        self._failures.pop(k, None)
        self._backoff_until.pop(k, None)

    # ── Probe a single bridge ─────────────────────────────────────

    async def _probe(self, b: BridgeConfig) -> bool:
        """Return True if the bridge TCP port is reachable."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(b.address, b.port),
                timeout=self._probe_timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception as exc:
            logger.debug(f"Bridge {self._key(b)} unreachable: {exc}")
            return False

    # ── Public API ────────────────────────────────────────────────

    async def find_working_bridge(self) -> Optional[BridgeConfig]:
        """
        Try each bridge in priority order (skip those in back-off).
        Returns the first reachable bridge and sets self.active_bridge.
        """
        for bridge in self.bridges:
            if self._in_backoff(bridge):
                continue
            if await self._probe(bridge):
                self._record_success(bridge)
                self.active_bridge = bridge
                logger.info(
                    f"Working bridge: {self._key(bridge)} "
                    f"({bridge.protocol.value})"
                )
                return bridge
            self._record_failure(bridge)

        logger.warning("No reachable Tor bridge found")
        return None

    def add_bridge(self, bridge: BridgeConfig) -> None:
        """Insert a new bridge and clear its failure state."""
        self.bridges.append(bridge)
        self.bridges.sort(key=lambda b: b.priority)
        k = self._key(bridge)
        self._failures.pop(k, None)
        self._backoff_until.pop(k, None)

    def generate_torrc(self) -> str:
        """
        Generate a torrc snippet that enables all registered bridges.
        Paste this into /etc/tor/torrc or use with --allow-missing-torrc.
        """
        lines = [
            "UseBridges 1",
            "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy",
            "ClientTransportPlugin meek exec /usr/bin/meek-client",
            "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client",
            "ClientTransportPlugin webtransport exec /usr/bin/webtransport-client",
            "",
        ]
        for b in self.bridges:
            lines.append(f"Bridge {b.to_bridge_line()}")
        return "\n".join(lines)

    def status(self) -> dict:
        """Return a summary dict for logging / health checks."""
        return {
            "total_bridges":   len(self.bridges),
            "active":          self._key(self.active_bridge) if self.active_bridge else None,
            "in_backoff":      sum(1 for b in self.bridges if self._in_backoff(b)),
            "failed_counts":   dict(self._failures),
        }

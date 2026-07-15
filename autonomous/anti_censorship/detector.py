"""
autonomous/anti_censorship/detector.py
=========================================
DPI detection: probes network conditions and identifies filtering level.
Specific signatures for Iran's censorship infrastructure (Huawei DPI, etc.).
"""

import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class FilteringLevel(IntEnum):
    """Severity of detected filtering / censorship."""
    NONE       = 0   # Open internet
    BASIC      = 1   # Simple IP / domain blocks
    MODERATE   = 2   # DNS poisoning + some DPI
    AGGRESSIVE = 3   # Heavy DPI, VPN detection, SNI blocking
    TOTAL      = 4   # Near-complete shutdown (shutdown mode)


@dataclass
class NetworkProbe:
    """Result of a single connectivity probe."""
    target:       str
    reachable:    bool
    latency_ms:   float
    dpi_detected: bool
    throttled:    bool
    protocol:     Optional[str] = None
    error:        Optional[str] = None


# ── Well-known probe targets ──────────────────────────────────────
_DNS_PROBES: List[Tuple[str, int]] = [
    ("8.8.8.8",         53),   # Google DNS
    ("1.1.1.1",         53),   # Cloudflare DNS
    ("208.67.222.222",  53),   # OpenDNS
    ("9.9.9.9",         53),   # Quad9
]

_HTTPS_PROBES: List[Tuple[str, int]] = [
    ("api.github.com",      443),
    ("www.google.com",      443),
    ("cloudflare.com",      443),
    ("ajax.googleapis.com", 443),
]

# ── Iran-specific DPI signatures (Huawei / ZTE based systems) ────
_IRAN_DPI_RST_LATENCY_MS = 600   # RST injection often arrives ~600 ms
_THROTTLE_THRESHOLD_MS   = 2_500  # Any latency above this suggests throttling


class DPIDetector:
    """
    Detect and characterise filtering / DPI on the current network.

    Fully asynchronous, cache results to avoid redundant probing.
    """

    def __init__(self, probe_timeout: float = 5.0):
        self._timeout = probe_timeout
        self._cache: Dict[str, Tuple[NetworkProbe, float]] = {}
        self._cache_ttl = 60.0  # seconds

    # ── Public API ────────────────────────────────────────────────

    async def probe_tcp(self, host: str, port: int) -> NetworkProbe:
        """Low-level TCP reachability probe."""
        cache_key = f"{host}:{port}"
        cached = self._cache.get(cache_key)
        if cached and (time.monotonic() - cached[1]) < self._cache_ttl:
            return cached[0]

        t0 = time.monotonic()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self._timeout,
            )
            latency_ms = (time.monotonic() - t0) * 1_000
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            # Iran DPI often injects RST very quickly; distinguish from real connections
            dpi_detected = latency_ms < 5.0  # suspiciously fast = likely RST injection
            probe = NetworkProbe(
                target=cache_key,
                reachable=True,
                latency_ms=latency_ms,
                dpi_detected=dpi_detected,
                throttled=latency_ms > _THROTTLE_THRESHOLD_MS,
            )
        except asyncio.TimeoutError:
            probe = NetworkProbe(
                target=cache_key,
                reachable=False,
                latency_ms=-1.0,
                dpi_detected=True,   # timeout ⟹ likely DPI drop
                throttled=False,
                error="timeout",
            )
        except (ConnectionRefusedError, OSError) as exc:
            probe = NetworkProbe(
                target=cache_key,
                reachable=False,
                latency_ms=-1.0,
                dpi_detected=False,
                throttled=False,
                error=str(exc),
            )

        self._cache[cache_key] = (probe, time.monotonic())
        return probe

    async def probe_dns(self, hostname: str = "www.google.com") -> bool:
        """
        Detect DNS poisoning: resolve a well-known hostname and compare
        against expected IP ranges.  Iran often redirects to 10.10.34.34.
        """
        POISONED_IPS = {
            "10.10.34.34",    # Iran FATA (known poison address)
            "10.10.34.35",
            "127.0.0.1",
        }
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.getaddrinfo(
                hostname, None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
            ip = infos[0][4][0]
            if ip in POISONED_IPS:
                logger.warning(f"DNS poisoning detected: {hostname} → {ip}")
                return True
            return False
        except Exception:
            return False  # Could not resolve — filtering present but not poison

    async def detect_filtering_level(self) -> FilteringLevel:
        """
        Probe multiple targets and return the overall FilteringLevel.
        Runs all probes concurrently for speed.
        """
        dns_probes, https_probes, dns_poisoned = await asyncio.gather(
            asyncio.gather(*[self.probe_tcp(h, p) for h, p in _DNS_PROBES]),
            asyncio.gather(*[self.probe_tcp(h, p) for h, p in _HTTPS_PROBES]),
            self.probe_dns(),
        )

        dns_up   = sum(1 for p in dns_probes   if p.reachable)
        https_up = sum(1 for p in https_probes if p.reachable)
        dpi_hits = sum(1 for p in list(dns_probes) + list(https_probes)
                       if p.dpi_detected)

        total_targets = len(_DNS_PROBES) + len(_HTTPS_PROBES)
        reachable     = dns_up + https_up

        logger.info(
            f"Filtering probe: {reachable}/{total_targets} reachable, "
            f"{dpi_hits} DPI hints, dns_poisoned={dns_poisoned}"
        )

        if reachable == total_targets and not dns_poisoned:
            return FilteringLevel.NONE
        elif reachable >= total_targets * 0.75:
            return FilteringLevel.BASIC
        elif reachable >= total_targets * 0.4 or dns_poisoned:
            return FilteringLevel.MODERATE
        elif reachable >= 1:
            return FilteringLevel.AGGRESSIVE
        else:
            return FilteringLevel.TOTAL

    def invalidate_cache(self) -> None:
        """Force fresh probes on next call."""
        self._cache.clear()

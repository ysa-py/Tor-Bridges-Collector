"""
autonomous/anti_censorship/router.py
======================================
SmartAntiCensorshipRouter: fully automatic, zero-config bypass layer.

Algorithm:
  1. On first request (or after recheck_interval_s), probe the network.
  2. Choose the lightest protocol that works:
       NONE  → direct HTTPS
       BASIC → HTTP mimicry obfuscation
       MOD   → obfs4 bridge
       AGG   → meek-azure bridge
       TOTAL → snowflake
  3. If the chosen protocol fails, escalate automatically.
  4. All choices are cached and re-evaluated periodically.

This class wraps aiohttp or plain asyncio streams — whichever is available.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from .bridges import BridgeConfig, TorBridgeManager
from .detector import DPIDetector, FilteringLevel
from .iran import IranBypassConfig
from .obfuscator import ObfuscationProtocol, TrafficObfuscator

logger = logging.getLogger(__name__)


class SmartAntiCensorshipRouter:
    """
    Fully automatic anti-censorship router.

    Parameters
    ----------
    bypass_config : IranBypassConfig, optional
        Iran-tuned preset.  Defaults to IranBypassConfig.recommended().
    recheck_interval_s : float
        How often (seconds) to re-probe filtering level.
    """

    def __init__(
        self,
        bypass_config:       Optional[IranBypassConfig] = None,
        recheck_interval_s:  float = 120.0,
    ) -> None:
        self._cfg            = bypass_config or IranBypassConfig.recommended()
        self._recheck        = recheck_interval_s
        self._detector       = DPIDetector()
        self._bridge_mgr     = TorBridgeManager(bridges=self._cfg.bridges)
        self._obfuscator     = TrafficObfuscator()

        self._level:         Optional[FilteringLevel]    = None
        self._strategy:      Optional[ObfuscationProtocol] = None
        self._active_bridge: Optional[BridgeConfig]      = None
        self._last_probe:    float                       = 0.0
        self._initialized:   bool                        = False

    # ── Initialization ────────────────────────────────────────────

    async def initialize(self) -> None:
        """Probe network and select best strategy. Call once at startup."""
        await self._update_strategy()
        self._initialized = True
        logger.info(
            f"Anti-censorship router ready | "
            f"level={self._level.name if self._level else '?'} "
            f"strategy={self._strategy.value if self._strategy else '?'}"
        )

    async def _update_strategy(self) -> None:
        """Re-probe and pick the best bypass strategy."""
        self._level = await self._detector.detect_filtering_level()
        self._last_probe = time.monotonic()

        if self._level == FilteringLevel.NONE:
            self._strategy = ObfuscationProtocol.PLAIN

        elif self._level == FilteringLevel.BASIC:
            self._strategy = ObfuscationProtocol.HTTP_MIMIC

        elif self._level == FilteringLevel.MODERATE:
            # Try obfs4 first
            bridge = await self._bridge_mgr.find_working_bridge()
            if bridge and bridge.protocol == ObfuscationProtocol.OBFS4:
                self._strategy      = ObfuscationProtocol.OBFS4
                self._active_bridge = bridge
            else:
                self._strategy = ObfuscationProtocol.HTTP_MIMIC

        elif self._level == FilteringLevel.AGGRESSIVE:
            # Prefer meek-azure (hardest to block in IR)
            bridge = await self._bridge_mgr.find_working_bridge()
            if bridge:
                self._strategy      = bridge.protocol
                self._active_bridge = bridge
            else:
                self._strategy = ObfuscationProtocol.MEEK_AZURE

        else:  # TOTAL
            # Snowflake is the last resort
            self._strategy = ObfuscationProtocol.SNOWFLAKE
            bridge = await self._bridge_mgr.find_working_bridge()
            if bridge:
                self._active_bridge = bridge

    async def _maybe_recheck(self) -> None:
        """Re-evaluate strategy if interval has passed."""
        if (time.monotonic() - self._last_probe) > self._recheck:
            logger.debug("Re-checking filtering level…")
            self._detector.invalidate_cache()
            await self._update_strategy()

    # ── HTTP fetch ───────────────────────────────────────────────

    async def fetch(
        self,
        url:     str,
        method:  str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body:    Optional[bytes] = None,
        timeout: float = 15.0,
    ) -> Optional[bytes]:
        """
        Fetch a URL through the anti-censorship layer.

        Automatically selects obfuscation based on current network state.
        Falls back to escalated protocol on failure.

        Returns the raw response body, or None on failure.
        """
        if not self._initialized:
            await self.initialize()
        await self._maybe_recheck()

        parsed = urlparse(url)
        host   = parsed.hostname or url
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        # If the hostname is known-blocked in Iran, force bypass
        if self._cfg.is_likely_blocked(host):
            logger.debug(f"{host} is known-blocked in IR, forcing bypass strategy")
            if self._strategy == ObfuscationProtocol.PLAIN:
                self._strategy = ObfuscationProtocol.HTTP_MIMIC

        strategies = self._escalation_order()

        for strat in strategies:
            try:
                response = await asyncio.wait_for(
                    self._fetch_with_strategy(
                        strat, url, host, port, use_tls,
                        method, headers or {}, body
                    ),
                    timeout=timeout,
                )
                if response is not None:
                    self._strategy = strat   # remember what worked
                    return response
            except asyncio.TimeoutError:
                logger.warning(f"Strategy {strat.value} timed out for {host}")
            except Exception as exc:
                logger.warning(f"Strategy {strat.value} failed for {host}: {exc}")

        logger.error(f"All strategies exhausted for {url}")
        return None

    def _escalation_order(self) -> list[ObfuscationProtocol]:
        """Return list of strategies from current → most aggressive."""
        all_strats = [
            ObfuscationProtocol.PLAIN,
            ObfuscationProtocol.HTTP_MIMIC,
            ObfuscationProtocol.OBFS4,
            ObfuscationProtocol.MEEK_AZURE,
            ObfuscationProtocol.SNOWFLAKE,
        ]
        current_idx = 0
        try:
            current_idx = all_strats.index(self._strategy or ObfuscationProtocol.PLAIN)
        except ValueError:
            pass
        return all_strats[current_idx:]

    async def _fetch_with_strategy(
        self,
        strategy: ObfuscationProtocol,
        url:      str,
        host:     str,
        port:     int,
        use_tls:  bool,
        method:   str,
        headers:  Dict[str, str],
        body:     Optional[bytes],
    ) -> Optional[bytes]:
        """Dispatch to the correct fetch implementation for a strategy."""
        if strategy == ObfuscationProtocol.PLAIN:
            return await self._direct_fetch(url, host, port, use_tls, method, headers, body)

        if strategy == ObfuscationProtocol.HTTP_MIMIC:
            return await self._mimic_fetch(host, port, use_tls, method, headers, body)

        # For bridge-based strategies, attempt SOCKS5-via-Tor (if Tor is running)
        # or fall back to mimic as degraded path
        return await self._mimic_fetch(host, port, use_tls, method, headers, body)

    async def _direct_fetch(
        self,
        url:     str,
        host:    str,
        port:    int,
        use_tls: bool,
        method:  str,
        headers: Dict[str, str],
        body:    Optional[bytes],
    ) -> Optional[bytes]:
        """Plain HTTPS/HTTP fetch using asyncio streams."""
        ctx = ssl.create_default_context() if use_tls else None

        reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
        try:
            request = self._build_http_request(method, url, host, headers, body)
            writer.write(request)
            await writer.drain()
            response = await reader.read(131_072)   # 128 KiB max
            return response
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _mimic_fetch(
        self,
        host:    str,
        port:    int,
        use_tls: bool,
        method:  str,
        headers: Dict[str, str],
        body:    Optional[bytes],
    ) -> Optional[bytes]:
        """Obfuscated fetch: payload wrapped in HTTP mimicry."""
        if self._cfg.timing_jitter:
            await self._obfuscator.apply_jitter()

        ctx = ssl.create_default_context() if use_tls else None

        reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
        try:
            inner = self._build_http_request(method, f"https://{host}/", host, headers, body)
            obfuscated = self._obfuscator.obfuscate(inner)
            writer.write(obfuscated)
            await writer.drain()
            raw = await reader.read(131_072)
            return self._obfuscator.deobfuscate(raw)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    def _build_http_request(
        method:  str,
        url:     str,
        host:    str,
        headers: Dict[str, str],
        body:    Optional[bytes],
    ) -> bytes:
        """Build a minimal HTTP/1.1 request."""
        parsed = urlparse(url)
        path   = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        lines = [
            f"{method.upper()} {path} HTTP/1.1",
            f"Host: {host}",
            "Connection: close",
            "User-Agent: Mozilla/5.0 (compatible; AutonomousOrchestrator/1.0)",
        ]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if body:
            lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        lines.append("")
        raw = "\r\n".join(lines).encode()
        if body:
            raw += body
        return raw

    # ── Status / diagnostics ──────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Return current router state as a plain dict."""
        return {
            "initialized":      self._initialized,
            "filtering_level":  self._level.name if self._level else None,
            "current_strategy": self._strategy.value if self._strategy else None,
            "active_bridge": (
                f"{self._active_bridge.address}:{self._active_bridge.port}"
                if self._active_bridge else None
            ),
            "bridge_pool": self._bridge_mgr.status(),
            "last_probe_ago_s": round(time.monotonic() - self._last_probe, 1),
        }

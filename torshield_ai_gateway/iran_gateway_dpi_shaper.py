from __future__ import annotations

"""
iran_gateway_dpi_shaper.py — AI Gateway-Specific DPI Evasion for Iran's SIAM/NGFW
==================================================================================

Uses CF AI Gateway as CDN front for all AI API traffic.

Key insight: CF AI Gateway traffic looks like Cloudflare CDN traffic
(TLS SNI = gateway.ai.cloudflare.com), which Iran cannot block without
blocking ALL Cloudflare traffic (economic cost too high).

Features:
  - CF Gateway domain fronting (Iran cannot selectively block)
  - ISP-specific slot routing (different CF PoPs bypass ISP IP blocks)
  - Browser-like header injection (avoid API traffic fingerprinting)
  - Randomized User-Agent rotation

NON-DESTRUCTIVE: New standalone module. Existing code untouched.
Version: 1.0.0 (Feature-2 v16.0)
"""


import logging
import random
import threading

logger = logging.getLogger("torshield.ai.iran_gateway_dpi_shaper")


# ── CF Gateway Domains (Iran cannot selectively block) ────────────────────────

CF_FRONTING_DOMAINS = [
    "gateway.ai.cloudflare.com",   # Primary AI gateway
    "api.cloudflare.com",          # REST API (also CF-fronted)
]


# ── ISP-Specific Slot Mapping ─────────────────────────────────────────────────
# Some ISPs block specific CF IPs; use multiple CF account slots
# to distribute across different CF PoPs.

ISP_SLOT_MAPPING: dict[str, list[int]] = {
    "irancell": [1, 2, 3],   # Irancell: slots 1-3
    "mci": [4, 5, 6],        # MCI (Hamrahe Aval): slots 4-6
    "rightel": [7, 8],       # RighTel: slots 7-8
    "shatel": [9, 10],       # Shatel: slots 9-10
    "other": [11],           # Fallback: slot 11
}


# ── Browser-like User-Agent Pool ──────────────────────────────────────────────

BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) Chrome/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/17.4",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Firefox/126.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/125.0",
]


# ── Gateway DPI Shaper ────────────────────────────────────────────────────────

class GatewayDPIShaper:
    """
    AI Gateway-specific DPI evasion for Iran's SIAM/NGFW.
    Uses CF AI Gateway as CDN front for all AI API traffic.

    Key insight: CF AI Gateway traffic looks like Cloudflare CDN traffic
    (TLS SNI = gateway.ai.cloudflare.com), which Iran cannot block without
    blocking ALL Cloudflare traffic (economic cost too high).
    """

    def get_optimal_slot_for_isp(
        self,
        detected_isp: str | None = None,
    ) -> int:
        """
        Route to the CF account slot best suited for the detected ISP.
        Different CF account IDs may be hosted on different CF PoPs,
        which can bypass ISP-specific IP blocks.
        """
        isp_key = (detected_isp or "other").lower()
        for isp_pattern, slots in ISP_SLOT_MAPPING.items():
            if isp_pattern in isp_key:
                return random.choice(slots)
        return random.choice(ISP_SLOT_MAPPING["other"])

    def get_dpi_evading_headers(
        self,
        base_headers: dict[str, str],
        threat_level: str = "none",
    ) -> dict[str, str]:
        """
        Augment request headers to better blend with normal HTTPS traffic.
        At medium+ threat levels, adds browser-like headers to avoid
        API traffic fingerprinting by Iran's DPI systems.
        """
        headers = dict(base_headers)

        if threat_level in ("medium", "high", "critical"):
            headers.update({
                "Accept": "application/json, text/event-stream, */*",
                "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Cache-Control": "no-cache",
                # Vary User-Agent to avoid per-session fingerprinting
                "User-Agent": random.choice(BROWSER_USER_AGENTS),
            })

        return headers

    def should_use_gateway_fronting(self, threat_level: str = "none") -> bool:
        """
        Determine if CF Gateway fronting should be used based on threat level.
        At LOW and above, CF Gateway fronting provides TLS SNI camouflage.
        """
        return threat_level in ("low", "medium", "high", "critical")

    def get_fronting_domain(self, threat_level: str = "none") -> str:
        """
        Get the best CF fronting domain for the current threat level.
        Returns primary gateway domain by default; rotates at higher threat levels.
        """
        if threat_level in ("high", "critical"):
            return random.choice(CF_FRONTING_DOMAINS)
        return CF_FRONTING_DOMAINS[0]


# ── Singleton ─────────────────────────────────────────────────────────────────

_gw_dpi_shaper: GatewayDPIShaper | None = None
_gw_dpi_shaper_lock = threading.Lock()


def get_gateway_dpi_shaper() -> GatewayDPIShaper:
    """Get or create the singleton GatewayDPIShaper instance."""
    global _gw_dpi_shaper
    with _gw_dpi_shaper_lock:
        if _gw_dpi_shaper is None:
            _gw_dpi_shaper = GatewayDPIShaper()
        return _gw_dpi_shaper

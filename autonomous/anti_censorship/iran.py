"""
autonomous/anti_censorship/iran.py
====================================
Iran-specific anti-censorship configuration.

Iran's filtering infrastructure (as of 2025):
  • Huawei / ZTE DPI boxes at ISP level
  • DNS poisoning (returns 10.10.34.34 / 127.0.0.1)
  • SNI inspection (HTTPS hostname blocking)
  • Shadowsocks / OpenVPN protocol fingerprinting
  • Throttling of encrypted traffic after ~50 Kbps
  • Telegram / WhatsApp / Twitter / YouTube / GitHub blocked
  • GitHub raw content blocked; api.github.com periodically blocked

Best bypass protocols in priority order (empirically tested):
  1. meek-azure   — tunnels over Azure CDN (IR can't block Azure)
  2. snowflake    — WebRTC; looks like video conferencing
  3. obfs4        — random bytes; defeats protocol fingerprinting
  4. trojan       — disguises as valid HTTPS traffic
  5. shadowsocks  — with obfs-plugin

References:
  https://ooni.org/country/ir
  https://www.ntia.doc.gov/report/2023/censorship-circumvention-iran
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .bridges import BridgeConfig
from .obfuscator import ObfuscationProtocol


# ── Known-poisoned IP ranges in Iran ─────────────────────────────
IRAN_POISON_IPS = frozenset({
    "10.10.34.34",
    "10.10.34.35",
    "127.0.0.1",
    "10.10.33.36",
    "10.10.34.36",
})

# ── Iran ISP CIDR blocks (commonly used as source IPs by censors) ─
IRAN_CENSOR_ASNS = frozenset({
    44244,   # IRANCELL
    16322,   # Pars Online
    12880,   # Information Technology Company (ITC)
    197207,  # Mobile Communication Company of Iran PLC
    58224,   # Iran Telecom Co
    43754,   # Asiatech
    48159,   # Telecommunication Infrastructure Company
})

# ── DNS servers that work inside Iran ────────────────────────────
IRAN_SAFE_DNS = [
    "10.202.10.10",   # Shecan — Iran-hosted DNS that bypasses some blocks
    "10.202.10.11",   # Shecan secondary
    # Note: 8.8.8.8 is reachable but DNS responses may be poisoned
]

# ── Domains known to be blocked in Iran (partial list) ───────────
IRAN_BLOCKED_DOMAINS = frozenset({
    "twitter.com",
    "x.com",
    "facebook.com",
    "youtube.com",
    "telegram.org",
    "t.me",
    "instagram.com",
    "reddit.com",
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "google.com",
    "whatsapp.com",
    "signal.org",
    "wikipedia.org",
    "bbc.com",
    "bbc.co.uk",
    "voanews.com",
    "radiofarda.com",
})


@dataclass
class IranBypassConfig:
    """
    Ready-made anti-censorship configuration tuned for Iran.

    Usage::

        cfg = IranBypassConfig.recommended()
        router = SmartAntiCensorshipRouter(bypass_config=cfg)
        await router.initialize()
    """

    # Ordered list of bridges to try
    bridges: List[BridgeConfig] = field(default_factory=list)

    # Fall-through DNS (used when system DNS appears poisoned)
    dns_over_https_url: str = "https://cloudflare-dns.com/dns-query"

    # Obfuscation to apply when not using Tor
    preferred_protocol: ObfuscationProtocol = ObfuscationProtocol.MEEK_AZURE

    # Allow falling back to direct connection when bypass isn't needed
    allow_direct_fallback: bool = True

    # Aggressively re-probe filtering every N seconds
    recheck_interval_s: float = 120.0

    # Enable timing jitter to foil traffic correlation
    timing_jitter: bool = True

    @classmethod
    def recommended(cls) -> "IranBypassConfig":
        """
        Return the recommended configuration for Iran.
        Bridges are tried top-to-bottom; update bridge IPs regularly.
        """
        bridges: List[BridgeConfig] = [
            # 1st choice: meek-azure (Azure CDN — almost impossible to block in IR)
            BridgeConfig(
                address="20.186.13.205",
                port=443,
                protocol=ObfuscationProtocol.MEEK_AZURE,
                extra_params={"url": "https://meek.azurefd.net/"},
                priority=10,
            ),
            # 2nd choice: Snowflake via WebRTC
            BridgeConfig(
                address="snowflake-broker.torproject.net",
                port=443,
                protocol=ObfuscationProtocol.SNOWFLAKE,
                priority=20,
            ),
            # 3rd choice: obfs4 (random-looking bytes)
            BridgeConfig(
                address="192.95.36.142",
                port=443,
                protocol=ObfuscationProtocol.OBFS4,
                fingerprint="CDF2E852BF539B82BD10E27E9115A31734E378C2",
                extra_params={
                    "cert": (
                        "qUVQ0srL1JI/vO6V6m/24anYXiJD3zP8o7ULQzu2RDy"
                        "6GIVCbvGrDlhk9MhFBlRmFBMf+Q"
                    ),
                    "iat-mode": "0",
                },
                priority=30,
            ),
        ]
        return cls(bridges=bridges)

    def is_likely_blocked(self, hostname: str) -> bool:
        """Quick check: is this hostname in Iran's known blocklist?"""
        hostname = hostname.lower().strip()
        if hostname in IRAN_BLOCKED_DOMAINS:
            return True
        # Check suffix match (e.g., foo.github.com)
        for blocked in IRAN_BLOCKED_DOMAINS:
            if hostname.endswith("." + blocked):
                return True
        return False

    def is_dns_poisoned(self, resolved_ip: str) -> bool:
        """Return True if the resolved IP is a known Iran poison address."""
        return resolved_ip in IRAN_POISON_IPS

    def build_torrc(self) -> str:
        """Generate a minimal torrc suitable for use inside Iran."""
        lines = [
            "# Generated by autonomous anti-censorship module",
            "# Optimised for Iran (IR) network conditions",
            "UseBridges 1",
            "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy",
            "ClientTransportPlugin meek exec /usr/bin/meek-client",
            "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client",
            # Force SOCKS5 on a fixed port
            "SocksPort 9050",
            # Avoid using guards that might be fingerprinted
            "StrictNodes 1",
            "ExcludeNodes {ir}",   # Don't route through Iran
            "",
        ]
        for b in self.bridges:
            lines.append(f"Bridge {b.to_bridge_line()}")
        return "\n".join(lines)

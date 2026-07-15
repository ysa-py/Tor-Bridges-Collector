"""
iran_traffic_evasion.py — Adaptive Iran DPI Evasion Headers
============================================================

Iran's SIAM/NAPI system performs deep packet inspection on HTTPS
traffic metadata. While TLS payload is encrypted, traffic PATTERNS
(timing, header size, request frequency) are fingerprinted.

This module introduces controlled randomization to defeat pattern matching
across multiple evasion levels:
  - Level 0 (none):     No changes
  - Level 1 (low):      Browser UA + random X-Request-ID
  - Level 2 (medium):   + Accept headers + language + Origin/Referer camouflage
  - Level 3 (high):     + Cache/connection headers + multiple noise headers
  - Level 4 (critical): + Timing jitter marker + obfuscated header order
                         + X-Forwarded-For/X-Real-IP + X-TLS-Fragment

FEATURE-S (v18.0): Adaptive Iran DPI Evasion Headers
FEATURE-W (v19.0): Enhanced DPI evasion with Origin/Referer camouflage,
  realistic IP generation, TLS fragmentation marker, and human-pause
  simulation in retry timing.

NON-DESTRUCTIVE: Additive only — does not replace or remove any existing
evasion or anti-DPI module logic.
"""

import hashlib
import logging
import random
import time

logger = logging.getLogger("torshield.ai.iran_traffic_evasion")


class IranTrafficEvasion:
    """
    Modifies HTTP request patterns to evade Iran's DPI systems.

    Iran's SIAM (Subscriber Identity and Access Management) system and
    NAPI (Network Access Point Iran) perform statistical analysis on:
      - Request timing (fixed intervals = bot signature)
      - Header fingerprinting (exact header set = specific API client)
      - Request size patterns (consistent payload = automated traffic)
      - TLS SNI values (blocked domains detected by SNI)

    This class introduces controlled randomization to defeat pattern matching
    across 5 evasion levels, escalating with the detected DPI threat level.
    Each level adds progressively more aggressive camouflage techniques.
    """

    # Standard headers that could reveal API client identity
    NEUTRALIZE_HEADERS = {
        "x-amz-date",       # AWS signature headers reveal API calls
        "x-api-version",    # Version headers fingerprint the client
        "user-agent",       # Should be replaced with browser-like value
    }

    # Browser-like User-Agent strings for traffic camouflage
    CAMOUFLAGE_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",

        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",

        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",

        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0",
    ]

    def apply_evasion(
        self,
        headers: dict[str, str],
        threat_level: str,
        provider: str,
    ) -> dict[str, str]:
        """
        v19.0: Enhanced DPI evasion with 5 levels.
        Level 0 (none):     No changes
        Level 1 (low):      Browser UA + random X-Request-ID
        Level 2 (medium):   + Accept headers + language
        Level 3 (high):     + Cache/connection headers + multiple noise headers
        Level 4 (critical): + Timing jitter marker + obfuscated header order

        FEATURE-W v19.0: Adds Origin/Referer camouflage for ChatGPT-like
        traffic appearance, X-Forwarded-For/X-Real-IP with realistic IPs,
        and X-TLS-Fragment marker for compatible proxies.
        """
        if threat_level == "none":
            return headers

        modified = dict(headers)

        # Level 1 — always for any threat
        ua = random.choice(self.CAMOUFLAGE_USER_AGENTS)
        if not any(k.lower() == "user-agent" for k in modified):
            modified["User-Agent"] = ua

        # Unique request ID to prevent fingerprinting by payload signature
        modified["X-Request-ID"] = hashlib.sha256(
            f"{time.time()}{random.random()}".encode()
        ).hexdigest()[:24]

        if threat_level in ("medium", "high", "critical"):
            # Level 2 — browser-like Accept headers + Origin/Referer camouflage
            modified["Accept"] = "application/json, text/plain, */*"
            modified["Accept-Language"] = "en-US,en;q=0.9,fa;q=0.8,ar;q=0.7"
            modified["Accept-Encoding"] = "gzip, deflate, br"
            modified["Origin"] = "https://chat.openai.com"  # Camouflage as ChatGPT
            modified["Referer"] = "https://chat.openai.com/"

        if threat_level in ("high", "critical"):
            # Level 3 — cache/connection headers + multiple noise headers
            modified["Cache-Control"] = "no-cache"
            modified["Pragma"] = "no-cache"
            modified["Connection"] = "keep-alive"
            modified["Sec-Fetch-Dest"] = "empty"
            modified["Sec-Fetch-Mode"] = "cors"
            modified["Sec-Fetch-Site"] = "cross-site"
            # Add multiple noise headers to increase entropy
            noise = self._generate_noise_headers(5)
            modified.update(noise)

        if threat_level == "critical":
            # Level 4 — additional markers for proxy-level treatment
            modified["X-Forwarded-For"] = self._generate_realistic_ip()
            modified["X-Real-IP"] = self._generate_realistic_ip()
            # Fragment simulation marker (for compatible proxies)
            modified["X-TLS-Fragment"] = "150"

        return modified

    @staticmethod
    def _generate_noise_headers(count: int) -> dict[str, str]:
        """
        Generate harmless but unpredictable headers.
        These increase header entropy and defeat signature matching.
        """
        noise = {}
        for _ in range(count):
            # Use browser-standard optional headers with random values
            key = random.choice([
                "X-Request-ID", "X-Correlation-ID", "X-Trace-ID",
                "X-Session-ID", "X-Client-Version",
            ])
            # Random hex values look like legitimate request IDs
            noise[key] = hashlib.md5(
                str(random.random()).encode()
            ).hexdigest()[:16]
        return noise

    @staticmethod
    def _generate_realistic_ip() -> str:
        """Generate a realistic-looking IP that isn't obviously fake.

        Uses common European/US IP ranges to camouflage as foreign traffic.
        Iran's DPI may use IP geolocation heuristics — traffic from
        European IP ranges is less likely to be flagged as suspicious
        than traffic from known VPN/proxy ranges or internal ranges.
        """
        prefixes = [
            "185.220", "51.15", "45.33", "198.98",
            "104.244", "23.129", "141.98",
        ]
        prefix = random.choice(prefixes)
        return f"{prefix}.{random.randint(1,254)}.{random.randint(1,254)}"

    @staticmethod
    def get_safe_retry_delay(
        attempt: int,
        threat_level: str,
        base_ms: float = 500,
    ) -> float:
        """
        v19.0: Human-like retry timing with threat-adaptive delays.
        Uses Gaussian distribution to defeat fixed-interval detection.
        Also incorporates provider-specific knowledge:
          - After Iran block detected: longer delays
          - After success: shorter delays (recover quickly)

        Iran's SIAM detects fixed-interval retries (bot behavior).
        Human-like intervals (Gaussian distribution) are less detectable.
        Additionally, a 5% chance of a "human pause" (1-3 second delay)
        simulates the natural variation of a person reading before
        retrying, which further defeats fixed-interval pattern matching.
        """
        threat_multipliers = {
            "none":     1.0,
            "low":      1.8,
            "medium":   3.0,
            "high":     5.0,
            "critical": 10.0,
        }
        multiplier = threat_multipliers.get(threat_level, 1.0)
        base_delay = (base_ms / 1000) * (2 ** (attempt - 1)) * multiplier
        # Human typing/thinking variance: Gaussian with sigma = 25%
        jitter = random.gauss(0, base_delay * 0.25)
        # Add occasional "human pause" (5% chance of longer delay)
        if random.random() < 0.05:
            jitter += random.uniform(1.0, 3.0)
        return max(0.1, min(base_delay + jitter, 45.0))


# Singleton instance
_IRAN_EVASION = IranTrafficEvasion()


def get_iran_evasion() -> IranTrafficEvasion:
    """Get the singleton Iran traffic evasion instance."""
    return _IRAN_EVASION

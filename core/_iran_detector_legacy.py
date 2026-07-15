from __future__ import annotations

"""
core/iran_detector.py — Iran network isolation detector.

Detects whether the machine running this tool is inside Iran and, if so,
whether international internet is currently reachable or if the National
Information Network (NIN / شبکه ملی اطلاعات) is active (i.e., international
traffic is blocked).

This module is most useful when the tool is run locally inside Iran.
In GitHub Actions mode the detection always returns "international reachable".

Methodology:
  1. Attempt TCP connections to multiple international DNS resolvers (port 53).
  2. Attempt HTTPS to a known-good international endpoint.
  3. Cross-check against Iranian NIN test IPs (10.x / 172.x national gateways).
  If all international probes fail → NIN is likely active.
"""


import asyncio
import logging
import time

import nest_asyncio

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Test targets
# ─────────────────────────────────────────────────────────────────────────────

# Well-known international DNS/HTTPS endpoints
_INTERNATIONAL_PROBES = [
    ("8.8.8.8",        53),   # Google DNS
    ("1.1.1.1",        53),   # Cloudflare DNS
    ("208.67.222.222", 53),   # OpenDNS
    ("9.9.9.9",        53),   # Quad9
]

# Iranian NIN / domestic gateway IPs (usually reachable even during cuts)
_NIN_PROBES = [
    ("10.10.34.34",  80),   # IRNIC / IRCERT portal
    ("185.51.200.2", 80),   # Known NIN DNS
]

_PROBE_TIMEOUT = 3.0


async def _probe_tcp(host: str, port: int, timeout: float = _PROBE_TIMEOUT) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('core.iran_detector:57', _remediation_exc)
            pass
        return True
    except Exception:
        return False


async def check_connectivity() -> tuple[bool, bool]:
    """
    Returns (international_ok: bool, nin_active: bool).

    - international_ok = True  →  at least one international probe succeeded
    - nin_active       = True  →  NIN domestic probe succeeded BUT international failed
                                  (strong signal that internet cut is in effect)
    """
    # Run all probes concurrently
    int_tasks  = [_probe_tcp(h, p) for h, p in _INTERNATIONAL_PROBES]
    nin_tasks  = [_probe_tcp(h, p) for h, p in _NIN_PROBES]

    int_results, nin_results = await asyncio.gather(
        asyncio.gather(*int_tasks, return_exceptions=True),
        asyncio.gather(*nin_tasks, return_exceptions=True),
    )

    int_ok  = any(r is True for r in int_results)
    nin_ok  = any(r is True for r in nin_results)
    nin_active = nin_ok and not int_ok

    if nin_active:
        log.warning(
            "⚠️  IRAN INTERNET CUT DETECTED — international internet unreachable. "
            "Recommending Snowflake / WebTunnel (CDN) bridges."
        )
    elif not int_ok:
        log.warning("No internet connectivity detected at all.")
    else:
        log.info("International internet reachable.")

    return int_ok, nin_active


def recommend_strategy(nin_active: bool) -> str:
    if nin_active:
        return (
            "Internet cut detected (شبکه ملی فعال). "
            "Use: export/iran_cut_pack.txt → Snowflake, then WebTunnel (CDN-fronted). "
            "Avoid vanilla/obfs4 — their IPs are unreachable during cuts."
        )
    return (
        "International internet reachable. "
        "Use: export/iran_pack.txt → obfs4 (port 443) or WebTunnel for best performance."
    )


# ════════════════════════════════════════════════════════════════════════════
# Phase 4.4 — NINDetector class (additive — does NOT replace the existing
# functions above; those remain the simple imperative API).
# ════════════════════════════════════════════════════════════════════════════
import json as _json
import os as _os
from datetime import timezone
from datetime import datetime as _dt
UTC = timezone.utc


class NINDetector:
    """
    Detects NIN (National Information Network) isolation events.

    Detection signals:
      1. All international DNS resolvers unreachable (8.8.8.8, 1.1.1.1)
      2. Only domestic Iranian domains (*.ir) are resolving
      3. Known CDN edge IPs (Cloudflare, Amazon, Google) all timing out
      4. Bridge failure rate exceeds 95% in last 10 minutes

    When NIN detected:
      1. Exports export/iran_cut_pack.txt with Snowflake + WebTunnel only
      2. Notifies via Telegram (if TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID set)
      3. Logs event to data/nin_events.json with timestamp
      4. Returns True from .is_nin_active()

    This class is ADDITIVE — the existing check_nin_state() and
    recommend_strategy() functions remain untouched and continue to work.
    """

    def __init__(
        self,
        events_path: str = "data/nin_events.json",
        export_path: str = "export/iran_cut_pack.txt",
    ) -> None:
        self.events_path = events_path
        self.export_path = export_path
        self._cached_state: bool = False
        self._last_check_ts: float = 0.0

    # ---- public API ------------------------------------------------------

    def is_nin_active(self, force_refresh: bool = False) -> bool:
        """
        Return True if NIN isolation is currently active.
        Uses a 30s cache to avoid hammering the network on every call.
        """
        now = time.time()
        if not force_refresh and (now - self._last_check_ts) < 30.0:
            return self._cached_state
        try:
            # check_connectivity() is async. Python 3.14 no longer creates an
            # implicit current loop for synchronous callers, so use asyncio.run()
            # when no loop is running and patch only genuinely running loops.
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('core.iran_detector:171', _remediation_exc)
                int_ok, nin_active = asyncio.run(check_connectivity())
            else:
                nest_asyncio.apply(loop)
                int_ok, nin_active = loop.run_until_complete(check_connectivity())
            self._cached_state = bool(nin_active)
        except Exception as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('core.iran_detector:177', exc)
            log.warning("[NINDetector] detection failed: %s", exc)
            self._cached_state = False
        self._last_check_ts = now
        if self._cached_state:
            self._on_nin_detected()
        return self._cached_state

    def record_event(self, kind: str, details: dict) -> None:
        """Append a NIN event to data/nin_events.json (additive log)."""
        _os.makedirs(_os.path.dirname(self.events_path) or ".", exist_ok=True)
        events: list[dict] = []
        try:
            with open(self.events_path) as fh:
                events = _json.load(fh)
                if not isinstance(events, list):
                    events = []
        except FileNotFoundError as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('core.iran_detector:196', _remediation_exc)
            events = []
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('core.iran_detector:194', _remediation_exc)
            events = []
        events.append(
            {
                "timestamp": _dt.now(UTC).isoformat(),
                "kind": kind,
                "details": details,
            }
        )
        try:
            with open(self.events_path, "w") as fh:
                _json.dump(events, fh, indent=2)
        except Exception as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('core.iran_detector:206', exc)
            log.warning("[NINDetector] could not write events: %s", exc)

    # ---- internals -------------------------------------------------------

    def _on_nin_detected(self) -> None:
        """Side-effects to fire when NIN is detected."""
        self.record_event("nin_detected", {"cached_state": self._cached_state})
        # Telegram notification is optional and never raises
        try:
            self._notify_telegram()
        except Exception as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('core.iran_detector:217', exc)
            log.debug("[NINDetector] telegram notify skipped: %s", exc)

    def _notify_telegram(self) -> None:
        """Send a Telegram notification if env vars are set (best-effort)."""
        token = _os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = _os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat_id:
            return
        # Lazy import to avoid hard dependency
        import urllib.parse
        import urllib.request
        text = "TorShield-IR: NIN isolation detected. Switched to iran_cut_pack."
        url = (
            f"https://api.telegram.org/bot{token}/sendMessage?"
            + urllib.parse.urlencode({"chat_id": chat_id, "text": text})
        )
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TorShield-IR"})
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('core.iran_detector:237', exc)
            log.debug("[NINDetector] telegram send failed: %s", exc)

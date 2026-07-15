#!/usr/bin/env python3
from __future__ import annotations

"""
core/nin_survival_pack.py — NIN Survival Mode: National Intranet Bridge Pack
=============================================================================

When Iran's international internet is fully cut (NIN isolation), only
these transport types can tunnel through:

    Transport     | Mechanism                            | Priority
    --------------+--------------------------------------+--------
    Snowflake     | WebRTC via STUN (domain-fronted)     | 1
    WebTunnel     | HTTPS camouflage via CDN             | 2
    meek-lite     | Azure/Amazon/Google CDN fronting     | 3
    obfs4 p443    | Port 443 only (HTTPS-disguised)      | 4

This module generates and maintains a bridge pack optimized for NIN
isolation. It auto-detects NIN state using IranNINDetector and switches
to CDN-fronted bridge prioritization automatically.

ADDITIVE: does NOT replace core/nin_selector.py or core/iran_detector.py.
"""


import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any
UTC = timezone.utc

# Additive: pull in the existing NIN detector (function-based API) so we
# can detect NIN state without duplicating logic.
try:
    from core.iran_detector import NINDetector  # noqa: F401 (re-exported)
    _NIN_DETECTOR_AVAILABLE = True
except Exception as _remediation_exc:  # additive: never hard-fail
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('core.nin_survival_pack:38', _remediation_exc)
    _NIN_DETECTOR_AVAILABLE = False

log = logging.getLogger(__name__)

__all__ = ["NINSurvivalPack", "NIN_TRANSPORT_PRIORITIES"]

# Priority ranking of transports during NIN isolation (1 = highest).
NIN_TRANSPORT_PRIORITIES: dict[str, int] = {
    "snowflake": 1,
    "webtunnel": 2,
    "meek_lite": 3,   # canonical form
    "meek-lite": 3,   # alt spelling
    "obfs4_443": 4,   # obfs4 on port 443 specifically
    "obfs4": 5,       # obfs4 on other ports — last resort during NIN
}


def _normalize_transport(bridge: dict[str, Any]) -> str:
    """Extract & normalize the transport name from a bridge dict."""
    raw = (
        bridge.get("transport")
        or bridge.get("transport_type")
        or bridge.get("type")
        or ""
    )
    if not raw:
        line = bridge.get("bridge_line") or bridge.get("line") or ""
        if line.startswith("bridge "):
            parts = line.split()
            if len(parts) > 1:
                raw = parts[1]
    s = str(raw).strip().lower().replace("-", "_")
    # obfs4 on port 443 gets a special priority bucket
    port = bridge.get("port") or 0
    if s == "obfs4" and str(port) == "443":
        return "obfs4_443"
    return s


def _is_nin_capable(transport: str) -> bool:
    return transport in NIN_TRANSPORT_PRIORITIES


class NINSurvivalPack:
    """
    Generates and maintains a bridge pack optimized for NIN isolation.

    Auto-detects NIN state using IranNINDetector and switches to
    CDN-fronted bridge prioritization automatically.

    Methods:
      .detect_nin_state() -> bool
      .generate_pack(all_bridges: list) -> list   # filtered + ranked
      .export_pack(path: str) -> None             # writes to export/iran_cut_pack.txt
      .get_status() -> dict
    """

    def __init__(
        self,
        export_path: str = "export/iran_cut_pack.txt",
        events_path: str = "data/nin_events.json",
    ) -> None:
        self.export_path = export_path
        self.events_path = events_path
        self._detector: Any | None = None
        if _NIN_DETECTOR_AVAILABLE:
            try:
                self._detector = NINDetector(events_path=events_path)
            except Exception as exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('core.nin_survival_pack:107', exc)
                log.warning("[NINSurvivalPack] NINDetector unavailable: %s", exc)
        self._last_pack: list[dict[str, Any]] = []
        self._last_generated_ts: float = 0.0

    # ---- public API ------------------------------------------------------

    def detect_nin_state(self) -> bool:
        """Return True if NIN isolation is currently active."""
        if self._detector is None:
            log.debug("[NINSurvivalPack] no detector — assuming NIN inactive")
            return False
        try:
            return bool(self._detector.is_nin_active())
        except Exception as exc:
            log.warning("[NINSurvivalPack] NIN detection failed: %s", exc)
            return False

    def generate_pack(self, all_bridges: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Filter ``all_bridges`` down to NIN-survivable transports and
        rank them by NIN priority. Returns a new list (does NOT mutate input).
        """
        # Defensive copy — never mutate caller's list
        candidates: list[dict[str, Any]] = []
        for b in all_bridges or []:
            try:
                tport = _normalize_transport(b)
                if _is_nin_capable(tport):
                    enriched = dict(b)
                    enriched.setdefault("transport", tport)
                    enriched["nin_priority"] = NIN_TRANSPORT_PRIORITIES[tport]
                    # Bonus for port 443 (Iran almost never blocks HTTPS)
                    try:
                        if int(b.get("port", 0)) == 443:
                            enriched["nin_priority"] = max(1, enriched["nin_priority"] - 1)
                            enriched["port_443_bonus"] = True
                    except Exception as _remediation_exc:
                        from monitoring.structured_logger import record_silent_failure
                        record_silent_failure('core.nin_survival_pack:144', _remediation_exc)
                        pass
                    # Bonus for IPv4 (more stable inside Iran)
                    addr = str(b.get("address") or b.get("ip") or "")
                    if "." in addr and ":" not in addr:
                        enriched["ipv4_bonus"] = True
                    candidates.append(enriched)
            except Exception as exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('core.nin_survival_pack:151', exc)
                log.debug("[NINSurvivalPack] skip malformed bridge: %s", exc)

        # Sort: nin_priority asc, then existing score desc (if present), then
        # last_seen desc.
        candidates.sort(
            key=lambda b: (
                int(b.get("nin_priority", 99)),
                -float(b.get("iran_score", b.get("score", 0.0)) or 0.0),
                -float(b.get("last_seen_ts", 0.0) or 0.0),
            )
        )
        self._last_pack = candidates
        self._last_generated_ts = time.time()
        return candidates

    def export_pack(self, path: str | None = None) -> None:
        """
        Write the most recently generated pack to ``path`` (defaults to
        ``self.export_path``). The file format is one bridge line per line,
        with a header comment.
        """
        target = path or self.export_path
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(
                f"# TorShield-IR Ultra VIP — NIN Survival Pack\n"
                f"# Generated: {datetime.now(UTC).isoformat()}\n"
                f"# Transports: snowflake > webtunnel > meek-lite > obfs4:443\n"
                f"# Total: {len(self._last_pack)} bridges\n"
                f"# Source: core/nin_survival_pack.py\n\n"
            )
            for b in self._last_pack:
                line = (
                    b.get("bridge_line")
                    or b.get("line")
                    or self._format_bridge_line(b)
                )
                fh.write(f"{line}\n")
        log.info(
            "[NINSurvivalPack] exported %d bridges → %s",
            len(self._last_pack), target,
        )

    def get_status(self) -> dict[str, Any]:
        return {
            "engine": "NINSurvivalPack",
            "nin_detector_available": self._detector is not None,
            "nin_active": self.detect_nin_state() if self._detector else False,
            "last_pack_size": len(self._last_pack),
            "last_generated_ts": self._last_generated_ts,
            "transport_priorities": NIN_TRANSPORT_PRIORITIES,
            "export_path": self.export_path,
        }

    # ---- internals -------------------------------------------------------

    @staticmethod
    def _format_bridge_line(b: dict[str, Any]) -> str:
        """Best-effort bridge-line formatter when none was provided."""
        tport = b.get("transport", "obfs4")
        addr = b.get("address") or b.get("ip") or "0.0.0.0"
        port = b.get("port", 443)
        fingerprint = b.get("fingerprint") or b.get("id") or "0" * 40
        return f"bridge {tport} {addr}:{port} {fingerprint}"


# ════════════════════════════════════════════════════════════════════════════
# CLI entry — non-blocking smoke test
# ════════════════════════════════════════════════════════════════════════════
def _main() -> None:
    import sys
    logging.basicConfig(level=logging.INFO)
    pack = NINSurvivalPack()
    # If a JSON bridge file is provided, build a pack from it; otherwise
    # emit status only.
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1]) as fh:
            bridges = json.load(fh)
        if isinstance(bridges, dict) and "bridges" in bridges:
            bridges = bridges["bridges"]
        ranked = pack.generate_pack(bridges)
        pack.export_pack()
        print(f"Generated NIN survival pack: {len(ranked)} bridges → {pack.export_path}")
    print(json.dumps(pack.get_status(), indent=2))


if __name__ == "__main__":
    _main()

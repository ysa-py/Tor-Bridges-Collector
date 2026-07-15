from __future__ import annotations

"""Local-only polymorphic traffic morphing configuration helpers.

This module intentionally emits deterministic configuration plans instead of
performing raw packet manipulation. GitHub runners and bridge clients can apply
these plans in their own transport layer while preserving the LocalAIEngine as a
non-blocking fallback for every decision.
"""

import logging
from typing import Any

from .local_ai_engine import LocalAIEngine

log = logging.getLogger("torshield.ai.polymorphic_morpher")


class PolymorphicTrafficMorpher:
    """Build adaptive header, padding, and timing plans from local RL feedback."""

    def __init__(self, engine: LocalAIEngine | None = None):
        self.engine = engine or LocalAIEngine()

    def plan(
        self,
        transport: str = "obfs4",
        isp: str = "unknown",
        censorship_level: int = 4,
        feedback: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        feedback = feedback or {}
        try:
            return self.engine.build_polymorphic_morphing_profile(
                transport=transport,
                isp=isp,
                censorship_level=censorship_level,
                handshake_failure=bool(feedback.get("handshake_failure")),
                dpi_trigger=bool(feedback.get("dpi_trigger")),
            )
        except Exception as exc:  # ultimate local fallback; never block callers
            log.warning("Morphing profile failed; using conservative fallback: %s", exc)
            return {
                "selected_transport": transport,
                "packet_headers": {"rotate_user_agent": True, "tls_profile": "chrome_stable"},
                "padding": {"mode": "bounded_random", "min_bytes": 0, "max_bytes": 128},
                "fragmentation_timing": {"enabled": False, "min_delay_ms": 0, "max_delay_ms": 0},
                "retry_reconfigure_loop": {"max_attempts": 1, "non_blocking_fallback": "static_safe_profile"},
                "source": "polymorphic_morpher_static_fallback",
            }

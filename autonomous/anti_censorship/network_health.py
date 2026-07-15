"""
autonomous/anti_censorship/network_health.py
=============================================
AntiCensorshipNetworkHealth: extends the base NetworkHealth dataclass
to track whether bypass mode is active and which protocol is in use.

This is a drop-in replacement for `autonomous.NetworkHealth` that the
bootstrap script imports when the anti-censorship module is available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AntiCensorshipNetworkHealth:
    """
    Drop-in for autonomous.NetworkHealth with bypass awareness.

    Parameters
    ----------
    latency_ms       : observed latency in milliseconds
    packet_loss      : fraction 0.0–1.0
    bandwidth_kbps   : available bandwidth in kbps
    online           : whether the network is considered reachable
    bypass_active    : True when anti-censorship bypass is in use
    bypass_protocol  : name of the active bypass protocol (e.g. "meek-azure")
    filtering_level  : string label of detected filtering ("NONE", "AGGRESSIVE", …)
    """

    latency_ms:      float
    packet_loss:     float
    bandwidth_kbps:  float
    online:          bool
    bypass_active:   bool                 = False
    bypass_protocol: Optional[str]        = None
    filtering_level: Optional[str]        = None

    # ── Convenience constructors ──────────────────────────────────

    @classmethod
    def direct(
        cls,
        latency_ms:    float,
        packet_loss:   float = 0.0,
        bandwidth_kbps: float = 4_096.0,
        online:        bool  = True,
    ) -> "AntiCensorshipNetworkHealth":
        """Create a plain (no bypass) health record."""
        return cls(
            latency_ms=latency_ms,
            packet_loss=packet_loss,
            bandwidth_kbps=bandwidth_kbps,
            online=online,
            bypass_active=False,
        )

    @classmethod
    def bypassed(
        cls,
        protocol:      str,
        latency_ms:    float,
        filtering_level: str   = "AGGRESSIVE",
        packet_loss:   float   = 0.02,
        bandwidth_kbps: float  = 1_024.0,
    ) -> "AntiCensorshipNetworkHealth":
        """Create a health record for a bypass connection."""
        return cls(
            latency_ms=latency_ms,
            packet_loss=packet_loss,
            bandwidth_kbps=bandwidth_kbps,
            online=True,
            bypass_active=True,
            bypass_protocol=protocol,
            filtering_level=filtering_level,
        )

    # ── Integration helpers ───────────────────────────────────────

    def to_base_network_health(self):
        """
        Convert to a plain autonomous.NetworkHealth for code that does
        not know about the anti-censorship extension.
        """
        try:
            from autonomous import NetworkHealth
            return NetworkHealth(
                latency_ms=self.latency_ms,
                packet_loss=self.packet_loss,
                bandwidth_kbps=self.bandwidth_kbps,
                online=self.online,
            )
        except ImportError:
            return self  # fall back to self if base module not available

    def __str__(self) -> str:
        bypass_info = (
            f" via {self.bypass_protocol}" if self.bypass_active else ""
        )
        return (
            f"NetworkHealth(online={self.online}, "
            f"latency={self.latency_ms:.0f}ms, "
            f"loss={self.packet_loss:.1%}, "
            f"bw={self.bandwidth_kbps:.0f}kbps"
            f"{bypass_info})"
        )

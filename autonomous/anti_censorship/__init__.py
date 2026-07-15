"""
autonomous/anti_censorship/__init__.py
=======================================
Smart anti-censorship package for Iran and similar filtered networks.

Provides:
  - DPI detection & evasion
  - Tor bridge auto-discovery
  - Traffic obfuscation (obfs4-style, meek, snowflake)
  - Fully automatic protocol selection — zero manual config

Usage:
    from autonomous.anti_censorship import SmartAntiCensorshipRouter

    router = SmartAntiCensorshipRouter()
    await router.initialize()          # auto-detects filtering level
    result = await router.fetch("https://api.github.com/repos/...")
"""

from .detector import DPIDetector, FilteringLevel, NetworkProbe
from .obfuscator import TrafficObfuscator, ObfuscationProtocol
from .bridges import BridgeConfig, TorBridgeManager
from .router import SmartAntiCensorshipRouter
from .iran import IranBypassConfig
from .network_health import AntiCensorshipNetworkHealth

__all__ = [
    "DPIDetector",
    "FilteringLevel",
    "NetworkProbe",
    "TrafficObfuscator",
    "ObfuscationProtocol",
    "BridgeConfig",
    "TorBridgeManager",
    "SmartAntiCensorshipRouter",
    "IranBypassConfig",
    "AntiCensorshipNetworkHealth",
]

__version__ = "1.0.0"

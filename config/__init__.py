"""Configuration package — feature flags + transparent re-export of legacy config.py.

This package was originally shadowing the top-level ``config.py`` module
(which defines MAX_WORKERS, BRIDGE_DIR, etc.). To preserve BOTH files without
deleting either, we load ``config.py`` (the file at project root) by file-path
via importlib and re-export every public symbol here. The feature-flag values
from ``feature_flags.py`` are still exported alongside.

Nothing is deleted; nothing is renamed. ``import config`` now returns a single
namespace exposing both legacy attributes (MAX_WORKERS, BRIDGE_DIR, …) and the
new feature flags (ENABLE_CIRCUIT_BREAKER, ENABLE_IRST_ROUTING, …).
"""
import importlib.util as _ilu
import os as _os

# ─────────────────────────────────────────────────────────────────────────────
# 1. Load legacy config.py (top-level file) by PATH — bypasses name shadowing
# ─────────────────────────────────────────────────────────────────────────────
_THIS_DIR = _os.path.dirname(_os.path.abspath(__file__))
_ROOT_DIR = _os.path.dirname(_THIS_DIR)
_LEGACY_CONFIG_PATH = _os.path.join(_ROOT_DIR, "config.py")

_spec = _ilu.spec_from_file_location("_torshield_legacy_config", _LEGACY_CONFIG_PATH)
_legacy = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_legacy)

# Re-export every public symbol from legacy config.py
for _name in dir(_legacy):
    if _name.startswith("_"):
        continue
    globals()[_name] = getattr(_legacy, _name)

_legacy_all = [n for n in dir(_legacy) if not n.startswith("_")]

# ─────────────────────────────────────────────────────────────────────────────
# 2. Feature flags (from config/feature_flags.py)
# ─────────────────────────────────────────────────────────────────────────────
from .feature_flags import (
    ENABLE_ANTI_DPI_IRAN,
    ENABLE_CIRCUIT_BREAKER,
    ENABLE_COMPAT_PATH_FIX,
    ENABLE_ENDPOINT_VALIDATION,
    ENABLE_IRST_ROUTING,
    ENABLE_MODEL_REGISTRY,
    ENABLE_REPORT_GENERATION,
    ENABLE_RETRY_FAILOVER,
    ENABLE_SELF_HEALING,
    ENABLE_STRUCTURED_LOGGING,
    ENABLE_TELEMETRY,
    ENABLE_UTLS_EVASION,
    get_all_config,
    get_all_flags,
)

_flag_all = [
    "get_all_flags",
    "get_all_config",
    "ENABLE_ENDPOINT_VALIDATION",
    "ENABLE_CIRCUIT_BREAKER",
    "ENABLE_MODEL_REGISTRY",
    "ENABLE_RETRY_FAILOVER",
    "ENABLE_SELF_HEALING",
    "ENABLE_STRUCTURED_LOGGING",
    "ENABLE_REPORT_GENERATION",
    "ENABLE_ANTI_DPI_IRAN",
    "ENABLE_UTLS_EVASION",
    "ENABLE_IRST_ROUTING",
    "ENABLE_COMPAT_PATH_FIX",
    "ENABLE_TELEMETRY",
]

__all__ = sorted(set(_legacy_all) | set(_flag_all))

# Explicit references to satisfy pyflakes F401 (these are re-exported via __all__).
_PYFLAKES_F401_GUARD = (ENABLE_ANTI_DPI_IRAN, ENABLE_CIRCUIT_BREAKER, ENABLE_COMPAT_PATH_FIX, ENABLE_ENDPOINT_VALIDATION, ENABLE_IRST_ROUTING, ENABLE_MODEL_REGISTRY, ENABLE_REPORT_GENERATION, ENABLE_RETRY_FAILOVER, ENABLE_SELF_HEALING, ENABLE_STRUCTURED_LOGGING, ENABLE_TELEMETRY, ENABLE_UTLS_EVASION, get_all_config, get_all_flags)  # noqa: F841

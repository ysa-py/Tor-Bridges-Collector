from __future__ import annotations

"""
core/iran_detector.py — Rust-backed shim (Gate 4: legacy eradication).

The Iran network-isolation detection logic now lives in **Rust**
(`torshield_ir_ultra::iran_detector`, the verified parity port) and is exposed
to Python through the compiled PyO3 extension `_iran_detector_rs`.

This module contains **no detection logic of its own**. It:
  * re-exports the Rust `recommend_strategy`, and
  * provides thin `async` adapters over the Rust (synchronous) probing calls so
    the existing runtime call sites keep working *unchanged*
    (`await check_connectivity()` in main.py; `asyncio.run(check_connectivity())`
    in uTLS_evasion_layer.py; `NINDetector(...)` in core/nin_survival_pack.py and
    tests/test_ultra_vip.py).

The original pure-Python implementation is retained ONLY as a test-time parity
baseline in `core/_iran_detector_legacy.py` (imported by the Rust differential
parity suite as the ground-truth oracle) — nothing at runtime imports it.

Fallback: if the compiled extension is unavailable (e.g. a platform for which
it has not been built yet), this shim logs a warning and delegates to the
legacy baseline so the runtime never hard-fails. The intended and CI-verified
runtime path is Rust; the fallback exists purely as a safety net and preserves
feature parity (§14, no-feature-loss).
"""

import logging

log = logging.getLogger(__name__)

try:
    from core import _iran_detector_rs as _rs  # compiled PyO3 extension

    _RUST_BACKED = True
except ImportError as _exc:  # pragma: no cover - platform-specific safety net
    from core import _iran_detector_legacy as _legacy

    _rs = None
    _RUST_BACKED = False
    log.warning(
        "[iran_detector] Rust extension _iran_detector_rs unavailable (%s); "
        "falling back to the legacy Python baseline. Build the extension "
        "(rust/iran_detector_py) to use the Rust runtime path.",
        _exc,
    )

# ── Module-level constants (mirrored from Rust; kept for API compatibility) ──
if _RUST_BACKED:
    _INTERNATIONAL_PROBES = [tuple(x) for x in _rs.INTERNATIONAL_PROBES]
    _NIN_PROBES = [tuple(x) for x in _rs.NIN_PROBES]
    _PROBE_TIMEOUT = _rs.PROBE_TIMEOUT
else:  # pragma: no cover
    _INTERNATIONAL_PROBES = _legacy._INTERNATIONAL_PROBES
    _NIN_PROBES = _legacy._NIN_PROBES
    _PROBE_TIMEOUT = _legacy._PROBE_TIMEOUT


async def _probe_tcp(host: str, port: int, timeout: float = _PROBE_TIMEOUT) -> bool:
    """Async adapter over the Rust (sync) TCP probe. Preserves the legacy
    signature so any caller awaiting it keeps working."""
    if _RUST_BACKED:
        return _rs.probe_tcp(host, port, timeout)
    return await _legacy._probe_tcp(host, port, timeout)  # pragma: no cover


async def check_connectivity() -> tuple[bool, bool]:
    """
    Returns (international_ok, nin_active). Probing executes in Rust; this async
    wrapper exists only so `await` / `asyncio.run` call sites are unchanged.
    """
    if _RUST_BACKED:
        return _rs.check_connectivity()
    return await _legacy.check_connectivity()  # pragma: no cover


def recommend_strategy(nin_active: bool) -> str:
    if _RUST_BACKED:
        return _rs.recommend_strategy(nin_active)
    return _legacy.recommend_strategy(nin_active)  # pragma: no cover


class NINDetector:
    """
    Rust-backed drop-in for the legacy `NINDetector`. Same constructor
    signature, same public methods and the `export_path` attribute the tests
    assert on. All real work is delegated to the Rust `RustNinDetector`.
    """

    def __init__(
        self,
        events_path: str = "data/nin_events.json",
        export_path: str = "export/iran_cut_pack.txt",
    ) -> None:
        self.events_path = events_path
        self.export_path = export_path
        if _RUST_BACKED:
            self._inner = _rs.RustNinDetector(events_path, export_path)
        else:  # pragma: no cover
            self._inner = _legacy.NINDetector(events_path=events_path, export_path=export_path)

    def is_nin_active(self, force_refresh: bool = False) -> bool:
        return self._inner.is_nin_active(force_refresh)

    def record_event(self, kind: str, details: dict) -> None:
        if _RUST_BACKED:
            import json

            self._inner.record_event(kind, json.dumps(details))
        else:  # pragma: no cover
            self._inner.record_event(kind, details)

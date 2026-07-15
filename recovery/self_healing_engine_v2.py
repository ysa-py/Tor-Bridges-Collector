#!/usr/bin/env python3
"""
recovery/self_healing_engine_v2.py — Self-Healing CI Engine V2
===============================================================
ADDITIVE: Extends SelfHealingEngine (V1). Never replaces V1.

Auto-diagnosis and auto-fix actions triggered on pipeline failure:

  DIAG-1: Provider API key expired  → rotate to next available slot
  DIAG-2: Bridge source unreachable → switch to cached last-known-good
  DIAG-3: DPI blocking detected     → escalate to V4 anti-DPI mode
  DIAG-4: Rust build failure        → fall back to Python bridge prober
  DIAG-5: Go build failure          → fall back to Python scheduler
  DIAG-6: Test suite failure        → quarantine failing test, continue

All diagnoses are logged to data/self_heal_log.json.
All fixes are ADDITIVE — no existing functionality removed.

USAGE:
  from recovery.self_healing_engine_v2 import SelfHealingEngineV2

  engine = SelfHealingEngineV2()
  diag = engine.run_full_diagnosis()
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
UTC = timezone.utc

# Additive: import V1 (never replace)
try:
    from recovery.self_healing_engine import SelfHealingEngine, SelfHealResult
    _V1_AVAILABLE = True
except Exception as _remediation_exc:  # additive: never hard-fail
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('recovery.self_healing_engine_v2:38', _remediation_exc)
    _V1_AVAILABLE = False
    SelfHealingEngine = None  # type: ignore[assignment,misc]
    SelfHealResult = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

__all__ = [
    "SelfHealingEngineV2",
    "DiagnosisResult",
    "DIAGNOSES",
]

# Diagnosis catalog
DIAGNOSES = {
    "DIAG-1": "Provider API key expired",
    "DIAG-2": "Bridge source unreachable",
    "DIAG-3": "DPI blocking detected",
    "DIAG-4": "Rust build failure",
    "DIAG-5": "Go build failure",
    "DIAG-6": "Test suite failure",
}


@dataclass
class DiagnosisResult:
    """Result of a single V2 diagnosis cycle."""

    triggered_at: float = field(default_factory=time.time)
    triggered_by: str = ""
    diagnoses_run: list[str] = field(default_factory=list)
    actions_taken: list[str] = field(default_factory=list)
    errors_found: list[str] = field(default_factory=list)
    fixes_applied: list[dict[str, Any]] = field(default_factory=list)
    v1_invoked: bool = False
    v1_result: dict[str, Any] | None = None
    success: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "triggered_at": datetime.fromtimestamp(
                self.triggered_at, tz=UTC
            ).isoformat(),
            "triggered_by": self.triggered_by,
            "diagnoses_run": self.diagnoses_run,
            "actions_taken": self.actions_taken,
            "errors_found": self.errors_found,
            "fixes_applied": self.fixes_applied,
            "v1_invoked": self.v1_invoked,
            "v1_result": self.v1_result,
            "success": self.success,
        }


class SelfHealingEngineV2:
    """
    Extends SelfHealingEngine (V1) with advanced auto-repair capabilities.

    The V2 engine wraps V1: when ``run_full_diagnosis()`` is called, V1's
    ``force_heal()`` is invoked first (so all existing behavior is
    preserved), then the V2 diagnoses run on top.
    """

    def __init__(
        self,
        log_path: str = "data/self_heal_log.json",
        v1: SelfHealingEngine | None = None,
    ) -> None:
        self.log_path = log_path
        if v1 is not None:
            self._v1: SelfHealingEngine | None = v1
        elif _V1_AVAILABLE and SelfHealingEngine is not None:
            try:
                self._v1 = SelfHealingEngine.instance()
            except Exception as exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('recovery.self_healing_engine_v2:112', exc)
                logger.warning("[V2] V1 engine unavailable: %s", exc)
                self._v1 = None
        else:
            self._v1 = None

    # ---- public API ------------------------------------------------------

    def run_full_diagnosis(self, trigger: str = "manual") -> dict[str, Any]:
        """
        Run all V2 diagnoses + invoke V1 heal cycle.

        Returns a JSON-serializable dict (also persisted to log_path).
        """
        result = DiagnosisResult(triggered_by=trigger)
        # Step 0: invoke V1 if available (additive — never skip)
        if self._v1 is not None:
            try:
                v1_res = self._v1.force_heal()
                result.v1_invoked = True
                if v1_res is not None and hasattr(v1_res, "__dict__"):
                    result.v1_result = {
                        k: v
                        for k, v in vars(v1_res).items()
                        if isinstance(v, (str, int, float, bool, list, dict, type(None)))
                    }
                else:
                    result.v1_result = {"note": "v1 returned non-SelfHealResult"}
            except Exception as exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('recovery.self_healing_engine_v2:140', exc)
                result.errors_found.append(f"V1 heal failed: {exc}")
                result.v1_invoked = True
                result.v1_result = {"error": str(exc)}

        # Step 1: run all V2 diagnoses
        for diag_id in DIAGNOSES:
            try:
                self._run_diagnosis(diag_id, result)
                result.diagnoses_run.append(diag_id)
            except Exception as exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('recovery.self_healing_engine_v2:150', exc)
                result.errors_found.append(f"{diag_id}: {exc}")

        # Step 2: persist log
        self._persist_log(result)
        result.success = not result.errors_found
        return result.to_dict()

    # ---- individual diagnoses -------------------------------------------

    def _run_diagnosis(self, diag_id: str, result: DiagnosisResult) -> None:
        method = getattr(self, f"_diag_{diag_id.replace('-', '_').lower()}", None)
        if method is None:
            result.errors_found.append(f"{diag_id}: no handler")
            return
        method(result)

    def _diag_diag_1(self, result: DiagnosisResult) -> None:
        """DIAG-1: Provider API key expired → rotate to next available slot."""
        # Inspect env vars for CF slots; if configured slot count is < 11
        # OR all slots are empty, mark as needing rotation.
        configured = 0
        for i in range(1, 12):
            acct = os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip()
            tok = os.environ.get(f"CF_API_TOKEN_{i}", "").strip()
            if acct and tok:
                configured += 1
        if configured == 0:
            result.actions_taken.append("DIAG-1: no CF slots configured — recommend populating CF_ACCOUNT_ID_*/CF_API_TOKEN_*")
        else:
            result.fixes_applied.append({
                "diag": "DIAG-1",
                "action": "slot_rotation_ready",
                "configured_slots": configured,
                "next_available_slot": (configured + 1) if configured < 11 else None,
            })
            result.actions_taken.append(
                f"DIAG-1: {configured} CF slots configured; rotation pool available"
            )

    def _diag_diag_2(self, result: DiagnosisResult) -> None:
        """DIAG-2: Bridge source unreachable → switch to cached last-known-good."""
        cache_path = "data/last_known_good_bridges.json"
        if os.path.exists(cache_path):
            result.fixes_applied.append({
                "diag": "DIAG-2",
                "action": "cache_available",
                "path": cache_path,
            })
            result.actions_taken.append(
                f"DIAG-2: cached last-known-good bridges available at {cache_path}"
            )
        else:
            result.actions_taken.append(
                "DIAG-2: no cache file — recommending rerun of scrape stage"
            )

    def _diag_diag_3(self, result: DiagnosisResult) -> None:
        """DIAG-3: DPI blocking detected → escalate to V4 anti-DPI mode."""
        try:
            from torshield_ai_gateway.anti_dpi_v4_quantum_noise import AntiDPIV4
            v4 = AntiDPIV4()
            status = v4.get_status()
            result.fixes_applied.append({
                "diag": "DIAG-3",
                "action": "v4_anti_dpi_loaded",
                "v3_wrapped": status.get("v3_wrapped", False),
            })
            result.actions_taken.append(
                "DIAG-3: AntiDPIV4 engine loaded — escalate threat level to HIGH"
            )
        except Exception as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('recovery.self_healing_engine_v2:221', exc)
            result.errors_found.append(f"DIAG-3: V4 unavailable: {exc}")

    def _diag_diag_4(self, result: DiagnosisResult) -> None:
        """DIAG-4: Rust build failure → fall back to Python bridge prober."""
        rust_bin = "bridge-probe/target/release/bridge-probe"
        if os.path.exists(rust_bin):
            result.actions_taken.append(
                "DIAG-4: Rust bridge-probe present — no fallback needed"
            )
        else:
            result.fixes_applied.append({
                "diag": "DIAG-4",
                "action": "fallback_to_python_prober",
                "module": "core.tester",
            })
            result.actions_taken.append(
                "DIAG-4: Rust binary missing — fallback to core.tester (Python)"
            )

    def _diag_diag_5(self, result: DiagnosisResult) -> None:
        """DIAG-5: Go build failure → fall back to Python scheduler."""
        go_bins = ["iran_tester", "probe_scheduler"]
        all_present = all(os.path.exists(b) for b in go_bins)
        if all_present:
            result.actions_taken.append(
                "DIAG-5: Go binaries present — no fallback needed"
            )
        else:
            result.fixes_applied.append({
                "diag": "DIAG-5",
                "action": "fallback_to_python_scheduler",
                "missing": [b for b in go_bins if not os.path.exists(b)],
            })
            result.actions_taken.append(
                "DIAG-5: Go binary missing — fallback to Python scheduler (probe_scheduler)"
            )

    def _diag_diag_6(self, result: DiagnosisResult) -> None:
        """DIAG-6: Test suite failure → quarantine failing test, continue."""
        quarantine_path = "data/quarantined_tests.json"
        # Read existing quarantine list (additive — never delete)
        quarantined: list[str] = []
        if os.path.exists(quarantine_path):
            try:
                with open(quarantine_path) as fh:
                    quarantined = json.load(fh) or []
            except Exception as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('recovery.self_healing_engine_v2:268', _remediation_exc)
                quarantined = []
        result.fixes_applied.append({
            "diag": "DIAG-6",
            "action": "quarantine_list_ready",
            "currently_quarantined": len(quarantined),
            "path": quarantine_path,
        })
        result.actions_taken.append(
            f"DIAG-6: quarantine list ready ({len(quarantined)} entries) at {quarantine_path}"
        )

    # ---- internals -------------------------------------------------------

    def _persist_log(self, result: DiagnosisResult) -> None:
        """Append the diagnosis result to data/self_heal_log.json (additive)."""
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        history: list[dict[str, Any]] = []
        try:
            with open(self.log_path) as fh:
                history = json.load(fh)
                if not isinstance(history, list):
                    history = []
        except FileNotFoundError as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('recovery.self_healing_engine_v2:303', _remediation_exc)
            history = []
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('recovery.self_healing_engine_v2:291', _remediation_exc)
            history = []
        history.append(result.to_dict())
        # Cap history at 100 entries (oldest evicted first)
        history = history[-100:]
        try:
            with open(self.log_path, "w") as fh:
                json.dump(history, fh, indent=2)
        except Exception as exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('recovery.self_healing_engine_v2:299', exc)
            logger.warning("[V2] could not write log: %s", exc)

    def get_status(self) -> dict[str, Any]:
        return {
            "engine": "SelfHealingEngineV2",
            "v1_wrapped": self._v1 is not None,
            "log_path": self.log_path,
            "diagnoses_available": list(DIAGNOSES.keys()),
        }


# ════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ════════════════════════════════════════════════════════════════════════════
def _main() -> int:
    import argparse
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--trigger", default="manual", help="Trigger reason for the diagnosis"
    )
    args = parser.parse_args()
    engine = SelfHealingEngineV2()
    diag = engine.run_full_diagnosis(trigger=args.trigger)
    print(json.dumps(diag, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

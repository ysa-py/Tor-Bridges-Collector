#!/usr/bin/env python3
from __future__ import annotations

"""
monitoring/telemetry_dashboard.py — Real-time monitoring for TorShield-IR
=========================================================================
ADDITIVE: extends monitoring/* with a real-time dashboard generator.

Generates a JSON dashboard (data/dashboard.json) updated every pipeline run:

    {
      "timestamp": "ISO-8601",
      "bridges": { ... },
      "dpi": { ... },
      "gateway": { ... },
      "pipeline": { ... }
    }
"""


import json
import logging
import os
from datetime import datetime, timezone
from typing import Any
UTC = timezone.utc

logger = logging.getLogger(__name__)

__all__ = ["TelemetryDashboard"]


class TelemetryDashboard:
    """
    Real-time monitoring dashboard generator.

    Aggregates state from multiple sources into a single JSON snapshot:

      - bridges      : total / tested / iran_reachable / nin_survival
      - dpi          : threat_level / active_evasion / last_assessment
      - gateway      : primary_provider / fallback_used / health_status
      - pipeline     : run_id / duration_seconds / errors / warnings

    Sources (all optional — never fails if a source is missing):
      - data/iran_bridges.json
      - data/dpi_intelligence.json
      - data/quality_report.json
      - data/zero_error_report.json
      - data/self_heal_log.json
    """

    def __init__(self, output_path: str = "data/dashboard.json") -> None:
        self.output_path = output_path

    # ---- public API ------------------------------------------------------

    def generate(self) -> str:
        """
        Generate the dashboard JSON, write it to ``self.output_path``,
        and return the JSON string.
        """
        snapshot: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "bridges": self._collect_bridges(),
            "dpi": self._collect_dpi(),
            "gateway": self._collect_gateway(),
            "pipeline": self._collect_pipeline(),
        }
        os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2, ensure_ascii=False)
        logger.info("[TelemetryDashboard] snapshot written → %s", self.output_path)
        return json.dumps(snapshot, indent=2, ensure_ascii=False)

    def get_status(self) -> dict[str, Any]:
        return {
            "engine": "TelemetryDashboard",
            "output_path": self.output_path,
            "last_snapshot_at": (
                datetime.fromtimestamp(
                    os.path.getmtime(self.output_path), tz=UTC
                ).isoformat()
                if os.path.exists(self.output_path)
                else None
            ),
        }

    # ---- collectors ------------------------------------------------------

    def _collect_bridges(self) -> dict[str, Any]:
        """Count bridges across known data files."""
        result = {"total": 0, "tested": 0, "iran_reachable": 0, "nin_survival": 0}
        # iran_bridges.json
        iran_bridges = self._read_json("data/iran_bridges.json")
        if iran_bridges and isinstance(iran_bridges, list):
            result["total"] = len(iran_bridges)
            result["tested"] = sum(
                1 for b in iran_bridges if b.get("tested") or b.get("last_tested")
            )
            result["iran_reachable"] = sum(
                1 for b in iran_bridges if b.get("iran_reachable") or b.get("reachable")
            )
            result["nin_survival"] = sum(
                1
                for b in iran_bridges
                if str(b.get("transport", "")).lower()
                in ("snowflake", "webtunnel", "meek_lite", "meek-lite")
            )
        # Fallback: try export/bridges_api.json
        if result["total"] == 0:
            api = self._read_json("export/bridges_api.json")
            if api and isinstance(api, dict) and "bridges" in api:
                result["total"] = len(api["bridges"])
        return result

    def _collect_dpi(self) -> dict[str, Any]:
        """Pull the latest DPI assessment."""
        result: dict[str, Any] = {
            "threat_level": "UNKNOWN",
            "active_evasion": "none",
            "last_assessment": None,
        }
        dpi_state = self._read_json("data/dpi_intelligence.json")
        if dpi_state and isinstance(dpi_state, dict):
            result["threat_level"] = dpi_state.get(
                "threat_level", dpi_state.get("level", "UNKNOWN")
            )
            result["active_evasion"] = dpi_state.get(
                "active_evasion", dpi_state.get("evasion", "none")
            )
            result["last_assessment"] = dpi_state.get(
                "last_assessment", dpi_state.get("timestamp")
            )
        # If V4 anti-DPI is loaded, report it
        try:
            from torshield_ai_gateway.anti_dpi_v4_quantum_noise import AntiDPIV4
            v4 = AntiDPIV4()
            status = v4.get_status()
            result["active_evasion"] = (
                f"v4:{status.get('state', {}).get('last_tier_used', 'none')}"
            )
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('monitoring.telemetry_dashboard:141', _remediation_exc)
            pass
        return result

    def _collect_gateway(self) -> dict[str, Any]:
        """Pull the latest gateway health snapshot."""
        result: dict[str, Any] = {
            "primary_provider": "unknown",
            "fallback_used": False,
            "health_status": "unknown",
        }
        # Try health-check report if available
        health = self._read_json("data/gateway_health.json")
        if health and isinstance(health, dict):
            result["primary_provider"] = health.get("primary_provider", "unknown")
            result["fallback_used"] = bool(health.get("fallback_used", False))
            result["health_status"] = health.get("health_status", "unknown")
        return result

    def _collect_pipeline(self) -> dict[str, Any]:
        """Pull pipeline run metadata from zero-error report and self-heal log."""
        result: dict[str, Any] = {
            "run_id": os.environ.get("CI_PIPELINE_ID", "local"),
            "duration_seconds": 0,
            "errors": 0,
            "warnings": 0,
        }
        zer = self._read_json("data/zero_error_report.json")
        if zer and isinstance(zer, dict):
            result["errors"] = int(
                zer.get("syntax_errors", 0)
                + zer.get("import_errors", 0)
                + zer.get("test_failures", 0)
                + zer.get("build_errors", 0)
            )
            result["status"] = zer.get("status", "UNKNOWN")
        # self-heal log → warnings count
        sh = self._read_json("data/self_heal_log.json")
        if sh and isinstance(sh, list):
            result["warnings"] = len(sh)
        return result

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _read_json(path: str) -> Any | None:
        if not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            logger.debug("[TelemetryDashboard] could not read %s: %s", path, exc)
            return None


# ════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ════════════════════════════════════════════════════════════════════════════
def _main() -> int:
    logging.basicConfig(level=logging.INFO)
    dash = TelemetryDashboard()
    snapshot = dash.generate()
    print(snapshot)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

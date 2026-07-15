#!/usr/bin/env python3
from __future__ import annotations

"""
core/temporal_analyzer.py — Iran DPI Temporal Pattern Analyzer
==============================================================
ADDITIVE: does not modify any existing module.

Iran's DPI intensity varies by time of day (UTC+3:30):

    00:00-06:00 → LOW       (night — reduced DPI load)
    06:00-09:00 → MEDIUM    (morning — increasing)
    09:00-22:00 → HIGH      (business hours — peak DPI)
    22:00-00:00 → MEDIUM    (evening — partial relaxation)
    FRIDAY_ALL  → VARIABLE  (Friday — prayer time relaxation possible)

This module:
  - Returns current DPI threat level based on Iran time
  - Recommends best connection windows (LOW-threat periods)
  - Exports schedule to data/iran_temporal_schedule.json
"""


import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any
UTC = timezone.utc

logger = logging.getLogger(__name__)

__all__ = [
    "IRAN_BLOCKING_SCHEDULE",
    "IranTemporalAnalyzer",
    "IRAN_TZ",
]

# Iran Standard Time (UTC+3:30)
IRAN_TZ = timezone(timedelta(hours=3, minutes=30), name="IRST")

# Schedule of DPI threat levels by time-of-day window (Iran time).
# Each entry: (start_hour, end_hour, level)
# Friday gets its own override (prayer-time relaxation is common).
IRAN_BLOCKING_SCHEDULE: list[dict[str, Any]] = [
    {"window": "00:00-06:00", "start_h": 0, "end_h": 6, "level": "LOW",
     "note": "night — reduced DPI load"},
    {"window": "06:00-09:00", "start_h": 6, "end_h": 9, "level": "MEDIUM",
     "note": "morning — increasing"},
    {"window": "09:00-22:00", "start_h": 9, "end_h": 22, "level": "HIGH",
     "note": "business hours — peak DPI"},
    {"window": "22:00-00:00", "start_h": 22, "end_h": 24, "level": "MEDIUM",
     "note": "evening — partial relaxation"},
]


class IranTemporalAnalyzer:
    """
    Computes the current DPI threat level based on Iran local time and
    recommends the best connection windows.

    Methods:
      .current_threat_level() -> str           # LOW | MEDIUM | HIGH | VARIABLE
      .current_iran_time() -> datetime
      .best_connection_windows(limit=3) -> list[dict]
      .export_schedule(path="data/iran_temporal_schedule.json") -> None
      .get_status() -> dict
    """

    def __init__(self) -> None:
        self._schedule = list(IRAN_BLOCKING_SCHEDULE)

    # ---- public API ------------------------------------------------------

    def current_threat_level(self, now: datetime | None = None) -> str:
        """Return the current DPI threat level for Iran."""
        now = now or datetime.now(IRAN_TZ)
        # Friday special-case
        if now.weekday() == 4:  # Monday=0 ... Friday=4
            return "VARIABLE"
        hour = now.hour
        for entry in self._schedule:
            if entry["start_h"] <= hour < entry["end_h"]:
                return entry["level"]
        return "MEDIUM"  # safe default

    def current_iran_time(self) -> datetime:
        """Return the current time in Iran (UTC+3:30)."""
        return datetime.now(IRAN_TZ)

    def best_connection_windows(self, limit: int = 3) -> list[dict[str, Any]]:
        """
        Return the top ``limit`` upcoming LOW-threat windows.

        Each entry: {"window": str, "level": str, "starts_in_minutes": int}
        """
        now = self.current_iran_time()
        windows: list[dict[str, Any]] = []
        # Iterate the next 24 hours, marking LOW windows
        for offset_h in range(24):
            t = now + timedelta(hours=offset_h)
            if t.weekday() == 4:  # Friday — variable
                continue
            hour = t.hour
            for entry in self._schedule:
                if entry["start_h"] <= hour < entry["end_h"]:
                    if entry["level"] == "LOW":
                        starts_in_min = offset_h * 60 + (entry["start_h"] - hour) * 60
                        windows.append({
                            "window": entry["window"],
                            "level": entry["level"],
                            "starts_in_minutes": max(0, starts_in_min),
                            "note": entry["note"],
                        })
                    break
            if len(windows) >= limit:
                break
        return windows[:limit]

    def export_schedule(
        self, path: str = "data/iran_temporal_schedule.json"
    ) -> None:
        """Persist the full schedule + current snapshot to ``path``."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        now = self.current_iran_time()
        payload = {
            "generated_at": datetime.now(UTC).isoformat(),
            "iran_time": now.isoformat(),
            "current_threat_level": self.current_threat_level(now),
            "schedule": self._schedule,
            "friday_override": "VARIABLE",
            "timezone": "Asia/Tehran (UTC+3:30)",
            "best_windows_next_24h": self.best_connection_windows(limit=5),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        logger.info("[TemporalAnalyzer] schedule written → %s", path)

    def get_status(self) -> dict[str, Any]:
        now = self.current_iran_time()
        return {
            "engine": "IranTemporalAnalyzer",
            "iran_time": now.isoformat(),
            "weekday": now.strftime("%A"),
            "current_threat_level": self.current_threat_level(now),
            "best_windows_next_24h": self.best_connection_windows(limit=3),
        }


# ════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ════════════════════════════════════════════════════════════════════════════
def _main() -> int:
    import sys
    logging.basicConfig(level=logging.INFO)
    analyzer = IranTemporalAnalyzer()
    if len(sys.argv) > 1 and sys.argv[1] == "--export":
        out = sys.argv[2] if len(sys.argv) > 2 else "data/iran_temporal_schedule.json"
        analyzer.export_schedule(out)
        print(f"Schedule written to {out}")
    print(json.dumps(analyzer.get_status(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

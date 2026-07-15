#!/usr/bin/env python3
from __future__ import annotations

"""Adaptive bridge scoring and selection for Iran-oriented outputs.

The selector is opt-in via ADAPTIVE_IR_SCORING_ENABLED.  It never fetches or
removes source bridges; callers pass the final candidate records and, when
enabled, receive those records ranked and filtered by a composite adaptive score.
"""

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from generated_json_loader import load_generated_json


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class AdaptiveConfig:
    enabled: bool = False
    min_score: float = 0.0
    prefer_webtunnel: bool = False
    prefer_obfs4: bool = False
    recent_failure_penalty: float = 0.15

    @classmethod
    def from_env(cls) -> AdaptiveConfig:
        return cls(
            enabled=_env_bool("ADAPTIVE_IR_SCORING_ENABLED", False),
            min_score=_env_float("ADAPTIVE_IR_MIN_SCORE", 0.0),
            prefer_webtunnel=_env_bool("ADAPTIVE_IR_PREFER_WEBTUNNEL", False),
            prefer_obfs4=_env_bool("ADAPTIVE_IR_PREFER_OBFS4", False),
            recent_failure_penalty=_env_float("ADAPTIVE_IR_RECENT_FAILURE_PENALTY", 0.15),
        )


class AdaptiveBridgeSelector:
    """Score, rank, and optionally filter bridge records using local signals."""

    def __init__(self, config: AdaptiveConfig | None = None) -> None:
        self.config = config or AdaptiveConfig.from_env()
        self.iran_by_line = self._load_iran_results()
        self.scheduler_by_line = self._load_scheduler_results()
        self.latest_by_line = self._load_latest_results()

    def _load_iran_results(self) -> dict[str, dict[str, Any]]:
        data = load_generated_json(Path("bridge/iran_results.json"), {"bridges": []})
        bridges = data.get("bridges") if isinstance(data, dict) else []
        if not isinstance(bridges, list):
            bridges = []
        return {r.get("line", ""): r for r in bridges if isinstance(r, dict)}

    def _load_scheduler_results(self) -> dict[str, dict[str, Any]]:
        data = load_generated_json(Path("data/scheduler_results.json"), {"results": []})
        results = data.get("results") if isinstance(data, dict) else []
        if not isinstance(results, list):
            results = []
        return {r.get("bridge_line", ""): r for r in results if isinstance(r, dict)}

    def _load_latest_results(self) -> dict[str, dict[str, Any]]:
        data = load_generated_json(Path("data/latest-results.json"), {"bridges": []})
        bridges = data.get("bridges") if isinstance(data, dict) else []
        if not isinstance(bridges, list):
            bridges = []
        return {r.get("line", ""): r for r in bridges if isinstance(r, dict)}

    @staticmethod
    def _is_cdn_good(flags: Iterable[str], asn_org: str) -> bool:
        org = asn_org.lower()
        cdn_orgs = ("cloudflare", "fastly", "akamai", "azure", "amazon", "google", "cdn")
        return "domain_front_cdn_ok" in set(flags) or any(s in org for s in cdn_orgs)

    def score(self, line: str, record: dict[str, Any]) -> tuple[float, dict[str, Any]]:
        iran = self.iran_by_line.get(line, {})
        sched = self.scheduler_by_line.get(line, {})
        latest = self.latest_by_line.get(line, {})
        transport = (record.get("transport") or iran.get("transport") or sched.get("transport") or "").lower()

        tcp = iran.get("tcp_reachable", record.get("tcp_reachable"))
        tcp_factor = 1.0 if tcp is True or transport == "snowflake" else 0.0 if tcp is False else 0.5

        flags = list(iran.get("flags", []))
        iran_status = iran.get("iran_status", "")
        if iran_status == "iran_likely_working":
            asn_factor = 1.0
        elif iran_status == "iran_asn_blocked":
            asn_factor = 0.0
        elif self._is_cdn_good(flags, iran.get("asn_org", "")):
            asn_factor = 1.0
        elif "domain_front_degraded" in flags:
            asn_factor = 0.25
        else:
            asn_factor = 0.5

        ooni_factor = latest.get("ooni_factor")
        if ooni_factor is None:
            if iran_status == "iran_likely_working":
                ooni_factor = 1.0
            elif iran_status in {"iran_likely_blocked", "iran_frequently_blocked"}:
                ooni_factor = 0.0
            else:
                ooni_factor = 0.5

        if sched.get("ripe_tested"):
            ripe_factor = 1.0 if sched.get("ripe_reachable") else 0.0
        else:
            ripe_factor = 0.5

        pt_status = str(sched.get("pt_status", "")).lower()
        pt_factor = 1.0 if pt_status in {"reachable", "quic_reachable"} else 0.0 if pt_status in {"timeout", "refused", "error"} else 0.5

        failure_penalty = 0.0
        failed = iran_status in {"tcp_unreachable", "iran_likely_blocked", "iran_frequently_blocked"} or pt_factor == 0.0
        circuit_state = str(record.get("circuit_state") or iran.get("circuit_state") or latest.get("circuit_state") or "closed").lower()
        if failed:
            failure_penalty += self.config.recent_failure_penalty
        if circuit_state == "open":
            failure_penalty += self.config.recent_failure_penalty
        elif circuit_state == "half_open":
            failure_penalty += self.config.recent_failure_penalty / 2

        preference = 0.0
        if self.config.prefer_webtunnel and transport == "webtunnel":
            preference += 0.05
        if self.config.prefer_obfs4 and transport == "obfs4":
            preference += 0.05

        score = (0.25 * tcp_factor) + (0.15 * asn_factor) + (0.25 * float(ooni_factor)) + (0.15 * ripe_factor) + (0.20 * pt_factor)
        score = max(0.0, min(1.0, score + preference - failure_penalty))
        meta = {"adaptive_score": round(score, 4), "adaptive_signals": {"tcp": tcp_factor, "asn_cdn": asn_factor, "ooni": ooni_factor, "ripe": ripe_factor, "pt": pt_factor, "failure_penalty": round(failure_penalty, 4)}}
        return score, meta

    def select(self, items: list[tuple[str, dict[str, Any]]]) -> list[tuple[str, dict[str, Any]]]:
        if not self.config.enabled:
            return items
        scored = []
        for line, record in items:
            score, meta = self.score(line, record)
            if score >= self.config.min_score:
                enriched = {**record, **meta}
                scored.append((score, line, enriched))
        scored.sort(key=lambda x: (x[0], x[2].get("last_seen", ""), x[1]), reverse=True)
        return [(line, rec) for score, line, rec in scored]

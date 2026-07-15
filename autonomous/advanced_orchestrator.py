from __future__ import annotations

"""Advanced autonomous orchestration primitives kept separate from the base scheduler.

This module extends the stable offline-first scheduler without rewriting it.  The
split keeps pull requests easier to merge while still providing deterministic
AI-routing, caching, resource telemetry, and bounded validation-repair loops.
"""

import json
import math
import os
import platform
import shutil
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .resilient_orchestrator import AgentRole, AutonomousTask, EndpointState, NetworkHealth, ResilientOrchestrator as BaseResilientOrchestrator


@dataclass(slots=True)
class ValidationResult:
    """Result from one autonomous validation command."""

    command: str
    passed: bool
    output: str = ""
    cycle: int = 0
    repaired: bool = False
    repair_detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ResourceSnapshot:
    """Point-in-time local resource telemetry for self-healing decisions."""

    cpu_load_1m: float = 0.0
    memory_available_mb: float = 0.0
    storage_free_mb: float = 0.0
    process_count: int = 0
    captured_at: float = field(default_factory=time.time)

    @classmethod
    def capture(cls, path: str | os.PathLike[str] = ".") -> ResourceSnapshot:
        load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
        storage = shutil.disk_usage(path)
        memory_available_mb = 0.0
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("MemAvailable:"):
                    memory_available_mb = float(line.split()[1]) / 1024.0
                    break
        proc = Path("/proc")
        process_count = sum(1 for child in proc.iterdir() if child.name.isdigit()) if proc.exists() else 0
        return cls(
            cpu_load_1m=load,
            memory_available_mb=memory_available_mb,
            storage_free_mb=storage.free / (1024 * 1024),
            process_count=process_count,
        )


@dataclass(slots=True)
class ModelCandidate:
    """Model-routing candidate used for internal AI fallback decisions."""

    name: str
    quality: float
    latency_ms: float
    cost_per_1k: float = 0.0
    available: bool = True
    context_tokens: int = 8192

    @property
    def routing_score(self) -> float:
        latency_penalty = min(max(self.latency_ms, 0.0) / 10_000.0, 1.0)
        cost_penalty = min(max(self.cost_per_1k, 0.0) / 0.10, 1.0)
        context_bonus = min(max(self.context_tokens, 1) / 128_000.0, 1.0)
        availability = 1.0 if self.available else 0.0
        score = self.quality * 0.60 + (1 - latency_penalty) * 0.20 + (1 - cost_penalty) * 0.10 + context_bonus * 0.10
        return max(0.0, min(1.0, availability * score))


class AdvancedResilientOrchestrator(BaseResilientOrchestrator):
    """Base scheduler plus model routing, memory, telemetry, and repair loops."""

    def __init__(self, state_path: str | os.PathLike[str] = "data/autonomous_orchestrator_state.json") -> None:
        self.repair_handlers: dict[str, Callable[[ValidationResult], dict[str, Any]]] = {}
        self.local_cache: dict[str, dict[str, Any]] = {}
        self.session_recovery: dict[str, dict[str, Any]] = {}
        self.models: dict[str, ModelCandidate] = {}
        self.resource_snapshots: list[ResourceSnapshot] = []
        self.validation_history: list[dict[str, Any]] = []
        super().__init__(state_path)

    def register_repair_handler(self, command: str, handler: Callable[[ValidationResult], dict[str, Any]]) -> None:
        """Register a bounded repair function for a failed validation command."""
        self.repair_handlers[command] = handler

    def register_model(self, candidate: ModelCandidate) -> ModelCandidate:
        self.models[candidate.name] = candidate
        self.save()
        return candidate

    def route_model(self, required_context_tokens: int = 0) -> ModelCandidate | None:
        candidates = [candidate for candidate in self.models.values() if candidate.available and candidate.context_tokens >= required_context_tokens]
        if not candidates:
            candidates = [candidate for candidate in self.models.values() if candidate.available]
        if not candidates:
            self.reflect("model_route_unavailable", {"required_context_tokens": required_context_tokens})
            return None
        selected = max(candidates, key=lambda candidate: candidate.routing_score)
        self.reflect("model_routed", {"model": selected.name, "score": round(selected.routing_score, 4)})
        return selected

    def cache_response(self, key: str, value: Any, *, ttl_seconds: float = 300.0) -> None:
        self.local_cache[key] = {"value": value, "expires_at": time.time() + max(ttl_seconds, 0.0)}
        self.save()

    def cached_response(self, key: str) -> Any | None:
        entry = self.local_cache.get(key)
        if not entry:
            return None
        if entry["expires_at"] < time.time():
            self.local_cache.pop(key, None)
            self.reflect("cache_expired", {"key": key})
            self.save()
            return None
        return entry["value"]

    def record_resource_snapshot(self, snapshot: ResourceSnapshot | None = None) -> ResourceSnapshot:
        captured = snapshot or ResourceSnapshot.capture(self.state_path.parent)
        self.resource_snapshots.append(captured)
        self.resource_snapshots = self.resource_snapshots[-100:]
        self.reflect(
            "resource_snapshot",
            {
                "cpu_load_1m": round(captured.cpu_load_1m, 3),
                "memory_available_mb": round(captured.memory_available_mb, 1),
                "storage_free_mb": round(captured.storage_free_mb, 1),
                "platform": platform.system(),
            },
        )
        self.save()
        return captured

    def recover_sessions(self) -> list[AutonomousTask]:
        recovered: list[AutonomousTask] = []
        for task in self._queue:
            if task.status.value in {"running", "deferred"}:
                task.status = type(task.status).PENDING
                task.run_at = min(task.run_at, time.time())
                recovered.append(task)
        if recovered:
            self.reflect("sessions_recovered", {"count": len(recovered)})
            self.save()
        return recovered

    def synchronize_offline_queue(self, *, budget: int = 10) -> list[AutonomousTask]:
        if not self.choose_endpoint():
            self.reflect("sync_deferred_offline", {"queued": len(self._queue)})
            return []
        return self.run_ready(budget=budget)

    def plan_validation_cycle(self, commands: Sequence[str]) -> list[AutonomousTask]:
        planned: list[AutonomousTask] = []
        for index, command in enumerate(commands):
            planned.append(self.schedule("validation_command", {"command": command}, role=AgentRole.VALIDATOR, priority=10 + index))
        self.reflect("validation_cycle_planned", {"count": len(planned)})
        return planned

    def run_validation_repair_cycle(
        self,
        commands: Sequence[str],
        executor: Callable[[str], tuple[bool, str]],
        *,
        max_cycles: int = 3,
    ) -> list[ValidationResult]:
        """Run analyze→repair→validate loops until commands pass or repairs stop."""
        all_results: list[ValidationResult] = []
        bounded_cycles = max(1, min(max_cycles, 10))
        for cycle in range(1, bounded_cycles + 1):
            cycle_results: list[ValidationResult] = []
            for command in commands:
                passed, output = executor(command)
                result = ValidationResult(command=command, passed=passed, output=output[-4000:], cycle=cycle)
                cycle_results.append(result)
                all_results.append(result)
            self.validation_history.extend(asdict(result) for result in cycle_results)
            self.validation_history = self.validation_history[-200:]
            failures = [result for result in cycle_results if not result.passed]
            if not failures:
                self.reflect("validation_cycle_succeeded", {"cycle": cycle, "commands": len(commands)})
                self.save()
                return all_results
            repaired_any = False
            for failure in failures:
                repairer = self.repair_handlers.get(failure.command) or self.repair_handlers.get("*")
                if not repairer:
                    self.reflect("repair_unavailable", {"command": failure.command, "cycle": cycle})
                    continue
                detail = repairer(failure)
                failure.repaired = True
                failure.repair_detail = detail
                self.validation_history.append(asdict(failure))
                self.reflect("repair_applied", {"command": failure.command, "cycle": cycle, "detail": detail})
                repaired_any = True
            self.validation_history = self.validation_history[-200:]
            self.save()
            if not repaired_any:
                return all_results
        self.reflect("validation_cycle_exhausted", {"cycles": bounded_cycles, "commands": len(commands)})
        self.save()
        return all_results

    def save(self) -> None:
        super().save()
        if not self.state_path.exists():
            return
        payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        payload.update(
            {
                "local_cache": self.local_cache,
                "session_recovery": self.session_recovery,
                "models": {name: asdict(model) for name, model in self.models.items()},
                "resource_snapshots": [asdict(snapshot) for snapshot in self.resource_snapshots],
                "validation_history": self.validation_history[-200:],
            }
        )
        self.state_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def load(self) -> None:
        super().load()
        if not self.state_path.exists() or self.state_path.stat().st_size == 0:
            return
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.reflect("advanced_state_recovery", {"path": str(self.state_path), "error": str(exc)})
            return
        self.local_cache = payload.get("local_cache", {})
        self.session_recovery = payload.get("session_recovery", {})
        self.models = {name: ModelCandidate(**raw) for name, raw in payload.get("models", {}).items()}
        self.resource_snapshots = [ResourceSnapshot(**raw) for raw in payload.get("resource_snapshots", [])][-100:]
        self.validation_history = payload.get("validation_history", [])[-200:]


ResilientOrchestrator = AdvancedResilientOrchestrator

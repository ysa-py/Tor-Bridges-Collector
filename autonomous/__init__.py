"""Autonomous resilience primitives for TorShield-IR.

The package exposes offline-first orchestration building blocks used by the
bootstrap scripts and CI tests.  Implementations are deterministic and avoid
network side effects unless a caller injects concrete transport functions.
"""

from .resilient_orchestrator import (
    AgentRole,
    AutonomousTask,
    EndpointState,
    ModelCandidate,
    NetworkHealth,
    ResourceSnapshot,
    ResilientOrchestrator,
    TaskStatus,
)

__all__ = [
    "AgentRole",
    "AutonomousTask",
    "EndpointState",
    "ModelCandidate",
    "NetworkHealth",
    "ResourceSnapshot",
    "ResilientOrchestrator",
    "TaskStatus",
]

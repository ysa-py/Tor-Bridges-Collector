#!/usr/bin/env bash
# ================================================================
#  bootstrap_autonomous_orchestrator.sh
#  Bootstraps the autonomous orchestrator with anti-censorship
#  Anti-DPI / Smart Iran filter bypass — fully automatic
# ================================================================
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_PATH="${AUTONOMOUS_STATE_PATH:-$ROOT_DIR/data/autonomous_orchestrator_state.json}"

# ── Ensure data directory exists ─────────────────────────────────
mkdir -p "$(dirname "$STATE_PATH")"

cd "$ROOT_DIR"

# ── Merge conflict RESOLVED: use branch import (modular structure) ─
python - <<'PY'
import os
import sys
import asyncio
import logging

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("bootstrap")

# ── Resolved import (branch version is correct — advanced_orchestrator is a submodule) ──
try:
    from autonomous import AgentRole, NetworkHealth
    from autonomous.advanced_orchestrator import ModelCandidate, ResilientOrchestrator
except ImportError as e:
    logger.error(f"Import failed: {e}")
    logger.error("Ensure autonomous package and advanced_orchestrator submodule are installed.")
    sys.exit(1)

# ── Anti-censorship integration ──────────────────────────────────
try:
    from autonomous.anti_censorship import SmartAntiCensorshipRouter, AntiCensorshipNetworkHealth
    ANTI_CENSOR_AVAILABLE = True
except ImportError:
    ANTI_CENSOR_AVAILABLE = False
    logger.warning("Anti-censorship module not available, using direct connections")


async def bootstrap() -> None:
    state_path = os.environ.get(
        "AUTONOMOUS_STATE_PATH",
        "data/autonomous_orchestrator_state.json"
    )
    orch = ResilientOrchestrator(state_path)

    # ── Anti-censorship router initialization ────────────────────
    router = None
    if ANTI_CENSOR_AVAILABLE:
        router = SmartAntiCensorshipRouter()
        await router.initialize()
        status = router.get_status()
        logger.info(f"Anti-censorship router: {status}")
        NetworkHealthClass = AntiCensorshipNetworkHealth
    else:
        NetworkHealthClass = NetworkHealth

    # ── Register endpoints ───────────────────────────────────────
    orch.register_endpoint(
        "github-actions",
        "https://api.github.com",
        NetworkHealth(
            latency_ms=120,
            packet_loss=0.0,
            bandwidth_kbps=4096,
            online=True
        )
    )
    orch.register_endpoint(
        "local-cache",
        "file://data/cache",
        NetworkHealth(
            latency_ms=5,
            packet_loss=0.0,
            bandwidth_kbps=100_000,
            online=True
        )
    )

    # ── Register models ──────────────────────────────────────────
    orch.register_model(ModelCandidate(
        "local-fast",
        quality=0.74,
        latency_ms=80,
        cost_per_1k=0.0,
        available=True,
        context_tokens=8192
    ))
    orch.register_model(ModelCandidate(
        "github-hosted-deep",
        quality=0.92,
        latency_ms=450,
        cost_per_1k=0.0,
        available=True,
        context_tokens=128_000
    ))

    # ── Plan validation cycle ────────────────────────────────────
    orch.plan_validation_cycle([
        "python scripts/validate_artifacts.py",
        "python scripts/security_scan.py --fail-on-severity critical",
        "python scripts/validate_dependencies.py",
        "python scripts/generate_architecture_docs.py",
    ])

    orch.record_resource_snapshot()

    selected = orch.choose_endpoint()
    model    = orch.route_model(required_context_tokens=32_000)

    print(f"Autonomous orchestrator bootstrapped at {state_path}")
    print(
        f"endpoint={selected.name if selected else 'none'} "
        f"timeout={orch.adaptive_timeout_seconds(selected):.1f}s"
    )
    print(
        f"model={model.name if model else 'none'} "
        f"queued_validations={len(orch._queue)}"
    )

    if router:
        print(f"anti_censorship={router.get_status()}")


asyncio.run(bootstrap())
PY

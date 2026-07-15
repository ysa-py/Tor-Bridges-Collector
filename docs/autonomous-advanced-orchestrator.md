# Advanced Autonomous Orchestrator

The advanced orchestrator extends the stable base scheduler from `autonomous/resilient_orchestrator.py` without rewriting that file. This keeps merge conflicts small while adding the fully autonomous primitives requested for local AI planning, validation, repair, and resilient offline operation.

## High-level architecture

1. **Base scheduler**: persistent idempotent queue, endpoint health scoring, adaptive timeout, exponential backoff, circuit breaker, checkpoint recovery, and heartbeat reflection.
2. **Model router**: ranks internal model candidates by quality, latency, cost, context window, and availability, then falls back to the best available candidate.
3. **Memory/cache layer**: persists TTL-based local cache entries for temporary offline operation.
4. **Resource monitor**: captures CPU load, memory availability, storage availability, process count, and platform metadata for self-healing decisions.
5. **Offline synchronizer**: defers queued work while no endpoint is healthy and resumes execution after reconnection.
6. **Debugger/repair loop**: runs bounded analyze→repair→validate cycles using injected deterministic repair handlers, records validation history, and stops safely when no repair path exists.

## Bootstrap sequence

The bootstrap script registers safe local/GitHub endpoints, model candidates, validation tasks, and resource telemetry:

```bash
AUTONOMOUS_STATE_PATH=/tmp/micafp-orch-state.json ./scripts/bootstrap_autonomous_orchestrator.sh
```

No external bridge infrastructure is provisioned by the bootstrap. Command execution and code repair remain behind injected handlers so real CI jobs can decide which commands and remediation functions are allowed.

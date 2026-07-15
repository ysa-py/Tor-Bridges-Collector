from autonomous import NetworkHealth
from autonomous.advanced_orchestrator import ModelCandidate, ResilientOrchestrator, ResourceSnapshot, ValidationResult


def test_model_routing_prefers_available_quality_with_context(tmp_path):
    orch = ResilientOrchestrator(tmp_path / "state.json")
    orch.register_model(ModelCandidate("fast-small", quality=0.72, latency_ms=80, context_tokens=4096))
    orch.register_model(ModelCandidate("deep-large", quality=0.94, latency_ms=600, context_tokens=128000))
    assert orch.route_model(required_context_tokens=32000).name == "deep-large"


def test_cache_persists_and_expires(tmp_path):
    state = tmp_path / "state.json"
    orch = ResilientOrchestrator(state)
    orch.cache_response("health", {"ok": True}, ttl_seconds=60)
    loaded = ResilientOrchestrator(state)
    assert loaded.cached_response("health") == {"ok": True}
    loaded.local_cache["health"]["expires_at"] = 0
    assert loaded.cached_response("health") is None


def test_offline_queue_synchronizes_after_endpoint_recovers(tmp_path):
    orch = ResilientOrchestrator(tmp_path / "state.json")
    endpoint = orch.register_endpoint("primary", "https://primary.example", NetworkHealth(online=False))
    orch.register_handler("repair", lambda task, selected: {"endpoint": selected.name})
    orch.schedule("repair", {"target": "docs"}, priority=1)
    assert orch.synchronize_offline_queue(budget=1) == []
    endpoint.health.online = True
    completed = orch.synchronize_offline_queue(budget=1)
    assert completed[0].checkpoint == {"endpoint": "primary"}


def test_resource_snapshot_is_persisted(tmp_path):
    state = tmp_path / "state.json"
    orch = ResilientOrchestrator(state)
    orch.record_resource_snapshot(ResourceSnapshot(cpu_load_1m=0.5, memory_available_mb=512, storage_free_mb=2048, process_count=3))
    loaded = ResilientOrchestrator(state)
    assert loaded.resource_snapshots[0].storage_free_mb == 2048


def test_validation_cycle_plans_idempotent_tasks(tmp_path):
    orch = ResilientOrchestrator(tmp_path / "state.json")
    planned = orch.plan_validation_cycle(["python -m pytest -q", "go test ./..."])
    assert [task.payload["command"] for task in planned] == ["python -m pytest -q", "go test ./..."]
    assert len(orch._queue) == 2


def test_validation_repair_cycle_retries_until_clean(tmp_path):
    orch = ResilientOrchestrator(tmp_path / "state.json")
    repaired = {"done": False}

    def executor(command: str) -> tuple[bool, str]:
        return (repaired["done"], "clean" if repaired["done"] else "lint failure")

    def repair(result: ValidationResult) -> dict[str, object]:
        repaired["done"] = True
        return {"fixed": result.command, "strategy": "deterministic"}

    orch.register_repair_handler("python -m pytest -q", repair)
    results = orch.run_validation_repair_cycle(["python -m pytest -q"], executor, max_cycles=3)
    assert [result.passed for result in results] == [False, True]
    assert results[0].repaired is True
    assert orch.validation_history[-1]["passed"] is True


def test_validation_repair_cycle_stops_when_no_repair_handler(tmp_path):
    orch = ResilientOrchestrator(tmp_path / "state.json")
    results = orch.run_validation_repair_cycle(["go test ./..."], lambda command: (False, "compile error"), max_cycles=3)
    assert len(results) == 1
    assert results[0].passed is False
    assert orch.reflection_log[-1]["event"] == "repair_unavailable"


def test_validation_repair_cycle_persists_history(tmp_path):
    state = tmp_path / "state.json"
    orch = ResilientOrchestrator(state)
    orch.run_validation_repair_cycle(["bash -n script.sh"], lambda command: (True, "ok"))
    loaded = ResilientOrchestrator(state)
    assert loaded.validation_history[0]["command"] == "bash -n script.sh"
    assert loaded.validation_history[0]["passed"] is True

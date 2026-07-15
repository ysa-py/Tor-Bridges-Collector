from autonomous import AgentRole, NetworkHealth, ResilientOrchestrator, TaskStatus


def test_endpoint_selection_prefers_healthiest(tmp_path):
    orch = ResilientOrchestrator(tmp_path / "state.json")
    orch.register_endpoint("slow", "https://slow.example", NetworkHealth(latency_ms=1800, packet_loss=0.4, bandwidth_kbps=64, online=True))
    orch.register_endpoint("fast", "https://fast.example", NetworkHealth(latency_ms=50, packet_loss=0.0, bandwidth_kbps=8192, online=True))
    assert orch.choose_endpoint().name == "fast"


def test_task_deduplication_and_persistence(tmp_path):
    state = tmp_path / "state.json"
    orch = ResilientOrchestrator(state)
    first = orch.schedule("validate", {"target": "artifacts"}, role=AgentRole.VALIDATOR)
    second = orch.schedule("validate", {"target": "artifacts"}, role=AgentRole.VALIDATOR)
    assert first.idempotency_key == second.idempotency_key
    loaded = ResilientOrchestrator(state)
    assert len(loaded._queue) == 1


def test_circuit_breaker_defers_failed_endpoint(tmp_path):
    orch = ResilientOrchestrator(tmp_path / "state.json")
    endpoint = orch.register_endpoint("primary", "https://primary.example", NetworkHealth(online=True))
    for _ in range(3):
        orch.mark_failure(endpoint)
    assert not endpoint.available()


def test_run_ready_records_checkpoint(tmp_path):
    orch = ResilientOrchestrator(tmp_path / "state.json")
    orch.register_endpoint("local", "file://cache", NetworkHealth(latency_ms=1, online=True))
    orch.register_handler("validate", lambda task, endpoint: {"ok": True, "endpoint": endpoint.name})
    orch.schedule("validate", {"target": "docs"}, priority=1)
    completed = orch.run_ready(budget=1)
    assert completed[0].status == TaskStatus.SUCCEEDED
    assert completed[0].checkpoint == {"ok": True, "endpoint": "local"}


def test_model_routing_prefers_available_quality_with_context(tmp_path):
    from autonomous import ModelCandidate

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
    from autonomous import ResourceSnapshot

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

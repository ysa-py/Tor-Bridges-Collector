from __future__ import annotations

from scripts.ai_bridge_reranker import _ai_batch_refine


def test_ai_batch_refine_auto_uses_local_engine_by_default(monkeypatch):
    monkeypatch.delenv("AI_RERANK_EXTERNAL_AI", raising=False)
    bridges = [
        "snowflake 192.0.2.3:443 ABCDEF url=https://snowflake.example/ front=cdn.example",
        "obfs4 198.51.100.10:9001 ABCDEF cert=abc iat-mode=2",
    ]

    scored = _ai_batch_refine(
        bridges,
        smart_results=[],
        level=3,
        batch_size=10,
        top_n=2,
        ai_provider="auto",
    )

    assert set(scored) == set(bridges)
    assert all("score" in item for item in scored.values())
    assert scored[bridges[0]]["transport"] == "snowflake"


def test_ai_batch_refine_external_failure_falls_back_to_local(monkeypatch):
    monkeypatch.setenv("AI_RERANK_EXTERNAL_AI", "true")

    class BrokenIntel:
        def batch_ai_score(self, *args, **kwargs):
            raise TimeoutError("synthetic timeout")

    monkeypatch.setattr(
        "torshield_ai_gateway.iran_intelligence.IranIntelligenceLayer",
        lambda: BrokenIntel(),
    )
    bridge = "webtunnel 203.0.113.5:443 ABCDEF url=https://front.example/path"

    scored = _ai_batch_refine(
        [bridge],
        smart_results=[],
        level=4,
        batch_size=1,
        top_n=1,
        ai_provider="external",
        max_seconds=0.01,
    )

    assert list(scored) == [bridge]
    assert scored[bridge]["transport"] == "webtunnel"

from torshield_ai_gateway.local_ai_engine import LocalAIEngine
from torshield_ai_gateway.polymorphic_traffic_morpher import PolymorphicTrafficMorpher


def test_local_ai_rl_feedback_updates_state_without_external_calls(tmp_path):
    engine = LocalAIEngine(state_path=tmp_path / "state.json")
    before = engine.choose_dynamic_transport("MCI", censorship_level=4)
    result = engine.observe_feedback("MCI", "obfs4", "dpi_trigger", persist=True)
    after = engine.choose_dynamic_transport("MCI", censorship_level=4)

    assert result["source"] == "local_ai_engine_rl"
    assert (tmp_path / "state.json").exists()
    assert before["candidates"]
    assert after["candidates"]
    assert after["source"] == "local_ai_engine_rl"


def test_polymorphic_morphing_profile_handles_dpi_and_handshake_edges(tmp_path):
    engine = LocalAIEngine(state_path=tmp_path / "state.json")
    profile = engine.build_polymorphic_morphing_profile(
        transport="obfs4",
        isp="IRANCELL",
        censorship_level=5,
        handshake_failure=True,
        dpi_trigger=True,
    )

    assert profile["source"] == "local_ai_engine_rl"
    assert profile["padding"]["mode"] == "polymorphic"
    assert profile["retry_reconfigure_loop"]["max_attempts"] == 3
    assert "tcp_tls_handshake_failure" in profile["retry_reconfigure_loop"]
    assert profile["fragmentation_timing"]["enabled"] is False


def test_polymorphic_morpher_static_fallback_is_non_blocking(monkeypatch):
    class BrokenEngine:
        def build_polymorphic_morphing_profile(self, **kwargs):
            raise RuntimeError("boom")

    morpher = PolymorphicTrafficMorpher(engine=BrokenEngine())
    profile = morpher.plan(feedback={"dpi_trigger": True})

    assert profile["source"] == "polymorphic_morpher_static_fallback"
    assert profile["padding"]["max_bytes"] == 128

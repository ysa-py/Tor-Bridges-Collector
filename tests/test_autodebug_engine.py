from __future__ import annotations

from pathlib import Path


class _DummyIntel:
    def analyze_workflow_failure(self, workflow_name: str, error_log: str) -> dict:
        return {
            "root_cause": "diagnostic-only",
            "fix_type": "manual",
            "patch": "",
            "confidence": 0.0,
            "additive_only": True,
        }


def test_autodebug_runs_without_github_secrets(monkeypatch):
    """Internal AI diagnostics should not crash when GitHub push secrets are absent."""
    for key in ("GH_PAT_AUTOFIX", "GH_REPO_OWNER", "GH_REPO_NAME"):
        monkeypatch.delenv(key, raising=False)

    import torshield_ai_gateway.auto_debug as auto_debug

    monkeypatch.setattr(auto_debug, "IranIntelligenceLayer", lambda: _DummyIntel())
    engine = auto_debug.AutoDebugEngine()

    assert engine.github_configured is False
    assert "internal AI diagnosis" in engine.fetch_failed_run_logs("123")
    engine.run("AI Self-Healing Engine", "123")


def test_self_healing_workflow_runs_autodebug_for_transient_failures():
    """The workflow must not skip Run AutoDebugEngine just because a failure is transient."""
    workflow = Path(".github/workflows/ai_self_healing.yml").read_text(encoding="utf-8")

    assert "should_run_autodebug" in workflow
    assert 'f.write(f"should_run_autodebug={should_run_autodebug}\\n")' in workflow
    assert "if: steps.categorize-failure.outputs.should_run_autodebug == 'true'" in workflow
    assert "transient_categories = {\"network_error\", \"timeout\"}" in workflow
    assert "should_run_autodebug = \"true\"" in workflow
    assert "Skip AutoDebug (Transient Failure)" not in workflow

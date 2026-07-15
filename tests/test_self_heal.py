"""Tests for self_heal.py file discovery."""

import builtins
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from self_heal import iter_python_files


def test_iter_python_files_includes_nested_project_scripts():
    discovered = {Path(path).as_posix() for path in iter_python_files()}

    assert "torshield_ai_gateway/gateway.py" in discovered
    assert "scripts/run_full_audit.py" in discovered



def _raise_import_error_for_yaml(name, *args, **kwargs):
    if name == "yaml":
        raise ImportError("No module named yaml")
    return builtins.__import__(name, *args, **kwargs)


def test_yaml_import_error_skip_is_visible_in_heal_log(tmp_path, monkeypatch):
    import self_heal

    log_path = tmp_path / "self_heal_log.json"
    monkeypatch.setattr(self_heal, "HEAL_LOG", log_path)
    monkeypatch.delenv("SELF_HEAL_STRICT_YAML", raising=False)

    with patch("builtins.__import__", side_effect=_raise_import_error_for_yaml):
        errors = self_heal.check_yaml_syntax()

    assert errors == []

    self_heal.write_log(errors, [], False)
    entries = json.loads(log_path.read_text(encoding="utf-8"))
    latest = entries[-1]

    assert latest["yaml_validation_skipped"] is True
    assert latest["warnings"] == [
        {
            "type": "yaml_validation_skipped",
            "message": "YAML validation skipped because PyYAML is not installed.",
            "missing_dependency": "PyYAML",
        }
    ]


def test_yaml_import_error_is_error_in_strict_mode(monkeypatch):
    import self_heal

    monkeypatch.setenv("SELF_HEAL_STRICT_YAML", "true")

    with patch("builtins.__import__", side_effect=_raise_import_error_for_yaml):
        errors = self_heal.check_yaml_syntax()

    assert errors == [
        {
            "file": ".github/workflows",
            "error": "PyYAML is required for YAML validation when SELF_HEAL_STRICT_YAML=true.",
            "snippet": "No module named yaml",
        }
    ]

from __future__ import annotations

from generated_json_loader import load_generated_json


def test_load_generated_json_returns_fallback_for_missing_file(tmp_path):
    fallback = {"bridges": []}
    assert load_generated_json(tmp_path / "missing.json", fallback) is fallback


def test_load_generated_json_returns_fallback_for_invalid_json(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{not json", encoding="utf-8")
    fallback = {"results": []}
    assert load_generated_json(path, fallback) is fallback


def test_load_generated_json_returns_fallback_for_wrong_top_level_type(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[]", encoding="utf-8")
    fallback = {"bridges": []}
    assert load_generated_json(path, fallback) is fallback


def test_load_generated_json_normalizes_generated_list_fields(tmp_path):
    path = tmp_path / "artifact.json"
    path.write_text('{"bridges": null, "results": "bad", "other": 1}', encoding="utf-8")

    assert load_generated_json(path, {"bridges": [], "results": []}) == {
        "bridges": [],
        "results": [],
        "other": 1,
    }


def test_load_generated_json_keeps_valid_artifacts_unchanged(tmp_path):
    path = tmp_path / "artifact.json"
    expected = {"bridges": [{"line": "bridge"}], "summary": {"count": 1}}
    path.write_text('{"bridges": [{"line": "bridge"}], "summary": {"count": 1}}', encoding="utf-8")

    assert load_generated_json(path, {"bridges": [], "summary": {}}) == expected

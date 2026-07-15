"""Defensive loaders for generated JSON artifact files."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TypeVar

_LIST_FIELDS = ("bridges", "results")

T = TypeVar("T", dict, list)


def load_generated_json(path: Path, fallback: T) -> T:
    """Load a generated JSON artifact, returning *fallback* when unsafe.

    The artifact is considered unsafe when it is missing, unreadable, empty,
    invalid JSON, or when its parsed top-level type differs from the fallback's
    type. Dict artifacts also normalize common list-valued fields produced by
    pipeline generators so downstream consumers can iterate safely.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return fallback

    if not raw.strip():
        return fallback

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return fallback

    if not isinstance(data, type(fallback)):
        return fallback

    if isinstance(data, dict):
        for field in _LIST_FIELDS:
            if field in data or field in fallback:
                if not isinstance(data.get(field), list):
                    data[field] = []

    return data

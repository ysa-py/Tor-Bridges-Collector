# generated_json_loader.py Rust parity contract

This document records the Phase 1 parity anchor for
`generated_json_loader.py::load_generated_json`. The Python source remains in
place; deletion is not allowed until continuous parity proves identical behavior.

## Rust replacement

* Rust module: `src/generated_json_loader.rs`
* Cargo parity test entrypoint: `tests/generated_json_loader_parity.rs`
* Branch-covering parity cases: `tests/parity/generated_json_loader_parity.rs`

## Behavior contract

| Branch / input condition | Required Rust behavior |
| --- | --- |
| `path.read_text(encoding="utf-8")` raises `OSError` or `UnicodeError` | Return the caller-provided fallback unchanged. |
| File text is empty or whitespace-only after `strip()` | Return the caller-provided fallback unchanged. |
| `json.loads(raw)` raises `json.JSONDecodeError` | Return the caller-provided fallback unchanged. |
| Parsed top-level value is not the same runtime type as `fallback` | Return the caller-provided fallback unchanged. |
| Parsed value is a dict and either parsed data or fallback contains `bridges` / `results` | Ensure each present/common field is a list; replace non-list values with an empty list. |
| Parsed value is valid and type-compatible otherwise | Return parsed data with no additional mutation. |

`GeneratedJsonLoadStatus` exists only to make the branch taken observable in
Rust parity tests. The public `load_generated_json` return value remains the
Python-compatible JSON value.

## Deletion status

No Python file is deleted by this parity anchor. `generated_json_loader.py`
remains the source checked by parity tests at runtime.

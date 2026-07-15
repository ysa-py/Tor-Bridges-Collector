//! Parity port of `generated_json_loader.py`.
//!
//! The Python original remains in place. This module implements the same
//! defensive JSON-artifact loading semantics for use by parity tests before any
//! Python deletion is considered.

use std::{fs, io, path::Path};

use serde_json::{Map, Value};

const LIST_FIELDS: [&str; 2] = ["bridges", "results"];

/// Errors surfaced by [`load_generated_json`] for observability.
///
/// The public loader still returns the caller-provided fallback on every error,
/// exactly like `generated_json_loader.py::load_generated_json`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GeneratedJsonLoadStatus {
    Loaded,
    MissingOrUnreadable,
    Empty,
    InvalidJson,
    TypeMismatch,
}

/// Load a generated JSON artifact with Python-compatible defensive fallback.
///
/// Behavior traced to `generated_json_loader.py::load_generated_json`:
/// * missing/unreadable files return `fallback`;
/// * empty/whitespace-only files return `fallback`;
/// * invalid JSON returns `fallback`;
/// * top-level type mismatch against `fallback` returns `fallback`;
/// * object outputs normalize `bridges` and `results` to arrays whenever the
///   field exists in either parsed data or fallback but parsed data is not an
///   array for that field.
pub fn load_generated_json(path: &Path, fallback: Value) -> Value {
    load_generated_json_with_status(path, fallback).0
}

/// Same as [`load_generated_json`], also returning the branch taken for tests
/// and diagnostics without changing the Python-compatible return value.
pub fn load_generated_json_with_status(
    path: &Path,
    fallback: Value,
) -> (Value, GeneratedJsonLoadStatus) {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if is_python_os_or_unicode_error(&err) => {
            return (fallback, GeneratedJsonLoadStatus::MissingOrUnreadable);
        }
        Err(_) => return (fallback, GeneratedJsonLoadStatus::MissingOrUnreadable),
    };

    if raw.trim().is_empty() {
        return (fallback, GeneratedJsonLoadStatus::Empty);
    }

    let mut data: Value = match serde_json::from_str(&raw) {
        Ok(data) => data,
        Err(_) => return (fallback, GeneratedJsonLoadStatus::InvalidJson),
    };

    if !same_top_level_type(&data, &fallback) {
        return (fallback, GeneratedJsonLoadStatus::TypeMismatch);
    }

    if let (Some(data_obj), Some(fallback_obj)) = (data.as_object_mut(), fallback.as_object()) {
        normalize_common_list_fields(data_obj, fallback_obj);
    }

    (data, GeneratedJsonLoadStatus::Loaded)
}

fn is_python_os_or_unicode_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::Other
    )
}

fn same_top_level_type(data: &Value, fallback: &Value) -> bool {
    matches!(
        (data, fallback),
        (Value::Null, Value::Null)
            | (Value::Bool(_), Value::Bool(_))
            | (Value::Number(_), Value::Number(_))
            | (Value::String(_), Value::String(_))
            | (Value::Array(_), Value::Array(_))
            | (Value::Object(_), Value::Object(_))
    )
}

fn normalize_common_list_fields(data: &mut Map<String, Value>, fallback: &Map<String, Value>) {
    for field in LIST_FIELDS {
        if (data.contains_key(field) || fallback.contains_key(field))
            && !data.get(field).is_some_and(Value::is_array)
        {
            data.insert(field.to_string(), Value::Array(Vec::new()));
        }
    }
}

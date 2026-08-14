//! Versioned JSON Schema generation for the published model types.
//!
//! `schema-gen` writes one JSON Schema document per published type into
//! `schemas/`. Each document is deterministic (built from the same
//! `serde_json::Value` structure on every run), stamps
//! [`tbc_core::SCHEMA_VERSION`] as `x-schema-version`, and mirrors the serde
//! shapes of the `tbc-core` types — including which fields are always present
//! versus `skip_serializing_if`-omitted, and the externally-tagged encoding of
//! enum variants with fields.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};

use crate::error::XtaskError;

/// File name of the `BridgeLine` schema.
pub const BRIDGE_LINE_SCHEMA: &str = "bridge_line.schema.json";
/// File name of the `Observation` schema.
pub const OBSERVATION_SCHEMA: &str = "observation.schema.json";
/// File name of the `BridgeScore` schema.
pub const BRIDGE_SCORE_SCHEMA: &str = "bridge_score.schema.json";

/// Build the versioned schema documents for every published model type.
pub fn generate_schemas() -> BTreeMap<String, Value> {
    let version = tbc_core::SCHEMA_VERSION;
    let mut schemas = BTreeMap::new();
    schemas.insert(BRIDGE_LINE_SCHEMA.to_owned(), bridge_line_schema(version));
    schemas.insert(OBSERVATION_SCHEMA.to_owned(), observation_schema(version));
    schemas.insert(BRIDGE_SCORE_SCHEMA.to_owned(), bridge_score_schema(version));
    schemas
}

/// Write every generated schema under `out`, returning the number written.
pub fn write_schemas(out: &Path) -> Result<usize, XtaskError> {
    let schemas = generate_schemas();
    std::fs::create_dir_all(out).map_err(|source| XtaskError::io("create schema dir", source))?;
    for (name, value) in &schemas {
        let text = serde_json::to_string_pretty(value)?;
        std::fs::write(out.join(name), format!("{text}\n"))
            .map_err(|source| XtaskError::io(format!("write {name}"), source))?;
    }
    Ok(schemas.len())
}

fn bridge_line_schema(version: u32) -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://torshield-ir.dev/schemas/bridge_line.schema.json",
        "title": "BridgeLine",
        "description": "A fully parsed and validated bridge line (tbc-core::BridgeLine).",
        "x-schema-version": version,
        "type": "object",
        "additionalProperties": false,
        "required": ["raw", "transport", "host", "port", "params", "first_seen", "last_seen", "sources"],
        "properties": {
            "raw": { "type": "string", "description": "The original, unmodified bridge line." },
            "transport": { "type": "string", "description": "Canonical transport token (obfs4, webtunnel, vanilla, snowflake, meek, conjure) or the verbatim token for other transports." },
            "host": { "type": "string", "description": "Contact host: an IP literal (without brackets) or a DNS name." },
            "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
            "fingerprint": { "type": "string", "description": "Canonical 40-hex fingerprint, when the line carries one." },
            "params": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "cert": { "type": "string" },
                    "iat_mode": { "type": "string" },
                    "url": { "type": "string" },
                    "servername": { "type": "string" },
                    "utls": { "type": "string" },
                    "ver": { "type": "string" }
                }
            },
            "first_seen": { "type": "string", "format": "date-time" },
            "last_seen": { "type": "string", "format": "date-time" },
            "sources": { "type": "array", "uniqueItems": true, "items": { "type": "string" } }
        }
    })
}

fn observation_schema(version: u32) -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://torshield-ir.dev/schemas/observation.schema.json",
        "title": "Observation",
        "description": "A single, time-stamped measurement of one bridge from one vantage point (tbc-core::Observation).",
        "x-schema-version": version,
        "type": "object",
        "additionalProperties": false,
        "required": ["bridge_key", "vantage", "probe_kind", "evasion_profile", "verdict", "measured_at"],
        "properties": {
            "bridge_key": { "type": "string" },
            "vantage": {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "is_mobile"],
                "properties": {
                    "kind": { "type": "string", "description": "runner, ooni, ripe_atlas, globalping, volunteer_agent, or a verbatim other-kind token." },
                    "country": { "type": "string" },
                    "asn": { "type": "integer", "minimum": 0 },
                    "as_name": { "type": "string" },
                    "is_mobile": { "type": "boolean" }
                }
            },
            "probe_kind": {
                "type": "string",
                "enum": ["tcp_connect", "obfs4_handshake", "webtunnel_upgrade", "tor_bootstrap", "tls_sni", "tcp_traceroute"]
            },
            "evasion_profile": {
                "oneOf": [
                    { "type": "string", "enum": ["none"] },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["fragment"],
                        "properties": {
                            "fragment": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["n", "delay"],
                                "properties": {
                                    "n": { "type": "integer", "minimum": 0 },
                                    "delay": { "type": "integer", "minimum": 0 }
                                }
                            }
                        }
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["alt_client_hello"],
                        "properties": {
                            "alt_client_hello": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["profile"],
                                "properties": { "profile": { "type": "string" } }
                            }
                        }
                    }
                ]
            },
            "verdict": {
                "oneOf": [
                    { "type": "string", "enum": ["reachable", "refused", "timeout", "reset_injected", "tls_alert", "handshake_auth_fail", "dns_failure", "inconclusive"] },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["http_error"],
                        "properties": {
                            "http_error": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["code"],
                                "properties": { "code": { "type": "integer", "minimum": 100 } }
                            }
                        }
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["blocked"],
                        "properties": {
                            "blocked": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["evidence"],
                                "properties": { "evidence": { "type": "string" } }
                            }
                        }
                    }
                ]
            },
            "rtt_ms": { "type": "integer", "minimum": 0 },
            "bootstrap_pct": { "type": "integer", "minimum": 0, "maximum": 100 },
            "error_class": { "type": "string" },
            "raw_evidence": { "type": "string" },
            "measured_at": { "type": "string", "format": "date-time" },
            "measurement_ref": { "type": "string" }
        }
    })
}

fn bridge_score_schema(version: u32) -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://torshield-ir.dev/schemas/bridge_score.schema.json",
        "title": "BridgeScore",
        "description": "A scored bridge: global score, per-ASN scores, tier, and lifetime metadata (tbc-core::BridgeScore).",
        "x-schema-version": version,
        "type": "object",
        "additionalProperties": false,
        "required": ["global", "per_asn", "tier", "confidence", "freshness_age_seconds"],
        "properties": {
            "global": { "type": "number", "minimum": 0.0, "maximum": 100.0 },
            "per_asn": {
                "type": "object",
                "additionalProperties": { "type": "number" },
                "description": "Per-ASN scores keyed by autonomous-system number (string keys in JSON)."
            },
            "tier": { "type": "string", "enum": ["s", "a", "b", "c", "d"] },
            "confidence": {
                "type": "object",
                "additionalProperties": false,
                "required": ["k", "n"],
                "properties": {
                    "k": { "type": "integer", "minimum": 0 },
                    "n": { "type": "integer", "minimum": 0 }
                }
            },
            "first_confirmed_working_at": { "type": "string", "format": "date-time" },
            "first_blocked_at": { "type": "string", "format": "date-time" },
            "burn_seconds": { "type": "integer", "minimum": 0 },
            "median_lifetime_seconds": { "type": "integer", "minimum": 0 },
            "freshness_age_seconds": { "type": "integer", "minimum": 0 }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn generates_all_three_documents() {
        let schemas = generate_schemas();
        assert_eq!(schemas.len(), 3);
        assert!(schemas.contains_key(BRIDGE_LINE_SCHEMA));
        assert!(schemas.contains_key(OBSERVATION_SCHEMA));
        assert!(schemas.contains_key(BRIDGE_SCORE_SCHEMA));
    }

    #[test]
    fn each_schema_is_a_versioned_object_with_required_fields() {
        let schemas = generate_schemas();
        for (name, schema) in &schemas {
            assert_eq!(
                schema["type"], "object",
                "{name} should be an object schema"
            );
            assert_eq!(schema["x-schema-version"], tbc_core::SCHEMA_VERSION);
            assert!(
                schema["required"].is_array(),
                "{name} should declare required"
            );
            assert!(!schema["required"].as_array().unwrap().is_empty());
            assert_eq!(schema["additionalProperties"], false);
        }
    }

    #[test]
    fn observation_schema_encodes_closed_enums() {
        let schemas = generate_schemas();
        let observation = &schemas[OBSERVATION_SCHEMA];
        let probe_kind = &observation["properties"]["probe_kind"]["enum"];
        assert!(probe_kind
            .as_array()
            .unwrap()
            .contains(&json!("obfs4_handshake")));
        let tier = &schemas[BRIDGE_SCORE_SCHEMA]["properties"]["tier"]["enum"];
        assert_eq!(tier.as_array().unwrap().len(), 5);
    }
}

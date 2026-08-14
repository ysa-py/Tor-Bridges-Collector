//! Adapters from the `tbc-core` bridge model to transport codec inputs.
//!
//! These helpers are the seam the `prober` and `agent` crates use to turn a
//! parsed [`BridgeLine`] into the concrete inputs each codec expects, without
//! any network I/O.

use tbc_core::{BridgeLine, TransportKind};

use crate::error::TransportError;
use crate::obfs4::{decode_cert, IdentityKey};
use crate::webtunnel::UpgradeRequest;

/// Extract the obfs4 identity key from a parsed bridge line's `cert=` value.
pub fn obfs4_identity(bridge: &BridgeLine) -> Result<IdentityKey, TransportError> {
    if bridge.transport != TransportKind::Obfs4 {
        return Err(TransportError::UnsupportedTransport(
            bridge.transport.to_string(),
        ));
    }
    let cert = bridge
        .params
        .cert
        .as_deref()
        .ok_or(TransportError::MissingField("cert"))?;
    decode_cert(cert)
}

/// Build the HTTP upgrade request for a WebTunnel bridge, deriving the front
/// host and request path from its `url=` parameter.
pub fn webtunnel_request(
    bridge: &BridgeLine,
    key: [u8; 16],
) -> Result<UpgradeRequest, TransportError> {
    if bridge.transport != TransportKind::WebTunnel {
        return Err(TransportError::UnsupportedTransport(
            bridge.transport.to_string(),
        ));
    }
    let raw_url = bridge
        .params
        .url
        .as_deref()
        .ok_or(TransportError::MissingField("url"))?;
    let parsed =
        url::Url::parse(raw_url).map_err(|error| TransportError::Http(error.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or(TransportError::MissingField("host"))?
        .to_owned();
    let path = parsed.path().to_owned();
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };
    Ok(UpgradeRequest::new(host, key).with_path(path))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A 52-byte cert that decodes to a fixed identity.
    fn cert52() -> String {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        use base64::Engine as _;
        STANDARD_NO_PAD.encode([0x5Au8; 52])
    }

    #[test]
    fn extracts_obfs4_identity_from_bridge_line() {
        let line = format!(
            "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 cert={} iat-mode=0",
            cert52()
        );
        let bridge = BridgeLine::parse(&line, now()).unwrap();
        let identity = obfs4_identity(&bridge).unwrap();
        assert_eq!(identity.node_id, [0x5Au8; 20]);
        assert_eq!(identity.public_key, [0x5Au8; 32]);
    }

    #[test]
    fn rejects_non_obfs4_bridge() {
        let line = "webtunnel 1.2.3.4:443 FINGERPRINT url=https://example.com/x ver=0.0.3";
        let bridge = BridgeLine::parse(line, now()).unwrap();
        assert!(matches!(
            obfs4_identity(&bridge),
            Err(TransportError::UnsupportedTransport(_))
        ));
    }

    #[test]
    fn builds_webtunnel_request_from_bridge_line() {
        let line = "webtunnel 1.2.3.4:443 FINGERPRINT url=https://front.example.com/path ver=0.0.3";
        let bridge = BridgeLine::parse(line, now()).unwrap();
        let request = webtunnel_request(&bridge, [0u8; 16]).unwrap();
        assert_eq!(request.host, "front.example.com");
        assert_eq!(request.path, "/path");
    }
}

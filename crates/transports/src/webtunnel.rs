//! WebTunnel HTTP/WebSocket upgrade codec.
//!
//! WebTunnel bridges are reached by performing an RFC 6455 §4.2.1 HTTP upgrade
//! request over TLS to the bridge's front, then verifying the `101 Switching
//! Protocols` response. The distinctive WebTunnel detail is that the transport
//! places its padded client challenge in a `Sec-WebSocket-Protocol` header
//! (base64url, unpadded); this module exposes that value as a caller-supplied
//! protocol string so the padding policy lives with the caller.
//!
//! No sockets are opened here — only the request bytes are produced and the
//! response bytes are parsed.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;

use crate::error::TransportError;

/// The WebSocket version this codec emits.
pub const WEBSOCKET_VERSION: &str = "13";

/// An HTTP/1.1 WebSocket upgrade request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRequest {
    /// HTTP method, conventionally `GET`.
    pub method: String,
    /// Request target path, e.g. `/`.
    pub path: String,
    /// Value of the `Host` header (the bridge/front host).
    pub host: String,
    /// 16 random bytes backing the `Sec-WebSocket-Key` nonce.
    pub key: [u8; 16],
    /// Ordered `Sec-WebSocket-Protocol` values (WebTunnel's challenge, if any).
    pub protocols: Vec<String>,
}

impl UpgradeRequest {
    /// Construct a `GET /` request for `host` with a fresh handshake nonce.
    pub fn new(host: String, key: [u8; 16]) -> Self {
        Self {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            host,
            key,
            protocols: Vec::new(),
        }
    }

    /// Replace the request target path.
    pub fn with_path(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    /// Append a `Sec-WebSocket-Protocol` value.
    pub fn with_protocol(mut self, protocol: String) -> Self {
        self.protocols.push(protocol);
        self
    }

    /// The `Sec-WebSocket-Key` value: base64 of the 16-byte nonce (RFC 6455).
    pub fn sec_websocket_key(&self) -> String {
        STANDARD.encode(self.key)
    }

    /// Serialize the request to wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        if self.host.is_empty() {
            return Err(TransportError::MissingField("host"));
        }
        if self.method.is_empty() {
            return Err(TransportError::MissingField("method"));
        }
        if !self.path.starts_with('/') {
            return Err(TransportError::Http(
                "request path must start with '/'".to_owned(),
            ));
        }

        let mut out = String::new();
        out.push_str(&self.method);
        out.push(' ');
        out.push_str(&self.path);
        out.push_str(" HTTP/1.1\r\n");
        out.push_str("Host: ");
        out.push_str(&self.host);
        out.push_str("\r\n");
        out.push_str("Connection: Upgrade\r\n");
        out.push_str("Upgrade: websocket\r\n");
        out.push_str("Sec-WebSocket-Key: ");
        out.push_str(&self.sec_websocket_key());
        out.push_str("\r\n");
        out.push_str("Sec-WebSocket-Version: ");
        out.push_str(WEBSOCKET_VERSION);
        out.push_str("\r\n");
        for protocol in &self.protocols {
            out.push_str("Sec-WebSocket-Protocol: ");
            out.push_str(protocol);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        Ok(out.into_bytes())
    }
}

/// A parsed HTTP upgrade response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeResponse {
    /// The numeric HTTP status code.
    pub status_code: u16,
    /// The `Sec-WebSocket-Protocol` value echoed by the server, if any.
    pub subprotocol: Option<String>,
    /// All response headers, lower-cased names in order.
    pub headers: Vec<(String, String)>,
}

impl UpgradeResponse {
    /// Whether the server accepted the WebSocket upgrade (`101`).
    pub fn is_upgrade_accepted(&self) -> bool {
        self.status_code == 101
    }

    /// Parse an HTTP/1.1 upgrade response from wire bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, TransportError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| TransportError::Http("non-UTF-8 response".to_owned()))?;
        let mut lines = text.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| TransportError::Http("empty response".to_owned()))?;
        let status_code = parse_status_line(status_line)?;

        let mut subprotocol = None;
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| TransportError::Http(format!("malformed header: {line}")))?;
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_owned();
            if name == "sec-websocket-protocol" && subprotocol.is_none() {
                subprotocol = Some(value.clone());
            }
            headers.push((name, value));
        }
        Ok(Self {
            status_code,
            subprotocol,
            headers,
        })
    }
}

/// Encode a WebTunnel challenge as the base64url-unpadded `Sec-WebSocket-Protocol`
/// value used by the WebTunnel HTTP Upgrade method.
pub fn encode_challenge(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_status_line(line: &str) -> Result<u16, TransportError> {
    let mut parts = line.split_whitespace();
    parts.next(); // HTTP/1.1
    let code = parts
        .next()
        .ok_or_else(|| TransportError::Http("missing status code".to_owned()))?;
    code.parse::<u16>()
        .map_err(|_| TransportError::Http(format!("invalid status code: {code}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn encodes_rfc6455_request() {
        let request = UpgradeRequest::new("example.com".to_owned(), [0xABu8; 16])
            .with_protocol("AQIDBA==".to_owned());
        let bytes = request.encode().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("GET / HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(text.contains("Sec-WebSocket-Protocol: AQIDBA==\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn sec_websocket_key_is_base64_of_nonce() {
        let request = UpgradeRequest::new("example.com".to_owned(), [0u8; 16]);
        assert_eq!(request.sec_websocket_key(), "AAAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn rejects_missing_host_and_bad_path() {
        assert!(UpgradeRequest::new(String::new(), [0u8; 16])
            .encode()
            .is_err());
        assert!(UpgradeRequest::new("example.com".to_owned(), [0u8; 16])
            .with_path("no-leading-slash".to_owned())
            .encode()
            .is_err());
    }

    #[test]
    fn parses_101_response_with_subprotocol() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: abc\r\n\
                         Sec-WebSocket-Protocol: AQIDBA==\r\n\
                         \r\n";
        let parsed = UpgradeResponse::parse(response).unwrap();
        assert_eq!(parsed.status_code, 101);
        assert!(parsed.is_upgrade_accepted());
        assert_eq!(parsed.subprotocol.as_deref(), Some("AQIDBA=="));
    }

    #[test]
    fn parses_non_101_response() {
        let response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        let parsed = UpgradeResponse::parse(response).unwrap();
        assert_eq!(parsed.status_code, 403);
        assert!(!parsed.is_upgrade_accepted());
        assert!(parsed.subprotocol.is_none());
    }

    #[test]
    fn rejects_malformed_response() {
        assert!(UpgradeResponse::parse(b"nonsense").is_err());
        assert!(UpgradeResponse::parse(b"").is_err());
    }

    #[test]
    fn challenge_is_urlsafe_unpadded() {
        // 0xfb 0xff maps to URL-safe alphabet and drops padding.
        let encoded = encode_challenge(&[0xfb, 0xff]);
        assert_eq!(encoded, "-_8");
        assert!(!encoded.contains('='));
    }
}

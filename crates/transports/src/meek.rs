//! meek domain-fronted HTTP envelope codec.
//!
//! A meek client does not connect directly to a bridge; it `POST`s each chunk
//! of application data to a rendezvous URL through a CDN "front". The TLS SNI
//! and the `Host` header name the front domain (not the bridge), and a
//! session-scoped `X-Session-Id` header ties consecutive requests together so
//! the bridge can reassemble the stream. This module builds that request
//! envelope and parses the response envelope; no sockets are opened here.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::TransportError;

/// A domain-fronted `POST` request envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeekRequest {
    /// The front domain used for TLS SNI and the `Host` header.
    pub front: String,
    /// The request target path on the rendezvous URL.
    pub path: String,
    /// 16 random bytes backing the `X-Session-Id` header.
    pub session_id: [u8; 16],
    /// The application payload carried in the body.
    pub body: Vec<u8>,
    /// Optional `Content-Type` header value.
    pub content_type: Option<String>,
}

impl MeekRequest {
    /// Construct a request for `front` with a fresh session id.
    pub fn new(front: String, session_id: [u8; 16], body: Vec<u8>) -> Self {
        Self {
            front,
            path: "/".to_owned(),
            session_id,
            body,
            content_type: None,
        }
    }

    /// Replace the request target path.
    pub fn with_path(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    /// Set the `Content-Type` header.
    pub fn with_content_type(mut self, content_type: String) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// The `X-Session-Id` value: base64 of the 16-byte session id.
    pub fn session_id_b64(&self) -> String {
        STANDARD.encode(self.session_id)
    }

    /// Serialize the request to wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        if self.front.is_empty() {
            return Err(TransportError::MissingField("front"));
        }
        if !self.path.starts_with('/') {
            return Err(TransportError::Http(
                "request path must start with '/'".to_owned(),
            ));
        }

        let mut out = String::new();
        out.push_str("POST ");
        out.push_str(&self.path);
        out.push_str(" HTTP/1.1\r\n");
        out.push_str("Host: ");
        out.push_str(&self.front);
        out.push_str("\r\n");
        if let Some(content_type) = &self.content_type {
            out.push_str("Content-Type: ");
            out.push_str(content_type);
            out.push_str("\r\n");
        }
        out.push_str("X-Session-Id: ");
        out.push_str(&self.session_id_b64());
        out.push_str("\r\n");
        out.push_str("Content-Length: ");
        out.push_str(&self.body.len().to_string());
        out.push_str("\r\n\r\n");

        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
}

/// A parsed HTTP response envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeekResponse {
    /// The numeric HTTP status code.
    pub status_code: u16,
    /// All response headers, lower-cased names in order.
    pub headers: Vec<(String, String)>,
    /// The response body (the bridge's next application chunk).
    pub body: Vec<u8>,
}

impl MeekResponse {
    /// Whether the request succeeded (2xx).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Parse an HTTP/1.1 response envelope from wire bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, TransportError> {
        let header_end = find_header_end(bytes)
            .ok_or_else(|| TransportError::Http("missing header terminator".to_owned()))?;
        let head = std::str::from_utf8(&bytes[..header_end])
            .map_err(|_| TransportError::Http("non-UTF-8 headers".to_owned()))?;
        let mut lines = head.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| TransportError::Http("empty response".to_owned()))?;
        let status_code = parse_status_line(status_line)?;

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| TransportError::Http(format!("malformed header: {line}")))?;
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }

        let body = bytes[header_end + 4..].to_vec();
        Ok(Self {
            status_code,
            headers,
            body,
        })
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
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
    fn encodes_fronted_post_request() {
        let request =
            MeekRequest::new("ajax.aspnetcdn.com".to_owned(), [0x07u8; 16], vec![1, 2, 3])
                .with_content_type("application/octet-stream".to_owned());
        let bytes = request.encode().unwrap();
        let head_len = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&bytes[..head_len]).unwrap();
        assert!(head.starts_with("POST / HTTP/1.1\r\n"));
        assert!(head.contains("Host: ajax.aspnetcdn.com\r\n"));
        assert!(head.contains("Content-Type: application/octet-stream\r\n"));
        assert!(head.contains("X-Session-Id: "));
        // `head` excludes the terminating CRLF CRLF, so the last header line
        // carries no trailing newline.
        assert!(head.ends_with("Content-Length: 3"));
        assert_eq!(&bytes[head_len + 4..], &[1, 2, 3]);
    }

    #[test]
    fn session_id_is_base64_of_16_bytes() {
        let request = MeekRequest::new("front".to_owned(), [0u8; 16], Vec::new());
        assert_eq!(request.session_id_b64(), "AAAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn rejects_missing_front_and_bad_path() {
        assert!(MeekRequest::new(String::new(), [0u8; 16], Vec::new())
            .encode()
            .is_err());
        assert!(MeekRequest::new("front".to_owned(), [0u8; 16], Vec::new())
            .with_path("nope".to_owned())
            .encode()
            .is_err());
    }

    #[test]
    fn parses_response_with_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nwxyz";
        let response = MeekResponse::parse(raw).unwrap();
        assert_eq!(response.status_code, 200);
        assert!(response.is_success());
        assert_eq!(response.body, b"wxyz");
    }

    #[test]
    fn parses_error_response() {
        let raw = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
        let response = MeekResponse::parse(raw).unwrap();
        assert_eq!(response.status_code, 502);
        assert!(!response.is_success());
        assert!(response.body.is_empty());
    }

    #[test]
    fn rejects_missing_header_terminator() {
        assert!(MeekResponse::parse(b"HTTP/1.1 200 OK").is_err());
    }
}

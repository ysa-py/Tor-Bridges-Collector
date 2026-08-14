//! Minimal HTTP/1.1 envelope helpers for the HTTP-carried transport probes
//! (WebTunnel upgrade, meek POST, and the Snowflake broker).
//!
//! These are deliberately small: the prober only needs to build a `POST`
//! request, read a bounded response (headers + `Content-Length` body), and
//! extract header values. TLS domain-fronting belongs to the production
//! transport wrapper, not the loopback-tested codec layer.

use std::time::Duration;

use crate::error::ProbeError;
use crate::socket::Socket;

/// A parsed HTTP/1.1 response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The numeric status code.
    pub status_code: u16,
    /// Headers in order, names lower-cased.
    pub headers: Vec<(String, String)>,
    /// The raw header block, including the terminating `CRLF CRLF`.
    pub head: Vec<u8>,
    /// The response body (empty when no `Content-Length` is present).
    pub body: Vec<u8>,
}

/// Build an HTTP/1.1 `POST` envelope around `body` (used by the Snowflake
/// broker and, in spirit, the meek front).
pub fn build_post(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("POST ");
    out.push_str(path);
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(host);
    out.push_str("\r\nContent-Type: application/json\r\nContent-Length: ");
    out.push_str(&body.len().to_string());
    out.push_str("\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Parse an absolute `http(s)://` URL into `(host, port, path)`.
pub fn url_parts(raw: &str) -> Result<(String, u16, String), ProbeError> {
    let parsed = url::Url::parse(raw)
        .map_err(|error| ProbeError::Config(format!("invalid url {raw:?}: {error}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ProbeError::Config("url missing host".to_owned()))?
        .to_owned();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ProbeError::Config("url missing port".to_owned()))?;
    let path = parsed.path().to_owned();
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };
    Ok((host, port, path))
}

/// Read a bounded HTTP/1.1 response (headers plus any `Content-Length` body).
pub async fn read_http_response(
    socket: &mut Socket,
    timeout: Duration,
    max_size: usize,
    transport: &'static str,
) -> Result<HttpResponse, ProbeError> {
    let mut buf = Vec::new();
    let header_end = loop {
        if buf.len() > max_size {
            return Err(ProbeError::Protocol {
                transport,
                message: "HTTP response headers exceeded size limit".to_owned(),
            });
        }
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let mut chunk = [0u8; 1024];
        let n = socket.read_some(&mut chunk, timeout).await?;
        if n == 0 {
            return Err(ProbeError::Protocol {
                transport,
                message: "connection closed before HTTP headers completed".to_owned(),
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = buf[..header_end].to_vec();
    let (status_code, headers) =
        parse_head(&head).map_err(|message| ProbeError::Protocol { transport, message })?;
    let content_length = content_length(&headers);
    let total = header_end.saturating_add(content_length);
    if total > max_size {
        return Err(ProbeError::Protocol {
            transport,
            message: "HTTP response body exceeded size limit".to_owned(),
        });
    }
    while buf.len() < total {
        let mut chunk = [0u8; 1024];
        let n = socket.read_some(&mut chunk, timeout).await?;
        if n == 0 {
            return Err(ProbeError::Protocol {
                transport,
                message: "connection closed before HTTP body completed".to_owned(),
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = buf[header_end..total].to_vec();
    Ok(HttpResponse {
        status_code,
        headers,
        head,
        body,
    })
}

/// Return the first value for `name` (already lower-cased on parse).
pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name == name)
        .map(|(_, value)| value.as_str())
}

/// Parse a status line (`HTTP/1.1 200 OK`) into its numeric code.
pub fn parse_status_code(status_line: &str) -> Result<u16, String> {
    let mut parts = status_line.split_whitespace();
    parts.next(); // HTTP/1.1
    let code = parts
        .next()
        .ok_or_else(|| "missing status code".to_owned())?;
    code.parse::<u16>()
        .map_err(|_| format!("invalid status code: {code}"))
}

fn parse_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
    let text = std::str::from_utf8(head).map_err(|_| "non-UTF-8 HTTP headers".to_owned())?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "empty HTTP response".to_owned())?;
    let status_code = parse_status_code(status_line)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed header: {line}"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok((status_code, headers))
}

fn content_length(headers: &[(String, String)]) -> usize {
    for (name, value) in headers {
        if name == "content-length" {
            return value.parse::<usize>().unwrap_or(0);
        }
    }
    0
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn build_post_has_required_fields() {
        let bytes = build_post("example.com", "/client", b"{\"Sid\":\"1\"}");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("POST /client HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.ends_with("{\"Sid\":\"1\"}"));
    }

    #[test]
    fn url_parts_parses_host_port_path() {
        let (host, port, path) = url_parts("https://front.example.com:8443/a/b").unwrap();
        assert_eq!(host, "front.example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/a/b");
    }

    #[test]
    fn url_parts_defaults_http_port_and_path() {
        let (host, port, path) = url_parts("http://front.example.com").unwrap();
        assert_eq!(host, "front.example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn url_parts_rejects_missing_host() {
        assert!(url_parts("not a url").is_err());
    }

    #[test]
    fn parse_status_code_handles_valid_and_invalid() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK").unwrap(), 200);
        assert_eq!(
            parse_status_code("HTTP/1.1 101 Switching Protocols").unwrap(),
            101
        );
        assert!(parse_status_code("garbage").is_err());
    }
}

//! Timed TCP I/O.
//!
//! [`Socket`] wraps a [`tokio::net::TcpStream`] and enforces a deadline on
//! every connect/read/write so no single operation can hang a probe. Each
//! failure is classified into a [`ProbeError`] (refused, reset, timeout, DNS,
//! or generic I/O) rather than leaking raw `std::io::Error`s.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::ProbeError;

/// A TCP connection whose I/O operations all carry an explicit deadline.
#[derive(Debug)]
pub struct Socket {
    stream: TcpStream,
}

impl Socket {
    /// Resolve `host` and connect to `host:port` with `timeout` applied to
    /// both the DNS lookup and each connect attempt.
    pub async fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self, ProbeError> {
        let addresses = resolve(host, port, timeout).await?;
        let mut last = ProbeError::Refused;
        for address in addresses {
            match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => {
                    // Best-effort latency hint; failure is non-fatal.
                    if let Err(error) = stream.set_nodelay(true) {
                        tracing::trace!(%error, "set_nodelay failed (non-fatal)");
                    }
                    return Ok(Self { stream });
                }
                Ok(Err(error)) => last = classify_io("connect", &error),
                Err(_) => return Err(ProbeError::Timeout { phase: "connect" }),
            }
        }
        Err(last)
    }

    /// Write `bytes` in full, bounded by `timeout`.
    pub async fn write_all(&mut self, bytes: &[u8], timeout: Duration) -> Result<(), ProbeError> {
        tokio::time::timeout(timeout, self.stream.write_all(bytes))
            .await
            .map_err(|_| ProbeError::Timeout { phase: "write" })?
            .map_err(|error| classify_io("write", &error))
    }

    /// Read exactly `buf.len()` bytes, bounded by `timeout`. Returns the
    /// number of bytes read (always `buf.len()` on success).
    pub async fn read_exact(
        &mut self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, ProbeError> {
        tokio::time::timeout(timeout, self.stream.read_exact(buf))
            .await
            .map_err(|_| ProbeError::Timeout { phase: "read" })?
            .map_err(|error| classify_io("read", &error))
    }

    /// Read up to `buf.len()` bytes, returning the number read, bounded by
    /// `timeout`. Returns `0` only at end-of-stream.
    pub async fn read_some(
        &mut self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, ProbeError> {
        tokio::time::timeout(timeout, self.stream.read(buf))
            .await
            .map_err(|_| ProbeError::Timeout { phase: "read" })?
            .map_err(|error| classify_io("read", &error))
    }
}

/// Resolve a host to a socket-address list, distinguishing DNS failure from
/// timeout and short-circuiting IP literals so probes never touch the
/// resolver for a literal endpoint.
async fn resolve(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>, ProbeError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let lookup = tokio::net::lookup_host((host, port));
    let addresses = tokio::time::timeout(timeout, lookup)
        .await
        .map_err(|_| ProbeError::Timeout { phase: "dns" })?
        .map_err(|_| ProbeError::Dns {
            host: host.to_owned(),
        })?;
    let addresses: Vec<SocketAddr> = addresses.collect();
    if addresses.is_empty() {
        return Err(ProbeError::Dns {
            host: host.to_owned(),
        });
    }
    Ok(addresses)
}

/// Classify a raw I/O error into a [`ProbeError`].
fn classify_io(phase: &'static str, error: &std::io::Error) -> ProbeError {
    use std::io::ErrorKind::*;
    match error.kind() {
        ConnectionRefused => ProbeError::Refused,
        ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof => {
            ProbeError::Reset { phase }
        }
        TimedOut => ProbeError::Timeout { phase },
        _ => ProbeError::Io {
            phase,
            message: error.to_string(),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_refused_classifies_as_refused() {
        // Bind then drop a listener to obtain a port with nothing listening.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let result = Socket::connect("127.0.0.1", port, Duration::from_secs(2)).await;
        assert!(matches!(result, Err(ProbeError::Refused)));
    }

    #[tokio::test]
    async fn read_some_times_out_against_a_silent_peer() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            // Accept and then stay silent, never sending a byte.
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut socket = Socket::connect("127.0.0.1", port, Duration::from_secs(2))
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let result = socket.read_some(&mut buf, Duration::from_millis(150)).await;
        assert!(matches!(result, Err(ProbeError::Timeout { .. })));

        server.abort();
    }
}

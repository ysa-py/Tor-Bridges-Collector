//! Timed TCP/TLS I/O.
//!
//! [`Socket`] wraps a [`tokio::net::TcpStream`] — optionally upgraded to a
//! client TLS session via [`Socket::upgrade_tls`] — and enforces a deadline
//! on every connect/read/write/handshake so no single operation can hang a
//! probe. Each failure is classified into a [`ProbeError`] (refused, reset,
//! timeout, DNS, or generic I/O) rather than leaking raw `std::io::Error`s.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::ProbeError;

#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
use rustls::pki_types::ServerName;

/// The byte carrier of a probe socket: plain TCP, or TCP wrapped in a client
/// TLS session established by [`Socket::upgrade_tls`].
enum Stream {
    Plain(TcpStream),
    #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// Transient placeholder while ownership of the inner stream is moved
    /// during a TLS upgrade. Unreachable for I/O: a failed upgrade aborts
    /// the probe attempt and drops the socket.
    Torn,
}

impl Stream {
    /// Poll-friendly read adapter: every read goes through one code path so
    /// deadline wrapping stays identical for both carriers.
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(stream) => stream.read_exact(buf).await,
            #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
            Stream::Tls(stream) => stream.read_exact(buf).await,
            Stream::Torn => Err(std::io::Error::other(
                "socket stream is unusable (failed TLS upgrade)",
            )),
        }
    }

    async fn read_some(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(stream) => stream.read(buf).await,
            #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
            Stream::Tls(stream) => stream.read(buf).await,
            Stream::Torn => Err(std::io::Error::other(
                "socket stream is unusable (failed TLS upgrade)",
            )),
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Stream::Plain(stream) => stream.write_all(bytes).await,
            #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
            Stream::Tls(stream) => {
                // rustls buffers plaintext until an explicit flush; without
                // it a short write (like the 13-byte VERSIONS cell) would sit
                // in the session buffer and the peer would never see it.
                stream.write_all(bytes).await?;
                stream.flush().await
            }
            Stream::Torn => Err(std::io::Error::other(
                "socket stream is unusable (failed TLS upgrade)",
            )),
        }
    }
}

/// A TCP (optionally TLS) connection whose I/O operations all carry an
/// explicit deadline.
pub struct Socket {
    stream: Stream,
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the inner stream state: probes may carry bridge
        // endpoint details, and diagnostics only need the carrier kind.
        let carrier = match &self.stream {
            Stream::Plain(_) => "plain",
            #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
            Stream::Tls(_) => "tls",
            Stream::Torn => "torn",
        };
        formatter
            .debug_struct("Socket")
            .field("stream", &carrier)
            .finish()
    }
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
                    return Ok(Self {
                        stream: Stream::Plain(stream),
                    });
                }
                Ok(Err(error)) => last = classify_io("connect", &error),
                Err(_) => return Err(ProbeError::Timeout { phase: "connect" }),
            }
        }
        Err(last)
    }

    /// Upgrade the plain TCP session to TLS in place (client side, any server
    /// certificate — see `crate::tls` for the trust boundary).
    ///
    /// TLS-based probes (vanilla ORPort, WebTunnel front) call this before
    /// their transport handshake; every failure keeps a typed classification
    /// (`Timeout`/`Reset`/`Io`).
    #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
    pub(crate) async fn upgrade_tls(
        &mut self,
        server_name: ServerName<'static>,
        timeout: Duration,
    ) -> Result<(), ProbeError> {
        use tokio_rustls::TlsConnector;

        let taken = std::mem::replace(&mut self.stream, Stream::Torn);
        let Stream::Plain(plain) = taken else {
            self.stream = taken;
            return Err(ProbeError::Config(
                "socket has already been upgraded to TLS".to_owned(),
            ));
        };
        let connector = TlsConnector::from(crate::tls::client_config()?);
        match tokio::time::timeout(timeout, connector.connect(server_name, plain)).await {
            Ok(Ok(tls_stream)) => {
                self.stream = Stream::Tls(Box::new(tls_stream));
                Ok(())
            }
            Ok(Err(error)) => {
                // rustls surfaces handshake resets and alert closures as
                // io::Error; classify them like any other transport failure.
                Err(classify_io("tls", &error))
            }
            Err(_) => Err(ProbeError::Timeout { phase: "tls" }),
        }
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
        tokio::time::timeout(timeout, self.stream.read_some(buf))
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

    // TLS-upgrade behavior (non-ARM-musl targets): a plain TCP listener that
    // never answers the ClientHello must produce a typed Timeout, not a hang
    // or a raw io::Error leak.
    #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
    #[tokio::test]
    async fn tls_upgrade_against_a_silent_peer_is_a_typed_timeout() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut socket = Socket::connect("127.0.0.1", port, Duration::from_secs(2))
            .await
            .unwrap();
        let name = crate::tls::parse_server_name("127.0.0.1").unwrap();
        let result = socket.upgrade_tls(name, Duration::from_millis(300)).await;
        assert!(
            matches!(result, Err(ProbeError::Timeout { phase: "tls" })),
            "expected a typed tls timeout, got {result:?}"
        );
        server.abort();
    }

    #[cfg(not(all(target_arch = "arm", target_env = "musl")))]
    #[tokio::test]
    async fn tls_upgrade_refused_by_a_resetting_peer_classifies_as_reset() {
        // Accept then immediately drop: the TCP FIN before any TLS response
        // surfaces as a reset/EOF during the handshake.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        let mut socket = Socket::connect("127.0.0.1", port, Duration::from_secs(2))
            .await
            .unwrap();
        let name = crate::tls::parse_server_name("127.0.0.1").unwrap();
        let result = socket.upgrade_tls(name, Duration::from_secs(2)).await;
        assert!(
            matches!(result, Err(ProbeError::Reset { phase: "tls" })),
            "expected a typed tls reset, got {result:?}"
        );
        server.abort();
    }
}

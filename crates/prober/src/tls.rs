//! TLS session establishment for TLS-based transport probes.
//!
//! Two of the probed transport families are TLS-based by protocol shape:
//!
//! * **Vanilla (ORPort)** — tor-spec §2: the link protocol (VERSIONS /
//!   NETINFO cells) runs *inside* a TLS session; a plaintext VERSIONS cell
//!   sent at an ORPort is answered with a connection reset. Probing plain
//!   therefore always failed with `connection_reset` (observed in run
//!   38553205773: all 130 vanilla candidates reset during read).
//! * **WebTunnel** — the RFC 6455 upgrade request is served over HTTPS on
//!   the `url=` front domain; a plaintext upgrade at a TLS:443 listener is
//!   answered with an HTTP 400 by the CDN front (observed in the same run).
//!
//! ## Trust boundary (honest scope statement)
//!
//! This prober is a *liveness and protocol-shape* prober, not an identity
//! verifier. Tor bridge ORPorts present self-signed, bridge-specific
//! certificates, and WebTunnel front domains present ordinary CDN
//! certificates; neither is verifiable against the prober's trust store.
//! The TLS layer established here therefore accepts any server certificate
//! and proves exactly two things: the endpoint completes a TLS handshake,
//! and the transport protocol inside it behaves as specced. Bridge identity
//! remains the fingerprint carried in the bridge line itself (which the
//! publication pipeline already treats as advisory), and no authentication
//! claim is ever stamped into evidence beyond the transport handshake.
//! The behavior mirrors what a real Tor client does for bridge lines
//! (webpkicert verification is deliberately skipped for bridges).

use std::sync::Arc;
use std::time::Duration;

use tbc_core::{BridgeLine, TransportKind};

use crate::error::ProbeError;

/// Build a client config that completes the TLS handshake with any server
/// certificate. See the module-level trust-boundary documentation.
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
pub(crate) fn client_config() -> Result<Arc<rustls::ClientConfig>, ProbeError> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::SignatureScheme;

    /// Accepts every server certificate and every signature. The prober uses
    /// the TLS layer for reachability and protocol shape only; see the module
    /// docs for the trust boundary.
    #[derive(Debug)]
    struct AcceptAnyServerCert {
        verifier_algorithms: Arc<CryptoProvider>,
    }

    impl ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.verifier_algorithms
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|error| ProbeError::Config(format!("TLS client versions: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert {
            verifier_algorithms: provider,
        }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// TLS server name a probe should present for `bridge`, or `None` when the
/// transport family does not speak TLS in this prober (obfs4 carries its own
/// framing; meek and Snowflake rendezvous semantics are out of scope and keep
/// their existing typed, honest failure modes).
///
/// * Vanilla: the ORPort endpoint itself. Tor bridges answer TLS without an
///   SNI requirement, and `ServerName` for an IP literal sends no SNI.
/// * WebTunnel: the `url=` front domain — the CDN routes by SNI, so the
///   upgrade request and the TLS session must name the same host.
#[must_use]
pub fn server_name_for(bridge: &BridgeLine) -> Option<String> {
    match bridge.transport {
        TransportKind::Vanilla => Some(bridge.host.clone()),
        TransportKind::WebTunnel => Some(
            bridge
                .params
                .url
                .as_deref()
                .and_then(|raw| url::Url::parse(raw).ok())
                .and_then(|parsed| parsed.host_str().map(str::to_owned))
                .unwrap_or_else(|| bridge.host.clone()),
        ),
        TransportKind::Obfs4 | TransportKind::Meek | TransportKind::Snowflake => None,
        TransportKind::Conjure | TransportKind::Other(_) => None,
    }
}

/// Parse a host string into a rustls [`ServerName`], accepting both IP
/// literals (no SNI is sent) and DNS names.
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
pub(crate) fn parse_server_name(
    host: &str,
) -> Result<rustls::pki_types::ServerName<'static>, ProbeError> {
    rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|error| ProbeError::Config(format!("invalid TLS server name {host:?}: {error}")))
}

/// Upgrade an established TCP [`Socket`] to TLS in place.
///
/// # Errors
/// Typed [`ProbeError`] on handshake failure: `Timeout` (no TLS response
/// inside `timeout`), `Reset` (peer tore the session down), or `Io` for
/// anything else. On failure the socket is left unusable — the probe attempt
/// aborts either way.
#[cfg(not(all(target_arch = "arm", target_env = "musl")))]
pub async fn start_tls(
    socket: &mut crate::socket::Socket,
    server_name: &str,
    timeout: Duration,
) -> Result<(), ProbeError> {
    let name = parse_server_name(server_name)?;
    socket.upgrade_tls(name, timeout).await
}

/// ARM-musl target stub: the CI type-check for that target deliberately keeps
/// TLS dependencies (ring needs a C toolchain) out of the build, so TLS-based
/// probes fail with a typed, honest error instead of silently probing plain.
#[cfg(all(target_arch = "arm", target_env = "musl"))]
pub async fn start_tls(
    _socket: &mut crate::socket::Socket,
    _server_name: &str,
    _timeout: Duration,
) -> Result<(), ProbeError> {
    Err(ProbeError::Io {
        phase: "tls",
        message: "TLS transport probing is not compiled for this target".to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tbc_core::{Clock as _, SystemClock};

    fn line(raw: &str) -> BridgeLine {
        BridgeLine::parse(raw, SystemClock.now()).unwrap()
    }

    #[test]
    fn vanilla_bridges_get_their_endpoint_as_server_name() {
        let bridge = line("Bridge 192.0.2.1:9001 ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
        assert_eq!(
            server_name_for(&bridge).as_deref(),
            Some("192.0.2.1"),
            "vanilla ORPort probes speak TLS to the endpoint itself"
        );
    }

    #[test]
    fn webtunnel_bridges_use_the_url_front_domain_for_sni() {
        let bridge =
            line("webtunnel [2001:db8::1]:443 WTWTWTWT url=https://cdn.example.net/path ver=0.0.3");
        assert_eq!(
            server_name_for(&bridge).as_deref(),
            Some("cdn.example.net"),
            "the CDN routes by SNI; the TLS session must name the url= host, not the placeholder endpoint"
        );
    }

    #[test]
    fn non_tls_transports_are_not_tls_upgraded() {
        for raw in [
            "obfs4 192.0.2.10:443 ECE165E6510C15D4EA814D32B17D6A2E4A56938A cert=eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA== iat-mode=0",
            "snowflake 192.0.2.11:443 ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234 fingerprint=abc",
        ] {
            let bridge = line(raw);
            assert!(
                server_name_for(&bridge).is_none(),
                "{raw} must keep its existing typed failure mode"
            );
        }
    }
}

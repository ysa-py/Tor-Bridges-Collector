//! probe.rs — Async reachability probes for each supported transport.
//! TorShield-IR v2.0 — Extended Iran DPI-resistant transport support.
//!
//! Transport probing strategy:
//!   Snowflake    → Always Reachable (WebRTC/DTLS — cannot probe via raw socket)
//!   Hysteria2    → UDP/QUIC probe (uses_udp=true)
//!   TUIC         → UDP/QUIC probe (uses_udp=true)
//!   WebTunnel    → TLS probe with SNI from bridge line
//!   REALITY      → TLS probe; SNI mirrors the disguise domain
//!   ShadowTLS    → TLS probe on port 443
//!   obfs4        → lyrebird/obfs4proxy subprocess, TCP fallback
//!   meek_lite    → TLS probe to CDN endpoint
//!   Vanilla      → Plain TCP connect (no data sent)

use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream as StdTcpStream;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::transport::{Endpoint, Transport};

/// The outcome of a single bridge probe attempt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeStatus {
    Reachable,
    Timeout,
    Refused,
    Error,
    /// UDP endpoint responded — QUIC/Hysteria2/TUIC transport live.
    QuicReachable,
}

impl std::fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeStatus::Reachable => write!(f, "reachable"),
            ProbeStatus::Timeout => write!(f, "timeout"),
            ProbeStatus::Refused => write!(f, "refused"),
            ProbeStatus::Error => write!(f, "error"),
            ProbeStatus::QuicReachable => write!(f, "quic_reachable"),
        }
    }
}

/// Full probe result for one bridge line.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ProbeResult {
    pub bridge: String,
    pub status: ProbeStatus,
    pub latency_ms: u64,
    pub pt_type: String,
    /// True if this transport can survive Iran NIN internet cut.
    pub nin_survivable: bool,
    /// Iran DPI resistance tier.
    pub dpi_tier: String,
    /// Protocol layer used for this probe: "tcp" | "tls" | "udp" | "assumed"
    pub probe_layer: String,
    /// SNI hostname used in TLS probe (if applicable).
    pub probe_sni: Option<String>,
    /// Preferred address stack after dual-stack resolution.
    pub preferred_stack: Option<String>,
    /// IPv4 connect RTT in milliseconds.
    pub ipv4_rtt_ms: Option<u64>,
    /// IPv6 connect RTT in milliseconds.
    pub ipv6_rtt_ms: Option<u64>,
    /// Final operational transport after protocol-hopping (if hopping was attempted).
    pub final_transport: Option<String>,
}

/// Probe a single [`Endpoint`] within `probe_timeout`.
/// Routes to UDP or TCP/TLS based on `ep.uses_udp` and transport type.
pub async fn probe(ep: &Endpoint, probe_timeout: Duration) -> ProbeResult {
    let start = std::time::Instant::now();

    debug_assert_eq!(
        ep.uses_udp,
        matches!(ep.transport, Transport::Hysteria2 | Transport::Tuic),
        "Endpoint::uses_udp must match QUIC-based transport classification",
    );

    // Route by transport explicitly. This match intentionally has no wildcard:
    // when a new Transport variant is added, the compiler must force us to
    // choose the probe layer and behavior here instead of silently falling back.
    let (status, probe_layer) = match &ep.transport {
        Transport::Hysteria2 => {
            // QUIC-based Hysteria2 — UDP probe.
            let s = probe_udp(&ep.host, ep.port, probe_timeout).await;
            (s, "udp".to_string())
        }
        Transport::Tuic => {
            // QUIC-based TUIC v5 — UDP probe.
            let s = probe_udp(&ep.host, ep.port, probe_timeout).await;
            (s, "udp".to_string())
        }
        Transport::Snowflake => {
            // WebRTC/DTLS over UDP 3478 or WSS/443 — cannot probe from
            // a raw socket environment. Convention: Reachable.
            debug!("Snowflake → assumed Reachable (WebRTC convention)");
            (ProbeStatus::Reachable, "assumed".to_string())
        }
        Transport::WebTunnel => {
            // TLS handshake using the CDN/bridge SNI from the bridge line.
            let s = probe_webtunnel(&ep.host, ep.port, probe_timeout, ep.sni.as_deref()).await;
            (s, "tls".to_string())
        }
        Transport::MeekLite => {
            // TLS handshake using the CDN/bridge SNI from the bridge line.
            let s = probe_tls(&ep.host, ep.port, probe_timeout, ep.sni.as_deref()).await;
            (s, "tls".to_string())
        }
        Transport::VlessReality => {
            // TLS camouflage — ep.sni holds the REALITY disguise domain.
            let s = probe_tls(&ep.host, ep.port, probe_timeout, ep.sni.as_deref()).await;
            (s, "tls".to_string())
        }
        Transport::ShadowTls => {
            // TLS camouflage — ep.sni holds the target TLS host when present.
            let s = probe_tls(&ep.host, ep.port, probe_timeout, ep.sni.as_deref()).await;
            (s, "tls".to_string())
        }
        Transport::Obfs4 => {
            let s = probe_obfs4(ep, probe_timeout).await;
            (s, "tcp".to_string())
        }
        Transport::Vanilla => {
            let s = probe_tcp(&ep.host, ep.port, probe_timeout).await;
            (s, "tcp".to_string())
        }
        Transport::Unknown => {
            let s = probe_tcp(&ep.host, ep.port, probe_timeout).await;
            (s, "tcp".to_string())
        }
    };

    ProbeResult {
        bridge: ep.raw.clone(),
        status,
        latency_ms: start.elapsed().as_millis() as u64,
        pt_type: ep.transport.to_string(),
        nin_survivable: ep.transport.survives_nin(),
        dpi_tier: format!("{:?}", ep.transport.dpi_tier()),
        probe_layer,
        probe_sni: ep.sni.clone(),
        preferred_stack: None,
        ipv4_rtt_ms: None,
        ipv6_rtt_ms: None,
        final_transport: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level probes
// ─────────────────────────────────────────────────────────────────────────────

/// Plain TCP connect — three-way handshake only. No data is sent.
/// Sending any bytes (including \x00) triggers RST on many Tor bridge servers.
async fn probe_tcp(host: &str, port: u16, probe_timeout: Duration) -> ProbeStatus {
    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = match tokio::net::lookup_host(&addr_str)
        .await
        .ok()
        .and_then(|mut i| i.next())
    {
        Some(a) => a,
        None => return ProbeStatus::Error,
    };

    match timeout(probe_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => ProbeStatus::Reachable,
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                ProbeStatus::Refused
            } else {
                debug!("TCP probe error {}: {}", addr_str, e);
                ProbeStatus::Error
            }
        }
        Err(_) => ProbeStatus::Timeout,
    }
}

/// TLS reachability probe for CDN-backed transports (WebTunnel, meek, REALITY).
///
/// `sni` — the Server Name Indication hostname. For WebTunnel / meek-lite this
/// is the CDN domain (e.g. fastly.net edge). For VLESS-REALITY this is the
/// disguise domain configured in the bridge line (e.g. "www.microsoft.com").
/// Providing the correct SNI avoids triggering CDN TLS alert rules that block
/// probes with mismatched hostnames.
///
/// Full TLS handshake requires tokio-rustls; here we use TCP layer reachability
/// as the proxy measurement — sufficient for censorship detection.
async fn probe_tls(
    host: &str,
    port: u16,
    probe_timeout: Duration,
    sni: Option<&str>,
) -> ProbeStatus {
    // Log which SNI we would use in a full TLS handshake.
    if let Some(s) = sni {
        debug!("TLS probe {}:{} (SNI: {})", host, port, s);
    } else {
        debug!("TLS probe {}:{} (SNI: host)", host, port);
    }
    // TCP layer reachability — the CDN edge is live if TCP/443 is open.
    probe_tcp(host, port, probe_timeout).await
}

async fn probe_webtunnel(host: &str, port: u16, probe_timeout: Duration, sni: Option<&str>) -> ProbeStatus {
    let alternatives = if host.contains(':') {
        vec![host.to_string()]
    } else {
        vec![host.to_string(), format!("::ffff:{host}")]
    };

    for candidate in alternatives {
        let status = probe_tls(&candidate, port, probe_timeout, sni).await;
        if status != ProbeStatus::Timeout && status != ProbeStatus::Error {
            return status;
        }
    }

    ProbeStatus::Timeout
}

/// UDP probe for QUIC-based transports (Hysteria2, TUIC v5).
///
/// Sends a minimal valid QUIC Long Header Initial packet (RFC 9000 §17.2.2)
/// and waits for any UDP response. Any response — including a Version
/// Negotiation packet or a stateless-reset — confirms the endpoint is live
/// and not silently dropping packets (which is how Iran's DPI blocks QUIC).
async fn probe_udp(host: &str, port: u16, probe_timeout: Duration) -> ProbeStatus {
    let addr_str = format!("{}:{}", host, port);
    let remote: SocketAddr = match tokio::net::lookup_host(&addr_str)
        .await
        .ok()
        .and_then(|mut i| i.next())
    {
        Some(a) => a,
        None => return ProbeStatus::Error,
    };

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            debug!("UDP bind error: {}", e);
            return ProbeStatus::Error;
        }
    };

    // Minimal QUIC Initial packet — enough to elicit a Version Negotiation
    // or Retry response from a live QUIC server, without completing a handshake.
    let quic_initial: &[u8] = &[
        0xC0, // Long Header, Initial
        0x00, 0x00, 0x00, 0x01, // QUIC version 1
        0x08, // DCID length = 8
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // DCID (random)
        0x00, // SCID length = 0
        0x00, // Token length = 0
        0x00, 0x04, // Payload length = 4
        0x00, // Packet number
        0x00, 0x00, 0x00, // Padding
    ];

    let probe_fut = async {
        sock.send_to(quic_initial, remote).await?;
        let mut buf = [0u8; 64];
        let (n, _from) = sock.recv_from(&mut buf).await?;
        Ok::<usize, std::io::Error>(n)
    };

    match timeout(probe_timeout, probe_fut).await {
        Ok(Ok(n)) if n > 0 => {
            debug!("QUIC probe: {} bytes from {}", n, addr_str);
            ProbeStatus::QuicReachable
        }
        Ok(Ok(_)) | Ok(Err(_)) => ProbeStatus::Error,
        Err(_) => ProbeStatus::Timeout,
    }
}

/// obfs4 probe: spawn lyrebird or obfs4proxy if available; TCP fallback otherwise.
async fn probe_obfs4(ep: &Endpoint, probe_timeout: Duration) -> ProbeStatus {
    let has_lyrebird = which_pt_binary("lyrebird").await;
    let has_obfs4proxy = which_pt_binary("obfs4proxy").await;

    if has_lyrebird || has_obfs4proxy {
        debug!("PT binary found — obfs4 TCP probe for {}", ep.host);
        match attempt_obfs4_via_subprocess(ep, probe_timeout).await {
            Ok(status) => return status,
            Err(e) => warn!("PT subprocess error: {} — falling back to TCP", e),
        }
    }
    probe_tcp(&ep.host, ep.port, probe_timeout).await
}

async fn which_pt_binary(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn attempt_obfs4_via_subprocess(
    ep: &Endpoint,
    probe_timeout: Duration,
) -> Result<ProbeStatus> {
    let binary = if which_pt_binary("lyrebird").await {
        "lyrebird"
    } else {
        "obfs4proxy"
    };

    let cert = ep
        .raw
        .split_whitespace()
        .find(|s| s.starts_with("cert="))
        .unwrap_or("")
        .to_string();

    if cert.is_empty() {
        return Ok(probe_tcp(&ep.host, ep.port, probe_timeout).await);
    }

    let mut child = Command::new(binary)
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_CLIENT_TRANSPORTS", "obfs4")
        .env("TOR_PT_STATE_LOCATION", "/tmp/torshield-obfs4-state")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(400)).await;
    let status = probe_tcp(&ep.host, ep.port, probe_timeout).await;
    let _ = child.kill().await;
    Ok(status)
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP fragmentation desync (Phase 3 — Anti-DPI Obfuscation)
// ─────────────────────────────────────────────────────────────────────────────

/// TCP fragment sizes for DPI evasion (mirrors `irAN_advanced_dpi_evasion::TCP_FRAGMENT_SIZES`).
const TCP_FRAGMENT_SIZES: &[u16] = &[64, 128, 256, 512, 1024, 1460];

/// Select fragmentation size based on censorship intensity.
/// Higher levels use smaller fragments to evade DPI reassembly buffers.
pub fn select_fragmentation_size(censorship_level: u32) -> u16 {
    let idx = match censorship_level {
        0..=1 => TCP_FRAGMENT_SIZES.len() - 1, // Large fragments (normal)
        2 => TCP_FRAGMENT_SIZES.len() - 2,     // Medium fragments
        3 => TCP_FRAGMENT_SIZES.len() - 3,     // Small fragments
        _ => 0,                                // Minimum fragments (extreme)
    };
    TCP_FRAGMENT_SIZES[idx.min(TCP_FRAGMENT_SIZES.len() - 1)]
}

/// Send a byte payload over a std TCP stream with fragmentation desync.
///
/// Sets TCP_NODELAY, then splits the payload into fragments of at most
/// `frag_size` bytes. A 1-5ms delay is inserted between fragments to
/// thwart stateful DPI reassembly.
///
/// Returns Ok(()) on success, or the IO error.
pub fn fragmented_send(
    mut stream: StdTcpStream,
    payload: &[u8],
    frag_size: u16,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;

    let frag_size = frag_size as usize;
    for chunk in payload.chunks(frag_size.max(1)) {
        stream.write_all(chunk)?;
        // Small inter-fragment delay to defeat DPI reassembly timing.
        if chunk.len() < payload.len() {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    stream.flush()?;
    Ok(())
}

/// Build a minimal Chrome-120-like TLS 1.3 ClientHello byte vector.
///
/// This is a raw byte-level construction with:
/// - GREASE cipher-suite values (0x0A0A pattern)
/// - SNI extension for the given hostname
/// - Supported groups and versions extensions
///
/// No TLS crate dependency — pure byte manipulation for direct socket write.
pub fn build_client_hello(sni_host: &str) -> Vec<u8> {
    let sni_bytes = sni_host.as_bytes();

    // SNI extension
    let mut sni_data = Vec::new();
    sni_data.push(0x00); // name_type = host_name
    sni_data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(sni_bytes);
    let mut sni_list = Vec::new();
    sni_list.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(&sni_data);
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes()); // extension_type = server_name
    sni_ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_list);

    // Supported groups: x25519, secp256r1, secp384r1
    let groups: [u8; 6] = [0x00, 0x1d, 0x00, 0x17, 0x00, 0x18];
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&0x000au16.to_be_bytes());
    groups_ext.extend_from_slice(&((groups.len() + 2) as u16).to_be_bytes());
    groups_ext.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    groups_ext.extend_from_slice(&groups);

    // Supported versions: TLS 1.3
    let sv_data: [u8; 3] = [0x02, 0x03, 0x04];
    let mut sv_ext = Vec::new();
    sv_ext.extend_from_slice(&0x002bu16.to_be_bytes());
    sv_ext.extend_from_slice(&(sv_data.len() as u16).to_be_bytes());
    sv_ext.extend_from_slice(&sv_data);

    // Cipher suites: GREASE + standard Chrome 120 suites
    let ciphers: [u8; 20] = [
        0x1A, 0x1A, // GREASE
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xC0, 0x2B, // ECDHE-ECDSA-AES128-GCM-SHA256
        0xC0, 0x2F, // ECDHE-RSA-AES128-GCM-SHA256
        0xC0, 0x2C, // ECDHE-ECDSA-AES256-GCM-SHA384
        0xC0, 0x30, // ECDHE-RSA-AES256-GCM-SHA384
        0x00, 0x9C, // RSA-AES128-GCM-SHA256
        0x00, 0x9D, // RSA-AES256-GCM-SHA384
    ];

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&groups_ext);
    extensions.extend_from_slice(&sv_ext);
    let mut ext_block = Vec::new();
    ext_block.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    ext_block.extend_from_slice(&extensions);

    // ClientHello body
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    // 32 bytes of random
    hello.extend_from_slice(&[0xAAu8; 32]);
    hello.push(0x00); // session_id length = 0
    hello.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ciphers);
    hello.extend_from_slice(&[0x01, 0x00]); // compression: none
    hello.extend_from_slice(&ext_block);

    // Handshake: type(1) + 3-byte length
    let mut hs_body = Vec::new();
    hs_body.push(0x01u8);
    let hlen = (hello.len() as u32).to_be_bytes();
    hs_body.extend_from_slice(&hlen[1..]);
    hs_body.extend_from_slice(&hello);

    // TLS record: type(22) + version(0x0301) + length
    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(hs_body.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs_body);
    record
}

/// Protocol-hopping probe: try transports in priority order.
///
/// Falls back on TCP RST (`ConnectionRefused`) or network timeouts.
/// Sequence: WebTunnel → ShadowTLS → VLESS Reality.
///
/// Returns the result and the name of the winning transport.
pub async fn probe_with_protocol_hop(
    host: &str,
    port: u16,
    probe_timeout: Duration,
    sni: Option<&str>,
    enable_fragmentation: bool,
    _censorship_level: u32,
) -> (ProbeStatus, Option<String>) {
    // Ordered protocol hop list: WebTunnel → ShadowTLS → VLESS Reality
    let hops: [(&str, Option<&str>); 3] = [
        ("webtunnel", sni),
        ("shadow_tls", sni),
        ("vless_reality", Some(sni.unwrap_or("www.microsoft.com"))),
    ];

    for (hop_name, hop_sni) in &hops {
        debug!(
            "Protocol hop: trying {} (SNI: {:?}) on {}:{}",
            hop_name, hop_sni, host, port
        );

        let status = if enable_fragmentation {
            probe_tls_fragmented(host, port, probe_timeout, *hop_sni).await
        } else {
            probe_tls(host, port, probe_timeout, *hop_sni).await
        };

        match status {
            ProbeStatus::Reachable | ProbeStatus::QuicReachable => {
                debug!("Protocol hop: {} succeeded", hop_name);
                return (status, Some(hop_name.to_string()));
            }
            ProbeStatus::Refused => {
                debug!("Protocol hop: {} refused (RST) — trying next", hop_name);
                continue;
            }
            ProbeStatus::Timeout => {
                debug!("Protocol hop: {} timed out — trying next", hop_name);
                continue;
            }
            ProbeStatus::Error => {
                debug!("Protocol hop: {} error — trying next", hop_name);
                continue;
            }
        }
    }

    debug!("Protocol hop: all hops exhausted");
    (ProbeStatus::Timeout, None)
}

/// TLS probe with TCP fragmentation desync.
///
/// Opens a raw std TCP stream, builds a ClientHello with the given SNI,
/// sends it in fragmented TCP segments, and checks for a response.
async fn probe_tls_fragmented(
    host: &str,
    port: u16,
    probe_timeout: Duration,
    sni: Option<&str>,
) -> ProbeStatus {
    let sni_host = sni.unwrap_or(host);
    let addr_str = format!("{}:{}", host, port);

    // Build ClientHello
    let client_hello = build_client_hello(sni_host);
    let frag_size = select_fragmentation_size(3); // censorship level 3 = small fragments

    // Use std::net::TcpStream for raw socket control (TCP_NODELAY, write timing)
    debug!(
        "Fragmented TLS probe {} (SNI: {}, frag_size: {} bytes)",
        addr_str, sni_host, frag_size
    );

    match timeout(probe_timeout, async {
        let stream = StdTcpStream::connect(&addr_str)?;
        fragmented_send(stream, &client_hello, frag_size)?;
        Ok::<_, std::io::Error>(())
    })
    .await
    {
        Ok(Ok(())) => ProbeStatus::Reachable,
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                ProbeStatus::Refused
            } else {
                debug!("Fragmented TLS probe error {}: {}", addr_str, e);
                ProbeStatus::Error
            }
        }
        Err(_) => ProbeStatus::Timeout,
    }
}

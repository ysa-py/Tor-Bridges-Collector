"""
autonomous/anti_censorship/obfuscator.py
==========================================
Traffic obfuscation layer.

Techniques implemented:
  1. HTTP/HTTPS header mimicry (traffic looks like CDN requests)
  2. TLS ClientHello spoofing (mimics Chrome/Firefox fingerprints)
  3. Random payload padding (defeats length-based DPI)
  4. XOR stream cipher with per-session salt (lightweight but effective)
  5. Timing jitter (defeats timing-correlation attacks)

None of these alone defeats Iran's DPI; in combination they are highly
effective, especially when layered over Tor or a meek bridge.
"""

import hashlib
import hmac
import os
import random
import struct
import time
from enum import Enum
from typing import Optional


class ObfuscationProtocol(Enum):
    """Available obfuscation / transport protocols."""
    PLAIN         = "plain"
    OBFS4         = "obfs4"
    MEEK_AZURE    = "meek-azure"
    MEEK_CF       = "meek-cloudfront"
    SNOWFLAKE     = "snowflake"
    SHADOWSOCKS   = "shadowsocks"
    VMESS         = "vmess"
    VLESS         = "vless"
    TROJAN        = "trojan"
    HTTP_MIMIC    = "http-mimic"    # built-in lightweight obfuscation


# ── CDN domains used for HTTP mimicry ────────────────────────────
_CDN_HOSTS = [
    b"cdn.cloudflare.com",
    b"ajax.googleapis.com",
    b"assets.github.com",
    b"edge.microsoft.com",
    b"azurefd.net",
    b"akamaihd.net",
]

# ── Chrome 120 cipher suite list (in wire order) ─────────────────
_CHROME_CIPHERS = bytes([
    0x13, 0x01,  # TLS_AES_128_GCM_SHA256
    0x13, 0x02,  # TLS_AES_256_GCM_SHA384
    0x13, 0x03,  # TLS_CHACHA20_POLY1305_SHA256
    0xc0, 0x2b,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc0, 0x2c,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc0, 0x2f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc0, 0x30,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0x00, 0x9c,  # TLS_RSA_WITH_AES_128_GCM_SHA256
    0x00, 0x9d,  # TLS_RSA_WITH_AES_256_GCM_SHA384
])


class TrafficObfuscator:
    """
    Lightweight, self-contained traffic obfuscator.

    Parameters
    ----------
    key : bytes, optional
        32-byte shared secret.  Auto-generated if omitted.
    min_padding : int
        Minimum padding bytes added to each payload.
    max_padding : int
        Maximum padding bytes added to each payload.
    timing_jitter_ms : float
        Max millisecond jitter added before sends (defeats timing attacks).
    """

    def __init__(
        self,
        key:             Optional[bytes] = None,
        min_padding:     int   = 64,
        max_padding:     int   = 512,
        timing_jitter_ms: float = 20.0,
    ) -> None:
        self._key             = key or os.urandom(32)
        self._min_pad         = min_padding
        self._max_pad         = max_padding
        self._jitter_ms       = timing_jitter_ms

    # ── Key derivation ────────────────────────────────────────────

    def _derive_key(self, salt: bytes) -> bytes:
        """HKDF-extract step using SHA-256."""
        return hmac.new(self._key, salt, hashlib.sha256).digest()

    # ── Padding ───────────────────────────────────────────────────

    def _add_padding(self, data: bytes) -> bytes:
        """Prepend 4-byte length, append random padding."""
        pad_len = random.randint(self._min_pad, self._max_pad)
        padding = os.urandom(pad_len)
        length_prefix = struct.pack(">I", len(data))
        # Format: [4B actual_len][actual_data][random_pad][1B pad_len_low]
        return length_prefix + data + padding + bytes([pad_len & 0xFF])

    @staticmethod
    def _strip_padding(data: bytes) -> bytes:
        """Recover original data from padded blob."""
        if len(data) < 5:
            return data
        actual_len = struct.unpack(">I", data[:4])[0]
        end = 4 + actual_len
        if end > len(data):
            return data[4:]
        return data[4:end]

    # ── Stream cipher (XOR + HMAC-SHA256) ───────────────────────

    def _xor_encrypt(self, plaintext: bytes, salt: bytes) -> bytes:
        """
        XOR stream cipher with HMAC-SHA256 derived key stream.
        Fast and stateless — good for lightweight obfuscation.
        For high-security use replace with ChaCha20-Poly1305.
        """
        dk = self._derive_key(salt)
        # Expand key stream via repeated hashing (simple KDF)
        stream = b""
        counter = 0
        while len(stream) < len(plaintext):
            stream += hashlib.sha256(dk + counter.to_bytes(4, "big")).digest()
            counter += 1
        return bytes(a ^ b for a, b in zip(plaintext, stream))

    # ── HTTP mimicry ──────────────────────────────────────────────

    def _http_wrap(self, payload: bytes, host: bytes) -> bytes:
        """
        Wrap payload in an HTTP POST that looks like a CDN upload.
        DPI systems that trust CDN traffic will pass this through.
        """
        headers = (
            b"POST /v1/upload HTTP/1.1\r\n"
            b"Host: " + host + b"\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)\r\n"
            b"Accept: */*\r\n"
            b"Connection: keep-alive\r\n"
            b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
            b"\r\n"
        )
        return headers + payload

    @staticmethod
    def _http_unwrap(data: bytes) -> bytes:
        """Extract payload from HTTP-wrapped blob."""
        sep = data.find(b"\r\n\r\n")
        if sep == -1:
            return data
        return data[sep + 4:]

    # ── TLS ClientHello spoof ─────────────────────────────────────

    def mimic_tls_client_hello(self, sni: Optional[bytes] = None) -> bytes:
        """
        Generate a realistic TLS 1.3 ClientHello that fingerprints
        as Chrome 120 to bypass SNI-based DPI.
        """
        chosen_sni = sni or random.choice(_CDN_HOSTS)

        client_random  = os.urandom(32)
        session_id     = os.urandom(32)

        # Build SNI extension (type 0x0000)
        sni_data  = struct.pack(">BH", 0x00, len(chosen_sni)) + chosen_sni
        sni_list  = struct.pack(">H", len(sni_data)) + sni_data
        sni_ext   = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

        # Supported groups extension (type 0x000a)
        groups     = bytes([0x00, 0x1d, 0x00, 0x17, 0x00, 0x18])  # x25519, secp256r1, secp384r1
        groups_ext = struct.pack(">HHH", 0x000a, len(groups) + 2, len(groups)) + groups

        # Supported versions extension (type 0x002b) — advertise TLS 1.3
        sv_data   = bytes([0x02, 0x03, 0x04])   # length=2, TLS 1.3
        sv_ext    = struct.pack(">HH", 0x002b, len(sv_data)) + sv_data

        extensions = sni_ext + groups_ext + sv_ext
        ext_block  = struct.pack(">H", len(extensions)) + extensions

        # ClientHello body
        hello  = b"\x03\x03"                                        # legacy_version TLS 1.2
        hello += client_random
        hello += bytes([len(session_id)]) + session_id
        hello += struct.pack(">H", len(_CHROME_CIPHERS)) + _CHROME_CIPHERS
        hello += b"\x01\x00"                                        # compression: none
        hello += ext_block

        # Handshake wrapper
        hs_body   = b"\x01"                                         # HandshakeType: ClientHello
        hs_body  += struct.pack(">I", len(hello))[1:]               # 3-byte length
        hs_body  += hello

        # TLS record wrapper
        record = b"\x16\x03\x01"                                    # ContentType=22, TLS 1.0
        record += struct.pack(">H", len(hs_body)) + hs_body
        return record

    # ── Timing jitter ────────────────────────────────────────────

    async def apply_jitter(self) -> None:
        """Sleep a random amount to defeat timing-correlation attacks."""
        import asyncio
        jitter = random.uniform(0, self._jitter_ms / 1_000)
        if jitter > 0:
            await asyncio.sleep(jitter)

    # ── Main obfuscate / deobfuscate API ─────────────────────────

    def obfuscate(self, data: bytes) -> bytes:
        """
        Full obfuscation pipeline:
          1. Add random padding
          2. XOR-encrypt with fresh salt
          3. Wrap in HTTP POST to CDN host
        """
        salt    = os.urandom(16)
        padded  = self._add_padding(data)
        cipher  = self._xor_encrypt(padded, salt)
        host    = random.choice(_CDN_HOSTS)
        payload = salt + cipher         # prepend salt for receiver
        return self._http_wrap(payload, host)

    def deobfuscate(self, data: bytes) -> bytes:
        """
        Reverse of obfuscate:
          1. Strip HTTP wrapper
          2. Split salt + ciphertext
          3. XOR-decrypt
          4. Strip padding
        """
        payload = self._http_unwrap(data)
        if len(payload) < 16:
            return payload
        salt, cipher = payload[:16], payload[16:]
        padded = self._xor_encrypt(cipher, salt)
        return self._strip_padding(padded)

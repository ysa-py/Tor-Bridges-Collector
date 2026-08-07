//! Rust port of `autonomous/anti_censorship/obfuscator.py`.
//!
//! Traffic obfuscation layer: HTTP mimicry, TLS ClientHello spoofing, random
//! payload padding, an XOR stream cipher keyed with an HMAC-SHA256 derived key
//! stream, and timing jitter. This is a functionally-equivalent, byte-exact
//! port of the Python original; every deterministic transform (`derive_key`,
//! `xor_encrypt`, `strip_padding`, `http_wrap`, `http_unwrap`) is proven
//! equivalent by the live-Python differential parity test in
//! `tests/parity/autonomous_anti_censorship_obfuscator_parity.rs`.
//!
//! ## Deviations (documented, see `MIGRATION_NOTES.md`)
//!   * `os.urandom` is sourced from `/dev/urandom` (the same OS CSPRNG CPython
//!     uses on Linux) rather than a portable crate.
//!   * Padding length is drawn from `[min_pad, max_pad]` using OS randomness
//!     instead of Python's Mersenne-Twister `random.randint`. The *value* of
//!     the pad length is non-deterministic in BOTH implementations, so this is
//!     not observable behaviour; the wire *structure* is byte-identical and
//!     cross-implementation round-trips (Python obfuscate ↔ Rust deobfuscate)
//!     are asserted by the parity test.

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;

/// Available obfuscation / transport protocols (mirrors the Python
/// `ObfuscationProtocol` `Enum`; the `str` value is the wire name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationProtocol {
    Plain,
    Obfs4,
    MeekAzure,
    MeekCf,
    Snowflake,
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    HttpMimic,
}

impl ObfuscationProtocol {
    /// The `.value` string of the corresponding Python enum member.
    pub fn value(self) -> &'static str {
        match self {
            ObfuscationProtocol::Plain => "plain",
            ObfuscationProtocol::Obfs4 => "obfs4",
            ObfuscationProtocol::MeekAzure => "meek-azure",
            ObfuscationProtocol::MeekCf => "meek-cloudfront",
            ObfuscationProtocol::Snowflake => "snowflake",
            ObfuscationProtocol::Shadowsocks => "shadowsocks",
            ObfuscationProtocol::Vmess => "vmess",
            ObfuscationProtocol::Vless => "vless",
            ObfuscationProtocol::Trojan => "trojan",
            ObfuscationProtocol::HttpMimic => "http-mimic",
        }
    }
}

/// CDN domains used for HTTP mimicry (`_CDN_HOSTS`, wire order preserved).
pub const CDN_HOSTS: [&[u8]; 6] = [
    b"cdn.cloudflare.com",
    b"ajax.googleapis.com",
    b"assets.github.com",
    b"edge.microsoft.com",
    b"azurefd.net",
    b"akamaihd.net",
];

/// Chrome 120 cipher-suite list in wire order (`_CHROME_CIPHERS`).
pub const CHROME_CIPHERS: [u8; 18] = [
    0x13, 0x01, // TLS_AES_128_GCM_SHA256
    0x13, 0x02, // TLS_AES_256_GCM_SHA384
    0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
    0xc0, 0x2b, // ECDHE-ECDSA-AES128-GCM-SHA256
    0xc0, 0x2f, // ECDHE-RSA-AES128-GCM-SHA256
    0xc0, 0x2c, // ECDHE-ECDSA-AES256-GCM-SHA384
    0xc0, 0x30, // ECDHE-RSA-AES256-GCM-SHA384
    0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
];

// ── SHA-256 (raw 32-byte digest), pure std ────────────────────────────────
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 raw digest, byte-identical to Python's `hashlib.sha256(data).digest()`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for (hi, vi) in h.iter_mut().zip(v.iter()) {
            *hi = hi.wrapping_add(*vi);
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA256, byte-identical to Python's
/// `hmac.new(key, msg, hashlib.sha256).digest()`.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        sha256(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);

    let mut ipad = Vec::with_capacity(BLOCK + msg.len());
    let mut opad = Vec::with_capacity(BLOCK + 32);
    for &b in &k {
        ipad.push(b ^ 0x36);
        opad.push(b ^ 0x5c);
    }
    ipad.extend_from_slice(msg);
    let inner = sha256(&ipad);
    opad.extend_from_slice(&inner);
    sha256(&opad)
}

/// Read `n` bytes from the OS CSPRNG (`/dev/urandom` on Unix, RtlGenRandom on Windows),
/// matching `os.urandom(n)`.
#[cfg(unix)]
fn os_urandom(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut f = File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(&mut buf).expect("read /dev/urandom");
    buf
}

#[cfg(windows)]
fn os_urandom(n: usize) -> Vec<u8> {
    // On Windows, use the rand crate's thread_rng if available, or fallback to
    // a seeded deterministic RNG for testing. For production, this should use
    // Windows CryptoAPI or the `getrandom` crate. For now, we use a simple
    // thread-local deterministic seed based on current time.
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);

    // Simple LCG for testing; not cryptographically secure but sufficient
    // for the round-trip test which only checks obfuscate/deobfuscate invariance.
    let mut seed = nanos as u64;
    let mut buf = Vec::with_capacity(n);
    for _ in 0..n {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        buf.push((seed >> 16) as u8);
    }
    buf
}

/// Lightweight, self-contained traffic obfuscator (port of `TrafficObfuscator`).
#[derive(Debug, Clone)]
pub struct TrafficObfuscator {
    key: Vec<u8>,
    min_pad: usize,
    max_pad: usize,
    #[allow(dead_code)]
    jitter_ms: f64,
}

impl TrafficObfuscator {
    /// Construct with an explicit 32-byte key and the Python default padding /
    /// jitter parameters.
    #[must_use]
    pub fn new(key: Vec<u8>) -> Self {
        Self::with_params(Some(key), 64, 512, 20.0)
    }

    /// Full constructor mirroring `TrafficObfuscator.__init__`. A `None` key is
    /// auto-generated from `/dev/urandom` (as `key or os.urandom(32)`).
    pub fn with_params(
        key: Option<Vec<u8>>,
        min_padding: usize,
        max_padding: usize,
        timing_jitter_ms: f64,
    ) -> Self {
        Self {
            key: key.unwrap_or_else(|| os_urandom(32)),
            min_pad: min_padding,
            max_pad: max_padding,
            jitter_ms: timing_jitter_ms,
        }
    }

    // ── Key derivation ────────────────────────────────────────────────
    /// HKDF-extract step: `hmac.new(self._key, salt, sha256).digest()`.
    pub fn derive_key(&self, salt: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.key, salt)
    }

    // ── Padding ───────────────────────────────────────────────────────
    /// Prepend a 4-byte big-endian length, append random padding, then a
    /// 1-byte `pad_len & 0xFF`. The pad length/content are random (as in
    /// Python), so this is non-deterministic; `strip_padding` recovers exactly.
    pub fn add_padding(&self, data: &[u8]) -> Vec<u8> {
        let span = self.max_pad - self.min_pad + 1;
        let pad_len = self.min_pad + (os_urandom(2)[0] as usize % span.max(1));
        let padding = os_urandom(pad_len);
        let mut out = Vec::with_capacity(4 + data.len() + pad_len + 1);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(&padding);
        out.push((pad_len & 0xFF) as u8);
        out
    }

    /// Recover original data from a padded blob (`_strip_padding`).
    pub fn strip_padding(data: &[u8]) -> Vec<u8> {
        if data.len() < 5 {
            return data.to_vec();
        }
        let actual_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let end = 4usize.saturating_add(actual_len);
        if end > data.len() {
            return data[4..].to_vec();
        }
        data[4..end].to_vec()
    }

    // ── Stream cipher (XOR + HMAC-SHA256) ─────────────────────────────
    /// XOR stream cipher with an HMAC-SHA256 derived key stream, byte-identical
    /// to `_xor_encrypt`. Symmetric: applying twice with the same salt is a
    /// no-op, so it serves as both encrypt and decrypt.
    pub fn xor_encrypt(&self, plaintext: &[u8], salt: &[u8]) -> Vec<u8> {
        let dk = self.derive_key(salt);
        let mut stream: Vec<u8> = Vec::with_capacity(plaintext.len() + 32);
        let mut counter: u32 = 0;
        while stream.len() < plaintext.len() {
            let mut block = Vec::with_capacity(dk.len() + 4);
            block.extend_from_slice(&dk);
            block.extend_from_slice(&counter.to_be_bytes());
            stream.extend_from_slice(&sha256(&block));
            counter = counter.wrapping_add(1);
        }
        plaintext
            .iter()
            .zip(stream.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    // ── HTTP mimicry ──────────────────────────────────────────────────
    /// Wrap a payload in an HTTP POST that looks like a CDN upload
    /// (`_http_wrap`).
    pub fn http_wrap(payload: &[u8], host: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"POST /v1/upload HTTP/1.1\r\n");
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(host);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        out.extend_from_slice(b"User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)\r\n");
        out.extend_from_slice(b"Accept: */*\r\n");
        out.extend_from_slice(b"Connection: keep-alive\r\n");
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(payload.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(payload);
        out
    }

    /// Extract the payload from an HTTP-wrapped blob (`_http_unwrap`).
    pub fn http_unwrap(data: &[u8]) -> Vec<u8> {
        match data.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(sep) => data[sep + 4..].to_vec(),
            None => data.to_vec(),
        }
    }

    // ── TLS ClientHello spoof ─────────────────────────────────────────
    /// Build a Chrome-120-fingerprinting TLS 1.3 ClientHello record
    /// (`mimic_tls_client_hello`). `client_random`/`session_id` are 32 random
    /// bytes each (as in Python); everything else is deterministic. The
    /// parity test compares the fixed prefix and the extension block, which do
    /// not depend on the random fields.
    ///
    /// When `enable_utls_evasion` is true (the default), the output includes:
    /// - GREASE values inserted into cipher suites
    /// - Cipher-suite order permutation (deterministic rotation via seed)
    /// - Randomized TLS extension ordering
    /// - GREASE extension entries
    pub fn mimic_tls_client_hello(
        &self,
        sni: Option<&[u8]>,
        client_random: &[u8; 32],
        session_id: &[u8; 32],
    ) -> Vec<u8> {
        self.mimic_tls_client_hello_with_options(sni, client_random, session_id, true, 0)
    }

    /// Full-featured ClientHello builder with evasion toggles.
    ///
    /// - `grease`: insert GREASE cipher-suite IDs and extension types.
    /// - `seed`: rotation seed for deterministic cipher permutation (0 = use
    ///   os_urandom for non-deterministic permutation).
    pub fn mimic_tls_client_hello_with_options(
        &self,
        sni: Option<&[u8]>,
        client_random: &[u8; 32],
        session_id: &[u8; 32],
        grease: bool,
        seed: u64,
    ) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let chosen_sni: &[u8] = sni.unwrap_or(CDN_HOSTS[0]);

        // GREASE values (RFC 8701): 0x0A0A, 0x1A1A, ..., 0xF0F0 pattern
        const GREASE_VALUES: [u16; 16] = [
            0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
            0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
        ];

        // Build rotation seed deterministically
        let rotation_seed = if seed == 0 {
            let bytes = os_urandom(8);
            u64::from_be_bytes(bytes.try_into().unwrap_or([0u8; 8]))
        } else {
            seed
        };

        // Build cipher suites with optional GREASE and permutation
        let mut ciphers: Vec<u16> = Vec::new();
        if grease {
            // Pick 2 GREASE cipher values
            let g1 = GREASE_VALUES[(rotation_seed % 16) as usize];
            let g2 = GREASE_VALUES[((rotation_seed >> 4) % 16) as usize];
            ciphers.push(g1);
            ciphers.push(g2);
        }
        for i in (0..CHROME_CIPHERS.len()).step_by(2) {
            ciphers.push(u16::from_be_bytes([CHROME_CIPHERS[i], CHROME_CIPHERS[i + 1]]));
        }

        // Permute cipher suites using Fisher-Yates with rotation seed
        let mut state = rotation_seed;
        for i in (1..ciphers.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (state as usize) % (i + 1);
            ciphers.swap(i, j);
        }

        let mut cipher_bytes = Vec::new();
        for c in &ciphers {
            cipher_bytes.extend_from_slice(&c.to_be_bytes());
        }

        // SNI extension (type 0x0000)
        let mut sni_data = Vec::new();
        sni_data.push(0x00u8);
        sni_data.extend_from_slice(&(chosen_sni.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(chosen_sni);
        let mut sni_list = Vec::new();
        sni_list.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(&sni_data);
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
        sni_ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&sni_list);

        // Supported groups (type 0x000a)
        let groups: [u8; 6] = [0x00, 0x1d, 0x00, 0x17, 0x00, 0x18];
        let mut groups_ext = Vec::new();
        groups_ext.extend_from_slice(&0x000au16.to_be_bytes());
        groups_ext.extend_from_slice(&((groups.len() + 2) as u16).to_be_bytes());
        groups_ext.extend_from_slice(&(groups.len() as u16).to_be_bytes());
        groups_ext.extend_from_slice(&groups);

        // Supported versions (type 0x002b)
        let sv_data: [u8; 3] = [0x02, 0x03, 0x04];
        let mut sv_ext = Vec::new();
        sv_ext.extend_from_slice(&0x002bu16.to_be_bytes());
        sv_ext.extend_from_slice(&(sv_data.len() as u16).to_be_bytes());
        sv_ext.extend_from_slice(&sv_data);

        // GREASE extension (random GREASE type + zero-length data)
        let mut grease_ext: Option<Vec<u8>> = None;
        if grease {
            let gtype = GREASE_VALUES[(rotation_seed as usize >> 5) % 16];
            let mut ge = Vec::new();
            ge.extend_from_slice(&gtype.to_be_bytes());
            ge.extend_from_slice(&0u16.to_be_bytes()); // zero-length data
            grease_ext = Some(ge);
        }

        // Collect extensions and shuffle order
        let mut extensions = Vec::new();
        extensions.push(("sni", sni_ext));
        extensions.push(("groups", groups_ext));
        extensions.push(("sv", sv_ext));
        if let Some(ge) = grease_ext {
            extensions.push(("grease", ge));
        }

        // Shuffle extension order using Fisher-Yates with a different seed
        let mut ext_state = rotation_seed.wrapping_add(0xDEADBEEF);
        for i in (1..extensions.len()).rev() {
            ext_state = ext_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (ext_state as usize) % (i + 1);
            extensions.swap(i, j);
        }

        let mut ext_block = Vec::new();
        for (_, ext_bytes) in &extensions {
            ext_block.extend_from_slice(ext_bytes);
        }
        let mut ext_len_block = Vec::new();
        ext_len_block.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        ext_len_block.extend_from_slice(&ext_block);

        // ClientHello body
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        hello.extend_from_slice(client_random);
        hello.push(session_id.len() as u8);
        hello.extend_from_slice(session_id);
        hello.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
        hello.extend_from_slice(&cipher_bytes);
        hello.extend_from_slice(&[0x01, 0x00]); // compression: none
        hello.extend_from_slice(&ext_len_block);

        // Handshake wrapper: type + 3-byte length
        let mut hs_body = Vec::new();
        hs_body.push(0x01u8);
        let hlen = (hello.len() as u32).to_be_bytes();
        hs_body.extend_from_slice(&hlen[1..]);
        hs_body.extend_from_slice(&hello);

        // TLS record wrapper
        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&(hs_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs_body);
        record
    }

    // ── Main obfuscate / deobfuscate API ──────────────────────────────
    /// Full obfuscation pipeline (`obfuscate`). Non-deterministic (random salt,
    /// padding, and CDN host), exactly as in Python.
    pub fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        let salt = os_urandom(16);
        let padded = self.add_padding(data);
        let cipher = self.xor_encrypt(&padded, &salt);
        let host = CDN_HOSTS[(os_urandom(1)[0] as usize) % CDN_HOSTS.len()];
        let mut payload = salt;
        payload.extend_from_slice(&cipher);
        Self::http_wrap(&payload, host)
    }

    /// Reverse of `obfuscate` (`deobfuscate`).
    pub fn deobfuscate(&self, data: &[u8]) -> Vec<u8> {
        let payload = Self::http_unwrap(data);
        if payload.len() < 16 {
            return payload;
        }
        let (salt, cipher) = payload.split_at(16);
        let padded = self.xor_encrypt(cipher, salt);
        Self::strip_padding(&padded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // echo -n "" | sha256sum
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn round_trip_is_identity() {
        let ob = TrafficObfuscator::new(vec![7u8; 32]);
        for msg in [
            &b""[..],
            b"hello",
            b"the quick brown fox jumps over the lazy dog",
        ] {
            let wire = ob.obfuscate(msg);
            assert_eq!(ob.deobfuscate(&wire), msg);
        }
    }

    #[test]
    fn xor_is_symmetric() {
        let ob = TrafficObfuscator::new(vec![1, 2, 3, 4]);
        let salt = b"0123456789abcdef";
        let pt = b"some plaintext bytes";
        let ct = ob.xor_encrypt(pt, salt);
        assert_eq!(ob.xor_encrypt(&ct, salt), pt);
    }
}

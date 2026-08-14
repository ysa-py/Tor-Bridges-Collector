//! Syntactic and semantic validation primitives.
//!
//! These are the single source of truth for the validation rules required by
//! the master spec: IPv4/IPv6 correctness, port range, 40-hex fingerprint
//! format, base64 certificate length, and URL scheme. Parsers and the
//! [`crate::types::BridgeLine::validate`] method both delegate here so the
//! rules cannot drift between "parse time" and "loaded from JSON" time.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;

use crate::error::ModelError;

/// Number of bytes an obfs4 `cert=` value must decode to: a 20-byte node id
/// plus a 32-byte `B` key, per the obfs4 specification. 52 bytes encode to 70
/// unpadded base64 characters (or 72 with `==` padding), which matches the
/// `cert=` values observed in the published bridge lists.
pub const OBFS4_CERT_BYTES: usize = 52;

/// Base64 engine that accepts both padded and unpadded standard-alphabet
/// input. Published obfs4 `cert=` values are unpadded, so strict canonical
/// decoding alone would reject real data.
const BASE64_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Validate and return an IPv4 literal.
pub fn validate_ipv4(host: &str) -> Result<Ipv4Addr, ModelError> {
    host.parse()
        .map_err(|_| ModelError::InvalidIpv4(host.to_owned()))
}

/// Validate and return an IPv6 literal.
pub fn validate_ipv6(host: &str) -> Result<Ipv6Addr, ModelError> {
    host.parse()
        .map_err(|_| ModelError::InvalidIpv6(host.to_owned()))
}

/// Validate and return any IP literal (IPv4 or IPv6).
pub fn validate_ip(host: &str) -> Result<IpAddr, ModelError> {
    host.parse()
        .map_err(|_| ModelError::InvalidHost(host.to_owned()))
}

/// Parse a port string, rejecting non-numeric input and the reserved port 0.
pub fn validate_port(value: &str) -> Result<u16, ModelError> {
    let port: u16 = value
        .parse()
        .map_err(|_| ModelError::InvalidPort(value.to_owned()))?;
    if port == 0 {
        return Err(ModelError::InvalidPort(value.to_owned()));
    }
    Ok(port)
}

/// Normalize a fingerprint to uppercase, returning `None` unless the input is
/// exactly 40 hexadecimal characters.
pub fn normalize_fingerprint(value: &str) -> Option<String> {
    let cleaned = value.trim();
    let valid = cleaned.len() == 40 && cleaned.bytes().all(|byte| byte.is_ascii_hexdigit());
    valid.then(|| cleaned.to_ascii_uppercase())
}

/// Validate a fingerprint, returning the normalized (uppercase) form.
pub fn validate_fingerprint(value: &str) -> Result<String, ModelError> {
    normalize_fingerprint(value).ok_or_else(|| ModelError::InvalidFingerprint(value.to_owned()))
}

/// Decode a base64 value (standard alphabet, padded or unpadded).
pub fn decode_base64(value: &str) -> Result<Vec<u8>, ModelError> {
    BASE64_ENGINE
        .decode(value.trim())
        .map_err(|_| ModelError::InvalidCert(value.to_owned()))
}

/// Validate an obfs4 `cert=` value: valid base64 that decodes to exactly
/// [`OBFS4_CERT_BYTES`] bytes.
pub fn validate_obfs4_cert(value: &str) -> Result<(), ModelError> {
    let decoded = decode_base64(value)?;
    if decoded.len() == OBFS4_CERT_BYTES {
        Ok(())
    } else {
        Err(ModelError::InvalidCertLength(decoded.len()))
    }
}

/// Whether a URL uses an allowed HTTP scheme.
pub fn is_http_scheme(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_normalization_requires_40_hex() {
        let fp = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            normalize_fingerprint(fp),
            Some("0123456789ABCDEF0123456789ABCDEF01234567".to_owned())
        );
        assert!(normalize_fingerprint("0123456789ABCDEF0123456789ABCDEF0123456").is_none());
        assert!(normalize_fingerprint("0123456789ABCDEF0123456789ABCDEF0123456G").is_none());
        assert!(normalize_fingerprint("").is_none());
    }

    #[test]
    fn port_validation_rejects_zero_and_non_numeric() {
        assert_eq!(validate_port("443").unwrap(), 443);
        assert_eq!(validate_port("65535").unwrap(), 65535);
        assert!(validate_port("0").is_err());
        assert!(validate_port("65536").is_err());
        assert!(validate_port("abc").is_err());
    }

    #[test]
    fn ip_validation_distinguishes_families() {
        assert!(validate_ipv4("1.2.3.4").is_ok());
        assert!(validate_ipv4("1.2.3.256").is_err());
        assert!(validate_ipv6("2001:db8::1").is_ok());
        assert!(validate_ipv6("1.2.3.4").is_err());
        assert!(validate_ip("::1").unwrap().is_ipv6());
    }

    #[test]
    fn cert_validation_requires_52_bytes() {
        // 52 bytes -> 70 unpadded base64 chars.
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0x5au8; 52]);
        assert_eq!(encoded.len(), 70);
        assert!(validate_obfs4_cert(&encoded).is_ok());

        // A truncated 66-char cert (observed once in the real lists) decodes
        // to fewer bytes and must be rejected.
        let truncated = &encoded[..66];
        let err = validate_obfs4_cert(truncated).unwrap_err();
        assert!(matches!(err, ModelError::InvalidCertLength(n) if n < 52));
    }
}

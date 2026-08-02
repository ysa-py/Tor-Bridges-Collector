// Live-Python differential parity test for
// `autonomous/anti_censorship/obfuscator.py` vs the Rust port
// `src/autonomous_anti_censorship_obfuscator.rs`.
//
// Every deterministic transform is executed by the REAL CPython original
// (spawned as a subprocess oracle) and compared byte-for-byte against the Rust
// port: `_derive_key`, `_xor_encrypt`, `_strip_padding`, `_http_wrap`,
// `_http_unwrap`, and the enum `.value` strings. In addition, the
// non-deterministic `obfuscate`/`deobfuscate` pipeline is proven
// cross-compatible in BOTH directions (Python encodes → Rust decodes, and
// Rust encodes → Python decodes), which pins the wire format exactly.

use std::process::Command;

use torshield_ir_ultra::autonomous_anti_censorship_obfuscator::{
    ObfuscationProtocol, TrafficObfuscator,
};

fn python_executable() -> &'static str {
    if Command::new("python")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        "python"
    } else {
        "python3"
    }
}

const ORACLE: &str = r#"
import sys, json
from autonomous.anti_censorship.obfuscator import (
    TrafficObfuscator, ObfuscationProtocol,
)

op = sys.argv[1]

def H(b): return b.hex()
def U(s): return bytes.fromhex(s)

if op == "derive":
    key, salt = U(sys.argv[2]), U(sys.argv[3])
    ob = TrafficObfuscator(key=key)
    print(H(ob._derive_key(salt)))
elif op == "xor":
    key, pt, salt = U(sys.argv[2]), U(sys.argv[3]), U(sys.argv[4])
    ob = TrafficObfuscator(key=key)
    print(H(ob._xor_encrypt(pt, salt)))
elif op == "strip":
    print(H(TrafficObfuscator._strip_padding(U(sys.argv[2]))))
elif op == "wrap":
    payload, host = U(sys.argv[2]), sys.argv[3].encode()
    ob = TrafficObfuscator(key=b"\x00"*32)
    print(H(ob._http_wrap(payload, host)))
elif op == "unwrap":
    print(H(TrafficObfuscator._http_unwrap(U(sys.argv[2]))))
elif op == "obf":
    key, data = U(sys.argv[2]), U(sys.argv[3])
    ob = TrafficObfuscator(key=key)
    print(H(ob.obfuscate(data)))
elif op == "deobf":
    key, data = U(sys.argv[2]), U(sys.argv[3])
    ob = TrafficObfuscator(key=key)
    print(H(ob.deobfuscate(data)))
elif op == "enum":
    print(json.dumps([
        ObfuscationProtocol.PLAIN.value,
        ObfuscationProtocol.OBFS4.value,
        ObfuscationProtocol.MEEK_AZURE.value,
        ObfuscationProtocol.MEEK_CF.value,
        ObfuscationProtocol.SNOWFLAKE.value,
        ObfuscationProtocol.SHADOWSOCKS.value,
        ObfuscationProtocol.VMESS.value,
        ObfuscationProtocol.VLESS.value,
        ObfuscationProtocol.TROJAN.value,
        ObfuscationProtocol.HTTP_MIMIC.value,
    ]))
else:
    sys.exit("unknown op " + op)
"#;

fn oracle(args: &[&str]) -> String {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(python_executable())
        .current_dir(repo_root)
        .env("PYTHONPATH", repo_root)
        .arg("-c")
        .arg(ORACLE)
        .args(args)
        .output()
        .expect("python obfuscator oracle must execute");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const KEY: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

#[test]
fn parity_derive_key() {
    let ob = TrafficObfuscator::new(KEY.to_vec());
    for salt in [&b""[..], b"0123456789abcdef", b"salt", &[0u8; 16]] {
        let py = oracle(&["derive", &hex(&KEY), &hex(salt)]);
        assert_eq!(
            py,
            hex(&ob.derive_key(salt)),
            "derive mismatch salt={salt:?}"
        );
    }
}

#[test]
fn parity_xor_encrypt() {
    let ob = TrafficObfuscator::new(KEY.to_vec());
    let salt = b"0123456789abcdef";
    let cases: [&[u8]; 5] = [
        b"",
        b"a",
        b"hello world",
        b"the quick brown fox jumps over the lazy dog 1234567890!!",
        &[0xAB; 200],
    ];
    for pt in cases {
        let py = oracle(&["xor", &hex(&KEY), &hex(pt), &hex(salt)]);
        assert_eq!(
            py,
            hex(&ob.xor_encrypt(pt, salt)),
            "xor mismatch len={}",
            pt.len()
        );
    }
}

#[test]
fn parity_strip_padding() {
    // Build a variety of blobs: valid, too-short, and length-prefix > blob.
    let mut valid = Vec::new();
    valid.extend_from_slice(&(5u32).to_be_bytes());
    valid.extend_from_slice(b"hello");
    valid.extend_from_slice(b"PADDINGPADDING");
    valid.push(14);

    let mut overrun = Vec::new();
    overrun.extend_from_slice(&(9999u32).to_be_bytes());
    overrun.extend_from_slice(b"short");

    let cases: [&[u8]; 4] = [&valid, &overrun, b"abc", b""];
    for blob in cases {
        let py = oracle(&["strip", &hex(blob)]);
        assert_eq!(
            py,
            hex(&TrafficObfuscator::strip_padding(blob)),
            "strip mismatch blob_len={}",
            blob.len()
        );
    }
}

#[test]
fn parity_http_wrap_unwrap() {
    for (payload, host) in [
        (&b""[..], "cdn.cloudflare.com"),
        (b"payloadbytes", "azurefd.net"),
        (&[0u8; 300][..], "assets.github.com"),
    ] {
        let py_wrap = oracle(&["wrap", &hex(payload), host]);
        let rust_wrap = TrafficObfuscator::http_wrap(payload, host.as_bytes());
        assert_eq!(py_wrap, hex(&rust_wrap), "wrap mismatch");

        // unwrap the Python-produced wrap on the Rust side and vice versa.
        let py_unwrap = oracle(&["unwrap", &py_wrap]);
        assert_eq!(
            py_unwrap,
            hex(&TrafficObfuscator::http_unwrap(&unhex(&py_wrap)))
        );
    }
    // unwrap of a blob with no CRLFCRLF separator returns it unchanged.
    let raw = "deadbeef";
    assert_eq!(oracle(&["unwrap", raw]), raw);
}

#[test]
fn parity_enum_values() {
    let py: Vec<String> = serde_json::from_str(&oracle(&["enum"])).unwrap();
    let rust = [
        ObfuscationProtocol::Plain,
        ObfuscationProtocol::Obfs4,
        ObfuscationProtocol::MeekAzure,
        ObfuscationProtocol::MeekCf,
        ObfuscationProtocol::Snowflake,
        ObfuscationProtocol::Shadowsocks,
        ObfuscationProtocol::Vmess,
        ObfuscationProtocol::Vless,
        ObfuscationProtocol::Trojan,
        ObfuscationProtocol::HttpMimic,
    ];
    assert_eq!(py.len(), rust.len());
    for (p, r) in py.iter().zip(rust.iter()) {
        assert_eq!(p, r.value());
    }
}

#[test]
fn parity_cross_roundtrip_python_encode_rust_decode() {
    let ob = TrafficObfuscator::new(KEY.to_vec());
    for data in [&b""[..], b"secret message", &[0x42u8; 128][..]] {
        let py_wire = oracle(&["obf", &hex(&KEY), &hex(data)]);
        let decoded = ob.deobfuscate(&unhex(&py_wire));
        assert_eq!(
            hex(&decoded),
            hex(data),
            "Rust could not decode Python obfuscate output"
        );
    }
}

#[test]
fn parity_cross_roundtrip_rust_encode_python_decode() {
    let ob = TrafficObfuscator::new(KEY.to_vec());
    for data in [&b""[..], b"another payload", &[0x7fu8; 90][..]] {
        let wire = ob.obfuscate(data);
        let decoded = oracle(&["deobf", &hex(&KEY), &hex(&wire)]);
        assert_eq!(
            decoded,
            hex(data),
            "Python could not decode Rust obfuscate output"
        );
    }
}

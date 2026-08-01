use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "network")]
use std::thread;
#[cfg(feature = "network")]
use std::time::Duration;
use zip::write::FileOptions;

const REQUIRED_FILES: &[&str] = &[
    "bridge_history.json",
    "bridge_list_for_testing.json",
    "bridge_scores.json",
    "conjure.txt",
    "conjure_72h.txt",
    "conjure_tested.txt",
    "iran_blocked.txt",
    "iran_likely_working_all.txt",
    "iran_likely_working_nin.txt",
    "iran_likely_working_obfs4.txt",
    "iran_likely_working_snowflake.txt",
    "iran_likely_working_vanilla.txt",
    "iran_likely_working_webtunnel.txt",
    "iran_results.json",
    "meek-azure.txt",
    "meek-azure_72h.txt",
    "meek-azure_tested.txt",
    "meek_lite.txt",
    "meek_lite_72h.txt",
    "meek_lite_72h_ipv6.txt",
    "meek_lite_ipv6.txt",
    "meek_lite_ipv6_tested.txt",
    "meek_lite_tested.txt",
    "obfs4.txt",
    "obfs4_72h.txt",
    "obfs4_72h_ipv6.txt",
    "obfs4_ipv6.txt",
    "obfs4_ipv6_72h.txt",
    "obfs4_ipv6_tested.txt",
    "obfs4_tested.txt",
    "snowflake.txt",
    "snowflake_72h.txt",
    "snowflake_72h_ipv6.txt",
    "snowflake_ipv6.txt",
    "snowflake_ipv6_tested.txt",
    "snowflake_tested.txt",
    "telegram_manifest.json",
    "tested_global_obfs4.txt",
    "tested_global_vanilla.txt",
    "tested_global_webtunnel.txt",
    "tor_bridges.zip",
    "vanilla.txt",
    "vanilla_72h.txt",
    "vanilla_72h_ipv6.txt",
    "vanilla_ipv6.txt",
    "vanilla_ipv6_72h.txt",
    "vanilla_ipv6_tested.txt",
    "vanilla_tested.txt",
    "webtunnel.txt",
    "webtunnel_72h.txt",
    "webtunnel_72h_ipv6.txt",
    "webtunnel_ipv6.txt",
    "webtunnel_ipv6_72h.txt",
    "webtunnel_ipv6_tested.txt",
    "webtunnel_tested.txt",
];
const SUMMARY_FILES: &[&str] = &[
    "iran_likely_working_all.txt",
    "iran_likely_working_obfs4.txt",
    "iran_likely_working_webtunnel.txt",
    "iran_likely_working_snowflake.txt",
    "iran_likely_working_nin.txt",
    "tested_global_obfs4.txt",
    "tested_global_webtunnel.txt",
    "tested_global_vanilla.txt",
];

#[derive(Serialize)]
struct ManifestFile {
    name: String,
    path: String,
    raw_url: String,
    size_bytes: u64,
    non_empty_lines: Option<usize>,
    sha256: String,
}
#[derive(Serialize)]
struct Manifest {
    generated_at: String,
    mode: String,
    bridge_directory: String,
    telegram_archive: String,
    telegram_archive_committed: bool,
    required_files_present: bool,
    missing_required_files: Vec<String>,
    files: Vec<ManifestFile>,
    summary: BTreeMap<String, usize>,
}

fn arg_value(args: &[String], flag: &str, default: String) -> String {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .unwrap_or(default)
}
fn bool_arg(args: &[String], flag: &str, default: String) -> bool {
    matches!(
        arg_value(args, flag, default).to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
fn count_lines(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}
fn sha256(path: &Path) -> io::Result<String> {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut data = fs::read(path)?;
    let bit_len = (data.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = H0;
    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, bytes) in chunk.chunks_exact(4).take(16).enumerate() {
            w[i] = u32::from_be_bytes(bytes.try_into().expect("four-byte SHA-256 word"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(value);
        }
    }
    Ok(h.iter().map(|word| format!("{word:08x}")).collect())
}
fn bridge_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut v: Vec<_> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file() && matches!(p.extension().and_then(|s| s.to_str()), Some("txt" | "json"))
        })
        .collect();
    v.sort();
    Ok(v)
}
fn manifest_files(dir: &Path, zip_path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = bridge_files(dir)?;
    let committed_zip = dir.join("tor_bridges.zip");
    if committed_zip.exists() {
        files.push(committed_zip);
    } else if zip_path.exists() {
        files.push(zip_path.to_path_buf());
    }
    files.sort();
    Ok(files)
}
fn build_zip(dir: &Path, zip_path: &Path) -> io::Result<()> {
    if let Some(parent) = zip_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let opts = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for path in bridge_files(dir)? {
        if path == zip_path || path.file_name().and_then(|s| s.to_str()) == Some("tor_bridges.zip")
        {
            continue;
        }
        zip.start_file(path.file_name().unwrap().to_string_lossy(), opts)?;
        zip.write_all(&fs::read(path)?)?;
    }
    zip.finish()?;
    Ok(())
}
fn missing_required_files(dir: &Path) -> Vec<String> {
    REQUIRED_FILES
        .iter()
        .filter(|n| !dir.join(n).exists() && **n != "telegram_manifest.json")
        .map(|s| s.to_string())
        .collect()
}
fn write_manifest(dir: &Path, repo_url: &str, zip_path: &Path) -> io::Result<Manifest> {
    let missing = missing_required_files(dir);
    let files = manifest_files(dir, zip_path)?
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            Ok(ManifestFile {
                raw_url: format!("{}/bridge/{}", repo_url.trim_end_matches('/'), name),
                path: p.to_string_lossy().to_string(),
                size_bytes: p.metadata()?.len(),
                non_empty_lines: (p.extension().and_then(|s| s.to_str()) == Some("txt"))
                    .then(|| count_lines(&p)),
                sha256: sha256(&p)?,
                name,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let summary = SUMMARY_FILES
        .iter()
        .map(|n| (n.to_string(), count_lines(&dir.join(n))))
        .collect();
    let manifest = Manifest {
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        mode: "rust-native-dual-persist".into(),
        bridge_directory: dir.to_string_lossy().into(),
        telegram_archive: zip_path.to_string_lossy().into(),
        telegram_archive_committed: dir.join("tor_bridges.zip").exists(),
        required_files_present: missing.is_empty(),
        missing_required_files: missing,
        files,
        summary,
    };
    fs::write(
        dir.join("telegram_manifest.json"),
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;
    Ok(manifest)
}
#[cfg(feature = "network")]
fn telegram_upload(
    token: &str,
    chat_id: &str,
    zip_path: &Path,
    caption: &str,
    retries: u32,
) -> bool {
    let client = reqwest::blocking::Client::new();
    let url = format!("https://api.telegram.org/bot{token}/sendDocument");
    for attempt in 1..=retries {
        let boundary = format!("----TorShieldIR{}{}", Utc::now().timestamp(), attempt);
        let mut body = Vec::new();
        for (key, value) in [
            ("chat_id", chat_id),
            ("caption", caption),
            ("parse_mode", "Markdown"),
        ] {
            body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n").as_bytes());
        }
        let file_name = zip_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("tor_bridges.zip");
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{file_name}\"\r\nContent-Type: application/zip\r\n\r\n").as_bytes());
        match fs::read(zip_path) {
            Ok(bytes) => body.extend_from_slice(&bytes),
            Err(error) => {
                eprintln!("telegram upload attempt {attempt} failed to read archive: {error}");
                return false;
            }
        }
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        match client
            .post(&url)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
        {
            Ok(r) if r.status().is_success() => {
                println!("telegram upload attempt {attempt}: HTTP {}", r.status());
                return true;
            }
            Ok(r) => eprintln!("telegram upload attempt {attempt}: HTTP {}", r.status()),
            Err(e) => eprintln!("telegram upload attempt {attempt} failed: {e}"),
        }
        thread::sleep(Duration::from_secs((attempt * 5).min(20) as u64));
    }
    false
}
#[cfg(not(feature = "network"))]
fn telegram_upload(_: &str, _: &str, _: &Path, _: &str, _: u32) -> bool {
    eprintln!("telegram upload requires --features network");
    false
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let bridge_dir = PathBuf::from(arg_value(&args, "--bridge-dir", "bridge".into()));
    let archive_path = PathBuf::from(arg_value(
        &args,
        "--archive-path",
        env::var("TELEGRAM_ARCHIVE_PATH").unwrap_or_else(|_| {
            bridge_dir
                .join("tor_bridges.zip")
                .to_string_lossy()
                .into_owned()
        }),
    ));
    let repo_url = arg_value(
        &args,
        "--repo-url",
        env::var("REPO_URL").unwrap_or_else(|_| {
            "https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main".into()
        }),
    );
    let upload = bool_arg(
        &args,
        "--telegram-upload",
        env::var("TELEGRAM_UPLOAD").unwrap_or_else(|_| "false".into()),
    );
    let token = arg_value(
        &args,
        "--telegram-token",
        env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default(),
    );
    let chat = arg_value(
        &args,
        "--telegram-chat-id",
        env::var("TELEGRAM_CHAT_ID").unwrap_or_default(),
    );
    let retries: u32 = arg_value(&args, "--retries", "3".into())
        .parse()
        .unwrap_or(3);
    fs::create_dir_all(&bridge_dir)?;
    build_zip(&bridge_dir, &archive_path)?;
    let committed_archive = bridge_dir.join("tor_bridges.zip");
    if archive_path != committed_archive {
        fs::copy(&archive_path, &committed_archive)?;
    }
    let manifest = write_manifest(&bridge_dir, &repo_url, &archive_path)?;
    if !manifest.required_files_present {
        eprintln!(
            "missing required bridge artifacts: {}",
            manifest.missing_required_files.join(", ")
        );
        std::process::exit(5);
    }
    println!(
        "wrote {} and {}",
        archive_path.display(),
        bridge_dir.join("telegram_manifest.json").display()
    );
    let caption = format!(
        "🛡️ *TorShield-IR bridge pack*\n{}",
        SUMMARY_FILES[..5]
            .iter()
            .map(|n| format!("• `{n}`: *{}*", count_lines(&bridge_dir.join(n))))
            .collect::<Vec<_>>()
            .join("\n")
    );
    if upload {
        if token.is_empty() || chat.is_empty() {
            eprintln!("telegram upload requested but credentials are missing");
            std::process::exit(3);
        }
        if !telegram_upload(&token, &chat, &archive_path, &caption, retries) {
            std::process::exit(4);
        }
    }
    Ok(())
}

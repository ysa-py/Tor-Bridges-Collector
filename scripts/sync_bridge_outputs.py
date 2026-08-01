#!/usr/bin/env python3
"""Synchronize Tor bridge artifacts for GitHub and optional Telegram delivery."""
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_BRIDGE_FILES = [
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
]

BRIDGE_ORDER = [
    "iran_likely_working_all.txt",
    "iran_likely_working_obfs4.txt",
    "iran_likely_working_webtunnel.txt",
    "iran_likely_working_snowflake.txt",
    "iran_likely_working_nin.txt",
    "tested_global_obfs4.txt",
    "tested_global_webtunnel.txt",
    "tested_global_vanilla.txt",
]


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_zip(bridge_dir: Path, archive_path: Path) -> Path:
    zip_path = archive_path
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(
        p for p in bridge_dir.iterdir()
        if p.is_file() and p.resolve() != zip_path.resolve() and p.suffix in {".txt", ".json"}
    )
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            archive.write(path, arcname=path.name)
    return zip_path


def write_manifest(bridge_dir: Path, repo_url: str, zip_path: Path) -> Path:
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    files = []
    for path in sorted(p for p in bridge_dir.iterdir() if p.is_file() and p.suffix in {".txt", ".json", ".zip"}):
        files.append({
            "name": path.name,
            "path": str(path),
            "raw_url": f"{repo_url.rstrip('/')}/bridge/{path.name}",
            "size_bytes": path.stat().st_size,
            "non_empty_lines": count_lines(path) if path.suffix == ".txt" else None,
            "sha256": sha256(path),
        })
    manifest = {
        "generated_at": generated_at,
        "mode": "dual-persist",
        "bridge_directory": str(bridge_dir),
        "telegram_archive": str(zip_path),
        "telegram_archive_committed": zip_path.parent.resolve() == bridge_dir.resolve(),
        "required_files_total": len(REQUIRED_BRIDGE_FILES),
        "missing_required_files": [name for name in REQUIRED_BRIDGE_FILES if not (bridge_dir / name).exists()],
        "files": files,
        "summary": {name: count_lines(bridge_dir / name) for name in BRIDGE_ORDER},
    }
    path = bridge_dir / "telegram_manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def multipart_body(fields: dict[str, str], file_field: str, file_path: Path) -> tuple[bytes, str]:
    boundary = f"----TorShieldIR{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode(),
            value.encode(),
            b"\r\n",
        ])
    content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    chunks.extend([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'.encode(),
        f"Content-Type: {content_type}\r\n\r\n".encode(),
        file_path.read_bytes(),
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    return b"".join(chunks), boundary


def telegram_upload(token: str, chat_id: str, file_path: Path, caption: str, retries: int) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    for attempt in range(1, retries + 1):
        body, boundary = multipart_body({"chat_id": chat_id, "caption": caption, "parse_mode": "Markdown"}, "document", file_path)
        request = urllib.request.Request(url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                ok = 200 <= response.status < 300
                print(f"telegram upload attempt {attempt}: HTTP {response.status}")
                return ok
        except urllib.error.URLError as error:
            print(f"telegram upload attempt {attempt} failed: {error}", file=sys.stderr)
            if attempt < retries:
                time.sleep(min(20, attempt * 5))
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge-dir", default="bridge")
    parser.add_argument("--archive-path", default=os.getenv("TELEGRAM_ARCHIVE_PATH", "/tmp/torshield-ir/tor_bridges.zip"))
    parser.add_argument("--repo-url", default=os.getenv("REPO_URL", "https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main"))
    parser.add_argument("--telegram-upload", default=os.getenv("TELEGRAM_UPLOAD", "false"))
    parser.add_argument("--telegram-token", default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    parser.add_argument("--telegram-chat-id", default=os.getenv("TELEGRAM_CHAT_ID", ""))
    parser.add_argument("--retries", type=int, default=3)
    args = parser.parse_args()

    bridge_dir = Path(args.bridge_dir)
    bridge_dir.mkdir(parents=True, exist_ok=True)
    zip_path = build_zip(bridge_dir, Path(args.archive_path))
    manifest_path = write_manifest(bridge_dir, args.repo_url, zip_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    missing = manifest.get("missing_required_files", [])
    if missing:
        print(f"missing required bridge files: {missing}", file=sys.stderr)
        return 2
    print(f"wrote {zip_path} and {manifest_path}")

    caption = "🛡️ *TorShield-IR bridge pack*\n" + "\n".join(
        f"• `{name}`: *{count_lines(bridge_dir / name)}*" for name in BRIDGE_ORDER[:5]
    )
    wants_upload = args.telegram_upload.lower() in {"1", "true", "yes", "on"}
    if wants_upload:
        if not args.telegram_token or not args.telegram_chat_id:
            print("telegram upload requested but credentials are missing", file=sys.stderr)
            return 3
        if not telegram_upload(args.telegram_token, args.telegram_chat_id, zip_path, caption, args.retries):
            return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Publication contract gate + re-attestation for bridge/:
# manifest ↔ payload ↔ ZIP ↔ README.
#
# Root cause this guards against (2026-10-11): the 21:06 commit (971b17ad) left
# one tree holding THREE different publications. bridge/telegram_manifest.json
# came from the newer run (generated_at 21:06:45Z, 1497 probes), most of the
# bridge/ payload still came from the previous run, and bridge/tor_bridges.zip
# was the older 20:29:53Z archive. Every healthy commit before it was internally
# consistent (manifest timestamp == ZIP timestamp, every hash matching); the
# mixture is the Stage 11 conflict-marker corruption signature, and it is what
# makes `sync_bridge_outputs --verify-only` fail in Stage 9 on pull requests.
#
# What --check enforces (mirrors verify_publication in src/bridge_publication.rs,
# so the Quality Gate fails fast without a cargo build):
#   1. bridge/telegram_manifest.json parses and attests required_files_present
#   2. every required file except tor_bridges.zip/telegram_manifest.json has a
#      SHA-256 entry, the published bytes match it, and size_bytes agrees
#   3. bridge/tor_bridges.zip ships every required file except itself, each entry
#      byte-identical to the payload, with exactly len(required_files) - 1 entries
#   4. README.md states the SHA-256 of the ZIP that is actually committed
#      (render_readme writes it right after the archive is verified)
# The canonical REQUIRED_FILES list lives in src/bridge_publication.rs; this
# script enforces the contract the manifest itself declares, so it cannot drift.
#
# --rebuild re-attests the manifest to the bytes that are actually published
# (sha256/size_bytes only - payload content is never rewritten) and rebuilds the
# ZIP deterministically. It refuses while any payload file still carries conflict
# markers, NUL bytes, or unparseable JSON: re-attesting corrupt data is not
# repair. Counts in the manifest summary that the publisher derives from payload
# content are reported as advisory and must be re-attested explicitly with
# --set-count NAME=VALUE.
#
# Usage
#   scripts/publication_contract.sh --check [--root DIR] [--bridge-dir DIR]
#   scripts/publication_contract.sh --rebuild [--root DIR] [--set-count NAME=N]...
#
# Exit codes: 0 ok · 1 contract violation · 2 refused (corrupt payload / usage)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BRIDGE_DIR=""
mode="check"
set_counts=()

usage() {
  cat <<'USAGE'
Usage:
  publication_contract.sh --check   [--root DIR] [--bridge-dir DIR]
  publication_contract.sh --rebuild [--root DIR] [--set-count NAME=VALUE]...

--check    verify manifest hashes, ZIP entries, and README archive hash (default)
--rebuild  re-attest manifest hashes/sizes to the published bytes and rebuild the
           ZIP; refuses while the payload still carries conflict markers
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) mode="check" ;;
    --rebuild) mode="rebuild" ;;
    --root)
      ROOT="${2:?--root needs a directory}"
      shift
      ;;
    --bridge-dir)
      BRIDGE_DIR="${2:?--bridge-dir needs a directory}"
      shift
      ;;
    --set-count)
      set_counts+=("${2:?--set-count needs NAME=VALUE}")
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

BRIDGE_DIR="${BRIDGE_DIR:-$ROOT/bridge}"
set_counts_joined=""
if [ "${#set_counts[@]}" -gt 0 ]; then
  set_counts_joined="$(printf '%s\n' "${set_counts[@]}")"
fi

# python3 is preinstalled on the GitHub runners and already used by this
# repository's workflow steps; no *.py file may live in the tree (quality_gate
# py-check), so the contract logic is embedded here.
CONTRACT_MODE="$mode" \
  CONTRACT_ROOT="$ROOT" \
  CONTRACT_BRIDGE_DIR="$BRIDGE_DIR" \
  CONTRACT_SET_COUNTS="$set_counts_joined" \
  python3 - <<'PY'
import hashlib
import json
import os
import re
import sys
import zipfile

MODE = os.environ["CONTRACT_MODE"]
ROOT = os.environ["CONTRACT_ROOT"]
BRIDGE = os.environ["CONTRACT_BRIDGE_DIR"]
SET_COUNTS = [p for p in os.environ["CONTRACT_SET_COUNTS"].splitlines() if p]

MANIFEST_NAME = "telegram_manifest.json"
ARCHIVE_NAME = "tor_bridges.zip"
MARKER_RE = re.compile(r"^(<<<<<<<|>>>>>>>|\|\|\|\|\|\|\|)( |$)")
MIRROR_RE = re.compile(r"^=======$")


def fail(code, message):
    print(f"publication_contract: {message}", file=sys.stderr)
    raise SystemExit(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    with open(path, "rb") as handle:
        return handle.read()


def write_atomic(path, body):
    temporary = f"{path}.{os.getpid()}.tmp"
    with open(temporary, "wb") as handle:
        handle.write(body)
    os.replace(temporary, path)


def payload_of(required):
    return [n for n in required if n not in (ARCHIVE_NAME, MANIFEST_NAME)]


def safe_name(name):
    return bool(name) and not name.startswith("/") and ".." not in name.split("/")


def payload_count(name, data):
    """Row count the publisher records in the manifest summary, when derivable."""
    if name.endswith(".json"):
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if isinstance(parsed, list):
            return len(parsed)
        if isinstance(parsed, dict):
            for key in ("bridges", "records", "results", "entries"):
                value = parsed.get(key)
                if isinstance(value, list):
                    return len(value)
            return len(parsed)
        return None
    text = data.decode("utf-8", "replace")
    return len([line for line in text.splitlines() if line.strip()])


def contract_problems(manifest):
    errors = []
    advisories = []
    if manifest.get("required_files_present") is not True:
        errors.append("manifest does not attest a complete inventory (required_files_present != true)")
    required = manifest.get("required_files")
    if not isinstance(required, list) or not required or not all(isinstance(n, str) for n in required):
        errors.append("manifest required_files must be a non-empty array of strings")
        return errors, advisories
    if len(set(required)) != len(required):
        errors.append("manifest required_files carries duplicates")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        errors.append("manifest files must be an array")
        return errors, advisories

    by_name = {}
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("manifest files entries must be objects")
            continue
        name = entry.get("name")
        digest = entry.get("sha256")
        if not isinstance(name, str) or not isinstance(digest, str):
            errors.append("manifest files entries must carry name + sha256 strings")
            continue
        if name in by_name:
            errors.append(f"manifest hashes {name} more than once")
        by_name[name] = entry

    for name in required:
        if not safe_name(name):
            errors.append(f"manifest lists an unsafe path: {name!r}")

    for name in payload_of(required):
        entry = by_name.get(name)
        if entry is None:
            errors.append(f"manifest does not hash payload file: {name}")
            continue
        path = os.path.join(BRIDGE, name)
        if not os.path.isfile(path):
            errors.append(f"required payload file is missing: {name}")
            continue
        data = read(path)
        if sha256(data) != entry["sha256"]:
            errors.append(f"manifest SHA-256 mismatch for {name}")
        size = entry.get("size_bytes")
        if isinstance(size, int) and size != len(data):
            errors.append(f"manifest size_bytes mismatch for {name} (recorded {size}, published {len(data)})")

    for name in by_name:
        if name not in required:
            advisories.append(f"manifest hashes a file that is not in required_files: {name}")

    archive_path = os.path.join(BRIDGE, ARCHIVE_NAME)
    if not os.path.isfile(archive_path):
        errors.append(f"{ARCHIVE_NAME} is missing from {BRIDGE}")
    else:
        try:
            with zipfile.ZipFile(archive_path) as archive:
                members = archive.namelist()
                for name in required:
                    if name == ARCHIVE_NAME:
                        continue
                    member = f"bridge/{name}"
                    if member not in members:
                        errors.append(f"archive is missing {member}")
                        continue
                    local = os.path.join(BRIDGE, name)
                    if os.path.isfile(local) and archive.read(member) != read(local):
                        errors.append(f"archive content mismatch for {name}")
                expected_entries = len(required) - 1
                if len(members) != expected_entries:
                    errors.append(
                        f"archive entry count mismatch: expected {expected_entries}, got {len(members)}"
                    )
        except zipfile.BadZipFile as exc:
            errors.append(f"{ARCHIVE_NAME} is not a readable ZIP: {exc}")

        readme = os.path.join(ROOT, "README.md")
        if os.path.isfile(readme):
            match = re.search(
                r"Archive payload SHA-256:\*\* `([0-9a-f]{64})`",
                read(readme).decode("utf-8", "replace"),
            )
            actual = sha256(read(archive_path))
            if match is None:
                advisories.append("README.md does not state the archive SHA-256")
            elif match.group(1) != actual:
                errors.append(
                    "README.md archive SHA-256 is stale "
                    f"(states {match.group(1)[:16]}..., published ZIP is {actual[:16]}...)"
                )

    summary = manifest.get("summary")
    if isinstance(summary, dict):
        for name in payload_of(required):
            path = os.path.join(BRIDGE, name)
            if not os.path.isfile(path) or name not in summary:
                continue
            actual = payload_count(name, read(path))
            if actual is not None and summary[name] != actual:
                advisories.append(
                    f"summary count for {name} says {summary[name]}, payload holds {actual} "
                    "(re-attest with --rebuild --set-count)"
                )
    return errors, advisories


def load_manifest():
    path = os.path.join(BRIDGE, MANIFEST_NAME)
    if not os.path.isfile(path):
        return path, None, None
    raw = read(path)
    try:
        return path, raw, json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(1, f"{MANIFEST_NAME} is not valid JSON: {exc}")


def report(errors, advisories):
    for note in advisories:
        print(f"publication_contract: advisory: {note}")
    for problem in errors:
        print(f"publication_contract: ERROR: {problem}", file=sys.stderr)


manifest_path, raw, manifest = load_manifest()
if manifest is None:
    # Mirrors Stage 9's declared no-op: a tree without a committed publication
    # contract is not a violation, it is explicitly declared as absent.
    print(f"publication_contract: no committed publication contract ({manifest_path} missing) - nothing to verify")
    raise SystemExit(0)

errors, advisories = contract_problems(manifest)
if MODE == "check":
    report(errors, advisories)
    if errors:
        fail(1, f"{len(errors)} publication contract violation(s)")
    required = manifest.get("required_files") or []
    print(f"publication_contract: OK ({len(payload_of(required))} payload files, archive + README attested)")
    raise SystemExit(0)

# ── --rebuild ───────────────────────────────────────────────────────────────
required = manifest.get("required_files")
if not isinstance(required, list) or not all(isinstance(n, str) for n in required):
    fail(2, "manifest required_files must be an array of strings before re-attestation")

# Faithful re-serialization guard: only rewrite the manifest when the writer is
# byte-identical to the publisher's serde_json pretty form (2-space indent,
# raw UTF-8, trailing newline). Anything else is hand-edited and must be fixed
# by hand rather than silently reformatted.
canonical = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
if canonical != raw:
    fail(2, f"{MANIFEST_NAME} is not in the canonical pretty-JSON form; refusing to rewrite it")

for name in payload_of(required):
    path = os.path.join(BRIDGE, name)
    if not os.path.isfile(path):
        fail(2, f"refusing to re-attest: required payload file is missing: {name}")
    data = read(path)
    text = data.decode("utf-8", "replace")
    if "\0" in text:
        fail(2, f"refusing to re-attest corrupt payload: {name} contains a NUL byte")
    for line in text.splitlines():
        if MARKER_RE.match(line) or MIRROR_RE.match(line):
            fail(2, f"refusing to re-attest corrupt payload: {name} still carries a conflict marker")
    if name.endswith(".json"):
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            fail(2, f"refusing to re-attest corrupt payload: {name} is not valid JSON: {exc}")

by_name = {entry["name"]: entry for entry in manifest["files"] if isinstance(entry, dict)}
reattested = []
for name in payload_of(required):
    entry = by_name.get(name)
    if entry is None:
        fail(2, f"refusing to rebuild: manifest has no hash entry for {name}")
    data = read(os.path.join(BRIDGE, name))
    digest = sha256(data)
    if entry.get("sha256") != digest or entry.get("size_bytes") != len(data):
        entry["sha256"] = digest
        entry["size_bytes"] = len(data)
        reattested.append(name)

summary = manifest.get("summary")
if not isinstance(summary, dict):
    fail(2, "manifest summary must be an object")
for pair in SET_COUNTS:
    name, separator, value = pair.partition("=")
    if not separator or name not in required:
        fail(2, f"--set-count must name a required file: {pair!r}")
    if not value.isdigit():
        fail(2, f"--set-count value must be a non-negative integer: {pair!r}")
    summary[name] = int(value)
    reattested.append(f"{name} (summary)")

write_atomic(manifest_path, (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))

# Rebuild the archive exactly as the publisher frames it: every required file
# except the ZIP itself, sorted, under bridge/<name>, deterministic timestamps.
archive_path = os.path.join(BRIDGE, ARCHIVE_NAME)
temporary = f"{archive_path}.{os.getpid()}.tmp"
with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
    for name in sorted(n for n in required if n != ARCHIVE_NAME):
        info = zipfile.ZipInfo(f"bridge/{name}", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, read(os.path.join(BRIDGE, name)))
os.replace(temporary, archive_path)
archive_sha256 = sha256(read(archive_path))

readme = os.path.join(ROOT, "README.md")
if os.path.isfile(readme):
    body = read(readme).decode("utf-8")
    patched, swapped = re.subn(
        r"(Archive payload SHA-256:\*\* `)[0-9a-f]{64}(`)",
        rf"\g<1>{archive_sha256}\g<2>",
        body,
    )
    if swapped:
        write_atomic(readme, patched.encode("utf-8"))
        reattested.append("README.md (archive SHA-256)")

# Self-verify from disk: a rebuild that does not converge is a failure.
_, _, reloaded = load_manifest()
errors, advisories = contract_problems(reloaded)
report(errors, advisories)
if errors:
    fail(1, f"re-attestation did not converge: {len(errors)} violation(s) left")
detail = ", ".join(reattested) if reattested else "nothing changed"
print(f"publication_contract: re-attested -> {detail}")
print(f"publication_contract: archive rebuilt (sha256 {archive_sha256}) and contract verified")
PY

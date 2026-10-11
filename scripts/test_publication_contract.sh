#!/usr/bin/env bash
# Hermetic tests for scripts/publication_contract.sh.
#
# Offline, no repository state is touched: the fixture is a throwaway directory
# under $TMPDIR with its own miniature publication contract (payload, manifest,
# ZIP, README). Conflict markers are assembled with printf so this test file
# itself never contains a marker at column 0 (the conflict-marker gate in
# main-ci scans every tracked file, this one included).
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
contract="$script_dir/publication_contract.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'ok: %s\n' "$1"
}

expect_status() {
  local expected="$1" desc="$2" status=0
  shift 2
  "$@" >/dev/null 2>&1 || status=$?
  [ "$status" -eq "$expected" ] || fail "$desc (expected exit $expected, got $status)"
  pass "$desc"
}

expect_message() {
  local expected="$1" needle="$2" desc="$3" status=0 output
  shift 3
  output="$("$@" 2>&1)" || status=$?
  [ "$status" -eq "$expected" ] || fail "$desc (expected exit $expected, got $status)"
  case "$output" in
    *"$needle"*) ;;
    *) fail "$desc (output did not mention '$needle': $output)" ;;
  esac
  pass "$desc"
}

build_fixture() { # rebuilds the healthy contract from scratch
  FIXTURE_DIR="$tmp_dir" python3 - <<'PY'
import hashlib, json, os, pathlib, zipfile

root = pathlib.Path(os.environ["FIXTURE_DIR"])
bridge = root / "bridge"
bridge.mkdir(parents=True, exist_ok=True)
bridge.joinpath("a.json").write_text('{"records": [1, 2, 3]}\n')
bridge.joinpath("b.txt").write_text("one\ntwo\n")

required = ["a.json", "b.txt", "telegram_manifest.json", "tor_bridges.zip"]
files = []
for name in ("a.json", "b.txt"):
    data = (bridge / name).read_bytes()
    files.append({
        "name": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    })
manifest = {
    "schema_version": 1,
    "generated_at": "2026-01-01T00:00:00Z",
    "required_files": required,
    "required_files_present": True,
    "files": files,
    "summary": {"a.json": 3, "b.txt": 2},
    "archive": {"name": "tor_bridges.zip", "entry_count": len(required) - 1, "excludes_self": True},
}
(bridge / "telegram_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

def rebuild_archive():
    with zipfile.ZipFile(bridge / "tor_bridges.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(n for n in required if n != "tor_bridges.zip"):
            info = zipfile.ZipInfo(f"bridge/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, (bridge / name).read_bytes())

rebuild_archive()
archive_sha = hashlib.sha256((bridge / "tor_bridges.zip").read_bytes()).hexdigest()
(root / "README.md").write_text(
    "> **Last publication:** `2026-01-01T00:00:00Z` · "
    f"**Archive payload SHA-256:** `{archive_sha}`\n"
)
PY
}

build_fixture

# ── healthy contract ────────────────────────────────────────────────────────
expect_message 0 "publication_contract: OK" "healthy contract passes --check" \
  "$contract" --check --root "$tmp_dir"

# ── payload drift: the manifest no longer describes the published bytes ─────
printf '%s\n' 'three' >>"$tmp_dir/bridge/b.txt"
expect_message 1 "manifest SHA-256 mismatch for b.txt" "payload drift fails --check" \
  "$contract" --check --root "$tmp_dir"
expect_message 0 "re-attested" "payload drift is re-attested by --rebuild" \
  "$contract" --rebuild --root "$tmp_dir"
expect_status 0 "re-attested contract passes --check" \
  "$contract" --check --root "$tmp_dir"

# ── stale README archive hash ───────────────────────────────────────────────
README_FILE="$tmp_dir/README.md" python3 - <<'PY'
import os, pathlib, re

path = pathlib.Path(os.environ["README_FILE"])
path.write_text(re.sub(r"`[0-9a-f]{64}`", "`" + "0" * 64 + "`", path.read_text()))
PY
expect_message 1 "README.md archive SHA-256 is stale" "stale README hash fails --check" \
  "$contract" --check --root "$tmp_dir"
expect_message 0 "contract verified" "stale README hash is repaired by --rebuild" \
  "$contract" --rebuild --root "$tmp_dir"

# ── refusal: re-attesting corrupt payload is not repair ─────────────────────
{
  printf '%s\n' 'one'
  printf '%s\n' "<<<<<<< Updated upstream"
  printf '%s\n' 'two'
  printf '%s\n' '======='
  printf '%s\n' 'three'
  printf '%s\n' ">>>>>>> Stashed changes"
} >"$tmp_dir/bridge/b.txt"
expect_message 2 "still carries a conflict marker" "--rebuild refuses a marker payload" \
  "$contract" --rebuild --root "$tmp_dir"
expect_status 1 "corrupt payload fails --check" \
  "$contract" --check --root "$tmp_dir"

# ── declared absence: mirrors Stage 9's no-op branch ────────────────────────
mv "$tmp_dir/bridge/telegram_manifest.json" "$tmp_dir/telegram_manifest.json.bak"
expect_message 0 "no committed publication contract" "missing manifest is a declared no-op" \
  "$contract" --check --root "$tmp_dir"

printf 'all publication-contract tests passed\n'

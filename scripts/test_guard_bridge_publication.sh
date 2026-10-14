#!/usr/bin/env bash
# Hermetic fault-injection tests for scripts/guard_bridge_publication.sh.
#
# Offline, no repository state is touched: each scenario runs inside a
# throwaway git repo under $TMPDIR holding its own miniature publication
# contract (payload, manifest, ZIP, README). Conflict markers are assembled
# with printf so this test file itself never contains a marker at column 0.
#
# Scenario 1 reproduces the 2026-10-13 production failure (runs 38465273560
# and 38477508742): a degraded run published an empty payload file, Stage 9
# attested the empty bytes, and the wipe guard restored last-known-good
# content — before this fix, telegram_manifest.json / tor_bridges.zip /
# README.md still described the empty bytes, so publication_contract --check
# rejected the commit (12 violations) and Stage 11 pushed nothing.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
guard="$script_dir/guard_bridge_publication.sh"
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

# ── fixture: a real git repo whose HEAD holds a healthy publication ─────────
setup_fixture() {
  local root="$1"
  git -C "$root" init -q -b main
  git -C "$root" config user.name "fixture"
  git -C "$root" config user.email "fixture@example.com"
  FIXTURE_DIR="$root" python3 - <<'PY'
import hashlib, json, os, pathlib, zipfile

root = pathlib.Path(os.environ["FIXTURE_DIR"])
bridge = root / "bridge"
bridge.mkdir(parents=True, exist_ok=True)
(bridge / "a.json").write_text('{"records": [1, 2, 3]}\n')
(bridge / "b.txt").write_text("one\ntwo\n")

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

with zipfile.ZipFile(bridge / "tor_bridges.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    for name in sorted(n for n in required if n != "tor_bridges.zip"):
        info = zipfile.ZipInfo(f"bridge/{name}", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, (bridge / name).read_bytes())

archive_sha = hashlib.sha256((bridge / "tor_bridges.zip").read_bytes()).hexdigest()
(root / "README.md").write_text(
    "> **Last publication:** `2026-01-01T00:00:00Z` · "
    f"**Archive payload SHA-256:** `{archive_sha}`\n"
)
PY
  git -C "$root" add -A
  git -C "$root" commit -qm "last-known-good publication"
}

# Stage 9 replay: attest the CURRENT (wiped) payload bytes like the publisher.
attest_current_payload() { # $1 = root, $2 = payload name
  local root="$1" name="$2"
  ATTEST_ROOT="$root" ATTEST_NAME="$name" python3 - <<'PY'
import hashlib, json, os, pathlib, zipfile

root = pathlib.Path(os.environ["ATTEST_ROOT"])
bridge = root / "bridge"
name = os.environ["ATTEST_NAME"]
manifest_path = bridge / "telegram_manifest.json"
manifest = json.loads(manifest_path.read_text())
data = (bridge / name).read_bytes()
for entry in manifest["files"]:
    if entry["name"] == name:
        entry["sha256"] = hashlib.sha256(data).hexdigest()
        entry["size_bytes"] = len(data)
manifest["summary"][name] = 0
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

required = manifest["required_files"]
with zipfile.ZipFile(bridge / "tor_bridges.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    for n in sorted(n for n in required if n != "tor_bridges.zip"):
        info = zipfile.ZipInfo(f"bridge/{n}", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, (bridge / n).read_bytes())

import hashlib as _h
archive_sha = _h.sha256((bridge / "tor_bridges.zip").read_bytes()).hexdigest()
readme = root / "README.md"
readme.write_text(
    "> **Last publication:** `2026-01-01T00:00:00Z` · "
    f"**Archive payload SHA-256:** `{archive_sha}`\n"
)
PY
}

# ── scenario 1b: exact production failure reproduction ───────────────────────
# Stage 9/9b attested the wiped payload (self-consistent, --check green), then
# the wipe guard restored last-known-good bytes WITHOUT re-attesting — that
# mixed tree is what publication_contract --check rejected in production
# (runs 38465273560, 38477508742: "manifest SHA-256 mismatch ... recorded 0,
# published 39620").
s1b="$tmp_dir/s1b"
mkdir -p "$s1b"
setup_fixture "$s1b"
: >"$s1b/bridge/b.txt"
attest_current_payload "$s1b" "b.txt"
( cd "$s1b" && bash "$contract" --check --root "$s1b" ) >/dev/null 2>&1 \
  || fail "scenario 1b precondition: attested wipe should pass --check (Stage 9b did)"
pass "scenario 1b precondition: attested wipe passes --check (Stage 9b state)"

git -C "$s1b" checkout HEAD -- bridge/b.txt   # old-guard restore, no re-attestation
restored_bytes=$(wc -c <"$s1b/bridge/b.txt")
[ "$restored_bytes" -gt 0 ] || fail "scenario 1b: restore produced no bytes"
check_out="$( cd "$s1b" && bash "$contract" --check --root "$s1b" 2>&1 )" \
  && fail "scenario 1b: mixed tree unexpectedly passes --check"
case "$check_out" in
  *"manifest SHA-256 mismatch for b.txt"*) 
    pass "scenario 1b: production failure signature reproduced" ;;
  *) fail "scenario 1b: unexpected failure output: $check_out" ;;
esac

# ── scenario 1: degraded run wipes a payload file → restore + re-attest ─────
s1="$tmp_dir/s1"
mkdir -p "$s1"
setup_fixture "$s1"
: >"$s1/bridge/b.txt"                       # this run produced an empty b.txt
attest_current_payload "$s1" "b.txt"        # Stage 9 attested the empty bytes
mkdir -p "$s1/data"
printf '{"degraded": true, "reason": "test: simulated stage-2 deadline"}\n' >"$s1/data/run_state.json"

out="$( cd "$s1" && bash "$guard" --bridge-dir bridge --live false --root "$s1" 2>&1 )" \
  || fail "scenario 1: guard exited non-zero: $out"
case "$out" in
  *"restored=1"*) pass "scenario 1: guard restored the wiped payload file" ;;
  *) fail "scenario 1: guard did not restore (output: $out)" ;;
esac
case "$out" in
  *"re-attested ->"*) pass "scenario 1: guard re-attested the publication" ;;
  *) fail "scenario 1: guard did not re-attest (output: $out)" ;;
esac

[ "$(grep -c . "$s1/bridge/b.txt")" = "2" ] \
  || fail "scenario 1: b.txt was not restored to the last-known-good content"
pass "scenario 1: b.txt content restored (2 lines)"

( cd "$s1" && bash "$contract" --check --root "$s1" ) >/dev/null 2>&1 \
  || fail "scenario 1: re-attested publication still fails --check"
pass "scenario 1: re-attested publication passes --check"

python3 - "$s1" <<'PY' || fail "scenario 1: run manifest inconsistent with restored payload"
import hashlib, json, os, sys, zipfile

root = sys.argv[1]
run_manifest = json.load(open(os.path.join(root, "data", "run_manifest.json")))
assert run_manifest["degraded"] is True, "degraded verdict missing"
assert run_manifest["restored_last_known_good"] == ["b.txt"], run_manifest["restored_last_known_good"]
entry = run_manifest["files"]["b.txt"]
data = open(os.path.join(root, "bridge", "b.txt"), "rb").read()
assert entry["bytes"] == len(data) and entry["sha256"] == hashlib.sha256(data).hexdigest()
manifest = json.load(open(os.path.join(root, "bridge", "telegram_manifest.json")))
m_entry = next(f for f in manifest["files"] if f["name"] == "b.txt")
assert m_entry["size_bytes"] == len(data) > 0, "manifest still attests empty bytes"
with zipfile.ZipFile(os.path.join(root, "bridge", "tor_bridges.zip")) as archive:
    assert archive.read("bridge/b.txt") == data, "archive holds pre-restore bytes"
PY
pass "scenario 1: manifest/ZIP/run_manifest all aligned to the restored bytes"

# ── scenario 2: healthy run with truthful churn must stay untouched ─────────
s2="$tmp_dir/s2"
mkdir -p "$s2"
setup_fixture "$s2"
: >"$s2/bridge/b.txt"
attest_current_payload "$s2" "b.txt"        # healthy run attests its own empty file

out="$( cd "$s2" && bash "$guard" --bridge-dir bridge --live false --root "$s2" 2>&1 )" \
  || fail "scenario 2: guard exited non-zero: $out"
case "$out" in
  *"restored=0"*) pass "scenario 2: healthy run is trusted (no restore)" ;;
  *) fail "scenario 2: healthy run was degraded (output: $out)" ;;
esac
[ "$(wc -c <"$s2/bridge/b.txt")" = "0" ] \
  || fail "scenario 2: healthy churn was overwritten"
( cd "$s2" && bash "$contract" --check --root "$s2" ) >/dev/null 2>&1 \
  || fail "scenario 2: healthy attested publication fails --check"
pass "scenario 2: truthful churn survives and stays contract-clean"

printf 'all guard fault-injection tests passed\n'

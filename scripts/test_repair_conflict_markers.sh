#!/usr/bin/env bash
# Hermetic tests for scripts/repair_conflict_markers.sh.
#
# Offline, no repository state is touched: every fixture lives in a throwaway
# git repo under $TMPDIR. Conflict markers are assembled with printf so this
# test file itself never contains a marker at column 0 (the --check gate in
# main-ci scans every tracked file, this one included).
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repair="$script_dir/repair_conflict_markers.sh"
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

write_corrupt() { # $1 dest, $2 first side line, $3 second side line
  {
    printf '%s\n' '{'
    printf '%s\n' '  "a": 1,'
    printf '%s\n' "<<<<<<< Updated upstream"
    printf '%s\n' "$2"
    printf '%s\n' '======='
    printf '%s\n' "$3"
    printf '%s\n' ">>>>>>> Stashed changes"
    printf '%s\n' '  "c": 3'
    printf '%s\n' '}'
  } >"$1"
}

mkdir -p "$tmp_dir/bridge" "$tmp_dir/data" "$tmp_dir/docs"
git -C "$tmp_dir" init -q -b main
git -C "$tmp_dir" config user.email test@example.com
git -C "$tmp_dir" config user.name "conflict marker test"

# ── fixture B baseline: a valid revision exists in history ──────────────────
printf '%s\n' '{"history": ["valid", "earlier", "revision"]}' >"$tmp_dir/bridge/history.json"
printf '%s\n' '# Clean document' 'no markers here' >"$tmp_dir/docs/notes.md"
git -C "$tmp_dir" add -A
git -C "$tmp_dir" commit -qm "valid baseline"

# ── corrupt fixtures ────────────────────────────────────────────────────────
# A: both sides valid JSON -> the freshly generated second side must win.
write_corrupt "$tmp_dir/data/report.json" '  "b": 1,' '  "b": 2,'
# B: second side is NOT valid JSON -> fall back to the newest valid revision.
{
  printf '%s\n' '{'
  printf '%s\n' '<<<<<<< Updated upstream'
  printf '%s\n' '"history": ["valid", "earlier", "revision"]}'
  printf '%s\n' '======='
  printf '%s\n' '"history": ["broken",'
  printf '%s\n' ">>>>>>> Stashed changes"
} >"$tmp_dir/bridge/history.json"
# D: markers plus a legitimate Markdown setext underline outside any block.
{
  printf '%s\n' '# Title'
  printf '%s\n' '=========='
  printf '%s\n' "<<<<<<< Updated upstream"
  printf '%s\n' 'old text'
  printf '%s\n' '======='
  printf '%s\n' 'new text'
  printf '%s\n' ">>>>>>> Stashed changes"
} >"$tmp_dir/data/mirror.md"
# README.md lives at the repo root, outside the healed directories.
write_corrupt "$tmp_dir/README.md" '  "b": 1,' '  "b": 2,'
cp "$tmp_dir/docs/notes.md" "$tmp_dir/notes.md.expected"

git -C "$tmp_dir" add -A

expect_status 2 "--check detects the corrupt fixtures" bash "$repair" --root "$tmp_dir" --check
expect_status 1 "--validate-json rejects the corrupt payload" bash "$repair" --root "$tmp_dir" --validate-json data
expect_status 0 "heal reports success" bash "$repair" --root "$tmp_dir"

# ── heal outcome ────────────────────────────────────────────────────────────
jq -e '.a == 1 and .b == 2 and .c == 3' "$tmp_dir/data/report.json" >/dev/null ||
  fail "fresh side must win in data/report.json"
pass "fresh side wins in data/report.json"

cmp -s <(git -C "$tmp_dir" show HEAD:bridge/history.json) "$tmp_dir/bridge/history.json" ||
  fail "bridge/history.json must fall back to the newest valid revision"
pass "invalid fresh side falls back to the newest valid git revision"

cmp -s "$tmp_dir/notes.md.expected" "$tmp_dir/docs/notes.md" ||
  fail "a marker-free file must not be touched"
pass "marker-free files are untouched"

grep -qxF '==========' "$tmp_dir/data/mirror.md" ||
  fail "a legitimate setext underline must survive marker repair"
grep -qxF 'new text' "$tmp_dir/data/mirror.md" || fail "fresh markdown side must survive"
pass "setext underline preserved, fresh markdown side kept"

jq -e '.b == 2' "$tmp_dir/README.md" >/dev/null || fail "README.md must heal with the other outputs"
pass "README.md heals"

if grep -rqE '^(<<<<<<<|>>>>>>>)( |$)' "$tmp_dir" --exclude-dir=.git; then
  fail "no conflict marker may survive a heal"
fi
pass "no conflict markers survive a heal"

# --check inspects the staged/committed payload (that is what a run publishes),
# so the healed result has to be staged the way Stage 11 stages it.
git -C "$tmp_dir" add -A
expect_status 0 "--check passes once the healed result is staged" bash "$repair" --root "$tmp_dir" --check
expect_status 0 "--validate-json passes after healing" bash "$repair" --root "$tmp_dir" --validate-json bridge data

# ── idempotency ─────────────────────────────────────────────────────────────
checksums="$(find "$tmp_dir" -not -path '*/.git/*' \( -name '*.json' -o -name '*.md' \) | sort | xargs sha256sum)"
expect_status 0 "second heal run is a clean no-op" bash "$repair" --root "$tmp_dir"
[ "$checksums" = "$(find "$tmp_dir" -not -path '*/.git/*' \( -name '*.json' -o -name '*.md' \) | sort | xargs sha256sum)" ] ||
  fail "healing twice must be idempotent"
pass "healing is idempotent"

# ── never publish an unrepairable payload ───────────────────────────────────
orphan="$tmp_dir/data/orphan.json"
{
  printf '%s\n' '{'
  printf '%s\n' "<<<<<<< Updated upstream"
  printf '%s\n' '"only": "upstream side"'
  printf '%s\n' '======='
  printf '%s\n' ">>>>>>> Stashed changes"
} >"$orphan"
cp "$orphan" "$tmp_dir/orphan.expected"
git -C "$tmp_dir" add -A
expect_status 1 "unrepairable file fails the heal" bash "$repair" --root "$tmp_dir"
cmp -s "$tmp_dir/orphan.expected" "$orphan" ||
  fail "an unrepairable file must be left untouched, never emptied"
pass "unrepairable file is left untouched"

# ── --check outside a git repository ────────────────────────────────────────
plain_dir="$(mktemp -d)"
mkdir -p "$plain_dir/data"
expect_status 0 "--check works without git when clean" bash "$repair" --root "$plain_dir" --check
write_corrupt "$plain_dir/data/report.json" '  "b": 1,' '  "b": 2,'
expect_status 2 "--check works without git when corrupt" bash "$repair" --root "$plain_dir" --check
rm -rf "$plain_dir"

printf 'all repair_conflict_markers tests passed\n'

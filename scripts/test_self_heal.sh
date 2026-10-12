#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/work"
cat > "$TMP/bin/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${CARGO_TEST_LOG:?CARGO_TEST_LOG must be set}"
case "$*" in
  "fmt --all -- --check")
    exit 0
    ;;
  "clippy --workspace --all-targets -- -D warnings")
    exit 0
    ;;
  "audit --version")
    echo "simulated: cargo-audit is unavailable" >&2
    exit 1
    ;;
  "install cargo-audit --locked")
    echo "simulated: cargo-audit install failed" >&2
    exit 1
    ;;
  "test --workspace --release")
    echo "SELF_HEAL_RELEASE_TEST_RAN"
    exit 0
    ;;
  *)
    echo "unexpected cargo invocation: $*" >&2
    exit 97
    ;;
esac
FAKE_CARGO
chmod +x "$TMP/bin/cargo"

export PATH="$TMP/bin:$PATH"
export CARGO_TEST_LOG="$TMP/cargo-calls.log"
cd "$TMP/work"

set +e
bash "$ROOT/scripts/self_heal.sh" > "$TMP/self-heal.log" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
  echo "test_self_heal: expected non-zero status when audit installation fails" >&2
  cat "$TMP/self-heal.log" >&2
  exit 1
fi

if ! grep -q '^test --workspace --release$' "$CARGO_TEST_LOG"; then
  echo "test_self_heal: release tests were not invoked after the audit bootstrap failure" >&2
  cat "$CARGO_TEST_LOG" >&2
  exit 1
fi

TEST_LOG="$(find "$TMP/work/diagnostics" -type f -name test-output.log -print -quit)"
if [ -z "$TEST_LOG" ] || ! grep -q 'SELF_HEAL_RELEASE_TEST_RAN' "$TEST_LOG"; then
  echo "test_self_heal: release test output was not captured" >&2
  cat "$TMP/self-heal.log" >&2
  exit 1
fi

if grep -Eq '^audit --json$|^audit$' "$CARGO_TEST_LOG"; then
  echo "test_self_heal: cargo audit was invoked after its installation failed" >&2
  cat "$CARGO_TEST_LOG" >&2
  exit 1
fi

INDEX="$(find "$TMP/work/diagnostics" -type f -name index.json -print -quit)"
if [ -z "$INDEX" ] || ! grep -Eq '"audit_count_valid"[[:space:]]*:[[:space:]]*false' "$INDEX"; then
  echo "test_self_heal: diagnostic index did not mark the audit count as unknown" >&2
  [ -z "$INDEX" ] || cat "$INDEX" >&2
  exit 1
fi

if ! grep -q 'cargo audit unavailable; vulnerability count is UNKNOWN' "$TMP/self-heal.log"; then
  echo "test_self_heal: unknown audit status was not reported explicitly" >&2
  cat "$TMP/self-heal.log" >&2
  exit 1
fi

echo "test_self_heal: PASS (audit fail-closed; release tests continue; unknown status recorded)"

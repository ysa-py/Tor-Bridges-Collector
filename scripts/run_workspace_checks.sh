#!/usr/bin/env bash
# run_workspace_checks.sh — Available-toolchain verification.
#
# Runs every local gate whose toolchain is present. Missing cargo/go/npm are
# recorded as SKIPPED and are never reported as green. The script fails if any
# executed gate fails.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0
RAN=()
SKIPPED=()

run_gate() {
  local name="$1"
  shift
  echo "═══ ${name} ═══"
  if "$@"; then
    echo "  ✓ ${name}"
    RAN+=("${name}")
  else
    echo "::error::${name} failed"
    FAIL=1
    RAN+=("${name} (FAILED)")
  fi
}

skip_gate() {
  local name="$1"
  local reason="$2"
  echo "═══ ${name} ═══"
  echo "  ⚠ skipped: ${reason} — not claimed green"
  SKIPPED+=("${name} (${reason})")
}

# ── Rust ────────────────────────────────────────────────────────
if command -v cargo >/dev/null 2>&1; then
  run_gate "Rust: cargo test --workspace" bash -c "cd \"$ROOT\" && cargo test --workspace"
else
  skip_gate "Rust: cargo test --workspace" "cargo not found"
fi

# ── Go ──────────────────────────────────────────────────────────
if command -v go >/dev/null 2>&1; then
  run_gate "Go: go test ./internal/..." bash -c "cd \"$ROOT\" && go test ./internal/..."
else
  skip_gate "Go: go test ./internal/..." "go not found"
fi

# ── Python golden vectors ───────────────────────────────────────
if command -v python3 >/dev/null 2>&1; then
  run_gate "Python golden vectors" bash "$ROOT/scripts/test_golden_vectors.sh"
  if [[ -f "$ROOT/scripts/test_probe_relay_smoke.sh" ]]; then
    run_gate "probe-relay smoke unit tests" bash "$ROOT/scripts/test_probe_relay_smoke.sh"
  fi
  if [[ -f "$ROOT/scripts/test_validate_probe_relay_secrets.sh" ]]; then
    run_gate "probe-relay secret validator tests" bash "$ROOT/scripts/test_validate_probe_relay_secrets.sh"
  fi
else
  skip_gate "Python golden vectors" "python3 not found"
fi

# ── probe-relay (Node) ──────────────────────────────────────────
if command -v npm >/dev/null 2>&1 && [[ -f "$ROOT/probe-relay/package.json" ]]; then
  if [[ ! -d "$ROOT/probe-relay/node_modules" ]]; then
    run_gate "probe-relay npm ci" npm --prefix "$ROOT/probe-relay" ci
  fi
  if [[ -d "$ROOT/probe-relay/node_modules" ]]; then
    run_gate "probe-relay typecheck" npm --prefix "$ROOT/probe-relay" run typecheck
    run_gate "probe-relay vitest" npm --prefix "$ROOT/probe-relay" test
  else
    skip_gate "probe-relay vitest" "node_modules missing after npm ci"
  fi
else
  skip_gate "probe-relay vitest" "npm not found"
fi

# ── ShellCheck ──────────────────────────────────────────────────
if command -v shellcheck >/dev/null 2>&1; then
  echo "═══ ShellCheck ═══"
  shell_fail=0
  while IFS= read -r -d '' script; do
    if ! shellcheck --severity=warning "$script"; then
      echo "::error::shellcheck failed: $script"
      shell_fail=1
    fi
  done < <(find "$ROOT" -type f \( -name '*.sh' -o -name '*.bash' \) \
    -not -path '*/.git/*' -not -path '*/vendor/*' -not -path '*/node_modules/*' -print0)
  if [[ "$shell_fail" -eq 0 ]]; then
    echo "  ✓ ShellCheck"
    RAN+=("ShellCheck")
  else
    FAIL=1
    RAN+=("ShellCheck (FAILED)")
  fi
else
  skip_gate "ShellCheck" "shellcheck not found"
fi

echo
if ((${#RAN[@]})); then echo "ran: ${RAN[*]}"; else echo "ran: none"; fi
if ((${#SKIPPED[@]})); then echo "skipped (not green): ${SKIPPED[*]}"; else echo "skipped (not green): none"; fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "═══ Available workspace checks: FAILED ═══"
  exit 1
fi
if [[ ${#RAN[@]} -eq 0 ]]; then
  echo "::error::no available gates executed"
  exit 1
fi
echo "═══ Available workspace checks: PASSED ═══"

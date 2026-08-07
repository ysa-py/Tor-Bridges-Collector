#!/usr/bin/env bash
# run_workspace_checks.sh — Unified workspace verification.
#
# Runs cargo test (Rust), go test (Go), and shellcheck across all workspace
# shell scripts in a single NUL-safe loop. Exits non-zero on first failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0

# ── Rust ────────────────────────────────────────────────────────
echo "═══ Rust: cargo test --workspace ═══"
if command -v cargo >/dev/null 2>&1; then
  ( cd "$ROOT" && cargo test --workspace ) || { echo "::error::cargo test failed"; FAIL=1; }
else
  echo "  ⚠ cargo not found — skipping Rust tests"
fi

# ── Go ──────────────────────────────────────────────────────────
echo "═══ Go: go test ./... ═══"
if command -v go >/dev/null 2>&1; then
  ( cd "$ROOT" && go test ./... ) || { echo "::error::go test failed"; FAIL=1; }
else
  echo "  ⚠ go not found — skipping Go tests"
fi

# ── ShellCheck ──────────────────────────────────────────────────
echo "═══ ShellCheck ═══"
if command -v shellcheck >/dev/null 2>&1; then
  while IFS= read -r -d '' script; do
    if ! shellcheck "$script"; then
      echo "::error::shellcheck failed: $script"
      FAIL=1
    fi
  done < <(find "$ROOT" -type f \( -name '*.sh' -o -name '*.bash' \) \
    -not -path '*/.git/*' -not -path '*/vendor/*' -print0)
else
  echo "  ⚠ shellcheck not found — skipping ShellCheck"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "═══ Workspace checks: FAILED ═══"
  exit 1
fi
echo "═══ Workspace checks: PASSED ═══"

#!/usr/bin/env bash
set -euo pipefail

# Self-healing automation script (safe mode)
# - Performs workspace validations (fmt, clippy, audit, tests)
# - Collects deterministic diagnostics into diagnostics/<timestamp>/
# - Does NOT modify source logic. Only fixes safe, workspace-level issues elsewhere (future scope).

TS=$(date -u +"%Y%m%dT%H%M%SZ")
DIAG_DIR="diagnostics/${TS}"
mkdir -p "${DIAG_DIR}"
EXIT_CODE=0

echo "[self-heal] Starting validation run at ${TS}"

# 1) cargo fmt check
echo "[self-heal] Running cargo fmt --all -- --check"
if ! cargo fmt --all -- --check 2>&1 | tee "${DIAG_DIR}/cargo-fmt.log"; then
  echo "[self-heal] cargo fmt reported issues"
  EXIT_CODE=1
else
  echo "[self-heal] cargo fmt OK"
fi

# 2) cargo clippy (treat warnings as errors) — capture output
echo "[self-heal] Running cargo clippy (warnings as errors)"
if ! cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee "${DIAG_DIR}/cargo-clippy.log"; then
  echo "[self-heal] cargo clippy reported warnings/errors"
  EXIT_CODE=1
else
  echo "[self-heal] cargo clippy OK"
fi

# 3) cargo audit — produce JSON report and human-readable logs
echo "[self-heal] Running cargo audit to produce JSON report"
# Ensure jq is available; if not, record warning but continue
if ! command -v jq >/dev/null 2>&1; then
  echo "[self-heal] Warning: jq not found on PATH — JSON parsing may fail" | tee "${DIAG_DIR}/self-heal-warnings.log"
fi

# Generate JSON report (allow non-zero exit so we can always parse)
cargo audit --json > "${DIAG_DIR}/audit-report.json" 2> "${DIAG_DIR}/cargo-audit-stderr.log" || true
# Capture human-readable output as well
cargo audit 2>&1 | tee "${DIAG_DIR}/cargo-audit-stdout.log" || true

# Deterministic parsing
VCOUNT=0
if [ -f "${DIAG_DIR}/audit-report.json" ]; then
  VCOUNT=$(jq -r '(.vulnerabilities.count // .vulnerabilities.found // (.vulnerabilities.list | length) // 0) as $c | ($c // 0)' "${DIAG_DIR}/audit-report.json" 2>/dev/null || echo 0)
  echo "[self-heal] cargo-audit reported vulnerability count: ${VCOUNT}"
  if [ "${VCOUNT}" -gt 0 ]; then
    EXIT_CODE=1
  fi
else
  echo "[self-heal] No audit-report.json produced"
fi

# 4) Run release tests (capture output)
echo "[self-heal] Running cargo test --workspace --release (this may take time)"
# Capture exit code carefully
set +o pipefail
cargo test --workspace --release 2>&1 | tee "${DIAG_DIR}/test-output.log"
TCODE=${PIPESTATUS[0]}
set -o pipefail
if [ ${TCODE} -ne 0 ]; then
  echo "[self-heal] Tests failed with exit code ${TCODE}"
  EXIT_CODE=1
else
  echo "[self-heal] Tests passed"
fi

# Finalize
if [ ${EXIT_CODE} -ne 0 ]; then
  echo "[self-heal] Validation detected issues. Diagnostics saved to ${DIAG_DIR}"
  # Create a lightweight index for diagnostics
  jq -n --arg ts "${TS}" --arg vcount "${VCOUNT}" '{timestamp: $ts, vulnerabilities: ($vcount|tonumber)}' > "${DIAG_DIR}/index.json" || true
  exit 1
fi

echo "[self-heal] All checks passed. No diagnostics generated."
exit 0

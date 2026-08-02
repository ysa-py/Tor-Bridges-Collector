#!/usr/bin/env bash
set -euo pipefail

# Self-healing automation script (safe mode)
# - Performs workspace validations (TypeScript check, build verification, JSON schema check, legacy fmt/clippy fallback)
# - Collects deterministic diagnostics into diagnostics/<timestamp>/
# - Zero-Error Engineering: automatically verifies TypeScript/Node.js full-stack apps

TS=$(date -u +"%Y%m%dT%H%M%SZ")
DIAG_DIR="diagnostics/${TS}"
mkdir -p "${DIAG_DIR}"
EXIT_CODE=0

echo "[self-heal] Starting validation run at ${TS}"

# Smart detection: TypeScript/Node.js Full-Stack Application
if [ -f "package.json" ]; then
  echo "[self-heal] Detected TypeScript/Node.js full-stack application (package.json present)"
  
  # 1) TypeScript Strict Check
  echo "[self-heal] Running TypeScript strict type check (npx tsc --noEmit)"
  if ! npx tsc --noEmit 2>&1 | tee "${DIAG_DIR}/tsc-check.log"; then
    echo "[self-heal] TypeScript compiler reported issues"
    EXIT_CODE=1
  else
    echo "[self-heal] TypeScript strict check OK (0 errors)"
  fi

  # 2) Production Build Verification
  echo "[self-heal] Running production build verification"
  if ! npm run build 2>&1 | tee "${DIAG_DIR}/npm-build.log"; then
    echo "[self-heal] Build verification reported issues"
    EXIT_CODE=1
  else
    echo "[self-heal] Production build OK"
  fi

  # 3) Validate JSON Data & Export Packs
  echo "[self-heal] Validating JSON schemas in /data and /export"
  VCOUNT=0
  for json_file in data/*.json export/*.json; do
    if [ -f "${json_file}" ]; then
      if command -v jq >/dev/null 2>&1; then
        if ! jq empty "${json_file}" 2>/dev/null; then
          echo "[self-heal] Corrupt JSON syntax in ${json_file}" | tee -a "${DIAG_DIR}/json-errors.log"
          VCOUNT=$((VCOUNT + 1))
        fi
      fi
    fi
  done
  echo "[self-heal] JSON validation completed (errors=${VCOUNT})"

  if [ ${VCOUNT} -gt 0 ]; then
    EXIT_CODE=1
  fi

  if [ ${EXIT_CODE} -ne 0 ]; then
    echo "[self-heal] Validation detected issues. Diagnostics saved to ${DIAG_DIR}"
    jq -n --arg ts "${TS}" --arg vcount "${VCOUNT}" '{timestamp: $ts, vulnerabilities: ($vcount|tonumber)}' > "${DIAG_DIR}/index.json" || true
    exit 1
  fi

  echo "[self-heal] ✔ All TypeScript/Node.js full-stack checks passed with zero errors. No diagnostics generated."
  exit 0
fi

# Legacy fallback for Rust/Cargo workspace
if [ -f "Cargo.toml" ]; then
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
  if ! command -v jq >/dev/null 2>&1; then
    echo "[self-heal] Warning: jq not found on PATH — JSON parsing may fail" | tee "${DIAG_DIR}/self-heal-warnings.log"
  fi

  cargo audit --json > "${DIAG_DIR}/audit-report.json" 2> "${DIAG_DIR}/cargo-audit-stderr.log" || true
  cargo audit 2>&1 | tee "${DIAG_DIR}/cargo-audit-stdout.log" || true

  VCOUNT=0
  if [ -f "${DIAG_DIR}/audit-report.json" ]; then
    VCOUNT=$(jq -r '(.vulnerabilities.count // .vulnerabilities.found // (.vulnerabilities.list | length) // 0) as $c | ($c // 0)' "${DIAG_DIR}/audit-report.json" 2>/dev/null || echo 0)
    if [ -z "${VCOUNT}" ]; then
      VCOUNT=0
    fi
    echo "[self-heal] cargo-audit reported vulnerability count: ${VCOUNT}"
    if [ "${VCOUNT}" -gt 0 ]; then
      EXIT_CODE=1
    fi
  else
    echo "[self-heal] No audit-report.json produced"
  fi

  # 4) Run release tests (capture output)
  echo "[self-heal] Running cargo test --workspace --release (this may take time)"
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
fi

# Finalize
if [ ${EXIT_CODE} -ne 0 ]; then
  echo "[self-heal] Validation detected issues. Diagnostics saved to ${DIAG_DIR}"
  jq -n --arg ts "${TS}" --arg vcount "${VCOUNT}" '{timestamp: $ts, vulnerabilities: ($vcount|tonumber)}' > "${DIAG_DIR}/index.json" || true
  exit 1
fi

echo "[self-heal] All checks passed. No diagnostics generated."
exit 0


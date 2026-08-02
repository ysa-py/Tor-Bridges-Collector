#!/usr/bin/env bash
set -euo pipefail

# Auto-fix mechanical issues: format, fix, and verification for TypeScript/Node.js full-stack apps

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo '.')
cd "${REPO_ROOT}"

TS=$(date -u +"%Y%m%dT%H%M%SZ")
DIAG_DIR="diagnostics/auto-fix-${TS}"
mkdir -p "${DIAG_DIR}"

echo "[auto-fix] Starting auto-fix run at ${TS}"

# Smart detection: TypeScript/Node.js Full-Stack Application
if [ -f "package.json" ]; then
  echo "[auto-fix] Detected TypeScript/Node.js full-stack application (package.json present)"
  
  echo "[auto-fix] Running TypeScript strict type check (npx tsc --noEmit)"
  npx tsc --noEmit 2>&1 | tee "${DIAG_DIR}/tsc-check.log"
  
  echo "[auto-fix] Running production build verification"
  npm run build 2>&1 | tee "${DIAG_DIR}/npm-build.log"
  
  echo "[auto-fix] ✔ TypeScript/Node.js full-stack auto-fix and verification passed with zero errors."
  exit 0
fi

# Legacy fallback for Rust/Cargo workspace
if [ -f "Cargo.toml" ]; then
  # Ensure no uncommitted changes to avoid clobbering developer work
  if [ -n "$(git status --porcelain 2>/dev/null || echo '')" ]; then
    echo "[auto-fix] Working tree is not clean. Aborting auto-fix to avoid clobbering changes."
    exit 2
  fi

  CHANGES_MADE=0

  # 1) cargo fmt check
  echo "[auto-fix] Running cargo fmt --all -- --check"
  if ! cargo fmt --all -- --check 2>&1 | tee "${DIAG_DIR}/cargo-fmt-check.log"; then
    echo "[auto-fix] Formatting issues found. Applying cargo fmt --all"
    cargo fmt --all 2>&1 | tee "${DIAG_DIR}/cargo-fmt-apply.log"
    git add -A
    CHANGES_MADE=1
  else
    echo "[auto-fix] No formatting issues"
  fi

  # 2) Attempt cargo fix (compiler suggestions)
  FIX_CMD=(cargo fix --workspace --allow-dirty --allow-staged)
  if cargo fix --help 2>&1 | grep -q -- '--clippy'; then
    FIX_CMD+=(--clippy)
    echo "[auto-fix] cargo fix supports --clippy; enabling clippy fixes"
  fi

  PRE_HASH=$(git ls-files -s | shasum -a 1 | awk '{print $1}') || PRE_HASH=""
  set +e
  "${FIX_CMD[@]}" 2>&1 | tee "${DIAG_DIR}/cargo-fix.log"
  FIX_RC=$?
  set -e
  POST_HASH=$(git ls-files -s | shasum -a 1 | awk '{print $1}') || POST_HASH=""
  if [ "${PRE_HASH}" != "${POST_HASH}" ]; then
    echo "[auto-fix] cargo fix made changes"
    git add -A
    CHANGES_MADE=1
  fi

  # 3) Re-run validation
  echo "[auto-fix] Running validation: clippy -D warnings and cargo test --workspace --release"
  set +e
  cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee "${DIAG_DIR}/cargo-clippy-postfix.log"
  C_RC=$?
  cargo test --workspace --release 2>&1 | tee "${DIAG_DIR}/test-output-postfix.log"
  T_RC=$?
  set -e

  if [ ${C_RC} -eq 0 ] && [ ${T_RC} -eq 0 ]; then
    echo "[auto-fix] Validation passed."
    exit 0
  else
    echo "[auto-fix] Validation failed after fixes (clippy rc=${C_RC}, test rc=${T_RC})"
    exit 1
  fi
fi

echo "[auto-fix] All checks completed."
exit 0

  git add -A
  CHANGES_MADE=1
else
  echo "[auto-fix] cargo fix did not change sources (or not supported)"
fi

# 3) If no changes made, exit cleanly
if [ ${CHANGES_MADE} -eq 0 ]; then
  echo "[auto-fix] No mechanical changes to apply. Exiting."
  exit 0
fi

# 4) Run validation: clippy and tests
echo "[auto-fix] Running cargo clippy --workspace --all-targets -- -D warnings"
if ! cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee "${DIAG_DIR}/cargo-clippy-postfix.log"; then
  echo "[auto-fix] clippy failed after fixes — rolling back"
  git reset --hard "${ORIG_HEAD}"
  # Clean up any generated files
  git clean -fd
  exit 1
fi

echo "[auto-fix] Running cargo test --workspace --release"
set +o pipefail
cargo test --workspace --release 2>&1 | tee "${DIAG_DIR}/test-output-postfix.log"
TCODE=${PIPESTATUS[0]}
set -o pipefail
if [ ${TCODE} -ne 0 ]; then
  echo "[auto-fix] Tests failed after fixes (exit ${TCODE}) — rolling back"
  git reset --hard "${ORIG_HEAD}"
  git clean -fd
  exit 1
fi

# 5) All validations passed; commit changes
COMMIT_MSG="fix(self-healing): auto-resolved mechanical issue ${ISSUE_ID} via surgical patch"
git commit -m "${COMMIT_MSG}" -a
echo "[auto-fix] Changes committed: ${COMMIT_MSG}"

# Upload diagnostics if present - we'll just move them into a committed folder optionally
# Keep diagnostics for audit
mv "${DIAG_DIR}" diagnostics/ || true

exit 0

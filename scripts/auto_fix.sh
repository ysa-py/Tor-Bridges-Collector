#!/usr/bin/env bash
set -euo pipefail

# Auto-fix mechanical issues: format, cargo fix (including clippy-suggested fixes if supported)
# Workflow:
# 1. Ensure clean working tree
# 2. Run cargo fmt check -> if fail, run cargo fmt --all
# 3. Run cargo fix (with --clippy if supported) to apply automated fixes
# 4. Re-run validation (clippy -D warnings, tests)
# 5. If validation passes: commit changes with message
# 6. If validation fails: rollback to original HEAD

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo '.')
cd "${REPO_ROOT}"

# Ensure no uncommitted changes to avoid clobbering developer work
if [ -n "$(git status --porcelain)" ]; then
  echo "[auto-fix] Working tree is not clean. Aborting auto-fix to avoid clobbering changes."
  exit 2
fi

ORIG_HEAD=$(git rev-parse --verify HEAD)
TS=$(date -u +"%Y%m%dT%H%M%SZ")
ISSUE_ID="mechanical-${TS}"
DIAG_DIR="diagnostics/auto-fix-${TS}"
mkdir -p "${DIAG_DIR}"
CHANGES_MADE=0

echo "[auto-fix] Starting auto-fix run (${ISSUE_ID})"

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
# Check if cargo fix supports --clippy
if cargo fix --help 2>&1 | grep -q -- '--clippy'; then
  FIX_CMD+=(--clippy)
  echo "[auto-fix] cargo fix supports --clippy; enabling clippy fixes"
fi

# Run cargo fix only if needed
# We'll run it and detect if any files changed
PRE_HASH=$(git ls-files -s | shasum -a 1 | awk '{print $1}') || PRE_HASH=""
set +e
"${FIX_CMD[@]}" 2>&1 | tee "${DIAG_DIR}/cargo-fix.log"
# shellcheck disable=SC2034
FIX_RC=$?
set -e
POST_HASH=$(git ls-files -s | shasum -a 1 | awk '{print $1}') || POST_HASH=""
if [ "${PRE_HASH}" != "${POST_HASH}" ]; then
  echo "[auto-fix] cargo fix made changes"
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

#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════
# scripts/circleci_packaging.sh — emits the final distribution archive.
#
# Output:
#   dist/ultra-main-vip-zero-error-quantum-ultra.tar.gz
#
# This script is additive — it does NOT delete or modify any existing file.
# It only collects, checksums, and archives the project tree into a single
# distributable tarball.
# ════════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_NAME="ultra-main-vip-zero-error-quantum-ultra"
STAGE_DIR="$ROOT/dist/stage-$ARCHIVE_NAME"
OUT_FILE="$ROOT/dist/$ARCHIVE_NAME.tar.gz"

mkdir -p "$ROOT/dist"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/$ARCHIVE_NAME"

echo "── Staging project tree ─────────────────────────────────────────"
# Copy everything except heavy CI caches, virtualenvs, and dist/ itself.
rsync -a \
    --exclude='.git/' \
    --exclude='node_modules/' \
    --exclude='.venv/' \
    --exclude='venv/' \
    --exclude='__pycache__/' \
    --exclude='.pytest_cache/' \
    --exclude='.mypy_cache/' \
    --exclude='.ruff_cache/' \
    --exclude='.cache/' \
    --exclude='target/' \
    --exclude='dist/' \
    --exclude='*.pyc' \
    --exclude='*.log.*' \
    "$ROOT/" "$STAGE_DIR/$ARCHIVE_NAME/"

# Write a build manifest at the archive root.
cat > "$STAGE_DIR/$ARCHIVE_NAME/BUILD_INFO.txt" <<EOF
TorShield-IR — Ultra VIP Zero-Error Quantum Edition
Build time (UTC) : $VERSION
Built on         : CircleCI
Pipeline         : ${CIRCLE_BUILD_URL:-local}
Branch           : ${CIRCLE_BRANCH:-unknown}
Commit           : ${CIRCLE_SHA1:-unknown}
Archive          : $ARCHIVE_NAME.tar.gz

Layout:
  .circleci/                  CircleCI config + setup README (THIS pipeline)
  .github/workflows/          GitHub Actions (preserved, untouched)
  .gitlab-ci.yml + .gitlab/ci GitLab CI (preserved; includes fixed)
  internal/ooni/client.go     OONI API client (api.ooni.io)
  scripts/circleci_ooni_poller.py  Scheduled OONI snapshot writer
  scripts/circleci_env_bootstrap.sh  Materialises .env from CircleCI Context
  scripts/circleci_packaging.sh     This script
EOF

echo "── Generating checksums ────────────────────────────────────────"
cd "$STAGE_DIR"
find "$ARCHIVE_NAME" -type f -print0 \
    | xargs -0 sha256sum \
    | sed "s|  $ARCHIVE_NAME/|  |" > "$ARCHIVE_NAME/CHECKSUMS.sha256"

echo "── Building tarball ────────────────────────────────────────────"
mkdir -p "$ROOT/dist"
tar -czf "$OUT_FILE" "$ARCHIVE_NAME"

# Clean up the staging dir to keep the workspace tidy.
rm -rf "$STAGE_DIR"

echo
echo "✓ Archive built:"
echo "    $OUT_FILE"
echo "    size: $(du -h "$OUT_FILE" | cut -f1)"
echo "    sha256: $(sha256sum "$OUT_FILE" | cut -d' ' -f1)"

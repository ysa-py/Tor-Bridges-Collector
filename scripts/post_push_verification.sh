#!/usr/bin/env bash
# Post-push publication verification (directive v43 §G).
#
# Re-downloads the published payload from the raw GitHub CDN and compares
# every SHA-256 against bridge/telegram_manifest.json — the same contract the
# pre-push publisher verified, but measured against what the CDN actually
# serves after the push. Closes the last gap between "the worktree was
# verified" and "main's published bytes are the verified bytes".
#
# Fail-closed: after the bounded retry budget a mismatch or missing file
# exits 1 with a ::error:: annotation. CDN propagation lag is absorbed by
# the retry loop (raw.githubusercontent serves the pushed commit lazily for
# a few seconds on rare occasions).
#
# Never prints secrets. Bridge line contents are never printed; only file
# names, SHA-256 prefixes, and HTTP codes are logged.
set -euo pipefail
export LC_ALL=C

BRIDGE_DIR="${1:-bridge}"
BRANCH="${POST_PUSH_VERIFY_BRANCH:-main}"
ATTEMPTS="${POST_PUSH_VERIFY_ATTEMPTS:-5}"
SLEEP_SECS="${POST_PUSH_VERIFY_SLEEP_SECS:-10}"
# Every payload file listed in the manifest is verified (no sampling): the
# payload is small text files and the whole point is byte-level certainty.

repo="${GITHUB_REPOSITORY:-ysa-py/Tor-Bridges-Collector}"
base_url="https://raw.githubusercontent.com/${repo}/refs/heads/${BRANCH}"
manifest_local="${BRIDGE_DIR}/telegram_manifest.json"

if [[ ! -s "$manifest_local" ]]; then
  echo "::error::post-push verification cannot run: ${manifest_local} is missing"
  exit 1
fi

manifest_downloaded="$(mktemp)"
trap 'rm -f "$manifest_downloaded"' EXIT

fetch_manifest() {
  local attempt code
  for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
    code="$(curl --silent --show-error --max-time 30 --connect-timeout 15 \
      --output "$manifest_downloaded" \
      --write-out '%{http_code}' "${base_url}/bridge/telegram_manifest.json" 2>/dev/null || echo 000)"
    if [[ "$code" == 200 ]] && jq -e '.required_files_present == true' "$manifest_downloaded" >/dev/null 2>&1; then
      echo "manifest fetched from ${BRANCH} (attempt ${attempt}/${ATTEMPTS}, HTTP 200)"
      return 0
    fi
    echo "manifest fetch attempt ${attempt}/${ATTEMPTS}: HTTP ${code}; retrying in ${SLEEP_SECS}s"
    sleep "$SLEEP_SECS"
  done
  echo "::error::post-push verification could not download telegram_manifest.json from ${BRANCH} after ${ATTEMPTS} attempts (last HTTP ${code})"
  return 1
}

# The pushed manifest must be byte-identical to the verified local one:
# GitHub serves the commit we just pushed, so any drift is a real defect.
if ! fetch_manifest; then
  exit 1
fi
if ! cmp -s "$manifest_local" "$manifest_downloaded"; then
  echo "::error::post-push manifest drift: the ${BRANCH} telegram_manifest.json differs from the verified local bytes (SHA-256 local=$(sha256sum "$manifest_local" | cut -c1-16)… remote=$(sha256sum "$manifest_downloaded" | cut -c1-16)…)"
  exit 1
fi
echo "✅ post-push manifest byte-identical to the verified publication"

# Verify every payload file's SHA-256 exactly as --verify-only does locally.
names="$(jq -r '.files[] | select(.name != "telegram_manifest.json") | .name' "$manifest_downloaded")"
total=0
verified=0
failed_files=()
while IFS= read -r name; do
  [[ -n "$name" ]] || continue
  total=$((total + 1))
  expected="$(jq -r --arg n "$name" '.files[] | select(.name == $n) | .sha256' "$manifest_downloaded")"
  fetched="$(mktemp)"
  code=000
  for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
    code="$(curl --silent --show-error --max-time 45 --connect-timeout 15 \
      --output "$fetched" \
      --write-out '%{http_code}' "${base_url}/bridge/${name}" 2>/dev/null || echo 000)"
    [[ "$code" == 200 ]] && break
    sleep "$SLEEP_SECS"
  done
  if [[ "$code" != 200 ]]; then
    failed_files+=("${name}: HTTP ${code}")
  elif [[ "$(sha256sum "$fetched" | cut -d' ' -f1)" != "$expected" ]]; then
    failed_files+=("${name}: sha256 drift")
  else
    verified=$((verified + 1))
  fi
  rm -f "$fetched"
done <<< "$names"

if (( ${#failed_files[@]} > 0 )); then
  for entry in "${failed_files[@]}"; do
    echo "::error::post-push verification mismatch: ${entry%%:*} — ${entry#*:} (raw URL ${base_url}/bridge/${entry%%:*})"
  done
  echo "::error::post-push verification failed for ${#failed_files[@]}/${total} payload file(s); the published ${BRANCH} bytes do not match the manifest"
  exit 1
fi

echo "✅ post-push verification passed: ${verified}/${total} payload files re-downloaded from ${BRANCH} and byte-verified against telegram_manifest.json"

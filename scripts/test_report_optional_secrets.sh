#!/usr/bin/env bash
# Hermetic tests for the optional-secret reporter; all inputs are booleans.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
reporter="$script_dir/report_optional_secrets.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

empty_output="$(env -i PATH="$PATH" GITHUB_OUTPUT="$tmp_dir/empty.out" bash "$reporter")"
grep -Fq 'Optional secrets available: 0/5' <<<"$empty_output"
grep -Fq 'result=not_configured' "$tmp_dir/empty.out"
grep -Fq '::warning::No optional AI/provider secrets configured' <<<"$empty_output"

partial_output="$(env -i PATH="$PATH" \
  HAS_CEREBRAS_API_KEY_1=true \
  HAS_CF_API_TOKEN_1=true \
  bash "$reporter")"
grep -Fq 'Optional secrets available: 2/5' <<<"$partial_output"

full_output="$(env -i PATH="$PATH" \
  HAS_CEREBRAS_API_KEY_1=true \
  HAS_PORTKEY_API_KEY_1=true \
  HAS_CF_ACCOUNT_ID_1=true \
  HAS_CF_API_TOKEN_1=true \
  HAS_GH_PAT_AUTOFIX=true \
  GITHUB_OUTPUT="$tmp_dir/full.out" \
  bash "$reporter")"
grep -Fq 'Optional secrets available: 5/5' <<<"$full_output"
grep -Fq 'result=passed' "$tmp_dir/full.out"

# Refuse a raw value and ensure it never appears in emitted diagnostics.
if env -i PATH="$PATH" HAS_CEREBRAS_API_KEY_1='raw-test-value' \
  bash "$reporter" >"$tmp_dir/invalid.out" 2>&1; then
  echo 'reporter accepted a non-boolean value' >&2
  exit 1
fi
if grep -Fq 'raw-test-value' "$tmp_dir/invalid.out"; then
  echo 'reporter leaked an input value' >&2
  exit 1
fi
grep -Fq 'must be a boolean presence flag' "$tmp_dir/invalid.out"

echo 'Optional-secret reporter tests passed.'

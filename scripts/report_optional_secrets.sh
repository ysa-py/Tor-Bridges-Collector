#!/usr/bin/env bash
# Report optional GitHub-secret availability without ever passing secret values
# to the runner. Callers must provide HAS_<SECRET_NAME>=true|false booleans.
set -euo pipefail

readonly secret_names=(
  CEREBRAS_API_KEY_1
  PORTKEY_API_KEY_1
  CF_ACCOUNT_ID_1
  CF_API_TOKEN_1
  GH_PAT_AUTOFIX
)

available=0
for secret_name in "${secret_names[@]}"; do
  flag_name="HAS_${secret_name}"
  value="${!flag_name:-false}"
  case "$value" in
    true)
      printf '  ✓ %s is configured\n' "$secret_name"
      available=$((available + 1))
      ;;
    false|'')
      printf '  - %s is not configured (optional)\n' "$secret_name"
      ;;
    *)
      printf '::error::%s must be a boolean presence flag; do not pass secret values.\n' "$flag_name"
      exit 2
      ;;
  esac
done

total=${#secret_names[@]}
printf 'Optional secrets available: %s/%s\n' "$available" "$total"
if (( available == 0 )); then
  result=not_configured
  printf '::warning::No optional AI/provider secrets configured; continuing with offline Rust-native checks.\n'
elif (( available < total )); then
  result=partial
  printf '::notice::Some optional AI/provider secrets are configured; offline checks remain available.\n'
else
  result=passed
fi

# GitHub step outputs let the quality report distinguish absent optional
# secrets from a failed check without exposing any values.
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'result=%s\navailable=%s\ntotal=%s\n' "$result" "$available" "$total" >> "$GITHUB_OUTPUT"
fi

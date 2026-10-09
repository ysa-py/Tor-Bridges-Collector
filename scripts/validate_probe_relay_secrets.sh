#!/usr/bin/env bash
# Validate optional Stage 4 relay credentials without disclosing any values.
# Presence flags are explicit because GitHub Actions materializes unset secrets
# as empty environment variables for steps that declare them.
set -euo pipefail

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo '::error::GITHUB_OUTPUT is required for Stage 4 secret validation.'
  exit 2
fi

validate_secret() {
  local name="$1"
  local raw_val="$2"
  local is_present="$3"
  local format_check="$4"
  local trimmed

  if [[ "$is_present" != true ]]; then
    echo "::warning::Stage 4 secret '${name}' is not configured; relay deployment and Stage 4 will be skipped."
    return 1
  fi

  # Trim surrounding whitespace without xargs parsing/rewriting secret values.
  trimmed="${raw_val#"${raw_val%%[![:space:]]*}"}"
  trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
  if [[ -z "$trimmed" ]]; then
    echo "::warning::Stage 4 secret '${name}' is configured but blank; Stage 4 will be skipped."
    return 1
  fi
  if [[ "$raw_val" != "$trimmed" ]]; then
    echo "::warning::Stage 4 secret '${name}' has leading or trailing whitespace (value redacted); Stage 4 will be skipped."
    return 1
  fi

  case "$format_check" in
    HTTPS_URL)
      if ! printf '%s' "$trimmed" | grep -qE '^https://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+(/[^[:space:]?#@]*)?/?$'; then
        echo "::warning::Stage 4 secret '${name}' is not a valid HTTPS endpoint (value redacted; queries, fragments, and user-info are not allowed)."
        return 1
      fi
      ;;
    CF_ACCOUNT_ID)
      if ! printf '%s' "$trimmed" | grep -qE '^[a-f0-9]{32}$'; then
        echo "::warning::Stage 4 secret '${name}' is not a valid Cloudflare Account ID (value redacted)."
        return 1
      fi
      ;;
    CF_API_TOKEN)
      if [[ "${#trimmed}" -lt 20 ]]; then
        echo "::warning::Stage 4 secret '${name}' is too short to be a valid Cloudflare API token (value redacted)."
        return 1
      fi
      ;;
    NONEMPTY) ;;
    *)
      echo '::error::Internal error: unknown Stage 4 secret validation rule.'
      return 2
      ;;
  esac

  echo "  ✓ ${name} is configured and valid."
}

errors=0
validate_secret 'PROBE_RELAY_URL' "${PROBE_RELAY_URL:-}" "${HAS_PROBE_RELAY_URL:-false}" HTTPS_URL || errors=$((errors + 1))
validate_secret 'PROBE_RELAY_TOKEN' "${PROBE_RELAY_TOKEN:-}" "${HAS_PROBE_RELAY_TOKEN:-false}" NONEMPTY || errors=$((errors + 1))
validate_secret 'CF_WORKER_ACCOUNT_ID' "${CF_WORKER_ACCOUNT_ID:-}" "${HAS_CF_WORKER_ACCOUNT_ID:-false}" CF_ACCOUNT_ID || errors=$((errors + 1))
validate_secret 'CF_WORKER_API_TOKEN' "${CF_WORKER_API_TOKEN:-}" "${HAS_CF_WORKER_API_TOKEN:-false}" CF_API_TOKEN || errors=$((errors + 1))

if (( errors > 0 )); then
  echo 'PROBE_RELAY_SKIP=true' >> "$GITHUB_OUTPUT"
  echo "::notice::${errors} Stage 4 secret(s) are missing, blank, or invalid; Stage 4 will be skipped. Collection and publication continue."
fi

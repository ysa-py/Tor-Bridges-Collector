#!/usr/bin/env bash
# Validate required authenticated relay credentials and optional deploy credentials.
# Presence flags are explicit because GitHub Actions materializes unset secrets as empty values.
set -euo pipefail
export LC_ALL=C

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo '::error::GITHUB_OUTPUT is required for probe relay secret validation.'
  exit 2
fi

validate_secret() {
  local name="$1"
  local raw_val="$2"
  local is_present="$3"
  local format_check="$4"
  local trimmed

  if [[ "$is_present" != true ]]; then
    echo "::warning::Required secret '${name}' is not configured (value redacted)."
    return 1
  fi

  trimmed="${raw_val#"${raw_val%%[![:space:]]*}"}"
  trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
  if [[ -z "$trimmed" ]]; then
    echo "::warning::Secret '${name}' is configured but blank (value redacted)."
    return 1
  fi
  if [[ "$raw_val" != "$trimmed" ]]; then
    echo "::warning::Secret '${name}' has leading or trailing whitespace (value redacted)."
    return 1
  fi

  case "$format_check" in
    HTTPS_URL)
      if (( ${#trimmed} > 2048 )) || [[ "$trimmed" == *'?'* || "$trimmed" == *'#'* || "$trimmed" == *'@'* || "$trimmed" == *'"'* || "$trimmed" == *\\* || "$trimmed" == *$'\r'* || "$trimmed" == *$'\n'* || "$trimmed" == *[[:space:]]* || "$trimmed" == *[[:cntrl:]]* ]] || \
         ! printf '%s' "$trimmed" | grep -qE '^https://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})(/[^[:space:]?#@"]*)?/?$'; then
        echo "::warning::Secret '${name}' is not a valid safe HTTPS relay endpoint (URL redacted; user-info, queries, fragments, quotes, backslashes, and whitespace are disallowed)."
        return 1
      fi
      ;;
    CF_ACCOUNT_ID)
      if ! printf '%s' "$trimmed" | grep -qE '^[a-f0-9]{32}$'; then
        echo "::warning::Secret '${name}' is not a valid Cloudflare Account ID (value redacted)."
        return 1
      fi
      ;;
    CF_API_TOKEN)
      if [[ ${#trimmed} -lt 20 || ${#trimmed} -gt 1024 || "$trimmed" == *[[:cntrl:]]* ]]; then
        echo "::warning::Secret '${name}' is not a valid Cloudflare API token (value redacted)."
        return 1
      fi
      ;;
    TOKEN)
      if [[ ${#trimmed} -lt 16 || ${#trimmed} -gt 1024 || "$trimmed" == *[[:cntrl:]]* ]]; then
        echo "::warning::Secret '${name}' must contain 16-1024 printable characters (value redacted)."
        return 1
      fi
      ;;
    *)
      echo '::error::Internal error: unknown probe relay secret validation rule.'
      return 2
      ;;
  esac

  echo "  ✓ ${name} is configured and valid."
}

relay_errors=0
deploy_errors=0
validate_secret 'PROBE_RELAY_URL' "${PROBE_RELAY_URL:-}" "${HAS_PROBE_RELAY_URL:-false}" HTTPS_URL || relay_errors=$((relay_errors + 1))
validate_secret 'PROBE_RELAY_TOKEN' "${PROBE_RELAY_TOKEN:-}" "${HAS_PROBE_RELAY_TOKEN:-false}" TOKEN || relay_errors=$((relay_errors + 1))

# Existing production Workers can still be smoke-tested securely when the
# optional deploy credentials are absent; deployment is skipped separately.
validate_secret 'CF_WORKER_ACCOUNT_ID' "${CF_WORKER_ACCOUNT_ID:-}" "${HAS_CF_WORKER_ACCOUNT_ID:-false}" CF_ACCOUNT_ID || deploy_errors=$((deploy_errors + 1))
validate_secret 'CF_WORKER_API_TOKEN' "${CF_WORKER_API_TOKEN:-}" "${HAS_CF_WORKER_API_TOKEN:-false}" CF_API_TOKEN || deploy_errors=$((deploy_errors + 1))

if (( relay_errors > 0 )); then
  echo 'PROBE_RELAY_SKIP=true' >> "$GITHUB_OUTPUT"
  echo 'PROBE_RELAY_DEPLOY_SKIP=true' >> "$GITHUB_OUTPUT"
  echo "::notice::${relay_errors} required relay credential(s) are missing, blank, or invalid; authenticated relay calls and Stage 4 are skipped."
elif (( deploy_errors > 0 )); then
  echo 'PROBE_RELAY_DEPLOY_SKIP=true' >> "$GITHUB_OUTPUT"
  echo "::notice::${deploy_errors} optional Cloudflare deployment credential(s) are missing, blank, or invalid; deployment is skipped, but the authenticated live canary still runs."
fi

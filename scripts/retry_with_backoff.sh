#!/usr/bin/env bash
set -euo pipefail

max_attempts=3
sleep_base=2
sleep_max=60
args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-attempts)
      max_attempts="$2"
      shift 2
      ;;
    --sleep-base)
      sleep_base="$2"
      shift 2
      ;;
    --sleep-max)
      sleep_max="$2"
      shift 2
      ;;
    --)
      shift
      args=("$@")
      break
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

if [[ ${#args[@]} -eq 0 ]]; then
  echo "usage: retry_with_backoff.sh [--max-attempts N] [--sleep-base N] [--sleep-max N] -- command [args...]" >&2
  exit 2
fi

attempt=1
while true; do
  set +e
  "${args[@]}"
  status=$?
  set -e

  if [[ $status -eq 0 ]] || [[ $attempt -ge $max_attempts ]]; then
    exit "$status"
  fi

  delay=$sleep_base
  if (( delay > sleep_max )); then
    delay=$sleep_max
  fi
  if (( attempt > 1 )); then
    delay=$(( delay * attempt ))
    if (( delay > sleep_max )); then
      delay=$sleep_max
    fi
  fi

  echo "command failed with exit $status (attempt $attempt/$max_attempts); retrying in ${delay}s" >&2
  sleep "$delay"
  attempt=$((attempt + 1))
done

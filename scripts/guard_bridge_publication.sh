#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# guard_bridge_publication.sh — empty-output / degraded-run publication guard
# (ENGINEERING DIRECTIVE v42 §A: "Empty files must never be committed silently")
#
# What it does, in order:
#   1. Collects degradation signals for this run:
#        - bridge/iran_results.json summary.run_deadline_exceeded == true
#        - a data/run_state.json marker written by a failed/degraded stage
#        - missing/empty data/pt_results.json on a live collection run
#   2. When the run is degraded, restores the last-known-good (HEAD) version
#      of every REQUIRED bridge/ file that the new run would have wiped
#      (empty or missing while HEAD holds a non-empty version). Healthy runs
#      are trusted: deliberate evidence churn (e.g. a publication filter
#      removing fake supply) is legitimate.
#   2b. After any restore, re-attests the publication contract
#      (scripts/publication_contract.sh --rebuild --set-count ...): Stage 9
#      attested telegram_manifest.json / tor_bridges.zip / README.md against
#      the PRE-restore payload bytes, so without re-attestation --check
#      rejects the mixed publication and Stage 11 pushes nothing (the
#      2026-10-13/14 webtunnel wipe failures, runs 38465273560 and
#      38477508742, failed exactly here: 12 contract violations, exit 1,
#      no publication commit). Re-attestation makes the restored publication
#      internally consistent again: manifest hashes/sizes point at the
#      restored bytes, the archive is rebuilt deterministically from them,
#      and the README archive hash is patched.
#   3. Writes data/run_manifest.json: per-file line count, byte size and
#      SHA-256 for the complete REQUIRED set, plus the degradation verdict —
#      the integrity/freshness manifest consumers and the step summary read.
#   4. Appends a per-class summary to $GITHUB_STEP_SUMMARY when available.
#
# The REQUIRED set is read from bridge/telegram_manifest.json (written by the
# same Stage 9 publisher that produced this run's payload), extended with the
# manifest and the archive themselves, so the guard can never drift from the
# publication contract.
#
# Usage: scripts/guard_bridge_publication.sh [--bridge-dir bridge] [--live true|false] [--root DIR]
# Exit codes: 0 = publication may proceed; 1 = contract violation, which
# fails the run loudly; 2 = re-attestation refused (corrupt payload / usage).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BRIDGE_DIR="bridge"
LIVE="true"
while [ $# -gt 0 ]; do
  case "$1" in
    --bridge-dir) BRIDGE_DIR="$2"; shift 2 ;;
    --live) LIVE="$2"; shift 2 ;;
    --root) ROOT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

MANIFEST="${BRIDGE_DIR}/telegram_manifest.json"
if [ ! -s "${MANIFEST}" ]; then
  echo "::error::publication guard requires ${MANIFEST} (Stage 9 output) and it is missing or empty"
  exit 1
fi
if ! jq -e '.files | type == "array"' "${MANIFEST}" > /dev/null 2>&1; then
  echo "::error::${MANIFEST} does not contain a files array; refusing to guard an unknown contract"
  exit 1
fi

restored=0
restored_list=""
degraded=false
degraded_reasons=()

# ── 1) Degradation signals ────────────────────────────────────────────────────
if [ -f "${BRIDGE_DIR}/iran_results.json" ]; then
  if [ "$(jq -r '.summary.run_deadline_exceeded // false' "${BRIDGE_DIR}/iran_results.json" 2>/dev/null)" = "true" ]; then
    degraded=true
    degraded_reasons+=("iran_tester run deadline exceeded")
  fi
fi
if [ -f data/run_state.json ]; then
  if [ "$(jq -r '.degraded // false' data/run_state.json 2>/dev/null)" = "true" ]; then
    degraded=true
    degraded_reasons+=("$(jq -r '.reason // "a stage reported degraded"' data/run_state.json 2>/dev/null)")
  fi
fi
if [ "${LIVE}" = "true" ] && { [ ! -s data/pt_results.json ] || [ "$(jq 'length' data/pt_results.json 2>/dev/null || echo 0)" = "0" ]; }; then
  degraded=true
  degraded_reasons+=("no probe observations recorded this run (data/pt_results.json empty)")
fi

# ── 2) Wipe guard on degraded runs ───────────────────────────────────────────
# Every contract file: the Stage 9 inventory + the manifest + the archive.
required_list="$(jq -r '.files[].name' "${MANIFEST}"; echo "telegram_manifest.json"; echo "tor_bridges.zip")"
required_count="$(printf '%s\n' ${required_list} | sed '/^$/d' | sort -u | wc -l | tr -d ' ')"

for name in ${required_list}; do
  [ -n "${name}" ] || continue
  path="${BRIDGE_DIR}/${name}"
  head_nonempty=false
  if git cat-file -e "HEAD:${path}" 2>/dev/null; then
    if [ "$(git show "HEAD:${path}" 2>/dev/null | wc -c)" -gt 0 ]; then
      head_nonempty=true
    fi
  fi
  if [ "${degraded}" = "true" ] && [ "${head_nonempty}" = "true" ] && [ ! -s "${path}" ]; then
    git checkout HEAD -- "${path}"
    restored=$((restored + 1))
    restored_list="${restored_list} ${name}"
    echo "::warning::degraded run: restored last-known-good ${path} instead of committing an empty file"
  fi
  if [ ! -f "${path}" ]; then
    echo "::error::REQUIRED bridge file missing from the publication tree: ${path}"
    exit 1
  fi
done

# ── 2b) Re-attest the publication after any last-known-good restore ──────────
# Stage 9 attested the manifest/ZIP/README against this run's payload. Once the
# wipe guard above replaced empty payload files with last-known-good blobs,
# those attested artifacts describe bytes that are no longer on disk, and the
# fail-closed contract check in Stage 11 would reject the commit. Re-attest
# here, exactly the way the contract prescribes: --rebuild --set-count for
# every restored file. Payload bytes are never rewritten by this step; only
# the manifest hashes/sizes, the deterministic archive and the README archive
# hash are re-aligned to what is actually about to be committed.
if [ "${restored}" -gt 0 ]; then
  set_counts=()
  for name in ${restored_list}; do
    [ -n "${name}" ] || continue
    path="${BRIDGE_DIR}/${name}"
    [ -f "${path}" ] || continue
    case "${name}" in
      *.json)
        count="$(jq '(if type == "array" then length
                      elif has("bridges") then (.bridges | length)
                      elif has("records") then (.records | length)
                      elif has("results") then (.results | length)
                      elif has("entries") then (.entries | length)
                      else length end)' "${path}" 2>/dev/null || echo 0)" || count=0
        ;;
      *)
        count="$(grep -c . "${path}" 2>/dev/null || true)" || count=0
        ;;
    esac
    count="${count//[$'\t\r\n ']/}"
    count="${count:-0}"
    set_counts+=(--set-count "${name}=${count}")
  done
  echo "re-attesting publication after restoring ${restored} last-known-good file(s)"
  bash "${SCRIPT_DIR}/publication_contract.sh" --rebuild --root "${ROOT}" --bridge-dir "${BRIDGE_DIR}" "${set_counts[@]}"
fi

# ── 3) Run manifest (counts + SHA-256) ───────────────────────────────────────
mkdir -p data
manifest_tmp="$(mktemp)"
reasons_json="$(for reason in ${degraded_reasons[@]+"${degraded_reasons[@]}"}; do jq -Rn --arg r "$reason" '$r'; done | jq -sc .)"
restored_json="$(for name in ${restored_list}; do echo "${name}"; done | jq -Rsc 'split("\n") | map(select(length > 0))')"
{
  printf '{\n'
  printf '  "generated_at": "%s",\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  printf '  "degraded": %s,\n' "${degraded}"
  printf '  "degraded_reasons": %s,\n' "${reasons_json}"
  printf '  "restored_last_known_good": %s,\n' "${restored_json}"
  printf '  "files": {\n'
  first=1
  for name in ${required_list}; do
    [ -n "${name}" ] || continue
    path="${BRIDGE_DIR}/${name}"
    bytes="$(wc -c < "${path}" | tr -d ' ')"
    lines="$(wc -l < "${path}" | tr -d ' ')"
    sha="$(sha256sum "${path}" | cut -d' ' -f1)"
    [ "${first}" = "1" ] || printf ',\n'
    first=0
    printf '    "%s": {"bytes": %s, "lines": %s, "sha256": "%s"}' "${name}" "${bytes}" "${lines}" "${sha}"
  done
  printf '\n  }\n}\n'
} > "${manifest_tmp}"
jq -e . "${manifest_tmp}" > /dev/null 2>&1 || { echo "::error::run manifest failed to validate"; exit 1; }
mv "${manifest_tmp}" data/run_manifest.json

# ── 4) Step summary ───────────────────────────────────────────────────────────
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Publication guard"
    echo "- degraded: \`${degraded}\`"
    for reason in ${degraded_reasons[@]+"${degraded_reasons[@]}"}; do
      [ -n "${reason}" ] || continue
      echo "- signal: ${reason}"
    done
    echo "- restored_last_known_good: \`${restored}\` file(s)"
    if [ "${restored}" -gt 0 ]; then
      echo "- re-attested: manifest/ZIP/README re-aligned to the restored bytes"
    fi
    echo "- required files: \`${required_count}\`"
    echo "- manifest: \`data/run_manifest.json\` (line count, byte size, SHA-256 per file)"
  } >> "${GITHUB_STEP_SUMMARY}" 2>/dev/null || true
fi

echo "guard: degraded=${degraded} restored=${restored} required=${required_count}"
exit 0

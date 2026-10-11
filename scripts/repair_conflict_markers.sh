#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Self-heal generated files that were committed with git conflict markers.
#
# Root cause this guards against (2026-10-11): Stage 11 ran
# `git pull origin main --rebase --autostash` AFTER the pipeline had already
# regenerated bridge/ + data/. The autostash replayed that fresh output on top
# of the previous hourly publication commit, which had rewritten the very same
# generated files, so git wrote `<<<<<<< Updated upstream` / `=======` /
# `>>>>>>> Stashed changes` into 56 JSON/text files. The following `git add`
# committed the corrupt payload, and every later run read invalid
# bridge_history.json / iran_results.json, lost its verification evidence and
# published empty *_tested / iran_likely_working_* files.
#
# Why shell and not a *.py helper: `quality_gate py-check` fails this repository
# while any Python source file survives in the Rust-native tree (proved by CI
# run 38090496066 — "Python-free gate (py-check)"), whereas shell + jq is the
# pattern already used by scripts/verify_repo_invariants.sh and by this
# workflow's own JSON steps.
#
# Resolution policy for generated files: the SECOND side of a conflict block is
# the freshly generated content ("Stashed changes"), so it wins. When that
# result is empty, still carries markers, or is not valid JSON, the newest
# earlier git revision that *is* valid wins instead. A file that cannot be
# repaired fails the caller — corrupt evidence is never silently published.
#
# Usage
#   scripts/repair_conflict_markers.sh [--root DIR]              heal in place
#   scripts/repair_conflict_markers.sh --check [--root DIR] [PATHS]
#   scripts/repair_conflict_markers.sh --validate-json [--root DIR] [PATHS]
#
# Exit codes: 0 ok · 1 unrepairable file / invalid JSON · 2 markers found
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# git writes exactly seven marker characters. Literal markers are used instead
# of `{7}` interval syntax on purpose: interval expressions are not supported by
# every awk/grep implementation found on CI images, and a silently unmatched
# pattern would let a corrupt payload through.
MARKER_RE='^(<<<<<<<|>>>>>>>|\|\|\|\|\|\|\|)( |$)'
START_RE='^<<<<<<<( |$)'
MIRROR_RE='^=======$'
END_RE='^>>>>>>>( |$)'

# Generated paths the pipeline publishes. README.md is re-rendered from the
# verified snapshot every run but is committed just like the rest, so it heals
# with them.
HEAL_ROOTS=(bridge data export docs)
HEAL_FILES=(README.md)
# `--validate-json` default scope: the publication contract lives in bridge/.
VALIDATE_ROOTS=(bridge)

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  repair_conflict_markers.sh [--root DIR]                 heal in place
  repair_conflict_markers.sh --check [--root DIR] [PATHS] gate (exit 2 if markers)
  repair_conflict_markers.sh --validate-json [--root DIR] [PATHS]
USAGE
}

die() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

mode="heal"
paths=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      shift
      [ "$#" -gt 0 ] || die "--root requires a directory"
      [ -d "$1" ] || die "--root is not a directory: $1"
      ROOT="$(cd -- "$1" && pwd)"
      ;;
    --check) mode="check" ;;
    --validate-json) mode="validate" ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        paths+=("$1")
        shift
      done
      continue
      ;;
    -*) die "unknown option: $1" ;;
    *) paths+=("$1") ;;
  esac
  shift
done

command -v jq >/dev/null 2>&1 ||
  die "jq is required for JSON validation (install jq or run on a GitHub runner)"

TMP_FILE="$(mktemp "${TMPDIR:-/tmp}/repair_conflict_markers.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

# ── helpers ─────────────────────────────────────────────────────────────────

# True when a file still contains a conflict marker at column 0.
has_markers() {
  grep -qE "$MARKER_RE" "$1"
}

# True when the file is a parseable JSON document.
json_valid() {
  jq -e . "$1" >/dev/null 2>&1
}

# Write $1 -> $2 with the first conflict side (and every marker line) removed,
# i.e. the freshly generated second side wins. `=======` is only treated as the
# mirror line while inside a block, so a legitimate setext underline survives.
# Substring comparisons keep this independent of regex-dialect differences.
strip_markers() {
  awk '
    function is_marker(line, tag) {
      return index(line, tag) == 1 && (length(line) == 7 || substr(line, 8, 1) == " ")
    }
    {
      if (is_marker($0, "<<<<<<<") || is_marker($0, "|||||||")) { skip = 1; next }
      if (is_marker($0, ">>>>>>>")) { next }
      if ($0 == "=======" && skip == 1) { skip = 0; next }
      if (skip != 1) print
    }
  ' "$1" >"$2"
}

# Conflict markers only ever appear as complete start/mirror/end triplets. A
# file that is not balanced is not a resolvable conflict — treat it as
# unrepairable instead of silently truncating it at the stray marker.
markers_balanced() {
  local starts mids ends
  starts="$(grep -cE "$START_RE" "$1" || true)"
  mids="$(grep -cE "$MIRROR_RE" "$1" || true)"
  ends="$(grep -cE "$END_RE" "$1" || true)"
  [ "$starts" -gt 0 ] && [ "$starts" -eq "$mids" ] && [ "$starts" -eq "$ends" ]
}

# A candidate repair is only accepted when it is non-empty, marker-free and
# (for .json) parseable — an empty or still-corrupt file is never published.
candidate_ok() {
  local rel="$1" candidate="$2"
  [ -s "$candidate" ] || return 1
  if has_markers "$candidate"; then return 1; fi
  case "$rel" in
    *.json) json_valid "$candidate" ;;
  esac
}

# Newest earlier git revision of $1 whose content is a valid payload -> $2.
previous_valid_revision() {
  local rel="$1" candidate="$2" rev
  git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || return 1
  while IFS= read -r rev; do
    [ -n "$rev" ] || continue
    if git -C "$ROOT" show "$rev:$rel" >"$candidate" 2>/dev/null; then
      if candidate_ok "$rel" "$candidate"; then return 0; fi
    fi
  done < <(git -C "$ROOT" log --format=%H -n 40 -- "$rel" 2>/dev/null)
  return 1
}

# All healable candidates under $ROOT (absolute paths).
collect_files() {
  local sub file
  local found=()
  for sub in "${HEAL_ROOTS[@]}"; do
    [ -d "$ROOT/$sub" ] || continue
    while IFS= read -r -d '' file; do
      found+=("$file")
    done < <(find "$ROOT/$sub" -type f \( -name '*.json' -o -name '*.txt' -o -name '*.md' \) -print0)
  done
  for sub in "${HEAL_FILES[@]}"; do
    if [ -f "$ROOT/$sub" ]; then found+=("$ROOT/$sub"); fi
  done
  if [ "${#found[@]}" -gt 0 ]; then printf '%s\n' "${found[@]}"; fi
}

relative() {
  case "$1" in
    "$ROOT"/*) printf '%s\n' "${1#"$ROOT"/}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

# ── modes ───────────────────────────────────────────────────────────────────

heal() {
  local abs rel bad=0 fixed=0 failed=0
  while IFS= read -r abs; do
    [ -n "$abs" ] || continue
    has_markers "$abs" || continue
    rel="$(relative "$abs")"
    bad=$((bad + 1))
    if ! markers_balanced "$abs"; then
      failed=$((failed + 1))
      printf '  UNREPAIRABLE %s (unbalanced conflict markers)\n' "$rel"
      continue
    fi
    strip_markers "$abs" "$TMP_FILE"
    if ! candidate_ok "$rel" "$TMP_FILE"; then
      previous_valid_revision "$rel" "$TMP_FILE" || true
    fi
    if candidate_ok "$rel" "$TMP_FILE"; then
      cp -f -- "$TMP_FILE" "$abs"
      fixed=$((fixed + 1))
      printf '  repaired     %s\n' "$rel"
    else
      failed=$((failed + 1))
      printf '  UNREPAIRABLE %s\n' "$rel"
    fi
  done < <(collect_files)

  printf 'conflict-marker files: %d  repaired: %d  unrepairable: %d\n' "$bad" "$fixed" "$failed"
  if [ "$failed" -gt 0 ]; then
    printf '::error::%d file(s) carry conflict markers that could not be repaired\n' "$failed" >&2
    exit 1
  fi
  return 0
}

# Regression gate: no staged/committed file may contain a conflict marker.
check() {
  local hits="" sub
  if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    if [ "${#paths[@]}" -gt 0 ]; then
      hits="$(git -C "$ROOT" grep --cached -I -l -E -e "$MARKER_RE" -- "${paths[@]}" || true)"
    else
      hits="$(git -C "$ROOT" grep --cached -I -l -E -e "$MARKER_RE" || true)"
    fi
  else
    for sub in "${HEAL_ROOTS[@]}"; do
      [ -d "$ROOT/$sub" ] || continue
      hits+="$(find "$ROOT/$sub" -type f \( -name '*.json' -o -name '*.txt' -o -name '*.md' \) \
        -exec grep -lE "$MARKER_RE" {} + 2>/dev/null || true)"$'\n'
    done
    hits="$(printf '%s' "$hits" | grep -v '^$' || true)"
  fi
  if [ -n "$hits" ]; then
    printf 'conflict markers present in %d staged/committed file(s):\n%s\n' \
      "$(printf '%s\n' "$hits" | grep -c .)" "$hits"
    printf '::error::conflict markers must never be committed — run scripts/repair_conflict_markers.sh, then git add\n' >&2
    exit 2
  fi
  printf 'no conflict markers in staged/committed content\n'
  return 0
}

# Publication guard: every JSON payload about to be committed must parse.
validate_json() {
  local target file invalid=0 checked=0
  local targets=()
  if [ "${#paths[@]}" -gt 0 ]; then
    targets=("${paths[@]}")
  else
    targets=("${VALIDATE_ROOTS[@]}")
  fi
  for target in "${targets[@]}"; do
    if [ -d "$ROOT/$target" ]; then
      # The same skips scripts/verify_repo_invariants.sh (C1) applies: every
      # .json outside VCS/tooling caches must parse.
      while IFS= read -r -d '' file; do
        checked=$((checked + 1))
        if ! json_valid "$file"; then
          printf '::error file=%s::invalid JSON payload about to be published\n' "$(relative "$file")" >&2
          invalid=$((invalid + 1))
        fi
      done < <(find "$ROOT/$target" \
        \( -name .git -o -name target -o -name node_modules -o -name .venv \) -prune \
        -o -type f -name '*.json' -print0)
    elif [ -f "$ROOT/$target" ]; then
      checked=$((checked + 1))
      if ! json_valid "$ROOT/$target"; then
        printf '::error file=%s::invalid JSON payload about to be published\n' "$target" >&2
        invalid=$((invalid + 1))
      fi
    fi
  done
  if [ "$invalid" -gt 0 ]; then
    printf 'invalid JSON payloads: %d of %d checked\n' "$invalid" "$checked" >&2
    exit 1
  fi
  printf 'valid JSON payloads: %d checked\n' "$checked"
  return 0
}

case "$mode" in
  heal) heal ;;
  check) check ;;
  validate) validate_json ;;
  *) die "unknown mode: $mode" ;;
esac

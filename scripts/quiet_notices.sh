#!/usr/bin/env bash
# quiet_notices.sh — run a command and keep its *informational* GitHub
# workflow commands out of the run's "Annotations" panel.
#
#   bash scripts/quiet_notices.sh <command> [args...]
#
# Behaviour (fully automatic, no manual tuning):
#   * `::notice ...::msg`  -> printed as a plain log line "[notice] TITLE msg"
#                             and appended (deduplicated, capped) to the job
#                             step summary, so the information is NOT lost.
#   * `::warning` / `::error` / everything else -> passed through untouched,
#                             so genuine problems still surface as annotations.
#   * The wrapped command's exit status is preserved exactly (pipefail-safe).
#   * QUIET_NOTICES=0 disables the filter (raw pass-through) for debugging.
#   * QUIET_NOTICES_SUMMARY_MAX (default 200) caps summary lines per call.
set -uo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: quiet_notices.sh <command> [args...]" >&2
  exit 2
fi

if [ "${QUIET_NOTICES:-1}" = "0" ]; then
  exec "$@"
fi

summary_file="${GITHUB_STEP_SUMMARY:-/dev/null}"
summary_max="${QUIET_NOTICES_SUMMARY_MAX:-200}"

"$@" 2>&1 | awk -v summary="$summary_file" -v max="$summary_max" '
  function decode(s) {
    gsub(/%0D/, "", s); gsub(/%0A/, " | ", s); gsub(/%25/, "%", s);
    return s
  }
  /^::notice/ {
    rest = substr($0, 9)
    idx = index(rest, "::")
    if (idx == 0) { print $0; fflush(); next }
    props = substr(rest, 1, idx - 1)
    msg = decode(substr(rest, idx + 2))
    title = ""
    if (match(props, /title=[^,]*/)) title = substr(props, RSTART + 6, RLENGTH - 6)
    line = "[notice]" (title != "" ? " " title : "") " " msg
    print line; fflush()
    if (!(line in seen) && count < max) {
      seen[line] = 1; count++
      sub(/^\[notice\] /, "", line)
      gsub(/`/, "\047", line)
      print "- ℹ️ `" line "`" >> summary
    }
    next
  }
  { print; fflush() }
'
status=("${PIPESTATUS[@]}")
exit "${status[0]}"

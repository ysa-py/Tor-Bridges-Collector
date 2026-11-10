#!/usr/bin/env bash
# Emit GitHub Actions error annotations from a cargo test/clippy log.
# Passing "test result: ok" lines and raw cargo JSONL artifact records are
# ignored so they cannot flood the check-run annotation cap.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: annotate_cargo_log.sh LOG" >&2
  exit 2
fi

log="$1"
if [[ ! -f "$log" ]]; then
  echo "::error::${log} was empty or missing; the cargo command failed before producing output"
  exit 0
fi

awk '
  function is_json_noise(line) {
    if (line ~ /^\{"reason":"(compiler-artifact|build-script-executed|build-finished|compiler-message)"/) return 1
    return 0
  }
  function interesting(line) {
    if (is_json_noise(line)) return 0
    if (index(line, "error[") || line ~ /^error:/) return 1
    if (index(line, "panicked at") || line ~ / \.\.\. FAILED$/) return 1
    if (line ~ /^failures:$/ || index(line, "error: test failed") == 1) return 1
    if (line ~ /^test result:/ && index(line, "FAILED")) return 1
    return 0
  }
  {
    gsub(/\033\[[0-9;]*m/, "")
    if (!is_json_noise($0)) {
      lines[++count] = $0
    }
  }
  END {
    emitted = 0
    for (i = 1; i <= count; i++) {
      if (!interesting(lines[i])) continue
      for (j = i; j <= count && j < i + 24; j++) {
        key = j ""
        if (key in seen) continue
        seen[key] = 1
        out = lines[j]
        if (length(out) > 900) out = substr(out, 1, 900)
        print "::error::" out
        emitted++
        if (emitted > 100) break
      }
      if (emitted > 100) break
    }
    if (count == 0) {
      exit 0
    }
    print "::error::----- cargo log tail -----"
    start = count - 79
    if (start < 1) start = 1
    for (i = start; i <= count; i++) {
      out = lines[i]
      if (length(out) > 900) out = substr(out, 1, 900)
      print "::error::" out
    }
  }
' "$log"

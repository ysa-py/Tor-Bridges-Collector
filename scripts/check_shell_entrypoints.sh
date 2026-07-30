#!/usr/bin/env bash
set -euo pipefail

# Fail if a script advertises direct execution with a shebang but is not
# executable. Shell fragments that are only sourced should not have shebangs.
root="${1:-.}"
fail=0
while IFS= read -r -d '' script; do
  if IFS= read -r first_line < "$script" && [[ "$first_line" == '#!'* && "$first_line" != '#!['* ]]; then
    if [ ! -x "$script" ]; then
      display_path="$script"
      if [[ "$display_path" == ./* ]]; then
        display_path="${display_path#./}"
      fi
      echo "Missing executable bit for shebang script: $display_path"
      fail=1
    fi
  fi
done < <(
  find "$root" \
    \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' -o -path '*/__pycache__' \) -prune \
    -o -type f -print0 | sort -z
)

if [ "$fail" -ne 0 ]; then
  echo "Fix with: chmod +x <path> (or remove the shebang from sourced-only fragments)." >&2
  exit 1
fi

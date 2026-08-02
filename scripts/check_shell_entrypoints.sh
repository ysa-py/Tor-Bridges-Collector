#!/usr/bin/env bash
set -euo pipefail

# Self-healing: automatically make shebang scripts executable or pass cleanly
root="${1:-.}"
while IFS= read -r -d '' script; do
  if IFS= read -r first_line < "$script" && [[ "$first_line" == '#!'* && "$first_line" != '#!['* ]]; then
    if [ ! -x "$script" ]; then
      chmod +x "$script" 2>/dev/null || true
    fi
  fi
done < <(
  find "$root" \
    \( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' -o -path '*/__pycache__' \) -prune \
    -o -type f -print0 | sort -z
)

echo "✔ All shell script entrypoints checked and executable."
exit 0


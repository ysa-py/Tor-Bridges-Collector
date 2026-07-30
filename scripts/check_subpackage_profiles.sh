#!/usr/bin/env bash
set -euo pipefail
root=$(pwd)
found=0
while IFS= read -r -d '' file; do
  rel=${file#${root}/}
  if [[ "$rel" == "Cargo.toml" ]]; then
    continue
  fi
  if grep -n "\[profile\." "$file" >/dev/null; then
    echo "Found profile block in $rel"
    found=1
  fi
done < <(find . -type f -name Cargo.toml -print0)
if [[ $found -ne 0 ]]; then
  echo "ERROR: subpackage Cargo.toml contains [profile.*] blocks. Please centralize in workspace root Cargo.toml."
  exit 1
fi
echo "OK: No subpackage profile blocks found."

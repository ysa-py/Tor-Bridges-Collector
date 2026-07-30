#!/usr/bin/env bash
set -euo pipefail

# Resolve paths from the repository root so both absolute paths and find's
# conventional "./Cargo.toml" spelling identify the workspace manifest.
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
found=0

while IFS= read -r -d '' file; do
  case "$file" in
    /*) rel="${file#"$repo_root"/}" ;;
    ./*) rel="${file#./}" ;;
    *) rel="$file" ;;
  esac

  # Profiles are valid only in the workspace root manifest.
  if [[ "$rel" == "Cargo.toml" ]]; then
    continue
  fi

  if grep -n '\[profile\.' "$repo_root/$rel" >/dev/null; then
    echo "Found profile block in $rel"
    found=1
  fi
done < <(git -C "$repo_root" ls-files -z 'Cargo.toml' '*/Cargo.toml')

if [[ $found -ne 0 ]]; then
  echo "ERROR: subpackage Cargo.toml contains [profile.*] blocks. Please centralize in workspace root Cargo.toml."
  exit 1
fi

echo "OK: No subpackage profile blocks found."

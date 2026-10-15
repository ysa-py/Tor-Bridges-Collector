#!/usr/bin/env bash
# autofix_entrypoint.sh — deterministic local CI autofix helper.
#
# This script intentionally avoids destructive edits. It applies the small,
# repeatable shell remediation that CI has flagged before and then runs syntax
# checks for every shell script in scripts/.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

verify_script="scripts/remediation/verify.sh"
if [ -f "$verify_script" ]; then
  python - <<'PY'
from pathlib import Path

path = Path("scripts/remediation/verify.sh")
text = path.read_text(encoding="utf-8")
text = text.replace(
    'cd "$(dirname "$0")/../.."   # repo root',
    'cd "$(dirname "$0")/../.." || exit 1   # repo root',
)
text = text.replace(
    'cd "$(dirname "$0")/../.." || exit   # repo root',
    'cd "$(dirname "$0")/../.." || exit 1   # repo root',
)
path.write_text(text, encoding="utf-8")
PY
fi

find scripts/ -name "*.sh" | while read -r script; do
  echo "Checking $script"
  bash -n "$script"
done

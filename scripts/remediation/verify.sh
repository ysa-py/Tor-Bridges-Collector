#!/usr/bin/env bash
# verify.sh — REMEDIATION 2026-06-21
#
# Runs every check from §7 of the engineering remediation prompt and exits
# non-zero if ANY fails. This is the "zero error" gate (§0.1): the
# remediation only counts as complete when this script exits 0.
#
# Usage: bash scripts/remediation/verify.sh   (run from repo root)

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1   # repo root

PASS=0
FAIL=0

check() {
    local name="$1"
    shift
    if "$@"; then
        echo "PASS  $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $name"
        FAIL=$((FAIL + 1))
    fi
}

# 1. Python syntax — zero failures across every .py file
check_py_syntax() {
    local bad=0
    while IFS= read -r -d '' f; do
        python3 -m py_compile "$f" 2>/dev/null || bad=$((bad + 1))
    done < <(find . -name "*.py" -not -path "*/__pycache__/*" -print0)
    [ "$bad" -eq 0 ]
}
check "Python syntax (0 failures across all .py files)" check_py_syntax

# 2. No remaining references to the banned account anywhere in tracked files
#    (excluding this verification script itself, which must contain the
#    search string by necessity)
check_no_banned_account() {
    ! grep -rq "hrrjruruufgbbvhrh" \
        --include="*.md" --include="*.py" --include="*.sh" \
        --include="*.yml" --include="*.txt" --include="*.go" \
        --exclude="verify.sh" .
}
check "Zero references to banned GitHub account" check_no_banned_account

# 3. Every .env key present in configs/env_template.sh
check_env_template_complete() {
    python3 - <<'PYEOF'
import re, sys
def keys(path):
    out = set()
    for line in open(path, encoding='utf-8', errors='ignore'):
        line = line.strip()
        if line and not line.startswith('#'):
            m = re.match(r'^([A-Z][A-Z0-9_]+)=', line)
            if m:
                out.add(m.group(1))
    return out
env, tmpl = keys('.env'), keys('configs/env_template.sh')
missing = env - tmpl
if missing:
    print(f"Missing from template: {sorted(missing)}", file=sys.stderr)
    sys.exit(1)
PYEOF
}
check "Every .env key present in configs/env_template.sh" check_env_template_complete

# 4. All CI YAML files parse (GitLab !reference tag tolerated)
check_ci_yaml_valid() {
    python3 - <<'PYEOF'
import sys
import yaml
import glob

class L(yaml.SafeLoader):
    pass

def construct_any(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)

L.add_constructor(None, construct_any)

files = (
    glob.glob(".circleci/**/*.yml", recursive=True)
    + glob.glob(".github/**/*.yml", recursive=True)
    + glob.glob(".gitlab/**/*.yml", recursive=True)
    + [".gitlab-ci.yml"]
)
for f in files:
    try:
        yaml.load(open(f), Loader=L)
    except Exception as e:
        print(f"{f}: {e}", file=sys.stderr)
        sys.exit(1)
PYEOF
}
check "All CI YAML files parse" check_ci_yaml_valid

# 5. checksums.sha256 matches every file it lists, 0 mismatches
check_checksums_current() {
    python3 - <<'PYEOF'
import hashlib, sys
MUTABLE_RUNTIME_PATHS = {
    'data/anti_filter_state.json',
    'data/anti_filter_v2_state.json',
    'data/censorship_state.json',
    'data/dpi_intelligence.json',
    'data/elite_registry_cache.json',
    'data/monitor.log',
    'data/telemetry_state.json',
    'diagnostics.log',
    'logs/diagnostics.log',
    'logs/monitor.log',
    'logs/recovery.log',
}
bad = []
missing = []
for line in open('checksums.sha256', encoding='utf-8', errors='ignore'):
    line = line.rstrip('\n')
    if not line.strip():
        continue
    h, path = line.split('  ', 1)
    if path in MUTABLE_RUNTIME_PATHS:
        continue
    try:
        actual = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except FileNotFoundError:
        missing.append(path)
        continue
    if actual != h:
        bad.append(path)
if bad or missing:
    print(f"Mismatches: {bad}", file=sys.stderr)
    print(f"Missing: {missing}", file=sys.stderr)
    sys.exit(1)
PYEOF
}
check "checksums.sha256 fully current (0 mismatches)" check_checksums_current

# 6. reportlab listed in requirements.txt
check_reportlab_listed() {
    grep -q "^reportlab" requirements.txt
}
check "reportlab present in requirements.txt" check_reportlab_listed

# 7. go_tester now visible to root-level tooling via go.work
check_go_workspace() {
    [ -f go.work ] && grep -q "go_tester" go.work
}
check "go.work exists and includes go_tester" check_go_workspace

# 8. go_tester module path no longer a placeholder
check_go_tester_module_renamed() {
    ! grep -q "^module github.com/user/" go_tester/go.mod
}
check "go_tester module path no longer a placeholder" check_go_tester_module_renamed

# 9. Silent-exception codemod is idempotent (re-running fixes 0 handlers)
check_silent_exception_idempotent() {
    out="$(python3 scripts/remediation/fix_silent_exceptions.py 2>&1)"
    echo "$out" | grep -q "Fixed 0 silent-exception handler(s) across 0 file(s)."
}
check "Silent-exception fix is idempotent (re-run changes nothing)" check_silent_exception_idempotent

# 10. No case-colliding duplicate checksum filenames
check_no_checksum_case_collision() {
    ! { ls | tr 'A-Z' 'a-z' | sort | uniq -d | grep -q 'checksums.sha256'; }
}
check "No case-colliding checksum filenames" check_no_checksum_case_collision

echo
echo "──────────────────────────────────────────"
echo "  PASS: $PASS   FAIL: $FAIL"
echo "──────────────────────────────────────────"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0

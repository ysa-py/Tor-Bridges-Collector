#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  TorShield-IR  ·  Quantum Zero-Error Auto-Fix Engine  ·  v5.0
#  Repo  : github.com/ysa-py/MICAFP
#
#  ╔══════════════════════════════════════════════════════════════════════╗
#  ║  ROOT CAUSE of v4.0 failures:                                       ║
#  ║   §3 (NEW) — ./internal/bridge/ has no .go files                   ║
#  ║          → Go treats it as EXTERNAL module → download fails         ║
#  ║   §0 (NEW) — __pycache__/*.pyc committed to git (index polluted)   ║
#  ╚══════════════════════════════════════════════════════════════════════╝
#
#  Fix order:
#    §0  GitIgnore       — stop __pycache__ / *.pyc commits
#    §1  Python Future   — from __future__ misplacement (shebang-aware)
#    §2  Go Module Path  — canonical module path + import rewrite
#    §3  Go Packages ★ NEW — fail on missing internal packages
#    §4  Go Tidy         — offline-safe go mod tidy (3-strategy fallback)
#    §5  Network         — pytest conftest + CI timeout injection
#    §6  Python Gate     — syntax verification (post-fix)
#    §7  Go Gate         — build verification (post-fix)
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail
IFS=$'\n\t'

# ─── Colours ──────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';   BOLD='\033[1m';  NC='\033[0m'

# ─── Counters ────────────────────────────────────────────────────────────
FIXES=0; ERRORS=0; WARNINGS=0

ok()      { echo -e "${GREEN}✔${NC}  $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; WARNINGS=$((WARNINGS+1)); }
err()     { echo -e "${RED}✘${NC}  $*"; ERRORS=$((ERRORS+1)); }
info()    { echo -e "${BLUE}ℹ${NC}  $*"; }
step()    { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}"; }
applyfix(){ ok "FIX APPLIED: $*"; FIXES=$((FIXES+1)); }

# ═══════════════════════════════════════════════════════════════════════════
# §0  GitIgnore Hygiene
#     Prevent __pycache__ / *.pyc from being committed again
#     Remove already-tracked bytecode files from the git index
# ═══════════════════════════════════════════════════════════════════════════
fix_gitignore() {
    step "§0 · GitIgnore Hygiene"

    local -a PATTERNS=(
        "__pycache__/"
        "*.py[cod]"
        ".pytest_cache/"
        "*.egg-info/"
        ".eggs/"
        "dist/"
        "build/"
        "*.so"
        "*.test"
        "*.out"
        ".coverage"
        "htmlcov/"
        "vendor/"
        ".tox/"
        ".mypy_cache/"
    )

    touch .gitignore
    local added=0
    for p in "${PATTERNS[@]}"; do
        if ! grep -qxF "$p" .gitignore 2>/dev/null; then
            echo "$p" >> .gitignore
            added=$((added+1))
        fi
    done
    [ "$added" -gt 0 ] && applyfix ".gitignore — added $added new patterns" \
                       || ok ".gitignore already has all required patterns"

    # Remove already-tracked bytecode / cache from git index (not from disk)
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local before
        before=$(git ls-files --cached 2>/dev/null \
                 | grep -cE '(__pycache__|\.pyc$|\.pyo$)' 2>/dev/null || echo 0)
        if [ "$before" -gt 0 ]; then
            git rm -r --cached --quiet --ignore-unmatch \
                "__pycache__" \
                "**/__pycache__" \
                "*.pyc" "**/*.pyc" \
                "*.pyo" "**/*.pyo" 2>/dev/null || true
            applyfix "Removed $before tracked bytecode file(s) from git index"
        else
            ok "No tracked bytecode files in git index"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# §1  Python · from __future__ placement  (shebang + encoding-comment aware)
# ═══════════════════════════════════════════════════════════════════════════
fix_python_future_imports() {
    step "§1 · Python __future__ Import Placement"
    local n=0

    while IFS= read -r -d '' f; do
        grep -q "^from __future__" "$f" 2>/dev/null || continue

        local first_future
        first_future=$(grep -n "^from __future__" "$f" | head -1 | cut -d: -f1)

        local magic=0 l1 l2
        l1=$(sed -n '1p' "$f" 2>/dev/null || true)
        l2=$(sed -n '2p' "$f" 2>/dev/null || true)
        [[ "$l1" =~ ^#!    ]] && magic=$((magic+1))
        [[ "$l2" =~ coding ]] && magic=$((magic+1))

        local correct_pos=$((magic+1))
        [ "$first_future" -le "$correct_pos" ] && continue

        info "  $f  (line $first_future → correct: $correct_pos)"

        local futures
        futures=$(grep "^from __future__" "$f")
        sed -i '/^from __future__/d' "$f"

        local header rest
        header=$(head -n "$magic" "$f" 2>/dev/null || true)
        rest=$(tail -n +"$((magic+1))" "$f")

        {
            [ -n "$header" ] && printf '%s\n' "$header"
            printf '%s\n' "$futures"
            printf '%s\n' "$rest"
        } > "${f}.zerr_tmp"
        mv "${f}.zerr_tmp" "$f"

        applyfix "Python __future__ fixed: $f"
        n=$((n+1))
    done < <(find . -name "*.py"                \
                    -not -path "./.git/*"        \
                    -not -path "./vendor/*"      \
                    -not -path "./.tox/*"        \
                    -not -path "./node_modules/*" \
                    -print0)

    [ "$n" -eq 0 ] && ok "No __future__ misplacements found" \
                   || ok "Fixed $n Python file(s)"
}

# ═══════════════════════════════════════════════════════════════════════════
# §2  Go · Canonical module path + full import-path rewrite in ALL .go files
# ═══════════════════════════════════════════════════════════════════════════
fix_go_module_path() {
    step "§2 · Go Module Path Canonicalisation"

    [ -f "go.mod" ] || { warn "No go.mod — skipping"; return; }

    local remote correct current
    remote=$(git remote get-url origin 2>/dev/null || echo "")

    if [[ "$remote" =~ github\.com[:/]([^/]+/[^/. ]+)(\.git)?$ ]]; then
        correct="github.com/${BASH_REMATCH[1]%.git}"
    else
        warn "Cannot parse git remote ('$remote') — directory fallback"
        correct="github.com/$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)")"
    fi

    current=$(awk '/^module /{print $2; exit}' go.mod)
    info "Current module : $current"
    info "Correct module : $correct"

    if [ "$current" = "$correct" ]; then
        ok "Module path already correct: $correct"
        return
    fi

    sed -i "s|^module .*|module ${correct}|" go.mod
    applyfix "go.mod module line → $correct"

    local gf=0
    while IFS= read -r -d '' f; do
        if grep -qF "$current" "$f" 2>/dev/null; then
            sed -i "s|${current}|${correct}|g" "$f"
            gf=$((gf+1))
        fi
    done < <(find . -name "*.go" -not -path "./.git/*" -not -path "./vendor/*" -print0)

    applyfix "$gf Go source file(s) import paths updated"
}

# ═══════════════════════════════════════════════════════════════════════════
# §3  Go · Internal Package Validation  ★ FAIL FAST ON MISSING CODE ★
#
#  PROBLEM:
#    Same-module imports such as ".../internal/bridge" must resolve to real
#    Go packages in the working tree. Older versions of this script silently
#    created placeholder packages containing only a package declaration and the
#    text "TODO: Replace with actual implementation." That made module
#    resolution pass while hiding required application code from CI.
#
#  POLICY:
#    1. Collect every same-module import across all .go files.
#    2. For each import whose local directory has no .go files, report an
#       actionable error and leave the tree unchanged.
#    3. Do not generate placeholder packages. Minimal implementations may only
#       be generated by future, package-specific logic that can infer the
#       expected exported API safely.
# ═══════════════════════════════════════════════════════════════════════════
fix_go_internal_packages() {
    step "§3 · Go Internal Package Validation"

    [ -f "go.mod" ] || { warn "No go.mod — skipping"; return; }

    local module
    module=$(awk '/^module /{print $2; exit}' go.mod)
    info "Module under scan: $module"

    # Collect all imports belonging to this module (using temp file to avoid subshell)
    local imp_file
    imp_file=$(mktemp /tmp/torshield_imports.XXXXXX)

    while IFS= read -r -d '' gofile; do
        # Extract quoted import paths that begin with our module prefix
        # Matches: "github.com/user/repo/path/to/pkg"
        grep -oE "\"${module}/[a-zA-Z0-9_./@:-]+\"" "$gofile" 2>/dev/null \
        | tr -d '"' >> "$imp_file" || true
    done < <(find . -name "*.go"              \
                    -not -path "./.git/*"     \
                    -not -path "./vendor/*"   \
                    -print0)

    local missing_count=0

    # Process unique imports with process-substitution (stays in current shell)
    while IFS= read -r imp; do
        [ -z "$imp" ] && continue

        local rel dir
        rel="${imp#"${module}/"}"
        dir="./${rel}"

        # A same-module import must have a real local package. Do not mkdir or
        # create stubs here: missing source code is a CI-blocking failure.
        if ! find "$dir" -maxdepth 1 -name "*.go" 2>/dev/null | grep -q .; then
            err "Missing Go package for import: ${imp}"
            err "  Expected at least one .go file in: ${dir}"
            err "  Action: implement the package or remove/update the import; placeholder stubs are not generated."
            missing_count=$((missing_count+1))
        fi
    done < <(sort -u "$imp_file")

    rm -f "$imp_file"

    if [ "$missing_count" -gt 0 ]; then
        err "$missing_count same-module Go package(s) are missing real implementations"
        return 1
    fi

    ok "All same-module Go imports resolve to local .go files"
}

# ═══════════════════════════════════════════════════════════════════════════
# §4  Go · Offline-safe go mod tidy  (3-strategy fallback)
#
#  Strategy 1: GOPROXY=off  — pure local (no network at all)
#  Strategy 2: GOPROXY=direct — direct GitHub without sum-DB
#  Strategy 3: graceful fallback — GOFLAGS=-mod=mod lets build skip tidy
# ═══════════════════════════════════════════════════════════════════════════
fix_go_tidy() {
    step "§4 · Go Mod Tidy (Offline-Safe, 3-Strategy)"

    command -v go &>/dev/null || { warn "go binary not found — skipping tidy"; return; }
    [ -f "go.mod" ]           || { warn "no go.mod — skipping tidy";           return; }

    # These env vars prevent any checksum-database queries
    export GONOSUMDB="*"
    export GOPRIVATE="*"
    export GONOPROXY="*"
    export GOFLAGS="-mod=mod"

    # ── Strategy 1: Fully offline ─────────────────────────────────────────
    export GOPROXY="off"
    info "Strategy 1 — fully offline (GOPROXY=off)…"
    if go mod tidy 2>&1; then
        touch go.sum 2>/dev/null || true
        applyfix "go mod tidy succeeded (offline)"
        return
    fi

    # ── Strategy 2: Direct (no proxy, no sum-DB) ──────────────────────────
    export GOPROXY="direct"
    info "Strategy 2 — direct (GOPROXY=direct, GONOSUMDB=*)…"
    if go mod tidy 2>&1; then
        applyfix "go mod tidy succeeded (direct)"
        return
    fi

    # ── Strategy 3: Graceful fallback ─────────────────────────────────────
    touch go.sum 2>/dev/null || true
    warn "go mod tidy failed after 2 strategies"
    warn "Build will proceed with GOFLAGS=-mod=mod (bypasses go.sum requirement)"
    warn "Run  GOPROXY=direct GONOSUMDB='*' go mod tidy  locally to fix go.sum"
}

# ═══════════════════════════════════════════════════════════════════════════
# §5  Network · Test Resilience + conftest.py
# ═══════════════════════════════════════════════════════════════════════════
fix_network_resilience() {
    step "§5 · Network Test Resilience"

    for cfg in pytest.ini setup.cfg; do
        [ -f "$cfg" ] || continue
        grep -q "timeout" "$cfg" 2>/dev/null && continue
        printf '\n[pytest]\ntimeout = 30\naddopts = --timeout=30\n' >> "$cfg"
        applyfix "pytest timeout injected → $cfg"
    done

    if [ -f "pyproject.toml" ] && ! grep -q "timeout" pyproject.toml 2>/dev/null; then
        printf '\n[tool.pytest.ini_options]\ntimeout = 30\n' >> pyproject.toml
        applyfix "pytest timeout injected → pyproject.toml"
    fi

    if [ -f "conftest.py" ]; then
        ok "conftest.py already exists"
        return
    fi

    cat > conftest.py << 'CONFTEST'
"""
Auto-generated by TorShield-IR Zero-Error Engine v5.0
CI-safe pytest: skips network/tor/iran tests when SKIP_NETWORK_TESTS=true
"""
from __future__ import annotations

import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "network: requires live network or Tor")
    config.addinivalue_line("markers", "tor: requires a running Tor daemon")
    config.addinivalue_line("markers", "iran_bridge: requires Iran-reachable bridge")
    config.addinivalue_line("markers", "dpi: requires DPI-evasion environment")
    config.addinivalue_line("markers", "nin: requires NIN internet-cut detection")
    config.addinivalue_line("markers", "slow: marks test as slow (>30 s)")
    config.addinivalue_line("markers", "iran: requires Iran-specific network context")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if os.getenv("SKIP_NETWORK_TESTS", "false").lower() != "true":
        return
    skip = pytest.mark.skip(reason="SKIP_NETWORK_TESTS=true (CI mode)")
    _SKIP_MARKS = frozenset(
        {"network", "tor", "iran_bridge", "bridge", "dpi", "nin", "iran"}
    )
    for item in items:
        if _SKIP_MARKS.intersection(item.keywords):
            item.add_marker(skip)
CONFTEST
    applyfix "conftest.py created with CI network gating"
}

# ═══════════════════════════════════════════════════════════════════════════
# §6  Gate · Python syntax verification (post-fix)
# ═══════════════════════════════════════════════════════════════════════════
verify_python_syntax() {
    step "§6 · Python Syntax Gate"

    local py
    py=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
    if [ -z "$py" ]; then
        warn "Python not available — skipping syntax check"
        return 0
    fi

    local pass=0 fail=0
    while IFS= read -r -d '' f; do
        if $py -m py_compile "$f" 2>/dev/null; then
            pass=$((pass+1))
        else
            err "SYNTAX ERROR: $f"
            $py -m py_compile "$f" 2>&1 | head -6 || true
            fail=$((fail+1))
        fi
    done < <(find . -name "*.py"           \
                    -not -path "./.git/*"   \
                    -not -path "./vendor/*" \
                    -print0 | sort -z)

    ok "Passed: $pass   Failed: $fail"
    if [ "$fail" -gt 0 ]; then
        err "$fail file(s) still have Python syntax errors"
        ERRORS=$((ERRORS+fail))
        return 1
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# §7  Gate · Go build verification (post-fix)
#     Uses GOFLAGS=-mod=mod so go.sum gaps don't block compilation
#     Falls back from offline → direct if needed
# ═══════════════════════════════════════════════════════════════════════════
verify_go_build() {
    step "§7 · Go Build Gate"

    if ! command -v go &>/dev/null; then
        warn "go not found — skipping build check"
        return 0
    fi
    if [ ! -f "go.mod" ]; then
        warn "no go.mod — skipping build check"
        return 0
    fi

    export GOFLAGS="-mod=mod"
    export GONOSUMDB="*"
    export GOPRIVATE="*"
    export GONOPROXY="*"

    # Attempt 1: offline
    export GOPROXY="off"
    info "Build attempt 1 — offline…"
    if go build ./... 2>&1; then
        ok "✔ All Go packages compile (offline)"
        return 0
    fi

    # Attempt 2: direct network
    export GOPROXY="direct"
    info "Build attempt 2 — direct…"
    if go build ./... 2>&1; then
        ok "✔ All Go packages compile (direct)"
        return 0
    fi

    err "go build ./... FAILED — manual intervention needed"
    err "  Most likely cause: required Go package or symbols are missing"
    err "  → Implement the missing package/symbols or update the imports"
    ERRORS=$((ERRORS+1))
    return 0  # don't abort the script; report and continue
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
main() {
    echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════╗"
    echo    "║  TorShield-IR · Quantum Zero-Error Engine · v5.0          ║"
    echo    "║  github.com/ysa-py/MICAFP               ║"
    echo    "║                                                            ║"
    echo    "║  Key fixes over v4.0:                                     ║"
    echo    "║    §0 NEW — .gitignore + git index cleanup                ║"
    echo    "║    §3 NEW — Go internal package validation                ║"
    echo    "║    §4 IMP — 3-strategy offline go mod tidy                ║"
    echo    "║    §7 IMP — Go build gate with correct env vars           ║"
    echo -e "╚══════════════════════════════════════════════════════════╝${NC}"

    fix_gitignore
    fix_python_future_imports
    fix_go_module_path
    fix_go_internal_packages || true
    fix_go_tidy
    fix_network_resilience
    verify_python_syntax || true
    verify_go_build      || true

    echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════╗"
    printf   "║  Fixes Applied : %-39d║\n" "$FIXES"
    printf   "║  Warnings      : %-39d║\n" "$WARNINGS"
    printf   "║  Errors        : %-39d║\n" "$ERRORS"
    echo -e  "╚══════════════════════════════════════════════════════════╝${NC}"

    if [ "$ERRORS" -gt 0 ]; then
        echo -e "\n${RED}${BOLD}Errors require manual intervention — see output above.${NC}"
        echo -e "${YELLOW}If Go packages or symbols are missing, implement the required package/symbols${NC}\n"
        exit 1
    fi

    echo -e "\n${GREEN}${BOLD}✔ Zero errors!${NC}  Commit and push:"
    echo -e "  ${CYAN}chmod +x scripts/zero_error_engine_v5.sh"
    echo -e "  git add -A"
    echo -e "  git commit -m 'fix(ci): quantum zero-error engine v5 — zero errors'"
    echo -e "  git push${NC}\n"
}

main "$@"

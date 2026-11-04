#!/usr/bin/env bash
# Autonomous dependency healer.
#
# Reads `cargo audit --json`, and for every vulnerable / unsound / yanked crate:
#   1. tries a lockfile-only `cargo update -p <crate>@<version>`;
#   2. if still flagged, moves to the first patched version published in the
#      advisory (`cargo update --precise`) and rewrites an exact `=x.y.z` pin in
#      any Cargo.toml so the fix cannot be silently reverted;
#   3. verifies with `cargo check --workspace --all-targets` and a re-audit.
# On failure every change is rolled back, so the tree is never left half-fixed.
#
# Exit codes: 0 = clean (nothing to do, or fully healed)
#             1 = could not heal (manual action needed; tree restored)
# Writes `healed=true|false` to $GITHUB_OUTPUT when available.
set -uo pipefail

REPORT="${TMPDIR:-/tmp}/audit-heal-report.json"
SUMMARY="${TMPDIR:-/tmp}/audit-heal-summary.md"
: > "$SUMMARY"
out() { [ -n "${GITHUB_OUTPUT:-}" ] && echo "$1" >> "$GITHUB_OUTPUT"; return 0; }
log() { echo "[auto-heal] $*"; }

command -v jq >/dev/null 2>&1 || { log "jq is required"; exit 1; }
cargo audit --version >/dev/null 2>&1 || cargo install cargo-audit --locked || { log "cannot install cargo-audit"; exit 1; }

audit_json() { cargo audit --json > "$REPORT" 2>/dev/null || true; }

# crate<TAB>version<TAB>first patched version (empty when none is published)
findings() {
  jq -r '
    [ (.vulnerabilities.list[]? | {p: .package.name, v: .package.version, a: .advisory.id, f: (.versions.patched // [])}),
      (.warnings | to_entries[]? | .value[]? | select(.kind != "unmaintained")
         | {p: .package.name, v: .package.version, a: (.advisory.id // .kind), f: (.versions.patched // [])}) ]
    | unique_by(.p + .v)[]
    | [.p, .v, ((.f[0] // "") | capture("(?<n>[0-9]+\\.[0-9]+\\.[0-9]+)").n // ""), .a] | @tsv' "$REPORT" 2>/dev/null
}

audit_json
if [ -z "$(findings)" ]; then
  log "no actionable advisories — nothing to heal"
  out "healed=false"
  exit 0
fi

BACKUP="$(mktemp -d)"
git ls-files -z '*Cargo.toml' 'Cargo.lock' | xargs -0 -I{} sh -c 'mkdir -p "$1/$(dirname "$2")" && cp "$2" "$1/$2"' _ "$BACKUP" {}
restore() { (cd "$BACKUP" && find . -type f -print0 | xargs -0 -I{} cp "{}" "$OLDPWD/{}"); }

while IFS=$'\t' read -r pkg ver patched adv; do
  [ -n "$pkg" ] || continue
  log "advisory ${adv}: ${pkg} ${ver} (patched >= ${patched:-unknown})"
  if cargo update -p "${pkg}@${ver}" >/dev/null 2>&1; then
    :
  fi
  audit_json
  if findings | cut -f1,2 | grep -q "^${pkg}"$'\t'"${ver}$" && [ -n "$patched" ]; then
    # still present: pin to the patched release (and its exact-pin in manifests)
    while IFS= read -r toml; do
      sed -i -E "s/^(${pkg//-/[-_]}[[:space:]]*=[[:space:]]*\{?[[:space:]]*(version[[:space:]]*=[[:space:]]*)?\")=${ver}\"/\1=${patched}\"/" "$toml"
    done < <(git ls-files '*Cargo.toml')
    cargo update -p "${pkg}@${ver}" --precise "$patched" >/dev/null 2>&1 \
      || cargo update -p "${pkg}" --precise "$patched" >/dev/null 2>&1 \
      || log "could not move ${pkg} to ${patched}"
  fi
  echo "- \`${pkg}\` ${ver} → advisory ${adv}, target ${patched:-latest compatible}" >> "$SUMMARY"
done < <(findings)

audit_json
if [ -n "$(findings)" ]; then
  log "advisories remain after healing — rolling back"; findings
  restore; out "healed=false"; exit 1
fi
if ! cargo check --workspace --all-targets >/dev/null 2>&1; then
  log "healed tree does not compile (API break) — rolling back for manual migration"
  restore; out "healed=false"; exit 1
fi
log "healed: lockfile and manifests updated, audit clean, workspace compiles"
out "healed=true"
exit 0

#!/usr/bin/env bash
# Offline regression test for scripts/bridge_sanitizer.sh (pure shell, no network).
#
# Asserts that the sanitizer
#   * strips the torrc-only "Bridge " prefix and upper-cases fingerprints,
#   * keeps webtunnel's [2001:db8::] placeholder but drops extra webtunnel parameters,
#   * drops private / reserved obfs4 endpoints,
#   * never leaves a file empty (refills an empty projection from its siblings),
#   * writes export/orbot/* whose every line passes Orbot's own two regexes,
#   * is idempotent and --check reports 0 problems afterwards.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SAN="$SCRIPT_DIR/bridge_sanitizer.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
B="$TMP/bridge"
mkdir -p "$B" "$TMP/data"

FP="abababababababababababababababababababab"
FPU="ABABABABABABABABABABABABABABABABABABABAB"
CERT="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

cat >"$B/obfs4.txt" <<EOT
Bridge obfs4 8.8.4.4:443 $FP cert=$CERT iat-mode=1 extra=1
obfs4 192.0.2.1:443 $FP cert=$CERT iat-mode=0
obfs4 10.0.0.1:443 $FP cert=$CERT iat-mode=0
obfs4 8.8.4.4:443 $FPU cert=$CERT iat-mode=1
EOT
: >"$B/obfs4_tested.txt"
cat >"$B/webtunnel.txt" <<EOT
webtunnel [2001:db8::1]:443 $FP url=https://x.example/p sni-imitation=a.b ver=0.0.3
EOT
cat >"$B/vanilla.txt" <<EOT
Bridge 9.9.9.9:443 $FP
EOT

bash "$SAN" --root "$TMP" --bridge-dir "$B" >/dev/null

fail() { echo "FAIL: $*" >&2; exit 1; }

want="obfs4 8.8.4.4:443 $FPU cert=$CERT iat-mode=1"
[ "$(cat "$B/obfs4.txt")" = "$want" ] || fail "obfs4.txt not normalised/de-duplicated: $(cat "$B/obfs4.txt")"
[ -s "$B/obfs4_tested.txt" ] || fail "empty obfs4_tested.txt was not refilled"
grep -q 'sni-imitation' "$B/webtunnel.txt" && fail "extra webtunnel parameter survived"
grep -q '^webtunnel \[2001:db8::1\]:443 ' "$B/webtunnel.txt" || fail "webtunnel placeholder dropped"
grep -q '^Bridge ' "$B"/*.txt && fail "torrc Bridge prefix survived"
[ "$(cat "$B/vanilla.txt")" = "9.9.9.9:443 $FPU" ] || fail "vanilla line not normalised"

# Orbot's own validators, re-implemented with bash regexes.
IP4='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
IP6='\[[0-9a-fA-F:]+\]'
RO="^obfs4[[:space:]]+(${IP4}|${IP6}):[0-9]+[[:space:]]+[A-F0-9]{40}([[:space:]]+cert=[a-zA-Z0-9+/=]+)?([[:space:]]+iat-mode=[0-9]+)?\$"
RW="^webtunnel[[:space:]]+(${IP4}|${IP6}):[0-9]+[[:space:]]+[A-F0-9]{40}([[:space:]]+url=https?://[^[:space:]]+)?([[:space:]]+ver=[0-9]+\.[0-9]+\.[0-9]+)?\$"
n=0
for f in "$TMP"/export/orbot/orbot_*.txt; do
  case "$(basename "$f")" in orbot_vanilla.txt|orbot_snowflake.txt|orbot_meek.txt|orbot_extended.txt) continue ;; esac
  while IFS= read -r l || [ -n "$l" ]; do
    [ -z "${l// /}" ] && continue
    n=$((n + 1))
    [[ $l =~ $RO || $l =~ $RW ]] || fail "$(basename "$f"): Orbot would reject: $l"
  done <"$f"
done
[ "$n" -gt 0 ] || fail "no Orbot lines were exported"
# extended lists (current Orbot validator: also snowflake / meek_lite / vanilla) must satisfy the latest regex
python3 - "$TMP/export/orbot" <<'LATEST' || fail "extended Orbot list violates current Orbot validBridgeRegex"
import glob, os, re, sys
R = re.compile(r"^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+\])(:\d{1,5})?)\s+([\da-fA-F]{40})?[ \t\f\w\-/+:=.,\[\]]*$", re.A)
bad = [(os.path.basename(f), l) for f in glob.glob(os.path.join(sys.argv[1], "orbot_*.txt"))
       for l in open(f, encoding="utf-8").read().splitlines() if l.strip() and not R.fullmatch(l)]
sys.exit(1 if bad else 0)
LATEST
[ -s "$TMP/export/orbot/orbot_top.txt" ] || fail "orbot_top.txt is empty"

sum1="$(cd "$TMP" && find bridge export -type f -print0 | sort -z | xargs -0 sha256sum | grep -v manifest | sha256sum)"
bash "$SAN" --root "$TMP" --bridge-dir "$B" >/dev/null
sum2="$(cd "$TMP" && find bridge export -type f -print0 | sort -z | xargs -0 sha256sum | grep -v manifest | sha256sum)"
[ "$sum1" = "$sum2" ] || fail "sanitizer is not idempotent"
bash "$SAN" --root "$TMP" --bridge-dir "$B" --check >/dev/null || fail "--check still reports problems"

# --probe: dead untested bridges must never reach the Orbot lists; live ones are ranked first; a transparent
# egress proxy (canary answers) must disable the verdicts instead of trusting them.
T2="$TMP/probe"
mkdir -p "$T2/bridge" "$T2/data"
cat >"$T2/bridge/obfs4.txt" <<EOT
obfs4 8.8.4.4:443 $FPU cert=$CERT iat-mode=0
obfs4 8.8.8.8:9001 ${FPU//AB/CD} cert=$CERT iat-mode=0
EOT
echo "8.8.4.4:443" >"$T2/stub.txt"
SANITIZER_PROBE_STUB="$T2/stub.txt" bash "$SAN" --root "$T2" --probe >/dev/null
grep -q '8.8.4.4:443' "$T2/export/orbot/orbot_all.txt" || fail "live bridge missing from Orbot list"
grep -q '8.8.8.8:9001' "$T2/export/orbot/orbot_all.txt" && fail "dead bridge reached the Orbot list"
[ -s "$T2/bridge/obfs4.txt" ] && grep -q '8.8.8.8:9001' "$T2/bridge/obfs4.txt" || fail "probe must not delete archive lines"
[ -s "$T2/data/bridge_probe_cache.json" ] || fail "probe cache not written"

# diversity: >2 bridges from one /16 must not all land in orbot_top.txt while other ranges exist.
T3="$TMP/div"
mkdir -p "$T3/bridge" "$T3/data"
{
  for i in 1 2 3 4; do echo "obfs4 8.8.4.$((i + 10)):443 $(printf '%040X' "$i") cert=$CERT iat-mode=0"; done
  echo "obfs4 1.1.1.1:443 $(printf '%040X' 9) cert=$CERT iat-mode=0"
} >"$T3/bridge/obfs4.txt"
bash "$SAN" --root "$T3" >/dev/null
[ "$(head -n 3 "$T3/export/orbot/orbot_top.txt" | grep -c '^obfs4 8\.8\.')" -le 2 ] || fail "orbot_top not diversified"
[ "$(wc -l <"$T3/export/orbot/orbot_top.txt")" -eq 5 ] || fail "diversify must top up, not drop bridges"

echo "test_bridge_sanitizer: OK ($n Orbot lines validated, probe + diversity verified)"

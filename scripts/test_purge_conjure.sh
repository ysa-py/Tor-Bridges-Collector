#!/usr/bin/env bash
# Regression test for scripts/purge_conjure.sh: conjure (and only conjure) disappears from every artefact,
# everything Orbot accepts survives byte-for-byte, and the purge is idempotent.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PURGE="$SCRIPT_DIR/purge_conjure.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

FP=0123456789ABCDEF0123456789ABCDEF01234567
CERT=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
mkdir -p "$TMP/bridge" "$TMP/export/orbot" "$TMP/data"
printf 'conjure 192.0.2.12:80 %s url=https://registration.refraction.network/api transport=min\n' "$FP" >"$TMP/bridge/conjure.txt"
cat >"$TMP/bridge/iran_likely_working_all.txt" <<EOT
obfs4 8.8.4.4:443 $FP cert=$CERT iat-mode=0
conjure 192.0.2.12:80 $FP url=https://registration.refraction.network/api transport=min
webtunnel 8.8.8.8:443 $FP url=https://example.org/x ver=0.0.4
EOT
cat >"$TMP/export/iran_fastest.torrc" <<EOT
UseBridges 1
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client
ClientTransportPlugin conjure exec /usr/bin/conjure-client
ClientTransportPlugin obfs4,conjure,webtunnel exec /usr/bin/lyrebird
Bridge conjure 192.0.2.12:80 $FP url=https://x.example/api
Bridge obfs4 8.8.4.4:443 $FP cert=$CERT iat-mode=0
EOT
cat >"$TMP/bridge/bridge_history.json" <<EOT
{
  "obfs4 8.8.4.4:443 $FP": {"raw": "obfs4 8.8.4.4:443 $FP", "transport": "obfs4"},
  "conjure 192.0.2.12:80 $FP": {"raw": "conjure 192.0.2.12:80 $FP", "transport": "conjure"}
}
EOT
cat >"$TMP/bridge/telegram_manifest.json" <<EOT
{"required_files": ["conjure.txt", "obfs4.txt"], "files": [{"name": "conjure.txt"}, {"name": "obfs4.txt"}], "summary": {"conjure.txt": 1, "obfs4.txt": 2}}
EOT
printf '# bridges\n- [conjure.txt](https://x/bridge/conjure.txt)\n- [obfs4.txt](https://x/bridge/obfs4.txt)\n' >"$TMP/README.md"

bash "$PURGE" --root "$TMP" --check >/dev/null && fail "--check should report leftovers"
bash "$PURGE" --root "$TMP" >/dev/null

[ ! -e "$TMP/bridge/conjure.txt" ] || fail "conjure.txt not deleted"
grep -rqi conjure "$TMP" && fail "conjure text survived: $(grep -rIil conjure "$TMP")"
grep -q '^obfs4 8.8.4.4:443' "$TMP/bridge/iran_likely_working_all.txt" || fail "obfs4 line lost"
grep -q '^webtunnel 8.8.8.8:443' "$TMP/bridge/iran_likely_working_all.txt" || fail "webtunnel line lost"
grep -q 'ClientTransportPlugin obfs4,webtunnel exec /usr/bin/lyrebird' "$TMP/export/iran_fastest.torrc" || fail "shared plugin line not rewritten"
grep -q 'ClientTransportPlugin snowflake' "$TMP/export/iran_fastest.torrc" || fail "snowflake plugin lost"
python3 - "$TMP" <<'PY' || fail "JSON purge wrong"
import json, sys
t = sys.argv[1]
h = json.load(open(f"{t}/bridge/bridge_history.json"))
assert list(h) == [k for k in h if k.startswith("obfs4")] and len(h) == 1, h
m = json.load(open(f"{t}/bridge/telegram_manifest.json"))
assert m["required_files"] == ["obfs4.txt"] and m["files"] == [{"name": "obfs4.txt"}] and m["summary"] == {"obfs4.txt": 2}, m
PY
grep -q 'obfs4.txt' "$TMP/README.md" || fail "README obfs4 row lost"

sum1="$(cd "$TMP" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)"
bash "$PURGE" --root "$TMP" >/dev/null
sum2="$(cd "$TMP" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)"
[ "$sum1" = "$sum2" ] || fail "purge is not idempotent"
bash "$PURGE" --root "$TMP" --check >/dev/null || fail "--check still reports leftovers"
echo "test_purge_conjure: OK"

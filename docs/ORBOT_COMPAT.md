# Orbot compatibility, "Invalid bridge format" and conjure removal

## Root cause of `Invalid bridge format`

Orbot validates **every non-blank line** of the pasted text with one regex
(`CustomBridgeBottomSheet.kt`, `validBridgeRegex`) and rejects the **whole paste** if a single line fails:

```
^((meek_lite|obfs4|webtunnel|snowflake|dnstt)\s+)?          optional transport (conjure is NOT in the list)
((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+])(:\d{1,5})?)\s+   IPv4 / [IPv6] endpoint (required)
([\da-fA-F]{40})?                                            optional fingerprint
[ \t\f\w\-/+:=.,\[\]]*$                                      arguments: no ? ~ % @ & # ; characters
```

Older Orbot releases are stricter still (only `obfs4` and `webtunnel` lines, upper-case fingerprints).

What broke pastes in this repository, and what now prevents it:

| Cause | Fix (automatic, every run) |
| --- | --- |
| `conjure …` lines inside `iran_likely_working_all.txt`, `iran_likely_working_nin.txt`, `export/*` | `scripts/purge_conjure.sh` removes conjure everywhere; the Rust publisher no longer emits it |
| address-less `snowflake <FP> …` / `meek_lite <FP> url=…` lines in `export/*` | `scripts/bridge_sanitizer.sh` inserts the standard TEST-NET placeholder endpoint |
| torrc-style `Bridge ` prefix, comments, BOM / CR, lower-case fingerprints | normalised by the sanitizer |
| obfs4 certificates that are not exactly 70 base64 characters | rejected by the sanitizer |
| lines the latest Orbot regex would reject (`?`, `~`, `%` … in arguments) | dropped by the sanitizer |

## Paste-ready lists

`export/orbot/` (rebuilt hourly, every line re-validated before it is written):

* `orbot_top.txt` – 40 ranked, network-diversified lines (**recommended**)
* `orbot_obfs4.txt`, `orbot_webtunnel.txt`, `orbot_all.txt`, `orbot_ipv4.txt`, `orbot_ipv6.txt` – valid for old **and** new Orbot
* `orbot_vanilla.txt`, `orbot_snowflake.txt`, `orbot_meek.txt`, `orbot_extended.txt` – current Orbot only

Every `bridge/*.txt` file is also valid for current Orbot (verified by `scripts/test_bridge_sanitizer.sh`).

## Conjure

Orbot and Tor Browser for Android cannot use conjure, so it is removed completely: no `conjure*.txt` files,
no conjure lines, no `ClientTransportPlugin conjure`, no conjure rows in the manifest / ZIP / README.
`scripts/purge_conjure.sh --check` runs in CI and fails if anything reappears.

## Hourly dynamic pipeline

`.github/workflows/auto-bridge-fusion.yml` (hourly + after every TorShield-IR run) →
`scripts/auto_bridge_fusion.sh`: discovery (Moat, Onionoo, GitHub search with yield memory, community mirrors) →
validation → probing (network-honesty guard) → online-learning AI ranking → hourly rotated projections →
`purge_conjure.sh` → `bridge_sanitizer.sh` → derived Iran packs (`export/iran_fastest.torrc`,
`export/iran_turbo.torrc`, anti-DPI profile) → manifest / ZIP / README re-attestation.

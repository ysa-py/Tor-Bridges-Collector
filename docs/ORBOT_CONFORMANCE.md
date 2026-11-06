# Orbot conformance gate (`scripts/orbot_validate.mjs`)

`docs/ORBOT_COMPAT.md` explains *why* Orbot rejects a paste. This document adds the
**measurable guarantee** and the automated gate that keeps it true.

Orbot validates every non-blank line and rejects the whole paste when one line
fails — that is the `Invalid bridge format` dialog. The gate runs the same regex
over every published list, so a bad line can no longer reach a user.

## What the gate checks

| Check | Severity | Meaning |
| --- | --- | --- |
| `invalid` | **hard fail (exit 1)** | line does not match the current Orbot regex → users get `Invalid bridge format` |
| `duplicates` | hard fail with `--check` | identical line published twice; wastes paste size |
| `legacyInvalid` | report only | line rejected by older Orbot (IPv6, `snowflake`, `meek_lite`, `vanilla`, `dnstt`) |
| `placeholders` | warning | line uses TEST-NET (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) — syntactically valid, never reachable |
| `noFingerprint` | warning | line has no 40-hex fingerprint (Orbot accepts it, but pinning is weaker) |

## Current state (measured with this script)

```
files=18 lines=23987 hard=0 legacyOnly=14 duplicates=0 placeholders=363 noFingerprint=288
orbot_top.txt        lines=40   invalid=0 legacyInvalid=0    placeholder=0   noFP=0
orbot_ipv4.txt       lines=1204 invalid=0 legacyInvalid=0    placeholder=0   noFP=0
orbot_obfs4.txt      lines=1067 invalid=0 legacyInvalid=132  placeholder=0   noFP=0
orbot_webtunnel.txt  lines=532  invalid=0 legacyInvalid=263  placeholder=0   noFP=0
orbot_snowflake.txt  lines=61   invalid=0 legacyInvalid=61   placeholder=41  noFP=0
orbot_meek.txt       lines=88   invalid=0 legacyInvalid=88   placeholder=60  noFP=86
bridge/obfs4.txt     lines=8032 invalid=0 legacyInvalid=0    placeholder=0   noFP=0
```

Conclusions:

* **No line anywhere violates the current Orbot regex** — `hard=0`.
* `orbot_top.txt`, `orbot_ipv4.txt` and `bridge/obfs4.txt` are also **legacy-safe**
  (IPv4 only, `obfs4`/`webtunnel` only).
* `orbot_snowflake.txt` / `orbot_meek.txt` / `bridge/snowflake.txt` /
  `bridge/meek*.txt` consist largely of **TEST-NET placeholder endpoints**.
  They parse in Orbot but cannot connect; they should never be advertised as
  "working bridges". Keep them as format fixtures, or filter them out of the
  ranked lists.
* Mixed lists (`orbot_all.txt`, `orbot_extended.txt`, `orbot_vanilla.txt`) contain
  IPv6 / `snowflake` / `meek_lite` / `vanilla` lines and therefore fail on older
  Orbot builds. Point old devices at `orbot_top.txt`.

## Usage

```bash
# human readable summary for bridge/, export/orbot/ and export/
node scripts/orbot_validate.mjs

# CI gate: non-zero exit on hard violations or duplicates
node scripts/orbot_validate.mjs --check --json orbot-conformance-report.json

# safe normalisation (BOM/CR, "Bridge " prefix, duplicated params, fingerprint case)
node scripts/orbot_validate.mjs --fix

# a single directory, e.g. before publishing a Telegram export
node scripts/orbot_validate.mjs --dir export/orbot
```

`--fix` never deletes a bridge and never rewrites its semantics. It only:

* strips BOM/CR and a leading `Bridge ` prefix,
* keeps the first occurrence of a duplicated parameter (`fingerprint=` was
  duplicated on every snowflake line),
* upper-cases the fingerprint,
* drops **exact** duplicate lines.

## CI

`.github/workflows/orbot-conformance.yml` runs the gate hourly, on every pull
request that touches `bridge/`, `export/` or the script, and on pushes to `main`.
It is read-only (no commits, no data mutation) and uploads
`orbot-conformance-report.json` as an artifact.

Conjure is still handled by `scripts/purge_conjure.sh`; this gate never accepts a
conjure line, so a re-introduced conjure line fails CI immediately.

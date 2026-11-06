# Orbot conformance gate (`scripts/orbot_validate.mjs`)

`docs/ORBOT_COMPAT.md` explains *why* Orbot rejects a paste. This document adds the
**measured guarantee** and the automated gate that keeps it true.

Orbot validates every non-blank line with one regex and rejects the **whole paste**
when a single line fails — that dialog is `Invalid bridge format`.

## Scope

| Directory | Mode | Why |
| --- | --- | --- |
| `export/orbot/` | **hard gate** (exit 1 on one bad line) | this is what users paste into Orbot |
| `bridge/` | soft report | collector data sets (blocked / likely-working / histories) use other columns on purpose |
| `export/` | soft report | human reports, `.torrc`, CT domain lists and anti-DPI packs |

## Checks

| Field | Severity | Meaning |
| --- | --- | --- |
| `invalid` | **hard fail** | line does not match the current Orbot regex → user sees `Invalid bridge format` |
| `duplicates` | warning | identical line repeated; wastes paste budget |
| `legacyInvalid` | report | line rejected by older Orbot (IPv6, `snowflake`, `meek_lite`, `vanilla`, `dnstt`) |
| `placeholders` | warning | TEST-NET endpoint (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`): parses, never connects |
| `noFingerprint` | warning | no 40-hex fingerprint; Orbot accepts it, pinning is weaker |

## Measured on `main` (2026-11-06)

```
export/orbot : files=10 lines=12636 hard=0 duplicates=0 placeholders=202 noFingerprint=172
whole repo   : files=95 lines=73554 hard=80 duplicates=300 placeholders=2288 noFingerprint=1844
```

* **`export/orbot/` is clean: 0 invalid lines** — every paste-ready file matches Orbot's regex.
* `orbot_top.txt` (40 lines), `orbot_ipv4.txt` (1204) and `bridge/obfs4.txt` (8032) are
  additionally **legacy-safe** (IPv4-only, `obfs4`/`webtunnel` only). Old Orbot builds
  must use those; `orbot_all.txt`, `orbot_ipv6.txt`, `orbot_vanilla.txt`,
  `orbot_snowflake.txt`, `orbot_meek.txt` contain IPv6/other transports by design.
* `orbot_snowflake.txt` (41/61) and `orbot_meek.txt` (60/88) are mostly TEST-NET
  placeholders: valid syntax, unreachable endpoints. They are useful as format
  fixtures, but should not be described as working bridges.
* The 80 `invalid` lines of the soft report are confined to report/pack files in
  `export/` (`anti_ai_dpi_bridges.txt`, `iran_anti_dpi_elite.txt`, `iran_cut_pack.txt`,
  `iran_fastest.torrc`, `ct_*.txt`). They contain `#` headers, bare domains, or
  address-less `snowflake <fp> …` / `meek_lite <fp> …` lines. Anyone who pastes
  those into Orbot gets `Invalid bridge format`; the gate now measures them so the
  claim stays honest.

## Usage

```bash
node scripts/orbot_validate.mjs                                  # export/orbot, hard
node scripts/orbot_validate.mjs --all --soft --json report.json   # whole repo, report only
node scripts/orbot_validate.mjs --dir bridge                      # any directory
node scripts/orbot_validate.mjs --dir export/orbot --fix          # safe normalisation
```

`--fix` never deletes a bridge and never rewrites its semantics. It only:

* strips BOM/CR and a leading `Bridge ` prefix,
* keeps the first occurrence of a duplicated parameter (snowflake lines carry
  `fingerprint=` twice),
* upper-cases the fingerprint,
* drops **exact** duplicate lines.

## CI

`.github/workflows/orbot-conformance.yml` runs the hard gate on `export/orbot`
hourly (minute 23), on every push to `main` and on pull requests touching the
lists or the script. The soft whole-repository report is always produced, and both
JSON reports are uploaded as artifacts. The workflow is read-only: no commits and
no data mutation.

Conjure stays removed: `scripts/purge_conjure.sh` keeps purging it and this gate
fails CI as soon as a `conjure` line reappears in a paste-ready list.

# Automatic pool maintenance (`scripts/bridge_autofill.mjs`)

The repository must never ship an empty, stale or Orbot-unusable bridge list.
This script is the maintenance engine and `.github/workflows/bridge-pool-autofill.yml`
runs it **every hour**, committing only when something actually changed.

```bash
node scripts/bridge_autofill.mjs                       # report only
node scripts/bridge_autofill.mjs --fix --fill --dynamic # what CI runs
node scripts/bridge_autofill.mjs --check                # hard gate (exit 1)
node scripts/bridge_autofill.mjs --json report.json     # machine readable
```

No dependency, no network call, no API key. Node >= 20.

## What each mode does

| Mode | Effect | Safety |
| --- | --- | --- |
| *(default)* | per-file census: lines, valid Orbot lines, duplicates, placeholders, conjure | read-only |
| `--fix` | strip BOM/CR, `Bridge ` prefix, duplicated params, upper-case fingerprints, drop **exact** duplicate lines | `.torrc` files are never rewritten (torrc syntax needs `Bridge `); no semantic change |
| `--fill` | refill lists below `--min-lines` (default 40) from sibling lists of the **same transport + IP family** | append-only; existing lines are kept and re-validated |
| `--dynamic` | rebuild the AI-ranked, network-diversified Iran anti-DPI list + hourly rotation plan + Orbot projection of the torrc exports + rejected-line report | every written line re-checked with Orbot's regex; nothing deleted |
| `--check` | exit 1 on conjure lines, Orbot-invalid lines in `export/orbot/`, or an empty `bridge/*` list | CI gate |

## Measured effect on `main` (2026-11-06)

Before → after, produced by one run of `--fix --fill --dynamic`:

| File | Before | After |
| --- | --- | --- |
| `bridge/vanilla_ipv6_tested.txt` | 1 usable line | **40** valid IPv6 lines (appendix of the same family) |
| `export/iran_nin_pack.txt` | 594 lines incl. **299 exact duplicates** | 295 unique lines |
| `export/iran_cut_pack.txt`, `export/iran_rotation_bridges.txt`, `export/nin_cut_survivable.txt` | duplicated params / BOM | normalised |
| `export/orbot/orbot_iran_antidpi.txt` | – | **new**: 59 AI-ranked lines (30 obfs4, 27 webtunnel, 2 snowflake) |
| `export/orbot/orbot_from_torrc.txt` | – | **new**: 47 Orbot-pasteable lines extracted from the `.torrc` exports |
| `export/orbot/orbot_rotation_plan.json` | – | **new**: rotation bucket, pool size, per-transport mix, top-10 explanations |
| `export/orbot_rejected_report.tsv` | – | **new**: 52 lines Orbot would reject, with file + reason (kept, never deleted) |

Whole coverage at that moment:

```
files=95  lines=73334  valid=73253 (99.9%)  invalid=52  empty=2  duplicates=299  placeholders=2288  conjure=0
export/orbot gate: lines=12566  invalid=0
```

The 2 "empty" files are `export/ct_clean_bridges.txt` and `export/ct_flagged_domains.txt`
(CT domain lists, not bridge lists) — they are reported, never filled with unrelated data.

## The internal ranking model

`--dynamic` scores every candidate line with an explainable additive model (no external
service). Weights are pinned in the script so the output is reproducible:

| Feature | Weight |
| --- | --- |
| `webtunnel` (looks like a real HTTPS site) | **+24** |
| `snowflake` | +18 |
| `obfs4` | +15 |
| `meek_lite` | +4 |
| port 443 / 80 / other high port | +12 / +3 / +2 |
| IPv4 / IPv6 | +6 / −10 (Iranian DPI is v4-centric) |
| pinned 40-hex fingerprint | +6 |
| `iat-mode=1` / `iat-mode=2` | +9 / +5 |
| `front=` present / `url=https` | +6 / +4 |
| fresh source file (≤ 12 h old) | up to +6 |
| TEST-NET placeholder | **−80** (dropped) |
| Orbot-invalid | −100 (dropped) |

Then a diversity filter keeps the list usable from Iran:

* at most **3 per IPv4 /16**, **1 per /24** (blocking one range cannot kill the list),
* one line per fingerprint,
* transport mix caps (≤ 45 % webtunnel, ≤ 50 % per other transport),
* IPv6 and TEST-NET placeholders excluded,
* identities present in `*blocked*` / `*flagged*` lists are skipped.

### Hourly rotation

Every line gets `bucket = sha1(identity) % 6`. The selected bucket is
`floor(now / 1h) % 6`, so the published list **rotates every hour**, is fully
deterministic per hour, and needs no external state. `orbot_rotation_plan.json`
records the active bucket, the next rotation time and the top-10 explanations.

## Why the `.torrc` files matter

`export/*.torrc` is correct torrc syntax: every bridge line starts with `Bridge `.
Pasting those lines into Orbot produces **`Invalid bridge format`**, because Orbot's
validator rejects the `Bridge ` prefix. `--dynamic` therefore writes
`export/orbot/orbot_from_torrc.txt`: the same identities, normalised and validated
for Orbot. The `.torrc` files themselves are left untouched.

## Conjure

Still only conjure is removed (Orbot has no such transport). The script drops conjure
lines it finds, `--check` fails if one reappears, and `scripts/purge_conjure.sh` keeps
handling the wider repository.

---

## Self-extending harvester + Iran anti-DPI model (`scripts/bridge_harvest.mjs`)

Runs every hour **before** the autofill step (see `.github/workflows/bridge-pool-autofill.yml`).

| Stage | What happens |
|-------|--------------|
| Discover | GitHub search + tree API finds *new* collector repos and their bridge files; they are stored in `data/bridge_harvest_sources.json` and polled from then on. |
| Fetch | Built-in mirrors + `data/ai_fusion_extra_sources.json` + discovered files; retry/back-off, dead sources are quarantined with exponential back-off and retried automatically. A dead network is never fatal. |
| Validate | Only real **obfs4 / webtunnel / vanilla** lines that match Orbot's regex survive. Conjure is dropped, reserved/private endpoints are dropped, bad certs/urls/fingerprints are dropped, duplicate params are collapsed. |
| Probe | TCP connect + RTT. The probe switches itself off when the environment cannot answer truthfully (egress proxy, no IPv6) and the AI ranking is used on its own. |
| Pool | `data/bridge_harvest_pool.json` is the durable pool (alive streak, fail streak, RTT, first/last seen). The hourly collector may rewrite `bridge/*.txt`; the pool re-injects live bridges on the next run. Entries that stopped validating are dropped from the pool only. |
| Publish | Live bridges are **appended** to `bridge/*.txt` (never removed) and `export/orbot/orbot_harvest_live.txt` (probe-verified, one per /24 or domain, fastest + best first). |

### Internal Iran anti-DPI model (`scripts/lib/iran_antidpi_model.mjs`)

Deterministic, explainable, offline, no API key. Terms: transport (WebTunnel > Snowflake > obfs4 > meek),
TLS-like ports, flagged classic Tor ports (9001/9030/…), CDN-shielded endpoints (Cloudflare / Fastly / Azure),
`iat-mode`, domain fronting, IPv6 penalty, pinned fingerprint, probe liveness and RTT (speed).
`export/orbot/orbot_iran_antidpi.txt` additionally hardens obfs4 lines client-side (`iat-mode=0` -> `1`,
randomised packet timing against flow-timing DPI). The list rotates hourly.

### Correction: TEST-NET addresses are not always placeholders

Tor itself writes **Snowflake, meek_lite and WebTunnel** lines with `192.0.2.x` / `2001:db8::` as a dummy
address; the real connection goes through `url=` / `front=`. Those lines are real and working, so the
autofill/validator now treat TEST-NET as a dead placeholder **only for obfs4 and vanilla** (which dial the
IP). Previously snowflake/meek were scored -80 and could never reach the AI-ranked list.

### CI invariants

`--fix` no longer rewrites byte-exact derived artifacts (`iran_cut_pack.txt`, `iran_anti_dpi_elite.*`) and the
workflow regenerates the cut pack and NIN manifest after every refresh, so invariants C11/C13 stay green.
All workflow jobs use pinned runners (`ubuntu-24.04`), satisfying C15.

```
node scripts/bridge_harvest.mjs --discover --probe        # harvest + probe (hourly in CI)
node scripts/bridge_harvest.mjs --dry --no-fetch          # inspect the pool only
node scripts/bridge_autofill.mjs --fix --fill --dynamic   # rank + rotate
```

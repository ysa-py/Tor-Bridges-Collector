# Iran anti-DPI AI, Orbot fix and self-extending pool

Everything below runs **hourly and unattended** from
`.github/workflows/bridge-pool-autofill.yml`. No UI, no API key, no new dependency
(Node ≥ 20). No bridge line is ever deleted; only exact duplicates and `conjure`
(which Orbot cannot use) are removed.

## 1. Why Orbot said "Invalid bridge format" — and the permanent fix

Orbot (`CustomBridgeBottomSheet.kt`) validates **every** pasted line with one regex and
rejects the **whole paste** if a single line fails. `scripts/lib/orbot_format.mjs` is a
byte-for-byte port of that regex plus Orbot's Unicode-space cleaning.

Measured on this repository:

| Location | Orbot-valid | Notes |
| --- | --- | --- |
| `bridge/*.txt`, `export/orbot/*.txt` | 100 % | safe to paste |
| `export/*.txt`, `export/*.torrc` packs | **not** | `Bridge ` torrc prefix, `#` headers, address-less `snowflake <FP> …` / `meek_lite <FP> …` lines |

Those packs are produced by byte-exact generators (invariants C8/C11/C13), so they are
never rewritten. Instead `scripts/orbot_project.mjs` writes a **paste-ready twin** for each:

```
export/iran_nin_pack.txt        ->  export/orbot/orbot_pack_iran_nin_pack.txt
export/iran_cut_pack.txt        ->  export/orbot/orbot_pack_iran_cut_pack.txt
export/iran_turbo.torrc         ->  export/orbot/orbot_pack_iran_turbo.txt
…                                   export/orbot/orbot_pack_manifest.json (what was repaired / skipped)
```

Repairs never change meaning: prefix removed, dummy address inserted exactly as Tor writes
it (`snowflake 192.0.2.3:80`, `meek_lite 192.0.2.18:80`), duplicated `key=` tokens collapsed,
fingerprint upper-cased. Comments, bare domains, torrc directives and conjure are *skipped*, not
"fixed".

`scripts/orbot_validate.mjs` additionally rejects lines that pass the regex but make Tor answer
"configuration is invalid" after **Connect**: octet > 255, port 0 / > 65535, `obfs4` without `cert=`,
`webtunnel` without `url=`.

## 2. Internal AI (offline, self-training)

`scripts/lib/iran_antidpi_learn.mjs` + `scripts/lib/iran_antidpi_model.mjs`

* **Prior** — hand-tuned, explainable additive model (transport, port class, CDN shield, iat-mode,
  fronting, IPv6 penalty, probe RTT).
* **Learner 1** — logistic regression (SGD + L2, seeded ⇒ deterministic) over static features.
* **Learner 2** — range reputation: smoothed positive-rate per IPv4 /16 (Iranian filters block by
  hosting range, so a /16 blocked 40/41 times is the strongest single signal).
* **Training data** — the repository's own evidence: `bridge/iran_blocked.txt` (negatives) vs
  `bridge/iran_likely_working_*.txt` (positives). Retrained every hour; persisted in
  `data/iran_antidpi_weights.json` so a failed hour never loses the model.
* **Honest self-assessment** — hold-out AUC is stored in the model (0.836 at the time of writing)
  and scales its influence: a weak model degrades to the prior, never to noise.
* **/24 density penalty** — ranges stuffed with candidates get blocked together; diversity caps are
  applied on top (`selectDiverse`).

Hourly outputs (all Orbot-valid, rotate every hour through 6 network buckets):

| File | Objective |
| --- | --- |
| `export/orbot/orbot_iran_antidpi.txt` | balanced AI top-60, obfs4 hardened to `iat-mode=1` |
| `export/orbot/orbot_iran_stealth.txt` | maximum DPI resistance (WebTunnel/fronted/CDN, port 443) |
| `export/orbot/orbot_iran_fast.txt` | least overhead (direct obfs4/vanilla, RTT when probed) |
| `export/ech_top_bridges.txt` | CDN-shielded / HTTPS bridges first (was frozen at 1 line for 113 days) |

## 3. Self-extending harvester (`scripts/bridge_harvest.mjs`)

* Discovery every **2 h** (was 5 h): 12 repository queries (name/description/readme/**topics**),
  30 results each, up to 70 repos × 10 files, **plus GitHub code search** (token required) that finds raw
  `obfs4 cert= iat-mode=` / `webtunnel url= ver=` files in repositories that never mention "bridge".
* Dead sources are quarantined with back-off; a dead network is never fatal.
* Unverified admission cap raised 1 500 → 4 500 (probe-verified bridges were never capped); every
  admitted line is Orbot-valid, non-reserved, with a well-formed cert / url / fingerprint.

## 4. Workflow hardening

* `--json` with an absolute path (`$RUNNER_TEMP/…`) crashed `bridge_autofill.mjs` with `ENOENT` after the
  lists were already written — fixed (`path.resolve`).
* The commit step retries and rebases on a lost push race (other hourly bots write to `main`).
* Alias files are synced from their canonical list so they can no longer silently freeze.

## Run by hand

```bash
node scripts/test_orbot_format.mjs
node scripts/bridge_harvest.mjs --discover --probe
node scripts/bridge_autofill.mjs --fix --fill --dynamic
node scripts/bridge_fill_empty.mjs
node scripts/orbot_project.mjs --check
node scripts/orbot_validate.mjs --dir export/orbot
```

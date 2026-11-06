# Orbot "Configuration Invalid" / "Invalid bridge format" — root cause and permanent fix

## Root cause
The hourly publisher (Rust collector + `auto_bridge_fusion.sh`) re-wrote `bridge/` and `export/` **after** the Node
healing tools had run, so fresh data re-introduced lines Orbot/Tor reject:

* Snowflake lines with a damaged fingerprint (39 hex chars instead of 40) — Orbot's regex lets them through,
  Tor then refuses the whole configuration ("Configuration Invalid");
* template webtunnel lines (`url=https://example.org/path`, `[2001:db8::1]`) that can never connect;
* `Bridge ` prefixes / `#` headers / address-less snowflake and meek_lite lines in `export/*.torrc|txt`.

## Fix (fully automatic, every hour)
`scripts/auto_bridge_fusion.sh` now runs, in this order, before it attests the publication:

1. `bridge_autofill.mjs --fix --fill --dynamic` — heals fingerprints, normalises, de-duplicates, refills empty lists;
2. `iran_antidpi_adaptive.mjs` — Thompson-sampled Iran anti-DPI transport mix;
3. `bridge_fill_empty.mjs` — orphan lists + byte-identical aliases;
4. `purge_conjure.sh` — **only** conjure is removed (Orbot cannot use it);
5. derived builders, then `orbot_project.mjs` (paste-ready twins) and `orbot_validate.mjs --dir export/orbot`.

Nothing else is deleted: invalid lines stay in their source lists and are only left out of the paste-ready
`export/orbot/*` files. Paste `export/orbot/orbot_pack_*.txt` or `export/orbot/orbot_iran_adaptive.txt` into Orbot.

## Workflow run retention
`workflow-run-janitor.yml` keeps, per workflow, the newest success + newest failure (2 runs for debugging),
purges every finished run of workflows whose file no longer exists, cancels stuck runs, and re-dispatches itself
(max 6 times) while a backlog remains. Optional secret `RUN_CLEANUP_TOKEN` raises the API budget to 5000/h.

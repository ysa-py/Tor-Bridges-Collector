# Iran datacenter vantage (check-host.net)

Workflow: `.github/workflows/iran-vantage.yml` (hourly at :20, `workflow_dispatch`, one job, one quota).
Code: `scripts/iran_vantage.mjs`, `scripts/lib/iran_vantage.mjs`. Tests: `scripts/test_iran_vantage.mjs` (offline, also run in `main-ci`).
Output (append-only): `data/iran_vantage.jsonl` (not `bridge/`: that directory is an exact 73-file publication contract enforced by invariant C2 and `REQUIRED_FILES`); cursors: `data/iran_vantage_cursors.json`.

## What it proves - and what it does not

* GitHub-hosted runners are **not** in Iran. Runner TCP/TLS/PT results stay runner-side observations.
* The only Iranian vantage is the probe that **check-host.net** operates (`ir*` nodes are datacenter hosts, not home ISPs).
  Nodes are re-discovered on every run from `GET /nodes/hosts` (never hard-coded). On 2026-11-06 the list held `ir1`..`ir8`
  (Tehran, Isfahan, Shiraz, Qom); there was no `ir9`.
* Each record is **one Iran node vs one control node** (`de`, else `nl`) and is capped at
  `tcp-from-iran-datacenter-only` / `https-from-iran-datacenter-only`.
* It is **not** an obfs4/lyrebird handshake, a meek tunnel, a WebTunnel upgrade, a Snowflake WebRTC session or a Tor circuit.
  Missing data is `inconclusive`, never `blocked` or `working`. `class` is never copied into any working-bridge list and the
  stage never edits `iran_likely_working_*.txt`.
* Placeholder endpoints (`192.0.2.0/24`, `10.0.0.0/8`, ...) and IPv6 are never sent. For meek / snowflake / conjure the written
  address is ignored and only the `front=` (else the `url=` origin) is checked over HTTPS. URL paths (possible capability secrets),
  fingerprints and certs are never sent or stored.

## Classes

`iran_tcp_open`, `iran_https_open` (any HTTP code with flag 1, 403 included), `iran_tcp_unreachable`, `iran_https_unreachable`,
`iran_node_refused`, `endpoint_down` (both sides failed), `inconclusive` (anything else, pending, or either side unknown).

## Budget

<= 20 check-host start calls per run, >= 3 s apart, one Iran node (rotating) + one control node per call, poll every 2 s at most
12 times. HTTP 403/429 or `ok != 1` stops the batch immediately (no retry storm) and the job still exits 0.
Cursors advance only past lines that were actually considered and wrap at the end of each file.

## Privacy

Public bridge endpoints already listed in `bridge/` are sent to a third party (check-host.net) as plain TCP/HTTPS checks; that
service publishes its own report page. The User-Agent is the generic `iran-tcp-vantage-measurement/1.0`. The runner hides a home
IP but **not** the GitHub account: do not assume anonymity. No secret, token or account is required.

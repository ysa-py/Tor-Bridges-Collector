# TRANSPORT_REPORT

## Plugin registry (VERIFIED — `src/transport_plugin.rs`)

Six `TransportPlugin` implementations are present:

| Transport | Plugin | Notes |
| --- | --- | --- |
| obfs4 | `Obfs4Plugin` | IP-literal, cert/iat-mode params, 40-char hex fingerprint validation |
| webtunnel | `WebTunnelPlugin` | `url=`-based, `ver=` versions 0.0.1–0.0.6/1.0.0, TLS+WS upgrade probing |
| snowflake | `SnowflakePlugin` | capability-check semantics (TCP is not meaningful) |
| vanilla | `VanillaPlugin` | plain Tor relay lines |
| meek | `MeekPlugin` | domain-fronted meek_lite |
| conjure | `ConjurePlugin` | conjure reflectors |

Additional transport *processing* exists beyond the plugin registry (pipeline
stages for next-gen protocols, quantum/ECH, WARP, XTLS/REALITY VLESS, eBPF/XDP,
JA3 rotation, CT monitoring — `pipeline.rs` stages `nextgen`, `quantum`,
`warp`, `reality`, `ebpf`, `ja3`, `ct`). These are scoring/generation stages,
not additional client handshake implementations.

## Fallback ladder / invariants (VERIFIED by inspection + tests)

- The transport fallback ladder is **intact**: obfs4 → webtunnel → snowflake →
  vanilla → meek → conjure are all present in the plugin registry and the
  `bridge/` projections (`obfs4.txt`, `webtunnel.txt`, `snowflake.txt`,
  `vanilla.txt`, `meek*.txt`, `conjure.txt`, each with `_72h`/`_ipv6`/`_tested`
  variants). **Nothing removed.**
- Health-gate invariant (3 consecutive clean failures) is preserved:
  `source_circuit_breaker.rs` defaults `failure_threshold: 3` and gates
  transports/sources after repeated failure.
- Blackout vs DPI distinction is preserved: `nin_internet_cut_classifier.rs`,
  `nin_cut_tester.rs`, and `censorship_scorer_fusion.rs` implement the
  multi-anchor blackout detection logic.
- Adaptive transport weighting is real: `adaptive_transport.rs` +
  `adaptive_selector.rs` run in the CI pipeline (`Stage 8`, `rotation` stage);
  per-transport yield telemetry is recorded (`data/collector_yield_report.json`,
  `data/collector_yield_history.json`).

## Tier model (NEW this session — VERIFIED)

`src/evidence_stamp.rs` tags every `iran_results.json` entry:

- `tier_2_pt_handshake` — PT-level capability evidence (obfs4/webtunnel/
  snowflake handshake, `transport_capable=true`, `ws_101`, …)
- `tier_1_tcp` — TCP/TLS observation
- `untested` — no observation (rate-limited / no endpoint)

Real-data run: all 1,459 entries tagged; 481 `tested_working`, 978
`tested_failing`, all at `tier_1_tcp` (no PT-level evidence in the current
committed dataset — consistent with GAP-4: full PT handshakes need the relay
path in CI).

## NOT VERIFIED

- Full obfs4/webtunnel/snowflake client handshakes against live endpoints from
  an unblocked egress (needs the Cloudflare relay + secrets; see GAP-4).
- Iranian-side behavior of any transport (runner-side evidence only; README
  says the same).

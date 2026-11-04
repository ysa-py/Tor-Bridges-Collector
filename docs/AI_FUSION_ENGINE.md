# AI Bridge Fusion Engine (hourly, fully automatic)

`scripts/auto_bridge_fusion.sh` runs every hour (`.github/workflows/auto-bridge-fusion.yml`) and after every
TorShield-IR run. It needs no human input and never fabricates bridges.

| Stage | What happens |
|-------|--------------|
| Discover | Tor Moat · **curated raw sources** (Tor Browser `pt_config.json`, scriptzteam, Delta-Kronecker …, self-growing registry `data/ai_fusion_extra_sources.json`) · GitHub repo search (25 rotating queries) · **topic search** · **code search** (token) · yield memory |
| Probe | threaded TCP/TLS probes behind a network-honesty guard; candidates are shuffled by hour so none is starved |
| Rank | online logistic model + health + Iran anti-DPI prior |
| Fill | every `bridge/*.txt` is re-derived from `bridge_history.json`; empties go through a fallback chain. Vanilla IPv6 (no public source exists) is served from real probed vanilla lines, flagged in `data/ai_fusion_fallbacks.json`, and replaced automatically once a real IPv6 vanilla bridge appears |
| Freshness | `data/bridge_freshness.json`: per-file `last_verified` (every run) vs `content_changed_at`, and `supply_limited` reasons (Tor publishes only 1 conjure / ≤3 meek / ~10 snowflake lines, so those files legitimately change rarely) |
| Anti-DPI | `data/iran_hourly_mix.json`, `data/iran_anti_dpi_profile.json`, **`data/iran_anti_dpi_ultra.json`** (escalation ladder, 24 h uTLS/fragmentation rotation, DoH bootstrap, fastest-per-transport) and **`export/iran_fastest.torrc`** (lowest latency first) |
| Attest | `publication_contract.sh --rebuild --sync-counts` re-attests manifest, ZIP, README and summary counts (no advisories left) |

The anti-DPI files are advisory client hardening profiles derived from live probes; they do not assert reachability inside Iran.

# 🛡️ TorShield-IR — Tor Bridge Intelligence for Iran

> Rust-native bridge collector with smart Iran DPI analysis.<br>
> OONI-aware · ASN-filtered · Composite-scored · Auto-synced to `bridge/` and Telegram.<br>
> **Last update:** `2026-08-01 17:36 UTC`

---

## 🚨 Quick Start for Iran

**If international internet is cut (شبکه ملی فعال):**
```text
Use: bridge/iran_likely_working_snowflake.txt
     bridge/iran_likely_working_webtunnel.txt
     bridge/iran_likely_working_nin.txt
```

**Normal censorship (فیلترینگ معمول):**
```text
Use: bridge/iran_likely_working_all.txt   ← TCP-tested / OONI-aware working set
     bridge/iran_likely_working_obfs4.txt ← obfs4-first anti-DPI fallback
```

---

## ✅ OONI-Aware / TCP-Tested Working Bridges (Iran)

| File | Bridges |
| :--- | :---: |
| [iran_likely_working_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_all.txt) | `454` |
| [iran_likely_working_obfs4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_obfs4.txt) | `258` |
| [iran_likely_working_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_webtunnel.txt) | `1` |
| [iran_likely_working_snowflake.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_snowflake.txt) | `4` |
| [iran_likely_working_nin.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_nin.txt) | `259` |

> Files are rebuilt automatically into `bridge/` and mirrored in the Telegram ZIP archive when Telegram upload is enabled.

## 🌐 Globally Tested (TCP-reachable, Iran status varies)

| File | Bridges |
| :--- | :---: |
| [tested_global_obfs4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/tested_global_obfs4.txt) | `258` |
| [tested_global_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/tested_global_webtunnel.txt) | `1` |
| [tested_global_vanilla.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/tested_global_vanilla.txt) | `191` |

---

## 📦 Automatic Dual Persistence

| Destination | Artifact | Status |
| :--- | :--- | :--- |
| Runtime artifact | `tor_bridges.zip` | Rust-built by the Rust-native Stage 9 synchronizer from every committed `.txt` and `.json` bridge output; stored in `bridge/` for repository consumers and reused for Telegram upload |
| Git repository | [telegram_manifest.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/telegram_manifest.json) | JSON manifest with SHA-256, counts, raw URLs, and required-file health |
| Telegram | `tor_bridges.zip` | Uploaded by the Rust Stage 9 sync when `TELEGRAM_UPLOAD=true` and secrets exist |

### GitHub Actions bridge automation

The `torshield-ir.yml` workflow builds every required `bridge/` artifact in Stage 9, writes `bridge/tor_bridges.zip`, updates `bridge/telegram_manifest.json`, verifies the full required-file set in Stage 9b, and then commits the refreshed bridge outputs in Stage 11. When `TELEGRAM_UPLOAD=true` and Telegram secrets are configured, the same ZIP is uploaded to Telegram, so repository storage and Telegram delivery stay synchronized.

---

## 📊 Pipeline Summary

| Metric | Value |
| :--- | :--- |
| Total tested | `1443` |
| Globally reachable | `454` |
| Iran likely working | `5` |
| Iran likely blocked | `0` |
| Telegram-ready files | `54` |

---

## 🔬 Smart Anti-Filtering Classification

1. **TCP reachability** — fast live reachability from the runner.
2. **ASN safety** — filters Iranian ISP ASNs to reduce honeypot/false-positive risk.
3. **Transport strategy** — prioritises Snowflake/WebTunnel for NIN and obfs4 for normal DPI.
4. **Port risk** — prefers HTTPS-like ports where possible.
5. **OONI context** — uses recent and temporal blocking signals when available.
6. **CDN front validation** — checks WebTunnel/Snowflake survivability assumptions.
7. **AI DPI analysis** — records anti-AI DPI and SIAM/NGFW scoring reports.
8. **Rust dual output integrity** — sorted, deduplicated files plus SHA-256 manifest and runtime Telegram archive without binary PR diffs.

---

*Report: [docs/iran-bridge-status.md](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/docs/iran-bridge-status.md)*

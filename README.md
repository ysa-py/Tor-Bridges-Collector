# 🛡️ TorShield-IR — Tor Bridge Intelligence for Iran

> Polyglot (Python · Go · Rust) bridge collector with 8-layer Iran DPI analysis.<br>
> OONI-verified · ASN-filtered · Composite-scored · Auto-updated hourly · Telegram mirrored.<br>
> **Last update:** `2026-08-01 15:56 UTC`

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

## ✅ OONI-Verified / TCP-Tested Working Bridges (Iran)

| File | Bridges |
| :--- | :---: |
| [iran_likely_working_all.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_all.txt) | `454` |
| [iran_likely_working_obfs4.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_obfs4.txt) | `258` |
| [iran_likely_working_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_webtunnel.txt) | `1` |
| [iran_likely_working_snowflake.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_snowflake.txt) | `4` |
| [iran_likely_working_nin.txt](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/iran_likely_working_nin.txt) | `259` |

> Files include OONI-confirmed bridges (Tier 1) and TCP-reachable bridges with no OONI data (Tier 2 fallback). Every listed artifact is persisted in `bridge/` and mirrored to Telegram via `tor_bridges.zip`.

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
| Runtime artifact | `tor_bridges.zip` | Rebuilt from all `bridge/` files during Stage 9 for Telegram upload; existing repository ZIP remains listed in `bridge/` without binary PR diffs |
| Git repository | [telegram_manifest.json](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/bridge/telegram_manifest.json) | JSON manifest with SHA-256, counts, and raw URLs |
| Telegram | `tor_bridges.zip` | Uploaded by Stage 9 when `TELEGRAM_UPLOAD=true` and secrets exist |

---

## 📊 Pipeline Summary

| Metric | Value |
| :--- | :--- |
| Total tested | `1443` |
| Globally reachable | `454` |
| Iran likely working | `5` |
| Iran likely blocked | `0` |
| Telegram-ready files | `55` |

---

## 🔬 8-Layer Classification

1. **TCP reachability** — from GitHub Actions runner
2. **ASN filter** — exclude Iranian ISP ASNs (honeypot/false-positive guard)
3. **TLS fingerprint risk** — JA3 hash vs. known Iran DPI blocklist
4. **Port risk** — flag ports 9001/9030/9050 and prioritise HTTPS-like ports
5. **OONI recent** — 7-day anomaly history from Iranian probes
6. **OONI temporal** — 90-day recurrence rate (> 2/month → `frequently_blocked`)
7. **CDN front validation** — WebTunnel/Snowflake front-domain survivability
8. **AI anti-DPI integrity** — sorted/deduplicated bridge files, SHA-256 manifest, and Telegram ZIP mirror without binary PR diffs

---

*Report: [docs/iran-bridge-status.md](https://raw.githubusercontent.com/ysa-py/Tor-Bridges-Collector/refs/heads/main/docs/iran-bridge-status.md)*

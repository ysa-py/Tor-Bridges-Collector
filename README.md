# 🛡️ TorShield-IR — Tor Bridge Intelligence for Iran

> Polyglot (Python · Go · Rust) bridge collector with 8-layer Iran DPI analysis.<br>
> OONI-verified · ASN-filtered · Composite-scored · Auto-updated hourly.<br>
> **Last update:** `2026-06-27 21:36 UTC`

---

## 🚨 Quick Start for Iran

**If international internet is cut (شبکه ملی فعال):**
```
Use: bridge/iran_likely_working_snowflake.txt
     bridge/iran_likely_working_webtunnel.txt
```

**Normal censorship (فیلترینگ معمول):**
```
Use: bridge/iran_likely_working_all.txt   ← OONI-verified / TCP-tested working
     bridge/iran_likely_working_obfs4.txt ← obfs4 on port 443
```

---

## ✅ OONI-Verified / TCP-Tested Working Bridges (Iran)

| File | Bridges |
| :--- | :---: |
| [iran_likely_working_all.txt](https://raw.githubusercontent.com/ysa-py/MICAFP/refs/heads/main/bridge/iran_likely_working_all.txt) | `454` |
| [iran_likely_working_obfs4.txt](https://raw.githubusercontent.com/ysa-py/MICAFP/refs/heads/main/bridge/iran_likely_working_obfs4.txt) | `258` |
| [iran_likely_working_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/MICAFP/refs/heads/main/bridge/iran_likely_working_webtunnel.txt) | `1` |
| [iran_likely_working_snowflake.txt](https://raw.githubusercontent.com/ysa-py/MICAFP/refs/heads/main/bridge/iran_likely_working_snowflake.txt) | `4` |

> Note: Files include OONI-confirmed bridges (Tier 1) and TCP-reachable
> bridges with no OONI data (Tier 2 fallback). WebTunnel bridges are nearly
> always Tier 2 because OONI measures by IP but WebTunnel uses HTTPS domains.

## 🌐 Globally Tested (TCP-reachable, Iran status varies)

| File | Bridges |
| :--- | :---: |
| [tested_global_obfs4.txt](https://raw.githubusercontent.com/ysa-py/MICAFP/refs/heads/main/bridge/tested_global_obfs4.txt) | `258` |
| [tested_global_webtunnel.txt](https://raw.githubusercontent.com/ysa-py/MICAFP/refs/heads/main/bridge/tested_global_webtunnel.txt) | `1` |
| [tested_global_vanilla.txt](https://raw.githubusercontent.com/ysa-py/MICAFP/refs/heads/main/bridge/tested_global_vanilla.txt) | `191` |

---

## 📊 Pipeline Summary

| Metric | Value |
| :--- | :--- |
| Total tested | `1443` |
| Globally reachable | `454` |
| Iran likely working | `5` |
| Iran likely blocked | `0` |
| Iran ASN-blocked | `0` |

---

## 🔬 8-Layer Classification

1. **TCP reachability** — from GitHub Actions runner
2. **ASN filter** — exclude Iranian ISP ASNs (honeypot/false-positive guard)
3. **TLS fingerprint risk** — JA3 hash vs. known Iran DPI blocklist
4. **Port risk** — flag ports 9001/9030/9050
5. **OONI recent** — 7-day anomaly history from Iranian probes
6. **OONI temporal** — 90-day recurrence rate (> 2/month → `frequently_blocked`)
7. **CDN front validation** — WebTunnel front-domain ASN check
8. **RIPE Atlas** — optional one-off TCP measurement from IR probes

---

*Report: [docs/iran-bridge-status.md](https://raw.githubusercontent.com/ysa-py/MICAFP/refs/heads/main/docs/iran-bridge-status.md)*

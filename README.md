# 🛡️ TorShield-IR — Tor Bridge Intelligence for Iran

> Polyglot (Python · Go · Rust) bridge collector with 8-layer Iran DPI analysis.  
> OONI-verified · ASN-filtered · Composite-scored · Auto-updated hourly.  
> **Last update:** `2026-08-01 22:06 UTC`

---

## 🚨 Quick Start for Iran

**If international internet is cut (شبکه ملی فعال):**

```text
Use: bridge/iran_likely_working_snowflake.txt
     bridge/iran_likely_working_webtunnel.txt
```

**Normal censorship (فیلترینگ معمول):**

```text
Use: bridge/iran_likely_working_all.txt   ← OONI-verified / TCP-tested
     bridge/iran_likely_working_obfs4.txt ← obfs4 on port 443
```

---

## ✅ OONI-Verified / TCP-Tested Working Bridges (Iran)

| File | Bridges |
|---|---:|
| [iran_likely_working_all.txt](bridge/iran_likely_working_all.txt) | `0` |
| [iran_likely_working_obfs4.txt](bridge/iran_likely_working_obfs4.txt) | `0` |
| [iran_likely_working_webtunnel.txt](bridge/iran_likely_working_webtunnel.txt) | `0` |
| [iran_likely_working_snowflake.txt](bridge/iran_likely_working_snowflake.txt) | `0` |
| [iran_likely_working_nin.txt](bridge/iran_likely_working_nin.txt) | `0` |

> Files include OONI-confirmed bridges (Tier 1) and TCP-reachable bridges with no OONI data (Tier 2 fallback). WebTunnel is ranked for HTTPS-domain survivability.

## 🌐 Globally Tested (TCP-reachable, Iran status varies)

| File | Bridges |
|---|---:|
| [tested_global_obfs4.txt](bridge/tested_global_obfs4.txt) | `0` |
| [tested_global_webtunnel.txt](bridge/tested_global_webtunnel.txt) | `0` |
| [tested_global_vanilla.txt](bridge/tested_global_vanilla.txt) | `0` |

---

## 📊 Pipeline Summary

| Metric | Value |
|---|---:|
| Total tested | `0` |
| Globally reachable | `0` |
| Iran likely working | `0` |
| Iran likely blocked | `0` |
| Iran ASN-blocked | `0` |

---

## 🔬 8-Layer Classification

1. **TCP reachability** — GitHub Actions runner probes and Rust `bridge-probe` handshakes.
2. **ASN filter** — excludes Iranian ISP ASNs as a honeypot / false-positive guard.
3. **TLS fingerprint risk** — JA3 and TLS characteristics are scored against Iran DPI risk patterns.
4. **Port risk** — risky Tor defaults such as `9001`, `9030`, and `9050` are penalized.
5. **OONI recent** — 7-day anomaly history from Iranian probes.
6. **OONI temporal** — 90-day recurrence rate flags frequently blocked endpoints.
7. **CDN front validation** — WebTunnel front-domain ASN and HTTPS survivability checks.
8. **RIPE Atlas** — optional one-off TCP measurement from IR probes.

## 📦 Artifacts

- Full archive: [`bridge/tor_bridges.zip`](bridge/tor_bridges.zip)
- Telegram manifest: [`bridge/telegram_manifest.json`](bridge/telegram_manifest.json)
- Status report: [`docs/iran-bridge-status.md`](docs/iran-bridge-status.md)

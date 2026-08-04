# 🚨 TorShield-IR — Iran Bridge Status Report

**Generated:** `2026-08-04 09:53 UTC`<br>
**Pipeline:** Python scraper → Go iran_tester → Rust bridge-probe → OONI correlator

---

## Summary

| Metric | Value |
| :--- | :--- |
| Total bridges analysed | `1590` |
| Composite score > 0.5 | `429` (27%) |
| OONI clean (Iran) | `0` |
| OONI anomaly/blocked | `0` |
| OONI no data | `1590` |
| Quality gate (≥ 30 %) | `FAIL 🚨` |

---

## Iran DPI Intelligence

Iran's censorship infrastructure (SIAM) uses:
- **TLS fingerprinting** — JA3 hash matching for known Tor patterns (`e7d705a3286e19ea42f587b344ee6865`)
- **Port-based blocking** — Ports 9001, 9030, 9050 are consistently blocked
- **IP-based blocking** — Known Tor relay/bridge IPs are blocklisted within 24–48 h of first use
- **Traffic volume anomaly detection** — Unusual traffic shapes are flagged

### Recommended Transport Priority for Iran

```
Snowflake → WebTunnel (CDN-fronted) → obfs4 (port 443) → meek-lite → vanilla
```

---

## Top 20 Working Bridges (composite score > 0.5)

| Host:Port | Transport | TCP | OONI-IR | Score |
| :--- | :---: | :---: | :---: | :---: |
| `129.153.78.39:9959` | 🟡 | ✅ | ❓ | `0.68` |
| `158.69.55.8:445` | 🟡 | ✅ | ❓ | `0.68` |
| `158.69.55.8:2025` | 🟡 | ✅ | ❓ | `0.68` |
| `134.209.113.118:9000` | 🟡 | ✅ | ❓ | `0.68` |
| `118.241.190.171:45883` | 🟡 | ✅ | ❓ | `0.68` |
| `168.235.74.31:11111` | 🟡 | ✅ | ❓ | `0.68` |
| `136.25.5.185:9001` | 🟡 | ✅ | ❓ | `0.68` |
| `107.173.164.249:50604` | 🟡 | ✅ | ❓ | `0.68` |
| `107.191.102.246:11111` | 🟡 | ✅ | ❓ | `0.68` |
| `172.178.90.66:8080` | 🟡 | ✅ | ❓ | `0.68` |
| `138.68.51.223:9443` | 🟡 | ✅ | ❓ | `0.68` |
| `128.52.137.187:443` | 🟡 | ✅ | ❓ | `0.68` |
| `158.69.55.8:25001` | 🟡 | ✅ | ❓ | `0.68` |
| `157.131.185.200:8888` | 🟡 | ✅ | ❓ | `0.68` |
| `104.152.210.181:1105` | 🟡 | ✅ | ❓ | `0.68` |
| `128.52.137.188:443` | 🟡 | ✅ | ❓ | `0.68` |
| `134.209.113.118:9001` | 🟡 | ✅ | ❓ | `0.68` |
| `118.241.190.171:45883` | 🟡 | ✅ | ❓ | `0.68` |
| `108.175.13.9:80` | 🟡 | ✅ | ❓ | `0.68` |
| `167.99.37.45:8444` | 🟡 | ✅ | ❓ | `0.68` |

---

## Classification Definitions

| Status | Meaning |
| :--- | :--- |
| `iran_likely_working` | OONI shows clean results from Iranian probes in last 7 days |
| `iran_likely_blocked` | OONI shows anomaly/confirmed block from Iranian probes |
| `iran_frequently_blocked` | Recurrence rate > 2 blocks per 30-day period |
| `iran_unknown` | No OONI data from Iranian probes; TCP reachable from GitHub Actions |
| `tcp_unreachable` | TCP connection failed from GitHub Actions runner (likely globally down) |
| `iran_asn_blocked` | Bridge IP resolves to an Iranian ISP ASN — excluded from all packs |

---

## DPI Risk Flags

| Flag | Description |
| :--- | :--- |
| `iran_dpi_high_risk` | Bridge uses a JA3 fingerprint or port known to Iran's DPI blocklist |
| `iran_port_high_risk` | Bridge is on port 9001, 9030, or 9050 |
| `domain_front_degraded` | WebTunnel front domain resolves to a non-CDN IP |
| `domain_front_cdn_ok` | WebTunnel front domain resolves to a known CDN (Cloudflare, Azure, Fastly) |

---

*This report is generated automatically by [TorShield-IR](https://github.com/user/torshield-ir).*

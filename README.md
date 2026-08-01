# TorShield-IR — Tor Bridge Intelligence for Iran

Polyglot (Python · Go · Rust) bridge collector with 8-layer Iran DPI analysis.
OOni-verified · ASN-filtered · Composite-scored · Auto-updated hourly.

Last update: {{LAST_UPDATE_UTC}}

---

Quick Start for Iran
- If international internet is cut: use `bridge/iran_likely_working_snowflake.txt` or `bridge/iran_likely_working_webtunnel.txt`
- For normal censorship: `bridge/iran_likely_working_all.txt` (OOni-verified) or `bridge/iran_likely_working_obfs4.txt` (obfs4 on 443)

OOni-Verified / TCP-Tested Working Bridges (Iran)
| File | Bridges |
|---|---|
| iran_likely_working_all.txt | {{COUNTS.iran_likely_working_all}} |
| iran_likely_working_obfs4.txt | {{COUNTS.iran_likely_working_obfs4}} |
| iran_likely_working_webtunnel.txt | {{COUNTS.iran_likely_working_webtunnel}} |
| iran_likely_working_snowflake.txt | {{COUNTS.iran_likely_working_snowflake}} |

Globally Tested (TCP-reachable, Iran status varies)
| File | Bridges |
| tested_global_obfs4.txt | {{COUNTS.tested_global_obfs4}} |
| tested_global_webtunnel.txt | {{COUNTS.tested_global_webtunnel}} |
| tested_global_vanilla.txt | {{COUNTS.tested_global_vanilla}} |

Pipeline Summary
| Metric | Value |
| Total tested | {{METRICS.total_tested}} |
| Globally reachable | {{METRICS.globally_reachable}} |
| Iran likely working | {{METRICS.iran_likely_working}} |
| Iran likely blocked | {{METRICS.iran_likely_blocked}} |
| Iran ASN-blocked | {{METRICS.iran_asn_blocked}} |

8-Layer Classification
1. TCP reachability — from GitHub Actions runner
2. ASN filter — exclude Iranian ISP ASNs (honeypot/false-positive guard)
3. TLS fingerprint risk — JA3 hash vs. known Iran DPI blocklist
4. Port risk — flag ports 9001/9030/9050
5. OONI recent — 7-day anomaly history from Iranian probes
6. OONI temporal — 90-day recurrence rate (>2/month => frequently_blocked)
7. CDN front validation — WebTunnel front-domain ASN check
8. RIPE Atlas — optional one-off TCP measurement from IR probes

Report: docs/iran-bridge-status.md

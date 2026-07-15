# 🛡️ گزارش تحلیل SIAM ایران / Iran SIAM DPI Analysis

> آخرین بروزرسانی: `2026-06-27 21:36 UTC`  
> کل پل‌های تحلیل‌شده: **1443**  
> میانگین امتیاز دور زدن: **53.7%**  
> بهترین امتیاز: **93.0%**

---

## 📊 خلاصه لایه‌بندی SIAM / SIAM Bypass Tier Summary

| سطح / Tier | تعداد / Count | توضیح / Description |
| :--- | :---: | :--- |
| 👻 PHANTOM  | 6  | کاملاً ناشناس — سیستم SIAM هیچ سیگنالی دریافت نمی‌کند |
| 🕶️ STEALTH  | 228  | قوی — از ۶-۷ لایه از ۸ لایه عبور می‌کند |
| 🥷 COVERT   | 757   | متوسط — از ۴-۵ لایه عبور می‌کند |
| ⚠️ EXPOSED  | 0  | ضعیف — اکثر لایه‌های SIAM تشخیص می‌دهند |
| 🚫 DETECTED | 452 | بلاک می‌شود — SIAM تشخیص کامل می‌دهد |

---

## 🔬 ۸ لایه سیستم SIAM ایران / 8 Layers of Iran SIAM DPI

| لایه | نام | توضیح |
| :--- | :--- | :--- |
| L1 | Packet Length Fingerprinting | CNN تحلیل هیستوگرام اندازه بسته‌ها |
| L2 | IAT Timing Analysis | LSTM تحلیل فواصل زمانی بین بسته‌ها |
| L3 | Flow Feature Extraction | NetFlow + گشتاورهای آماری |
| L4 | JA3/JA3S Fingerprint | پایگاه داده ۵۰k اثر انگشت TLS |
| L5 | Certificate + SNI | تطبیق گواهی و SNI با پایگاه داده رله Tor |
| L6 | ALPN Anomaly | تشخیص ALPN نامعمول روی پورت ۴۴۳ |
| L7 | Temporal Analysis | تشخیص ضربان ۱ ثانیه‌ای Tor vanilla |
| L8 | AS Relationship Graph | ارتباط ASN رله با شبکه‌های CDN |

---

## 🚀 راهنمای انتخاب پل / Bridge Selection Guide

```
شبکه ملی فعال (NIN / قطع اینترنت بین‌المللی):
  → export/iran_phantom_bridges.txt  (Snowflake + WebTunnel CDN)

فیلترینگ معمولی SIAM:
  → export/iran_stealth_bridges.txt  (obfs4 IAT-2 + meek-lite)

هر شرایطی / Any condition:
  → bridge/iran_likely_working_all.txt
```

---

## 📈 توزیع transport / Transport Distribution

| Transport | تعداد |
| :--- | :---: |
| obfs4 | 802 |
| vanilla | 452 |
| webtunnel | 185 |
| snowflake | 4 |

---

*تولید شده توسط iran_anti_siam.py — TorShield-IR*
# 🛡️ گزارش تحلیل SIAM ایران / Iran SIAM DPI Analysis

> آخرین بروزرسانی: `2026-08-09 15:58 UTC`  
> کل پل‌های تحلیل‌شده: **1447**  
> میانگین امتیاز دور زدن: **50.4%**  
> بهترین امتیاز: **93.0%**

---

## 📊 خلاصه لایه‌بندی SIAM / SIAM Bypass Tier Summary

| سطح / Tier | تعداد / Count | توضیح / Description |
| :--- | :---: | :--- |
| 👻 PHANTOM  | 4  | کاملاً ناشناس — سیستم SIAM هیچ سیگنالی دریافت نمی‌کند |
| 🕶️ STEALTH  | 58  | قوی — از ۶-۷ لایه از ۸ لایه عبور می‌کند |
| 🥷 COVERT   | 920   | متوسط — از ۴-۵ لایه عبور می‌کند |
| ⚠️ EXPOSED  | 0  | ضعیف — اکثر لایه‌های SIAM تشخیص می‌دهند |
| 🚫 DETECTED | 465 | بلاک می‌شود — SIAM تشخیص کامل می‌دهد |

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
| obfs4 | 973 |
| vanilla | 465 |
| webtunnel | 7 |
| snowflake | 2 |

---

*تولید شده توسط iran_anti_siam.py — TorShield-IR*
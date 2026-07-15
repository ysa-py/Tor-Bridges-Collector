# راهنمای استقرار: جایگزینی GitHub Actions / CircleCI / GitLab CI با n8n روی Hugging Face Spaces

## معماری

```
GitHub repo (torshield-ir)
   │ push webhook
   ▼
Hugging Face Space (Docker, Private, رایگان، بدون کارت)
   ├── n8n  (orchestrator — همان نقش CircleCI/GitHub Actions)
   ├── Python 3.12 + Go 1.22 + Rust 1.80  (همان toolchain فعلی)
   └── کلون لوکال ریپو (هر بوت رفرش می‌شود)
   │
   ▼ workflows/credentials persist
Supabase Postgres (رایگان، بدون کارت)
```

همه چیز در **یک کانتینر** است — n8n با نود Execute Command مستقیم روی
همان کانتینر دستور اجرا می‌کند، پس به SSH بین دو سرویس نیازی نیست
(SSH/Dev Mode هاگینگ‌فیس فقط با اشتراک پولی PRO فعال می‌شود).

## چرا این ترکیب

| نیاز شما | راه‌حل |
|---|---|
| بدون VPS / بدون هاست جدا | Hugging Face Space میزبانی را رایگان انجام می‌دهد |
| بدون کارت بانکی | هم HF و هم Supabase بدون کارت کار می‌کنند |
| رایگان | ۲ vCPU / ۱۶ گیگ رم / ۵۰ گیگ دیسک — کافی برای این پایپ‌لاین |
| کاملاً خودکار | Webhook گیت‌هاب + Schedule/Error Trigger داخلی n8n |
| داده‌ها از بین نروند | دیسک Space ephemeral است → Supabase دیتابیس n8n را پایدار نگه می‌دارد |

## واقعیت‌هایی که باید بدانید (برای "صفر خطا" واقعی)

- Space رایگان بعد از مدتی بی‌فعالیتی sleep می‌شود → کرون‌های داخلی n8n
  هم متوقف می‌شوند. **راه‌حل:** یک پینگر رایگان (مثلاً cron-job.org،
  بدون کارت) که هر ۲۵-۳۰ دقیقه آدرس Space را بزند تا بیدار بماند.
- دیسک لوکال با هر ری‌استارت پاک می‌شود — برای همین .env هر بار از نو
  از Secrets ساخته می‌شود (همان منطق `circleci_env_bootstrap.sh` بدون
  تغییر) و نتایج هر job (مثل ooni-poll) مستقیم به گیت‌هاب push می‌شوند،
  دقیقاً مثل الان.
- اولین build ایمیج (نصب Go+Rust+Python+n8n) چند دقیقه طول می‌کشد؛
  بیلدهای بعدی سریع‌ترند چون لایه‌ها کش می‌شوند.

## مرحله به مرحله

1. **حساب Hugging Face** بسازید (بدون کارت) → `New Space` →
   SDK = Docker، Visibility = **Private**.
2. **حساب Supabase** بسازید (بدون کارت) → پروژه جدید → از تب Connect،
   بخش Transaction Pooler را باز کنید و host/port/user/dbname/password
   را یادداشت کنید.
3. فایل‌های `Dockerfile`، `entrypoint.sh` و `SPACE_README.md` (با تغییر
   نام به `README.md`) را در ریپوی همان Space پوش کنید.
4. در تنظیمات Space → **Variables and secrets**، این‌ها را اضافه کنید:
   - `GH_PAT`, `GH_OWNER`, `GH_REPO`, `GIT_BRANCH=main`
   - تمام متغیرهای `configs/env_template.sh` پروژه (همان نام‌ها)
   - `DB_TYPE=postgresdb`, `DB_POSTGRESDB_HOST`, `DB_POSTGRESDB_PORT`,
     `DB_POSTGRESDB_USER`, `DB_POSTGRESDB_PASSWORD`,
     `DB_POSTGRESDB_DATABASE` (مقادیر را از Supabase بردارید)
   - `N8N_ENCRYPTION_KEY` (یک رشته‌ی تصادفی طولانی خودتان بسازید و جایی
     ذخیره کنید — اگر عوض شود credentialهای ذخیره‌شده در n8n قابل
     رمزگشایی نمی‌مانند)
5. Space را Restart کنید؛ صفحه‌ی n8n را در یک تب جدید باز کنید و یک
   اکانت ادمین بسازید.
6. در گیت‌هاب ریپوی torshield-ir → Settings → Webhooks → آدرس
   webhook نود n8n (بعد از ساخت ورک‌فلوی push در مرحله بعد) را اضافه
   کنید، event = `push`.
7. یک پینگر رایگان (cron-job.org) روی آدرس Space ست کنید، هر ۲۵ دقیقه.
8. ورک‌فلوهای n8n را طبق جدول نگاشت زیر بسازید (هر کدام چند نود
   Execute Command + یک Trigger).

## نگاشت دقیق job ها به n8n

| منبع (CircleCI job) | دستور اصلی | Trigger در n8n |
|---|---|---|
| env-bootstrap | `bash scripts/circleci_env_bootstrap.sh` | همه‌ی workflow ها اول این را صدا می‌زنند (یا در entrypoint انجام می‌شود) |
| quality-gate | py_compile loop + yaml lint + `ruff check .` + `mypy .` + `pytest --cov=.` | روی push |
| go-quality-gate | `go vet ./...` + `gofmt -l .` + `go test -short ./...` | روی push |
| build-rust | `cd bridge-probe && cargo build --release && cargo test --release` | روی push |
| build-go | `go build ./cmd/iran_tester/` + `./cmd/probe_scheduler/` | روی push |
| scrape | `python main.py --mode full` + `ooni_correlator.py` + `ai_anti_dpi_iran.py` + `ai_dpi_quantum_evasion.py` | روی push به main/master، بعد از quality-gate/build |
| ai-rerank | `ai_bridge_reranker.py` + `_v2.py` | بعد از scrape |
| packaging | `bash scripts/circleci_packaging.sh` | بعد از ai-rerank، روی main/master |
| ooni-poll (shallow) | `circleci_ooni_poller.py --depth shallow` + git commit/push | Schedule Trigger هر ۶ ساعت |
| ooni-poll (deep) + ai-gateway-health + self-heal | همان به‌علاوه `ai_gateway_health_check.py` و `self_healing_engine_v2.py` | Schedule Trigger هر ۱۲ ساعت |
| ai-gateway-health (سبک) | `ai_gateway_health_check.py` | Schedule Trigger ساعتی |
| daily packaging | quality-gate → scrape → ai-rerank → packaging | Schedule Trigger روزانه |
| self-heal | `self_healing_engine_v2.py` + `zero_error_engine_v5.sh` | Error Trigger (داخلی n8n، روی فِیل هر ورک‌فلوی دیگر) |

## قدم بعدی

این فایل‌ها معماری و اسکلت را آماده می‌کنند؛ ساخت دقیق نودهای n8n (با
تنظیمات داخل هر Execute Command node) قدم بعدی است. چون اینجا اتصال
اینترنت/n8n واقعی برای تست ندارم، پیشنهاد می‌کنم یکی‌یکی ورک‌فلوها را
بسازیم — مثلاً اول `ci-push` (سنگین‌ترین و پرکاربردترین) — و من برای هر
کدام دقیقاً بگویم چه نودی، با چه پارامتری.

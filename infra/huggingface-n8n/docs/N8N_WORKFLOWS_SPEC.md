# مشخصات دقیق ورک‌فلوهای n8n — معادل ۱:۱ با .circleci/config.yml

> منبع: همین فایل `.circleci/config.yml` خودِ پروژه (۶۴۱ خط، ۹ job، ۶ workflow).
> هیچ دستوری حذف، خلاصه، یا تغییر داده نشده — فقط executor تغییر کرده
> (به‌جای container جدا برای هر job، همه روی یک کانتینر n8n اجرا می‌شن).

## چرا بعضی بخش‌ها در n8n نیستن (حذف نشده‌اند — بی‌نیاز شده‌اند)

| بخش CircleCI | چرا در n8n لازم نیست |
|---|---|
| `persist_to_workspace` / `attach_workspace` | همه‌ی نودها روی یک فایل‌سیستم مشترک کار می‌کنن؛ فایلی که یک نود ساخت، نود بعدی همون‌جا می‌بینتش |
| `restore_cache` / `save_cache` (pip/go/cargo) | کانتینر بین اجراها زنده می‌مونه (تا قبل از sleep/restart)؛ کش روی دیسک باقی می‌مونه بدون نیاز به مدیریت دستی |
| `docker auth: *ghcr-auth` | فقط برای pull کردن image های `cimg/*` لازم بود؛ الان همه‌چیز در یک Dockerfile خودمونه |
| `executor: rust-180` / `go-122` / ... | یک Dockerfile واحد (که قبلاً ساختیم) همه‌ی toolchain ها رو داره |

هیچ‌کدوم از این‌ها قابلیت از دست رفته نیستن — فقط در معماری تک‌کانتینری بی‌مصرف شدن.

---

## Workflow 1 — `ci-push` (معادل push trigger)

**Trigger:** Webhook node → متد POST، مسیر `/webhook/ci-push`، گیت‌هاب روی push بهش هوک می‌زنه.

| # | نوع نود | نام | دستور / تنظیمات (عیناً از config.yml) |
|---|---|---|---|
| 1 | Execute Command | env-bootstrap | `cd /home/user/torshield-ir && bash scripts/circleci_env_bootstrap.sh` |
| 2 | Execute Command | quality-gate · syntax | همون حلقه‌ی `py_compile` خط ۲۲۲-۲۳۸ کانفیگ، عیناً |
| 3 | Execute Command | quality-gate · yaml-lint | `python -c "import yaml,sys,glob; [yaml.safe_load(open(f)) for f in glob.glob('**/*.yml', recursive=True) if '.venv/' not in f]"` |
| 4 | Execute Command | quality-gate · ruff | `ruff check . --exclude .venv --exclude build` (با `continueOnFail: true`، چون در کانفیگ اصلی `\|\| true` داره) |
| 5 | Execute Command | quality-gate · mypy | `mypy . --ignore-missing-imports --no-error-summary` (continueOnFail) |
| 6 | Execute Command | quality-gate · pytest | `pytest --cov=. --cov-report=xml:reports/coverage.xml --cov-report=html:reports/coverage_html --junitxml=reports/junit.xml -ra -q` (continueOnFail) |
| 7 | Execute Command | go-quality-gate · vet | `go vet ./...` (continueOnFail) |
| 8 | Execute Command | go-quality-gate · gofmt | `out=$(gofmt -l . 2>/dev/null \| grep -v '^vendor/' \|\| true); if [ -n "$out" ]; then echo "$out"; exit 1; fi` |
| 9 | Execute Command | go-quality-gate · test | `go test -short -count=1 ./...` (continueOnFail) |
| 10 | Execute Command | build-rust | `cd bridge-probe && cargo build --release && cp target/release/bridge-probe ../bridge-probe-bin` |
| 11 | Execute Command | build-rust · test | `cd bridge-probe && cargo test --release` (continueOnFail) |
| 12 | Execute Command | build-go | `CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags '-s -w' -o iran_tester ./cmd/iran_tester/ && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags '-s -w' -o probe_scheduler ./cmd/probe_scheduler/` |
| 13 | IF | فقط main/master؟ | شرط: `{{$json.branch}} == "main" \|\| "master"` (از payload وب‌هوک گیت‌هاب) |
| 14 | Execute Command | scrape · main pipeline | `python main.py --mode full` (تایم‌اوت نود را ۴۵ دقیقه بگذارید — معادل `no_output_timeout: 45m`) |
| 15 | Execute Command | scrape · ooni correlator | `python ooni_correlator.py` (continueOnFail) |
| 16 | Execute Command | scrape · AI anti-DPI | `python ai_anti_dpi_iran.py && python ai_dpi_quantum_evasion.py` (continueOnFail) |
| 17 | Execute Command | ai-rerank | `python scripts/ai_bridge_reranker.py && python scripts/ai_bridge_reranker_v2.py` (continueOnFail) |
| 18 | Execute Command | packaging | `bash scripts/circleci_packaging.sh` |
| 19 | HTTP Request | آپلود تارگز به GitHub Release | POST به `https://api.github.com/repos/{{GH_OWNER}}/{{GH_REPO}}/releases` با هدر `Authorization: token {{GH_PAT}}` — **جایگزین `store_artifacts`** که در CircleCI آرتیفکت رو نگه می‌داشت |
| 20 | Slack (اختیاری) | notify-on-failure | فقط اگر `SLACK_WEBHOOK_URL` ست شده باشه؛ روی هر نود قبلی که fail بشه |

---

## Workflow 2 — `schedule-ooni-6h`

**Trigger:** Schedule Trigger node → Cron: `0 */6 * * *`

| # | نود | دستور |
|---|---|---|
| 1 | Execute Command | env-bootstrap (همون دستور بالا) |
| 2 | Execute Command | `python scripts/circleci_ooni_poller.py --depth shallow --out data/ooni_iran_snapshot.json --dashboard data/dashboard.json --telemetry data/telemetry_state.json` |
| 3 | Execute Command | commit & push: <br>`git diff --quiet --exit-code data/ \|\| (git add data/ooni_iran_snapshot.json data/dashboard.json data/telemetry_state.json data/censorship_state.json && git commit -m "chore(ooni): shallow poll — $(date -u +%FT%TZ)" && git pull --rebase origin main && git push origin main)` |

## Workflow 3 — `schedule-ooni-12h`

**Trigger:** Schedule Trigger → Cron: `0 */12 * * *`

همان نودهای بالا با `--depth deep`، به‌علاوه دو نود موازی:
- `python scripts/ai_gateway_health_check.py` (تایم‌اوت ۲۰ دقیقه)
- `python recovery/self_healing_engine_v2.py && bash scripts/zero_error_engine_v5.sh`

## Workflow 4 — `schedule-hourly-health`

**Trigger:** Schedule Trigger → Cron: `0 * * * *`
نود: `python scripts/ai_gateway_health_check.py`

## Workflow 5 — `schedule-daily-packaging`

**Trigger:** Schedule Trigger → Cron: `0 3 * * *` (یا هر ساعتی که می‌خواید)
ترتیب: env-bootstrap → quality-gate (نودهای ۲-۶ بالا) → scrape (۱۴-۱۶) → ai-rerank (۱۷) → packaging + Release upload (۱۸-۱۹)

## Workflow 6 — `on-failure-self-heal`

**Trigger:** Error Trigger node (داخلی n8n — خودکار روی fail شدن هر ۵ ورک‌فلوی بالا فعال می‌شه؛ نیازی به سیم‌کشی دستی نیست)
نود: `python recovery/self_healing_engine_v2.py && bash scripts/zero_error_engine_v5.sh`

---

## نکته‌ی مهم درباره‌ی Render (بک‌آپ)

مستندات Render می‌گه بدون کارت، ولی چند کاربر واقعی در فروم خودشون (۲۰۲۴ و ۲۰۲۵) گزارش دادن هنگام ساخت Web Service ازشون کارت خواسته شده — احتمالاً بسته به ریسک حساب/منطقه. **همون Dockerfile فعلی بدون تغییر روی Render هم کار می‌کنه** (Render از Dockerfile مستقیم پشتیبانی می‌کنه)، پس اگه خواستید امتحان کنید فقط ریپو رو وصل کنید و Build Command خالی بذارید (Dockerfile خودش تشخیص داده می‌شه). اگه کارت خواست، خبر بدید بک‌آپ بعدی رو بررسی کنیم.

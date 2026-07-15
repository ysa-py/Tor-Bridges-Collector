# ورک‌فلوهای n8n — نسخه‌ی ذخیره‌شده در گیت

این پوشه نسخه‌ی اولیه‌ی هر ۶ ورک‌فلوی n8n پروژه است (معادل دقیق
`.circleci/config.yml`)، به‌صورت JSON قابل Import مستقیم در n8n.

| فایل | معادل CircleCI workflow |
|---|---|
| `01-ci-push.json` | `ci-push` |
| `02-schedule-ooni-6h.json` | `schedule-ooni-6h` |
| `03-schedule-ooni-12h.json` | `schedule-oomi-12h` |
| `04-schedule-hourly-health.json` | `schedule-hourly-health` |
| `05-schedule-daily-packaging.json` | `schedule-daily-packaging` |
| `06-on-failure-self-heal.json` | `on-failure-self-heal` |

## چرا این فایل‌ها در گیت نگه می‌داریم (نه فقط در Supabase)

دیتابیس n8n (Supabase) خود ورک‌فلوها رو پایدار نگه می‌داره، ولی اگه
Space بن بشه یا حساب Supabase مشکل پیدا کنه، این JSON ها تنها نسخه‌ی
قابل بازیابی سریع شما هستن — با Import همین فایل‌ها در هر نصب تازه‌ی
n8n (روی هر هاستی)، در چند دقیقه کل پایپ‌لاین دوباره سر پا می‌شه.

## نحوه‌ی Import

در n8n: منوی بالا → **Import from File** → فایل JSON مربوطه رو انتخاب
کنید. بعد از Import:
1. مقادیر env (`GH_PAT`, `GH_OWNER`, `GH_REPO`, ...) از Space Secrets
   خونده می‌شن — نیازی به تنظیم دستی نیست.
2. روی نود `scrape - main pipeline` (در `01-ci-push.json` و
   `05-schedule-daily-packaging.json`) تنظیم Timeout رو روی ۴۵ دقیقه
   بذارید (یادداشت داخل خود نود هم هست).
3. روی نود `ai-gateway-health` تنظیم Timeout رو روی ۲۰ دقیقه بذارید.
4. در Settings هر ۵ ورک‌فلوی غیر از خودِ self-heal، گزینه‌ی **Error
   Workflow** رو روی `on-failure-self-heal` تنظیم کنید (این لینک باید
   بعد از Import دستی انجام بشه چون به ID واقعی workflow نیاز داره).
5. در `01-ci-push.json`، آدرس Webhook نود اول رو در GitHub →
   Settings → Webhooks ثبت کنید.

## انضباط نگه‌داری: هر بار که ورک‌فلو رو در n8n تغییر دادید

n8n خودش export/import JSON داره — بعد از هر تغییر در UI:
**سه‌نقطه‌ی بالای ورک‌فلو → Download** → فایل جدید رو جایگزین همین
فایل در این پوشه کنید و commit بزنید. این کار رو همیشه انجام بدید،
حتی برای تغییرات کوچیک — اینجوری گیت همیشه آینه‌ی دقیق Supabase
می‌مونه و یک منبع حقیقت (source of truth) قابل بازیابی دارید.

## نکته‌ی مهم درباره‌ی صحت این فایل‌ها

این ۶ فایل بدون اجرای واقعی n8n نوشته شدن (محیط تولیدشون اتصال
اینترنت نداشت). ساختار و نوع نودها مطابق مستندات n8n هست، ولی اگه
موقع Import یک نود (خصوصاً IF) هشدار سازگاری نسخه داد، n8n معمولاً
خودش پیشنهاد آپدیت می‌ده — قبول کنید و دو شرط شاخه (main/master) رو
دوباره چک کنید. نودهای Execute Command (اکثریت قریب‌به‌اتفاق این
ورک‌فلوها) ساختار بسیار ساده و پایداری دارن و نباید مشکلی بدن.

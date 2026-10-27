# بستهٔ عمومی بازیابی Rescue — ۲۰۲۶-۱۰-۲۷

این مخزن ابزارهای کوچک تشخیص شبکه، دریافت امن بسته و پژوهش روش‌های دسترسی
محدود Google، GitHub و Cloudflare را نگه می‌دارد. محتوای اصلی زیر `files/`
یک snapshot ثابت است؛ گزارش‌های داخل snapshot وضعیت زمان ساخت را شرح می‌دهند.
این بسته به‌تنهایی تونل اینترنت عمومی ایجاد نمی‌کند.

نسخهٔ ثابت فایل‌ها:

```text
60795a1526d8e2f94a41c8722f7435d05573b057
```

SHA-256 مورد اعتماد `files/manifest.json`:

```text
34e1a9dbc8dc91d6665e63bed144c841c7c8e50b515a855eb9befeef667066f6
```

این hash، ابزار دریافت و تنظیم منابع را پیش از بحران در محل مستقل نگه دارید.
دریافت hash فقط از همان mirror اعتماد اولیهٔ مستقل ایجاد نمی‌کند.

| منبع | وضعیت آزمون ۲۷ اکتبر ۲۰۲۶ |
|---|---|
| [Google Apps Script](https://script.google.com/macros/s/AKfycbyuYdoAydxraxEEajOrknwOpgQTPncFpFaVuyug2iVYU5NELpiuaQEy1a-HC7VN_uQ/exec) | بازیابی کامل ۲۹ artifact و manifest از دستگاه مدیریت؛ بایت‌ها و مجوزها برابر |
| GitHub Contents API، commit بالا، `prefix: files` | بازیابی کامل و ناشناس؛ همهٔ ۳۰ دریافت از ورودی اول موفق شدند |
| [دامنهٔ Cloudflare](https://recovery.salamnext.ir/) و [workers.dev](https://rescue-recovery-static.razavioo.workers.dev/) | منتشر شده؛ دریافت عمومی هنوز تأیید نشده، فقط کاندیدای آخر |

`recovery-sources.json` حاوی نشانی‌های عمومی واقعی است و credential ندارد.
دو ورودی GitHub فقط دو تلاش محدود به همان مخزن‌اند؛ سهمیه و ارائه‌دهندهٔ
مشترک دارند. دو hostname کلادفلر هم مستقل از یکدیگر نیستند. IP تاریخی ثابت
Google خاموش است، چون برای این deployment آزموده نشده است.

با ابزار ازپیش‌نگه‌داری‌شده و مقصدی که هنوز وجود ندارد:

```bash
python3 files/scripts/rescue-bootstrap.py \
  --sources recovery-sources.json \
  --manifest-sha256 34e1a9dbc8dc91d6665e63bed144c841c7c8e50b515a855eb9befeef667066f6 \
  --timeout 10 --total-timeout 1800 \
  --output recovered-kit-next
```

برای کپی محلی، `--sources recovery-sources.json` را با `--offline-dir files`
جایگزین کنید. ابزار همهٔ فایل‌ها را پیش از انتشار پوشهٔ خروجی با hash بررسی
می‌کند، مقصد موجود را جایگزین نمی‌کند و فایل دریافتی را اجرا یا نصب نمی‌کند.
فایل‌ها `0600` و پوشه `0700` خواهند بود. Python 3، curl و Linux با `renameat2`
لازم‌اند؛ مسیر عملیاتی پروژه Ubuntu است.

نتیجهٔ کامل `verified_files: 29` و `executed: false` دارد. برای سنجش مستقل هر
mirror، کپی تنظیم را فقط به همان ارائه‌دهنده محدود کنید؛ fallback یک منبع
سالم نباید خرابی دیگری را بپوشاند. هر بازیابی GitHub دست‌کم ۳۰ درخواست موفق
API لازم دارد؛ آزمون را بی‌دلیل تکرار نکنید. اگر همهٔ منابع کند یا قطع باشند،
بودجهٔ بالا می‌تواند حدود ۲۵ تا ۳۰ دقیقه طول بکشد.

این نتایج تضمین کارکرد روی همهٔ اپراتورها یا قطعی آینده نیستند. GooseRelay
در snapshot فقط آماده‌سازی منبع و تنظیم کاندیداست؛ خروجی خارجی اختصاصی، رفع
موانع ثبت‌شده و آزمون کامل لازم دارد. mirror ایستا یا دسترسی Search جای آن
را نمی‌گیرد. این بسته شامل هویت تونل، کلید خصوصی یا باینری‌های چندمگابایتی نیست.

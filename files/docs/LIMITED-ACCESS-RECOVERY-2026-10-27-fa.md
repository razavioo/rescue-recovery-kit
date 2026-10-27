# آمادگی برای دسترسی محدود Google، Cloudflare و GitHub — ۲۷ اکتبر ۲۰۲۶

این تغییر سه قابلیت عملی به ساختار پروژه اضافه می‌کند: تشخیص محدود و قابل
بازبینی دسترسی، دریافت بستهٔ بازیابی با hash مستقل از چند منبع، و آماده‌سازی
نسخهٔ مشخص یک حامل TCP از مسیر Google Apps Script. مسیرهای فعال فعلی دفتر
با این ابزارها عوض نمی‌شوند. مسیر تازه تا آزمون کامل، به اشتراک مشترکان و
انتخاب خودکار وارد نمی‌شود.

دو گزارش پژوهشی مکمل، روش‌ها و منابع اولیه را به تفصیل پوشش می‌دهند:
[Google و GitHub](SHUTDOWN-GOOGLE-GITHUB-RESEARCH-2026-10-27-fa.md) و
[Cloudflare و دیگر حامل‌ها](SHUTDOWN-CLOUDFLARE-TRANSPORTS-2026-10-27-fa.md).
گزارش‌های رخداد خرداد ۱۴۰۴ با ابزارها و تغییرات سال ۲۰۲۶ مخلوط نشده‌اند.
فهرست حاضر تضمین کشف همهٔ روش‌های خصوصی یا موفقیت در قطعی آینده نیست.

## انتخاب بر اساس چیزی که واقعاً باز مانده است

| دسترسی قابل اثبات | مسیر قابل بررسی | وابستگی‌ای که همچنان باید آزموده شود |
|---|---|---|
| فقط یک IP گوگل | انتخاب همان edge با حفظ hostname و TLS؛ Apps Script/AMP در صورت پاسخ واقعی | میزبانی سرویس روی همان IP، redirect و خروجی؛ باز بودن Search کافی نیست |
| Apps Script و redirect آن | GooseRelay برای TCP؛ mirror ایستای بازیابی برای فایل | deployment قبلی و خروجی خارجی؛ محدودیت حساب و افت ظرفیت |
| Google AMP | Champa با origin و کلید خودمان؛ Snowflake فقط برای معرفی | Champa کند و محدود؛ Snowflake همچنان به مسیر peer نیاز دارد |
| فقط `api.github.com` | Contents API برای manifest، راهنما و فایل کوچک | commit دقیق، hash مستقل و سهمیه؛ raw و release میزبان جدا هستند |
| edge کلادفلر روی TCP/443 | MASQUE/H2، CDN/Worker با دامنه و origin واقعی | هویت، گواهی و data plane؛ پاسخ trace یک تونل را تأیید نمی‌کند |
| UDP/QUIC کلادفلر | MASQUE/H3 یا WARP/WireGuard در صورت آزمون کامل | endpoint، هویت و ظرفیت واقعی؛ وابستگی مشترک به Cloudflare |
| resolver داخلی با recursion خارجی | MasterDNS؛ DNSTT/Slipstream و مشابه‌ها به‌صورت کاندیدا | delegation، authoritative UDP/53 خارجی، TXT و انتقال دوطرفه؛ فقط جواب DNS کافی نیست |
| broker و STUN به‌اضافه مسیر peer | Snowflake، Conduit و حامل‌های WebRTC | اتصال peer؛ STUN گوگل خروجی عمومی TCP ایجاد نمی‌کند |
| مسیر inbound یا پروتکل native مشخص | SSH معکوس، GRE رمز‌شده و IPsec موجود | قوانین واقعی اپراتور، NAT و مسیر دوطرفه؛ آزمایش محلی تضمین قطعی ملی نیست |
| تنها خدمات داخلی | سرویس‌ها و بسته‌های آفلاین، محتوای cacheشده؛ پیام‌رسان فقط در صورت آزمایش واقعی | بدون حامل خارجی قابل دسترس، ابزار نرم‌افزاری به‌تنهایی اتصال خارجی نمی‌سازد |

مقالهٔ اندازه‌گیری [FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0016.php)
و [گزارش هم‌زمان خرداد ۱۴۰۴](https://github.com/net4people/bbs/issues/484)
تغییر رفتار شبکه در مراحل مختلف قطع را نشان می‌دهند. نام اپراتور یا یک IP
تاریخی جای اندازه‌گیری زمان و مکان فعلی را نمی‌گیرد.

در معماری خودمان، SSH و MasterDNS و GRE و IPsec همچنان بخشی از مسیر را روی
زیرساخت واسط قبلی دارند؛ MASQUE به Cloudflare متکی است. چند نام کانال الزاماً
چند نقطهٔ شکست مستقل نیست. خراب شدن برق یا اینترنت دفتر، ingress مشترک، DNS،
خروجی خارجی یا Cloudflare باید جدا ارزیابی شود. با دستور فعلی کاربر، روی
ParsPack هیچ مدیریت یا استقرار تازه‌ای انجام نمی‌شود.

## ۱. تشخیص دسترسی

```bash
python3 scripts/probe-limited-access.py \
  --families ipv4,ipv6 --timeout 8 --total-timeout 60 \
  --output private/limited-access-report.json

# پس از نصب ابزارهای کمکی روی میزبان مقصد:
connectivityctl diagnose --json --timeout 5
rescue-access-probe --families ipv4,ipv6
```

probe، HTTPS وب، API، raw و DoH را جدا بررسی می‌کند. بدنهٔ معتبر مورد انتظار،
گواهی TLS، سقف بایت، مهلت هر درخواست و بودجهٔ کل کنترل می‌شوند. پروکسی محیط،
curlrc و overrideهای حساس TLS استفاده نمی‌شوند. `--proxy socks5h://127.0.0.1:PORT`
فقط با انتخاب صریح اعمال می‌شود؛ در آن حالت family مربوط به اتصال پروکسی است.
`--custom-url` فقط وضعیت HTTPS مقصد انتخابی را بررسی می‌کند و شاهد تونل نیست.
بدنه، IP خروجی و URL یا credential سفارشی در گزارش چاپ نمی‌شود.

در [آزمون دستگاه مدیریت](evidence/limited-access-local-2026-10-27.json)،
۸ بررسی از ۱۱ بررسی IPv4 بدنهٔ مورد انتظار داشتند؛ Google API پاسخ ۴۰۳ داد و
DoHهای آزمایش‌شده به مهلت خوردند. IPv6 تأیید نشد. در
[آزمون مستقیم Ubuntu دفتر](evidence/limited-access-office-2026-10-27.json)،
فقط کنترل ایرانی IPv4 پاسخ مورد انتظار داد. مقصدهای خارجی IPv4 timeout و
IPv6 شکست اتصال یا DNS داشتند. این آزمون با سیاست موجود دفتر و بدون افزودن
استثنای خروجی انجام شد؛ نتیجهٔ آن شاهد همین مسیر است، نه همهٔ اپراتورهای کشور.

## ۲. بستهٔ بازیابی و mirrorهای آماده

```bash
python3 scripts/build-limited-access-kit.py
```

خروجی پیش‌فرض زیر `offline-toolkit/limited-access-kit-2026-10-27/` است:

- `files/`: ابزارها، تنظیمات نمونه و همین سه گزارش با manifest و SHA-256 فایل‌ها.
- `MANIFEST.sha256`: hash مورد اعتماد manifest؛ برای نگهداری جداگانه پیش از بحران.
- `google-apps-script/Code.gs`: mirror ایستای عمومی به شکل JSON/base64.
- `cloudflare-worker/worker.js` و `wrangler.jsonc`: mirror ایستا با نام‌های مجاز ثابت.
- `build-report.json`: فهرست محدودهٔ ساخت و اعلام منتشرنشدن.

فقط allowlist صریح فایل‌های عمومی بسته‌بندی می‌شود. پوشهٔ `private/`، اطلاعات
اشتراک، هویت WARP، session، کلید و overlayهای سرور وارد این خروجی نمی‌شوند.
mirrorها درخواست را به اینترنت forward نمی‌کنند و هیچ کلید تونلی ندارند.
ساخت فایل، استقرار Worker یا Apps Script محسوب نمی‌شود.

برای بررسی محلی و بازیابی بدون شبکه:

```bash
cd offline-toolkit/limited-access-kit-2026-10-27
sha256sum -c MANIFEST.sha256
cd ../..

python3 scripts/rescue-bootstrap.py \
  --offline-dir offline-toolkit/limited-access-kit-2026-10-27/files \
  --manifest-sha256 HASH_KEPT_INDEPENDENTLY \
  --output private/recovered-kit-v1
```

برای دریافت شبکه‌ای، نمونهٔ `connectivity/recovery-sources.example.json` را
در محل خصوصی تکمیل و فقط منابع ساخته‌شدهٔ خودتان را فعال کنید:

```bash
rescue-bootstrap --sources /ABSOLUTE/PRIVATE/PATH/recovery-sources.json \
  --manifest-sha256 HASH_KEPT_INDEPENDENTLY \
  --timeout 15 --total-timeout 180 \
  --output /ABSOLUTE/PRIVATE/PATH/recovered-kit-v2
```

GitHub Contents با commit کامل ۴۰ رقمی از JSON/base64 خود API می‌خواند؛ لینک
`download_url` را دنبال نمی‌کند. برای mirror استاندارد، پوشهٔ `files/` را در
مخزن انتخابی قرار دهید و commit نهایی را در source config ثبت کنید. این کار
نیازمند انتشار آگاهانهٔ مالک است و در این تغییر انجام نشده است. توکن عمومی
لازم نیست؛ مخزن خصوصی می‌تواند `token_file` با مجوز `0600` و دسترسی فقط‌خواندنی
داشته باشد. نام source باید برچسب غیرحساس باشد؛ نام و URL حساب را در آن نگذارید.

خوانندهٔ Gist برای بسته‌های با نام فایل ساده وجود دارد و پاسخ revision ثابت
را cache می‌کند؛ Gist نام فایل دارای `/` نمی‌پذیرد. خروجی چندپوشه‌ای این سازنده
را مستقیم در Gist نگذارید؛ برای این بسته Contents API را به کار ببرید.

در source شبکه‌ای می‌توان `connect_ip` صریح IPv4 یا IPv6 داد. اتصال TCP به
آن edge می‌رود، اما hostname، SNI و بررسی گواهی اصلی حفظ می‌شوند. برای Apps
Script، همان override روی redirect مجاز `script.googleusercontent.com` نیز
اعمال می‌شود. IP نمونهٔ گوگل صرفاً کاندیدای تاریخی و خاموش است؛ اگر آن edge
سرویس مورد نظر را ارائه نکند، درخواست باید شکست بخورد. DNS کل سیستم تغییر نمی‌کند.

اگر منبع اول پاسخ ندهد یا hash اشتباه بدهد، منبع بعدی همان فایل بررسی می‌شود.
تمام فایل‌ها پیش از commit شدن بسته تأیید می‌شوند؛ خرابی یک فایل، خروجی ناقص
منتشر نمی‌کند. مقصد موجود، حتی پوشهٔ خالی، جایگزین نمی‌شود. فایل دریافتی
`0600` است و اجرا، import، نصب یا فعال نمی‌شود. commit اتمیک فعلی روی Linux
به `renameat2` نیاز دارد؛ ابزار اجرایی این پروژه برای Ubuntu آزموده شده است.
hash گرفته‌شده از همان mirror بدون مرجع مستقل، اعتماد اولیه ایجاد نمی‌کند.

در [آزمون واقعی API](evidence/recovery-github-api-2026-10-27.json)، `go.mod`
و `Code.gs` نسخهٔ ثابت GooseRelay دقیقاً با archive تأییدشده برابر بودند؛
بازیابی `go.mod` پس از نبودن فایل در منبع محلی از API موفق شد. manifest آن
آزمون محلی بود. این نتیجه، انتشار یا دسترس‌پذیری mirror اختصاصی ما را ثابت نمی‌کند.

## ۳. حامل تازهٔ Google: آماده‌سازی GooseRelay

نسخهٔ canonical با commit `0ed803f635890cbc021f71d7c8746ca1d2f262b1`، digest
archive و مجوز MIT ثبت شده است. ۷۲ فایل منبع دریافت و بررسی یکپارچگی شدند.
دریافت archive از API به `codeload.github.com` redirect می‌شود؛ آن را به زمان
قطع API-only موکول نکنید. archive ذخیره‌شده امکان بازاجرای بدون شبکه را می‌دهد:

```bash
python3 scripts/prepare-google-relay.py --download
# نوبت‌های بعد، بدون شبکه:
python3 scripts/prepare-google-relay.py \
  --archive offline-toolkit/google-relay/0ed803f635890cbc021f71d7c8746ca1d2f262b1/source.tar.gz
```

این آماده‌ساز کد upstream را build یا اجرا نمی‌کند. رندر اختیاری تنظیمات واقعی،
کلید خصوصی ثابت، listener محلی کلاینت `12982` و سرور خروجی `18443` دارد؛ پورت
کلاینت با Psiphon موجود تداخل ندارد. مراحل رندر و محدودیت‌ها در گزارش Google
آمده‌اند. endpoint خارجی باید HTTPS معتبر در جلوی listener محلی داشته باشد.
کلید AES-GCM فقط در client/server نگه‌داری می‌شود؛ در Code.gs قرار نمی‌گیرد.

پس از این آماده‌سازی، build جداگانهٔ Linux/amd64 با Go 1.26.8 انجام شد.
هشت وابستگی با `go.sum` و Go checksum database بررسی شدند و build نهایی از
cache، با شبکهٔ خاموش، `CGO_ENABLED=0` و `-mod=readonly` انجام شد. دو باینری
زیر `candidate-bin/` کنار منبع ذخیره‌اند؛ خود باینری‌های تونل اجرا نشده‌اند.
compiler و cache برای بازساخت آفلاین نیز در `offline-toolkit/` نگه‌داری شده‌اند.
این فایل‌های چندمگابایتی در mirror کوچک بازیابی قرار نمی‌گیرند؛ باید پیش از
قطع، جداگانه روی دستگاه‌های لازم ذخیره شوند. digest و روش بازساخت در
`candidate-bin/build-evidence.json` ثبت شده‌اند.

[بازبینی دقیق منبع](evidence/google-relay-source-review-2026-10-27.json)
چند مانع پذیرش تولید را روشن کرد: نبود بودجهٔ امنِ حجم پس از decompression،
نبود سقف کلی session و درخواست هم‌زمان، حفاظت ناکافی در برابر replay، و
امکان دسترسی دارندگان کلید مشترک به مقصدهای خصوصی خروجی. حالت `relay_urls`
مستقیم هم در این نسخه اشکال SNI دارد؛ خاموش‌کردن بررسی گواهی راه‌حل نیست.
مسیر آزمایشی Apps Script این اشکال مستقیم را ندارد، ولی همچنان به محدودیت
منابع و خروجی ایزوله نیاز دارد. بنابراین باینری ساخته‌شده فعلاً کاندیداست؛
قابل build بودن به معنی آماده‌بودن برای انتشار عمومی نیست.

این مسیر به حساب و deployment گوگل، خروجی خارجی و آزمایش کامل نیاز دارد.
HTTPS معمولی گوگل، موفقیت `doGet` یا وجود listener به‌تنهایی کافی نیست.
پیش از پذیرش باید SOCKS با DNS از داخل همان مسیر، چند HTTPS هم‌زمان، انتقال
دوطرفه با hash، توقف و بازگشت carrier و سپس زمان طولانی‌تر آزموده شوند.
پروتکل TCP است؛ UDP، QUIC و تماس صوتی عمومی از آن نتیجه نمی‌شود.

## ۴. نصب ابزارها و باقی آماده‌سازی‌ها

```bash
sudo bash scripts/install-limited-access-tools.sh
```

این نصب‌کننده فقط ابزار تشخیص و دریافت را نصب می‌کند؛ سرویس یا حساب جدید
فعال نمی‌کند. staged server-bundle هم منابع و گزارش‌های لازم را همراه دارد.
نصب روی `office-host` انجام شد و hash هر هفت فایل نصب‌شده با منبع
محلی برابر بود. `--help` هر دو ابزار و فرمان `connectivityctl diagnose`
از محل نصب‌شده اجرا شدند. آزمون سریع تشخیص فقط smoke test برنامه بود؛
آن را شاهد دسترسی شبکه یا سلامت MasterDNS نمی‌گیریم.
[شاهد نصب و محدودیت نتیجه](evidence/limited-access-tools-office-2026-10-27.json).

برای Aether/MASQUE، هویت‌های ازپیش‌ثبت‌شده و backup خصوصی مستقل همچنان ضروری‌اند؛
ورود به پنل یا ثبت حساب هنگام قطع، نقطهٔ شکست bootstrap است. برای Tor و
Psiphon/Lantern نیز باینری، bridge/config و وابستگی‌ها را پیش از قطع نگه دارید.
دسترسی broker، rendezvous و مسیر داده را جدا آزمایش کنید.

برای فعال‌سازی مسیرهای واقعاً جدید، این منابع لازم‌اند:

| منبع | استفادهٔ مشخص |
|---|---|
| حساب Google و انتخاب Web app | deployment مربوط به GooseRelay و در صورت انتخاب، mirror ایستای فایل |
| سرور خارج از محدودهٔ قطع و hostname دارای TLS | endpoint اختصاصی GooseRelay؛ دفترِ بدون خروجی جای آن را نمی‌گیرد |
| حساب/zone کلادفلر و دامنهٔ انتخابی | انتشار mirror یا ورودی CDN/Worker؛ وضعیت طرح و حدود اتصال بررسی شود |
| مخزن GitHub انتخابی | mirror فایل‌های عمومی در commit مشخص؛ نیازی به ساخت VPN با Issue/Actions نیست |
| اتصال واقعی اپراتورها | پذیرش هر مسیر روی اینترنت کاربر و ثبت تفاوت v4/v6 و قطع/بازگشت |

کلید یا توکن را در گفتگو یا فایل عمومی وارد نکنید؛ دسترسی حساب از مرورگر
یا فایل خصوصی با حداقل اختیار قابل استفاده است. این موارد، وابستگی اجرای
بعدی‌اند؛ اسناد و فایل‌های آماده همین حالا قابل بررسی و استفادهٔ آفلاین‌اند.

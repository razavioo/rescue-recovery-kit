# مسیرهای Google و GitHub در قطع اینترنت؛ بررسی و آماده‌سازی ۲۰۲۶-۱۰-۲۷

در قطع خرداد ۱۴۰۴، بعضی کاربران واقعاً از چند IP گوگل و API گیت‌هاب دسترسی محدود داشتند. این دسترسی به‌خودی‌خود اینترنت عمومی ایجاد نمی‌کرد: باید سرویس در دسترس بتواند درخواست را به بیرون منتقل کند، یا اطلاعات لازم برای بازیابی را برگرداند. در این بررسی مسیرهای واقعی، ابزارهای بعدی سال ۲۰۲۶ و وابستگی‌های هرکدام جدا شده‌اند. نتیجه عملی این تغییر، ذخیره آفلاین منبع مشخص GooseRelay و ابزار ساخت تنظیمات خصوصی آن است؛ استقرار Google یا راه‌اندازی تونل انجام نشده است.

دامنه بررسی: گزارش اصلی رخداد در net4people، ارائه نویسنده Snowflake/Champa، مخزن و کد ابزارهای نام‌برده و مستندات رسمی سرویس‌ها تا تاریخ بالا. مشاهده کاربران در ایران، ادعای نویسنده ابزار و آزمایش محلی آماده‌ساز سه نوع شاهد متفاوت‌اند. این سند تأیید اتصال زنده همه این روش‌ها روی همه اپراتورها نیست.

## در قطع قبلی چه اتفاقی افتاد؟

گزارش دست اول David Fifield از قطع ۱۸ تا ۲۶ ژوئن ۲۰۲۵، حدود ۶۰ ساعت قطع شدید و سپس دوره دسترسی محدود را توضیح می‌دهد. در اندازه‌گیری‌های نقل‌شده، `api.github.com` روی `140.82.121.6` و یک مقصد گوگل روی `216.239.38.120` قابل دسترس بودند. برای بعضی سرویس‌های دیگر گوگل، انتخاب آن IP با حفظ نام درست TLS/HTTP کمک می‌کرد. این شاهدِ مجاز بودن یک IP است؛ نمی‌توان از آن دسترسی به کل شبکه Google، تمام دامنه‌های GitHub یا موفقیت همین IP در قطع بعدی را نتیجه گرفت. در قطع کوتاه ۵ ژوئیه همان استثنای گوگل گزارش نشده بود. [ارائه اصلی، ۸ اوت ۲۰۲۵](https://www.bamsoftware.com/talks/crysp-2025-iran/)

گزارش هم‌زمان کاربران نیز API گیت‌هاب و تفاوت آن با وب‌سایت را ثبت می‌کند. یک کاربر در ۲۰ ژوئن صریحاً از پذیرش SNIهای مختلف روی IP قابل دسترس گوگل خبر داد؛ بنابراین بخشی از موفقیت‌های آن روز به انتخاب مقصد شبکه مربوط بود و لزوماً شکستن بررسی SNI نبود. [گزارش API](https://github.com/net4people/bbs/issues/484#issuecomment-2987484989)، [آزمایش IP/SNI](https://github.com/net4people/bbs/issues/484#issuecomment-2989892386)

جدول زیر تفاوت کارکرد مسیرها را نشان می‌دهد. «نیاز به خروجی» یعنی یک سرور خارج از محدوده قطع باید بتواند به مقصد واقعی وصل شود؛ سرور داخل ایران که خودش خروجی ندارد جای آن را نمی‌گیرد.

| روش | چیزی که جابه‌جا می‌کند | پیش‌نیاز اصلی | محدودیت تعیین‌کننده |
|---|---|---|---|
| Google Search، Translate و خواندن صفحات | متن/صفحه سازگار با سرویس | خود سرویس و زنجیره مقصدهایش باز باشد | تونل عمومی TCP/UDP نیست |
| انتخاب IP قابل دسترس برای Drive یا AMP | درخواست HTTPS به همان سرویس گوگل | مقصد IP باید آن سرویس را واقعاً میزبانی کند | باز بودن Search کافی نیست؛ گواهی TLS باید معتبر بماند |
| Snowflake با AMP | معرفی اولیه به یک پراکسی، سپس WebRTC | AMP، broker، ICE/STUN و مسیر داده peer | AMP فقط مرحله معرفی است؛ مسدود بودن WebRTC مسیر را متوقف می‌کند |
| Champa با AMP | جریان TCP با خروجی اختصاصی | مبدأ HTTPS عمومی، کلید سرور و پراکسی خروجی | کندی و محدودیت شدید AMP؛ سرورهای عمومی قدیمی فعال نیستند |
| Apps Script از نوع HTTP relay | درخواست HTTP/HTTPS | حساب Google و Web app | بعضی پیاده‌سازی‌ها به CA محلی برای MITM نیاز دارند؛ TCP عمومی نیست |
| GooseRelay | SOCKS5 برای جریان TCP رمز‌شده | Apps Script و خروجی HTTPS اختصاصی | سهمیه حساب، redirect و رفتار front گوگل؛ UDP ندارد |
| Drive/Docs به‌عنوان حامل | جریان TCP از طریق صف فایل یا fetch | OAuth یا مبدأ اختصاصی، خروجی خارج از قطع | تأخیر، سهمیه و بلوغ کمتر؛ برای تولید این پروژه تأیید نشده |
| GitHub REST Contents/Gist | فایل کوچک و اطلاعات بازیابی | همان API باز باشد | محدودیت اندازه/نرخ؛ دانلود release و raw میزبان جدا دارند |
| GitHub Actions به‌عنوان واسطه | در گزارش‌ها بیشتر انتقال/آینه فایل | حساب، مخزن و runner | پیشنهاد یک تونل عمومی به معنای پیاده‌سازی پایدار موجود نیست |

## Google AMP، Champa و Snowflake

Champa پروژه واقعی نویسنده Snowflake برای انتقال TCP روی Google AMP Cache است. باید یک مبدأ HTTPS بیرون از قطع، سرویس Champa و مقصد TCP پشت آن داشت. کلاینت به کلید عمومی صحیح سرور نیاز دارد؛ خود ابزار به‌تنهایی یک SOCKS عمومی آماده نیست. راهنمای نویسنده از حدود `15 KB/s`، حدود پانزده دقیقه کارکرد و گاهی چند ساعت انتظار برای رفع محدودیت AMP صحبت می‌کند؛ این اعداد سقف تضمین‌شده یا نتیجه آزمایش ما نیستند. برای دریافت تنظیمات، متن و بازیابی محدود قابل بررسی است، برای بار عادی برنامه نباید بر آن تکیه کرد. [منبع اصلی و README](https://repo.or.cz/champa.git)، [بحث معرفی و آزمایش کاربران](https://github.com/net4people/bbs/issues/485)

سرور عمومی منتشرشده در ژانویه ۲۰۲۶ در ۲۲ سپتامبر ۲۰۲۶ غیرفعال شده است. نمونه‌های عمومی قدیمی را نباید به بسته بازیابی به‌عنوان مسیر آماده و زنده اضافه کرد. آماده‌سازی مفید شامل نگهداری منبع، باینری بررسی‌شده، کلید عمومی خودمان، مبدأ HTTPS و آزمایش کامل آن پیش از قطع است. این تغییر برای Champa سرور یا کلید تولید نکرده است. [اعلان وضعیت سرور عمومی](https://github.com/net4people/bbs/issues/485#issuecomment-3769529313)، [تأیید بعدی نویسنده](https://github.com/net4people/bbs/issues/485#issuecomment-5769800293)

در Snowflake، AMP یکی از راه‌های rendezvous یا پیدا کردن پراکسی است. بعد از پاسخ broker، داده باید از WebRTC به peer و سپس bridge برسد. عبارت «Tor روی ۱۰ درصد مانده» یا دریافت پاسخ AMP تأیید مسیر داده نیست؛ باید باز شدن DataChannel و اتصال واقعی را دید. راه AMP از سال ۲۰۲۳ برای کلاینت‌های سازگار توضیح داده شده بود. [معرفی AMP rendezvous](https://github.com/net4people/bbs/issues/197)، [معماری مقاله Snowflake](https://www.bamsoftware.com/papers/snowflake/)

در ژوئن ۲۰۲۵ نویسنده صریحاً بین موفقیت معرفی از AMP و شکست WebRTC فرق گذاشت. یک گزارش موفقیت Snowflake در ۲۳ ژوئن، پس از تغییر وضعیت شبکه، شاهد همان اپراتور و زمان است؛ آن را نمی‌توان به دوره قطع کامل تعمیم داد. تنظیمات AMP جایگزین سیاست مجاز خروجی peer/STUN در فایروال پروژه نمی‌شود. [توضیح فنی نویسنده](https://github.com/net4people/bbs/issues/485#issuecomment-3006360379)، [گزارش موفقیت محدود](https://github.com/net4people/bbs/issues/484#issuecomment-2998249820)

## Apps Script: تفاوت HTTP relay با TCP relay

API رسمی `UrlFetchApp` درخواست HTTP/HTTPS انجام می‌دهد. از یک اسکریپت خالی نمی‌توان اتصال TCP دلخواه به SSH یا MTProto گرفت. HTTP relayهایی مانند MasterHttpRelayVPN و بازنویسی Rust آن می‌توانند درخواست وب را منتقل کنند؛ در مسیرهایی که TLS را در پراکسی محلی باز می‌کنند نصب CA لازم می‌شود. این تغییر هیچ CA روی دستگاه نصب نکرده است. [API رسمی UrlFetch](https://developers.google.com/apps-script/reference/url-fetch/url-fetch-app)، [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN)، [بازنویسی Rust](https://github.com/therealaleph/MasterHttpRelayVPN-RUST)

GooseRelay برای TCP یک خروجی واقعی اضافه می‌کند: کلاینت محلی، batchهای TCP را فشرده و با AES-GCM رمز می‌کند؛ Apps Script محتوای درخواست را به خروجی منتقل می‌کند؛ خروجی TCP مقصد را باز می‌کند. این معماری به CA محلی احتیاج ندارد. بررسی ما وجود این مسیر و گزینه‌های تنظیمات را در کد مشخص کرد؛ ممیزی کامل رمزنگاری، مقاومت در برابر سوءاستفاده یا تضمین ظرفیت آن انجام نشده است. [مخزن اصلی](https://github.com/Kianmhz/GooseRelayVPN)، [کد carrier در نسخه ثابت](https://github.com/Kianmhz/GooseRelayVPN/blob/0ed803f635890cbc021f71d7c8746ca1d2f262b1/internal/carrier/fronting.go)

زنجیره لازم این است:

```text
برنامه → SOCKS5 روی 127.0.0.1
       → TLS به IP گوگل با SNI انتخاب‌شده و درخواست Apps Script
       → Web app و پاسخ ContentService / redirect
       → HTTPS /tunnel روی خروجی اختصاصی
       → اتصال TCP به مقصد واقعی
```

Apps Script برای پاسخ ContentService از URL یک‌بارمصرف روی `script.googleusercontent.com` استفاده می‌کند. کلاینت باید redirect را درست پردازش کند؛ موفقیت صفحه Google یا حتی صفحه `/exec` به‌تنهایی کافی نیست. در بازبینی منبع GooseRelay رفتار front و زنجیره redirect هم بخشی از وابستگی ثبت شده است. آزمایش بعدی باید payload رفت‌وبرگشت را از مسیر کامل عبور دهد. [مستند رسمی ContentService](https://developers.google.com/apps-script/guides/content)، [کد واقعی forwarder](https://github.com/Kianmhz/GooseRelayVPN/blob/0ed803f635890cbc021f71d7c8746ca1d2f262b1/apps_script/Code.gs)

سهمیه فعلی رسمی UrlFetch برای حساب معمولی `20,000` و برای Workspace برابر `100,000` درخواست در روز است. سهمیه به کاربر تعلق دارد و از ۲۴ ساعت پس از اولین درخواست بازنشانی می‌شود؛ ساخت چند deployment زیر یک حساب آن را چند برابر نمی‌کند. حد هم‌زمانی و مدت اجرای اسکریپت هم وجود دارد. توضیح midnight Pacific در بعضی READMEها و شمارنده داخلی ابزار، مرجع صحیح بازنشانی سهمیه نیست. این مقادیر ممکن است تغییر کنند. [جدول رسمی سهمیه‌ها](https://developers.google.com/apps-script/guides/services/quotas)

در کاتالوگ ابزارهای سال ۲۰۲۶، GooseRelay به‌عنوان SOCKS5 روی Apps Script معرفی شده است؛ این معرفی مستقل از اثبات کارکرد روی اتصال فعلی ماست. در همین خانواده، گزارش خطای `403` بین GAS و یک خروجی `trycloudflare` وجود دارد؛ پس زنجیره GAS→خروجی نیز باید جدا آزمایش شود. برای پایداری به URL موقت عمومی اتکا نشده و آماده‌ساز ما خروجی HTTPS اختصاصی می‌خواهد. [معرفی ژوئن ۲۰۲۶](https://github.com/net4people/bbs/issues/586#issuecomment-4698049551)، [گزارش خطای پیاده‌سازی Rust](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/849)

## آماده‌ساز اضافه‌شده در این پروژه

نسخه ثابت انتخاب‌شده از مالک اصلی `Kianmhz/GooseRelayVPN` است، با مجوز MIT:

```text
commit: 0ed803f635890cbc021f71d7c8746ca1d2f262b1
commit date: 2026-05-29T19:16:46Z
archive SHA-256:
bfe19da90b9d7810cc9d0e1e8d860ef785b80ef7f89ed940c9b996aef3178aff
```

هویت منبع، مجوز، نام پوشه archive و مسیرهای بازبینی‌شده در [قفل نسخه](../connectivity/google-relay-release.json) ثبت شده‌اند. محتوای archive شامل ۷۲ فایل با این digest دریافت و آفلاین بازآماده‌سازی شد. digest مربوط به همین بایت‌های archive است؛ اگر GitHub بسته همان commit را با بایت‌های متفاوت تولید کند، ابزار عمداً متوقف می‌شود. راه بازیابی قابل تکرار، نگهداری archive تأییدشده است؛ تغییر checksum باید با بررسی انسانی انجام شود.

برای ذخیره منبع پیش از قطع:

```bash
python3 scripts/prepare-google-relay.py --download
```

این دانلود از API آغاز می‌شود ولی GitHub آن را به `codeload.github.com` هدایت می‌کند. اگر فقط `api.github.com` باز باشد این فرمان الزاماً کار نمی‌کند. نسخه محلی آماده‌شده در مسیر زیر قرار گرفته است:

```text
offline-toolkit/google-relay/0ed803f635890cbc021f71d7c8746ca1d2f262b1/
  source.tar.gz
  source/
  source-lock.json
  prepared.json
```

بازاجرای بدون شبکه:

```bash
python3 scripts/prepare-google-relay.py \
  --archive offline-toolkit/google-relay/0ed803f635890cbc021f71d7c8746ca1d2f262b1/source.tar.gz
```

آماده‌ساز SHA-256 را پیش از نوشتن بررسی می‌کند، مسیرهای traversal و absolute، لینک و فایل ویژه، عضو تکراری و archive بزرگ را رد می‌کند. کد دریافت‌شده را اجرا یا build نمی‌کند. خروجی خصوصی با مجوز `0600` و پوشه مقصد خصوصی ساخته می‌شود؛ بازاجرا کلید را عوض نمی‌کند و فایل متفاوت موجود را بازنویسی نمی‌کند. این رفتارها در [تست آفلاین](../tests/test_google_relay_prep.py) بررسی شده‌اند.

برای ساخت تنظیمات خصوصی پس از آماده شدن زیرساخت، فایل نمونه [google-relay.example.json](../connectivity/google-relay.example.json) را در یک محل خصوصی خارج از کنترل نسخه تکمیل کنید. placeholderهای آن عمداً قابل اجرا نیستند. `google_host` یک مقصد آزمایشی تاریخی است، نه IP تضمین‌شده. `script_keys[].id` باید deployment ID واقعی باشد؛ `account` برچسب کوتاه غیرحساس است. `exit_relay_url` باید URL واقعی HTTPS با مسیر `/tunnel` روی خروجی تحت اختیار شما باشد.

```bash
python3 scripts/prepare-google-relay.py \
  --archive offline-toolkit/google-relay/0ed803f635890cbc021f71d7c8746ca1d2f262b1/source.tar.gz \
  --output /ABSOLUTE/PRIVATE/PATH/google-relay \
  --config /ABSOLUTE/PRIVATE/PATH/google-relay.json \
  --generate-key
```

سه خروجی `private/client_config.json`، `private/server_config.json` و `private/Code.gs` مطابق parser واقعی upstream ساخته می‌شوند و `private/tunnel.key` کلید مشترک را نگه می‌دارد. برای کلید موجود، به‌جای `--generate-key` از `--key-file /ABSOLUTE/PRIVATE/PATH/tunnel.key` با فایل `0600` استفاده کنید. کلید در آرگومان خط فرمان، stdout یا Code.gs قرار نمی‌گیرد. listener هر دو سمت به `127.0.0.1` محدود است؛ HTTPS خروجی باید جداگانه جلوی سرویس سمت خارج قرار بگیرد. [فیلدهای واقعی کلاینت](https://github.com/Kianmhz/GooseRelayVPN/blob/0ed803f635890cbc021f71d7c8746ca1d2f262b1/internal/config/client.go)، [فیلدهای سرور](https://github.com/Kianmhz/GooseRelayVPN/blob/0ed803f635890cbc021f71d7c8746ca1d2f262b1/internal/config/server.go)

این مرحله منبع و template می‌دهد. منبع Go به toolchain و moduleهایش نیاز دارد؛ داشتن tarball به‌تنهایی build آفلاین را تضمین نمی‌کند. در گام جداگانهٔ همین بررسی، compiler و وابستگی‌های قفل‌شده هم ذخیره و دو باینری کاندیدا ساخته شدند؛ جزئیات در بخش بعد آمده است. هنوز خروجی HTTPS اختصاصی، حساب/deployment گوگل، رفع یا مهار اشکال‌های مشخص و آزمایش اپراتور لازم‌اند. گزینه `-config` در برنامه اصلی وجود دارد، اما اجرای برنامه برای صرفاً اعتبارسنجی JSON مناسب نیست، چون startup اتصال شبکه برقرار می‌کند. [وابستگی‌های Go](https://github.com/Kianmhz/GooseRelayVPN/blob/0ed803f635890cbc021f71d7c8746ca1d2f262b1/go.mod)، [ورودی واقعی کلاینت](https://github.com/Kianmhz/GooseRelayVPN/blob/0ed803f635890cbc021f71d7c8746ca1d2f262b1/cmd/client/main.go)

برای تکمیل این مسیر، کارهای وابسته به مالک سرویس این‌هاست: تعیین یک خروجی خارج از قطع با HTTPS پایدار؛ بررسی/تأمین باینری مناسب و وابستگی‌های آفلاین؛ ساخت Web app در حساب گوگل با Execute as مالک و دسترسی متناسب با کلاینت؛ ثبت deployment ID؛ رندر تنظیمات؛ سپس آزمایش TCP واقعی و قطع/وصل مسیر. تصمیم حساب، خروجی و deployment باید پیش از انتشار نهایی روشن شود. باز کردن مرورگر برای مطالعه منابع لازم نبود؛ این کارها به دسترسی حساب مربوط‌اند. [راهنمای رسمی Web app](https://developers.google.com/apps-script/guides/web)

## بازبینی منبع و build آفلاین کاندیدا

[رکورد بازبینی](evidence/google-relay-source-review-2026-10-27.json) یافته‌های مشخص را با مسیر و خط منبع ثبت می‌کند. بررسی TLS، قالب رمز، ورودی خروجی، session، تنظیمات، Apps Script و مسیر build انجام شد؛ این ممیزی رسمی کامل یا آزمون نفوذ نیست. TLS عادی و AES-GCM با nonce تصادفی وجود دارند، اما از آن‌ها حفاظت در برابر replay یا جداسازی امنیتی کاربران دارای کلید مشترک نتیجه نمی‌شود.

موانع اصلی تولید عبارت‌اند از decompression بدون سقف مناسب برنامه، نبود سقف کلی درخواست/session و صف sequence خارج از ترتیب، مصرف منابع توسط POST خالیِ بدون احراز، و دسترسی صاحب PSK به مقصدهای خصوصی/loopback خروجی. خروجی باید ایزوله، کم‌اختیار و محدود از نظر egress و منابع باشد؛ این نیاز با قرار دادن صرف سرویس پشت HTTPS حل نمی‌شود. حالت مستقیم `relay_urls` در این commit، SNI را همچنان `www.google.com` می‌گذارد و برای گواهی معمول سرور اختصاصی شکست می‌خورد. خاموش‌کردن TLS verification پذیرفته نیست. مسیر Apps Script به‌عنوان کاندیدای جدا باقی مانده است.

Go 1.26.8 از بسته‌های رسمی Ubuntu، بدون نصب سیستمی، استخراج شد. هشت نسخهٔ module در محیط جدا با Go checksum database دریافت و با `go.sum` ثابت مقایسه شدند؛ `go mod verify` موفق بود. سپس تست‌های pureِ بررسی‌شدهٔ frame و build با شبکهٔ خاموش، `CGO_ENABLED=0`، `-mod=readonly` و `-trimpath` انجام شد. Linux/amd64 client و server در `offline-toolkit/google-relay/0ed803f635890cbc021f71d7c8746ca1d2f262b1/candidate-bin/` هستند؛ hash و روش بازساخت در `build-evidence.json` کنار آن‌هاست. toolchain و cache محلی هم نگه داشته شده‌اند. این باینری‌ها اجرا نشده‌اند و هیچ installer upstream یا سرویس تازه‌ای فعال نشده است.

برای بازساخت **فقط با cache آمادهٔ همین دستگاه**، از ریشهٔ پروژه و با مقصد تازه:

```bash
relay_repo="$PWD"
relay_pin=0ed803f635890cbc021f71d7c8746ca1d2f262b1
relay_base="$relay_repo/offline-toolkit/google-relay/$relay_pin"
relay_sdk="$relay_repo/offline-toolkit/go-toolchain/ubuntu-go1.26.8/extracted/usr/lib/go-1.26"
relay_output="$(mktemp -d "$relay_base/rebuild.XXXXXX")"
cd "$relay_base/source"
export GOROOT="$relay_sdk" GOTOOLCHAIN=local GOENV=off GOWORK=off
export GOMODCACHE="$relay_base/candidate-bin/module-cache"
export GOCACHE="$relay_output/build-cache" GOPROXY=off GOSUMDB=off
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOFLAGS=
"$relay_sdk/bin/go" mod verify
"$relay_sdk/bin/go" build -mod=readonly -trimpath -buildvcs=false \
  -ldflags '-s -w -X main.version=source-0ed803f-candidate' \
  -o "$relay_output/goose-client-linux-amd64" ./cmd/client
"$relay_sdk/bin/go" build -mod=readonly -trimpath -buildvcs=false \
  -ldflags '-s -w -X main.version=source-0ed803f-candidate' \
  -o "$relay_output/goose-server-linux-amd64" ./cmd/server
sha256sum "$relay_output/goose-client-linux-amd64" "$relay_output/goose-server-linux-amd64"
```

خاموش‌بودن SumDB در این مرحله فقط برای بازاستفادهٔ آفلاین از moduleهایی است که قبلاً با SumDB روشن تأیید شده‌اند. این فرمان جای دریافت و تأیید اولیهٔ وابستگی نیست. hash دو خروجی ساخته‌شده در این بررسی به‌ترتیب `7d5a496ded757aa5522e9930cee3c9557df946c1441854e3aa0ed0ace205af37` و `531fce456357b57625b5bb305017c50db8084c8bcbaf930b3e03d45e45947567` است. هیچ‌یک از فرمان‌های بالا خود برنامهٔ تونل را اجرا نمی‌کند.

## Drive، Docs، Cloud Run، Translate و GOST

چند مسیر مکمل واقعی هم پیدا شد، اما خودکار وارد سرویس فعال نشده‌اند:

| پروژه/سرویس | شاهد و نسخه بررسی‌شده | آماده‌سازی لازم و علت فعال نشدن |
|---|---|---|
| FlowDriver | [مخزن اصلی](https://github.com/NullLatency/FlowDriver)، commit `fa8ee8950107ee1bde58d3adf6e479e7bd2fcd73`، ۲۰۲۶-۰۵-۱۷ | فایل‌های Drive صف رفت‌وبرگشت TCP هستند؛ OAuth، Drive API، shared folder و سرور بیرونی لازم است. نویسنده آن را تحقیق شخصی و نامناسب تولید معرفی می‌کند؛ polling و refresh token باید آزمایش شود. |
| SaffronBridge / Hybrid-Relay-Google | [مخزن اصلی](https://github.com/free-the-internet/Hybrid-Relay-Google)، commit `2ca63371816bf14e0e0873f9a0d20e38387bd73b`، ۲۰۲۶-۰۵-۲۱ | Apps Script برای uplink و Drive برای downlink؛ علاوه بر خروجی، دو مسیر Google و OAuth لازم‌اند. ادعای ظرفیت README سنجش مستقل ما نیست. |
| gdocs-tunnel | [مخزن اصلی](https://github.com/0xinf0/gdocs-tunnel)، commit `487b5a1173398af13cf49c7916dfa956e4e28ffb`، ۲۰۲۶-۰۱-۲۰ | نویسنده Docs Viewer، SOCKS5، رمزنگاری و IPv6 rotation را شرح می‌دهد. آدرس/کلیدهای نمونه نباید خروجی مورد اعتماد تلقی شوند؛ بازبینی و مبدأ اختصاصی لازم است. |
| Cloud Run/WebSocket | [مستند رسمی](https://docs.cloud.google.com/run/docs/triggering/websockets) | به project، مجوز و معمولاً billing و دسترسی واقعی endpoint نیاز دارد. WebSocket محدود به timeout درخواست است و reconnect/state لازم دارد؛ دسترسی Google Search به معنای دسترسی `run.app` نیست. |
| Google Translate / EzyTel | [راهنمای Translate](https://support.google.com/translate/answer/2534559)، [مخزن EzyTel](https://github.com/MoBiNMN/EzyTel) | ترجمه/خواندن صفحات و بازنویسی ابزار crawl تلگرام؛ این شواهد یک تونل کامل MTProto، ورود حساب یا TCP عمومی را اثبات نمی‌کنند. برای متن عمومی مفید است، نه جایگزین مسیر داده برنامه. |
| GOST | [گزارش کاربرد در net4people](https://github.com/net4people/bbs/issues/586#issuecomment-4021882330) | در این گزارش چند مسیر DNSTT را با TCP round-robin جمع می‌کند. GOST به‌تنهایی حامل گوگل یا راه عبور از whitelist نیست؛ ابتدا یک مسیر کارآمد لازم دارد. |

همچنین دستورهای قدیمی meek/Google App Engine نباید صرفاً با SNI گوگل زنده فرض شوند. Tor در ۲۰۱۸ تغییر سیاست Google و Amazon نسبت به domain fronting را مستند کرده است. موفقیت محدود AMP یا Apps Script شاهد پشتیبانی تمام سرویس‌های Google Cloud از fronting نیست. [توضیح رسمی Tor](https://blog.torproject.org/domain-fronting-critical-open-web/)

## وقتی فقط API گیت‌هاب باز است

کاربرد قابل اتکای API، دریافت اطلاعات کوچک بازیابی است: manifest، نشانی‌ها، hash فایل‌ها و تنظیمات عمومی غیرحساس. Contents API برای فایل تا یک مگابایت محتوا را در JSON/base64 می‌دهد؛ این راه به `raw.githubusercontent.com` وابسته نیست. ref باید commit دقیق باشد و محتوا پس از دریافت با مقدار مورد اعتماد تأیید شود. برای فایل‌های بزرگ‌تر قواعد پاسخ فرق می‌کند و فایل بالای ۱۰۰ مگابایت از این API پشتیبانی نمی‌شود. [مستند رسمی Contents](https://docs.github.com/en/rest/repos/contents?apiVersion=2022-11-28#get-repository-content)

در Gist نیز باید `truncated` بررسی شود؛ `raw_url` ممکن است به میزبان دیگری ببرد. دریافت عمومی به توکن نیاز ندارد، اما ایجاد/تغییر Gist احراز هویت می‌خواهد. هیچ توکن نوشتن یا کلید تونل نباید در Gist/Issue عمومی منتشر شود. نام‌های مبهم مانند «Gist API VPN» بدون پروژه و مسیر داده بررسی‌شده، اثبات تونل عمومی نیستند. [مستند رسمی Gist](https://docs.github.com/en/rest/gists/gists?apiVersion=2022-11-28#get-a-gist)

سقف عمومی بدون احراز هویت معمولاً ۶۰ درخواست در ساعت برای IP مبدأ است؛ NAT مشترک می‌تواند این سهمیه را بین کاربران تقسیم کند. polling سریع برای ساخت تونل روی API با این مدل سازگار نیست. cache محلی، درخواست کم، ETag و رعایت پاسخ rate limit برای بازیابی مفیدترند. توکن اختیاری خواندن نیز نباید در URL یا log قرار بگیرد. [مستند رسمی نرخ API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)

مسیرهای `github.com`، `api.github.com`، `raw.githubusercontent.com`، `codeload.github.com` و `release-assets.githubusercontent.com` باید جدا سنجیده شوند. لینک API archive یا release می‌تواند redirect بدهد. در نتیجه نباید تمام باینری‌ها را برای لحظه قطع به Releases واگذار کرد. گزارش‌های سال ۲۰۲۶ هم تفاوت این میزبان‌ها را ثبت کرده‌اند. [فهرست مسیرهای گزارش‌شده](https://github.com/net4people/bbs/issues/586#issuecomment-4276248556)

پیشنهادهای GitHub Actions شامل دریافت فایل در runner و گذاشتن آن در مخزن بوده‌اند. این یک آینه فایل است و همچنان به میزبان دریافت، زمان runner، اعتبار حساب و محدودیت‌های GitHub وابسته می‌ماند. در بحث Turbo Tunnel بر Actions، نویسنده صریحاً می‌گوید پیاده‌سازی مشخصی نمی‌شناسد؛ آن را به‌عنوان VPN آماده وارد معماری نکرده‌ایم. خواندن Issue/Comment برای خبر و تبادل نشانی ممکن است، ولی نباید محتوای عمومی آن خودکار اجرا شود. [نمونه آینه فایل](https://github.com/net4people/bbs/issues/586#issuecomment-4305263231)، [توضیح درباره تونل Actions](https://github.com/net4people/bbs/issues/586#issuecomment-4383762647)

کتابخانه Kindling نیز برای bootstrap داده کم با چند روش مطرح است. کاربرد آن یافتن مسیر و اطلاعات شروع است؛ ظرفیت bulk VPN از نام آن نتیجه نمی‌شود. برای این پروژه باید داده بازیابی کوچک، قابل تأیید و از پیش cache‌شده بماند. [مخزن Kindling](https://github.com/getlantern/kindling)

## شواهد آماده‌سازی و مرز نتیجه

دریافت منبع ثابت GooseRelay و بازاجرای محلی archive موفق بود. هفت تست آفلاین آماده‌ساز، بررسی digest، مسیر archive، redirect مجاز، فیلدهای واقعی، ورودی نامعتبر، حفظ کلید و مقاومت در برابر symlink را پوشش می‌دهند. گزارش پاک‌سازی‌شده در [evidence](evidence/google-relay-preparation-2026-10-27.json) است. دستور تست:

```bash
python3 -m unittest discover -s tests -p test_google_relay_prep.py -v
```

گزارش اولیهٔ آماده‌ساز پیش از build ثبت شده است؛ وضعیت بعدی ساخت و بازبینی در رکورد جداگانهٔ بالا آمده است. آزمایش زنده Google→Apps Script→خروجی، تعیین ظرفیت اپراتورهای ایران و نصب سرویس همچنان انجام نشده‌اند. هیچ حساب Google، پروژه Cloud، دامنه یا relay تازه‌ای در این پژوهش منتشر نشده و سرور قدیمی ParsPack هم تغییر نکرده است. منبع، تنظیمات، compiler و باینری‌های کاندیدا برای مرحلهٔ بعد نگه‌داری شده‌اند و موانع پذیرش صریح‌اند.

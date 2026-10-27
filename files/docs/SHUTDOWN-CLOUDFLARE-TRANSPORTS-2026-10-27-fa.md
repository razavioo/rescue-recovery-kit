# مسیرهای Cloudflare، Tor، DNS و WebRTC هنگام دسترسی گزینشی

تاریخ بررسی منابع: **۲۷ اکتبر ۲۰۲۶**. این گزارش مکمل پژوهش Google/GitHub و
[آماده‌سازی قبلی Cloudflare](CLOUDFLARE-RESCUE-2026-10-24-fa.md) و
[پژوهش نسخه‌های ترابری](TRANSPORT-RESEARCH-2026-10-25-fa.md) است.
محدوده، خانواده‌های نام‌برده در جدول‌های زیر و منابع اولیهٔ پیوندشده است؛
وجود همهٔ ابزارهای منتشرشده یا موفقیت روی همهٔ اپراتورها ادعا نمی‌شود.
«مستند upstream» یعنی سازوکار یا قابلیت در منبع اصلی وجود دارد؛
«گزارش رخداد» یعنی مشاهدهٔ زمان‌دار؛ هیچ‌کدام به‌تنهایی آزمون شبکهٔ فعلی ما نیست.

## آنچه جنگ قبلی واقعاً نشان داد

در اندازه‌گیری خود Cloudflare، قطعی شدید ژوئن ۲۰۲۵ از ۱۸ ژوئن تا ۲۵ ژوئن
ادامه داشت و از ۲۱ ژوئن بازگشت جزئی دیده شد. تفاوت زمان و اپراتور در همان
رویداد وجود داشت. این داده افت دسترسی را نشان می‌دهد، نه اینکه هر IP متعلق
به Cloudflare برای همه باز بوده باشد.
[گزارش اولیهٔ Cloudflare از فصل دوم ۲۰۲۵](https://blog.cloudflare.com/q2-2025-internet-disruption-summary/)

در ثبت زندهٔ پژوهشگر حاضر در رخداد، IP خاص `google.com` و IP خاص
`api.github.com` قابل دسترس بودند، درحالی‌که بسیاری از مقصدهای دیگر نبودند.
بررسی او انتخاب IP و حفظ نام واقعی سرویس را از domain fronting جدا می‌کند.
AMP/Champa و بازیابی فایل از Drive نیز آزمایش شد، با کندی و محدودیت نرخ.
بنابراین «فقط گوگل وصل است» را باید به IP، نام، پورت و قابلیت دقیق تبدیل کرد.
[ثبت دست‌اول ژوئن ۲۰۲۵](https://ntc.rkn.quest/t/network-shutdown-in-iran-since-2025-06-18/17068)،
[گفت‌وگوی اصلی کاربران و آزمایشگران](https://github.com/net4people/bbs/issues/484)

برای ژانویهٔ ۲۰۲۶، گزارش رسمی پشتیبانی Tor در ۱۱ فوریه می‌گوید پس از تقریباً
دو هفته خاموشی، دسترسی با فهرست مجاز و ناپایداری شدید ادامه یافت و Snowflake
در اواخر ماه فقط در بعضی موارد کار کرد؛ رفتار میان ISPها و مناطق یکسان نبود.
این شاهد با عبارت «Snowflake در تمام خاموشی کار می‌کرد» سازگار نیست.
[گزارش رسمی پشتیبانی Tor برای ژانویهٔ ۲۰۲۶](https://forum.torproject.org/t/tor-project-user-support-report-for-january-2026/21221)

## معنی عملی «Cloudflare باز است»

| دسترسی مشاهده‌شده | قابلیت محتمل | چیزی که هنوز باید جدا ثابت شود |
|---|---|---|
| صفحهٔ HTTPS پشت CDN باز می‌شود | HTTP به همان hostname و edge | WebSocket، WAF، origin و انتقال طولانی |
| `1.1.1.1` پاسخ DNS می‌دهد | DNS به یک resolver | recursion به دامنهٔ تازهٔ خارجی، TXT/EDNS و انتقال تونل |
| WARP handshake می‌زند | ارتباط ابتدایی با endpoint | authenticated data plane، DNS و HTTPS مستقل |
| TCP/443 به Cloudflare باز است | TLS/H2 ممکن است | MASQUE endpoint و هویت معتبر؛ هر edge وب WARP نیست |
| UDP/443 به Cloudflare باز است | QUIC/H3 ممکن است | handshake واقعی، MTU و انتقال دوطرفه |
| IPv6 یک سرویس باز است | یک مسیر IPv6 سالم | route عمومی، بازگشت بسته و پایداری همان family |
| dashboard یا API باز است | امکان مدیریت یا ثبت‌نام | ترافیک کاربر و اتصال office به edge |

این جدول نتیجهٔ وابستگی‌های پروتکل‌هاست، نه نتیجهٔ اسکن زنده. موفقیت در یک
ردیف نباید باعث فعال‌سازی خودکار ردیف‌های دیگر شود.

## WARP: سه مسیر قابل تفکیک

۱. **WireGuard** به endpoint واقعی WARP و UDP عبوری نیاز دارد. داشتن IP تمیز
CDN یا دسترسی به صفحهٔ `cloudflare.com` جای این endpoint را نمی‌گیرد.

۲. **MASQUE روی H3** از QUIC/UDP استفاده می‌کند؛ انسداد UDP، افت MTU یا
محدودسازی QUIC می‌تواند آن را از کار بیندازد، حتی اگر HTTPS معمولی سالم باشد.

۳. **MASQUE روی H2** برای شبکه‌ای که TCP/TLS را عبور می‌دهد و UDP را می‌بندد
فرضیهٔ جداگانه‌ای است. مستند رسمی Cloudflare One اکنون `TCP 443` را صریحاً
برای fallback به HTTP/2 فهرست می‌کند. این قابلیت در ابزار/نسخهٔ واقعی باید
بررسی شود؛ عبارت MASQUE به‌تنهایی تضمین H2 نیست.
[فایروال و پورت‌های رسمی Cloudflare One؛ ویرایش ۲۴ ژوئیهٔ ۲۰۲۶](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/)

فهرست رسمی بالا WireGuard سازمانی را روی IPv4 `162.159.193.0/24` و IPv6
`2606:4700:100::/48`، و MASQUE سازمانی را روی `162.159.197.0/24` و
`2606:4700:102::/48` قرار می‌دهد. محدودهٔ consumer با Zero Trust یکسان نیست.
این محدوده‌ها مبنای برنامه‌ریزی‌اند، نه فهرست endpointهای موفق ایران؛ جایگزینی
کورکورانهٔ محدودهٔ حساب‌ها درست نیست. ثبت‌نام، orchestration و ورود IdP هم
وابستگی‌هایی جدا از تونل دارند.

برای پروژه، پیش‌ثبت هویت‌های مستقل WG/MASQUE، نسخهٔ ثابت باینری و نگهداری
خصوصی credentialها از افزودن دوبارهٔ اسم پروفایل مفیدتر است. wrapperهای قبلی
پروژه ثبت امن، pinning تونل، استفاده از هویت ذخیره‌شده و آزمون انتقال دارند؛
گزارش‌های قبلی را باید همراه نسخه خواند. موفقیت پیشین سرور خارج، آزمون
خروج مستقیم office زیر محدودیت جدید محسوب نمی‌شود. هیچ هویت خصوصی نباید
داخل لینک عمومی، گزارش JSON یا git قرار بگیرد.

WARP در حالت DNS-only فقط DNS را رمز می‌کند؛ VPN عمومی نمی‌سازد. در حالت
Traffic and DNS، ترافیک دستگاه حمل می‌شود. این دو mode در آزمون و متن راهنما
نباید یکسان نام‌گذاری شوند.
[تعریف رسمی modeهای WARP؛ مشاهده در ۲۷ اکتبر ۲۰۲۶](https://developers.cloudflare.com/warp-client/warp-modes/)

**آماده‌سازی بدون حساب تازه:** نگهداری خصوصی هویت موجود، ماتریس H2/H3/WG ×
v4/v6، کش endpointهای قبلاً موفق همراه زمان و شبکه، reconnect با backoff و
آزمون واقعی HTTPS. فعال‌سازی هر family به route همان family وابسته است.
انتخاب endpoint باید محدود، زمان‌دار و با تست داده انجام شود؛ ping یا TCP-open
به‌تنهایی معیار انتخاب نیست.

## CDN، Worker، Pages و Cloudflare Tunnel

این خانواده دو معماری متفاوت دارد:

| معماری | مسیر | دارایی لازم |
|---|---|---|
| CDN با origin متعلق به ما | کاربر → HTTPS/CDN → origin HTTP/WS → خروج | دامنه، گواهی، origin قابل دسترس از Cloudflare و proxy احرازشده |
| Worker با خروج TCP | کاربر → HTTPS/WS Worker → TCP مقصد یا egress متعلق به ما | حساب و کد Worker، secret اختصاصی و خروج سازگار |
| Named Tunnel به office | کاربر → HTTPS/CDN → تونل موجود → سرویس loopback office | دامنه/حساب، credential تونل و خروج office به edgeهای Tunnel |
| Pages استاتیک | کاربر → فایل HTML/JS | فقط میزبانی فایل؛ برای proxy اجرای سمت سرور/Functions هم لازم است |

Cloudflare رسماً WebSocket را در همهٔ پلن‌ها پشتیبانی می‌کند؛ درخواست upgrade
می‌تواند تحت WAF و rate limit رد شود و اتصال‌های برقرارشده نیز با به‌روزرسانی
شبکه قطع شوند. keepalive و reconnect لازم‌اند. پشتیبانی WS به معنی پشتیبانی
هر نوع HTTP Upgrade نیست.
[مستند رسمی WebSocket](https://developers.cloudflare.com/network/websockets/)

در Workers، `connect()` خروج TCP می‌دهد، ولی اتصال به IPهای خود Cloudflare،
loopback و IP خصوصی رد می‌شود و پورت ۲۵ نیز محدود است. در نتیجه Worker نمی‌تواند
با همین API مستقیماً به `192.0.2.10` یا به IP پروکسی‌شدهٔ خودش وصل شود.
اتصال Worker به hostname پشت Tunnel باید با API سازگار HTTP/WS طراحی شود،
یا از egress عمومی مجاز استفاده کند؛ تکرار `connect()` به همان Cloudflare یک
راه خروج مستقل ایجاد نمی‌کند.
[محدودیت‌های رسمی TCP sockets؛ ویرایش ۱۳ اکتبر ۲۰۲۶](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)

VLESS/Trojan روی Worker نمونه‌های واقعی upstream دارند؛
[BPB](https://github.com/bia-pain-bache/BPB-Worker-Panel) و
[edgetunnel](https://github.com/zizifn/edgetunnel) از این خانواده‌اند. وجود پنل و
لینک سازگار، کیفیت کد، پشتیبانی UDP عمومی یا پایداری ایران را ثابت نمی‌کند.
UUID/رمز، مسیر مدیریت، proxyIP، DoH، fallback و وابستگی‌های subscription باید
قبل از استقرار بازبینی شوند. upstream قدیمی edgetunnel آخرین commit مشاهده‌شده
را در نوامبر ۲۰۲۴ دارد؛ صرف پرستاره‌بودن دلیل انتخاب نسخه نیست.

در پلن رایگان Workers، محدودیت رسمی فعلی ۱۰۰هزار درخواست روزانه برای حساب،
۱۰ms زمان CPU هر درخواست و شش اتصال خروجی هم‌زمان هر درخواست است. زمان انتظار
شبکه همان CPU time نیست. دامنهٔ شخصی، محدودیت حساب را حذف نمی‌کند. طراحی باید
خطای quota و قطع runtime را مدیریت کند؛ راه‌حل «نامحدود چون دامنهٔ شخصی دارد»
از مستند فعلی نتیجه نمی‌شود.
[محدودیت‌های رسمی Workers؛ ویرایش ۱۲ اکتبر ۲۰۲۶](https://developers.cloudflare.com/workers/platform/limits/)

### نکتهٔ تعیین‌کننده برای office

`cloudflared` از office به edgeهای مخصوص Tunnel روی **پورت ۷۸۴۴** متصل
می‌شود: QUIC روی UDP و HTTP/2 روی TCP. H2 در این محصول به معنی fallback روی
TCP/443 نیست. اگر فقط وب Cloudflare روی ۴۴۳ باز باشد، Tunnel ممکن است اصلاً
برقرار نشود. کش credential اتصال از قبل مفید است، اما بسته‌بودن ۷۸۴۴ را حل
نمی‌کند. نام‌های discovery/SNI، IPهای region1/region2 و DNS لازم نیز باید در
بررسی خروج office حضور داشته باشند.
[فایروال رسمی Tunnel؛ ویرایش ۱۲ اکتبر ۲۰۲۶](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/)

اگر UDP قطع شود، خود `cloudflared` می‌تواند به H2/TCP برگردد؛ اگر هر دو حالت
۷۸۴۴ بسته باشند، تونل کار نمی‌کند. از `--protocol http2` می‌توان برای آزمون
جداگانه استفاده کرد، نه برای دورزدن نیاز پورت.
[عیب‌یابی رسمی Tunnel؛ ویرایش ۱۱ سپتامبر ۲۰۲۶](https://developers.cloudflare.com/tunnel/troubleshooting/)

Cloudflare Tunnel، WebSocket دارد، ولی **gRPC روی public hostname فعلاً
پشتیبانی نمی‌شود**؛ gRPC آن به private subnet routing مربوط است. این محدودیت
با gRPC در reverse proxy معمول CDN فرق دارد. بنابراین پروفایل gRPC یا XHTTP
که به stream-up مشابه gRPC متکی است نباید بدون تست به hostname تونل office
منتسب شود.
[gRPC رسمی Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/grpc/)،
[شرایط gRPC در CDN معمولی](https://developers.cloudflare.com/network/grpc-connections/)

**آماده‌سازی با منابع فعلی:** recipe و آزمون WS احرازشده، جداکردن سلامت
office→Tunnel از کاربر→edge، و بستهٔ استقرار بازبینی‌شده قابل تهیه است. انتشار
واقعی به zone/hostname/credential متعلق به کاربر نیاز دارد. Quick Tunnel
تصادفی جای hostname ذخیره‌شده و قابل توزیع آفلاین را نمی‌گیرد. در این پژوهش
هیچ حساب یا منبع خارجی ساخته یا تغییر داده نشده است.

## ECH، IP تمیز و تغییر ClientHello

**ECH** بخش حساس ClientHello، از جمله نام واقعی سرور، را رمز می‌کند. IP مقصد،
وجود ترافیک و public name بیرونی همچنان قابل مشاهده‌اند؛ مسدودشدن IPها یا
خود ECH ممکن است آن را بی‌اثر کند. کلاینت به ECHConfig معتبر و سرور پشتیبان
نیاز دارد. config کش‌شده ممکن است منقضی یا عوض شود. صرف قراردادن اسم دلخواه
در فیلد SNI، ECH فعال ایجاد نمی‌کند.
[شرح رسمی Cloudflare؛ ویرایش ۱۷ آوریل ۲۰۲۶](https://developers.cloudflare.com/ssl/edge-certificates/ech/)،
[استاندارد TLS ECH، RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)

**Domain fronting** به تفاوت نام بیرونی TLS و نام مقصد داخل HTTP و پذیرش
این تفاوت توسط ارائه‌دهنده نیاز دارد. ECH معادل آن نیست و مجوز استفاده از
هر hostname دلخواه را نمی‌دهد. در انتخاب IP تمیز، برعکس، می‌توان IP اتصال را
عوض کرد و SNI/Host واقعی سرویس خودمان و اعتبارسنجی گواهی را نگه داشت.
[توضیح اولیهٔ Cloudflare دربارهٔ تفاوت ECH و fronting](https://blog.cloudflare.com/handshake-encryption-endgame-an-ech-update/)

**Fragmentation، fingerprint، padding و F&F** برای فرضیهٔ تشخیص TLS/DPI
هستند. این‌ها route بسته را باز نمی‌کنند. نتیجهٔ هر preset باید با نسخهٔ دقیق
کلاینت، فایروال و انتقال واقعی ثبت شود. تنظیمات غیر استاندارد یک fork نباید
بدون بررسی داخل core دیگر کپی شوند. کاهش fingerprint با خاموش‌کردن بررسی
گواهی قابل پذیرش نیست. دستورهای proxyless fragmentation نیز تنها هنگامی
معنا دارند که IP مقصد از قبل قابل دسترس باشد.

## WS، HTTPUpgrade، gRPC و XHTTP چه تفاوتی دارند؟

| حامل | ویژگی مؤثر | محدودیت مهم |
|---|---|---|
| WebSocket | stream دوطرفه روی upgrade وب | رد WAF، قطع idle و reconnect؛ UDP عمومی خودکار نیست |
| HTTPUpgrade | حامل جدا با handshake upgrade | هر CDN که WS دارد الزاماً این upgrade را عبور نمی‌دهد |
| gRPC | جریان HTTP/2 | نیاز به H2/ALPN، origin و تنظیم CDN سازگار؛ Tunnel عمومی فرق دارد |
| XHTTP packet-up | آپلود در درخواست‌های جدا | سربار درخواست/تأخیر و وابستگی دو جهت به backend/session |
| XHTTP stream-up/stream-one | جریان HTTP و امکان H2/H3 | buffering، زمان‌بندی CDN و mode واقعی باید جدا آزموده شود |

راهنمای خود Xray برای XHTTP امکان انتخاب IP CDN با حفظ serverName، حالت‌های
مختلف و نیاز به keepalive را توضیح می‌دهد. نام چند transport روی یک دامنهٔ
Cloudflare به معنی چند زیرساخت مستقل نیست. برای office پشت Tunnel، WS و
packet-up را نیز باید مستقل تست کرد؛ توصیهٔ «gRPC را روشن کن» در origin عمومی
نباید بی‌بررسی به این معماری تعمیم داده شود.
[راهنمای اصلی XHTTP از توسعه‌دهنده](https://github.com/XTLS/Xray-core/discussions/4113)

مستند فعلی Xray برای gRPC مهاجرت به XHTTP را توصیه می‌کند. همچنین محدودیت
سازگاری protocol/transport/security وجود دارد؛ مثلاً REALITY با WebSocket
قابل ترکیب نیست. اضافه‌کردن `reality` به یک لینک CDN معمول، Cloudflare را به
سرور REALITY تبدیل نمی‌کند.
[راهنمای رسمی gRPC](https://xtls.github.io/en/config/transports/grpc.html)،
[جدول رسمی سازگاری transportها](https://xtls.github.io/en/config/transport.html)

## Tor و پل‌های مستقل

| روش | کانال لازم از داخل ایران | آماده‌سازی و مرز کارکرد |
|---|---|---|
| obfs4 | TCP به IP/پورت پل | پل خصوصی تازه، cert و fingerprint؛ تصادفی‌نما بودن روی فهرست مجاز سخت کافی نیست |
| WebTunnel | HTTPS به URL پل | URL، مسیر و fingerprint معتبر؛ شباهت به وب، مسدودشدن IP را حل نمی‌کند |
| meek | HTTP(S) به frontend سازگار | bridge line روز و backend واقعاً فعال؛ معمولاً پرهزینه‌تر و کندتر |
| Snowflake | signaling + STUN/ICE + DTLS به peer | دسترسی broker یا AMP فقط گام اول؛ data channel به داوطلب هم لازم است |
| Conjure | registration و اتصال به phantomهای ISP همکار | وابسته به ایستگاه/مسیر واقعی، نه قابل ساخت صرفاً با یک VPS عادی |

Lyrebird پیاده‌سازی چند transport شامل obfs4، meek، Snowflake و WebTunnel
را در اکوسیستم Tor فراهم می‌کند. برای obfs4/WebTunnel خط پل معتبر لازم است؛
bridge endpoint ساختگی هرچند syntax درست داشته باشد آمادهٔ استفاده نیست.
[راهنمای رسمی Tor برای رفع مسدودی](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)،
[تنظیم رسمی daemon و پل‌ها](https://support.torproject.org/little-t-tor/circumvention/using-bridges/)

دو اصلاح مهم نسبت به راهنماهای رایج:

* نام قدیمی **meek-azure** به معنی backend فعلی Azure نیست. Tor در نسخهٔ
  15.0a4 در ۲۰۲۵ آن را به **meek** تغییر داد، چون ارائه‌دهنده‌های پشت آن عوض
  شده‌اند. وابستگی «فقط Microsoft کافی است» از نام تاریخی نتیجه نمی‌شود.
  [اعلام رسمی Tor](https://forum.torproject.org/t/new-alpha-release-tor-browser-15-0a4/20697)
* در Snowflake، broker فقط peerها را پیدا و signaling را منتقل می‌کند.
  مقالهٔ اصلی سامانه توضیح می‌دهد که broker تطبیق‌هایی را که TURN لازم دارند
  کنار می‌گذارد. بنابراین بازبودن یک STUN گوگل یا AMP-cache به معنی عبور کل
  ترافیک از گوگل نیست؛ peer داوطلب مسیر داده است.
  [مقالهٔ توسعه‌دهندگان Snowflake در USENIX Security 2024](https://www.usenix.org/system/files/usenixsecurity24-bocovich.pdf)

Snowflake مسیرهای signaling مختلف، از جمله domain fronting، AMP cache و
Amazon SQS دارد. تنوع signaling با تنوع data plane یکی نیست؛ جایگزینی broker
اگر DTLS به همهٔ peerها بسته باشد مشکل اصلی را رفع نمی‌کند.
[مستند تیم ضد سانسور دربارهٔ signaling](https://rhatto.pages.torproject.net/wikipelago/anti-censorship/Signaling-Channels/Documentation-of-Use/)

Conjure از فضای IP استفاده‌نشدهٔ ISPهای همکار phantom proxy می‌سازد. پژوهش
خود اپراتورها دربارهٔ ایران در ۲۰۲۳ تا فوریهٔ ۲۰۲۵ تفاوت سانسور میان ASNها
و مسدودسازی IP/تزریق بسته را نشان می‌دهد؛ اندازه‌گیری قبل از جنگ، تضمین دورهٔ
خاموشی نیست. آماده‌سازی client و registration مفید است، ولی راه‌اندازی station
آن روی office عادی بدون همکاری شبکه جایگزین نمی‌شود.
[معرفی اصلی Conjure برای Tor](https://archive.torproject.org/websites/lists.torproject.org/pipermail/tor-dev/2022-August/014772.html)،
[پژوهش اولیهٔ اندازه‌گیری Conjure در ایران، ۲۰۲۵](https://ericw.us/trow/iran-proxy.pdf)،
[کد و پیش‌نیازهای ایستگاه](https://github.com/refraction-networking/conjure)

**آماده‌سازی قابل انجام:** Expert Bundle/نسخهٔ مناسب Lyrebird با hash، چند پل
تازه از کانال رسمی در فایل خصوصی، تنظیم‌های manual جدا و آزمون bootstrap کامل
همراه HTTPS. پیش از دادن دسترسی مستقیم peerهای Snowflake به office باید policy
خروج مشخص شود؛ محدودیت `iran_only` با signaling از مسیر مجاز، خودبه‌خود اجازهٔ
DTLS به peerهای خارجی ایجاد نمی‌کند. آزمون در namespace محدود و بدون تغییر
فایروال کل میزبان، مرز روشن‌تری دارد.

## Psiphon، Conduit و Lantern/Action Mode

Psiphon از چند مسیر در رقابت اتصال استفاده می‌کند؛ Conduit یک relay میان
کاربر و سرورهای Psiphon است و خروج نهایی مستقل متعلق به خود ما نمی‌سازد.
راهنمای رسمی بر تنوع IP، منابع کافی و reputation نزد broker تأکید می‌کند و
می‌گوید در بعضی شبکه‌ها کار نمی‌کند. خود سرویس در گزارش ۱۶ ژوئن ۲۰۲۶ از
۹٫۵میلیون کاربر یکتای ایران در ۳۰ ژانویه و عبور نیمی از ترافیک از Conduit
خبر می‌دهد؛ این آمار ناشر است، نه سنجش همهٔ شبکه‌های خاموش.
[راهنمای رسمی استقرار Conduit](https://github.com/Psiphon-Inc/conduit/blob/main/cli/GUIDE.md)،
[گزارش خود Psiphon](https://blog.psiphon.ca/2026/06/16/to-russians-with-love/)

شرح فنی فعلی inproxy می‌گوید مسیر client→proxy، WebRTC DataChannel/DTLS است،
ICE candidateهای host و STUN استفاده می‌شوند و **TURN candidate استفاده
نمی‌شود**. پس نصب Conduit در خارج، به‌تنهایی مسیر pure-Google یا pure-Cloudflare
برای office داخل ایران ایجاد نمی‌کند. broker و خروج از relay به Psiphon نیز
وابستگی مستقل دارند.
[مستند فنی upstream inproxy با نسخهٔ ثابت اکتبر ۲۰۲۶](https://pkg.go.dev/github.com/Psiphon-Labs/psiphon-tunnel-core@v1.0.11-0.20261005170209-c4a09096ab40/psiphon/common/inproxy)

Lantern، engine داوطلبانهٔ **Unbounded** را اکنون در محصول **Action Mode**
ارائه می‌کند. معماری consumer→WebRTC peer→egress دارد؛ discovery، نسخهٔ
client، peer واقعی و egress همه لازم‌اند. ماژول consumer فعلی lantern-box
نیز STUN/DTLS مستقیم به peer و QUIC روی DataChannel را شرح می‌دهد. صفحهٔ
داوطلب یا bootstrap قابل دسترس، آزمون خروج اینترنت نیست.
[مخزن اصلی Unbounded/Action Mode](https://github.com/getlantern/unbounded)،
[مستند consumer در lantern-box](https://pkg.go.dev/github.com/getlantern/lantern-box/protocol/unbounded)

**آماده‌سازی قابل انجام:** installerهای اصلی و قابل تأیید، تنظیم خصوصی client
و آزمون جدا از مسیرهای داخلی ما. تبدیل این محصولات به relay عمومی پروژه یا
اجرای داوطلب روی office، تصمیم جدا دربارهٔ مصرف ترافیک و policy است. این
پژوهش هیچ دستگاهی را به relay دیگران تبدیل نکرده است.

## وقتی فقط DNS باز است

| خانواده | سازوکار مستند | استقلال واقعی و مانع اصلی |
|---|---|---|
| DNSTT | KCP + Noise + smux روی DNS؛ UDP/DoH/DoT | نیاز به recursion تا authoritative خارج و کلید سرور |
| NoizDNS | مشتق DNSTT با تغییر label، cover traffic و resolverهای چندگانه | همان خانوادهٔ رمز/حمل؛ ادعای stealth باید روی شبکه آزموده شود |
| VayDNS | مشتق DNSTT با قالب و تنظیم‌های قابل تغییر | wire format پیش‌فرض با DNSTT فرق دارد؛ دو طرف باید سازگار باشند |
| Slipstream اصلی C | QUIC و multipath داخل پیام‌های DNS | رفتار resolver، polling و محدودیت نرخ همچنان تعیین‌کننده‌اند |
| slipstream-rust از Mygod | بازنویسی Rust همان ایده | نگهداری متوقف شده؛ برای انتخاب جدید اولویت ندارد |
| MasterDNS / SOAR / CottenDNS | خانواده‌های موجود یا قبلاً بررسی‌شدهٔ پروژه | نام‌های بیشتر به معنی resolver/domain/route مستقل نیست |

DNSTT سرور authoritative با دامنهٔ تفویض‌شده و UDP/53 در بیرون می‌خواهد.
کلاینت به resolver عمومی/قابل دسترس درخواست می‌دهد و resolver باید واقعاً
درخواست را به آن دامنه برساند. بازبودن DNS داخلی فقط برای دامنه‌های داخلی
کافی نیست. حالت خام UDP، محتوای تونل را در معرض تشخیص DNS قرار می‌دهد؛ DoH/DoT
مسیر client→resolver را رمز می‌کنند، ولی خود resolver همچنان تونل را می‌بیند.
[مستند اصلی DNSTT؛ آخرین به‌روزرسانی ۱ مهٔ ۲۰۲۶](https://www.bamsoftware.com/software/dnstt/)

در DNSTT، Noise سرور را احراز می‌کند، **کلاینت را احراز نمی‌کند**. سرور عمومی
که مستقیم به SOCKS بدون رمز وصل شود می‌تواند برای افراد دارای کلید عمومی
قابل استفاده شود. برای دسترسی خصوصی، احراز کلاینتِ لایهٔ درونی مانند SSH با
host key ثابت و کلید مجاز لازم است. public key تونل جای مجوز کاربر را نمی‌گیرد.
[شرح دقیق پروتکل DNSTT](https://www.bamsoftware.com/software/dnstt/protocol.html)

NoizDNS قابلیت‌هایی مانند طول label متغیر، cover traffic، health resolver و
DoH/DoT را در README اصلی دارد. VayDNS نیز حالت سازگار `-dnstt-compat`، نوع
رکوردهای مختلف و پارامترهای recovery را مستند می‌کند. این‌ها کاندیدای آزمایش
برای DPI یا resolver نامناسب‌اند؛ شواهد مستقل از موفقیت عمومی در خاموشی فعلی
در این بررسی به دست نیامد. پیکربندی aggressive می‌تواند بار و خطای resolver
را زیاد کند و نباید با اسکن انبوه اینترنت شروع شود.
[NoizDNS با commit ثابت](https://github.com/anonvector/noizdns/blob/f76c585093c7c31e9be6c10a1b425be033eb4938/README.md)،
[VayDNS با commit ثابت](https://github.com/anonvector/vaydns/blob/a0ff70110d5e96686ab8f4c8e1c44cd09be07a75/README.md)

در Slipstream، QUIC **داخل DNS** است؛ این به معنی نیاز مستقیم client به
UDP/443 خارجی نیست. در مقابل، استفاده از چند resolver اگر همه از یک خروج
بین‌الملل یا یک authoritative عبور کنند آن وابستگی را حذف نمی‌کند.
benchmarkهای upstream آزمایش نویسنده‌اند و throughput سیم‌کارت ما نیستند.
[Slipstream اصلی با commit ۲۴ اکتبر ۲۰۲۶](https://github.com/EndPositive/slipstream/blob/e158a681f1cc5cb000a92274371e67237d2a6493/README.md)،
[شرح پروتکل upstream](https://endpositive.github.io/slipstream/)

**اصلاح تازگی منبع:** `Mygod/slipstream-rust` در ۲۸ اوت ۲۰۲۶ archive شده است.
نویسنده علت را هزینهٔ معماری QUIC روی DNS، polling و سیاست resolver شرح می‌دهد
و MasterDnsVPN را جایگزین قابل بررسی معرفی می‌کند. این توقف به معنی توقف
Slipstream اصلی C نیست. نصب‌کننده‌ای که صرفاً نام Rust را جدیدتر می‌خواند
نباید مبنای انتخاب باشد.
[اعلام مستقیم توقف نگهداری](https://github.com/Mygod/slipstream-rust/discussions/111)

SlipNet یک client چندپروتکلی با DNS scanner است، نه شبکهٔ خروج مستقل. مخزن
اصلی توزیع App Store را منبع رسمی خود نمی‌داند. نام‌های تجاری مانند «StunTLS»
در بعضی صفحات فروش دیده می‌شوند؛ تا شناسایی upstream، نسخه، کد و تبادل دادهٔ
قابل بازتولید، آن نام نباید به‌عنوان حامل تأییدشده وارد selector شود.
[مخزن اصلی SlipNet با commit ثابت](https://github.com/anonvector/SlipNet/tree/552ab5078d90ae84294fcd6ef649b8e023ba2a63)

**آماده‌سازی لازم برای خانوادهٔ DNS:** subdomain کوتاه مستقل، NS صحیح، کلید
یا pin سرور، نسخه‌های سازگار دو طرف، سرور خارجی مجاز برای authoritative،
جداسازی پورت از DNS موجود و فهرست resolver مجازِ آزموده‌شده. این کار به
دسترسی zone و میزبان مجاز خارج نیاز دارد. رکورد A/AAAA مربوط به authoritative
نباید مثل یک وب‌سایت پشت پروکسی HTTP قرار بگیرد. DNSSEC/TTL، اندازهٔ EDNS،
fallback TCP، نرخ پرس‌وجو و رفتار timeout نیز باید در آزمون همان resolver ثبت
شوند. MasterDNS موجود را نباید برای امتحان پروتکل تازه جابه‌جا یا خاموش کرد.

## STUN، TURN، WebRTC و روش‌های تماس تصویری

STUN برای کشف نگاشت NAT و بررسی اتصال است؛ صرف پاسخ آن یک relay عمومی
اینترنت نمی‌سازد. TURN واقعاً allocation و relaying می‌دهد، ولی نیاز به سرور
قابل دسترس، credential معتبر، permission به peer و refresh دارد. مسیر
client→TURN می‌تواند UDP یا TCP/TLS باشد؛ ظرفیت و مسیر TURN→peer هم لازم
است. اگر فقط IP سرویس تماس مجاز باشد، ICE ممکن است مجبور به relay شود؛ وجود
نام STUN در config چنین relayی را تضمین نمی‌کند.
[استاندارد TURN، RFC 8656، فوریهٔ ۲۰۲۰](https://www.rfc-editor.org/rfc/rfc8656.html)

برای relay متعلق به خودمان یا مجاز، آزمون باید `Allocate`، `CreatePermission`،
جریان واقعی دوطرفه، تمدید allocation و انقضای credential را شامل شود. دریافت
پاسخ STUN یا صفحهٔ loginِ سرویس تماس کافی نیست. credential کوتاه‌عمر یک
برنامهٔ تماس را نباید credential دائمی تونل فرض کرد. این گزارش هیچ credential
یا relay متعلق به شخص ثالث را استخراج نکرده است.

Snowflake و Conduit را نباید خودکار «تونل از TURN گوگل/کلادفلر» نامید؛ منابع
اصلی بالا خلاف این تعمیم را روشن می‌کنند. مسیرهای مبتنی بر پیام‌رسان، تماس،
media stream، WebRTC DataChannel و relay اختصاصی باید جدا شناخته شوند.
حتی دو ابزار مبتنی بر WebRTC ممکن است یکی peer مستقیم و دیگری TURN داشته
باشد. معیار پذیرش، مقصدهای واقعاً مشاهده‌شدهٔ داده و آزمون قطع مسیر مستقیم
است، نه نام کتابخانهٔ WebRTC.

## اولویت اجرایی برای ساختار فعلی

این ترتیب قضاوت مهندسی بر پایهٔ وابستگی و دارایی موجود است، نه رتبه‌بندی
موفقیت اثبات‌شده در ایران:

1. **قوی‌ترکردن مسیرهای موجود:** آزمون endpoint با داده، H2 مستقل از WG/H3،
   هویت آفلاین، fallback با backoff، سلامت انتقال واقعی و گزارش family/ASN.
2. **ورودی CDN احرازشده به office:** recipe WS و یک hostname قابل توزیع،
   همراه آزمون جداگانهٔ خروج ۷۸۴۴ office؛ با حساب/دامنه/credential کاربر.
3. **آماده‌بودن client و bridgeهای تازهٔ Tor:** چند خانوادهٔ واقعی با خط پل
   معتبر و checksum؛ activation پس از احراز policy خروج هر خانواده.
4. **تنوع DNS هدفمند:** DNSTT یا VayDNS/NoizDNS در subdomain و پورت مستقل؛
   ابتدا به‌عنوان آزمایش با resolverهای از پیش مجاز، بدون دست‌زدن به MasterDNS.
5. **مسیرهای داوطلبانه یا TURN مجاز:** بستهٔ client و آزمون محدود آماده شود؛
   broker، credential، peer policy و میزبان خارج پیش‌نیاز activation هستند.

برای هر مسیر: HTTPS خارج از همان ارائه‌دهنده، DNS از داخل تونل، upload و
download کامل با hash، اتصال‌های هم‌زمان، idle، قطع یک‌طرفه، بازگشت مسیر و
restart سرویس باید آزموده شود. موفقیت `warp=on`، `Bootstrapped 100%` یا HTTP
200 صفحهٔ محلی به‌تنهایی انتقال کاربردی را ثابت نمی‌کند. گزارش آزمایش باید
زمان، ASN/شبکه، مکان کلی، family، نسخه/commit، endpoint و علت شکست را ثبت کند
و credential یا نشانی پل خصوصی را عمومی نکند.

استقرار برنامه فقط روی **`office-host`** مجاز است. سرور قدیمی ParsPack
و relayهای موجود آن در این کار تغییر نمی‌کنند. اگر یک راه جدید به IP عمومی،
UDP/53، تغییر شبکه یا egress خارج نیاز دارد، آن نیاز به‌عنوان داراییِ فراهم‌نشده
ثبت می‌شود؛ جای خالی آن با تغییر خودسرانهٔ سرور قدیمی پر نمی‌شود.

## رکورد تازگی مخزنهای کاندیدا

تاریخ‌ها از API رسمی GitHub در روز بررسی گرفته شدند؛ commit، هویت source
است، نه تأیید امنیت باینری یا نتیجهٔ تست ایران.

| مخزن | commit مشاهده‌شده | تاریخ commit |
|---|---|---|
| EndPositive/slipstream | `e158a681f1cc5cb000a92274371e67237d2a6493` | ۲۰۲۶-۱۰-۲۴ |
| Mygod/slipstream-rust | `7de506b222c83ae97a19a618e33fe26899af1bd5`؛ archived | ۲۰۲۶-۰۸-۲۸ |
| anonvector/noizdns | `f76c585093c7c31e9be6c10a1b425be033eb4938` | ۲۰۲۶-۰۸-۲۱ |
| anonvector/vaydns | `a0ff70110d5e96686ab8f4c8e1c44cd09be07a75` | ۲۰۲۶-۰۴-۱۰ |
| anonvector/SlipNet | `552ab5078d90ae84294fcd6ef649b8e023ba2a63` | ۲۰۲۶-۰۸-۲۱ |
| Psiphon-Inc/conduit | `e670d0b8ada53d834709ef3c21b93e18cbd3de14` | ۲۰۲۶-۰۹-۱۶ |
| getlantern/unbounded | `d28b500f13ad8cee2dff5f87ea3f3bd5f6fcbca8` | ۲۰۲۶-۱۰-۲۶ |
| bia-pain-bache/BPB-Worker-Panel | `9b2e33e8470b9c5de03a30592e99c640e7b1ae71` | ۲۰۲۶-۰۷-۲۰ |
| zizifn/edgetunnel | `44b9377986b6545517908cc3e2b52211aad10945` | ۲۰۲۴-۱۱-۲۷ |

در این پژوهش شبکهٔ فعلی سیم‌کارت، پایداری چندساعته، تازه‌بودن private bridgeها
و صحت امنیتی کامل forkهای DNS آزمایش نشده‌اند. دسترسی مستقیم GitLab Tor در
ابزار وب در چند مورد خطا داد؛ برای ادعای سازوکار از مستند رسمی Tor، مقالهٔ
نویسندگان و مستند نسخه‌دار module استفاده شد، نه mirror ناشناس یا متن تبلیغی.

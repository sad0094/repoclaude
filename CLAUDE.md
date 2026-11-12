# Nöbet — Claude için proje notları ve aktarım

Bu dosya, projeyi devralan Claude oturumu içindir. Her iş bitiminde güncel tutulur.

## Kalıcı kullanıcı talimatı

**Her işin sonunda kullanıcıya "başka bir Claude'a aktarım" çıktısı sun** (kullanıcı 11.11.2026'da istedi):
yanıtın sonunda, kopyalanabilir tek bir blok hâlinde; içinde proje durumu, bu işte yapılanlar,
doğrulananlar/doğrulanmayanlar ve sıradaki adımlar bulunsun. Aynı bilgiyi bu dosyanın
"Güncel durum" bölümüne de işle. Kullanıcıyla Türkçe konuş.

## Proje nedir

Çok şirketli (MSP tarzı) IT monitörleme. Her müşteri şirketin sunucusuna **Agent** kurulur,
hepsi tek merkezi **Manager** paneline rapor gönderir (bağlantıyı her zaman Agent başlatır).
Kritik uyarılar Telegram botuna/webhook'a gider ve onaylanana kadar tekrarlanır.
Ürün adı (geçici): "Nöbet". Depo: `sad0094/repoclaude`, çalışma dalı `claude/stoic-lamport-6xe26u`.

## Yapı

| Yol | İçerik |
| --- | --- |
| `manager/db.py` | SQLite şeması, tek-yazar işlem kilidi, ayar varsayılanları, şirket/anahtar işlemleri |
| `manager/core.py` | `Engine`: rapor işleme (`ingest`), uyarı kuralları, servis kontrol sonuçları, periyodik `tick` (çevrimdışı, tekrar bildirimi, temizlik) |
| `manager/notify.py` | Telegram + webhook gönderimi (arka plan kuyruğu) |
| `manager/totp.py` | İki adımlı doğrulama: TOTP üretme/doğrulama, kurtarma kodları |
| `manager/qr.py` | QR kod üreteci (bayt kipi, seviye M, sürüm 1-10); kurulum adresini panelde göstermek için |
| `manager/web.py` | HTTP sunucusu, oturum, kullanıcı/rol yetkilendirmesi, panel API'si, statik dosyalar |
| `manager/static/` | Tek sayfalık panel (bağımlılıksız JS; `h\`\`` şablonu her değeri kaçışlar) |
| `agent/nobet_agent.py` | Linux ajanı (tek dosya): /proc ölçümleri, ARP keşfi, AF_PACKET ile SYN yakalama, auth.log/journald, servis kontrolleri, USB (sysfs) ve klasör izleme (inotify) |
| `agent/windows/nobet-agent.ps1` | Windows ajanı (PowerShell 5.1): CIM ölçümleri, komşu tablosu, Security olayları 5156/5157/5152 ve 4624/4625 |
| `agent/install.sh`, `agent/windows/install.ps1` | Kurulum betikleri (systemd servisi / SYSTEM zamanlanmış görevi) |
| `tests/test_nobet.py` | Uçtan uca + birim testleri |
| `tools/demo.py` | Paneli örnek veriyle doldurur (gerçek ölçüm değil) |

Tasarım kaynağı (koyu tema, renkler, yerleşim): https://claude.ai/artifact/DBEfrrDbDfsrtF9rqWN7X7

## Komutlar

- Test: `python3 -m unittest discover -s tests`
- Manager: `python3 -m manager --port 8080 --db data/nobet.db` (ilk çalıştırmada `admin` kullanıcısının parolası ekrana yazılır; `NOBET_ADMIN_PASSWORD` ile verilebilir; sıfırlama: `--set-password --user AD`)
- Linux ajanı deneme: `sudo python3 agent/nobet_agent.py --manager URL --token nbt_... --print`

## Kurallar ve tuzaklar

- Yalnızca standart kitaplık: Manager ve Linux ajanına üçüncü taraf paket ekleme.
- Ajan verisi güvenilmezdir: `core.py` içindeki `_s/_f/_i/_ip/_port/_mac` temizleyicilerinden geçmeden veritabanına yazma; arayüzde `h\`\`` dışında HTML birleştirme.
- `.ps1` dosyaları **yalnızca ASCII** olmalı (PowerShell 5.1 BOM'suz dosyayı ANSI okur) ve PS 5.1 sözdizimiyle yazılmalı (`?:`, `??`, `&&` yok).
- `conn_events.kind` değerleri `tcp | ssh_fail | ssh_ok`; son ikisi adı öyle kalsa da her türlü oturum açmayı (SSH, RDP, Windows ağ) taşır. Windows oturumlarında `port` NULL olabilir.
- Rapor sözleşmesi: `POST /api/agent/report`, `Authorization: Bearer <şirket anahtarı>`; alanlar için `tests/test_nobet.py` içindeki `report()` ve `test_windows_agent_report_shape` örnek alınır. İki ajan da aynı sözleşmeyi kullanır.
- Yetkilendirme: roller `admin | operator | viewer`. Panel sorgularının hepsi `App._scope(user, query, sütun)` üzerinden şirket kısıtı alır; yeni bir sorgu/uç nokta eklerken `user` parametresini geçirmeden veri döndürme. Tek kayıt üzerinde işlem yapan uç noktalar `owned(tablo, id)` ile kontrol edilir (yetkisizse 404). Yönetim uç noktaları `admin_only()` çağırır. Arayüzdeki gizleme (`canEdit()`, `isAdmin()`) yalnızca görünümdür; asıl kontrol sunucudadır.
- Şema değişikliği gerekirse `DB._migrate` içine ekle (mevcut veritabanları yerinde yükseltilir).
- Servis kontrolleri: tanımlar `checks` tablosunda, Manager bunları rapor **yanıtında** (`checks` alanı) ajana yollar, ajan sonuçları bir sonraki raporda (`checks` alanı) bildirir. `Engine._ingest_checks` yalnızca o sunucuya atanmış kontrollerin sonucunu kabul eder. Hedef biçimi `App._check_fields` içinde sıkı doğrulanır (ajanlar bu hedeflere bağlanır); ajan asla yanıt gövdesi göndermez. Yeni kontrol türü eklenirse üç yerde (Manager doğrulaması, Linux `run_check`, Windows `Invoke-ServiceCheck`) birlikte eklenmeli.
- İşlem günlüğü: paneldeki durum değiştiren her uç nokta `log(...)` (içeride `App.audit`) çağırmalı; yeni bir eylem eklenince `app.js` içindeki `AUDIT` etiket tablosuna da eklenir. Parola, anahtar, bot token'ı, webhook adresi gibi gizli değerler asla `detail` alanına yazılmaz (`App.SECRET_SETTINGS`). Günlüğü silen/değiştiren uç nokta eklenmez.
- Veri koruma: izlenen klasörler `watch_paths` tablosunda, tanımlar rapor yanıtında (`watch_paths`) ajana gider, olaylar raporun `dlp` alanında (`usb`, `files`, `watch_status`) gelir ve `dlp_events` tablosuna yazılır. `Engine._ingest_dlp` yalnızca o sunucuya atanmış izlemenin **altındaki** yolları kabul eder (`_under`). Sayfa ve API izleyici rolüne kapalıdır (çalışan etkinliği). Dosya içeriği hiçbir zaman okunmaz/gönderilmez; yalnızca ad ve işlem türü. Kayıtlar `dlp_retention_days` sonra silinir. Kullanıcı tam içerik denetimli DLP'yi kapsam dışı bıraktı; bu modül yalnızca izleme yapar, engelleme eklenmez.
- İki adımlı doğrulama: `manager/totp.py` (RFC 6238; test vektörleri testte). Giriş akışı `App.login(username, password, code, client)`: parola doğru ama kod yoksa `401 + totp_required` döner (hata sayılmaz). `require_2fa` ayarı açıkken kurulumu olmayan kullanıcı yalnızca `/api/me*` uç noktalarına erişir (`403 + setup_2fa`). Kurtarma kodları yalnızca SHA-256 özetiyle saklanır; TOTP gizli anahtarı hiçbir API yanıtında (kurulum anı dışında) veya günlükte yer almaz. Yeni bir kimlik doğrulama yolu eklenirse deneme sınırı (`_fails`, IP + hesap) ve işlem günlüğü kaydı da eklenmeli.
- QR kod: `manager/qr.py` standart kitaplıkla yazıldı (dış kitaplık eklenmez). `tests/test_nobet.py` içindeki `qr_decode` üretecin yardımcılarını kullanmayan bağımsız bir çözücüdür; üreteçte değişiklik yapılırsa `QrTest` geçmeli. En fazla 213 bayt taşır; adres uzarsa `totp_setup` boş `qr` döndürür ve anahtar elle girilir. QR, gizli anahtarı içerdiği için yalnızca kurulum yanıtında bulunur; hiçbir yere kaydedilmez veya günlüğe yazılmaz.
- Zaman damgası rapor Manager'a ulaştığında verilir; ajan saatine güvenilmez.
- Commit iletilerine ve depoya model adı yazma. Kullanıcı açıkça istemedikçe PR açma.

## Güncel durum (son güncelleme: 12.11.2026)

Çalışan ve doğrulanan:
- Manager + Linux ajanı uçtan uca çalıştı; 43 test geçiyor; panel başsız tarayıcıda tüm sayfalarıyla denendi.
- Linux'ta SYN yakalama, loopback'e enjekte edilen çerçevelerle doğrulandı (port taraması uyarısı üretti).
- Şirket bazlı kullanıcı/rol sistemi, servis sağlık kontrolleri, işlem günlüğü: test + tarayıcı.
- Veri koruma: Linux klasör izleme gerçek ajanla uçtan uca; USB algılama sahte sysfs ağacıyla.
- İki adımlı doğrulama: RFC 6238 test vektörleri, kurulum, kodla ve kurtarma koduyla giriş, tekrar kullanım engeli, deneme sınırı, zorunlu kurulum ve yönetici sıfırlaması testle; tüm akış tarayıcıda (kodlar Node ile üretilerek) doğrulandı. Gerçek bir telefon uygulamasıyla denenmedi.
- QR kod üreteci: Reed-Solomon, biçim ve sürüm bilgisi bilinen değerlerle; tüm sürüm (1-10) ve maskelerde bağımsız çözücüyle gidiş-dönüş; panelde görüntü olarak kontrol edildi. **Gerçek telefon kamerasıyla okutulmadı** (ortamda QR okuyucu yoktu, referans kitaplığı çalıştırma izni reddedildi).

Yazıldı ama doğrulanmadı:
- **Windows ajanı ve `install.ps1`/`uninstall.ps1` hiç çalıştırılmadı** (ortamda PowerShell yoktu; indirme izni reddedildi). Servis kontrolleri ve veri koruma (`Update-UsbDevices`, `Set-WatchedFolders`, `Read-FileAuditEvents`) dahil. Yalnızca gözle inceleme, ASCII ve ayraç dengesi kontrolü yapıldı. Belirsiz noktalar: 5156/5157/5152 olaylarında kaynak/hedef yönü, XPath filtresinin performansı, `ConvertTo-Json` dizi biçimi, `HttpWebRequest` hata sarmalama, `Add-Type` sertifika geri çağrısı, `Get-Acl -Audit`/`Set-Acl` ile SACL ekleme yetkisi, 4663 olay hacmi ve klasör listelemenin "okuma" sayılması.
- Gerçek USB aygıtı takılması; gerçek Telegram gönderimi; gerçek kimlik doğrulama uygulaması.
- `agent/install.sh`, systemd birimleri, `--trust-proxy` ve `--reset-2fa` gerçek ortamda denenmedi.

Bilinen eksikler / sıradaki adaylar:
1. Windows ajanını gerçek bir Windows Server'da `-Print` ile çalıştırıp hataları düzeltmek (en öncelikli; doğrulanmamış kod birikti).
2. Veri koruma devamı: Linux'ta kullanıcı kimliği (auditd), olağandışı büyük dışa veri aktarımı uyarısı, çalışan bilgisayarları için hafif ajan.
3. Bildirimlerin kullanıcı bazlı yönlendirilmesi; işlem günlüğünün dış sunucuya (syslog) aktarımı.
4. Servis kontrollerinde ek türler (ping, DNS, içerik eşleştirme), düzenleme formu, yanıt süresi grafiği.
5. UDP izleme, yönlendirici arkasındaki alt ağların keşfi (SNMP), MAC üretici adı; şirket silme, dışa aktarma, raporlar.

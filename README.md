# Nöbet — çok şirketli IT monitörleme

Her şirketin sunucusuna bir **Agent** kurulur; hepsi tek bir merkezi **Manager** paneline rapor gönderir.

```
XXXX LTD sunucusu ── Agent ─┐
                            ├─ HTTPS + şirket anahtarı ─▶ Manager (panel + API + SQLite) ─▶ Telegram / webhook
YYY LTD sunucusu  ── Agent ─┘
```

Bağlantıyı her zaman Agent başlatır; şirket ağlarında dışarıya port açmak gerekmez.
İki bileşen de yalnızca Python 3 standart kitaplığını kullanır (kurulacak paket yok).

## Neler yapar

| Alan | Ayrıntı |
| --- | --- |
| Sunucu sağlığı | CPU, bellek, disk bölümleri, ağ trafiği, çalışma süresi; 24 saatlik grafikler |
| Ağ cihazları | Agent yerel alt ağı tarar (ARP), ağdaki tüm cihazları IP/MAC/ad ile listeler; yeni cihaz bilgi uyarısı üretir; "İzle" denen cihaz kaybolursa kritik uyarı |
| Bağlantı analizi | Sunucuya gelen her TCP bağlantı denemesi (kapalı portlara gelenler dahil), başarılı/başarısız oturum açmalar (Linux: SSH, Windows: RDP ve ağ); kaynak, port, kullanıcı adı ve zaman dökümü |
| Saldırı tespiti | Port taraması (10 dk içinde 15+ farklı port) ve parola denemesi saldırısı (10 dk içinde 10+ başarısız giriş) kritik uyarı üretir |
| Servis sağlığı | Panelden tanımlanan TCP portu ve HTTP/HTTPS kontrolleri; yanıt süresi, 24 saatlik erişilebilirlik, sertifika bitiş süresi; art arda başarısız olan servis kritik uyarı üretir |
| Veri koruma | USB depolama takılması ve hassas klasörlerdeki dosya işlemleri (okuma, yazma, silme, taşıma); toplu silme ve toplu okuma uyarıları |
| Çok şirketli yönetim | Her şirketin kendi kodu ve ajan anahtarı vardır; panel tüm şirketleri birlikte veya tek tek gösterir |
| Acil durum çağrısı | Kritik uyarılar Telegram botuna (ve isteğe bağlı webhook'a) gider; onaylanana kadar 15 dakikada bir tekrarlanır; şirket başına ayrı sohbet seçilebilir |

Eşiklerin tamamı paneldeki **Ayarlar** sayfasından değiştirilir.

## Manager kurulumu (merkez sunucu)

```bash
python3 -m manager --port 8080 --db data/nobet.db
```

İlk çalıştırmada `admin` kullanıcısı oluşturulur ve parolası ekrana bir kez yazılır
(`NOBET_ADMIN_PASSWORD` ortam değişkeniyle kendiniz de verebilirsiniz). Unutulan bir parolayı
sunucudan sıfırlamak için:

```bash
python3 -m manager --db data/nobet.db --set-password --user admin
```

## Kullanıcılar ve roller

Panelde **Kullanıcılar** sayfasından (yalnızca yönetici) hesap açılır; her hesaba bir rol ve
erişebileceği şirketler atanır.

| Rol | Görebildiği | Yapabildiği |
| --- | --- | --- |
| Yönetici | Tüm şirketler | Her şey: şirket ve ajan anahtarı, kullanıcılar, bildirim ve eşik ayarları |
| Operatör | Atandığı şirketler (veya tümü) | Uyarı onaylama, cihazı izlemeye alma ve adlandırma |
| İzleyici | Atandığı şirketler (veya tümü) | Yalnızca görüntüleme |

Şirket kısıtı sunucu tarafında her sorguya uygulanır: kullanıcı, atanmadığı bir şirketin sunucusunu,
cihazını, uyarısını veya bağlantı kaydını adresini bilse bile göremez. Uyarıyı kimin onayladığı kaydedilir.
Herkes **Hesabım** sayfasından kendi parolasını değiştirebilir. Sistemde her zaman en az bir etkin yönetici kalır.
Eski (tek parolalı) bir veritabanı ilk açılışta otomatik taşınır: mevcut parola `admin` kullanıcısının parolası olur.

**TLS zorunlu sayılmalı:** ajan anahtarları ve panel oturumu bu bağlantıdan geçer. Ya `--cert`/`--key`
verin ya da Manager'ı `--host 127.0.0.1` ile çalıştırıp önüne TLS sonlandıran bir ters vekil
(Caddy, nginx) koyun. Kalıcı servis için `deploy/nobet-manager.service` örneğine bakın.

## Şirket ve Agent ekleme

1. Panelde **Ayarlar → Şirket ekle** (ör. kod `XXXX`, ad `XXXX LTD Şirketi`). Ajan anahtarı yalnızca bir kez gösterilir.
2. `agent/` klasörünü şirket sunucusuna kopyalayın ve çalıştırın:

```bash
sudo ./agent/install.sh https://panel.example.com nbt_ANAHTAR
```

Betik ajanı `/opt/nobet` altına kurar, ayarı `/etc/nobet/agent.json` dosyasına (yalnızca root okur)
yazar ve `nobet-agent` systemd servisini başlatır. Kurmadan denemek için:

```bash
sudo python3 agent/nobet_agent.py --manager https://panel.example.com --token nbt_ANAHTAR --print
```

`agent.json` seçenekleri: `interval` (rapor aralığı, sn), `scan_interval` (ağ taraması aralığı, sn),
`subnets` (taranacak alt ağlar; boşsa otomatik), `capture` / `discovery` (`false` ile kapatılır),
`ca_file` (özel CA sertifikası).

### Windows sunucu

`agent/windows/` klasörünü sunucuya kopyalayın ve **yönetici** PowerShell'den çalıştırın
(Windows Server 2016+; ek kurulum gerekmez, Windows PowerShell 5.1 yeterlidir):

```powershell
.\install.ps1 -Manager https://panel.example.com -Token nbt_ANAHTAR -EnableConnectionAudit
```

Betik ajanı `C:\Program Files\Nobet` altına kopyalar, ayarı `C:\ProgramData\Nobet\agent.json`
dosyasına yazar (yalnızca SYSTEM ve Administrators okur) ve açılışta SYSTEM olarak çalışan
`NobetAgent` zamanlanmış görevini başlatır. Günlük: `C:\ProgramData\Nobet\agent.log`.

`-EnableConnectionAudit`, izin verilen **ve engellenen** tüm bağlantı denemelerinin görülebilmesi için
Windows güvenlik duvarı denetim kayıtlarını (5156/5157/5152) açar. Bu, Security günlüğüne çok sayıda
kayıt yazar; günlük boyutunu buna göre ayarlayın. Anahtar verilmezse ajan yalnızca kurulan
bağlantıları görür. Oturum açma denemeleri (RDP ve ağ; olay 4625/4624) her iki durumda da izlenir.

Kurmadan denemek için: `.\nobet-agent.ps1 -Manager https://... -Token nbt_... -Print`.
Kaldırmak için: `.\uninstall.ps1`.

## İki adımlı doğrulama

Her kullanıcı **Hesabım** sayfasından iki adımlı doğrulamayı açabilir: ekrandaki QR kod telefondaki bir kimlik
doğrulama uygulamasıyla (Google Authenticator, Microsoft Authenticator, Authy) okutulur, sonraki girişlerde
paroladan sonra uygulamanın gösterdiği 6 haneli kod istenir.

- Kurulum sonunda 8 **kurtarma kodu** bir kez gösterilir; telefon yokken her biri bir kez kullanılabilir.
- **Ayarlar → Oturum güvenliği** altındaki seçenekle tüm kullanıcılar için zorunlu tutulabilir; kurmayan
  kullanıcı kurana kadar yalnızca kendi hesap sayfasını görür.
- Telefonunu kaybeden kullanıcı için yönetici **Kullanıcılar** sayfasından "İki adımı sıfırla" der. Tek yönetici
  kilitlenirse sunucudan: `python3 -m manager --db data/nobet.db --reset-2fa --user admin`
- Hatalı kod denemeleri hesap ve IP başına dakikada 5 ile sınırlıdır; kullanılan kod tekrar kullanılamaz.
- QR kod okutulamazsa aynı ekrandaki kurulum anahtarı elle girilebilir; paneli telefonda açan kullanıcı
  "Bu cihazdaki uygulamada aç" bağlantısını kullanabilir. QR kod sunucuda üretilir, dış servise gönderilmez.

## Veri koruma (veri sızıntısı izleme)

**Veri Koruma** sayfası (yönetici ve operatör; izleyici göremez) iki şeyi izler:

- **USB depolama:** ajan kurulu sunucuya USB bellek/disk takılınca ve çıkarılınca kayıt düşer (model, seri no,
  kapasite) ve uyarı üretilir.
- **Hassas klasörler:** panelden klasör yolu ve sunucu seçilir; o klasördeki (alt klasörler dahil) okuma, yazma,
  oluşturma, silme ve taşıma işlemleri kaydedilir. 10 dakikada 50+ silme kritik, 500+ okuma uyarı üretir.

Yalnızca dosya adı ve işlem türü kaydedilir; **dosya içeriği okunmaz ve hiçbir işlem engellenmez**. Bu bir izleme
aracıdır, içerik denetimi yapan tam bir DLP değildir.

| | Linux ajanı | Windows ajanı |
| --- | --- | --- |
| USB algılama | `/sys/block` | `Win32_DiskDrive` |
| Klasör izleme | inotify | Security olayı 4663 (klasöre denetim kuralı eklenir) |
| İşlemi yapan kullanıcı | **Bilinmez** | Bilinir (`ETKİALANI\kullanıcı`) |
| Ön koşul | Yok | Kurulumda `-EnableFileAudit` |

Windows'ta klasör izleme için ajanı `-EnableFileAudit` ile kurun; bu, "File System" denetim ilkesini açar ve
ajanın izlenen klasörlere denetim kuralı (SACL) eklemesine izin verir. Bir sunucuda bu modülü tümüyle kapatmak
için `agent.json` içine `"dlp": false` yazın. Sistem klasörleri ve sürücü kökleri izlemeye alınamaz.

**Hukuki not:** Bu modül çalışanların dosya ve cihaz kullanımını kaydeder. İzlemeye başlamadan önce ilgili şirkette
çalışanların bilgilendirilmesi ve hukuki dayanağın belirlenmesi gerekir (KVKK); bir hukukçuya danışın. Kayıtlar
varsayılan olarak 30 gün sonra silinir (Ayarlar → Veri koruma).

## İşlem günlüğü

**İşlem Günlüğü** sayfası (yalnızca yönetici) panelde yapılan her işlemi gösterir: kim, ne zaman, hangi IP'den,
hangi şirkette ne yaptı. Kaydedilenler: giriş/çıkış ve başarısız girişler, parola değişiklikleri, uyarı onayları,
cihaz izleme/adlandırma, servis kontrolü ekleme/değiştirme/silme, kullanıcı ve şirket işlemleri, ajan anahtarı
yenileme, ayar değişiklikleri (eski → yeni değer) ve test bildirimleri.

- Kayıtlar panelden değiştirilemez ve silinemez; bir yıl saklanır.
- Parolalar, ajan anahtarları, Telegram bot anahtarı ve webhook adresi günlüğe yazılmaz (yalnızca "değiştirildi").
- Manager ters vekil arkasındaysa gerçek istemci adresinin kaydedilmesi için `--trust-proxy` ile çalıştırın;
  vekil yoksa bu seçeneği **kullanmayın** (başlık sahte olabilir).

## Servis sağlık kontrolleri

**Servisler** sayfasından (yönetici ve operatör) kontrol eklenir: ad, tür (HTTP/HTTPS adresi veya TCP portu),
hedef ve kontrolü çalıştıracak sunucu. Kontrolü o sunucudaki ajan **kendi ağının içinden** çalıştırır; bu sayede
dışarıya açık olmayan iç servisler (ERP, veritabanı, dosya sunucusu) de izlenir. Tanımlar ajana rapor yanıtıyla
gider, ayrıca ajan tarafında ayar gerekmez.

- Bir kontrol art arda 2 kez başarısız olursa kritik uyarı çıkar (Telegram'a gider); düzelince kapanır.
- HTTPS kontrollerinde sertifikanın kalan süresi izlenir: 14 gün kala uyarı, 3 gün kala kritik.
- "Yavaş eşiği" verilirse eşiği aşan yanıtlar panelde "Yavaş" görünür (uyarı üretmez).
- HTTP'de varsayılan başarı ölçütü 200–399 kodlarıdır; yönlendirmeler izlenmez.
- Ajan panele yalnızca durum, HTTP kodu ve yanıt süresini bildirir; yanıt içeriği gönderilmez.
- Bir sunucuda kontrolleri tümüyle kapatmak için `agent.json` içine `"checks": false` yazın.

Eşikler **Ayarlar → Uyarı eşikleri** bölümündedir.

## Telegram

1. Telegram'da @BotFather ile bot oluşturup anahtarını alın.
2. Botu acil durum grubuna ekleyin ve grubun sohbet kimliğini öğrenin.
3. **Ayarlar → Acil durum bildirimleri** bölümüne ikisini girin, **Test bildirimi gönder** ile doğrulayın.

Telegram botları sesli arama yapamaz; telefonla arama gerekiyorsa webhook alanına bir çağrı
servisinin (ör. Opsgenie, PagerDuty, Twilio köprüsü) adresini girin. Webhook'a uyarı JSON olarak gönderilir.

## Geliştirme

```bash
python3 -m unittest discover -s tests
```

Paneli örnek veriyle görmek için (gerçek ölçüm değildir, üretimde çalıştırmayın):

```bash
python3 tools/demo.py http://127.0.0.1:8080 nbt_ANAHTAR
```

## Bilinen sınırlar

- **Windows ajanı (`agent/windows/`) henüz hiçbir Windows makinesinde çalıştırılmadı**; geliştirme
  ortamında PowerShell yoktu. Üretime almadan önce bir test sunucusunda `-Print` ile deneyin.
  Manager'ın Windows biçimli raporu işlediği otomatik testle doğrulandı.
- Linux ajanı `/proc` ve ham soket kullanır; Windows ajanı CIM, komşu tablosu ve Security günlüğünü kullanır.
- Veri koruma: Linux'ta dosya işlemini yapan kullanıcı bilinmez; USB algılama yalnızca ajan kurulu makineleri
  kapsar (çalışan bilgisayarları için o bilgisayarlara da ajan kurmak gerekir); kopyalanan içerik izlenmez.
- Servis kontrolleri TCP ve HTTP/HTTPS ile sınırlıdır (ping, DNS, içerik eşleştirme yok); kontroller ajanın
  rapor aralığında (varsayılan 30 sn) bir kez çalışır.
- Bağlantı yakalama TCP içindir ve root gerektirir. Root yoksa ajan yalnızca kabul edilen
  bağlantıları görür; panel bunu sunucu sayfasında belirtir. UDP izlenmez.
- Ağ keşfi ajanın bulunduğu alt ağla sınırlıdır (en fazla /22); yönlendirici arkasındaki ağlar görülmez.
- İki adımlı doğrulamada gizli anahtarlar veritabanında şifrelenmeden durur, bu yüzden veritabanı dosyasına erişim
  korunmalıdır. Donanım anahtarı (WebAuthn) desteklenmez. QR kod üreteci testlerle doğrulandı ama gerçek bir
  telefon kamerasıyla henüz okutulmadı.
- İşlem günlüğü panel işlemlerini kapsar; veritabanı dosyasına doğrudan erişen biri kayıtları değiştirebilir
  (dış bir günlük sunucusuna aktarım yok).
- Systemd servis dosyaları ve `install.sh` gerçek bir sunucuda henüz denenmedi.
- Veriler SQLite'ta tutulur: ölçümler 7 gün, bağlantı kayıtları ve çözülen uyarılar 30 gün saklanır.

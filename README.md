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
| Bağlantı analizi | Sunucuya gelen her TCP bağlantı denemesi (kapalı portlara gelenler dahil), SSH başarılı/başarısız girişler; kaynak, port, kullanıcı adı ve zaman dökümü |
| Saldırı tespiti | Port taraması (10 dk içinde 15+ farklı port) ve SSH parola denemesi (10 dk içinde 10+ hata) kritik uyarı üretir |
| Çok şirketli yönetim | Her şirketin kendi kodu ve ajan anahtarı vardır; panel tüm şirketleri birlikte veya tek tek gösterir |
| Acil durum çağrısı | Kritik uyarılar Telegram botuna (ve isteğe bağlı webhook'a) gider; onaylanana kadar 15 dakikada bir tekrarlanır; şirket başına ayrı sohbet seçilebilir |

Eşiklerin tamamı paneldeki **Ayarlar** sayfasından değiştirilir.

## Manager kurulumu (merkez sunucu)

```bash
python3 -m manager --port 8080 --db data/nobet.db
```

İlk çalıştırmada yönetici parolası üretilip ekrana bir kez yazılır (`NOBET_ADMIN_PASSWORD` ortam
değişkeniyle kendiniz de verebilirsiniz). Değiştirmek için:

```bash
python3 -m manager --db data/nobet.db --set-password
```

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

- Agent yalnızca Linux'ta çalışır (`/proc` ve ham soket kullanır); Windows ajanı yok.
- Bağlantı yakalama TCP içindir ve root gerektirir. Root yoksa ajan yalnızca kabul edilen
  bağlantıları görür; panel bunu sunucu sayfasında belirtir. UDP izlenmez.
- Ağ keşfi ajanın bulunduğu alt ağla sınırlıdır (en fazla /22); yönlendirici arkasındaki ağlar görülmez.
- Panelde tek yönetici hesabı vardır; şirket bazlı kullanıcı/rol ayrımı yok.
- Systemd servis dosyaları ve `install.sh` gerçek bir sunucuda henüz denenmedi.
- Veriler SQLite'ta tutulur: ölçümler 7 gün, bağlantı kayıtları ve çözülen uyarılar 30 gün saklanır.

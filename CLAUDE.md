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
Ürün adı (geçici): "Nöbet". Depo: `sad0094/repoclaude`, çalışma dalı `claude/adoring-hawking-c6u5l0`.

## Yapı

| Yol | İçerik |
| --- | --- |
| `manager/db.py` | SQLite şeması, tek-yazar işlem kilidi, ayar varsayılanları, şirket/anahtar işlemleri |
| `manager/core.py` | `Engine`: rapor işleme (`ingest`), uyarı kuralları, periyodik `tick` (çevrimdışı, tekrar bildirimi, temizlik) |
| `manager/notify.py` | Telegram + webhook gönderimi (arka plan kuyruğu) |
| `manager/web.py` | HTTP sunucusu, oturum, panel API'si, statik dosyalar |
| `manager/static/` | Tek sayfalık panel (bağımlılıksız JS; `h\`\`` şablonu her değeri kaçışlar) |
| `agent/nobet_agent.py` | Linux ajanı (tek dosya): /proc ölçümleri, ARP keşfi, AF_PACKET ile SYN yakalama, auth.log/journald |
| `agent/windows/nobet-agent.ps1` | Windows ajanı (PowerShell 5.1): CIM ölçümleri, komşu tablosu, Security olayları 5156/5157/5152 ve 4624/4625 |
| `agent/install.sh`, `agent/windows/install.ps1` | Kurulum betikleri (systemd servisi / SYSTEM zamanlanmış görevi) |
| `tests/test_nobet.py` | Uçtan uca + birim testleri |
| `tools/demo.py` | Paneli örnek veriyle doldurur (gerçek ölçüm değil) |

Tasarım kaynağı (koyu tema, renkler, yerleşim): https://claude.ai/artifact/DBEfrrDbDfsrtF9rqWN7X7

## Komutlar

- Test: `python3 -m unittest discover -s tests`
- Manager: `python3 -m manager --port 8080 --db data/nobet.db` (ilk çalıştırmada parola ekrana yazılır; `NOBET_ADMIN_PASSWORD` ile verilebilir)
- Linux ajanı deneme: `sudo python3 agent/nobet_agent.py --manager URL --token nbt_... --print`

## Kurallar ve tuzaklar

- Yalnızca standart kitaplık: Manager ve Linux ajanına üçüncü taraf paket ekleme.
- Ajan verisi güvenilmezdir: `core.py` içindeki `_s/_f/_i/_ip/_port/_mac` temizleyicilerinden geçmeden veritabanına yazma; arayüzde `h\`\`` dışında HTML birleştirme.
- `.ps1` dosyaları **yalnızca ASCII** olmalı (PowerShell 5.1 BOM'suz dosyayı ANSI okur) ve PS 5.1 sözdizimiyle yazılmalı (`?:`, `??`, `&&` yok).
- `conn_events.kind` değerleri `tcp | ssh_fail | ssh_ok`; son ikisi adı öyle kalsa da her türlü oturum açmayı (SSH, RDP, Windows ağ) taşır. Windows oturumlarında `port` NULL olabilir.
- Rapor sözleşmesi: `POST /api/agent/report`, `Authorization: Bearer <şirket anahtarı>`; alanlar için `tests/test_nobet.py` içindeki `report()` ve `test_windows_agent_report_shape` örnek alınır. İki ajan da aynı sözleşmeyi kullanır.
- Zaman damgası rapor Manager'a ulaştığında verilir; ajan saatine güvenilmez.
- Commit iletilerine ve depoya model adı yazma. Kullanıcı açıkça istemedikçe PR açma.

## Güncel durum (son güncelleme: 11.11.2026)

Çalışan ve doğrulanan:
- Manager + Linux ajanı uçtan uca çalıştı; 20 test geçiyor; panel başsız tarayıcıda tüm sayfalarıyla denendi.
- Linux'ta SYN yakalama, loopback'e enjekte edilen çerçevelerle doğrulandı (port taraması uyarısı üretti).

Yazıldı ama doğrulanmadı:
- **Windows ajanı ve `install.ps1`/`uninstall.ps1` hiç çalıştırılmadı** (ortamda PowerShell yoktu; indirme izni reddedildi). Yalnızca gözle inceleme, ASCII ve ayraç dengesi kontrolü yapıldı. Belirsiz noktalar: 5156/5157/5152 olaylarında kaynak/hedef yönü (kod iki yönü de yerel adres karşılaştırmasıyla çözüyor), XPath filtresinin performansı, `ConvertTo-Json` dizi biçimi.
- Gerçek Telegram gönderimi (yalnızca sahte sunucuya karşı test edildi).
- `agent/install.sh` ve systemd birimleri gerçek sunucuda denenmedi.

Bilinen eksikler / sıradaki adaylar:
1. Windows ajanını gerçek bir Windows Server'da `-Print` ile çalıştırıp hataları düzeltmek (en öncelikli).
2. Şirket bazlı kullanıcı/rol (şu an tek yönetici hesabı).
3. Sunucu servis/port sağlık kontrolleri (HTTP, TCP, sertifika süresi) — tasarımdaki "Servis durumu" bölümü henüz yok.
4. UDP izleme, yönlendirici arkasındaki alt ağların keşfi (SNMP), MAC üretici adı.
5. Şirket silme ve veri dışa aktarma; raporlar sayfası.

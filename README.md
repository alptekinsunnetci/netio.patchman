# netio.patchman

**Merkezi Linux Güvenlik Açığı ve Güncelleme Yönetimi**

netio.patchman, yüzlerce Linux sunucunun güvenlik açıklarını ve paket güncellemelerini tek bir panelden izlemenizi ve yönetmenizi sağlayan, kendi altyapınızda çalışan (self-hosted) bir platformdur.

- Merkezi sunucu tek bir Docker konteyneridir. Gömülü SQLite veritabanı kullanır; ayrı bir veritabanı, kuyruk ya da önbellek servisi gerekmez.
- Yönetilen her sunucuya küçük bir ajan kurulur. Ajan port açmaz; merkezi sunucuya kendisi bağlanır.
- Arayüz, e-postalar ve belgeler Türkçedir. CVE verileri kaynağındaki haliyle, çevrilmeden gösterilir.

## İçindekiler

- [Özellikler](#özellikler)
- [Nasıl çalışır](#nasıl-çalışır)
- [Kurulum (Docker)](#kurulum-docker)
- [Sunuculara ajan kurulumu](#sunuculara-ajan-kurulumu)
- [Güncelleme, yedekleme ve kaldırma](#güncelleme-yedekleme-ve-kaldırma)
- [Yapılandırma](#yapılandırma)
- [Sorun giderme](#sorun-giderme)
- [Güvenlik](#güvenlik)
- [Geliştirme](#geliştirme)

## Özellikler

- **Sunucu envanteri:** İşletim sistemi, çekirdek, IP adresleri, kurulu paketler, bekleyen güncellemeler ve yeniden başlatma ihtiyacı.
- **Güvenlik açığı taraması:** Kurulu paket sürümleri [OSV.dev](https://osv.dev) üzerinden dağıtımların resmî güvenlik verileriyle eşleştirilir. CVSS puanı, önem derecesi, düzeltilmiş sürüm ve üretici güvenlik duyuruları gösterilir.
- **Aktif istismar bilgisi:** CISA Known Exploited Vulnerabilities (KEV) kataloğundaki açıklar ayrıca işaretlenir ve önceliklendirilir.
- **Merkezi güncelleme:** Panelden tek bir sunucuda, seçilen sunucularda veya tümünde güvenlik güncellemeleri, tüm güncellemeler ya da seçili paketler kurulabilir. Bir CVE için **Düzeltmeyi uygula** ile etkilenen tüm sunucularda ilgili paketler güncellenir.
- **Zamanlanmış güncellemeler:** "Her pazar 03:00'te Ubuntu sunucularında güvenlik güncellemelerini uygula" gibi bakım pencereleri. Sunucular hiçbir zaman kendiliğinden yeniden başlatılmaz.
- **Otomatik ajan güncellemesi:** Merkezi sunucu yeni sürüme geçince ajanlar yeni sürümü indirir, SHA-256 özetini doğrular ve kendini günceller.
- **Bulgu yönetimi:** Açık, İşlemde, Risk Kabul Edildi, Hatalı Tespit durumları. Paket güncellenince bulgu otomatik olarak "Çözüldü" olur.
- **Bildirimler:** Bildirim merkezi ve Türkçe e-posta bildirimleri: yeni açıklar, bağlantısı kesilen ajanlar, başarısız güncelleme işleri.
- **Kullanıcılar ve yetkiler:** Yönetici, Operatör ve İzleyici rolleri; denetim kayıtları.
- **Paneldense yapılandırma:** SMTP, sunucu adresi, saat dilimi, veri kaynakları ve tüm işletim ayarları panelden değiştirilir. Değişiklikler yeniden başlatma gerektirmez.
- **Dışa aktarma:** Sunucu ve güvenlik açığı listeleri Excel uyumlu CSV olarak indirilebilir.

### Desteklenen dağıtımlar

| Dağıtım | Envanter ve güncelleme | Güvenlik açığı taraması |
|---|---|---|
| Debian, Ubuntu | apt | ✓ |
| AlmaLinux, Rocky Linux, Red Hat Enterprise Linux | dnf / yum | ✓ |
| SUSE Linux Enterprise, openSUSE Leap | zypper | ✓ |
| Alpine Linux | apk | ✓ |
| Diğer dağıtımlar (dnf, yum, zypper, apt veya apk kullanan) | ✓ | — |

Ajan amd64 ve arm64 mimarilerinde çalışır. Kurulum betiği systemd gerektirir.

## Nasıl çalışır

```
 Yönetilen sunucular                     Merkezi sunucu (Docker)                 Dış kaynaklar
┌──────────────────────┐   HTTPS   ┌──────────────────────────────┐   HTTPS   ┌──────────────┐
│ netio-patchman-agent │ ────────▶ │ netio.patchman               │ ────────▶ │ api.osv.dev  │
│  envanter, işler     │  (giden)  │  panel + API + SQLite        │           │ CISA KEV     │
└──────────────────────┘           └──────────────────────────────┘           └──────────────┘
                                                 ▲
                                    Tarayıcı ────┘  (yönetim paneli)
```

1. Ajan, belirli aralıklarla merkezi sunucuya bağlanır. Kurulu paketleri ve bekleyen güncellemeleri bildirir, sırada bir iş varsa alır.
2. Merkezi sunucu paket sürümlerini OSV.dev'deki dağıtım güvenlik verileriyle eşleştirir ve bulguları panelde gösterir.
3. Paneldeki güncelleme işleri ajanın bir sonraki bağlantısında ajana iletilir. Ajan işi sabit paket yöneticisi komutlarıyla çalıştırır ve sonucu bildirir.

Yönetilen sunucularda gelen bağlantı için port açmanız gerekmez.

## Kurulum (Docker)

### Gereksinimler

- Docker Engine 24 veya üzeri ve Docker Compose v2.24 veya üzeri yüklü bir Linux sunucu.
- `git`.
- **İnternet erişimi:** İlk derlemede Docker imajları ve Go modülleri indirilir. Güvenlik açığı verileri için de `api.osv.dev` ve `www.cisa.gov` adreslerine HTTPS erişimi gerekir. İnternet erişimi olmayan ortamlar için bkz. [docs/kurulum.md](docs/kurulum.md#8-internet-erişimi-olmayan-ortamlar).
- **Önerilen kaynaklar:** 100 sunucuya kadar 1 çekirdek, 1 GB bellek ve 5 GB disk.

Docker yüklü değilse, Docker'ın resmî betiğiyle kurabilirsiniz:

```sh
curl -fsSL https://get.docker.com | sudo sh
```

### 1. Depoyu indirin

```sh
git clone https://github.com/alptekinsunnetci/netio.patchman.git
cd netio.patchman
```

### 2. (İsteğe bağlı) Sunucu adresini belirleyin

Ajanların ve kullanıcıların merkezi sunucuya ulaşacağı adresi `.env` dosyasına yazabilirsiniz:

```sh
cp .env.example .env
nano .env        # PATCHMAN_BASE_URL=https://patchman.your-domain
```

Bu adımı atlarsanız adres `http://localhost:8080` olarak başlar. Kurulumdan sonra panelde **Sistem Ayarları → Sunucu yapılandırması** sayfasından değiştirebilirsiniz. Ajanları kurmadan önce adresin doğru olduğundan emin olun, çünkü kurulum komutu bu adresi kullanır.

### 3. Başlatın

```sh
docker compose up -d --build
```

İlk derleme internet hızına bağlı olarak birkaç dakika sürer. Durumu kontrol edin:

```sh
docker compose ps                 # STATUS sütununda "healthy" görünmeli
docker compose logs -f server     # günlük kayıtları (çıkmak için Ctrl+C)
```

### 4. İlk yönetici hesabını oluşturun

Tarayıcıda `http://<sunucu-adresi>:8080` adresini açın. Veritabanı boş olduğu için **İlk Kurulum** sayfası açılır. Burada yönetici hesabını oluşturun. Bu sayfa yalnızca hiç kullanıcı yokken açılır.

### 5. Temel ayarları yapın

Panelde **Sistem Ayarları → Sunucu yapılandırması** sayfasında:

- **Sunucu adresi:** Ajanların erişeceği dış adres, örneğin `https://patchman.your-domain`.
- **E-posta sunucusu (SMTP):** E-posta bildirimleri için. Aynı sayfadan deneme e-postası gönderebilirsiniz.

Kurulum tamamlandı. Sıradaki adım sunuculara ajan kurmak.

### HTTPS

Ajanlar ve tarayıcılar sunucuya HTTPS ile bağlanmalıdır. Önerilen yöntem, sunucuyu nginx, Caddy veya HAProxy gibi bir ters vekilin arkasına koymaktır. Bu durumda panelde **Ters vekil başlıklarına güven** seçeneğini açın. Örnek yapılandırmalar ve sunucunun TLS'i kendisinin sonlandırması için bkz. [docs/kurulum.md](docs/kurulum.md#3-tls-ve-ters-vekil).

Yayınlanan portu değiştirmek için `.env` dosyasına `PATCHMAN_PUBLISH_PORT=9090` yazın ve `docker compose up -d` komutunu yeniden çalıştırın.

## Sunuculara ajan kurulumu

1. Panelde **Ajan Yönetimi** sayfasından bir **kayıt anahtarı** oluşturun. Anahtar yalnızca bir kez gösterilir. Süre ve kullanım sınırı verebilirsiniz.
2. Sayfada gösterilen komutu yönetilecek her sunucuda root olarak çalıştırın:

   ```sh
   curl -fsSL https://patchman.your-domain/downloads/install-agent.sh | \
     sudo sh -s -- --server-url https://patchman.your-domain --token <KAYIT-ANAHTARI>
   ```

3. Sunucu birkaç saniye içinde **Sunucu Envanteri** sayfasında görünür ve ilk güvenlik taraması otomatik olarak başlar.

Kurulum betiği şunları yapar:

- Ajanı `/usr/local/bin/netio-patchman-agent` konumuna kurar.
- Yapılandırmayı `/etc/netio-patchman/agent.env` dosyasına yazar.
- `netio-patchman-agent.service` systemd hizmetini başlatır.

Ajanın durumunu ve kayıtlarını şu komutlarla görebilirsiniz:

```sh
systemctl status netio-patchman-agent
journalctl -u netio-patchman-agent -f
```

Toplu dağıtım (Ansible vb.), çevrimdışı kurulum, ajan seçenekleri ve kaldırma adımları için bkz. [docs/kurulum.md](docs/kurulum.md#4-ajan-kurulumu).

## Güncelleme, yedekleme ve kaldırma

### Yeni sürüme geçme

```sh
cd netio.patchman
git pull
docker compose up -d --build
```

- Veritabanı şeması açılışta otomatik olarak güncellenir; yine de öncesinde yedek alın.
- Sürüm, depodaki `VERSION` dosyasından okunur.
- **Sistem Ayarları → Ajanlar → Ajanları otomatik olarak güncelle** seçeneği açıksa (varsayılan) ajanlar yeni sürüme kendiliğinden geçer.

### Yedekleme ve geri yükleme

Sunucu çalışırken tutarlı bir yedek alabilirsiniz:

```sh
docker compose exec server netio-patchman-server backup -out /data/yedek.db
docker compose cp server:/data/yedek.db ./yedek-$(date +%Y%m%d).db
```

Yedekten geri yükleme:

```sh
docker compose stop server
docker compose cp ./yedek-20261120.db server:/data/netio-patchman.db
docker compose start server
```

Veritabanı, `netio-patchman-data` adlı Docker biriminde (`/data/netio-patchman.db`) tutulur. Yedeklerde SMTP parolası da bulunur; yedekleri buna göre koruyun.

### Yönetici parolasını sıfırlama

```sh
docker compose exec server netio-patchman-server reset-password -email yonetici@your-domain
```

Komut yeni bir parola üretip ekrana yazar.

### Kaldırma veya sıfırdan başlama

```sh
docker compose down        # konteyneri durdurur, veriler korunur
docker compose down -v     # konteyneri ve veritabanını siler (geri alınamaz)
```

`down -v` sonrasında `docker compose up -d` ile sistem boş bir veritabanıyla, **İlk Kurulum** adımından başlar.

## Yapılandırma

Yapılandırmanın tamamı yönetim panelinden yapılabilir:

- **Sistem Ayarları:** Bildirim eşikleri ve alıcıları, ajan bağlantı aralıkları, otomatik ajan güncellemesi, tarama ve kayıt saklama süresi.
- **Sistem Ayarları → Sunucu yapılandırması:** Sunucu adresi, ters vekil, saat dilimi, günlük seviyesi, SMTP ve veri kaynakları (OSV, CISA KEV).

`.env` dosyasındaki `PATCHMAN_` önekli değişkenler yalnızca ilk değerleri verir; panelde kaydedilen değer bunların yerine geçer. Aşağıdaki tabloda "Panelden" sütununda "—" ile işaretli değerler sunucu başlarken gerektiği için yalnızca `.env` ile değiştirilebilir ve yeniden başlatma gerektirir. Tüm seçenekler açıklamalarıyla [.env.example](.env.example) dosyasındadır.

| Değişken | Varsayılan | Açıklama | Panelden |
|---|---|---|---|
| `PATCHMAN_BASE_URL` | `http://localhost:8080` | Panelin ve ajanların kullandığı dış adres | evet |
| `PATCHMAN_PUBLISH_PORT` | `8080` | Docker'ın sunucuda yayınladığı port | — |
| `PATCHMAN_HTTP_ADDR` | `:8080` | Konteyner içindeki HTTP dinleme adresi | — |
| `PATCHMAN_TRUST_PROXY` | `false` | Ters vekil arkasında istemci IP'sini `X-Forwarded-For` başlığından al | evet |
| `PATCHMAN_TLS_CERT_FILE`, `PATCHMAN_TLS_KEY_FILE` | — | Sunucunun TLS'i kendisinin sonlandırması için sertifika ve anahtar | — |
| `PATCHMAN_TIMEZONE` | `Europe/Istanbul` | Tarih ve saatlerin gösterildiği saat dilimi | evet |
| `PATCHMAN_LOCALE` | `tr-TR` | Arayüz dili | — |
| `PATCHMAN_OSV_URL` | `https://api.osv.dev` | OSV API adresi (iç ağ yansısı kullanılabilir) | evet |
| `PATCHMAN_KEV_URL` | CISA KEV adresi | KEV kataloğu adresi; `off` ile kapatılır | evet |
| `PATCHMAN_SMTP_HOST`, `PATCHMAN_SMTP_PORT` | —, `587` | E-posta sunucusu | evet |
| `PATCHMAN_SMTP_USERNAME`, `PATCHMAN_SMTP_PASSWORD` | — | SMTP kimlik bilgileri | evet |
| `PATCHMAN_SMTP_FROM_NAME`, `PATCHMAN_SMTP_FROM_ADDRESS` | `netio.patchman`, — | Gönderen adı ve adresi | evet |
| `PATCHMAN_LOG_LEVEL`, `PATCHMAN_LOG_FORMAT` | `info`, `json` | Günlük seviyesi ve biçimi | seviye: evet, biçim: — |
| `PATCHMAN_VERSION` | `VERSION` dosyası | Derlenen sunucu ve ajan sürümü | — |

Ortam değişkenlerinde hatalı bir değer varsa sunucu başlamaz ve hataları Türkçe olarak listeler.

## Sorun giderme

| Belirti | Kontrol |
|---|---|
| Panel açılmıyor | `docker compose ps` ve `docker compose logs server`. Güvenlik duvarında 8080 (veya `PATCHMAN_PUBLISH_PORT`) portu açık mı? |
| Kurulum komutu `localhost` adresini gösteriyor | **Sunucu yapılandırması** sayfasında sunucu adresini ajanların erişebileceği adresle değiştirin. |
| Ajan kaydolmuyor | Ajanın bulunduğu sunucudan `curl -I https://patchman.your-domain/healthz` çalışıyor mu? `journalctl -u netio-patchman-agent -n 50` |
| Açık taraması sonuç vermiyor | Merkezi sunucunun `api.osv.dev` adresine erişimi var mı? Günlüklerde OSV hatası arayın. |
| E-posta gelmiyor | **Sunucu yapılandırması** sayfasından deneme e-postası gönderin; hata mesajı panelde gösterilir. |

Ayrıntılı bilgi: [docs/kurulum.md](docs/kurulum.md) (kurulum ve işletim), [docs/kullanim.md](docs/kullanim.md) (panel kullanımı).

## Dil ve yerelleştirme

- Varsayılan dil Türkçedir (`tr-TR`).
- **Güvenlik açığı verileri çevrilmez.** CVE numaraları, resmî başlıklar, açıklamalar, CVSS değerleri, paket adları ve üretici duyuruları kaynağında yayımlandığı haliyle gösterilir.
- Zaman bilgileri UTC olarak saklanır ve seçilen saat diliminde (varsayılan `Europe/Istanbul`) gösterilir.
- Arayüz metinleri `internal/i18n/locales/` altındadır. Yeni bir dil, aynı anahtarlarla yeni bir dosya eklenerek desteklenir.

## Güvenlik

- Parolalar PBKDF2-SHA256 (600.000 tekrar) ile saklanır. Oturum, kayıt anahtarı ve ajan kimlikleri veritabanında yalnızca SHA-256 özeti olarak tutulur.
- Tüm form işlemleri CSRF korumalıdır. Başarısız girişler IP ve hesap bazında sınırlandırılır.
- Ajan port açmaz ve dışarıdan bağlantı kabul etmez. Yalnızca önceden tanımlı paket yöneticisi komutlarını, kabuk kullanmadan çalıştırır; paket adları her iki tarafta doğrulanır.
- Bir sunucuda uzaktan güncellemeyi tamamen kapatmak için o sunucunun `/etc/netio-patchman/agent.env` dosyasına `PATCHMAN_REMOTE_UPDATES=false` yazın.
- Panel katı bir Content-Security-Policy ile sunulur ve dış kaynak (CDN, yazı tipi) kullanmaz; internet erişimi olmayan ağlarda da çalışır.

## Geliştirme

Gereksinim: Go 1.26 veya üzeri.

```sh
go test ./...                                   # birim ve uçtan uca testler
go vet ./...
PATCHMAN_DATA_DIR=./data go run ./cmd/netio-patchman-server

# Ajan dosyalarını sunucunun dağıtım biçiminde dist/agent/ altına derleme
scripts/build-agent.sh                                    # Linux / macOS
powershell -File scripts\build-agent.ps1                  # Windows

# OSV.dev'e karşı canlı tarama testi (internet erişimi gerekir)
go test -tags live -run Live -v ./internal/scanner/
```

Ürün gereksinimleri [docs/spec/](docs/spec/) dizinindedir.

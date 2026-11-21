# netio.patchman Kurulum ve İşletim Kılavuzu

Bu belge, netio.patchman sunucusunun üretim ortamına kurulmasını, ajanların dağıtılmasını, yedekleme ve sürüm yükseltme işlemlerini anlatır.

## 1. Sistem gereksinimleri

**Sunucu**

| Sunucu sayısı | İşlemci | Bellek | Disk |
|---|---|---|---|
| 100'e kadar | 1 çekirdek | 1 GB | 5 GB |
| 100–500 | 2 çekirdek | 2 GB | 20 GB |
| 500 üzeri | 4 çekirdek | 4 GB | 40 GB |

- Docker Engine 24+ ve Docker Compose v2.24+ ya da doğrudan çalıştırma için herhangi bir Linux dağıtımı.
- Ajanların erişebileceği bir alan adı ve TLS sertifikası (önerilir).
- Güvenlik açığı verileri için `api.osv.dev` ve `www.cisa.gov` adreslerine, Windows sunucuları varsa `api.msrc.microsoft.com` adresine HTTPS (443) erişimi. Erişim yoksa bkz. [Bölüm 8](#8-internet-erişimi-olmayan-ortamlar).

**Yönetilen sunucular (ajan)**

- systemd veya OpenRC (Alpine) kullanan bir Linux dağıtımı, amd64 veya arm64 mimari.
- ya da Windows Server 2016, 2019, 2022, 2025 veya Windows 10, 11 (x64). Bkz. [Bölüm 4.5](#45-windows-sunucuları).
- Sunucu adresine HTTPS erişimi. Ajan bağlantıyı her zaman kendisi başlatır; yönetilen sunucularda gelen bağlantı için port açmak gerekmez.

## 2. Docker Compose ile kurulum

```sh
git clone https://github.com/alptekinsunnetci/netio.patchman.git netio-patchman && cd netio-patchman
cp .env.example .env
```

`.env` dosyasında yalnızca sunucunun dış adresini girmeniz yeterlidir:

```sh
PATCHMAN_BASE_URL=https://patchman.your-domain
```

Sunucu adresi, ters vekil ayarı, SMTP, saat dilimi, günlük seviyesi ve veri kaynakları kurulumdan sonra panelde **Sistem Ayarları → Sunucu yapılandırması** sayfasından değiştirilebilir (bkz. bölüm 2.1).

Başlatın:

```sh
docker compose up -d --build
docker compose ps                  # durum "healthy" olmalı
docker compose logs -f server
```

Compose proje adı `netio-patchman`, imaj adı `netio-patchman-server`, veri birimi `netio-patchman-data`'dır. Veritabanı birimde `/data/netio-patchman.db` dosyasında tutulur.

İlk açılışta `PATCHMAN_BASE_URL/setup` adresinde ilk yönetici hesabı oluşturulur. Bu sayfa yalnızca hiç kullanıcı yokken açılır.

### 2.1 Panelden yapılandırma

**Sistem Ayarları → Sunucu yapılandırması** sayfası (yalnızca yöneticiler) şu ayarları içerir; kaydedilen değerler yeniden başlatma gerektirmeden hemen uygulanır:

| Ayar | Ortam değişkeni (ilk değer) |
|---|---|
| Sunucu adresi | `PATCHMAN_BASE_URL` |
| Ters vekil başlıklarına güven | `PATCHMAN_TRUST_PROXY` |
| Saat dilimi | `PATCHMAN_TIMEZONE` |
| Günlük seviyesi | `PATCHMAN_LOG_LEVEL` |
| SMTP sunucusu, port, kullanıcı adı, parola, gönderen adı ve adresi | `PATCHMAN_SMTP_*` |
| OSV API adresi, CISA KEV kataloğu (açık/kapalı ve adresi) | `PATCHMAN_OSV_URL`, `PATCHMAN_KEV_URL` |
| Yeni sürüm denetimi (açık/kapalı ve adresi) | `PATCHMAN_UPDATE_CHECK_URL` (`off` ile kapanır) |

- Ortam değişkenleri yalnızca ilk değerdir: panelde bir kez kaydedilen değer ortam değişkeninin yerine geçer. **Ortam değişkenlerine dön** düğmesi paneldeki değerleri siler.
- SMTP parolası veritabanında saklanır, sayfada hiçbir zaman gösterilmez ve denetim kaydına yazılmaz. Veritabanı yedeklerini buna göre koruyun.
- Sunucu adresi değiştiğinde yeni kurulum komutları ve e-posta bağlantıları yeni adresi kullanır. Kurulu ajanlar `/etc/netio-patchman/agent.env` dosyasındaki adresle bağlanmaya devam eder; adres gerçekten taşındıysa bu dosyadaki `PATCHMAN_SERVER_URL` değerini güncelleyip ajanı yeniden başlatın.
- Saat dilimi değiştiğinde zamanlanmış güncellemelerin bir sonraki çalışma zamanı yeni dilime göre yeniden hesaplanır.
- Panel, sunucu adresi HTTPS olsa bile başka bir adresten (ör. `http://localhost:8080`) erişimde çalışmaya devam eder; böylece yanlış girilen bir adres yönetici erişimini kesmez.

Sunucu başlarken, veritabanı açılmadan önce gereken şu değerler yalnızca ortam değişkeniyle değiştirilebilir ve yeniden başlatma gerektirir: `PATCHMAN_HTTP_ADDR`, `PATCHMAN_DATA_DIR`, `PATCHMAN_TLS_CERT_FILE`/`PATCHMAN_TLS_KEY_FILE`, `PATCHMAN_AGENT_DIST_DIR`, `PATCHMAN_LOG_FORMAT`, `PATCHMAN_LOCALE`. Sayfanın **Başlangıç yapılandırması** bölümü bu değerlerin geçerli hâlini gösterir.

## 3. TLS ve ters vekil

Ajanlar ve tarayıcılar sunucuya HTTPS ile bağlanmalıdır. İki seçenek vardır.

### 3.1 Ters vekil (önerilen)

Sunucuyu yalnızca yerel ağ arabiriminden yayınlayın (`.env` içinde `PATCHMAN_PUBLISH_PORT=127.0.0.1:8080` kullanılabilir) ve TLS'i nginx veya Caddy ile sonlandırın. **Sunucu yapılandırması** sayfasında "Ters vekil sunucunun … başlıklarına güven" seçeneğini açın (veya `PATCHMAN_TRUST_PROXY=true`).

**nginx örneği**

```nginx
server {
    listen 443 ssl http2;
    server_name patchman.your-domain;

    ssl_certificate     /etc/ssl/patchman/fullchain.pem;
    ssl_certificate_key /etc/ssl/patchman/privkey.pem;

    client_max_body_size 32m;   # büyük envanter raporları için

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
```

**Caddy örneği**

```
patchman.your-domain {
    reverse_proxy 127.0.0.1:8080
}
```

### 3.2 Sunucunun TLS'i kendisinin sonlandırması

```sh
PATCHMAN_TLS_CERT_FILE=/certs/tls.crt
PATCHMAN_TLS_KEY_FILE=/certs/tls.key
```

Sertifika dosyalarını konteynere salt okunur birim olarak bağlayın.

### 3.3 Kurum içi sertifika otoritesi

Sertifikanız kurum içi bir CA tarafından imzalandıysa, ajan kurulumunda CA dosyasını verin:

```sh
sh install-agent.sh --server-url https://patchman.your-domain --token <ANAHTAR> --ca-file /path/kurum-ca.pem
```

## 4. Ajan kurulumu

### 4.1 Sunucudan indirerek

Panelde **Ajan Yönetimi → Yeni kayıt anahtarı** ile bir anahtar oluşturun. Komut alanının üstünden sunucunun dağıtımını seçin; komut dağıtıma göre oluşur:

| Dağıtım | İndirme aracı | Varsayılan yetki |
|---|---|---|
| Ubuntu, Fedora | `curl` | `sudo` |
| RHEL, CentOS, AlmaLinux, Rocky, Oracle Linux | `curl` | root |
| SUSE, openSUSE | `curl` | root |
| Debian | `wget` | root |
| Alpine | `wget` | root |

Varsayılanlar standart kurulumlara göredir. **sudo ile çalıştır** kutusuyla değiştirebilirsiniz: root oturumunda sudo gerekmez, sudo kurulu değilse kutuyu boş bırakın. Örnek (root olarak, CentOS):

```sh
curl -fsSL https://patchman.your-domain/downloads/install-agent.sh | \
  sh -s -- --server-url https://patchman.your-domain --token <KAYIT-ANAHTARI>
```

Betik şunları yapar:

1. Mimariye uygun ajanı indirir ve SHA-256 özetini doğrular.
2. Ajanı `/usr/local/bin/netio-patchman-agent` konumuna kurar.
3. Yapılandırmayı `/etc/netio-patchman/agent.env` dosyasına yazar (yalnızca root okuyabilir).
4. Hizmet yöneticisini algılar ve hizmeti etkinleştirip başlatır:
   - systemd: `netio-patchman-agent.service`, kayıtlar `journalctl -u netio-patchman-agent -f`.
   - OpenRC (Alpine): `/etc/init.d/netio-patchman-agent` (supervise-daemon ile izlenir), kayıtlar `/var/log/netio-patchman-agent.log`.

İkisi de yoksa betik hata vererek durur.

Ajan ilk çalışmada kayıt anahtarıyla sunucuya kaydolur. Kalıcı kimliğini `/var/lib/netio-patchman/credentials.json` dosyasında saklar. Kayıttan sonra kayıt anahtarına ihtiyaç duyulmaz.

### 4.2 Toplu dağıtım

Kayıt anahtarını süreli ve kullanım sınırlı oluşturup Ansible, Puppet veya benzeri bir araçla aynı komutu çalıştırabilirsiniz. Örnek Ansible görevi:

```yaml
- name: netio.patchman ajanını kur
  ansible.builtin.shell: >
    curl -fsSL https://patchman.your-domain/downloads/install-agent.sh |
    sh -s -- --server-url https://patchman.your-domain --token {{ patchman_token }}
  args:
    creates: /usr/local/bin/netio-patchman-agent
  become: true
```

### 4.3 Ajan yapılandırması

`/etc/netio-patchman/agent.env`:

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `PATCHMAN_SERVER_URL` | — | Sunucu adresi (zorunlu) |
| `PATCHMAN_ENROLLMENT_TOKEN` | — | İlk kayıt için anahtar |
| `PATCHMAN_REMOTE_UPDATES` | `true` | `false` ise panelden başlatılan paket güncelleme işleri bu sunucuda çalıştırılmaz |
| `PATCHMAN_AUTO_UPDATE` | `true` | `false` ise ajan kendini otomatik olarak güncellemez (sürüm sabitleme) |
| `PATCHMAN_REFRESH_PACKAGE_LISTS` | `true` | Paket listelerini en fazla 6 saatte bir yeniler (`apt-get update`, `zypper refresh`, `apk update`) |
| `PATCHMAN_CA_FILE` | — | Ek CA sertifikası |
| `PATCHMAN_LOCALE` | `tr-TR` | Ajan günlüklerinin ve panelde görünen iş mesajlarının dili (`tr-TR`, `en-US`, `de-DE` veya `ru-RU`). Kurulumda `--locale` ile yazılır (ör. `--locale de-DE`) |

Değişiklikten sonra: `systemctl restart netio-patchman-agent.service` (Alpine: `rc-service netio-patchman-agent restart`)

### 4.4 Ajanı kaldırma

root olarak (veya komutların başına `sudo` ekleyerek):

```sh
systemctl disable --now netio-patchman-agent.service
rm -f /etc/systemd/system/netio-patchman-agent.service /usr/local/bin/netio-patchman-agent \
  /usr/local/bin/netio-patchman-agent.previous
rm -rf /etc/netio-patchman /var/lib/netio-patchman
systemctl daemon-reload
```

Alpine (OpenRC):

```sh
rc-service netio-patchman-agent stop
rc-update del netio-patchman-agent default
rm -f /etc/init.d/netio-patchman-agent /usr/local/bin/netio-patchman-agent \
  /usr/local/bin/netio-patchman-agent.previous /var/log/netio-patchman-agent.log
rm -rf /etc/netio-patchman /var/lib/netio-patchman
```

Ardından panelde sunucunun **Sistem Bilgisi** sekmesinden sunucuyu kaldırın.

### 4.5 Windows sunucuları

Desteklenen sürümler: Windows Server 2016, 2019, 2022, 2025 ve Windows 10, 11 (x64). Ajan bir Windows hizmeti olarak çalışır ve Windows Update Agent'ı kullanır. Windows Update hizmeti (`wuauserv`) devre dışı bırakılmamış olmalıdır. Sunucu WSUS'a bağlıysa ajan WSUS'ta onaylanan güncellemeleri görür ve kurar.

**Kurulum.** Panelde **Ajan Yönetimi** sayfasında **Windows / Windows Server (PowerShell)** seçeneğini seçin ve komutu sunucuda **yönetici olarak** açılan PowerShell veya komut isteminde çalıştırın:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm 'https://patchman.your-domain/downloads/install-agent.ps1').TrimStart([char]65279))) -ServerUrl 'https://patchman.your-domain' -Token '<KAYIT-ANAHTARI>'"
```

Komut, Windows Server 2016'da da çalışması için önce TLS 1.2'yi açar, ardından `install-agent.ps1` betiğini indirip çalıştırır. Betik:

1. Ajanı `https://patchman.your-domain/downloads/agent/netio-patchman-agent-windows-amd64.exe` adresinden indirir ve SHA-256 özetini doğrular.
2. Ajanı `C:\Program Files\netio-patchman\netio-patchman-agent.exe` konumuna kurar.
3. Yapılandırmayı `C:\ProgramData\netio-patchman\agent.env` dosyasına yazar. Bu dizin (kimlik bilgileri ve günlük dahil) yalnızca SYSTEM ve Administrators tarafından okunabilir.
4. `netio-patchman-agent` hizmetini otomatik başlatmalı olarak oluşturur. Hata durumunda ve kendini güncelledikten sonra Windows hizmeti yeniden başlatır (`sc failure` ve `sc failureflag`).

Betik seçenekleri: `-ServerUrl`, `-Token`, `-Binary <dosya>` (çevrimdışı kurulum), `-CaFile <dosya>` (ajanın sunucu sertifikasını doğrulaması için ek CA; betiğin kendi indirmesi Windows sertifika deposunu kullanır, iç CA'yı Windows'a ekleyin ya da `-Binary` kullanın), `-DisableRemoteUpdates`, `-DisableAutoUpdate`, `-Locale <dil>`, `-Uninstall`, `-Help`.

**Çevrimdışı kurulum.** `install-agent.ps1` ve `netio-patchman-agent-windows-amd64.exe` dosyalarını aynı klasöre kopyalayın:

```powershell
.\install-agent.ps1 -ServerUrl https://patchman.your-domain -Token <KAYIT-ANAHTARI> -Binary .\netio-patchman-agent-windows-amd64.exe
```

**Toplu dağıtım.** Kurulum komutu Group Policy başlangıç betiği, SCCM/Intune veya Ansible (`ansible.windows.win_shell`) ile çalıştırılabilir. Aynı anahtar birden çok sunucuda kullanılabilir.

**Durum ve günlük:**

```powershell
Get-Service netio-patchman-agent
Get-Content C:\ProgramData\netio-patchman\agent.log -Tail 50 -Wait
Restart-Service netio-patchman-agent        # agent.env değişikliğinden sonra
```

Günlük 10 MB'ı geçince `agent.log.1` olarak saklanır.

**Nasıl çalışır.**

- *Envanter:* Kurulu programlar ("Programlar ve Özellikler" listesi) ve Windows Update'te bekleyen güncellemeler (KB numarası, başlık, Microsoft önem derecesi, sınıflandırma). Tanım güncellemeleri (Defender) ve sürüm yükseltmeleri (feature update) listelenmez. Ajan Windows Update hizmetine en fazla 6 saatte bir çevrim içi sorar; arada Windows'un kendi son taramasının sonucunu okur (`PATCHMAN_REFRESH_PACKAGE_LISTS=false` ise hep bu sonucu kullanır).
- *Güvenlik açıkları:* Merkezi sunucu bekleyen her KB için [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide) API'sinden düzelttiği CVE'leri, CVSS puanlarını ve başlıkları alır. Toplu güncellemelerde (cumulative update) yerini aldığı eski KB'ler de, düzeltmeyi içeren Windows derlemesi sunucunun derlemesinden yeniyse eklenir. Bulgu, KB ile eşleştirilir; KB kurulunca bulgu "Çözüldü" olur. KEV işaretlemesi Linux'taki gibi çalışır. Microsoft'un CVE eşlemesi yayımlamadığı güncellemeler (bazı .NET toplu güncellemeleri gibi) güvenlik güncellemesi olarak listelenir ancak CVE bulgusu oluşturmaz. Üçüncü taraf programlar taranmaz.
- *Güncelleme işleri:* Güvenlik güncellemeleri, tüm güncellemeler, seçili KB'ler ve **Düzeltmeyi uygula** Windows Update üzerinden indirilip kurulur; ardından ajan bekleyen listeyi yeniden okuyarak kurulumu doğrular. Kurulum yeniden başlatma gerektiriyorsa iş çıktısında belirtilir ve sunucu **Yeniden başlatma gerekli** olarak işaretlenir. Zamanlanmış güncellemeler Windows'ta da sunucuyu yeniden başlatmaz.
- *Yeniden başlatma:* Paneldeki **Yeniden başlat** işi `shutdown.exe /r /t 60` çalıştırır; sonuç önce panele gönderilir.

**Kaldırma.** Yönetici PowerShell'de:

```powershell
.\install-agent.ps1 -Uninstall
```

Betik yoksa:

```powershell
Stop-Service netio-patchman-agent; sc.exe delete netio-patchman-agent
Remove-Item -Recurse -Force 'C:\Program Files\netio-patchman', 'C:\ProgramData\netio-patchman'
```

Ardından panelde sunucunun **Sistem Bilgisi** sekmesinden sunucuyu kaldırın.

## 5. Yedekleme ve geri yükleme

### 5.1 Otomatik yedekleme

Sunucu, veritabanını her gün belirlenen saatte (varsayılan 02:30, `PATCHMAN_TIMEZONE` saatine göre) tutarlı bir kopya olarak yedekler ve en yeni N yedeği saklar (varsayılan 7). Ayarlar **Sistem Ayarları → Otomatik yedekleme** bölümündedir. Sunucu yedekleme saatinde kapalıysa yedek, açıldıktan sonraki ilk dakikada alınır.

- Dosya adı: `netio-patchman-YYYYAAGG-SSDDss.db`. Her dosya doğrudan açılabilen bir SQLite veritabanıdır.
- Varsayılan dizin `/data/backups` (Docker biriminin içi). Birim ya da disk kaybına karşı yedekleri ayrı bir diske yazdırın:

  ```yaml
  # docker-compose.override.yml
  services:
    server:
      environment:
        PATCHMAN_BACKUP_DIR: /backups
      volumes:
        - /mnt/yedek/netio-patchman:/backups
  ```

  Konteyner 65532 numaralı kullanıcıyla çalışır; dizinin bu kullanıcıya yazma izni olmalıdır: `chown 65532:65532 /mnt/yedek/netio-patchman`.
- Panelde **Şimdi yedek al** ile anında yedek alınır ve listedeki **İndir** bağlantısıyla yedek indirilir. Yedekler parola özetlerini ve SMTP parolasını içerdiği için yalnızca yöneticiler indirebilir; her indirme denetim kayıtlarına yazılır.
- Yedekleme başarısız olursa (disk dolu, izin yok) bildirim merkezine kritik bir uyarı düşer ve e-posta bildirimleri açıksa e-posta gönderilir.

### 5.2 Elle yedekleme

Tutarlı bir veritabanı yedeği, sunucu çalışırken alınabilir:

```sh
docker compose exec server netio-patchman-server backup -out /data/yedek-$(date +%Y%m%d).db
docker compose cp server:/data/yedek-$(date +%Y%m%d).db ./
```

### 5.3 Geri yükleme

Otomatik ya da elle alınmış bir yedekten:

```sh
docker compose stop server
docker compose cp ./yedek-20261119.db server:/data/netio-patchman.db
docker compose start server
```

Otomatik yedek konteynerin içindeyse önce dışarı alın: `docker compose cp server:/data/backups/netio-patchman-20261119-023000.db ./yedek-20261119.db`. Yedekleri sunucu dışında da saklayın.

## 6. Sürüm yükseltme

```sh
git pull
docker compose up -d --build
```

Veritabanı şeması açılışta otomatik olarak güncellenir. Yükseltmeden önce yedek alın.

Sunucunun ve ajanların sürümü depodaki `VERSION` dosyasından alınır. Kendi derlemenize ayrı bir sürüm vermek için `.env` içinde `PATCHMAN_VERSION` tanımlayın. Ajanlar yalnızca sürüm değiştiğinde güncellenir.

### Yeni sürümün bildirilmesi

Sunucu, depodaki `VERSION` dosyasını açılıştan bir dakika sonra ve ardından 12 saatte bir okur. Daha yeni bir sürüm varsa:

- Yöneticiler her sayfanın üstünde bir uyarı ve kenar çubuğunda **Yeni sürüm** etiketi görür.
- Bildirim merkezine her yeni sürüm için bir kez bildirim düşer.
- E-posta bildirimleri açıksa yöneticilere (veya tanımlı alıcılara) her yeni sürüm için bir kez e-posta gider. **Sistem Ayarları → E-posta bildirimleri** bölümünden kapatılabilir.
- **Sistem Ayarları → Sunucu yapılandırması → Ürün sürümü** bölümünde kurulu sürüm, yayımlanan son sürüm, son denetim zamanı ve güncelleme komutları gösterilir. **Şimdi denetle** düğmesi denetimi hemen çalıştırır.

İstekte yalnızca `User-Agent: netio-patchman-server/<sürüm>` başlığı gönderilir; sunucular, kullanıcılar veya bulgular hakkında bilgi gönderilmez. Adres değiştirilebilir: düz metin bir `VERSION` dosyası veya GitHub sürüm API'si (`https://api.github.com/repos/<sahip>/<depo>/releases/latest`) kullanılabilir. Denetim aynı bölümden kapatılabilir.

Uyarı yalnızca bu özelliği içeren sürümden itibaren görünür. Daha eski bir sürümü çalıştıran sunucu, bir kez elle yükseltilmelidir.

### Ajanların otomatik güncellenmesi

Docker imajı, sunucuyla aynı sürümdeki amd64 ve arm64 Linux ile amd64 Windows ajan dosyalarını içerir. **Sistem Ayarları → Ajanlar → Ajanları otomatik olarak güncelle** açıkken (varsayılan):

1. Farklı sürüm çalıştıran bir ajan bağlandığında sunucu bir "Ajan güncellemesi" işi oluşturur.
2. Ajan yeni dosyayı sunucudan indirir, SHA-256 özetini karşılaştırır ve `-version` ile çalıştığını doğrular.
3. Mevcut dosyayı `netio-patchman-agent.previous` olarak saklar, yenisini yerine koyar ve çıkar; systemd ajanı yeni sürümle yeniden başlatır. Windows'ta çalışan dosya `netio-patchman-agent.exe.previous` adıyla kenara alınır ve hizmet, kurtarma ayarları sayesinde yeni sürümle birkaç saniye içinde yeniden başlar.

Aynı anda en fazla 25 ajan güncellenir. Başarısız bir güncelleme 6 saat sonra yeniden denenir ve Bildirim Merkezi'ne düşer. Otomatik güncelleme kapalıyken ajanlar **Ajan Yönetimi → Eski ajanları güncelle** düğmesiyle ya da sunucu sayfasındaki **Ajanı güncelle** düğmesiyle güncellenebilir.

Bir sunucuda ajan sürümünü sabitlemek için `/etc/netio-patchman/agent.env` dosyasına `PATCHMAN_AUTO_UPDATE=false` yazın (veya kurulumda `--disable-auto-update` kullanın).

Bir güncellemeyi geri almak için:

```sh
sudo mv /usr/local/bin/netio-patchman-agent.previous /usr/local/bin/netio-patchman-agent
sudo systemctl restart netio-patchman-agent.service
```

İmaj dışı kurulumlarda ajan dosyalarını `PATCHMAN_AGENT_DIST_DIR` dizinine `netio-patchman-agent-linux-<mimari>` ve `netio-patchman-agent-windows-amd64.exe` adıyla, sürümü de aynı dizindeki `version` dosyasına yazın. `scripts/build-agent.sh <sürüm> <dizin>` betiği bu dizini (Linux amd64 ve arm64, Windows amd64, SHA-256 özetleri ve `version` dosyası) hazır olarak üretir.

### Ajanı elle yeniden kurma

Kurulum komutunu `--token` seçeneği **olmadan** yeniden çalıştırırsanız ajanın mevcut kimliği korunur:

```sh
curl -fsSL https://patchman.your-domain/downloads/install-agent.sh | \
  sh -s -- --server-url https://patchman.your-domain
```

Komut `--token` ile çalıştırılırsa ajan yeniden kaydolur. Sunucu kaydı makine kimliğiyle eşleştirildiği için geçmiş veriler kaybolmaz.

## 7. Yönetici parolasını sıfırlama

Tüm yöneticilerin parolası unutulduysa:

```sh
docker compose exec server netio-patchman-server reset-password -email yonetici@your-domain
```

Komut, yeni bir parola üretip ekrana yazar ve hesabı etkinleştirir.

İki adımlı doğrulaması açık bir yönetici doğrulayıcı uygulamasına ve yedek kodlarına erişemiyorsa:

```sh
docker compose exec server netio-patchman-server reset-mfa -email yonetici@your-domain
```

Komut, kullanıcının doğrulayıcısını ve yedek kodlarını kaldırır, oturumlarını kapatır. Kullanıcı yalnızca parolayla giriş yapıp doğrulamayı yeniden tanımlar. “Zorunlu” ayarı açıksa ilk girişte Profilim sayfasına yönlendirilir.

## 8. İnternet erişimi olmayan ortamlar

- **Ajanlar:** Panelin **Ajan Yönetimi** sayfasındaki indirme adreslerinden ajan dosyasını, `netio-patchman-agent.service` dosyasını ve `install-agent.sh` betiğini alın, sunucuya kopyalayıp `--binary` seçeneğiyle kurun. Windows'ta `install-agent.ps1` ve `netio-patchman-agent-windows-amd64.exe` ile `-Binary` kullanılır.
- **Güvenlik açığı verisi:** **Sunucu yapılandırması** sayfasında OSV API adresini iç ağdaki bir yansıya yönlendirin. KEV kataloğunun adresini iç ağdaki bir kopyaya çevirin veya kataloğu kapatın. Windows sunucuları için Microsoft Security Update Guide adresini bir vekil sunucuya yönlendirin ya da kapatın; kapalıyken yalnızca Windows Update'in kendisinin bildirdiği CVE'ler kullanılır. (Ortam değişkenleri: `PATCHMAN_OSV_URL`, `PATCHMAN_KEV_URL`, `PATCHMAN_MSRC_URL`.)
- **Yeni sürüm denetimi:** **Sunucu yapılandırması → Sürüm denetimi** bölümünden kapatın veya iç ağdaki bir `VERSION` dosyasına yönlendirin (`PATCHMAN_UPDATE_CHECK_URL=off`).
- Panel dış kaynak (CDN, yazı tipi) kullanmaz.

## 9. Sorun giderme

| Belirti | Kontrol |
|---|---|
| Sunucu başlamıyor | `docker compose logs server`: yapılandırma hataları Türkçe olarak listelenir. |
| Ajan görünmüyor | Sunucuda `journalctl -u netio-patchman-agent.service -n 50`. Kayıt anahtarının süresi dolmuş veya kullanım sınırına ulaşmış olabilir. |
| Windows ajanı görünmüyor veya güncelleme listelemiyor | `Get-Content C:\ProgramData\netio-patchman\agent.log -Tail 50`. `wuauserv` hizmeti devre dışı mı? WSUS kullanılıyorsa güncellemeler onaylanmış mı? |
| Windows sunucusunda CVE yok | Merkezi sunucunun `api.msrc.microsoft.com` erişimini ve **Sunucu yapılandırması** sayfasındaki Microsoft Security Update Guide ayarını kontrol edin. |
| Ajan "Çevrimdışı" | Ajan hizmetini, sunucuya HTTPS erişimini ve saat eşitlemesini kontrol edin. |
| Güvenlik açığı bulunmuyor | **Sistem Ayarları → Tarama durumu** bölümünde son hatayı kontrol edin. Dağıtımın desteklendiğini doğrulayın. |
| E-posta gelmiyor | **Sistem Ayarları → Sunucu yapılandırması** sayfasında SMTP ayarlarını kontrol edip **Deneme e-postası** gönderin. |
| Güncelleme işi "Zaman aşımı" | Ajan 3 saat içinde sonuç bildirmedi. Sunucuda `journalctl -u netio-patchman-agent.service` çıktısını inceleyin. |

Sunucu günlükleri JSON biçimindedir ve her kayıtta `app=netio.patchman` alanı bulunur.

# netio.patchman'e katkı

🇬🇧 [English](CONTRIBUTING.md) · 🇹🇷 **Türkçe** · ⏱️ Okuma süresi: yaklaşık 10 dakika

Katkınız için teşekkürler! Bu rehber, depoyu klonladığınız andan pull request'inizin birleştirilmesine kadar gereken
her şeyi anlatır: geliştirme ortamı, sunucuyu ve bir ajanı çalıştırma, testler ve kod tabanının kuralları.

- Yeni misiniz? [**good first issue**](https://github.com/alptekinsunnetci/netio.patchman/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
  veya [**help wanted**](https://github.com/alptekinsunnetci/netio.patchman/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
  etiketli bir konu seçin ve üzerinde çalıştığınızı bir yorumla belirtin.
- Bir fikriniz mi var? Büyük bir değişikliğe başlamadan önce bir
  [özellik isteği](https://github.com/alptekinsunnetci/netio.patchman/issues/new?template=feature_request.yml) açın;
  yaklaşımda önceden anlaşalım.
- Bir güvenlik açığı mı buldunuz? Konu (issue) **açmayın**; bkz.
  [Güvenlik açığı bildirimi](docs/mimari-ve-guvenlik.md#12-güvenlik-açığı-bildirimi).
- Hiçbir şey kurmadan arayüzü deneyin: [canlı demo](https://alptekinsunnetci.github.io/netio.patchman/demo/).
- Konular ve pull request'ler Türkçe veya İngilizce yazılabilir.

## 1. Geliştirme ortamı

| Araç | Sürüm | Ne için |
|---|---|---|
| [Go](https://go.dev/dl/) | 1.26 (`go.mod`'a bakın) | Her şey. Derleme saf Go'dur (`CGO_ENABLED=0`), C derleyicisi gerekmez |
| Git | güncel bir sürüm | Klonlama, yükseltme testi |
| Docker ve Compose v2 | isteğe bağlı | Tam yığın, testler için PostgreSQL, imaj derleme |
| gcc | isteğe bağlı | `go test -race` (yarış dedektörü cgo gerektirir) |
| Bir Linux sanal makinesi veya WSL | isteğe bağlı | Gerçek bir ajan çalıştırmak (root ve paket yöneticisi gerekir) |

```sh
git clone https://github.com/alptekinsunnetci/netio.patchman.git
cd netio.patchman
go build ./...          # sunucu, ajan ve tüm paketler
go test ./...           # bir dizüstü bilgisayarda yaklaşık iki dakika
```

Windows geliştirme makinesi olarak kullanılabilir (bakımcılar da kullanıyor). Kabuk betikleri, systemd birimi ve OpenRC
betiği LF satır sonuyla kalmalıdır; CI bunu denetler.

## 2. Sunucuyu yerelde çalıştırma

En hızlı yol, yerel bir veri dizininde SQLite'tır:

```sh
# Linux / macOS / WSL
PATCHMAN_DATABASE_URL=sqlite PATCHMAN_DATA_DIR=./data PATCHMAN_HTTP_ADDR=127.0.0.1:8080 \
PATCHMAN_BASE_URL=http://127.0.0.1:8080 go run ./cmd/netio-patchman-server
```

```powershell
# Windows PowerShell
$env:PATCHMAN_DATABASE_URL='sqlite'; $env:PATCHMAN_DATA_DIR='.\data'; $env:PATCHMAN_HTTP_ADDR='127.0.0.1:8080'
$env:PATCHMAN_BASE_URL='http://127.0.0.1:8080'; go run ./cmd/netio-patchman-server
```

<http://127.0.0.1:8080/setup> adresini açıp ilk yöneticiyi oluşturun. Geliştirirken işe yarayan değişkenler:

| Değişken | Etkisi |
|---|---|
| `PATCHMAN_LOG_LEVEL=debug` | Ayrıntılı günlük |
| `PATCHMAN_UPDATE_CHECK_URL=off` | GitHub'a sürüm denetimi yapılmaz |
| `PATCHMAN_KEV_URL=off`, `PATCHMAN_EPSS_URL=off`, `PATCHMAN_EOL_URL=off`, `PATCHMAN_MSRC_URL=off` | Veri kaynakları indirilmez (hızlı açılış, çevrim dışı çalışma) |
| `PATCHMAN_LOCALE=en-US` | E-postaların ve günlüklerin varsayılan dili (arayüz dilini her kullanıcı seçer) |
| `PATCHMAN_AGENT_DIST_DIR=./dist/agent` | Sunucunun dağıttığı ajan dosyaları (`scripts/build-agent.sh` doldurur) |

Kullanıcıların çalıştırdığı gibi PostgreSQL'li tam yığın: `docker compose up -d --build` (bkz. [docs/kurulum.md](docs/kurulum.md)).

## 3. Sunucunuza bir ajan bağlama

Ajan paket veritabanlarını okur ve güncelleme uygular; bu yüzden onu silinebilir bir Linux sanal makinesinde veya WSL
dağıtımında root olarak çalıştırın:

```sh
GOOS=linux GOARCH=amd64 go build -o netio-patchman-agent ./cmd/netio-patchman-agent
cat > agent.env <<'EOF'
PATCHMAN_SERVER_URL=http://<makinenizin IP adresi>:8080
PATCHMAN_ENROLLMENT_TOKEN=<Ajan Yönetimi sayfasındaki kayıt anahtarı>
PATCHMAN_STATE_DIR=/tmp/np-agent
EOF
sudo ./netio-patchman-agent -config ./agent.env -debug
```

Sunucu bir dakika içinde envanterde görünür. Deneme yaparken `agent.env` içine `PATCHMAN_REMOTE_UPDATES=false`
yazarsanız ajan yalnızca envanter gönderir. Sunucu, sanal makinenin erişebileceği bir adreste dinlemelidir (örneğin
`PATCHMAN_HTTP_ADDR=0.0.0.0:8080`).

## 4. Testleri çalıştırma

| Ne | Komut |
|---|---|
| Hepsi (SQLite, sahte OSV sunucusuyla uçtan uca web testleri) | `go test ./...` |
| Tek paket veya test | `go test ./internal/compliance/ -run TestCatalogKeys -v` |
| Aynı testler PostgreSQL'de (her test kendi şemasını alır) | aşağıya bakın |
| Yarış dedektörü | `CGO_ENABLED=1 go test -race ./...` |
| Statik denetimler | `gofmt -l cmd internal deploy` (çıktı boş olmalı), `go vet ./...`, `GOOS=windows go vet ./...` |
| Çapraz derleme | `GOOS=linux GOARCH=arm64 go build ./...`, `GOOS=windows go build ./...` |
| Yükseltme, migration ve geri yükleme (CI'daki gibi) | `bash scripts/ci/upgrade-restore.sh` (PostgreSQL, `psql` ve sürüm etiketleri gerekir) |
| Gerçek OSV.dev API'sine karşı | `go test -tags live -run Live -v ./internal/scanner/` |
| Gerçek Windows Update araması (yalnızca Windows) | `go test -tags live -run LiveWindows -v ./internal/agent/` |

Testler için PostgreSQL:

```sh
docker run -d --name np-test-pg -p 55432:5432 -e POSTGRES_USER=np -e POSTGRES_PASSWORD=np -e POSTGRES_DB=np \
  -e POSTGRES_INITDB_ARGS="--encoding=UTF8 --locale=C" postgres:17-alpine
PATCHMAN_TEST_DATABASE_URL=postgres://np:np@127.0.0.1:55432/np?sslmode=disable go test ./...
```

**Sürekli entegrasyon** (CI) her pull request'te çalışır: biçim ve vet denetimi; SQLite'ta yarış dedektörüyle,
PostgreSQL 17'de ve Windows'ta testler; Linux amd64/arm64 ve Windows amd64 derlemeleri; Docker imajı ve Compose ile
açılış; yükseltme/geri yükleme testi; govulncheck, bağımlılık incelemesi ve konteyner imajı taraması. Bir pull request'in
birleştirilmesi için CI'nın başarılı olması gerekir.

## 5. Neyin nerede olduğu

| Yol | İçerik |
|---|---|
| `cmd/netio-patchman-server`, `cmd/netio-patchman-agent` | Giriş noktaları (sunucu alt komutları: `backup`, `restore`, `reset-password`, `reset-mfa`, `healthcheck`) |
| `internal/agent` | Toplayıcılar (apt, dnf/yum, zypper, apk, Windows Update, winget), iş çalıştırıcı, kendini güncelleme, izleme |
| `internal/protocol` | Ajan ↔ sunucu JSON sözleşmesi ve girdi doğrulama |
| `internal/api` | Ajan API'si (kayıt, bağlanma, rapor, iş sonuçları) |
| `internal/web` | Web sayfaları, şablonlar, statik dosyalar, oturumlar, REST API |
| `internal/store` | Tüm SQL; migration'lar `internal/store/migrations/` (SQLite) ve `migrations/postgres/` içinde |
| `internal/scanner` | OSV, KEV, EPSS, Microsoft MSRC; sürüm karşılaştırma ve ekosistem eşlemesi |
| `internal/compliance` | Uyum ve denetim: çerçeve profilleri, ölçümler, rapor motoru, dışa aktarma |
| `internal/i18n/locales` | İleti katalogları: `tr-TR`, `en-US`, `de-DE`, `ru-RU` |
| `deploy/` | Ajan kurulum betikleri, systemd/OpenRC birimleri, updater konteyneri |
| `docs/` | Kurulum ve kullanım kılavuzları, API, [mimari ve güvenlik modeli](docs/mimari-ve-guvenlik.md) |

Ajan protokolüne, kimlik doğrulamaya veya saklanan sırlara dokunan bir değişiklikten önce
[mimari ve güvenlik modeli](docs/mimari-ve-guvenlik.md) belgesini okuyun.

## 6. Kod tabanının kuralları

**Metin ve diller**

- Kullanıcının gördüğü her metin (sayfalar, e-postalar, hatalar, günlükler, CLI çıktısı, ajan iş mesajları)
  `internal/i18n/locales/` kataloglarından gelir. Yeni anahtarları **dört** kataloğa birden ekleyin; aksi halde
  `TestCatalogsMatch` ve `TestReferencedKeysExist` başarısız olur. Go kodunda veya şablonlarda sabit arayüz metni olmaz.
- Kod tanımlayıcıları, veritabanı sütunları, API alanları ve kod yorumları İngilizcedir.
- **Güvenlik açığı verisi asla çevrilmez veya yeniden yazılmaz**: CVE kimlikleri, resmî başlık ve açıklamalar, CVSS
  puanları ve vektörleri, paket adları ve sürümleri kaynağın yayımladığı gibi gösterilir.

**Veritabanı**

- Her sorgu hem SQLite hem PostgreSQL'de çalışmalıdır. `?` yer tutucularıyla taşınabilir SQL yazın; mevcut kodda olduğu
  gibi `ON CONFLICT`, `RETURNING id`, `lower(col)`, `CASE` ifadeleri ve `NULLS LAST` kullanın.
- Şema değişikliği, `migrations/` ve `migrations/postgres/` dizinlerinin **ikisine de** eklenen yeni numaralı bir
  migration'dır. Yayımlanmış bir migration asla değiştirilmez.
- Sunucuları, bulguları, işleri veya bildirimleri okuyan sorgular grup kapsamını uygulamalıdır (`hostScope`, `andScope`).

**Güvenlik**

- Ajan hiçbir portu dinlemez ve asla kabuk çalıştırmaz. İşler sabit paket yöneticisi komutları kullanır; paket ve
  servis adlarını iki tarafta da doğrulayın (`protocol.ValidPackageName`, `ValidServiceName`).
- Anahtar ve sırların yalnızca özetlerini saklayın. Oturum gerektiren her POST, CSRF anahtarını ve Origin'i denetler.
- İçerik güvenlik politikası satır içi betik ve stili yasaklar: davranışı `internal/web/static/app.js`, stilleri
  `app.css` içine koyun; başka bir sunucudan hiçbir şey yüklemeyin.

**Kod biçimi**

- `gofmt`, küçük ve odaklı fonksiyonlar, nedenini açıklayan yorumlar. Komşu bir dosyaya bakın ve onun kalıplarını izleyin.
- Zamanlar UTC Unix saniyesi olarak saklanır ve biçimlendirici üzerinden gösterilir.
- Ürün adı her zaman `netio.patchman` (küçük harf) yazılır.

## 7. Pull request'ler

1. Depoyu çatallayın (fork), bir dal açın (`feature/kisa-ad` veya `fix/kisa-ad`) ve onu tek bir değişikliğe odaklı tutun.
2. Değiştirdiğiniz davranış için test ekleyin veya güncelleyin.
3. `go test ./...`, `gofmt` ve `go vet` komutlarını yerelde çalıştırın; SQL değişikliklerinde testleri PostgreSQL'de de çalıştırın.
4. Davranış değiştiğinde belgeleri güncelleyin (README, `docs/`, API alanları için `docs/api.md` ve `docs/api.en.md`; Türkçe ve İngilizce belgeleri birlikte güncel tutun).
5. Pull request'i açıp şablonu doldurun. Arayüz değişikliklerinde ekran görüntüsü çok yardımcı olur.

Sürümleri bakımcı çıkarır: `VERSION` artırılır, sürüm commit'i `v<VERSION>` ile etiketlenip GitHub sürümü olarak
yayımlanır; ajanlar yeni sunucudan kendilerini günceller.

## 8. Lisans

netio.patchman, Commons Clause eki ile Apache License 2.0 altında lisanslanmıştır (bkz. [LICENSE](LICENSE)). Bir katkı
göndererek, katkınızın aynı koşullarla lisanslanmasını kabul etmiş olursunuz.

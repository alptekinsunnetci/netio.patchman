# netio.patchman REST API ve Prometheus

netio.patchman'deki sunucu, güvenlik açığı, güncelleme ve iş verilerini betiklerden, Ansible'dan veya izleme sistemlerinden okumak ve güncelleme işi başlatmak için kullanılır.

## Kimlik doğrulama

1. Panelde **Profilim → API anahtarları** bölümünden bir anahtar oluşturun. Anahtar yalnızca bir kez gösterilir; `npat_` ile başlar.
2. Her istekte başlığı gönderin:

   ```
   Authorization: Bearer npat_...
   ```

- Anahtar, oluşturan kullanıcının **rolüyle** ve **sunucu erişimiyle** çalışır. Grup bazlı sınırlanmış bir kullanıcının anahtarı yalnızca o gruplardaki sunucuları görür.
- **Salt okunur** anahtarlar (varsayılan) hiçbir şeyi değiştiremez. Güncelleme işi başlatmak için anahtar oluştururken **Güncelleme işi başlatabilsin** seçeneğini işaretleyin; bu seçenek yalnızca operatör ve yöneticilerde vardır.
- Anahtarın geçerlilik süresi gün olarak verilir (0 = süresiz). Anahtar Profilim sayfasından iptal edilir; kullanıcı silinir veya devre dışı bırakılırsa anahtarları da çalışmaz.
- Veritabanında yalnızca anahtarın SHA-256 özeti tutulur. İş başlatan istekler denetim kayıtlarına anahtarın adıyla (`api_token=<ad>`) yazılır.
- API çerez kabul etmez; tarayıcı oturumu API'de geçerli değildir.
- Hatalı anahtarlar IP bazında sınırlandırılır (art arda hatalı denemelerde `429`).

## Yanıt biçimi

- JSON, UTF-8. Alan adları İngilizcedir ve sürümler arasında korunur.
- Zamanlar UTC, RFC 3339 (`2026-11-21T10:15:00Z`); bilinmeyen zamanlar `null`.
- CVE başlıkları, paket adları ve sürümler kaynağındaki haliyle döner.
- Listeler sayfalıdır (sayfa başına 50 kayıt): `?page=2`. Yanıtta `pagination: {page, page_size, total}` bulunur.
- Hatalarda: `{"code": "...", "message": "..."}`. Kodlar: `unauthorized` (401), `forbidden` (403), `not_found` (404), `bad_request` (400), `rate_limited` (429), `job_rejected` (409), `internal` (500). `message`, sunucunun varsayılan dilindedir.

## Uç noktalar

| Yöntem | Yol | Açıklama |
|---|---|---|
| GET | `/api/v1/hosts` | Sunucular. Süzgeçler: `q` (ad, IP, işletim sistemi), `status` (`online`, `offline`, `reboot`, `vulnerable`, `updates`), `os` (ör. `ubuntu`, `windows`), `group` (grup no), `platform` (`virtual`, `physical`, `vmware`…) |
| GET | `/api/v1/hosts/{id}` | Tek sunucu |
| GET | `/api/v1/hosts/{id}/findings` | Sunucunun güvenlik açığı bulguları. Süzgeçler: `status` (boş = açık ve işlemde, `all`, `resolved`, `accepted_risk`…), `severity`, `kev=1`, `overdue=1` |
| GET | `/api/v1/hosts/{id}/updates` | Bekleyen güncellemeler; her kayıtta `excluded` (güncellenmeyecek paketler listesinde mi) ve yanıtta etkin `exclude` listesi |
| POST | `/api/v1/hosts/{id}/jobs` | Güncelleme işi başlatır (yazma yetkili anahtar). Gövde: `{"type": "...", "packages": [...]}` |
| GET | `/api/v1/vulnerabilities` | Filodaki açıklar (CVE başına). Süzgeçler: `q`, `severity`, `status`, `kev=1`, `fix=1`, `overdue=1`, `sort=epss` (önce KEV, sonra EPSS) |
| GET | `/api/v1/vulnerabilities/{cve}` | Açık ayrıntısı (resmî başlık, açıklama, CVSS, EPSS, KEV, duyurular) ve etkilenen sunucular |
| GET | `/api/v1/groups` | Sunucu grupları |
| GET | `/api/v1/jobs` | İşler, en yeni önce. Süzgeçler: `host` (sunucu no), `status` |
| GET | `/api/v1/jobs/{id}` | İş ayrıntısı ve komut çıktısı |
| GET | `/metrics` | Prometheus metrikleri |

### İş türleri

| `type` | Anlamı |
|---|---|
| `refresh` | Envanteri hemen yenile |
| `upgrade_security` | Güvenlik güncellemelerini kur |
| `upgrade_all` | Tüm güncellemeleri kur |
| `upgrade_packages` | `packages` içindeki paketleri (Windows'ta KB numaralarını veya winget kimliklerini) güncelle |
| `restart_services` | `packages` içindeki servisleri yeniden başlat |
| `reboot` | Sunucuyu 1 dakika sonra yeniden başlat |
| `agent_update` | Ajanı sunucunun dağıttığı sürüme güncelle |

İş, paneldekiyle aynı kurallarla oluşturulur: uzaktan güncellemesi kapalı sunucularda paket işleri reddedilir, güncellenmeyecek paketler atlanır, aynı türden bekleyen yeniden başlatma varsa yenisi oluşturulmaz. Reddedilen işte yanıt `409` ve `{"code": "job_rejected", "message": "..."}` olur. Başarılı yanıt `201` ve işin kendisidir; durumunu `/api/v1/jobs/{id}` ile izleyin (`queued` → `dispatched` → `succeeded` / `partial` / `failed`).

### Örnekler

```sh
KEY=npat_...
BASE=https://patchman.your-domain

# Açık bulgusu olan sunucular
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/hosts?status=vulnerable"

# Süresi geçmiş, istismar olasılığı en yüksek açıklar
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/vulnerabilities?overdue=1&sort=epss"

# Bir sunucuda güvenlik güncellemelerini başlat
curl -s -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"type":"upgrade_security"}' "$BASE/api/v1/hosts/12/jobs"

# Belirli paketleri güncelle
curl -s -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"type":"upgrade_packages","packages":["openssl","libssl3"]}' "$BASE/api/v1/hosts/12/jobs"
```

Örnek sunucu kaydı:

```json
{
  "id": 12,
  "hostname": "web-01",
  "os_id": "ubuntu",
  "os_name": "Ubuntu 24.04.1 LTS",
  "kernel": "6.8.0-45-generic",
  "online": true,
  "reboot_required": false,
  "kernel_patch": "livepatch",
  "groups": ["Üretim"],
  "updates": 14,
  "security_updates": 3,
  "vulnerabilities": {"critical": 1, "high": 4, "medium": 9, "low": 2, "other": 0}
}
```

## Prometheus

`/metrics` Prometheus metin biçimindedir ve aynı API anahtarıyla korunur. Grup bazlı sınırlı bir kullanıcının anahtarı yalnızca kendi sunucularının metriklerini döndürür.

```yaml
scrape_configs:
  - job_name: netio-patchman
    scheme: https
    scrape_interval: 60s
    authorization:
      credentials: npat_...
    static_configs:
      - targets: ["patchman.your-domain"]
```

| Metrik | Etiketler | Açıklama |
|---|---|---|
| `netio_patchman_info` | `version` | Sunucu sürümü (değer 1) |
| `netio_patchman_hosts` | `state` (`online`, `offline`, `never_seen`) | Sunucu sayısı |
| `netio_patchman_hosts_reboot_required` | — | Yeniden başlatma bekleyen sunucular |
| `netio_patchman_vulnerabilities` | `severity` | Açık bulgusu olan farklı CVE sayısı |
| `netio_patchman_vulnerabilities_known_exploited` | — | CISA KEV'deki açık CVE'ler |
| `netio_patchman_findings_overdue` | — | Düzeltme süresi (SLA) geçmiş bulgular |
| `netio_patchman_updates_pending` | `kind` (`all`, `security`) | Bekleyen güncellemeler |
| `netio_patchman_jobs_last_24h` | `status` | Son 24 saatte oluşturulan işler |
| `netio_patchman_scan_last_run_timestamp_seconds` | — | Son tarama zamanı |
| `netio_patchman_host_up` | `host`, `os` | Ajan son bağlantı süresi içinde bağlandıysa 1 |
| `netio_patchman_host_vulnerabilities` | `host`, `os`, `severity` | Sunucudaki açık CVE sayısı |
| `netio_patchman_host_updates_pending` | `host`, `os`, `kind` | Sunucudaki bekleyen güncellemeler |
| `netio_patchman_host_reboot_required` | `host`, `os` | Sunucu yeniden başlatma bekliyorsa 1 |

Örnek uyarı kuralları:

```yaml
groups:
  - name: netio-patchman
    rules:
      - alert: KritikAcik
        expr: netio_patchman_host_vulnerabilities{severity="critical"} > 0
        for: 1h
      - alert: AjanBaglantisiYok
        expr: netio_patchman_host_up == 0
        for: 30m
      - alert: SLASuresiGecti
        expr: netio_patchman_findings_overdue > 0
```

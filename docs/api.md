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
| GET | `/api/v1/hosts/{id}/software` | Sunucudaki tanınan yazılımlar (ürün, seri, sürüm, paket, servis durumu) ve servis listesi (`services_known` false ise ajan servis bildirmiyor) |
| GET | `/api/v1/software` | Filodaki yazılımlar. Süzgeçler: `software` (ürün kimliği, ör. `nginx`, `php`), `cycle` (ör. `8.2`) |
| GET | `/api/v1/eol` | İşletim sistemi ve yazılım destek durumları (`status`: `supported`, `soon`, `eol`, `unknown`; `distro_supported`: dağıtım sürdürüyor) |
| GET | `/api/v1/hosts/{id}/score` | Güvenlik puanı (`score`, `band`), toplam kesinti ve ölçüt bazında ayrıntı (`categories`). Puan henüz hesaplanmadıysa `score: null` |
| GET | `/api/v1/hosts/{id}/health` | Sürekli izleme: kontrollerin ve otomatik sınırların anlık durumu (`checks`: `key`, `name`, `type`, `builtin`, `ok`, `value`, `since`, `checked_at`), başarısız sayısı (`failing`) ve son kaynak ölçümü (`resources`: `cpus`, `load`, `memory_total`, `memory_available`, `swap_total`, `swap_free`, `disks[]` bayt cinsinden; `resources_at`) |
| GET | `/api/v1/drift` | Standart sapmaları. Süzgeçler: `standard`, `host`, `group`. Her kayıtta kural (`kind`, `subject_type`, `subject`, `expected`), bulunan durum (`found`), `first_seen` ve varsa önerilen güncelleme (`suggested_update`) |
| GET | `/api/v1/rollouts` | Kademeli güncellemeler, en yeni önce: durum, aşama, sunucu sayıları (`hosts.total`, `succeeded`, `failed`…). Grup bazlı sınırlı anahtarlara kapalıdır (`403`) |
| GET | `/metrics` | Prometheus metrikleri |

Sunucu kayıtlarında ayrıca `security_score` (henüz hesaplanmadıysa `null`) ve ajanın bildirdiği yetenekler (`capabilities`: `services`, `health`, `preview`, `rollback`) bulunur.

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
| `health_check` | Sunucuya uygulanan sağlık kontrollerini güncelleme yapmadan çalıştır (uzaktan güncelleme kapalı olsa da çalışır; ajanın `health` yeteneği ve en az bir kontrol gerekir) |

API ile başlatılan güncellemeler ön izleme (dry-run) onayı beklemez. Sağlık kontrolleri tanımlıysa güncelleme işlerinde önce ve sonra çalışır; sonuçları iş sayfasındadır.

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
| `netio_patchman_host_health_failing` | `host`, `os` | Sunucuda başarısız olan izlenen kontrol ve otomatik sınır sayısı |
| `netio_patchman_host_memory_used_percent` | `host`, `os` | Bellek kullanımı (toplam eksi kullanılabilir) |
| `netio_patchman_host_load_per_cpu_percent` | `host`, `os` | 1 dakikalık yük ortalamasının çekirdek sayısına oranı (Linux) |
| `netio_patchman_host_disk_used_percent` | `host`, `os`, `path` | Dosya sistemi doluluğu (df'nin gösterdiği gibi). Kaynak metrikleri yalnızca güncel ölçümler için yazılır (son 3 izleme aralığı, en az 15 dakika); bağlantısı kesilen sunucunun eski değerleri uyarı üretmez. |
| `netio_patchman_security_score` | `stat` (`avg`, `min`) | Filonun ortalama ve en düşük güvenlik puanı (puanlanmış sunucu yoksa yazılmaz) |
| `netio_patchman_eol` | `kind` (`os`, `software`), `status` (`eol`, `soon`, `eol_distro_maintained`) | Desteği bitmiş veya yakında bitecek işletim sistemi (sunucu) ve yazılım kurulumu sayısı |
| `netio_patchman_drift_deviations` | — | Açık standart sapmaları |
| `netio_patchman_rollouts` | `status` (`running`, `paused`, `failed`) | Kademeli güncellemeler (yalnızca sınırsız anahtarlarda) |
| `netio_patchman_channel_failing` | `channel`, `type` | Etkin bildirim kanalına son gönderim başarısızsa 1 (yalnızca sınırsız anahtarlarda) |

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
      - alert: DiskDoluyor
        expr: netio_patchman_host_disk_used_percent > 90
        for: 15m
      - alert: GuvenlikPuaniDusuk
        expr: netio_patchman_security_score{stat="min"} < 50
        for: 1h
      - alert: KademeliGuncellemeDurdu
        expr: netio_patchman_rollouts{status="failed"} > 0
      - alert: BildirimKanaliHatali
        expr: netio_patchman_channel_failing == 1
        for: 15m
```

## Grafana, Netdata ve Zabbix

- **Grafana:** Yukarıdaki Prometheus verisini veri kaynağı olarak ekleyin. Kullanışlı paneller: `netio_patchman_security_score`, `sum by (severity) (netio_patchman_host_vulnerabilities)`, `netio_patchman_updates_pending`, `netio_patchman_eol`. Sunucu bazında tablo için `netio_patchman_host_vulnerabilities{severity="critical"}` serisini `host` etiketine göre gösterin.
- **Netdata:** `go.d` Prometheus toplayıcısıyla `/metrics` okunabilir (`/etc/netdata/go.d/prometheus.conf`):

  ```yaml
  jobs:
    - name: netio_patchman
      url: https://patchman.your-domain/metrics
      update_every: 60
      headers:
        Authorization: Bearer npat_...
  ```

- **Zabbix:** İki yol vardır. Olaylar için **Sistem Ayarları → Bildirim kanalları** sayfasında **Zabbix (trapper)** kanalı ekleyin. Zabbix'te kanalda verilen host adıyla bir host ve aynı anahtarla “Zabbix trapper” türünde metin öğesi oluşturun. Değer JSON'dur (`event`, `kind`, `level`, `title`, `text`, `url`, `params`, `time`); tetikleyiciler bu değerle yazılabilir, ör. `find(/patchman/netio.patchman.event,,"like","\"event\":\"update_failed\"")=1`. Durum metrikleri için Zabbix 6.0 ve üstünün HTTP agent öğesi `/metrics` adresini `Authorization: Bearer npat_...` başlığıyla okuyabilir. Ardından “Prometheus pattern” ön işlemesiyle istenen metrik seçilir.

## Webhook ve kayıt sistemleri

Olayları dış sistemlere iletmek için bildirim kanalları kullanılır (Webhook, Jira, ServiceNow, GLPI, Zabbix, Slack, Teams, Telegram); alanlar, olay listesi ve imza doğrulaması için bkz. [kullanim.md](kullanim.md), “Bildirim kanalları ve entegrasyonlar”. Webhook imzasını doğrulama örneği (Python):

```python
import hashlib, hmac, time

def dogrula(secret: bytes, body: bytes, header: str, max_age=300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    ts = parts["t"]
    if abs(time.time() - int(ts)) > max_age:
        return False
    expected = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts["sha256"])

# header: X-Netio-Patchman-Signature-V2 başlığının değeri
```

# netio.patchman
## Uyum ve Denetim (Compliance & Audit) — Revize Geliştirme Planı

Durum: uygulandı (1.x, kod adı “gökalp”) · Son güncelleme: 23 Kasım 2026

### 0. Bu revizyonun dayanağı

Mimari karar: bilgi güvenliği yönetimi, BT temel koruma ve BT hizmet yönetimi denetimleri için ayrı menüler, ayrı
modüller veya ayrı raporlama sistemleri **kurulmaz**. Hepsi tek bir **Uyum ve Denetim** alanında, tek raporlama
motoruyla, tek ortak kanıt deposu üzerinden ve çerçeve başına ayrı kontrol değerlendirmeleriyle sunulur.

Çerçeveler ürün içinde tarafsız adlarla ve netio.patchman'in kendi kontrol kimlikleriyle tanımlanır; hiçbir standardın
adı, kontrol numarası veya metni kullanılmaz. Amaç, bu tür denetimlere giren kuruluşların ihtiyaç duyduğu teknik
kanıtları ve raporları üretebilmesidir.

Depoda önceki planın yazılı bir sürümü bulunmadığından bu revizyon, planın hedeflediği **mevcut koda** göre yapılmıştır:
`/reports` (Uyumluluk Raporu), `/standards` (Sunucu Standartları), `/settings/audit` (denetim kaydı), SLA, EOL, işler,
geri alma, kademeli güncellemeler ve günlük anlık görüntüler.

---

### 1. Hedef ve sınırlar

**Hedef:** Tek Uyum ve Denetim alanı, tek raporlama motoru, ortak kanıt deposu, birden fazla çerçeve
için birbirinden bağımsız kontrol değerlendirmeleri; Linux, Windows Server, Windows 10 ve Windows 11
için aynı motor.

**Kapsam dışı / bilinçli sınırlar:**

- Ürün **sertifikasyon, belgelendirme veya tam uygunluk garantisi vermez.** Hiçbir ekranda, raporda veya
  dışa aktarımda “uyumlu”, “compliant”, “certified”, “sertifikalı” gibi kesin hüküm ifadesi kullanılmaz.
  Kullanılan ifadeler: *kanıt mevcut*, *otomatik kontrol sonucu*, *kanıt eksik*, *sapma tespit edildi*,
  *manuel inceleme gerekli*, *uygulanamaz*.
- Bir yama ve güvenlik açığı yönetim aracı, bir ISMS'in örgütsel gereksinimlerinin (politikalar, roller,
  risk değerlendirmesi, yönetim gözden geçirmesi, eğitim vb.) çoğunu teknik olarak ölçemez. Bu kontroller
  katalogda yer alır, ancak durumları “manuel kanıt gerekir” olarak kalır ve “Eksik kanıtlar” bölümünde
  listelenir.
- Aynı kanıtın birden çok standartta kullanılması, o standartların ilgili kontrolünün **bütün**
  gereksinimlerinin karşılandığı anlamına gelmez. Her eşlemede kanıtın kontrolü hangi ölçüde desteklediği
  (`relevance`: `primary`, `supporting`, `partial`) saklanır ve raporda gösterilir.
- BT hizmet yönetimi değerlendirmesi “uygulama desteği kanıtı” olarak sunulur, hüküm içermez.

---

### 2. Mevcut durumun değerlendirmesi

| Mevcut yapı | Değerlendirme | Karar |
|---|---|---|
| `/reports` Uyumluluk Raporu (`web/pages_reports.go`, `store/reports.go`) | Her açılışta canlı hesaplanır; saklanmaz, sürümü yoktur; yalnızca tarayıcıdan yazdırma ile PDF; dönem ≤ 366 gün; standart/kontrol kavramı yok. Sorgular (bulgu akışı, KEV, SLA gecikmeleri, iş sayıları, eğilimler) doğru ve yeniden kullanılabilir. | Sayfa kaldırılır, sorgular ortak motorun **bölüm oluşturucuları** olur. `/reports` yeni adrese yönlenir. |
| `/standards` Sunucu Standartları + `drift_findings` | Teknik temel çizgi politikası; sapmalar zaten “uyum bulgusu, güvenlik açığı değil” olarak ayrılmış. Şu an *Güvenlik* grubunda. | **Uyum Politikaları** altına taşınır; veri modeli aynen kalır, sapmalar kanıt deposuna kanıt olarak yazılır. |
| `/settings/audit` denetim kaydı (`audit_log`) | 66 eylem türü; 365 gün sonra silinir; değiştirilemezlik/bütünlük kanıtı yok; Yönetim ayarlarının içinde gizli. | **Denetim Geçmişi** altına taşınır; eski adres yönlenir. Bütünlük için kanıt deposundaki hash zinciri kullanılır. |
| `daily_snapshots` | Yalnızca filo toplamları; ana sayfa eğilimleri için yeterli, geçmiş dönem varlık envanteri için yetersiz. | Kalır (gösterge paneli). Aynı bakım adımında sunucu başına günlük durum da yazılır (§4.3); ikinci bir toplama sistemi kurulmaz. |
| Saklama süreleri | İşler, çözülen bulgular ve bildirimler varsayılan **90 gün**, denetim kaydı **365 gün** sonra silinir. 12 aylık bir denetim dönemi bugün kanıtlanamaz. | Kanıtlar olay anında kanıt deposuna dondurulur; kanıt deposunun saklama süresi işletim verisinden bağımsızdır (§4.6). |
| SLA, kabul edilen risk süresi, EOL, güvenlik puanı | Doğru ve test edilmiş; ayarları farklı sayfalarda. | Değerlendirme kuralları bu ayarları **okur**, kopyalamaz. Uyum Politikaları sayfası bu ayarları gösterir ve ilgili ayar sayfasına bağlanır. |
| Platform ayrımı | Ajan `OSID=windows`; `OSName` “Windows Server 2022 …”, “Windows 10 …”, “Windows 11 …” ayrımını zaten taşıyor (Windows 11 düzeltmesi ajanda var). | Sunucu tarafında saf bir `compliance.Platform(host)` sınıflandırıcısı: `linux`, `windows_server`, `windows_10`, `windows_11`, `windows_other`. |

---

### 3. Bilgi mimarisi ve menü

Kenar çubuğunda tek yeni grup: `nav.group.compliance`. Ürün Türkçe öncelikli olduğundan (bkz.
`01-product-identity.md` §2) görünen adlar katalogdan gelir; İngilizce adlar `en-US` kataloğudur.

| Bölüm (en-US) | tr-TR etiketi | Adres | Görev |
|---|---|---|---|
| Compliance & Audit (grup) | Uyum ve Denetim | — | Menü grubu başlığı |
| Overview | Genel Bakış | `/compliance` | Kanıt toplama durumu, çerçeve başına son raporun kontrol dağılımı, eksik kanıt sayısı, yaklaşan SLA ihlalleri, son rapor sürümleri |
| Compliance Reports | Uyum Raporları | `/compliance/reports` | Rapor oluşturma, sürümler, görüntüleme, dışa aktarma (tüm çerçeveler burada) |
| Audit Evidence | Denetim Kanıtları | `/compliance/evidence` | Ortak kanıt deposu: arama, ayrıntı, hash, eşlendiği kontroller; manuel kanıt yükleme |
| Audit History | Denetim Geçmişi | `/compliance/history` | Rapor sürümleri ve değerlendirme çalıştırmaları zaman çizelgesi + kullanıcı denetim kaydı |
| Compliance Policies | Uyum Politikaları | `/compliance/policies` | Etkin çerçeveler ve katalog sürümleri, kontrol uygulanabilirliği, eşik değerleri, sunucu standartları |

Kaldırılan / taşınan menü öğeleri:

- `reports` (*Genel bakış* grubu) → kaldırılır; `/reports` → `/compliance/reports` (301).
- `standards` (*Güvenlik* grubu) → kaldırılır; `/standards` → `/compliance/policies/standards` (301).
- `/settings/audit` → `/compliance/history?tab=audit` (301); Sistem Ayarları sekmelerinden çıkarılır.

Standart başına menü, sekme veya sayfa **yoktur**. Çerçeve, rapor oluştururken seçilen bir parametredir;
rapor sayfasında seçilen çerçeveler aynı raporun bölümleri olarak görünür.

**Yetkiler** (`admin > operator > viewer`, grup sınırlı kullanıcılar dahil):

| İşlem | viewer | operator | admin |
|---|---|---|---|
| Rapor ve kanıt görüntüleme, dışa aktarma | ✓ (kapsamı içinde) | ✓ | ✓ |
| Taslak rapor / yeni sürüm oluşturma | — | ✓ | ✓ |
| Sürümü kesinleştirme (final), manuel inceleme kaydı | — | — | ✓ |
| Manuel kanıt yükleme ve kontrole eşleme | — | ✓ | ✓ |
| Uyum Politikaları (çerçeve etkinleştirme, uygulanabilirlik, eşikler) | — | — | ✓ |
| Kullanıcı denetim kaydı | — | — | ✓ |

Grup sınırlı kullanıcılar (`store.WithScope`) yalnızca kendi gruplarını kapsayan raporlar oluşturur ve
görür; kanıt sorguları `hostScope` uygular; filo geneli raporlar ve filo eğilimleri onlara kapalıdır
(`fleetWidePath` ile aynı kural). Tüm POST'lar mevcut `require()` + CSRF + Origin denetiminden geçer.

---

### 4. Mimari

```
 işler, bulgular, denetim kaydı, sapmalar, yedekler, sunucu durumları (mevcut kayıtlar)
        │  imleçlerle dakikada bir okunur; günlük durum 15 dakikada bir yazılır
        ▼
 compliance.Collector ── tek toplayıcı ──▶ evidence_items (yalnızca ekleme, hash zinciri)
        │                                evidence_host_states (sunucu × gün)
        ▼
 internal/compliance
   profiles/*.json (sürümlü, gömülü) ──▶ Profile ── kontrol → ortak ölçümler (checks)
   checks (ortak, işletim sisteminden bağımsız ölçüler) ──▶ CheckResult (metrik + kanıt kimlikleri)
   engine ──▶ ReportModel (bölümler + kontrol değerlendirmeleri + kanıt dizini)
        ▼
 compliance_reports / compliance_report_versions (JSON içerik + SHA-256, değişmez)
        ▼
 export: JSON · CSV (ZIP) · PDF          web: /compliance/...      API: /api/v1/compliance/...
```

İlkeler:

1. **Standarda özel veri toplama yoktur.** Tek toplayıcı, mevcut olaylardan standarttan habersiz
   kanıt üretir. Çerçeve bilgisi toplama anında değil, değerlendirme anında devreye girer.
2. **Gerçek kanıt ≠ otomatik değerlendirme ≠ manuel inceleme.** Üç ayrı katman, üç ayrı veri:
   - *Kanıt* (`evidence_items`): olmuş bir olgu; değiştirilemez, hash'li, zaman damgalı, kaynaklı.
   - *Otomatik değerlendirme* (`control_assessments.automated_*`): bir kural sürümünün kanıtlara
     uygulanmış yorumu; yeniden üretilebilir, motor ve katalog sürümüyle birlikte saklanır.
   - *Manuel inceleme* (`control_assessments.review_*`): yetkili kişinin kararı ve notu; otomatik sonucu
     ezmez, yanında durur.
3. **Her kontrol ayrı değerlendirilir.** Bir kontrolün sonucu başka bir kontrolden veya başka bir
   çerçeveden türetilmez; aynı ölçü (check) birden çok kontrolde kullanılsa da her kontrolün sonucu kendi
   satırında, kendi eşik ve uygulanabilirlik bilgisiyle hesaplanır.
4. **İşletim sisteminden bağımsız.** Ölçüler normalize olgular üzerinde çalışır: Linux paketleri ve
   Windows KB'leri aynı “güvenlik güncellemesi” olgusu, OSV ve MSRC bulguları aynı “bulgu” olgusudur.
   Platform yalnızca bir boyuttur (filtre ve rapor kırılımı), ayrı kod yolu değildir.
5. **Mevcut kurallara uyum:** iki veritabanı tek sorgu metni (`store/db.go` kuralları), UTC Unix saniye,
   `timeutil.Formatter` ile gösterim, tüm metinler i18n kataloğunda, güvenlik açığı verisi çevrilmez.

#### 4.1 Kanıt deposu (`store/evidence.go`, `compliance.Collector`)

`evidence_items` yalnızca eklenir (silme yalnızca saklama süresi budamasıyla). Alanlar: `kind`, `source`
(`agent`, `scanner`, `system`, `user`), `source_ref` (kaynak satır, tür başına benzersiz), `host_id` (yabancı anahtar
yok, sunucu silinse de kanıt kalır), `hostname`, `platform`, `subject`, `actor`, `outcome`, `occurred_at`,
`collected_at`, `payload` (JSON), `sha256`, `prev_sha256`.

Kanıt türleri: `update_job`, `change_job`, `vuln_resolved`, `audit_event`, `drift_detected`, `backup_result`,
`inventory_snapshot` (bir UTC gününün sunucu durumlarının hash'i), `manual`.

Kurallar:

- **Tek toplayıcı**: bakım döngüsü dakikada bir `Collector.Collect` çalıştırır (aynı anda tek çalıştırma). Her kaynağın
  bir imleci vardır (`compliance.state.*` ayar satırları, sistem ayarı değildir): işler `finished_at`, giderilen
  bulgular `resolved_at`, denetim kaydı `id`, sapmalar `first_seen`, yedekler `backup.last_at` / `last_error_at`,
  günlük envanter `day`. Dolu olmayan bir okumadan sonra son iki dakika yeniden okunur; `(source_ref, kind)` benzersiz
  olduğundan tekrar eklenmez. Böylece mevcut işlemlere dokunulmadan, geç işlenen satırlar da kaçırılmadan toplanır.
- **Hash zinciri**: `sha256` kaydın tüm alanlarını ve `prev_sha256`'yı kapsar. Zincir başı `compliance.state.chain_head`
  satırında tutulur ve yazma işleminde `FOR UPDATE` ile kilitlenir; satırlar tek tek eklenir, böylece kimlik sırası zincir
  sırasıdır. `VerifyEvidence` içerik, bağlantı ve zincir başını denetler (`content`, `link`, `head`).
- **Geriye dönük toplama**: ilk çalıştırmada henüz silinmemiş geçmiş kayıtlar aktarılır; `collected_at - occurred_at`
  bir günden uzunsa kanıt “geriye dönük” gösterilir.
- **Manuel kanıt**: belge dosyası saklanmaz; ad, tarih, konum/referans, açıklama ve eşlenen kontroller
  (`profil:KONTROL`) bir `manual` kanıtı olarak zincire eklenir. Yedekleme, geri yükleme ve veritabanı aktarımı ek dosya
  gerektirmez.
- Gizli bilgi kanıta yazılmaz (API anahtarı, oturum, kanal sırları, parolalar).

#### 4.2 Platform sınıflandırması

`compliance.Platform(h store.Host) string` — saf fonksiyon, tablo testli:

- `OSID != "windows"` → `linux`
- `OSName` “Windows Server” ile başlıyorsa → `windows_server`
- “Windows 11” → `windows_11`; “Windows 10” → `windows_10` (ajan, 22000+ yapılarda adı zaten düzeltir;
  eski ajanlar için yapı numarası `OSVersionID` üzerinden ikinci kez kontrol edilir)
- diğer → `windows_other`

Ajanda değişiklik gerekmez. İleride `HostInfo` alanına `InstallationType` (Client/Server/Server Core)
eklenirse sınıflandırıcı önce onu kullanır; eski ajanlar adla çalışmaya devam eder.

#### 4.3 Günlük sunucu durumu (`evidence_host_states`)

Geçmiş bir dönemin varlık envanterini ve güncelleme durumunu, işletim verisi budanmış olsa bile
gösterebilmek için bakım döngüsündeki `TakeSnapshot` adımı aynı işlemde sunucu başına bir satır yazar:
`(host_id, day)` anahtarı, `hostname`, `platform`, `os_name`, `os_version`, `agent_version`, `last_seen`,
bekleyen güvenlik güncellemesi sayısı, önem derecesine göre açık bulgu, KEV, SLA'sı geçmiş bulgu,
`reboot_required`, EOL durumu, grup kimlikleri. 500 sunucu × 730 gün ≈ 365 bin satır; sorun değil.
`daily_snapshots` filo toplamı olarak gösterge paneli için kalır; ikisi aynı adımda, aynı veriden yazılır.

#### 4.4 Çerçeve profilleri (sürümlü)

Gömülü JSON: `internal/compliance/profiles/<id>.json`. Kimlik `id@version` (ör. `isms@1`). Bir kontrol, kullandığı
ortak ölçümleri ve ilişkiyi (`primary` sonucu belirler, `supporting` yalnızca kanıt ekler), gerekirse platform sınırını
(`platforms`) ve gereken manuel belgeyi (`manual`: `policy`, `process`) listeler. Başlık ve açıklamalar i18n
kataloğundadır (`compliance.control.<profil>.<kontrol>` ve `.desc`), netio.patchman'in kendi ifadeleridir.

| Profil | Tarafsız ad | Kontrol | Kapsam |
|---|---|---|---|
| `isms@1` | Bilgi Güvenliği Yönetimi Denetimleri | ISMS-01 … ISMS-12 | envanter, açıklık yönetimi, yapılandırma, yazılım değişiklikleri, değişiklik yönetimi, kayıt, izleme, yedekleme, kimlik doğrulama, yaşam döngüsü, risk işleme, politikalar (manuel) |
| `baseline@1` | BT Temel Koruma Denetimleri | BASE-01 … BASE-12 | yama ve değişiklik, zamanında güvenlik güncellemesi, Linux sunucular, Windows sunucular, Windows istemciler (platform sınırlı), yönetim ve envanter, kayıt, yedekleme, kimlik, olay tespiti, standartlar, belgelenmiş konsept (manuel) |
| `itsm@1` | BT Hizmet Yönetimi Değerlendirmeleri | ITSM-01 … ITSM-08 | değişiklik etkinleştirme, sürüm ve dağıtım, yapılandırma, varlık yönetimi, izleme, bilgi güvenliği, hizmet seviyeleri, olay ve sorun süreci (manuel) |
| `general@1` | Genel Güvenlik ve Yama Uyumu | GEN-01 … GEN-12 | SLA, KEV, güncellik, iş başarısı, EOL, ajan kapsamı, yeniden başlatma, riskler, MFA, yedekleme, kanıt bütünlüğü, izleme |

- Uygulanabilirlik kurulumun ayarıdır (`compliance_control_settings`: `applicable`, zorunlu `justification`).
- `TestProfilesValid` (benzersiz kimlikler, kayıtlı ölçümler, geçerli platformlar, her kontrolde birincil ölçüm veya
  manuel kanıt) ve `TestCatalogKeys` (çalışma anında kurulan bütün anahtarlar dört katalogda) profilleri denetler.
- Yeni bir profil sürümü yeni bir dosyadır; eski rapor sürümleri değişmez.

#### 4.5 Ortak ölçüler (`internal/compliance/checks`)

Bir ölçü (check) çerçeveden habersizdir: dönem, kapsam (grup/sunucular/platformlar) ve politika eşiklerini
alır; `CheckResult{Metrics, Outcome, EvidenceIDs, Gaps}` döndürür. Örnekler:

| Ölçü | Kaynak | Çıktı |
|---|---|---|
| `inventory.completeness` | `evidence_host_states` | platform kırılımlı varlık sayısı, raporlamayan sunucular |
| `agent.coverage` | host states (`last_seen`) | dönem içinde erişilemeyen gün oranı |
| `patch.security_applied` | `patch_applied/failed` kanıtları | uygulanan/başarısız güvenlik güncellemeleri, platforma göre |
| `vuln.sla_compliance` | `vuln_detected/resolved` + `store.SLA` | SLA içinde kapatılan oran, geciken bulgular |
| `vuln.kev_overdue` | bulgu kanıtları + KEV | CISA son tarihi geçmiş açık KEV |
| `risk.accepted_valid` | `risk_accepted/expired` | süresi dolmuş veya gerekçesiz kabul edilen risk |
| `eol.unsupported` | `eol_status` | desteği bitmiş sistemler ve yazılımlar |
| `change.recorded` | `job_change` + `audit_event` | kullanıcıya bağlı değişiklik oranı, önizleme/onay, bakım penceresi dışı değişiklik |
| `change.rollback_ready` | rollback kanıtları | geri alma denemeleri ve sonuçları |
| `config.drift` | `drift_*` | açık sapmalar ve süreleri |
| `access.mfa_admins` | kullanıcı durumu + `access_event` | MFA'sız yönetici sayısı |
| `backup.daily` | `backup_result` | başarısız/eksik yedek günleri |
| `log.integrity` | `evidence.Verify` | zincir bütünlüğü, kayıt boşlukları |
| `monitoring.health` | sağlık/kaynak kanıtları | izleme kapsamı ve uyarılar |

Sonuç değerleri (`Outcome`): `evidence_sufficient`, `partial`, `deviation`, `evidence_missing`,
`not_applicable`, `manual_required`. Kontrol sonucu, kontrolün ölçülerinden kurala göre hesaplanır
(en kötü `primary` sonuç belirleyicidir; `supporting` ölçüler sonucu iyileştiremez, yalnızca kanıt ekler).

#### 4.6 Saklama

- Kanıt deposu işletim verisinin budamasından bağımsızdır: `compliance.evidence_days` (varsayılan 1095, en az 400).
  Günlük sunucu durumları da aynı süreyle tutulur.
- Kesinleşmiş rapor sürümlerinin kullandığı kanıtlar budanmaz. Budama sınırı `compliance.state.pruned_id`'de tutulur;
  bütünlük denetimi sınırın altındaki kayıtlarda yalnızca içeriği, üstünde bağlantıyı da denetler.
- Denetim kaydı (`audit_log`) 365 günlük budamayı korur; kayıtlar `audit_event` kanıtı olarak kanıt deposunda kalır.

---

### 5. Raporlama motoru ve rapor yapısı

#### 5.1 Rapor oluşturma

`/compliance/reports/new` formu:

- **Çerçeveler** (bir veya birden fazla, çoklu seçim): Bilgi Güvenliği Yönetimi Denetimleri · BT Temel Koruma
  Denetimleri · BT Hizmet Yönetimi Değerlendirmeleri · Genel Güvenlik ve Yama Uyumu. Yalnızca Uyum Politikaları'nda etkin olanlar listelenir.
- **Denetim dönemi:** hazır seçenekler (son 30/90 gün, son çeyrek, son 12 ay, takvim yılı) veya özel
  başlangıç–bitiş (gösterim saat diliminde gün sınırları, UTC saklanır; en fazla 731 gün).
- **Kapsam:** tüm filo / grup(lar) / platform(lar) (Linux, Windows Server, Windows 10, Windows 11).
- **Başlık** ve isteğe bağlı not.

Birden fazla çerçeve seçildiğinde motor kanıtları ve ölçüleri **bir kez** hesaplar; her çerçeve yalnızca
kendi kontrol listesini bu ortak sonuçlara uygular. Sonuç tek rapor, tek sürüm, tek dosyadır.

Oluşturma istek içinde çalışır (bir kez ölçülen kanıtlar üzerinde); sürüm numarası rapor satırı kilitlenerek verilir.

#### 5.2 Birleşik rapor bölümleri

| # | Bölüm | Kaynak |
|---|---|---|
| 1 | Yönetici Özeti | ölçü sonuçlarının özeti, çerçeve başına kontrol dağılımı (sayılar, hüküm değil), en önemli eksikler |
| 2 | Rapor Kapsamı ve Değerlendirme Dönemi | dönem, kapsam, seçilen çerçeveler ve katalog sürümleri, motor sürümü, kanıt toplamanın başladığı tarih (dönemden sonraysa uyarı) |
| 3 | Yönetilen Varlık Envanteri | `inventory.completeness`, platform kırılımı |
| 4 | Linux ve Windows Güncelleme Durumu | host states + `patch.*`, platforma göre |
| 5 | Güvenlik Açığı Yönetimi | bulgu akışı (mevcut `FindingFlow`), KEV (`OpenKEV`), önem dağılımı, eğilimler (mevcut `buildTrends`) |
| 6 | Yama Uyumu (Patch Compliance) | `patch.security_applied`, başarısız/kısmi işler |
| 7 | Güvenlik Güncellemesi SLA'sı | `vuln.sla_compliance`, geciken bulgular |
| 8 | Desteği Biten Sistemler (EOL) | `eol.unsupported` |
| 9 | Değişiklik Yönetimi | `change.*`: işler, önizleme/onay, zamanlamalar ve bakım pencereleri, kademeli güncellemeler, geri almalar, kim başlattı |
| 10 | Denetim Kayıtları | `audit_event` özeti, `log.integrity` |
| 11 | Kontrol Değerlendirmeleri | çerçeve başına ayrı tablo: ref · kısa tanım · otomatik sonuç · ilgili ölçüler ve `relevance` · manuel inceleme · uygulanabilirlik gerekçesi |
| 12 | Toplanan Teknik Kanıtlar | kanıt dizini: kimlik, tür, zaman, sunucu, hash, eşlendiği kontroller (`profil:KONTROL`) |
| 13 | Eksik Kanıtlar ve İyileştirme Önerileri | `evidence_missing`, `manual_required`, `deviation` kontrolleri ve somut adımlar (katalog anahtarlı öneriler) |

Her raporun başında ve her dışa aktarımın içinde sabit uyarı metni (katalogdan): rapor otomatik toplanan
teknik kanıtlara dayanır, bir belgelendirme veya uygunluk beyanı değildir, kararlar yetkili denetçiye aittir.

#### 5.3 Rapor ve sürüm modeli

| Tablo | Alanlar |
|---|---|
| `compliance_reports` | `id`, `title`, `profiles` (JSON: `["isms@1", …]`), `period_from`, `period_to` (hariç), `scope` (JSON: grup, platformlar), `note`, `created_by`, `created_by_email`, `created_at` |
| `compliance_report_versions` | `id`, `report_id`, `version` (1, 2, …), `status` (`draft`/`final`), `generated_at`, `generated_by`, `engine`, `content` (JSON rapor modeli), `sha256`, `finalized_at`, `finalized_by`, `final_sha256` |
| `control_assessments` | `version_id`, `profile`, `control`, `outcome` (otomatik), `applicable`, `review_status` (`not_reviewed`/`accepted`/`gap`), `review_note`, `reviewed_by`, `reviewed_at` |
| `assessment_evidence` | `version_id`, `profile`, `control`, `evidence_id`, `relevance` (`primary`, `supporting`, `manual`): “her kanıt hangi kontrole eşlendi” kaydı |
| `compliance_control_settings` | `profile`, `control`, `applicable`, `justification`, `updated_by`, `updated_at` |

- Yeniden oluşturma her zaman yeni sürüm açar; eski sürümler silinmez ve değişmez.
- `final` sürüm değiştirilemez; manuel incelemeler yalnızca `draft` sürüme yazılır, kesinleştirmede donar.
- Dışa aktarımlar **saklanan içerikten** üretilir, yeniden hesaplanmaz: aynı sürümün PDF/CSV/JSON'u her
  zaman aynı veridir; sürüm hash'i her çıktıda yazılıdır.

#### 5.4 Dışa aktarma

| Biçim | İçerik |
|---|---|
| JSON | kanonik rapor modeli, şema kimliği `netio.patchman/compliance-report/v1`; alan adları İngilizce ve kararlı (`docs/api.md`'de belgelenir) |
| CSV | ZIP içinde ayrı dosyalar: `controls.csv`, `evidence.csv`, `findings.csv`, `assets.csv`, `changes.csv`; ayırıcı `csv.separator`, tarih `format.datetime` |
| PDF | sunucuda üretilir (tarayıcıdan yazdırma da kalır); saf Go kütüphane (aday: `github.com/go-pdf/fpdf`, lisansı Faz 0'da doğrulanır), Türkçe karakterler için gömülü açık lisanslı yazı tipi; harici kaynak yok (hava boşluklu kurulumlar) |

Güvenlik açığı verisi (CVE kimliği, resmi başlık, CVSS) tüm biçimlerde çevrilmeden ve `9.8` noktalı
biçimde kalır. İndirmeler denetim kaydına yazılır (`compliance.export`).

---

### 6. Sayfalar

- **Genel Bakış** (`/compliance`): son kesinleştirilmiş rapor sürümleri; çerçeve başına kontrol sonuç
  dağılımı (sayı ve etiket, renk tek başına anlam taşımaz); eksik kanıt sayısı; yaklaşan SLA ihlalleri;
  kanıt zinciri doğrulama durumu; kanıt toplamanın başlangıç tarihi.
- **Uyum Raporları** (`/compliance/reports`): liste (başlık, çerçeveler, dönem, son sürüm, durum);
  rapor sayfası (sürüm seçici, bölümler, kontrol tabloları, manuel inceleme formu, dışa aktarma düğmeleri);
  sürüm karşılaştırma (iki sürüm arasında değişen kontrol sonuçları).
- **Denetim Kanıtları** (`/compliance/evidence`): filtreler (tür, kaynak, sunucu, platform, dönem,
  çerçeve/kontrol); kanıt ayrıntısı (payload, hash, zincir konumu, eşlendiği kontroller ve raporlar);
  manuel kanıt yükleme ve kontrol(ler)e eşleme.
- **Denetim Geçmişi** (`/compliance/history`): sekmeler — rapor sürümleri ve değerlendirme çalıştırmaları;
  kullanıcı denetim kaydı (taşınan `/settings/audit`); zincir doğrulama çalıştırmaları.
- **Uyum Politikaları** (`/compliance/policies`): etkin çerçeveler ve katalog sürümleri; kontrol başına
  uygulanabilirlik + gerekçe (Statement of Applicability benzeri liste); eşikler — mevcut ayarlar (SLA
  günleri, risk süresi, yedekleme, MFA zorunluluğu) burada **okunur ve bağlantıyla** düzenlenir, kopya
  ayar yoktur; sunucu standartları (taşınan `/standards`).

REST API (`/api/v1/compliance/…`, mevcut anahtar modeli, salt okunur anahtarlar POST yapamaz):
`GET reports`, `GET reports/{id}`, `GET reports/{id}/versions/{n}` (JSON modeli),
`GET reports/{id}/versions/{n}/export?format=pdf|csv|json`, `POST reports` (taslak/yeni sürüm),
`GET evidence`, `GET evidence/{id}`.

---

### 7. Paket ve dosya düzeni

```
internal/store/evidence.go     platform sınıflandırması, kanıt deposu, hash zinciri, toplama, günlük sunucu durumları
internal/store/compliance.go   raporlar, sürümler, değerlendirmeler, uygulanabilirlik, ölçümlerin canlı sorguları
internal/compliance/           profiller (profiles/*.json), ölçümler (checks.go), motor (engine.go), rapor modeli,
                               toplayıcı (collector.go), JSON/CSV (export.go), PDF (pdf.go, fonts/)
internal/store/migrations/0022_compliance.sql + migrations/postgres/0022_compliance.sql
internal/web/pages_compliance.go + templates/compliance*.html
```

Kaldırılan: `web/pages_reports.go`, `templates/report.html`, `templates/audit.html` (denetim kaydı Denetim
Geçmişi'nde), eski `report.*` katalog anahtarları. `/reports` ve `/settings/audit` yeni adreslere yönlenir.

---

### 8. Uygulama durumu

Tek sürümde uygulandı: migrasyon `0022_compliance` (SQLite ve PostgreSQL), `store/evidence.go`, `store/compliance.go`,
`internal/compliance` (profiller, ölçümler, motor, dışa aktarma, toplayıcı), `web/pages_compliance.go` ve
`compliance*.html`, REST API, dört dilde katalog, belgeler. PDF sunucuda saf Go ile (`github.com/go-pdf/fpdf`, MIT) ve
gömülü DejaVu Sans yazı tipiyle (Bitstream Vera lisansı, `internal/compliance/fonts/LICENSE`) üretilir.

Testler: hash zinciri (değiştirme, silme, sondan silme), budama ve kesin sürüm koruması, veritabanı aktarımı sonrası zincir,
platform sınıflandırması, profil ve katalog denetimi, uçtan uca rapor akışı (dört çerçeve tek raporda, aynı Windows
güncellemesinin dört çerçevenin kontrolüne eşlenmesi, platform sınırlı rapor, inceleme aktarımı, manuel kanıt,
kesinleştirme, dışa aktarımların aynı kalması, uygulanabilirlik, eşikler, grup sınırlı kullanıcı, API).

---

### 9. Ortadan kaldırılan tekrarlar

| Tekrar riski | Bu planda |
|---|---|
| Çerçeveler için ayrı menüler ve sayfalar | Yok; çerçeve rapor parametresidir |
| Standart başına veri toplayıcı veya tablo | Yok; tek `evidence_items`, tek toplayıcı |
| Standart başına rapor şablonu ve dışa aktarma | Yok; tek rapor modeli, tek dışa aktarma katmanı |
| Ayrı “uyumluluk raporu” ve “denetim raporu” | Tek Uyum Raporları bölümü |
| Denetim kaydının iki yerde gösterilmesi | Yalnızca Denetim Geçmişi'nde |
| SLA / risk / MFA eşiklerinin uyum için ikinci kopyası | Yok; mevcut ayarlar okunur |
| Sunucu standartlarının ayrı menüde kalması | Uyum Politikaları altında |
| Filo eğilimleri için ikinci anlık görüntü sistemi | Yok; `daily_snapshots` ve `evidence_host_states` aynı bakım adımında |
| Rapor sorgularının yeniden yazılması | Yok; `store/reports.go` sorguları ölçülerde yeniden kullanılır |

---

### 10. Riskler ve açık sorular

1. **Geriye dönük kanıt:** Kanıt toplama başlamadan önceki dönem için yalnızca henüz budanmamış kayıtlar aktarılabilir;
   günlük sunucu durumları geriye dönük üretilemez. Rapor bu durumu uyarı olarak gösterir.
2. **Windows istemcileri:** Windows 10/11 cihazlar sürekli açık değildir; erişim kapsamı eşiği tektir. Gerekirse platform
   bazlı eşik eklenebilir.
3. **Performans:** Rapor üretimi istek içinde çalışır; 500+ sunucu ve 12 aylık dönemde süresi ölçülmeli, gerekirse arka
   plana alınmalıdır.
4. **Hash zinciri ve PostgreSQL eşzamanlılığı:** zincir başı kilidi yazma hızını sınırlar; olay hacmi bunun çok altındadır.

### 11. Kabul ölçütleri (özet)

- Menüde tek **Uyum ve Denetim** grubu ve beş bölüm var; standart başına menü yok.
- Bir rapor bir veya birden çok çerçeveyle oluşturulur; tek rapor, tek sürüm, çerçeve başına ayrı kontrol
  tabloları.
- Bir Windows güvenlik güncellemesinin başarılı uygulanması tek bir `update_job` kanıtıdır ve aynı raporda ISMS-02,
  BASE-01, ITSM-01 ve GEN-04 satırlarında kendi `relevance` değeriyle görünür; bu kontrollerin hiçbiri yalnızca bu
  kanıtla “tamam” sayılmaz.
- Linux, Windows Server, Windows 10 ve Windows 11 sunucuları aynı rapordadır ve platforma göre süzülebilir.
- Kanıt, otomatik değerlendirme ve manuel inceleme ayrı saklanır ve ayrı gösterilir.
- Rapor sürümleri saklanır, final sürüm değişmez; PDF, CSV ve JSON aynı sürümden aynı içeriği verir.
- Hiçbir çıktıda sertifika veya tam uygunluk ifadesi yok; uyarı metni her çıktıda var.
- `go test ./...` SQLite ve PostgreSQL'de geçer; tüm yeni metinler dört katalogda.

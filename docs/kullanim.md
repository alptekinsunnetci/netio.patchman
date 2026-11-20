# netio.patchman Kullanım Kılavuzu

Bu belge, yönetim panelinin günlük kullanımını anlatır.

## Roller

| Rol | Yetkiler |
|---|---|
| **Yönetici** | Tüm işlemler: kullanıcı yönetimi, sistem ayarları, kayıt anahtarları, zamanlanmış güncellemeler, sunucu kaldırma |
| **Operatör** | Görüntüleme, güncelleme işi başlatma, envanter yenileme, bulgu durumunu değiştirme |
| **İzleyici** | Yalnızca görüntüleme ve CSV dışa aktarma |

## Gösterge Paneli

Altyapının genel durumunu gösterir:

- **Kritik Güvenlik Açığı:** Çözüm bekleyen kritik açıkların sayısı.
- **İstismar Edilen Açık:** CISA KEV kataloğunda yer alan, yani aktif olarak istismar edildiği bilinen açıklar. Bu açıklar her zaman önceliklidir.
- **Bekleyen Güvenlik Güncellemesi:** Dağıtımın güvenlik deposundan gelen ve henüz kurulmamış güncellemeler.
- **Çevrimdışı Ajan:** Belirlenen süre içinde bağlanmayan ajanlar.

Kartlara tıklayarak ilgili filtrelenmiş listeye geçebilirsiniz.

## Sunucu Envanteri

Her sunucu için işletim sistemi, son bağlantı zamanı, açık güvenlik açıkları (önem derecesine göre) ve bekleyen güncellemeler listelenir. Sunucu adına tıklayarak ayrıntı sayfasını açın:

- **Güvenlik Açıkları:** Bu sunucudaki bulgular.
- **Bekleyen Güncellemeler:** Güncellenebilir paketler. Paketleri seçip **Seçili paketleri güncelle** ile yalnızca bunları kurabilirsiniz.
- **Kurulu Paketler:** Tüm paketler ve sürümleri.
- **İşlem Geçmişi:** Bu sunucuda çalıştırılan işler.
- **Sistem Bilgisi:** Donanım, ajan bilgileri ve notlar.

Sayfanın üst kısmındaki düğmeler:

- **Envanteri yenile:** Ajandan paket listesini hemen yeniden göndermesini ister.
- **Güvenlik güncellemelerini uygula:** Yalnızca güvenlik güncellemelerini kurar.
- **Tüm güncellemeleri uygula:** Bekleyen tüm güncellemeleri kurar.

### Birden çok sunucuda toplu işlem

Sunucu Envanteri listesinde sunucuları işaretleyin (başlıktaki kutu, sayfadaki tüm sunucuları seçer). Ardından üstteki **Seçili sunucularda** çubuğundan işlemi seçip **Uygula**'ya basın:

- Güvenlik güncellemeleri
- Tüm güncellemeler
- Envanter yenileme
- Ajan güncellemesi

Filtrelerle birlikte kullanıldığında örneğin "Güncelleme bekleyen tüm Ubuntu sunucularında güvenlik güncellemelerini uygula" işlemi birkaç tıklamayla yapılır. Uzaktan güncellemesi kapalı sunucular atlanır ve sonuç mesajında listelenir.

“Yeniden başlatma gerekli” etiketi, kurulan güncellemelerin (örneğin çekirdek) etkinleşmesi için sunucunun yeniden başlatılması gerektiğini gösterir. netio.patchman sunucuları kendiliğinden yeniden başlatmaz.

## Güvenlik Açıkları

Tespit edilen açıklar en kritik olandan başlayarak listelenir. Aktif olarak istismar edilen açıklar **KEV** etiketiyle işaretlenir.

Bir açığın ayrıntı sayfasında:

- **Orijinal Açıklama:** CVE kaydındaki resmî açıklama, kaynağındaki dilde (genellikle İngilizce) ve değiştirilmeden gösterilir.
- **Güvenlik Önerisi:** Hangi paketin hangi sürüme güncellenmesi gerektiği.
- **Üretici Güvenlik Duyurusu:** Dağıtımın yayımladığı duyurular (DSA, USN, ALSA, RHSA vb.).
- **Etkilenen Sunucular:** Kurulu ve düzeltilmiş sürümleriyle birlikte.

Sunucuda birden fazla çekirdek kuruluysa yalnızca **çalışan çekirdek** (`uname -r`) taranır. Eski çekirdek paketleri güncellenemez, yalnızca kaldırılabilir; taranmaları yeni çekirdek kurulup çalışsa bile açıkların açık kalmasına yol açardı. Yeni çekirdek kurulmuş ama sunucu henüz yeniden başlatılmamışsa çalışan eski çekirdeğin açıkları, yeniden başlatılana kadar açık kalır. Çalışan çekirdek paket yöneticisiyle kurulmamışsa (WSL, konteyner, özel çekirdek) tüm paketler taranır.

Ubuntu'da çekirdek açıkları `linux` kaynak paketi altında gösterilir ve sayıları binlerle ifade edilebilir; bu, Ubuntu güvenlik verisinin yapısından kaynaklanır. İlk tarama bu nedenle birkaç dakika sürebilir; sonraki taramalar önbellekten yapılır.

**Düzeltmeyi uygula** düğmesi, düzeltilmiş sürümün depoda hazır olduğu tüm etkilenen sunucularda ilgili paketleri günceller. Debian, Ubuntu ve Alpine'de açıklar kaynak paket adıyla gösterilir (örneğin `openssl`); netio.patchman bu kaynaktan derlenen ikili paketleri (`libssl3`, `openssl`) otomatik olarak belirler.

### Çözüm durumları

| Durum | Anlamı |
|---|---|
| Açık | Yeni tespit edilmiş, işlem bekliyor |
| İşlemde | Üzerinde çalışılıyor |
| Risk Kabul Edildi | Değerlendirildi, şimdilik giderilmeyecek (açıklama zorunlu) |
| Hatalı Tespit | Sunucuyu etkilemediği doğrulandı (açıklama zorunlu) |
| Çözüldü | Paket güncellendi; netio.patchman bunu otomatik olarak belirler |

Risk Kabul Edildi ve Hatalı Tespit durumundaki bulgular sayımlara ve bildirimlere dahil edilmez. Çözülen bir açık yeniden tespit edilirse otomatik olarak tekrar açılır.

## Paket Yönetimi

- **Bekleyen Güncellemeler:** Tüm sunuculardaki güncellemeler paket bazında toplanır. **Tüm sunucularda güncelle** ile bir paketi her yerde güncelleyebilir, **Tüm güvenlik güncellemelerini uygula** ile bütün sunucularda güvenlik güncellemelerini başlatabilirsiniz.
- **Paket ayrıntısı:** Paket adına tıkladığınızda güncelleme bekleyen sunucular listelenir. Sunucuları işaretleyip **Seçili sunucularda güncelle** ile paketi yalnızca bu sunucularda güncelleyebilirsiniz (örneğin önce test sunucularında).
- **Kurulu Paket Ara:** Bir paketin hangi sunucuda hangi sürümle kurulu olduğunu bulun.

## Zamanlanmış Güncellemeler

Güncellemeleri belirli gün ve saatlerde, bakım penceresi içinde otomatik uygulamak için **Zamanlanmış Güncellemeler** sayfasında kural oluşturun (yalnızca yöneticiler). Örnek: “Her pazar 03:00'te Ubuntu sunucularında güvenlik güncellemelerini uygula, bakım penceresi 2 saat.”

| Alan | Açıklama |
|---|---|
| İşlem | Güvenlik güncellemeleri veya tüm güncellemeler |
| Günler, Başlangıç saati | Kuralın çalışacağı günler ve saat (`PATCHMAN_TIMEZONE`, varsayılan Europe/Istanbul) |
| Bakım penceresi | Ajanın işi alabileceği süre (15 dakika – 24 saat) |
| Kapsam | Tüm sunucular, belirli bir işletim sistemi (örneğin `ubuntu`) veya seçili sunucular |

Nasıl çalışır:

- Başlangıç saatinde, kapsamdaki ve ilgili türde bekleyen güncellemesi olan her sunucu için bir iş oluşturulur. Güncel sunucularda iş oluşturulmaz.
- Uzaktan güncellemesi kapalı sunucular ve aynı türde bekleyen işi olan sunucular atlanır.
- Ajan bakım penceresi içinde bağlanmazsa iş çalıştırılmaz ve **Süresi doldu** olarak işaretlenir. Böylece kapalı olan bir sunucu açıldığında güncelleme mesai saatine kaymaz. Pencere içinde başlayan bir iş, pencere bitse de tamamlanır.
- Merkezi sunucu bakım penceresi boyunca kapalıysa o çalışma atlanır ve bildirim merkezine uyarı düşer.
- Her çalışma için bildirim merkezine tek bir özet bildirimi düşer. Başarılı işler ayrıca bildirim üretmez; başarısız işler her zamanki gibi bildirilir ve e-postayla gönderilir.
- **Şimdi çalıştır** düğmesi kuralı hemen çalıştırır (bakım penceresi o andan başlar); normal zamanlama değişmez.
- Bir zamanlama silinirse henüz ajana iletilmemiş işleri iptal edilir; tamamlanmış işlerin geçmişi korunur.

netio.patchman sunucuları yeniden başlatmaz. Çekirdek güncellemelerinden sonra yeniden başlatmayı ayrıca planlayın; gereken sunucular “Yeniden başlatma gerekli” etiketiyle gösterilir. Bir sunucuyu kapsayan zamanlamalar, sunucu ayrıntısındaki **Sistem Bilgisi** sekmesinde listelenir.

## Güncelleme İşleri

Panelden veya bir zamanlamayla başlatılan her işlem bir iştir. İşler ajanın bir sonraki bağlantısında (varsayılan olarak en geç bir dakika içinde) çalıştırılır. İş sayfasında komut çıktısı, çıkış kodu ve süreler görüntülenir. Henüz ajana iletilmemiş işler iptal edilebilir. Ajan 3 saat içinde sonuç bildirmezse iş “Zaman aşımı” olarak işaretlenir. Zamanlamayla oluşturulan işlerde “Başlatan” sütununda zamanlamanın adı görünür.

Ajanlar sunucularda port açmaz. Merkezi sunucuya düzenli aralıklarla HTTPS ile bağlanır, bekleyen işleri alır ve sonuçları bildirir. Bu yüzden yönetilen sunuculara dışarıdan erişim gerekmez; yalnızca ajanın merkezi sunucuya erişebilmesi yeterlidir.

İş tamamlandığında ajan envanteri hemen yeniden gönderir ve güvenlik taraması güncellenir.

## Ajan Yönetimi

- **Kayıt anahtarları:** Yeni sunucuların kaydolması için kullanılır. Anahtar yalnızca oluşturulduğu anda gösterilir. Geçerlilik süresi ve kullanım sınırı verilmesi önerilir. Bir anahtarın iptal edilmesi kayıtlı ajanları etkilemez.
- **Ajanlar:** Ajan sürümleri, otomatik güncelleme ve uzaktan güncelleme durumları, son bağlantı zamanları. Eski sürümdeki ajanlar "Eski sürüm" etiketiyle gösterilir.
- **Ajan güncellemeleri:** Sunucunun dağıttığı ajan sürümü ve eski sürümdeki ajan sayısı. Otomatik güncelleme açıksa ajanlar kendiliğinden güncellenir; kapalıysa **Eski ajanları güncelle** düğmesi tüm eski ajanlar için güncelleme başlatır.

## Bildirim Merkezi ve e-postalar

Bildirim merkezi şu olayları gösterir: yeni güvenlik açıkları, ajan bağlantısının kesilmesi ve geri gelmesi, yeni sunucu kayıtları, iş sonuçları, tarama ve e-posta hataları.

E-posta bildirimleri **Sistem Ayarları** sayfasında yapılandırılır:

- **En düşük önem derecesi:** Bu derecenin altındaki açıklar için e-posta gönderilmez.
- **İstismar edilen açıklar:** KEV kataloğundaki açıklar için önem derecesinden bağımsız olarak e-posta gönderilir.
- **Özet e-posta eşiği:** Bir taramada çok sayıda yeni açık bulunursa (örneğin yeni eklenen bir sunucuda) her biri için ayrı e-posta yerine tek bir özet gönderilir.
- **Alıcılar:** Boş bırakılırsa tüm etkin yöneticilere gönderilir.

E-postaların gönderileceği SMTP sunucusu **Sistem Ayarları → Sunucu yapılandırması** sayfasında tanımlanır. Bu sayfada ayrıca sunucu adresi, saat dilimi, günlük seviyesi, ters vekil ayarı ve güvenlik açığı veri kaynakları (OSV, CISA KEV) bulunur. Değişiklikler yeniden başlatma gerektirmeden uygulanır. Ayarları kaydettikten sonra aynı sayfadan bir deneme e-postası gönderebilirsiniz.

Örnek e-posta konusu:

```
[KRİTİK] CVE-2026-12345 - 12 sunucuda güvenlik açığı tespit edildi
```

## Denetim Kayıtları

**Sistem Ayarları → Denetim Kayıtları** sayfasında girişler, başarısız giriş denemeleri, kullanıcı ve ayar değişiklikleri, başlatılan işler, kayıt anahtarı işlemleri ve sunucu kaldırma işlemleri kullanıcı ve IP adresiyle birlikte listelenir.

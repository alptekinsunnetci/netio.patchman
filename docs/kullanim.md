# netio.patchman Kullanım Kılavuzu

Bu belge, yönetim panelinin günlük kullanımını anlatır.

## Roller

| Rol | Yetkiler |
|---|---|
| **Yönetici** | Tüm işlemler: kullanıcı yönetimi, sistem ayarları, kayıt anahtarları, zamanlanmış güncellemeler, sunucu kaldırma |
| **Operatör** | Görüntüleme, güncelleme işi başlatma, envanter yenileme, bulgu durumunu değiştirme |
| **İzleyici** | Yalnızca görüntüleme ve CSV dışa aktarma |

### Grup bazlı erişim

Bir operatör veya izleyici yalnızca belirli gruplardaki sunucularla sınırlandırılabilir (ör. web ekibi yalnızca "Web" grubunu, bir müşteri yalnızca kendi grubunu görür). **Kullanıcı Yönetimi → kullanıcı → Sunucu erişimi → Yalnızca seçili gruplardaki sunucular** seçilip gruplar işaretlenir.

Sınırlı kullanıcı:

- yalnızca bu gruplardaki sunucuları, onların bulgularını, güncellemelerini, işlerini ve bu sunucularla ilgili bildirimleri görür; iş başlatma, durum değiştirme ve **Düzeltmeyi uygula** da yalnızca bu sunucularda çalışır,
- zamanlamaları, ajan yönetimini ve filo geneli eğilim grafiklerini görmez,
- API anahtarları da aynı sınırla çalışır.

Gruptan çıkarılan sunucu bu kullanıcılara görünmez olur. Hiç grup seçilmemiş sınırlı kullanıcı hiçbir sunucu görmez. Yöneticiler her zaman tüm sunucuları görür.

## Gösterge Paneli

Altyapının genel durumunu gösterir:

- **Kritik Güvenlik Açığı:** Çözüm bekleyen kritik açıkların sayısı.
- **İstismar Edilen Açık:** CISA KEV kataloğunda yer alan, yani aktif olarak istismar edildiği bilinen açıklar. Bu açıklar her zaman önceliklidir.
- **Bekleyen Güvenlik Güncellemesi:** Dağıtımın güvenlik deposundan gelen ve henüz kurulmamış güncellemeler.
- **Çevrimdışı Ajan:** Belirlenen süre içinde bağlanmayan ajanlar.
- **Yeniden Başlatma Bekleyen:** Yeni çekirdek veya mikro kod kurulmuş ama henüz yeniden başlatılmamış sunucular ve en eskisinin ne zamandan beri beklediği.

Kartlara tıklayarak ilgili filtrelenmiş listeye geçebilirsiniz.

**Takip ettiğim paketler** bölümü, nginx veya mariadb gibi özellikle izlemek istediğiniz paketlerin tüm sunuculardaki durumunu gösterir: kaç sunucuda kurulu olduğu, kaç farklı sürümün çalıştığı, kaç sunucuda güncelleme beklediği ve açık güvenlik açıklarının sayısı ile en yüksek önem derecesi. Bir paketi takibe almak için sunucunun **Kurulu Paketler** sekmesinde, **Paket Yönetimi** sayfasında ya da paket sayfasında adın yanındaki yıldıza tıklayın. Yıldıza yeniden tıklamak paketi listeden çıkarır. Liste kişiseldir: her kullanıcının listesi ayrıdır ve izleyici rolündeki kullanıcılar da kendi listelerini tutabilir. Bir kullanıcı en fazla 100 paket takip edebilir. Gruplarla sınırlandırılmış kullanıcılar yalnızca kendi sunucularındaki durumu görür.

**Günlük eğilim** bölümü son 30 günü dört küçük grafikte gösterir: kritik ve yüksek açık sayısı (CVE), aktif olarak istismar edilen açıklar (KEV), açık bulgular ve bekleyen güvenlik güncellemeleri. Fareyle grafiğin üzerine gelindiğinde (ya da grafik seçiliyken ok tuşlarıyla) o günün değeri gösterilir. **Günlük değerleri tablo olarak göster** aynı verileri tablo halinde açar. Sunucu filonun durumunu her 15 dakikada bir o günün kaydına yazar; merkezi sunucunun kapalı olduğu günlerde grafikte boşluk kalır. Grafik ikinci günden itibaren görünür.

## Sunucu Envanteri

Her sunucu için işletim sistemi, son bağlantı zamanı, açık güvenlik açıkları (önem derecesine göre) ve bekleyen güncellemeler listelenir. Sunucu adına tıklayarak ayrıntı sayfasını açın:

- **Güvenlik Açıkları:** Bu sunucudaki bulgular. Arama kutusu CVE numarası, başlık veya paket adıyla süzer. Debian/Ubuntu'da bulgular kaynak paket adıyla kaydedilir, ancak ikili paket adıyla da arayabilirsiniz: `mariadb-server` araması `mariadb` kaynak paketinin bulgularını getirir.
- **Bekleyen Güncellemeler:** Güncellenebilir paketler. Arama kutusu paket adına, Windows'ta KB numarasına, başlığa veya CVE'ye göre süzer. Paketleri seçip **Seçili paketleri güncelle** ile yalnızca bunları kurabilirsiniz.
- **Kurulu Paketler:** Tüm paketler ve sürümleri. Paket adının yanındaki yıldız paketi takip listenize ekler.
- **Takip Edilenler:** Takip ettiğiniz paketlerden bu sunucuda kurulu olanlar. Her paket için kurulu sürüm, varsa yeni sürüm ve açık güvenlik açıkları görünür. Paket eklemek için adını yazıp **Takip et**'e basın. Güncellemesi olan paketleri seçip burada da güncelleyebilirsiniz.
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

“Yeniden başlatma gerekli” etiketi, kurulan güncellemelerin (örneğin çekirdek) etkinleşmesi için sunucunun yeniden başlatılması gerektiğini gösterir. Etiketin ipucunda ve sunucunun **Sistem Bilgisi** sekmesinde bekleme başlangıcı görünür. Tespit yöntemi dağıtıma göre değişir: Ubuntu'da `/var/run/reboot-required`, Debian'da `/boot` altındaki çekirdeklerin çalışan çekirdekle karşılaştırılması, RHEL ailesinde `needs-restarting -r`, SUSE'de `zypper needs-rebooting`, Alpine'de kurulu `linux-*` paketinin çalışan çekirdekle karşılaştırılması. `needrestart` kuruluysa yeni mikro kod da dikkate alınır. netio.patchman sunucuları kendiliğinden yeniden başlatmaz.

### Platform

Ajan sunucunun hangi platformda çalıştığını bildirir: VMware, Hyper-V, KVM/QEMU, Xen, VirtualBox, Amazon EC2, Google Compute Engine gibi sanal makineler, Docker/Podman/LXC konteynerleri ya da fiziksel sunucu. Bilgi `systemd-detect-virt` ile, bu araç yoksa (örneğin Alpine) DMI bilgileri ve konteyner işaretleriyle, Windows'ta BIOS bilgisiyle belirlenir. Sunucu Envanteri'ndeki **platform** süzgeci ile örneğin yalnızca fiziksel sunucuları ya da yalnızca VMware sanal makinelerini listeleyebilirsiniz. 0.3.0 öncesi ajanlarda platform “Bilinmiyor” görünür; ajan güncellenince dolar.

### Windows sunucuları

Windows sunucuları Linux sunucularla aynı listelerde görünür; işletim sistemi kimliği `windows`'tur (filtrelerde ve zamanlama kapsamında bu ad kullanılır). Farklar:

- **Bekleyen Güncellemeler** sekmesinde paket yerine Windows Update güncellemeleri listelenir: KB numarası, başlık, Microsoft önem derecesi, sınıflandırma (Security Updates, Update Rollups vb.) ve yayın tarihi. Windows Update güncellemenin CVE'lerini bildirmişse sayısı başlığın yanında görünür. Güncellemeleri seçip **Seçili paketleri güncelle** ile yalnızca bu KB'leri kurabilirsiniz.
- **Kurulu Paketler** sekmesinde "Programlar ve Özellikler" listesindeki programlar görünür. Bu programlar güvenlik açığı taramasına girmez.
- **winget** (App Installer) kurulu sunucularda üçüncü taraf programların (Chrome, 7-Zip, Git vb.) güncellemeleri de Bekleyen Güncellemeler'de **winget** sınıflandırmasıyla listelenir ve **Tüm güncellemeler** ya da seçili paketlerle kurulur (güvenlik güncellemesi işi bunları kurmaz). Ajan SYSTEM hesabıyla çalıştığı için yalnızca tüm kullanıcılar için kurulmuş programlar görünür. Windows Server 2016/2019/2022'de App Installer genellikle kurulu değildir; winget yoksa bu özellik kendiliğinden devre dışıdır. `PATCHMAN_WINGET=false` ile kapatılır.
- **Güvenlik Açıkları:** Bekleyen her KB'nin düzelttiği CVE'ler Microsoft Security Update Guide'dan alınır. Bulguda **Etkilenen Paket** KB numarasıdır, **Kurulu Sürüm** sunucunun Windows derlemesi (örneğin `10.0.20348.2700`), **Düzeltilmiş Sürüm** düzeltmeyi içeren derlemedir. Sunucu birkaç ay geride kalmışsa, bekleyen toplu güncellemenin yerini aldığı önceki ayların CVE'leri de aynı KB altında gösterilir; tek KB'yi kurmak hepsini kapatır. **Düzeltmeyi uygula** ilgili KB'yi kurar. Microsoft'un CVE eşlemesi yayımlamadığı güncellemeler (bazı .NET toplu güncellemeleri gibi) güvenlik güncellemesi olarak listelenir ama CVE bulgusu oluşturmaz.
- **Güncelleme işleri** Windows Update üzerinden indirip kurar; iş çıktısında her KB için sonuç (kuruldu ya da sonuç kodu ve HRESULT ile kurulamadı) yazar. Doğrulama Linux'taki gibidir. Kurulum yeniden başlatma gerektiriyorsa çıktıda belirtilir ve sunucu “Yeniden başlatma gerekli” olarak işaretlenir. Yeniden başlatma ihtiyacı Windows Update ve Windows'un bileşen hizmetinin (CBS) kayıtlarından okunur.
- **Yeniden başlat** düğmesi Windows'ta `shutdown.exe /r /t 60` çalıştırır. Oturum açmış kullanıcılar uyarıyı görür.
- **Yeniden başlatılması gereken servisler** Windows'ta tespit edilmez; güncellemeler gerektiğinde zaten yeniden başlatma ister.
- Platform bilgisi BIOS (SMBIOS) üretici ve ürün adından belirlenir (Hyper-V, VMware, KVM vb.).

### Güncellenmeyecek paketler

Bazı paketlerin hiçbir güncelleme işinde değişmemesi gerekiyorsa (veritabanı sunucusu, çekirdek, sorun çıkardığı bilinen bir KB) desen listesi tanımlayın:

- **Sistem Ayarları → Güncellemeler:** tüm sunucular için,
- **Sunucu Grupları → grup:** gruptaki sunucular için,
- **Sunucu → Sistem Bilgisi → Güncellenmeyecek paketler:** tek sunucu için.

Desenler virgül, boşluk veya satırla ayrılır; `*` ve `?` kullanılabilir (`kernel*`, `mysql-*`, `KB5034439`, `7zip.7zip`). Üç liste birleştirilir. Merkezi sunucu işi ajana verirken listeyi iletir; ajan eşleşen paketleri atlar ve iş çıktısında belirtir. Bu, panelden, zamanlamalardan, **Düzeltmeyi uygula**'dan ve API'den gelen tüm işler için geçerlidir. Bekleyen Güncellemeler sekmesinde bu paketler **Dışlandı** etiketiyle görünür; güvenlik açıkları gösterilmeye devam eder.

Not: SUSE'de güvenlik yamaları (`zypper patch`) paket adına göre süzülemez; liste tanımlıysa SUSE güvenlik işi çalıştırılmaz, **Tüm güncellemeler** veya seçili paketler kullanılır.

### Canlı çekirdek yaması (KernelCare, Livepatch)

Ajan KernelCare (`kcarectl`) veya Canonical Livepatch (`canonical-livepatch`) kuruluysa bunu bildirir; sunucu başlığında ve **Sistem Bilgisi**'nde gösterilir.

- **KernelCare (RPM dağıtımları: CloudLinux, AlmaLinux, Rocky, RHEL):** Çekirdek bulguları, KernelCare'in yamaladığı çekirdek sürümüne (`kcarectl --uname`) göre değerlendirilir. Yeni çekirdek paketi kurulduğunda KernelCare bu sürümü zaten kapsıyorsa sunucu "Yeniden başlatma gerekli" olarak işaretlenmez; glibc veya systemd gibi güncellenen çekirdek kitaplıkları yine yeniden başlatma ister.
- **Canonical Livepatch (Ubuntu):** Livepatch'in kapattığı CVE'ler çekirdek paketleri için açık sayılmaz. Yeni çekirdek paketinin etkinleşmesi için yeniden başlatma uyarısı kalır.
- Debian/Ubuntu'da KernelCare sürümü paket sürümüne çevrilemediği için çekirdek bulguları paket sürümüne göre gösterilir.

## Sunucu Grupları

Sunucuları “Üretim”, “Test”, “Veritabanı” gibi gruplara ayırabilirsiniz. Bir sunucu birden fazla gruba üye olabilir.

- **Grup oluşturma, yeniden adlandırma, silme:** **Sunucu Grupları** sayfasından (yalnızca yöneticiler). Grup silinince sunucular silinmez.
- **Sunucu ekleme ve çıkarma (operatör ve yönetici):** Sunucu Envanteri'nde sunucuları işaretleyip **Seçili sunucuları gruba** çubuğundan grubu seçin ve **Gruba ekle** ya da **Gruptan çıkar** düğmesine basın. Tek bir sunucunun gruplarını, sunucu ayrıntısındaki **Sistem Bilgisi → Gruplar** bölümünden de değiştirebilirsiniz.
- **Kullanım:** Sunucu Envanteri gruba göre süzülebilir; zamanlanmış güncellemeler bir grubu hedefleyebilir; uyumluluk raporu grup için alınabilir. Grup sayfasında grubun kritik ve KEV açık sayıları görünür.

Bir grubu hedefleyen zamanlama, çalıştığı anda grubun üyelerine uygulanır; gruba sonradan eklenen sunucular da kapsanır. Grup silinirse bu zamanlamalar devre dışı bırakılır ve hedefleri boşaltılır; hiçbir zaman kendiliğinden tüm sunuculara yönelmez.

### Servisleri ve sunucuyu yeniden başlatma

Bir güncelleme, çalışan bir servisin kullandığı kütüphaneyi (örneğin `libssl3`, `libc6`) değiştirdiğinde servis, yeniden başlatılana kadar eski sürümü bellekte çalıştırmaya devam eder. Ajan bu servisleri her envanterde tespit eder:

- Debian/Ubuntu: `needrestart` paketiyle. Kurulu değilse `apt install needrestart` ile kurun. Kuruluysa apt güncellemeleri sırasında servisler zaten kendiliğinden yeniden başlatılır.
- RHEL ailesi: `needs-restarting -s` ile (`dnf-utils` / `yum-utils`).
- SUSE: `zypper ps` ile.

Tespit edilen servisler sunucu ayrıntısında **Yeniden başlatılması gereken servisler** bölümünde listelenir. Operatörler servisleri seçip **Seçili servisleri yeniden başlat** ile yeniden başlatabilir. Oturumları veya ağ bağlantısını kesebilecek servisler (dbus, systemd-logind, NetworkManager, getty vb.) ve ajanın kendisi atlanır; bunlar için sunucu yeniden başlatılmalıdır. Ajan, işten sonra servislerin gerçekten yenilendiğini kontrol eder.

Sunucu ayrıntısındaki **Yeniden başlat** düğmesi sunucuyu 1 dakika sonra yeniden başlatır. Bu süre, sonucun panele ulaşması ve oturumdaki kullanıcıların uyarılması içindir. Sunucu açıldığında ajan yeni envanter gönderir ve “Yeniden başlatma gerekli” etiketi kalkar. Her iki işlem de uzaktan güncellemenin açık olmasını gerektirir ve denetim kayıtlarına yazılır.

## Güvenlik Açıkları

Tespit edilen açıklar en kritik olandan başlayarak listelenir. Aktif olarak istismar edilen açıklar **KEV** etiketiyle işaretlenir.

Bir açığın ayrıntı sayfasında:

- **Orijinal Açıklama:** CVE kaydındaki resmî açıklama, kaynağındaki dilde (genellikle İngilizce) ve değiştirilmeden gösterilir.
- **Güvenlik Önerisi:** Hangi paketin hangi sürüme güncellenmesi gerektiği.
- **Üretici Güvenlik Duyurusu:** Dağıtımın yayımladığı duyurular (DSA, USN, ALSA, RHSA vb.); Windows'ta açığı düzelten KB ve Microsoft destek sayfası bağlantısı.
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

**Risk kabulü süreli verilir.** Durumu “Risk Kabul Edildi” yaparken **Risk kabulü süresi** seçilir: 30, 90, 180 veya 365 gün. Yönetici **Sistem Ayarları → Güvenlik → En uzun risk kabulü süresi** ile üst sınırı belirler (varsayılan 365 gün; 0 süresiz kabule izin verir). Süre, seçilen günün sonunda (gece 23:59) dolar. O anda bulgular yeniden **Açık** olur, bildirim merkezine her CVE için bir uyarı düşer, e-posta bildirimleri açıksa özet e-posta gider ve denetim kayıtlarına yazılır. Bulgu listelerinde ve raporda kabulün bitiş tarihi ile kabul eden kullanıcı görünür.

### Düzeltme süreleri (SLA) ve EPSS

**Sistem Ayarları → Düzeltme süreleri (SLA)** bölümünde her önem derecesi için gün sayısı belirlenir (varsayılan: kritik 15, yüksek 30, orta 90, düşük 180; 0 = süre yok). Son tarih, bulgunun ilk tespitinden itibaren hesaplanır.

- Bulgu listelerinde **Son tarih** sütunu ve süresi geçenlerde **Süresi geçti** etiketi görünür; **Süresi geçenler** süzgeciyle yalnızca bunlar listelenir.
- Gösterge panelinde **Süresi geçen bulgular** kartı, Uyumluluk Raporu'nda ayrı bir bölüm vardır.
- Bir bulgunun süresi dolduğunda bildirim merkezine tek bir özet bildirim düşer; ayarda açıksa e-posta gönderilir. Her bulgu için bir kez bildirilir.

**EPSS** (FIRST Exploit Prediction Scoring System), açığın önümüzdeki 30 günde istismar edilme olasılığıdır ve her gün güncellenir. Açık listesinde EPSS sütunu bulunur; **İstismar olasılığına göre (KEV, EPSS)** sıralaması önce aktif olarak istismar edilenleri, sonra EPSS'i yüksek olanları gösterir. Hangi açığın önce kapatılacağına karar verirken CVSS'ten daha iyi bir göstergedir.

## Uyumluluk Raporu

**Uyumluluk Raporu** sayfası seçilen dönem (varsayılan son 30 gün, en fazla 366 gün) ve isteğe bağlı bir grup için denetime hazır bir özet üretir:

- Sunucu sayısı, kritik ve yüksek açıklar, aktif olarak istismar edilen (KEV) açıklar, yeniden başlatma bekleyen sunucular
- Dönemde tespit edilen ve kapatılan bulgular, ortalama kapatma süresi (gün)
- Günlük eğilim grafikleri (tüm filo için)
- Açık KEV açıkları, CISA'nın belirlediği son tarih ve **Süresi geçti** işareti
- Sunucu bazında durum: işletim sistemi, platform, açıklar, bekleyen güvenlik güncellemeleri, yeniden başlatma
- Kabul edilen riskler: açıklama, kabul eden kullanıcı ve bitiş tarihi (süresiz olanlar ayrıca işaretlenir)
- Dönemde oluşturulan güncelleme işlerinin sonuçlara göre dağılımı

**Yazdır / PDF kaydet** düğmesi tarayıcının yazdırma penceresini açar. Hedef olarak “PDF olarak kaydet” seçildiğinde rapor menüler olmadan, beyaz zeminde kaydedilir. Rapor, oluşturulma zamanını ve oluşturan kullanıcıyı içerir. ISO 27001 ve KVKK denetimlerinde düzenli olarak (örneğin aylık) alınıp saklanabilir. Tüm roller raporu görüntüleyebilir.

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
| Kapsam | Tüm sunucular, belirli bir işletim sistemi (örneğin `ubuntu` veya `windows`) veya seçili sunucular |

Nasıl çalışır:

- Başlangıç saatinde, kapsamdaki ve ilgili türde bekleyen güncellemesi olan her sunucu için bir iş oluşturulur. Güncel sunucularda iş oluşturulmaz.
- Uzaktan güncellemesi kapalı sunucular ve aynı türde bekleyen işi olan sunucular atlanır.
- Ajan bakım penceresi içinde bağlanmazsa iş çalıştırılmaz ve **Süresi doldu** olarak işaretlenir. Böylece kapalı olan bir sunucu açıldığında güncelleme mesai saatine kaymaz. Pencere içinde başlayan bir iş, pencere bitse de tamamlanır.
- Merkezi sunucu bakım penceresi boyunca kapalıysa o çalışma atlanır ve bildirim merkezine uyarı düşer.
- Her çalışma için bildirim merkezine tek bir özet bildirimi düşer. Başarılı işler ayrıca bildirim üretmez; başarısız işler her zamanki gibi bildirilir ve e-postayla gönderilir.
- **Şimdi çalıştır** düğmesi kuralı hemen çalıştırır (bakım penceresi o andan başlar); normal zamanlama değişmez.
- Bir zamanlama silinirse henüz ajana iletilmemiş işleri iptal edilir; tamamlanmış işlerin geçmişi korunur.

Zamanlanmış güncellemeler, **Güncellemeden sonra gerekiyorsa sunucuyu bakım penceresi içinde yeniden başlat** seçeneği işaretlenmedikçe sunucuları yeniden başlatmaz. Seçenek işaretliyse güncelleme işi başarıyla (veya kısmen) bittikten sonra sunucu yeniden başlatma gerektirdiğini bildirirse ve bakım penceresi hâlâ açıksa 1 dakika sonra yeniden başlatılır; her güncelleme işi için en fazla bir kez. Seçenek kapalıyken çekirdek güncellemelerinden sonra yeniden başlatmayı sunucu ayrıntısındaki **Yeniden başlat** düğmesiyle ya da kendi yönteminizle planlayın; gereken sunucular “Yeniden başlatma gerekli” etiketiyle gösterilir. Bir sunucuyu kapsayan zamanlamalar, sunucu ayrıntısındaki **Sistem Bilgisi** sekmesinde listelenir.

## Güncelleme İşleri

Panelden veya bir zamanlamayla başlatılan her işlem bir iştir. İşler ajanın bir sonraki bağlantısında (varsayılan olarak en geç bir dakika içinde) çalıştırılır. İş sayfasında komut çıktısı, çıkış kodu ve süreler görüntülenir. Henüz ajana iletilmemiş işler iptal edilebilir. Ajan 3 saat içinde sonuç bildirmezse iş “Zaman aşımı” olarak işaretlenir. Zamanlamayla oluşturulan işlerde “Başlatan” sütununda zamanlamanın adı görünür.

Ajanlar sunucularda port açmaz. Merkezi sunucuya düzenli aralıklarla HTTPS ile bağlanır, bekleyen işleri alır ve sonuçları bildirir. Bu yüzden yönetilen sunuculara dışarıdan erişim gerekmez; yalnızca ajanın merkezi sunucuya erişebilmesi yeterlidir.

İş tamamlandığında ajan envanteri hemen yeniden gönderir ve güvenlik taraması güncellenir.

### Sonucun doğrulanması

Paket yöneticisinin hatasız bitmesi, paketlerin güncellendiği anlamına gelmez. Örneğin apt, kurulu olmayan veya sabitlenmiş (hold) paketleri uyarı vererek atlar ve yine de başarılı döner. Bu yüzden ajan her güncelleme işinde şu adımları izler:

1. Paket listelerini yeniler ve bekleyen güncellemeleri hedef olarak belirler. Seçili paketlerden bekleyen güncellemesi olmayanlar atlanır ve çıktıda belirtilir.
2. Güncelleme komutunu çalıştırır.
3. Hedeflerden hangilerinin hâlâ beklediğini yeniden kontrol eder.

İşin durumu bu kontrole göre belirlenir:

| Durum | Anlamı |
| --- | --- |
| Başarılı | Hedeflenen tüm paketler güncellendi (çıktıda “Doğrulandı”). |
| Kısmen başarılı | Bazı paketler güncellendi, bazıları hâlâ bekliyor. |
| Başarısız | Komut hata verdi ya da paketlerin hiçbiri güncellenmedi. |

Güncellenemeyen paketler iş sayfasında listelenir. **Kalanları yeniden dene** düğmesi yalnızca bu paketler için yeni bir iş oluşturur. Diğer başarısız işler **Yeniden dene** ile aynen tekrarlanabilir. Kısmen başarılı ve başarısız işler bildirim merkezine düşer ve ayarlarda açıksa e-postayla bildirilir. Ajan güncellemeyi kendiliğinden tekrar denemez: başarısızlığın nedeni (bağımlılık çakışması, sabitlenmiş paket, depo hatası) genellikle elle düzeltilmelidir. Zamanlanmış güncellemeler bir sonraki bakım penceresinde yeniden çalışır.

Kurulu olmayan yeni bağımlılıklar (örneğin yeni çekirdek sürümü veya bölünmüş firmware paketleri) güncelleme listesinde gösterilmez. Bunları gerektiren paket güncellendiğinde paket yöneticisi onları kendiliğinden kurar.

## Ajan Yönetimi

- **Kayıt anahtarları:** Yeni sunucuların kaydolması için kullanılır. Anahtar yalnızca oluşturulduğu anda gösterilir. Geçerlilik süresi ve kullanım sınırı verilmesi önerilir. Bir anahtarın iptal edilmesi kayıtlı ajanları etkilemez.
- **Ajanlar:** Ajan sürümleri, otomatik güncelleme ve uzaktan güncelleme durumları, son bağlantı zamanları. Eski sürümdeki ajanlar "Eski sürüm" etiketiyle gösterilir.
- **Ajan güncellemeleri:** Sunucunun dağıttığı ajan sürümü ve eski sürümdeki ajan sayısı. Otomatik güncelleme açıksa ajanlar kendiliğinden güncellenir; kapalıysa **Eski ajanları güncelle** düğmesi tüm eski ajanlar için güncelleme başlatır.

## Bildirim Merkezi ve e-postalar

Bildirim merkezi şu olayları gösterir: yeni güvenlik açıkları, ajan bağlantısının kesilmesi ve geri gelmesi, yeni sunucu kayıtları, iş sonuçları, tarama ve e-posta hataları ve yeni netio.patchman sürümleri.

**Yeni sürüm:** GitHub'da daha yeni bir netio.patchman sürümü yayımlandığında yöneticiler her sayfanın üstünde bir uyarı görür. **Güncelleme adımları** bağlantısı **Sistem Ayarları → Sunucu yapılandırması → Ürün sürümü** bölümünü açar. Orada kurulu ve yayımlanan sürüm, değişiklikler bağlantısı ve güncelleme komutları bulunur. Operatör ve izleyiciler bu uyarıyı görmez. E-posta bildirimleri açıksa yeni sürüm ayrıca e-postayla bildirilir; e-postadaki bağlantı sürüm notlarını açar. Denetim aynı sayfadaki **Sürüm denetimi** bölümünden, e-posta **Sistem Ayarları → E-posta bildirimleri** bölümünden kapatılabilir.

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

### Slack, Microsoft Teams, Telegram ve webhook

**Sistem Ayarları → Bildirim kanalları** sayfasında (yalnızca yöneticiler) bildirim merkezine düşen her bildirim ayrıca sohbet kanallarına gönderilebilir. Her kanal için en düşük seviye seçilir: **Bilgi** her şeyi, **Uyarı** yalnızca uyarı ve kritik olanları, **Kritik** yalnızca kritik olanları (kritik açıklar, KEV açıkları, başarısız yedekleme) gönderir.

| Tür | Gerekenler |
|---|---|
| Slack | Kanal için **Incoming Webhook** adresi (`https://hooks.slack.com/services/…`) |
| Microsoft Teams | Kanalda **Workflows → "Post to a channel when a webhook request is received"** ile oluşturulan adres. Mesaj, "Panelde aç" düğmeli bir Adaptive Card olarak gelir. |
| Telegram | @BotFather ile oluşturulan botun anahtarı ve sohbet kimliği (grup için `-100…`, kanal için `@kanal_adi`). Bot gruba eklenmiş olmalıdır. |
| Webhook (JSON) | Kendi sisteminizin adresi. Her bildirim `kind`, `level`, `text`, `url`, `params`, `created_at` alanlarıyla POST edilir. İmza anahtarı girilirse gövdenin HMAC-SHA256 imzası `X-Netio-Patchman-Signature: sha256=<hex>` başlığında gönderilir. |

Kanal eklendikten sonra **Deneme mesajı gönder** ile ayarı doğrulayın. Gönderim başarısız olursa iki kez yeniden denenir; hata, kanal listesinde "Hata" durumuyla ve mesajıyla gösterilir (bildirim merkezine ayrıca bildirim düşmez). Webhook adresleri ve bot anahtarları gizli bilgidir; kaydedildikten sonra tam olarak gösterilmez, değiştirmek için kanal silinip yeniden eklenir. Kanallar geçici olarak **Devre dışı bırak** ile durdurulabilir.

## Otomatik yedekleme

**Sistem Ayarları → Otomatik yedekleme** bölümünde günlük yedekleme saati ve saklanacak yedek sayısı ayarlanır (varsayılan her gün 02:30, 7 yedek). Aynı sayfanın altındaki **Yedekler** listesinde alınan yedekler, boyutları ve **İndir** bağlantıları bulunur; **Şimdi yedek al** anında bir yedek alır. Başarısız bir yedekleme bildirim merkezinde kritik uyarı olarak görünür ve e-posta ile bildirilir. Yedekleri sunucu dışında saklamak ve geri yükleme için bkz. [kurulum.md](kurulum.md), bölüm 5.

## Arayüz dili

Arayüz Türkçe, İngilizce, Almanca ve Rusça kullanılabilir. Giriş ekranının altındaki **Türkçe · Deutsch · English · Русский** bağlantılarıyla ya da **Profilim → Arayüz dili** ile seçilir. Profilde kaydedilen dil, başka bir cihazdan giriş yapıldığında da geçerlidir. Dil yalnızca sizin panelinizi etkiler: e-postalar, sohbet kanalı mesajları ve sistem günlükleri sunucunun varsayılan dilindedir. Bildirim merkezindeki bildirimler ise sizin seçtiğiniz dilde gösterilir. İngilizce arayüzde tarihler `2026-11-21`, CSV dosyaları `,` ayraçlıdır; Almanca ve Rusçada Türkçedeki gibi `21.11.2026` ve `;` kullanılır.

## Denetim Kayıtları

**Sistem Ayarları → Denetim Kayıtları** sayfasında girişler, başarısız giriş denemeleri, kullanıcı ve ayar değişiklikleri, başlatılan işler, kayıt anahtarı işlemleri ve sunucu kaldırma işlemleri kullanıcı ve IP adresiyle birlikte listelenir. Grup değişiklikleri, iki adımlı doğrulamanın açılıp kapatılması, hatalı doğrulama kodları ve süresi dolan risk kabulleri de kaydedilir.

## İki adımlı doğrulama

Her kullanıcı **Profilim** sayfasından iki adımlı doğrulamayı açabilir:

1. **Doğrulayıcı uygulaması tanımla** düğmesine basın.
2. Telefonunuzdaki doğrulayıcı uygulamasında (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP, 1Password vb.) yeni hesap ekleyip gösterilen kurulum anahtarını yazın. Panel telefonda açıksa **uygulamada aç** bağlantısı anahtarı doğrudan uygulamaya aktarır.
3. Uygulamanın gösterdiği 6 haneli kodu ve parolanızı girip **Doğrula ve aç**'a basın.

Açıldığında **10 yedek kod** bir kez gösterilir. Her biri, telefona erişilemediğinde bir kez giriş için kullanılabilir; güvenli bir yerde saklayın. Yedek kodlar aynı sayfadan yenilenebilir. Bu işlem parola ve geçerli bir kod ister ve eski kodları geçersiz kılar.

Girişte parola doğrulandıktan sonra kod istenir. Kod 30 saniyede bir değişir; telefon saatinin ±30 saniyelik kaymasına izin verilir. Kullanılan bir kod ikinci kez kabul edilmez. Beş hatalı koddan sonra giriş baştan alınmalıdır.

**Zorunlu kılma:** Yönetici **Sistem Ayarları → Güvenlik → Tüm kullanıcılar için iki adımlı doğrulamayı zorunlu kıl** seçeneğini açabilir. Doğrulayıcı tanımlamamış kullanıcılar, tanımlayana kadar yalnızca Profilim sayfasını açabilir. Zorunluyken kullanıcılar doğrulamayı kapatamaz.

**Telefon kaybolursa:** Yönetici **Kullanıcı Yönetimi → kullanıcı → İki adımlı doğrulamayı sıfırla** ile kullanıcının doğrulayıcısını kaldırır; kullanıcının açık oturumları kapanır. Yöneticinin kendisi erişemiyorsa sunucuda `netio-patchman-server reset-mfa -email <adres>` komutu kullanılır (bkz. [kurulum.md](kurulum.md)).

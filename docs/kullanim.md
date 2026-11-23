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
- **Kullanım:** Sunucu Envanteri gruba göre süzülebilir; zamanlanmış güncellemeler bir grubu hedefleyebilir; uyum raporları bir grup için oluşturulabilir. Grup sayfasında grubun kritik ve KEV açık sayıları görünür.

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
- Gösterge panelinde **Süresi geçen bulgular** kartı, uyum raporlarında **Güvenlik güncellemesi SLA'sı** bölümü vardır.
- Bir bulgunun süresi dolduğunda bildirim merkezine tek bir özet bildirim düşer; ayarda açıksa e-posta gönderilir. Her bulgu için bir kez bildirilir.

**EPSS** (FIRST Exploit Prediction Scoring System), açığın önümüzdeki 30 günde istismar edilme olasılığıdır ve her gün güncellenir. Açık listesinde EPSS sütunu bulunur; **İstismar olasılığına göre (KEV, EPSS)** sıralaması önce aktif olarak istismar edilenleri, sonra EPSS'i yüksek olanları gösterir. Hangi açığın önce kapatılacağına karar verirken CVSS'ten daha iyi bir göstergedir.

## Uyum ve Denetim

Denetime giren kuruluşların ihtiyaç duyduğu raporlar tek bir alandan üretilir: kenar çubuğundaki **Uyum ve Denetim** grubu. Ayrı çerçeveler için ayrı menüler veya ayrı rapor sistemleri yoktur; tek raporlama motoru, ortak bir kanıt deposu ve her çerçeve için ayrı kontrol değerlendirmeleri vardır.

| Bölüm | İçerik |
|---|---|
| **Genel Bakış** | Son raporlar ve kontrol sonuçları, kanıt deposunun büyüklüğü, kanıt toplamanın başladığı tarih |
| **Uyum Raporları** | Rapor oluşturma, sürümler, inceleme, kesinleştirme, PDF / CSV / JSON dışa aktarma |
| **Denetim Kanıtları** | Ortak kanıt deposu: arama, ayrıntı, hash, kanıtın kullanıldığı kontroller; manuel kanıt ekleme |
| **Denetim Geçmişi** | Rapor sürümleri, kullanıcı denetim kayıtları (yöneticiler), kanıt zincirinin bütünlük denetimi |
| **Uyum Politikaları** | Etkin çerçeveler, otomatik kontrol eşikleri, kontrol uygulanabilirliği, sunucu standartları |

> Raporlar otomatik toplanan teknik kanıtlara dayanır. Bir belgelendirme, sertifika veya uygunluk beyanı değildir. Bir kanıtın birden fazla çerçevede kullanılması, o çerçevelerin bütün gereksinimlerinin karşılandığı anlamına gelmez; değerlendirme ve karar denetçiye aittir. Bu not her raporda ve her dışa aktarımda yer alır.

### Değerlendirme çerçeveleri

Rapor oluştururken aşağıdakilerden biri veya birkaçı seçilir. Kontrol kimlikleri ve açıklamaları netio.patchman'e aittir; hiçbir standardın metni kopyalanmamıştır. Kataloglar sürümlüdür (ör. `isms@1`); bir rapor oluşturulduğu katalog sürümünü korur.

| Çerçeve | Kapsam | Kontrol |
|---|---|---|
| Bilgi Güvenliği Yönetimi Denetimleri (`isms`) | Varlık envanteri, açıklık yönetimi, yapılandırma, değişiklik, kayıt, izleme, yedekleme, erişim, yaşam döngüsü, risk işleme, politikalar | 12 |
| BT Temel Koruma Denetimleri (`baseline`) | Yama ve değişiklik yönetimi; Linux sunucular, Windows sunucular ve Windows istemciler için ayrı kontroller; kayıt, yedekleme, kimlik yönetimi | 12 |
| BT Hizmet Yönetimi Değerlendirmeleri (`itsm`) | Değişiklik etkinleştirme, sürüm ve dağıtım, yapılandırma ve varlık yönetimi, izleme, hizmet seviyeleri | 8 |
| Genel Güvenlik ve Yama Uyumu (`general`) | Ölçülebilir hedefli temel güvenlik ve güncelleme kontrolleri | 12 |

Birden fazla çerçeve seçildiğinde kanıtlar ve ölçümler bir kez hesaplanır, her çerçeve kendi kontrolleriyle ayrıca değerlendirilir ve sonuç tek bir rapordur.

### Kanıt deposu

Kanıtlar sunucu çalıştıkça dakikada bir mevcut kayıtlardan toplanır; çerçeveye özel veri toplanmaz:

| Kanıt türü | Kaynak |
|---|---|
| Güncelleme işi | Biten paket güncellemeleri ve geri dönüşler (Linux paketleri ve Windows KB'leri): sonuç, kalan paketler, başlatan (kullanıcı, zamanlama, kademeli güncelleme, otomatik), önizleme onayı |
| Değişiklik işi | Yeniden başlatma, servis yeniden başlatma, ajan güncellemesi, önizleme, sağlık kontrolü |
| Giderilen açık | CVE, paket, önem derecesi, tespit ve giderme zamanı, SLA içinde mi, KEV mi |
| Denetim kaydı | Kullanıcı ve sistem işlemleri |
| Standart sapması | Sunucu standartlarından ilk tespit edilen sapmalar |
| Yedekleme | Başarılı ve başarısız yedekler |
| Günlük envanter | Her UTC günü sonunda o günün sunucu durumlarının hash'i |
| Manuel kanıt | Kullanıcının eklediği belge kaydı (ad, tarih, konum, eşlenen kontroller) |

Ayrıca her sunucunun günlük durumu saklanır: platform, işletim sistemi, ajan sürümü, son bağlantı, bekleyen güncellemeler, önem derecesine göre açık bulgular, KEV ve SLA durumu, yeniden başlatma, işletim sisteminin destek durumu ve izleme. Böylece işler ve çözülen bulgular saklama süresi (varsayılan 90 gün) dolup silindikten sonra da 12 aylık bir denetim dönemi raporlanabilir.

- Kayıtlar değiştirilmez. Her kaydın SHA-256 hash'i içeriğini ve bir önceki kaydın hash'ini kapsar (hash zinciri); bir kayıt değiştirilir veya silinirse **Denetim Geçmişi → Kanıt bütünlüğü** bunu gösterir.
- Kanıt saklama süresi işletim verisinden bağımsızdır (varsayılan 1095 gün, en az 400). Kesinleşmiş rapor sürümlerinin kullandığı kanıtlar hiç silinmez.
- İlk çalıştırmada henüz silinmemiş geçmiş kayıtlar da aktarılır; bunlar **Geriye dönük** olarak işaretlenir. Kanıt toplama dönem başlangıcından sonra başladıysa rapor bunu uyarı olarak belirtir.
- **Manuel kanıt**, politika veya süreç belgesi gibi otomatik toplanamayan kanıtlar içindir. Belgenin kendisi değil; adı, tarihi, bulunduğu yer (belge yönetim numarası, adres) ve eşlendiği kontroller saklanır.
- Platform her sunucu için ayrı belirlenir: Linux, Windows Server, Windows 10, Windows 11.

### Rapor oluşturma ve rapor yapısı

**Uyum Raporları → Yeni rapor**: başlık, çerçeveler, denetim dönemi (son 30/90 gün, geçen çeyrek, son 12 ay, geçen takvim yılı veya en fazla 731 günlük özel aralık), kapsam (tüm sunucular veya bir grup) ve isteğe bağlı platformlar seçilir. Raporun bölümleri:

1. Yönetici özeti (çerçeve başına kontrol sonuçları, uyarılar)
2. Rapor kapsamı ve değerlendirme dönemi
3. Yönetilen varlık envanteri
4. Linux ve Windows güncelleme durumu (platforma göre)
5. Güvenlik açığı yönetimi (dönem başında ve sonunda açık bulgular, giderilenler, ortalama giderme süresi, açık KEV'ler)
6. Yama uyumu
7. Güvenlik güncellemesi SLA'sı
8. Desteği biten sistemler
9. Değişiklik yönetimi (türe ve başlatana göre, önizleme onayları)
10. Denetim kayıtları ve kanıt zincirinin durumu
11. Çerçevelere göre kontrol değerlendirmeleri ve ortak ölçümler
12. Toplanan teknik kanıtlar (kimlik, tür, hash, eşlendiği kontroller)
13. Eksik kanıtlar ve iyileştirme önerileri

Her kontrolün **otomatik sonucu** yalnızca birincil ölçümlerden hesaplanır; destekleyici ölçümler kanıt ekler ama sonucu iyileştirmez:

| Sonuç | Anlamı |
|---|---|
| Kanıt yeterli | Dönemin kanıtları kontrolü destekliyor |
| Kısmi | Kanıt var, eşiklerin altında kalan veya eksik yönler var |
| Sapma | Kanıt bir sapma gösteriyor (ör. süresi dolmuş açık, desteği biten sistem, MFA'sız yönetici) |
| Kanıt eksik | Dönem için kanıt yok |
| Manuel kanıt gerekli / mevcut | Kontrol yalnızca belgeyle desteklenebilir; belge eklenmiş olsa da incelenmesi gerekir |
| Uygulanamaz | Kapsam dışı bırakıldı (gerekçesiyle) veya kapsamda o platformda sunucu yok |

Örnek: bir Windows güvenlik güncellemesinin başarıyla uygulanması tek bir kanıt kaydıdır ve aynı raporda açıklık yönetimi (`ISMS-02`), yama ve değişiklik yönetimi (`BASE-01`), değişiklik etkinleştirme (`ITSM-01`) ve güncelleme başarısı (`GEN-04`) kontrollerinde, her birinde kendi ilişki düzeyiyle (birincil veya destekleyici) görünür.

### Sürümler, inceleme ve dışa aktarma

- Rapor her oluşturulduğunda yeni bir **sürüm** açılır; eski sürümler değişmeden saklanır. **Yeni sürüm oluştur** güncel kanıtlarla yeniden değerlendirir.
- Yöneticiler her kontrol için **manuel inceleme** kaydeder (incelendi, kabul edildi / incelendi, eksik var ve not). İnceleme otomatik sonucun yanında ayrıca saklanır, onu değiştirmez. Otomatik sonucu değişmeyen kontrollerin incelemeleri yeni sürüme aktarılır.
- **Sürümü kesinleştir** sürümü ve incelemelerini dondurur; kesin sürüm değiştirilemez, kesin sürümü olan rapor silinemez. Kesin sürüm içerik ve incelemeleri kapsayan ayrı bir SHA-256 taşır.
- Dışa aktarma saklanan sürümden üretilir, yeniden hesaplanmaz: aynı sürüm her zaman aynı içeriği verir.
  - **PDF**: sunucuda üretilir (gömülü yazı tipi, Türkçe ve Kiril harfler); sayfa altında sürüm hash'i bulunur.
  - **CSV**: ZIP içinde `summary`, `controls`, `checks`, `gaps`, `assets`, `evidence` dosyaları.
  - **JSON**: içerik, incelemeler ve hash'leriyle birlikte tüm kanıtlar (`netio.patchman/compliance-export/v1`).
- Dışa aktarmalar denetim kaydına yazılır. Denetim kaydı ayrıntılarını yalnızca yöneticiler görür; diğer rollerin dışa aktarımlarında bu kayıtların kişi ve ayrıntı alanları gizlenir.

### Uyum Politikaları

- **Çerçeveler ve eşikler**: rapor oluştururken sunulacak çerçeveler; erişim ve izleme kapsamı, güncelleme hatası oranı, güncel sunucu oranı, SLA içinde giderme oranı, en uzun yeniden başlatma bekleme süresi ve kanıt saklama süresi. Eşikler yeni oluşturulan sürümlerde kullanılır.
- SLA süreleri, risk kabul süresi, MFA zorunluluğu, önizleme onayı, yedekleme ve izleme ayarları kendi sayfalarında tek bir yerde tutulur; burada gösterilir ve bağlantı verilir.
- **Kontrol uygulanabilirliği**: kuruluşa uygulanmayan bir kontrol gerekçesiyle kapsam dışı bırakılır; gerekçe raporda kontrolün yanında görünür.
- **Sunucu standartları** da bu bölümdedir (bkz. sonraki başlık).

### Yetkiler

Tüm roller raporları ve kanıtları görür ve dışa aktarır. Rapor ve yeni sürüm oluşturmak ve manuel kanıt eklemek operatör ve yöneticilere; inceleme, kesinleştirme, silme ve politika değişiklikleri yöneticilere açıktır. Grup bazlı erişimi olan kullanıcılar yalnızca kendi gruplarından biri için rapor oluşturur ve görür; kanıt deposunda yalnızca kendi sunucularının kanıtlarını görür.

API: `/api/v1/compliance/reports`, `/api/v1/compliance/reports/{id}/versions/{n}`, `/api/v1/compliance/evidence` (bkz. [api.md](api.md)).

## Güvenlik Puanı

Her sunucu için 0-100 arası bir güvenlik puanı hesaplanır (yüksek = iyi). Puan 15 dakikada bir yenilenir ve günlük geçmişi saklanır. 100'den şu kesintiler düşülür:

| Ölçüt | Varsayılan |
|---|---|
| Açık CVE: kritik / yüksek / orta / düşük / bilinmeyen | 10 / 5 / 2 / 0,5 / 1 |
| CVE KEV kataloğunda | 25 |
| EPSS olasılığı | 20 × EPSS (ör. EPSS 0,5 → 10) |
| Düzeltme süresi (SLA) geçmiş | 12 |
| Açıklar için üst sınır | 70 |
| İşletim sistemi desteği bitmiş / yakında bitecek | 25 / 5 |
| Desteği bitmiş yazılım (dağıtımın desteklediği hariç) | yazılım başına 5, en fazla 15 |
| Bir açığa bağlanmamış güvenlik güncellemesi | güncelleme başına 1, en fazla 10 |

- **Bir CVE yalnızca bir kez sayılır.** Bir CVE aynı anda kritik, KEV kataloğunda ve süresi geçmiş olsa bile yalnızca en yüksek ölçütün kesintisi uygulanır. Aynı CVE birden çok pakette bulunsa da bir kez düşülür. Kabul edilen riskler ve yanlış pozitifler puana katılmaz.
- Güvenlik güncellemeleri yalnızca bir açık bulgusuna karşılık gelmiyorsa düşülür; aynı sorun hem açık hem güncelleme olarak iki kez cezalandırılmaz.
- Sunucu listesindeki puana tıklandığında hangi ölçütten kaç puan düşüldüğü ve son 90 günün puan geçmişi gösterilir. Liste puana göre sıralanabilir ve “Puanı 60'ın altında” gibi süzülebilir. Gösterge panelinde filonun ortalama ve en düşük puanı, Sunucu Grupları sayfasında her grubun ortalaması bulunur.
- Ağırlıklar **Sistem Ayarları → Güvenlik puanı** sayfasında (yalnızca yöneticiler) değiştirilir. Aynı sayfada bir eşik verilirse puanı bu eşiğin altına düşen sunucular için bir kez bildirim gönderilir. Puan eşiğin üstüne çıktıktan sonra yeniden düşerse yeniden bildirilir.
- API: `/api/v1/hosts/{id}/score`; Prometheus: `netio_patchman_security_score`.

## Sunucu Standartları ve Sapmalar

**Uyum ve Denetim → Uyum Politikaları → Sunucu Standartları** sayfasında tüm sunucular veya bir grup için kurallar tanımlanır (kural tanımlamak yalnızca yöneticilere açıktır, sapma raporunu tüm roller görür). Örnek: “Web sunucularında PHP yalnızca 8.2 veya 8.3 olmalı, telnetd kurulu olmamalı, nginx çalışıyor olmalı.”

| Kural | Anlamı |
|---|---|
| Kurulu olmalı | Yazılım veya paket kurulu olmalı |
| Kurulu olmamalı | Yazılım veya paket kurulu olmamalı |
| İzin verilen sürüm serileri | Yazılımın serisi listedekilerden biri olmalı (ör. `8.2, 8.3`) |
| En düşük sürüm | Paket sürümü en az bu olmalı |
| Çalışıyor olmalı | Yazılımın servisi çalışıyor olmalı |

- Kural konusu bir **yazılım** (Yazılım Envanteri'ndeki ürün, ör. `nginx`) veya tam bir **paket adı** olabilir.
- **En düşük sürüm** dağıtımın kendi sürüm numarasıyla karşılaştırılır (ör. `1.22.1-9+deb12u1`). Böylece dağıtımların güvenlik düzeltmelerini eski üst sürüme geri taşıması (backport) yanlış sapma üretmez. Üst proje sürümüyle karşılaştırma yapılmaz.
- Sapmalar her kaydetmede ve 15 dakikada bir yeniden değerlendirilir. Yeni bir sapma ilk görüldüğünde bildirim gönderilir. Giderilen sapmalar listeden kendiliğinden düşer.
- **Sapmalar** sekmesi her sapma için sunucuyu, kuralı, bulunan durumu ve ilk görülme zamanını gösterir. Bekleyen bir güncelleme sapmayı giderebiliyorsa öneri olarak gösterilir (ör. “php8.1-common güncelle”). Sunucu sayfasının Yazılım sekmesinde o sunucunun sapmaları listelenir.
- Sapmalar bir uyumluluk bulgusudur, güvenlik açığı değildir; güvenlik puanını etkilemez. API: `/api/v1/drift`.

## Paket Yönetimi

- **Bekleyen Güncellemeler:** Tüm sunuculardaki güncellemeler paket bazında toplanır. **Tüm sunucularda güncelle** ile bir paketi her yerde güncelleyebilir, **Tüm güvenlik güncellemelerini uygula** ile bütün sunucularda güvenlik güncellemelerini başlatabilirsiniz.
- **Paket ayrıntısı:** Paket adına tıkladığınızda güncelleme bekleyen sunucular listelenir. Sunucuları işaretleyip **Seçili sunucularda güncelle** ile paketi yalnızca bu sunucularda güncelleyebilirsiniz (örneğin önce test sunucularında).
- **Kurulu Paket Ara:** Bir paketin hangi sunucuda hangi sürümle kurulu olduğunu bulun.

## Yazılım Envanteri

**Yazılım Envanteri** sayfası sunuculardaki tanınan yazılımları gösterir; şu an 399 ürün tanınır. Paket adları ürün adına eşlenir (örneğin `nginx-core` → Nginx, `php8.2-fpm` → PHP-FPM 8.2, `ea-php82` → PHP 8.2, `openjdk-17-jre-headless` → Java 17). Debian/Ubuntu, Red Hat ailesi, SUSE ve Alpine paket adları ile Windows'ta kurulu programların adları tanınır. cPanel EasyApache (`ea-php*`, `ea-apache24`, `ea-nginx`) ve CloudLinux PHP Selector (`alt-php*`) paketleri de ilgili ürüne bağlanır.

| Kategori | Örnek ürünler |
|---|---|
| Çalışma ortamı | Python, PyPy, Java (OpenJDK, Temurin, Corretto, Zulu, Oracle), GraalVM, Node.js, Deno, Bun, PHP, PHP-FPM, Ruby, JRuby, Go, .NET, .NET SDK, Mono, Perl, Rust, Erlang, Elixir, Lua, R, Swift |
| Web sunucusu / proxy | Apache, Nginx, NGINX Unit, OpenResty, Caddy, Traefik, HAProxy, Envoy, Varnish, Squid, lighttpd, LiteSpeed, OpenLiteSpeed, Cherokee, H2O, Apache Traffic Server, Tengine, IIS, Tinyproxy, 3proxy, Privoxy |
| Uygulama sunucusu | Tomcat, TomEE, WildFly, JBoss EAP, Jetty, GlassFish, Gunicorn, uWSGI, Uvicorn, Daphne, Puma, Unicorn, Passenger, FrankenPHP |
| Veritabanı ve önbellek | MySQL, MariaDB, Percona Server, PostgreSQL, TimescaleDB, SQLite, SQL Server, Oracle Database, Firebird, CockroachDB, MongoDB, CouchDB, Couchbase, RethinkDB, RavenDB, ArangoDB, FerretDB, ScyllaDB, Cassandra, HBase, ClickHouse, InfluxDB, VictoriaMetrics, OpenTSDB, FoundationDB, Aerospike, Tarantool, Redis, Valkey, KeyDB, Dragonfly, Memcached, Hazelcast |
| Mesaj kuyruğu | RabbitMQ, Kafka, ActiveMQ, NATS, EMQX, VerneMQ, Mosquitto, Redpanda, Celery, Gearman, Beanstalkd, NSQ |
| Arama, günlük ve izleme | Elasticsearch, OpenSearch, Solr, Sphinx, Meilisearch, Typesense, Graylog, Loki, Fluentd, Fluent Bit, Logstash, Vector, Filebeat, Metricbeat, OpenTelemetry Collector, Jaeger, Kibana, Zabbix, Prometheus ve exporter'ları, Alertmanager, Grafana, Alloy, Tempo, Mimir, Icinga 2, Checkmk Agent, Centreon, Nagios, Netdata, Sensu, Telegraf, collectd, Munin, Monit, Thanos |
| E-posta | Postfix, Exim, Sendmail, OpenSMTPD, Dovecot, Courier, Cyrus IMAP, Rspamd, SpamAssassin, Amavis, ClamAV, OpenDKIM, OpenDMARC, Mailman, Roundcube, SOGo, MailScanner, Exchange |
| DNS ve ağ | BIND, Unbound, PowerDNS, Knot DNS, Knot Resolver, NSD, CoreDNS, dnsmasq, Kea, ISC DHCP, FRR, BIRD, OpenBGPD, Quagga, Open vSwitch, Keepalived, Corosync, Pacemaker, IPVS |
| VPN ve uzaktan erişim | OpenVPN, WireGuard, strongSwan, Tailscale, Headscale, ZeroTier, Nebula, SoftEther, OpenSSH, Dropbear |
| Kimlik | OpenLDAP, 389 Directory Server, FreeIPA, MIT ve Heimdal Kerberos, Keycloak, Authelia, Kanidm, SSSD, FreeRADIUS |
| Güvenlik | Fail2ban, CrowdSec, ClamAV, maldet, OSSEC, Wazuh, AIDE, Tripwire, Lynis, RKHunter, chkrootkit, Suricata, Snort, Zeek, ModSecurity, OWASP CRS, SELinux, AppArmor, nftables, iptables, firewalld, UFW, Shorewall, CSF, Imunify360, ImunifyAV, OpenSCAP, auditd, YARA, Falco, KernelCare, Certbot, OpenSSL, GnuPG |
| Konteyner ve sanallaştırma | Docker, Docker Compose, containerd, CRI-O, Podman, Buildah, Skopeo, runc, crun, LXC, LXD, Incus, Kubernetes, minikube, Helm, QEMU/KVM, libvirt, Proxmox VE, OpenNebula, oVirt, Xen, VirtualBox, Nomad |
| Depolama ve yedekleme | Ceph, GlusterFS, MooseFS, MinIO, DRBD, OpenZFS, Btrfs, LVM2, mdadm, multipath, Samba, NFS, iSCSI, Bacula, Bareos, BorgBackup, Restic, Duplicity, Duplicati, UrBackup, Amanda, Kopia, rsnapshot, rsync, Rclone, Veeam, Proxmox Backup Server, ReaR, pgBackRest, XtraBackup, Mariabackup, Barman, JetBackup |
| CI/CD ve otomasyon | Jenkins, GitLab, GitLab Runner, Gitea, Forgejo, Woodpecker, Buildbot, Ansible, Puppet, Chef, Salt, CFEngine, Terraform, OpenTofu, Packer, Vagrant, Rundeck, Semaphore, Artifactory |
| Barındırma paneli | cPanel & WHM, Plesk, DirectAdmin, Webmin, Virtualmin, ISPConfig, HestiaCP, CloudPanel, Froxlor, VestaCP, Cockpit, CageFS, LVE Manager, MySQL Governor |
| Web ve kurumsal uygulama (paketle kurulanlar) | WordPress, MediaWiki, phpMyAdmin, Adminer, phpBB, Redmine, Matomo, Odoo, Zammad, GLPI, Mattermost, Matrix Synapse, ONLYOFFICE, Collabora Online, OpenProject |
| Sistem aracı | systemd, D-Bus, Polkit, chrony, NTPsec, rsyslog, syslog-ng, logrotate, TuneD, smartmontools, sysstat, iproute2, tcpdump, TShark, nmap, sudo, coreutils ve benzerleri |

Sistem araçları kategorisi her sunucuda kurulu temel paketleri de gösterdiği için listeyi kalabalıklaştırabilir; kategori süzgeciyle ayrılabilir.

Paket yöneticisi dışında kurulan ürünleri ajan kendisi tespit eder ve tabloda **Ajan tespiti** olarak gösterir:
- **Linux:** cPanel (`/usr/local/cpanel/version`), Plesk (`/usr/local/psa/version`), LiteSpeed/OpenLiteSpeed (`/usr/local/lsws/VERSION`), DirectAdmin (kendi programının sürüm çıktısı), CSF (`/etc/csf/version.txt`), maldet ve ISPConfig.
- **Windows:** IIS ve SQL Server örneklerinin yama seviyesi kayıt defterinden okunur.

Bu tespit için ajan 1.0.2 veya sonrası gerekir.

Tarball, konteyner veya dil paket yöneticisiyle kurulan yazılımlar paket envanterinde görünmez. Örneğin sitelere ayrı ayrı kurulan WordPress, Joomla, Drupal, Magento, Nextcloud, Laravel veya Django uygulamaları ile Kubernetes içindeki Argo CD, Longhorn gibi bileşenler tanınmaz. Bunlar için web dizinlerini tarayan bir uygulama seviyesi tespit ileride eklenebilir.

- **Yazılımlar:** Her ürünün hangi sunucularda, hangi sürüm serisiyle kurulu olduğu. Ürün sayfasında sunucu başına paket, sürüm ve servis durumu yer alır.
- **Kurulu ve çalışan:** Ajan servis listesini de gönderir (systemd, OpenRC, Windows servisleri). Kurulu olup servisi çalışmayan yazılımlar ayrıca işaretlenir. Servis bilgisi yalnızca 1.0.0 ve üstü ajanlardan gelir.
- **Güvenlik açığı ve EOL bağlantısı:** Ürün satırlarında o yazılımın paketlerindeki açık bulgular ve destek bitiş durumu gösterilir.
- **Sunucu karşılaştırma:** İki sunucunun yazılımları ve sürüm serileri yan yana karşılaştırılır. Yalnızca birinde olan veya sürümü farklı olan satırlar işaretlenir.
- **Değişiklik geçmişi:** Kurulan, kaldırılan ve sürümü değişen yazılımlar tarih, sunucu, eski ve yeni sürümle listelenir. **Sistem Ayarları → Yazılım envanteri** bölümünde bu değişiklikler için bildirim açılıp kapatılabilir.

### Destek bitişi (EOL)

Yazılım Envanteri'nin **Destek bitişi (EOL)** sekmesi işletim sistemlerinin ve tanınan yazılımların destek takvimini gösterir: desteklenen, yakında bitecek, desteği bitmiş ve bilinmeyen.

- Takvimler [endoflife.date](https://endoflife.date) verisinden günde bir kez güncellenir. Ürünle birlikte gelen yerleşik takvim, internet erişimi olmayan kurulumlarda kullanılır (`PATCHMAN_EOL_URL=off`).
- Ubuntu, Debian ve RHEL ailesi gibi dağıtımlar kendi paketledikleri yazılımları (örneğin dağıtımın PHP veya Python sürümü) üst projenin desteği bittikten sonra da güvenlik güncellemeleriyle sürdürür. Bu kurulumlar **dağıtım destekliyor** olarak işaretlenir. EOL bildirimlerine ve güvenlik puanına dahil edilmez.
- **Uyarı süresi** (varsayılan 90 gün) **Sistem Ayarları → Destek bitişi** bölümünden değiştirilir. Desteği yaklaşan veya biten her sürüm için bir kez bildirim gönderilir.
- Sayfa durum, tür ve grup ile süzülebilir. API: `/api/v1/eol`.

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

### Ön izleme ve onay (dry-run)

Sunucu sayfasından başlatılan bir güncelleme önce **ön izleme** olarak çalışır. Ajan, paket yöneticisinin simülasyon kipini kullanır: `apt-get -s`, `dnf`/`yum` için `--assumeno`, `zypper --dry-run`. Bu sırada hiçbir paket değişmez. İş sayfasında güncellenecek, yeni kurulacak, kaldırılacak ve sürümü düşürülecek paketler, indirme boyutu ve yeniden başlatma gerekip gerekmeyeceği listelenir. Kaldırma veya sürüm düşürme varsa sayfa ayrıca uyarı gösterir. Güncelleme ancak **Onayla ve güncellemeyi başlat** düğmesine basıldıktan sonra başlar. Onay denetim kayıtlarına yazılır.

- Ön izleme zorunluluğu **Sistem Ayarları → Güncelleme ayarları → Sunucu sayfasından başlatılan güncellemeler önce ön izlemeden geçsin** ile kapatılabilir (varsayılan açık).
- Zamanlanmış güncellemeler, kademeli güncellemeler ve API ile başlatılan işler ön izleme beklemez.
- Ön izleme yalnızca bu özelliği bildiren ajanlarda (1.0.0 ve üstü) ve APT, DNF, YUM, Zypper ve apk'da yapılır. Windows Update'in simülasyon kipi olmadığı için Windows sunucularında ve eski ajanlarda güncelleme doğrudan başlar.
- Onaylanmadan bekleyen ön izleme hiçbir şey değiştirmez. Ön izlemeden sonra paket listesi değişse bile ajan güncelleme sırasında hedefleri yeniden belirler ve sonucu doğrular.

### Sağlık kontrolleri

**Sistem Ayarları → Sağlık kontrolleri** sayfasında (yalnızca yöneticiler) güncellemeden önce ve sonra, ayrıca kaynak izleme aralığıyla çalışacak ek kontroller tanımlanır. Her kontrol tüm sunuculara, bir gruba veya tek bir sunucuya uygulanabilir.

| Tür | Kontrol |
|---|---|
| HTTP/HTTPS | Adres beklenen durum koduyla (isteğe bağlı olarak beklenen metinle) yanıt veriyor mu |
| TCP bağlantı noktası | Bağlantı kabul ediliyor mu |
| Servis | Servis çalışıyor mu (systemd, OpenRC, Windows servisleri) |
| CPU, bellek ve disk | Yük, bellek ve disk kullanımı verilen sınırların altında mı |
| Yerel komut (health.d) | Sunucudaki `health.d` klasöründe bulunan betik 0 ile çıkıyor mu |

- Yerel komutlar güvenlik nedeniyle yalnızca adla çağrılır; panel ajana komut satırı gönderemez. Betiği sunucunun yöneticisi `/etc/netio-patchman/health.d/` klasörüne koyar. Windows'ta bu klasör `C:\ProgramData\netio-patchman\health.d\` olur ve `.ps1`, `.cmd`, `.bat` ve `.exe` dosyaları kabul edilir. Dosya ve klasör root'a ait olmalı, grup veya diğer kullanıcılar tarafından yazılabilir olmamalıdır. Ayrıntılar için bkz. [kurulum.md](kurulum.md), bölüm 4.6.
- Güncelleme işinde kontroller önce çalışır. Bir kontrol başarısızsa varsayılan olarak güncelleme yapılmaz ve iş başarısız sayılır. **Önceden başarısız kontrol olsa da güncellemeye devam et** seçilirse güncelleme yine yapılır.
- Güncellemeden sonra kontroller ayarlanan bekleme süresi geçince (varsayılan 15 saniye) yeniden çalışır. Önce başarılı olup sonra başarısız olan bir kontrol **bozulma** olarak işaretlenir. İş başarısız sayılır ve bildirim gönderilir.
- Sonuçlar iş sayfasında ve sunucu sayfasının **Sağlık** sekmesinde görünür. Sunucu sayfasındaki **Sağlık kontrollerini çalıştır** düğmesi kontrolleri güncelleme yapmadan çalıştırır.

#### Kaynak izleme

Ajanlar belirli aralıkla (varsayılan 5 dakika) işlemci, bellek, takas alanı ve tüm yerel disklerin kullanımını kendiliğinden bildirir. Bunun için hiçbir kontrol tanımlamak gerekmez. İşlemci kullanımı iki ölçüm arasındaki ortalamadır; Linux'ta yük ortalaması da gösterilir.

- **Sunucu sayfası:** **Sağlık** sekmesinin üstündeki **Kaynak kullanımı** bölümü şunları gösterir:
  - İşlemci, bellek, takas alanı ve her disk için güncel değerler, çubuklarla.
  - **Son 24 saat / Son 7 gün / Son 30 gün** grafikleri: işlemci, bellek ve en dolu disk.
  - Otomatik sınırların durumu.
- **Sunucu listesi:** **Kaynaklar** sütununda her sunucunun güncel işlemci, RAM ve en dolu disk değeri yer alır. Sınıra yaklaşan değerler turuncu, aşanlar kırmızı gösterilir. 15 dakikadan (veya üç ölçüm aralığından) eski ölçümler gösterilmez.
- **Otomatik sınırlar:** Disk doluluğu %90'a, bellek kullanımı %95'e, işlemci kullanımı %90'a ulaşan sunucular kendiliğinden uyarı üretir. Sınırlar ve ölçüm aralığı **Sistem Ayarları → Kaynak izleme** bölümünden değiştirilir; 0 ilgili sınırı veya izlemeyi kapatır.
- **Bildirim:** Bir sınır veya kontrol art arda iki ölçümde aşılırsa bir kez bildirilir; tek ölçümlük dalgalanmalar bildirim üretmez. Düzeldiğinde de bildirilir. Bildirim kanallarında bu bildirimler **Sağlık kontrolü ve kaynak uyarıları** olayına düşer.
- **Ek kontroller:** Web sitesi, port, servis veya betik kontrolleri isteğe bağlıdır. Tanımlanırsa aynı aralıkla çalışır ve sonuçları **Ek kontroller** bölümünde görünür. Her kontrolün **Ajanların sürekli izleme turlarında da çalıştır** seçeneği vardır (varsayılan açık).
- **Geçmiş:** Ölçümler 30 gün saklanır. Kontrol geçmişine yalnızca bir kontrolün başarılıdan başarısıza (veya tersine) geçtiği anlar yazılır.
- Ağ dosya sistemleri (NFS, CIFS) ölçülmez, çünkü erişilemeyen bir paylaşım ölçümü süresiz bekletebilir. Bunlar için bir yerel komut kontrolü kullanın.
- **Ajan sürümü:** Kaynak izleme ajan 1.0.2 veya sonrasını gerektirir. 1.0.1 ajanları ölçüm göndermiyordu; otomatik ajan güncellemesi açıksa ajanlar kendiliğinden yükselir.


### Geri dönüş (rollback)

netio.patchman disk veya sanal makine anlık görüntüsü (snapshot) almaz. Geri dönüş, paket yöneticisinin önceki sürümü kurmasıyla yapılır:

1. Her güncelleme işinde ajan işten önceki ve sonraki paket sürümlerini bildirir. Eski ajanlarda iş başlangıcındaki envanter saklanır. İş sayfasındaki **Paket değişiklikleri** bölümü bu farkı gösterir.
2. Geri alınacak paketleri seçip **Seçilenlerin geri alınabilirliğini kontrol et** düğmesine basın. Kontrol hiçbir şeyi değiştirmez. Önceki sürümlerin depolarda bulunup bulunmadığına bakar ve paket yöneticisinin simülasyonunu gösterir.
3. Kontrol sayfasında **Onayla ve geri al** ile geri dönüş başlatılır. İsterseniz geri alınan paketler bu sunucuda güncelleme dışı bırakılır; böylece bir sonraki güncellemede yeniden yükseltilmezler.
4. Ajan geri dönüşten sonra sürümleri yeniden okur. Her paket için **Geri alındı** veya **Başarısız** yazılır. Bazı paketler geri dönmezse iş “Kısmen başarılı” olur; başarı olarak gösterilmez. Sağlık kontrolleri tanımlıysa geri dönüşten sonra da çalışır.

Kısıtlar: Eski sürümü depodan kaldırılmış paketler geri alınamaz. Bu genellikle Ubuntu güvenlik depolarında ve tek sürüm tutan depolarda görülür. Yeni kurulan ve kaldırılan paketler geri dönüşe dahil edilmez. Alpine (apk) ve Windows Update desteklenmez. Çekirdek geri dönüşünden sonra sunucunun yeniden başlatılması gerekir. Kontrol ve geri dönüş denetim kayıtlarına yazılır.

## Kademeli Güncellemeler

**Kademeli Güncellemeler** sayfasında (operatör ve yöneticiler) bir güncelleme çok sayıda sunucuya aşama aşama uygulanır:

| Alan | Açıklama |
|---|---|
| Sunucular | Seçili sunucular, bir grup veya tüm sunucular. Sıralama sunucu adına veya grup sırasına göre yapılır. |
| Canary sunucu sayısı | İlk aşamada güncellenecek sunucu sayısı. 0 olursa canary aşaması olmaz. |
| Aşama başına sunucu | Sonraki aşamaların büyüklüğü |
| En fazla eşzamanlı güncelleme | Bir aşamada aynı anda çalışan iş sayısı |
| Aşamalar arası bekleme | Bir aşama bittikten sonra sonrakine geçmeden beklenen süre |
| En yüksek hata oranı | Bu oran aşılırsa dağıtım kendiliğinden durur |
| Canary aşamasından sonra dur | Canary bitince dağıtım duraklar ve elle devam ettirilmesini bekler |
| Sağlık kontrolü bozulursa başarısız say | Sağlık kontrolü bozulan sunucular hata oranına dahil edilir |

Dağıtım arka planda, sunucunun bakım döngüsünde (dakikada bir) ilerler. Sayfa kapatılsa da devam eder. **Duraklat**, **Devam ettir** ve **İptal et** düğmeleri denetim kayıtlarına yazılır. İptal edilen dağıtımda henüz ajana iletilmemiş işler iptal edilir. Başlamış işler tamamlanır. Hata oranı aşıldığında, canary sonrası beklerken ve dağıtım bittiğinde bildirim gönderilir. Hata oranı aşılıp durmuş bir dağıtım devam ettirilirse o ana kadarki hatalar kabul edilmiş sayılır ve oran sonraki sunucular için yeniden hesaplanır. Kısmen başarılı işler, ajan bağlanmadığı için süresi dolan veya zaman aşımına uğrayan işler de hata oranına başarısız olarak katılır.

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

### Bildirim kanalları ve entegrasyonlar

**Sistem Ayarları → Bildirim kanalları** sayfasında (yalnızca yöneticiler) bildirim merkezine düşen bildirimler sohbet kanallarına, kendi sistemlerinize, kayıt (ticket) sistemlerine ve Zabbix'e gönderilebilir. Her kanal için iki süzgeç vardır:

- **En düşük seviye:** **Bilgi** her şeyi, **Uyarı** yalnızca uyarı ve kritik olanları, **Kritik** yalnızca kritik olanları (kritik açıklar, KEV açıkları, başarısız yedekleme) gönderir.
- **Olaylar:** Bir veya daha fazla olay seçilirse yalnızca bu olaylar gönderilir ve seviyeye bakılmaz. Böylece örneğin bilgi seviyesindeki “Güncelleme başladı” olayı bir kanala abone edilebilir. Hiçbiri seçilmezse yalnızca seviye uygulanır.

| Olay | Ne zaman |
|---|---|
| Kritik CVE | Kritik bir açık yeni tespit edildiğinde |
| Aktif istismar edilen açık (KEV) | KEV kataloğundaki bir açık tespit edildiğinde |
| Diğer yeni açıklar | Kritik olmayan, KEV'de bulunmayan yeni açıklar |
| EOL yaklaşan veya geçen yazılım | Destek bitişi yaklaştığında veya geçtiğinde |
| Güncelleme başladı / başarılı / başarısız veya kısmi | Güncelleme işinin ajan tarafından alınması ve sonucu |
| Geri dönüş yapıldı | Bir geri dönüş tamamlandığında |
| Yeniden başlatma gerekiyor | Sunucu yeniden başlatma gerektirdiğini ilk kez bildirdiğinde |
| Sağlık kontrolü başarısız | Güncellemeden önce veya sonra bir kontrol başarısız olduğunda |
| SLA süresi aşıldı | Düzeltme süresi geçen bulgular olduğunda |
| Güvenlik puanı eşiğin altında | Bir sunucunun puanı eşiğin altına düştüğünde |
| Sunucu çevrimdışı | Ajana ulaşılamadığında |
| Standart sapması | Yeni bir standart sapması bulunduğunda |
| Kademeli dağıtım durumu | Dağıtım durduğunda, onay beklediğinde veya bittiğinde |
| Yazılım envanteri değişti | Yazılım kurulduğunda, kaldırıldığında veya sürümü değiştiğinde |
| Diğer bildirimler | Yedekleme hataları, yeni sürüm, risk kabulü bitişi ve diğerleri |

“Güncelleme başladı” ve “Yeniden başlatma gerekiyor” olayları sık oluştuğu için bildirim merkezine yazılmaz; yalnızca bu olaylara abone olan kanallara gönderilir.

| Tür | Gerekenler |
|---|---|
| Slack | Kanal için **Incoming Webhook** adresi (`https://hooks.slack.com/services/…`) |
| Microsoft Teams | Kanalda **Workflows → "Post to a channel when a webhook request is received"** ile oluşturulan adres. Mesaj, "Panelde aç" düğmeli bir Adaptive Card olarak gelir. |
| Telegram | @BotFather ile oluşturulan botun anahtarı ve sohbet kimliği (grup için `-100…`, kanal için `@kanal_adi`). Bot gruba eklenmiş olmalıdır. |
| Webhook (JSON) | Kendi sisteminizin adresi. Gövde ve imza biçimi aşağıda. |
| Jira | Jira adresi, kullanıcı (Jira Cloud'da e-posta adresi), API anahtarı (Jira Server'da kişisel erişim anahtarı), proje anahtarı ve kayıt türü (varsayılan `Task`). Her bildirim REST API v2 ile bir kayıt açar; kayda `netio.patchman` ve olay adı etiketleri eklenir. |
| ServiceNow | Örnek adresi (`https://<ornek>.service-now.com`), kullanıcı, parola ve tablo (varsayılan `incident`). Kayıt Table API ile açılır; kritik bildirimlerin aciliyeti 1, uyarıların 2, diğerlerinin 3 olur. |
| GLPI | REST API kök adresi (`…/apirest.php`), kullanıcının API anahtarı (user_token) ve API istemcisinin App-Token değeri. Her bildirim için oturum açılır, bir talep (Ticket) oluşturulur ve oturum kapatılır. |
| Zabbix (trapper) | Zabbix sunucusu veya proxy (`adres:port`, varsayılan port 10051), Zabbix'teki host adı ve öğe anahtarı (varsayılan `netio.patchman.event`). Bildirim, Zabbix sender protokolüyle “Zabbix trapper” türündeki metin öğesine JSON değer olarak gönderilir. Zabbix değeri işlediğini bildirmezse gönderim başarısız sayılır. |

**Webhook gövdesi:** Her bildirim `product`, `version`, `event_id`, `event` (yukarıdaki olay kimliği, ör. `update_failed`), `kind`, `level`, `title`, `text`, `link`, `url`, `params`, `created_at` alanlarıyla JSON olarak POST edilir. Başlıklar `X-Netio-Patchman-Event` (bildirim türü) ve `X-Netio-Patchman-Timestamp` (Unix saniye) değerlerini taşır. İmza anahtarı girilirse:

- `X-Netio-Patchman-Signature: sha256=<hex>`: gövdenin HMAC-SHA256 imzası (önceki sürümlerle uyumlu)
- `X-Netio-Patchman-Signature-V2: t=<zaman>,sha256=<hex>`: `<zaman>.<gövde>` metninin HMAC-SHA256 imzası. Alıcı zamanı da doğrulayıp (ör. 5 dakikadan eski istekleri reddederek) tekrar gönderilen eski istekleri ayırt edebilir.

Kanal eklendikten sonra **Deneme mesajı gönder** ile ayarı doğrulayın. Başarısız gönderim 5 saniye, 30 saniye ve 2 dakika sonra olmak üzere en fazla üç kez yeniden denenir. Bir kanalın yeniden denemeyi beklemesi diğer kanalları geciktirmez. Hata, kanal listesinde "Hata" durumuyla ve mesajıyla gösterilir (bildirim merkezine ayrıca bildirim düşmez).

Kanal adına tıklandığında kanalın sayfası açılır. Bu sayfada olay süzgeci değiştirilir ve **teslimat geçmişi** görülür: her gönderimin zamanı, olayı, sonucu, deneme sayısı, süresi ve hata mesajı. Teslim edilemeyen bir bildirim **Yeniden gönder** ile tekrar gönderilebilir. Teslimat geçmişi bildirim saklama süresi kadar tutulur.

Adresler, parolalar, API anahtarları ve bot anahtarları gizli bilgidir. Kaydedildikten sonra tam olarak gösterilmez, hata mesajlarından da çıkarılır. Değiştirmek için kanal silinip yeniden eklenir. Kanallar geçici olarak **Devre dışı bırak** ile durdurulabilir.

**Grafana, Prometheus ve Netdata:** Bu sistemler veriyi netio.patchman'den çeker. Prometheus `/metrics` adresini okur (sunucu, açık, güncelleme, güvenlik puanı, EOL, sapma, kademeli dağıtım ve kanal durumu metrikleri). Grafana bu Prometheus verisinden pano oluşturur. Netdata'nın Prometheus toplayıcısı (`go.d/prometheus`) aynı adresi okuyabilir. Ayrıntılar ve örnek yapılandırmalar için bkz. [api.md](api.md).

## Otomatik yedekleme

**Sistem Ayarları → Otomatik yedekleme** bölümünde günlük yedekleme saati ve saklanacak yedek sayısı ayarlanır (varsayılan her gün 02:30, 7 yedek). Aynı sayfanın altındaki **Yedekler** listesinde alınan yedekler, boyutları ve **İndir** bağlantıları bulunur; **Şimdi yedek al** anında bir yedek alır. Başarısız bir yedekleme bildirim merkezinde kritik uyarı olarak görünür ve e-posta ile bildirilir. Yedekleri sunucu dışında saklamak ve geri yükleme için bkz. [kurulum.md](kurulum.md), bölüm 5.

## Arayüz dili

Arayüz Türkçe, İngilizce, Almanca ve Rusça kullanılabilir. Giriş ekranının altındaki **Türkçe · Deutsch · English · Русский** bağlantılarıyla ya da **Profilim → Arayüz dili** ile seçilir. Profilde kaydedilen dil, başka bir cihazdan giriş yapıldığında da geçerlidir. Dil yalnızca sizin panelinizi etkiler: e-postalar, sohbet kanalı mesajları ve sistem günlükleri sunucunun varsayılan dilindedir. Bildirim merkezindeki bildirimler ise sizin seçtiğiniz dilde gösterilir. İngilizce arayüzde tarihler `2026-11-21`, CSV dosyaları `,` ayraçlıdır; Almanca ve Rusçada Türkçedeki gibi `21.11.2026` ve `;` kullanılır.

## Denetim Kayıtları

**Uyum ve Denetim → Denetim Geçmişi → Denetim kayıtları** sekmesinde (yöneticiler) girişler, başarısız giriş denemeleri, kullanıcı ve ayar değişiklikleri, başlatılan işler, kayıt anahtarı işlemleri ve sunucu kaldırma işlemleri kullanıcı ve IP adresiyle birlikte listelenir. Grup değişiklikleri, iki adımlı doğrulamanın açılıp kapatılması, hatalı doğrulama kodları ve süresi dolan risk kabulleri de kaydedilir.

## İki adımlı doğrulama

Her kullanıcı **Profilim** sayfasından iki adımlı doğrulamayı açabilir:

1. **Doğrulayıcı uygulaması tanımla** düğmesine basın.
2. Telefonunuzdaki doğrulayıcı uygulamasında (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP, 1Password vb.) yeni hesap ekleyip gösterilen kurulum anahtarını yazın. Panel telefonda açıksa **uygulamada aç** bağlantısı anahtarı doğrudan uygulamaya aktarır.
3. Uygulamanın gösterdiği 6 haneli kodu ve parolanızı girip **Doğrula ve aç**'a basın.

Açıldığında **10 yedek kod** bir kez gösterilir. Her biri, telefona erişilemediğinde bir kez giriş için kullanılabilir; güvenli bir yerde saklayın. Yedek kodlar aynı sayfadan yenilenebilir. Bu işlem parola ve geçerli bir kod ister ve eski kodları geçersiz kılar.

Girişte parola doğrulandıktan sonra kod istenir. Kod 30 saniyede bir değişir; telefon saatinin ±30 saniyelik kaymasına izin verilir. Kullanılan bir kod ikinci kez kabul edilmez. Beş hatalı koddan sonra giriş baştan alınmalıdır.

**Zorunlu kılma:** Yönetici **Sistem Ayarları → Güvenlik → Tüm kullanıcılar için iki adımlı doğrulamayı zorunlu kıl** seçeneğini açabilir. Doğrulayıcı tanımlamamış kullanıcılar, tanımlayana kadar yalnızca Profilim sayfasını açabilir. Zorunluyken kullanıcılar doğrulamayı kapatamaz.

**Telefon kaybolursa:** Yönetici **Kullanıcı Yönetimi → kullanıcı → İki adımlı doğrulamayı sıfırla** ile kullanıcının doğrulayıcısını kaldırır; kullanıcının açık oturumları kapanır. Yöneticinin kendisi erişemiyorsa sunucuda `netio-patchman-server reset-mfa -email <adres>` komutu kullanılır (bkz. [kurulum.md](kurulum.md)).

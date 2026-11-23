# netio.patchman
## Product Identity, Branding and Language Requirements

### 1. Product Name

Official product name:

**netio.patchman**

Use this name consistently throughout the application.

Product description:

"Linux ve Windows sunucular için merkezi güvenlik, güncelleme ve izleme yönetimi"

The product is an independent, self-hosted security, update and monitoring platform for Linux and Windows servers.

Do not use PatchMon branding in the final product.

PatchMon is only a reference project and potential source of reusable functionality, subject to its license.

### 2. Language Policy

The entire product must be developed primarily in Turkish.

Turkish is the default and primary language.

The following components must be Turkish:

- Web dashboard
- Navigation menus
- Server inventory
- Vulnerability management interface
- Package management interface
- Agent management
- System settings
- User management
- Notification center
- Email notifications
- Error messages
- Validation messages
- Installation documentation
- User documentation
- README
- Deployment instructions
- Help and guidance texts

Use natural, professional Turkish.

Avoid unnecessary English expressions in the user interface.

Keep source code identifiers, database columns, API names, programming documentation and technical protocol fields in English.

### 3. CVE and Vulnerability Language Policy

CVE data must NOT be translated into Turkish.

Preserve official vulnerability information exactly as provided by its source.

Examples:

- CVE identifiers remain unchanged.
- Official CVE titles remain unchanged.
- Original vulnerability descriptions remain unchanged.
- CVSS metrics remain unchanged.
- Official advisory titles remain unchanged.
- Package names remain unchanged.
- Technical identifiers remain unchanged.
- Vendor advisory references remain unchanged.

Example interface:

**CVE-2026-XXXXX**

Original description:
"Remote code execution vulnerability in the affected package."

Turkish interface labels:

- Önem Derecesi
- CVSS Puanı
- Etkilenen Sunucular
- Etkilenen Paket
- Kurulu Sürüm
- Düzeltilmiş Sürüm
- İlk Tespit Tarihi
- Son Kontrol Tarihi
- Güvenlik Önerisi
- Üretici Güvenlik Duyurusu
- İstismar Ediliyor mu?
- Çözüm Durumu

The original vulnerability description should remain in its source language.

Do not use machine translation on CVE descriptions.

### 4. Branding and Visual Identity

Product name: netio.patchman

Use a professional infrastructure and cybersecurity-oriented visual identity.

Brand personality:

- Technical
- Reliable
- Minimal
- Professional
- Enterprise-ready

Use a clean dashboard.

Avoid excessive gradients, unnecessary animations and decorative elements.

The product must look like a serious infrastructure management platform.

Use a consistent typography and icon system.

### 5. Turkish Email Notifications

All notification emails must be written in Turkish.

Example:

Subject:

[KRİTİK] CVE-2026-XXXXX - 12 sunucuda güvenlik açığı tespit edildi

Email content:

- Güvenlik açığı
- CVE numarası
- CVSS puanı
- Önem derecesi
- Etkilenen paket
- Kurulu sürüm
- Düzeltilmiş sürüm
- Etkilenen sunucular
- İlk tespit tarihi
- Çözüm önerisi
- Yönetim paneli bağlantısı

Keep the official CVE description in its original language.

### 6. Localization Architecture

Implement proper localization architecture from the beginning.

Default locale: tr-TR

Default timezone: Europe/Istanbul

Use UTF-8 everywhere.

Store timestamps in UTC.

Display timestamps in Europe/Istanbul timezone.

Design the frontend so that English can be added in the future, but do not spend initial development effort translating the product into English.

### 7. Final Product Identity

The finished product must consistently identify itself as:

netio.patchman

Use this name in:

- Web page title
- Dashboard branding
- Login page
- Docker image naming
- Application logs
- Agent identification
- Email sender name
- Documentation
- Installation scripts
- Default configuration examples

Suggested agent binary:

netio-patchman-agent

Suggested service name:

netio-patchman-agent.service

Suggested Docker Compose project name:

netio-patchman

The product must be Turkish-first, self-hosted, Go-based, lightweight and designed for centralized management of hundreds of Linux servers.

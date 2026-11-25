# Security policy

🇬🇧 **English** · 🇹🇷 [Türkçe özet](#türkçe-özet)

netio.patchman runs with high privileges: the agent installs packages as root or SYSTEM, and the server decides what
the agents do. Reports that help keep it safe are very welcome.

## Supported versions

| Version | Security fixes |
|---|---|
| Latest release (see [Releases](https://github.com/alptekinsunnetci/netio.patchman/releases/latest)) | Yes |
| Older releases | No: upgrade to the latest release (`git pull` and `docker compose up -d --build`, agents update themselves) |

Fixes are published as a new release. The dashboard announces new releases to administrators.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/alptekinsunnetci/netio.patchman/security/advisories/new)
(repository page → *Security* → *Report a vulnerability*). Only the maintainer sees the report.

Please include:

- the netio.patchman version (`netio-patchman-server -version`, the agent version from the agents page),
- the affected component (server, agent on which OS, install script, updater, REST API),
- the steps to reproduce, and what an attacker gains,
- whether the problem is already public or known to others.

## What to expect

- This is a project run by one maintainer. Reports are usually acknowledged within a week; there is no guaranteed
  response time.
- The report is assessed and you are told whether it is accepted. Accepted reports are fixed in a new release; the
  advisory is published with the release and credits you unless you prefer otherwise.
- Please keep the details private until the fixed release is out.

## Scope

In scope: the server (`cmd/netio-patchman-server`, `internal/...`), the Linux and Windows agent, the install scripts
and service files in `deploy/agent`, the updater container in `deploy/updater` and the default Docker Compose setup.
The trust boundaries are described in the [architecture and security model](docs/architecture-and-security.md).

Out of scope:

- vulnerabilities in third-party data the server reads (OSV.dev, CISA KEV, EPSS, Microsoft Security Update Guide,
  endoflife.date): report those to their publishers,
- problems that need administrator access to the dashboard or root access to a managed server, unless they let
  someone cross a trust boundary described in the security model,
- missing hardening of a deployment that does not follow the [installation guide](docs/installation.md) (for
  example the dashboard published on the internet without TLS),
- reports produced only by automated scanners without a working scenario.

Thank you for helping keep netio.patchman and its users safe.

---

## Türkçe özet

Güvenlik açıklarını **herkese açık bir issue, pull request veya tartışmada paylaşmayın**. GitHub üzerinden özel olarak
bildirin: [**Report a vulnerability**](https://github.com/alptekinsunnetci/netio.patchman/security/advisories/new)
(depo sayfası → *Security* → *Report a vulnerability*). Bildirimi yalnızca bakımcı görür.

Bildirime sürümü, etkilenen bileşeni (sunucu, hangi işletim sistemindeki ajan, kurulum betiği, güncelleyici, REST API),
yeniden üretme adımlarını ve saldırganın ne elde ettiğini ekleyin. Güvenlik düzeltmeleri yalnızca son sürüme yeni bir
sürüm olarak çıkar; eski sürümleri kullananlar son sürüme yükseltmelidir. Proje tek bir bakımcı tarafından yürütülür;
bildirimler genellikle bir hafta içinde yanıtlanır, kesin bir yanıt süresi taahhüt edilmez. Düzeltilmiş sürüm çıkana
kadar ayrıntıları paylaşmayın. Güven sınırları: [Mimari ve güvenlik modeli](docs/mimari-ve-guvenlik.md).

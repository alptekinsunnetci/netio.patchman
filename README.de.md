# netio.patchman

**Zentrales Schwachstellen- und Update-Management für Linux und Windows**

[Türkçe](README.md) · [English](README.en.md) · **Deutsch** · [Русский](README.ru.md)

netio.patchman ist eine selbst gehostete Plattform, mit der Sie die Schwachstellen und Paketupdates von Hunderten Linux- und Windows-Servern über ein einziges Dashboard überwachen und verwalten.

- Der zentrale Server läuft mit Docker Compose: Anwendungscontainer und PostgreSQL-Datenbank. Die SQLite-Datenbank früherer Versionen wird beim ersten Start automatisch nach PostgreSQL übertragen. Kein Warteschlangen- oder Cache-Dienst nötig.
- Auf jedem verwalteten Server wird ein kleiner Agent installiert. Der Agent öffnet keine Ports; er verbindet sich selbst mit dem zentralen Server.
- Die Weboberfläche gibt es auf Türkisch, Englisch, Deutsch und Russisch; jeder Benutzer wählt seine Sprache. CVE-Daten werden genau so angezeigt, wie die Quelle sie veröffentlicht, und nie übersetzt.

> [!WARNING]
> **Die Nutzung erfolgt vollständig auf eigenes Risiko.** netio.patchman aktualisiert Pakete und startet Dienste und Server auf Ihren Maschinen neu. Die Software wird „wie besehen“ und ohne jede Gewährleistung bereitgestellt. Für alle Schäden aus der Nutzung, einschließlich Datenverlust, Dienstausfällen, fehlgeschlagener Updates und Sicherheitslücken, ist die Person oder Organisation verantwortlich, die die Software installiert und nutzt. Details: [Haftungsausschluss](#haftungsausschluss).

![Dashboard](docs/images/dashboard.png)

## Inhalt

- [Funktionen](#funktionen)
- [Screenshots](#screenshots)
- [Funktionsweise](#funktionsweise)
- [Installation (Docker)](#installation-docker)
- [Agent auf Servern installieren](#agent-auf-servern-installieren)
- [Aktualisierung, Sicherung und Entfernung](#aktualisierung-sicherung-und-entfernung)
- [Konfiguration](#konfiguration)
- [REST-API und Prometheus](#rest-api-und-prometheus)
- [Fehlerbehebung](#fehlerbehebung)
- [Sprache und Lokalisierung](#sprache-und-lokalisierung)
- [Sicherheit](#sicherheit)
- [Entwicklung](#entwicklung)
- [Haftungsausschluss](#haftungsausschluss)
- [Lizenz](#lizenz)

## Funktionen

- **Serverinventar:** Betriebssystem, Kernel, IP-Adressen, installierte Pakete, ausstehende Updates, Neustartstatus und Dienste, die noch alten Code ausführen.
- **Schwachstellenscan:** Installierte Paketversionen werden über [OSV.dev](https://osv.dev) mit den offiziellen Sicherheitsdaten der Distributionen abgeglichen. CVSS-Wert, Schweregrad, korrigierte Version und Herstellerhinweise werden angezeigt.
- **Bekannt ausgenutzte Schwachstellen:** Schwachstellen aus dem CISA-Katalog Known Exploited Vulnerabilities (KEV) werden markiert und priorisiert.
- **Windows-Server:** Windows Server 2016, 2019, 2022, 2025 sowie Windows 10 und 11 werden im selben Dashboard verwaltet. Der Agent läuft als Windows-Dienst und meldet installierte Programme und die in Windows Update ausstehenden Updates (KB-Nummer, Titel, Microsoft-Schweregrad, Klassifizierung). Die CVEs, die jede ausstehende KB behebt, stammen aus dem Microsoft Security Update Guide (MSRC). Liegt ein Server mehrere Monate zurück, werden auch die CVEs der älteren, ersetzten kumulativen Updates anhand des Windows-Builds des Servers ergänzt. Sicherheitsupdates, alle Updates oder ausgewählte KBs werden aus dem Dashboard installiert und überprüft; der Server kann aus dem Dashboard neu gestartet werden.
- **Zentrale Updates:** Installieren Sie Sicherheitsupdates, alle Updates oder ausgewählte Pakete auf einem, auf ausgewählten oder auf allen Servern direkt im Dashboard. **Korrektur anwenden** bei einer CVE aktualisiert die betroffenen Pakete auf allen betroffenen Servern. Nach jedem Auftrag prüft der Agent, ob die Pakete tatsächlich aktualisiert wurden; nicht aktualisierte Pakete werden aufgelistet und können mit einem Klick erneut versucht werden.
- **Neustart von Diensten und Servern:** Dienste, die noch alte Versionen aktualisierter Bibliotheken verwenden, werden erkannt und können im Dashboard neu gestartet werden; Server können im Dashboard neu gestartet werden.
- **Geplante Updates:** Wartungsfenster wie „jeden Sonntag um 03:00 Sicherheitsupdates auf Ubuntu-Servern installieren“. Zeitpläne starten Server nie selbst neu.
- **Vorschau und Freigabe:** Ein auf der Serverseite gestartetes Update läuft zuerst im Simulationsmodus des Paketmanagers (APT, DNF, YUM, Zypper). Zu aktualisierende, neue, zu entfernende und herabzustufende Pakete, die Downloadgröße und ein nötiger Neustart werden angezeigt; das Update startet nach der Freigabe.
- **Zustandsprüfungen:** HTTP/HTTPS-, TCP-, Dienst-, CPU-/Speicher-/Festplatten- und lokale Skriptprüfungen (health.d) vor und nach einem Update. Schlägt eine Prüfung vorher fehl, wird nicht aktualisiert; eine danach fehlschlagende Prüfung lässt den Auftrag fehlschlagen und wird gemeldet.
- **Gestaffelte Updates:** Canary-Server, Stufen, eine Grenze für parallele Aufträge, Wartezeit zwischen Stufen und eine Fehlerquote. Wird sie überschritten, hält der Rollout selbst an; Pausieren, Fortsetzen und Abbrechen erfolgen manuell und werden protokolliert.
- **Rücksetzung ohne Snapshots:** Paketversionen vor und nach jedem Auftrag werden gespeichert. Zuerst wird geprüft, ob die alten Versionen noch in den Repositories liegen; nach der Freigabe setzt der Paketmanager zurück und das Ergebnis wird überprüft. Nicht zurückgesetzte Pakete werden nie als Erfolg angezeigt.
- **Software- und Dienstinventar:** Software wie nginx, PHP, MariaDB, PostgreSQL, Redis und Java wird aus den Paketen erkannt; installierte und laufende Dienste werden unterschieden, zwei Server lassen sich vergleichen, Installationen, Entfernungen und Versionswechsel werden als Verlauf gespeichert.
- **End-of-Life-(EOL-)Verfolgung:** endoflife.date-Kalender für Betriebssysteme und Software (offline mit eingebautem Kalender). Von der Distribution weiter gepflegte Pakete werden gekennzeichnet; nahende und überschrittene Termine werden gemeldet.
- **Sicherheitswert:** Ein Wert von 0-100 je Server, Gruppe und Flotte mit Tagesverlauf, einstellbaren Gewichten und Schwellenbenachrichtigung. Eine CVE, die mehrere Kriterien erfüllt, wird nur einmal abgezogen.
- **Serverstandards und Abweichungen:** Regeln wie „PHP nur 8.2 oder 8.3“, „telnetd darf nicht installiert sein“, „nginx muss laufen“. Versionsregeln vergleichen die Versionsnummern der Distribution (Backports erzeugen keine falschen Abweichungen), neue Abweichungen werden gemeldet und ein passendes Update vorgeschlagen.
- **Automatische Agentenupdates:** Wechselt der zentrale Server auf eine neue Version, laden die Agenten sie herunter, prüfen die SHA-256-Prüfsumme und aktualisieren sich selbst.
- **Hinweis auf neue Versionen:** Das Dashboard informiert Administratoren, wenn auf GitHub eine neue netio.patchman-Version erscheint, und zeigt die Update-Befehle. Für Installationen ohne Internetzugang abschaltbar. Mit dem optionalen Updater-Container läuft die Aktualisierung mit einem Klick aus dem Dashboard (git pull, Sicherung, Build, Neustart).
- **Befundverwaltung:** Status Offen, In Bearbeitung, Risiko akzeptiert und Fehlalarm. Wird ein Paket aktualisiert, wird der Befund automatisch „Behoben“. Risiken werden befristet akzeptiert (30, 90, 180 oder 365 Tage; das Maximum wird in den Einstellungen festgelegt). Nach Ablauf wird der Befund wieder geöffnet und es werden Benachrichtigung und E-Mail gesendet.
- **Servergruppen:** Teilen Sie Server in Gruppen wie „Produktion“, „Test“ oder „Datenbank“ ein. Ein Server kann mehreren Gruppen angehören. Listen lassen sich nach Gruppe filtern, geplante Updates können eine Gruppe als Ziel haben, Berichte können pro Gruppe erstellt werden.
- **Plattforminformation:** Der Agent meldet, ob der Server eine virtuelle Maschine (VMware, Hyper-V, KVM, Xen, VirtualBox), ein Docker/LXC-Container oder ein physischer Server ist. Die Serverliste lässt sich nach Plattform filtern.
- **Neustartverfolgung:** Wurde ein neuer Kernel installiert, der Server aber nicht neu gestartet, wird dies zusammen mit der Wartezeit angezeigt. Das Dashboard hat dafür eine eigene Kachel und einen Filter. Auch unter Debian (ohne `/var/run/reboot-required`) und Alpine wird dies durch Kernelvergleich erkannt.
- **Verlaufsdiagramme:** Der Server erfasst den Zustand der Flotte täglich. Das Dashboard zeigt für die letzten 30 Tage kritische und hohe Schwachstellen, aktiv ausgenutzte Schwachstellen, offene Befunde und ausstehende Sicherheitsupdates als Diagramme und Tabelle.
- **Compliance-Bericht:** Ein druckbarer Bericht (im Browser als PDF speicherbar) für einen gewählten Zeitraum und eine Gruppe: Kennzahlen, im Zeitraum erkannte und behobene Befunde, mittlere Behebungszeit, KEV-Schwachstellen nach Ablauf der CISA-Frist, Serverstatus, akzeptierte Risiken (mit akzeptierender Person und Ablaufdatum) und Update-Aufträge. Geeignet als Nachweis bei ISO-27001- und ähnlichen Audits.
- **Zwei-Faktor-Authentifizierung:** TOTP-Codes aus Apps wie Google Authenticator oder Microsoft Authenticator sowie einmalige Wiederherstellungscodes. Administratoren können sie für alle Benutzer vorschreiben und bei verlorenem Telefon für einen Benutzer zurücksetzen.
- **Benachrichtigungen:** Benachrichtigungszentrale und E-Mail-Benachrichtigungen für neue Schwachstellen, getrennte Agenten und fehlgeschlagene oder teilweise abgeschlossene Update-Aufträge.
- **Benachrichtigungskanäle und Integrationen:** Slack, Microsoft Teams, Telegram, HMAC-SHA256-signierte (mit Zeitstempel) JSON-Webhooks, Tickets in Jira, ServiceNow und GLPI sowie Zabbix-Trapper-Items. Jeder Kanal abonniert nach Stufe oder nach Ereignis (kritische CVE, KEV, EOL, Update gestartet/erfolgreich/fehlgeschlagen, Rücksetzung, Neustart, Zustandsprüfung, SLA, Wert, Server offline, Abweichung…). Fehlgeschlagene Zustellungen werden wiederholt; ein Zustellverlauf wird geführt und eine fehlgeschlagene Zustellung kann erneut gesendet werden.
- **Automatische Sicherungen:** Die Datenbank wird täglich zu einer festgelegten Uhrzeit gesichert, die neuesten N Sicherungen bleiben erhalten. Sicherungen lassen sich im Dashboard herunterladen; fehlgeschlagene Sicherungen werden gemeldet.
- **Mehrsprachige Oberfläche:** Türkisch, Englisch, Deutsch und Russisch. Jeder Benutzer wählt seine Sprache; Datum, Dezimaltrennzeichen und CSV-Format richten sich nach der Sprache.
- **Benutzer und Rollen:** Rollen Administrator, Operator und Betrachter; Prüfprotokoll.
- **Konfiguration im Dashboard:** SMTP, Serveradresse, Zeitzone, Datenquellen und alle Betriebseinstellungen werden im Dashboard geändert. Änderungen gelten ohne Neustart.
- **Export:** Server- und Schwachstellenlisten lassen sich als Excel-kompatible CSV-Dateien herunterladen.
- **Kernel-Live-Patching:** KernelCare (CloudLinux, AlmaLinux, Rocky, RHEL) und Canonical Livepatch (Ubuntu) werden erkannt. Die von KernelCare gepatchte Kernelversion gilt für Kernel-Befunde, von Livepatch behobene CVEs zählen nicht als offen, und ein von KernelCare abgedecktes Kernel-Update markiert den Server nicht als neustartbedürftig.
- **Nicht zu aktualisierende Pakete:** Muster wie `kernel*`, `mysql-*` oder `KB5034439` für alle Server, eine Gruppe oder einen Server. Alle Update-Aufträge aus Dashboard, Zeitplänen und API überspringen diese Pakete.
- **EPSS-Priorisierung:** Der FIRST-EPSS-Wert (Wahrscheinlichkeit der Ausnutzung in den nächsten 30 Tagen) wird je Schwachstelle angezeigt; die Liste lässt sich nach KEV und EPSS sortieren.
- **Behebungsfristen (SLA):** Tage je Schweregrad (Standard kritisch 15, hoch 30, mittel 90, niedrig 180). Überfällige Befunde werden markiert, erscheinen im Dashboard und im Bericht und lösen Benachrichtigung und E-Mail aus.
- **Gruppenbasierter Zugriff:** Operatoren und Betrachter lassen sich auf die Server bestimmter Gruppen beschränken (Teams oder Kunden).
- **Optionaler Neustart in Zeitplänen:** Server, die nach dem Update einen Neustart brauchen, können bei offenem Wartungsfenster neu gestartet werden (je Regel, standardmäßig aus).
- **Windows-Programme von Drittanbietern:** Auf Servern mit winget werden Updates von Programmen wie Chrome, 7-Zip oder Git angezeigt und installiert.
- **REST-API und Prometheus:** API-Schlüssel lesen Server, Schwachstellen, Updates und Aufträge und starten Update-Aufträge; `/metrics` liefert Metriken für Grafana/Prometheus. Siehe [docs/api.md](docs/api.md).

### Unterstützte Systeme

| System | Inventar und Updates | Schwachstellenscan |
|---|---|---|
| Debian, Ubuntu | apt | ✓ |
| AlmaLinux, Rocky Linux, Red Hat Enterprise Linux | dnf / yum | ✓ |
| CloudLinux 8, 9 | dnf | ✓ (mit AlmaLinux-Sicherheitsdaten) |
| CentOS 7, CloudLinux 7, Oracle Linux 7 | yum | ✓ (mit Red-Hat-7- und TuxCare-ELS-Daten) |
| Oracle Linux 8, 9; CentOS Linux 8 | dnf | ✓ (mit AlmaLinux-Daten) |
| Mageia, openEuler | dnf | ✓ |
| Linux Mint, Pop!_OS, Zorin OS, elementary OS, LMDE, Raspberry Pi OS | apt | ✓ (mit den Daten ihrer Ubuntu/Debian-Version) |
| SUSE Linux Enterprise, openSUSE Leap | zypper | ✓ |
| Alpine Linux | apk | ✓ |
| CentOS Stream, Amazon Linux, Fedora und andere Distributionen (mit dnf, yum, zypper, apt oder apk) | ✓ | — |
| Windows Server 2016, 2019, 2022, 2025; Windows 10, 11 (x64) | Windows Update | ✓ (ausstehende Microsoft-Updates) |

Der Agent läuft auf amd64 und arm64. Als Dienstmanager wird systemd oder OpenRC (Alpine) benötigt. Physische, virtuelle (VMware, Hyper-V, KVM/Proxmox) und Cloud-Server werden gleichermaßen unterstützt.

Unter Windows läuft der Agent auf x64-Systemen als Windows-Dienst und verwendet den Windows Update Agent; Server mit WSUS sehen die in WSUS genehmigten Updates. Der Schwachstellenscan unter Windows beschränkt sich auf Microsoft-Updates: Programme von Drittanbietern (Browser, 7-Zip usw.) erscheinen im Inventar, werden aber nicht gescannt. Updates, für die Microsoft keine CVE-Zuordnung veröffentlicht (etwa manche .NET-Rollups), werden als Sicherheitsupdates mit dem von Windows Update gemeldeten Schweregrad angezeigt.

CloudLinux 8 und 9 werden aus AlmaLinux-Quellen gebaut und mit den AlmaLinux-Sicherheitsdaten gescannt. CloudLinux-eigene Pakete (LVE-Werkzeuge, alt-php usw.) sind in diesen Daten nicht enthalten und werden nicht gescannt; der LVE-Kernel wird mit derselben AlmaLinux-Kernelversion verglichen. Für CloudLinux 7 gibt es keine Schwachstellendaten.

## Screenshots

Die Screenshots zeigen die türkische Oberfläche; die anderen Sprachen haben dasselbe Layout. Sie stammen von sechs Testservern mit Ubuntu, Debian, Rocky Linux, AlmaLinux und Alpine. Die Schwachstellen sind echte Daten von OSV.dev.

**Serverinventar:** Alle Server mit Schwachstellen nach Schweregrad, ausstehenden Updates und Agentenstatus. Auf ausgewählten Servern können Sammel-Updates gestartet werden.

![Serverinventar](docs/images/servers.png)

**Serverdetails:** Die Schwachstellen des Servers mit CVSS-Wert, betroffenem Paket, installierter und korrigierter Version. Sicherheitsupdates, alle Updates und Neustarts starten mit einem Klick.

![Serverdetails](docs/images/server.png)

**Schwachstellen:** Alle in der Flotte gefundenen Schwachstellen, filterbar nach Schweregrad, Ausnutzung und verfügbarer Korrektur.

![Schwachstellen](docs/images/vulnerabilities.png)

**Schwachstellendetails:** Die (nicht übersetzte) Originalbeschreibung, CVSS-Vektor, betroffene Server und Status.

![Schwachstellendetails](docs/images/vulnerability.png)

**Update-Auftrag:** Der Agent sendet die Befehlsausgabe und prüft nach dem Auftrag, ob die Pakete tatsächlich aktualisiert wurden.

![Update-Auftrag](docs/images/job.png)

**Geplante Updates:** Wartungsfenster mit Tagen, Uhrzeit, Dauer und Zielservern (alle, ein Betriebssystem, eine Gruppe oder ausgewählte Server).

![Geplantes Update](docs/images/schedule.png)

**Agenteninstallation:** Distribution wählen, der Installationsbefehl wird dafür erzeugt (curl oder wget, root oder sudo).

![Agenten](docs/images/agents.png)

**Dunkles Design:** Das Dashboard folgt der hellen oder dunklen Darstellung des Betriebssystems.

![Dashboard, dunkles Design](docs/images/dashboard-dark.png)

## Funktionsweise

```
 Verwaltete Server                       Zentraler Server (Docker)               Externe Quellen
┌──────────────────────┐   HTTPS   ┌──────────────────────────────┐   HTTPS   ┌──────────────┐
│ netio-patchman-agent │ ────────▶ │ netio.patchman               │ ────────▶ │ api.osv.dev  │
│  Inventar, Aufträge  │ (ausgeh.) │  Dashboard + API + PostgreSQL│           │ CISA KEV     │
│  (Linux, Windows)    │           │                              │           │ MSRC         │
└──────────────────────┘           └──────────────────────────────┘           └──────────────┘
                                                 ▲
                                     Browser ────┘  (Dashboard)
```

1. Der Agent verbindet sich in regelmäßigen Abständen mit dem zentralen Server. Er meldet installierte Pakete und ausstehende Updates und holt einen Auftrag ab, falls einer wartet.
2. Der zentrale Server gleicht Paketversionen mit den Sicherheitsdaten der Distributionen auf OSV.dev ab und zeigt die Befunde im Dashboard. Für Windows-Server stammen die CVEs der ausstehenden KBs aus dem Microsoft Security Update Guide.
3. Update-Aufträge aus dem Dashboard erhält der Agent bei seiner nächsten Verbindung. Er führt sie mit festen Paketmanager-Befehlen aus und meldet das Ergebnis.

Auf verwalteten Servern müssen keine eingehenden Ports geöffnet werden.

## Installation (Docker)

### Voraussetzungen

- Ein Linux-Server mit Docker Engine 24 oder neuer und Docker Compose v2.24 oder neuer.
- `git`.
- **Internetzugang:** Der erste Build lädt Docker-Images und Go-Module herunter. Für Schwachstellendaten ist außerdem HTTPS-Zugriff auf `api.osv.dev` und `www.cisa.gov` nötig. Für Umgebungen ohne Internetzugang siehe [docs/kurulum.md](docs/kurulum.md#8-internet-erişimi-olmayan-ortamlar) (Türkisch).
- **Empfohlene Ressourcen:** bis 100 Server: 1 CPU-Kern, 1 GB RAM und 5 GB Festplatte.

Ist Docker nicht installiert, können Sie es mit dem offiziellen Skript von Docker installieren:

```sh
curl -fsSL https://get.docker.com | sudo sh
```

### 1. Repository herunterladen

```sh
git clone https://github.com/alptekinsunnetci/netio.patchman.git
cd netio.patchman
```

### 2. (Optional) Serveradresse und Sprache festlegen

Tragen Sie die Adresse, über die Agenten und Benutzer den zentralen Server erreichen, in die Datei `.env` ein. Um Deutsch zur Standardsprache zu machen (für neue Benutzer, E-Mails, Chat-Nachrichten und Protokolle), setzen Sie außerdem `PATCHMAN_LOCALE`:

```sh
cp .env.example .env
nano .env        # PATCHMAN_BASE_URL=https://patchman.your-domain
                 # PATCHMAN_LOCALE=de-DE
```

Ohne diesen Schritt beginnt die Adresse mit `http://localhost:8080`. Sie können sie nach der Installation unter **Einstellungen → Serverkonfiguration** ändern. Prüfen Sie die Adresse, bevor Sie Agenten installieren, denn der Installationsbefehl verwendet sie.

### 3. Starten

```sh
docker compose up -d --build
```

Der erste Build dauert je nach Verbindung einige Minuten. Status prüfen:

```sh
docker compose ps                 # in der Spalte STATUS sollte "healthy" stehen
docker compose logs -f server     # Protokolle (Beenden mit Strg+C)
```

### 4. Erstes Administratorkonto anlegen

Öffnen Sie `http://<server-adresse>:8080` im Browser. Da die Datenbank leer ist, öffnet sich die Seite **Ersteinrichtung**. Wechseln Sie über den Link **Deutsch** unten auf der Seite die Sprache und legen Sie das Administratorkonto an. Diese Seite ist nur verfügbar, solange es keine Benutzer gibt.

### 5. Grundeinstellungen

Im Dashboard unter **Einstellungen → Serverkonfiguration**:

- **Serveradresse:** Die externe Adresse für die Agenten, zum Beispiel `https://patchman.your-domain`.
- **E-Mail-Server (SMTP):** Für E-Mail-Benachrichtigungen. Auf derselben Seite können Sie eine Test-E-Mail senden.

Die Installation ist abgeschlossen. Als Nächstes installieren Sie den Agenten auf Ihren Servern.

### HTTPS

Agenten und Browser sollten sich per HTTPS mit dem Server verbinden. Empfohlen ist ein Reverse-Proxy wie nginx, Caddy oder HAProxy vor dem Server. Schalten Sie in diesem Fall im Dashboard **Den Headern X-Forwarded-For und X-Forwarded-Proto eines Reverse-Proxys vertrauen** ein. Beispielkonfigurationen und TLS direkt im Server: siehe [docs/kurulum.md](docs/kurulum.md#3-tls-ve-ters-vekil) (Türkisch).

**Port ändern:** Setzen Sie `PATCHMAN_PUBLISH_PORT=8899` in `.env` und führen Sie `docker compose up -d` erneut aus. Läuft der Reverse-Proxy auf derselben Maschine, verwenden Sie `PATCHMAN_PUBLISH_PORT=127.0.0.1:8899`, damit das Dashboard nicht unverschlüsselt per HTTP erreichbar ist. Ändern Sie den Port nicht mit `PATCHMAN_HTTP_ADDR`; diese Einstellung ist für Installationen ohne Docker gedacht und wird von Docker Compose ignoriert.

**Plesk:** Fügen Sie unter **Apache- & nginx-Einstellungen → Zusätzliche nginx-Anweisungen** der Domain Folgendes ein. Die Form mit regulärem Ausdruck vermeidet einen Konflikt mit Plesks eigenem `location /`-Block:

```nginx
location ~ ^/ {
    proxy_pass http://127.0.0.1:8899;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 64m;
}
```

Schalten Sie anschließend die Reverse-Proxy-Option im Dashboard ein (oder setzen Sie `PATCHMAN_TRUST_PROXY=true` in `.env`).

## Agent auf Servern installieren

1. Erstellen Sie auf der Seite **Agenten** einen **Registrierungsschlüssel**. Der Schlüssel wird nur einmal angezeigt. Sie können eine Gültigkeitsdauer und ein Verwendungslimit festlegen.
2. Wählen Sie auf der Seite die Distribution des Servers. Der Befehl wird dafür erzeugt: `wget` unter Debian und Alpine, sonst `curl`. Wenn Sie als root verbunden sind, lassen Sie **Mit sudo ausführen** leer (sudo ist unter CentOS, Debian und Alpine oft nicht installiert). Ist das Dashboard auf Deutsch, enthält der Befehl `--locale de-DE`, damit auch die Meldungen des Agenten deutsch sind. Führen Sie den Befehl auf dem zu verwaltenden Server aus. Beispiel (als root, RHEL/CentOS):

   ```sh
   curl -fsSL https://patchman.your-domain/downloads/install-agent.sh | \
     sh -s -- --server-url https://patchman.your-domain --token <REGISTRIERUNGSSCHLÜSSEL> --locale de-DE
   ```

3. Der Server erscheint innerhalb von Sekunden im **Serverinventar**, und der erste Schwachstellenscan startet automatisch.

Das Installationsskript:

- installiert den Agenten als `/usr/local/bin/netio-patchman-agent`,
- schreibt die Konfiguration nach `/etc/netio-patchman/agent.env`,
- startet den Dienst: `netio-patchman-agent.service` mit systemd, `/etc/init.d/netio-patchman-agent` mit OpenRC (Alpine).

Die Ausgabe des Installationsskripts ist türkisch.

Status und Protokolle des Agenten:

```sh
systemctl status netio-patchman-agent
journalctl -u netio-patchman-agent -f
```

Massenverteilung (Ansible usw.), Offline-Installation, Agentenoptionen und Entfernung: siehe [docs/kurulum.md](docs/kurulum.md#4-ajan-kurulumu) (Türkisch).

### Windows-Server

Wählen Sie auf der Seite Agentenverwaltung **Windows / Windows Server (PowerShell)** und führen Sie den erzeugten Befehl auf dem Server in einer **als Administrator** geöffneten PowerShell oder Eingabeaufforderung aus:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm 'https://patchman.your-domain/downloads/install-agent.ps1').TrimStart([char]65279))) -ServerUrl 'https://patchman.your-domain' -Token '<REGISTRIERUNGSSCHLÜSSEL>'"
```

Das Installationsskript legt den Agenten unter `C:\Program Files\netio-patchman\netio-patchman-agent.exe` ab, schreibt die Konfiguration nach `C:\ProgramData\netio-patchman\agent.env` (nur für SYSTEM und Administratoren lesbar) und erstellt und startet den Windows-Dienst `netio-patchman-agent` (automatischer Start, Neustart bei Fehlern). Das Protokoll ist `C:\ProgramData\netio-patchman\agent.log`:

```powershell
Get-Service netio-patchman-agent
Get-Content C:\ProgramData\netio-patchman\agent.log -Tail 50 -Wait
```

Für Server ohne Internetzugang kopieren Sie `install-agent.ps1` und `netio-patchman-agent-windows-amd64.exe` in einen Ordner und verwenden die Option `-Binary`. Entfernen: `.\install-agent.ps1 -Uninstall`. Der Agent fragt den Windows-Update-Dienst höchstens alle 6 Stunden online ab; dazwischen liest er das Ergebnis der letzten Suche von Windows selbst.

## Aktualisierung, Sicherung und Entfernung

### Auf eine neue Version wechseln

```sh
cd netio.patchman
git pull
docker compose up -d --build
```

- Das Datenbankschema wird beim Start automatisch aktualisiert; erstellen Sie trotzdem vorher eine Sicherung.
- Die Version wird aus der Datei `VERSION` im Repository gelesen.
- Ist **Einstellungen → Agenten → Agenten automatisch aktualisieren** eingeschaltet (Standard), wechseln die Agenten selbst auf die neue Version.

### 0.8.0: Umstieg auf PostgreSQL

Mit Version 0.8.0 zieht die Datenbank von SQLite nach PostgreSQL um. Die Compose-Datei startet jetzt neben der Anwendung einen PostgreSQL-17-Container (`postgres`, Volume `netio-patchman-db`). Für den Umstieg ist nichts weiter nötig; das übliche `git pull && docker compose up -d --build` (oder **Jetzt aktualisieren** im Dashboard) genügt:

1. Der PostgreSQL-Container startet zum ersten Mal. Sein Passwort wird zufällig erzeugt und im Datenbank-Volume abgelegt; es wird kein Port veröffentlicht.
2. Ist PostgreSQL leer und gibt es `/data/netio-patchman.db`, kopiert der Server alle Tabellen in einer Transaktion nach PostgreSQL und vergleicht die Zeilenzahl jeder Tabelle mit der Quelle. Das Dashboard öffnet sich erst danach. Eine Datenbank mit 1,3 Millionen Zeilen wird in etwa 15 Sekunden übertragen.
3. Danach wird die alte Datei in `netio-patchman.db.imported-<Zeit>` umbenannt (nicht gelöscht), in der Benachrichtigungszentrale erscheint ein Hinweis und der Umzug wird im Audit-Log vermerkt.

Schlägt ein Schritt fehl, bleibt PostgreSQL leer, die SQLite-Datei unverändert und der Server startet nicht. Der Fehler steht in `docker compose logs server`. Nach Behebung der Ursache startet `docker compose up -d` die Übertragung erneut.

- **Bei SQLite bleiben:** `PATCHMAN_DATABASE_URL=sqlite` in `.env` eintragen. Der PostgreSQL-Container läuft weiter, wird aber nicht verwendet.
- **Externes PostgreSQL:** `PATCHMAN_DATABASE_URL=postgres://benutzer:passwort@host:5432/datenbank?sslmode=require` in `.env` eintragen. Ist diese Datenbank leer, werden die SQLite-Daten dorthin übertragen.
- **Zurück:** mit `PATCHMAN_DATABASE_URL=sqlite` starten und eine aktuelle Sicherung mit dem Befehl `restore` wiederherstellen; die Schritte stehen in [docs/kurulum.md](docs/kurulum.md#22-veritabanı) (Türkisch).

### Aktualisierung aus dem Dashboard (optional)

Die Aktualisierung lässt sich auch über **Einstellungen → Serverkonfiguration → Produktversion → Jetzt aktualisieren** starten. Schalten Sie dazu einmalig den `updater`-Container aus der Compose-Datei ein:

```sh
cd netio.patchman
echo "COMPOSE_PROFILES=updater" >> .env
docker compose up -d --build
```

Der Updater führt dann `git pull --ff-only`, eine Datenbanksicherung (`/data/before-update-<Version>-<Zeit>.db`), den Image-Build, den Neustart und eine Zustandsprüfung aus. Fortschritt und Befehlsausgabe erscheinen im Dashboard; die Seite lädt sich danach neu, das Ergebnis landet in der Benachrichtigungszentrale. Das Dashboard ist einige Sekunden nicht erreichbar; Agenten sind nicht betroffen. Schlägt ein Schritt fehl, läuft der Server mit der aktuellen Version weiter.

> [!WARNING]
> Der Updater hat Zugriff auf den Docker-Socket (`/var/run/docker.sock`), was root-Rechten auf dem Server entspricht. Er öffnet keinen Port, wartet nur auf die Anforderungsdatei, die das Dashboard in das Datenvolume schreibt, und führt feste Schritte aus; aus der Anforderung übernimmt er keine Parameter. Schalten Sie ihn trotzdem nur bei Bedarf ein und schützen Sie Administratorkonten mit Zwei-Faktor-Authentifizierung. Hat das Repository lokale Änderungen, bricht `git pull --ff-only` ab und es wird nichts aktualisiert.

### Sicherung und Wiederherstellung

**Automatische Sicherungen** sind standardmäßig eingeschaltet: Die Datenbank wird täglich um 02:30 nach `/data/backups/` gesichert, die neuesten 7 Sicherungen bleiben erhalten. Uhrzeit, Anzahl und Ein/Aus finden Sie unter **Einstellungen → Automatische Sicherung**, dort auch **Jetzt sichern** und Download-Links. Standardmäßig liegen die Sicherungen im selben Docker-Volume wie die Datenbank; kopieren Sie sie regelmäßig an einen anderen Ort oder schreiben Sie sie mit `PATCHMAN_BACKUP_DIR` auf eine separate Festplatte (siehe [docs/kurulum.md](docs/kurulum.md), Abschnitt 5.1, Türkisch).

Sie können auch manuell eine konsistente Sicherung erstellen:

```sh
docker compose exec server netio-patchman-server backup -out /data/sicherung.db
docker compose cp server:/data/sicherung.db ./sicherung-$(date +%Y%m%d).db
```

Wiederherstellung aus einer Sicherung (Sicherungen sind unabhängig von der verwendeten Datenbank SQLite-Dateien):

```sh
docker compose stop server
docker compose run --rm --no-deps server restore -in /data/backups/netio-patchman-20261120-023000.db
docker compose start server
```

Eine Sicherung von außerhalb zuerst ins Volume kopieren: `docker compose cp ./sicherung-20261120.db server:/data/sicherung.db`, dann mit `-in /data/sicherung.db` wiederherstellen. Die Wiederherstellung läuft in einer Transaktion: schlägt sie fehl, bleibt die Datenbank unverändert.

Die Daten liegen im PostgreSQL-Volume `netio-patchman-db`, die Sicherungen im Volume `netio-patchman-data` (`/data/backups`). Sicherungen enthalten auch das SMTP-Passwort; schützen Sie sie entsprechend.

### Administratorpasswort zurücksetzen

```sh
docker compose exec server netio-patchman-server reset-password -email admin@your-domain
```

Der Befehl erzeugt ein neues Passwort und gibt es aus.

Die Zwei-Faktor-Authentifizierung eines Benutzers, der sein Telefon verloren hat, lässt sich im Dashboard (**Benutzer → Benutzer → Zwei-Faktor-Authentifizierung zurücksetzen**) oder auf der Kommandozeile entfernen:

```sh
docker compose exec server netio-patchman-server reset-mfa -email admin@your-domain
```

### Entfernen oder neu beginnen

```sh
docker compose down        # stoppt den Container, Daten bleiben erhalten
docker compose down -v     # löscht Container und Datenbank (nicht rückgängig zu machen)
```

Nach `down -v` startet `docker compose up -d` mit einer leeren Datenbank bei der **Ersteinrichtung**.

## Konfiguration

Die gesamte Konfiguration ist im Dashboard möglich:

- **Einstellungen:** Benachrichtigungsschwellen und Empfänger, Verbindungsintervalle der Agenten, automatische Agentenupdates, Scans, Aufbewahrung, Sicherheit (Zwei-Faktor-Authentifizierung, Dauer der Risikoakzeptanz) und automatische Sicherungen.
- **Einstellungen → Benachrichtigungskanäle:** Slack, Microsoft Teams, Telegram, Webhooks, Jira, ServiceNow, GLPI und Zabbix, Ereignisfilter und Zustellverlauf.
- **Einstellungen → Zustandsprüfungen, Sicherheitswert:** Prüfungen vor und nach Updates, Gewichte und Schwelle des Werts.
- **Einstellungen → Serverkonfiguration:** Serveradresse, Reverse-Proxy, Zeitzone, Protokollstufe, SMTP und Datenquellen (OSV, CISA KEV, Microsoft Security Update Guide).

Die Variablen mit dem Präfix `PATCHMAN_` in `.env` liefern nur die Anfangswerte; ein im Dashboard gespeicherter Wert ersetzt sie. Mit „—“ in der Spalte „Dashboard“ markierte Werte werden beim Start benötigt und können nur in `.env` geändert werden; sie erfordern einen Neustart. Alle Optionen sind in [.env.example](.env.example) beschrieben (Kommentare auf Türkisch).

| Variable | Standard | Beschreibung | Dashboard |
|---|---|---|---|
| `PATCHMAN_BASE_URL` | `http://localhost:8080` | Externe Adresse für Dashboard und Agenten | ja |
| `PATCHMAN_PUBLISH_PORT` | `8080` | Von Docker auf dem Host veröffentlichter Port; die Form `127.0.0.1:8899` veröffentlicht nur lokal | — |
| `PATCHMAN_HTTP_ADDR` | `:8080` | Lauschadresse nur für Installationen ohne Docker; in Docker Compose fest `:8080` | — |
| `PATCHMAN_TRUST_PROXY` | `false` | Client-IP hinter einem Reverse-Proxy aus `X-Forwarded-For` übernehmen | ja |
| `PATCHMAN_TLS_CERT_FILE`, `PATCHMAN_TLS_KEY_FILE` | — | Zertifikat und Schlüssel, wenn der Server TLS selbst beendet | — |
| `PATCHMAN_TIMEZONE` | `Europe/Istanbul` | Zeitzone für die Anzeige von Datum und Uhrzeit | ja |
| `PATCHMAN_LOCALE` | `tr-TR` | Standardsprache (`tr-TR`, `en-US`, `de-DE` oder `ru-RU`): Oberfläche neuer Benutzer, E-Mails und Protokolle. Jeder Benutzer kann seine eigene Sprache wählen | — |
| `PATCHMAN_DATABASE_URL` | PostgreSQL aus Compose | PostgreSQL-Adresse (`postgres://benutzer@host:5432/datenbank`); `sqlite` verwendet die SQLite-Datei `/data/netio-patchman.db` | — |
| `PATCHMAN_DATABASE_PASSWORD_FILE` | Passwortdatei aus Compose | Datei, aus der das Passwort gelesen wird, wenn die Adresse keines enthält | — |
| `PATCHMAN_BACKUP_DIR` | `/data/backups` | Verzeichnis für automatische Sicherungen | — |
| `PATCHMAN_OSV_URL` | `https://api.osv.dev` | OSV-API-Adresse (ein interner Spiegel ist möglich) | ja |
| `PATCHMAN_KEV_URL` | CISA-KEV-Adresse | Adresse des KEV-Katalogs; `off` schaltet ihn ab | ja |
| `PATCHMAN_MSRC_URL` | `https://api.msrc.microsoft.com/sug/v2.0/en-US` | Adresse des Microsoft Security Update Guide für die CVE-Zuordnung von Windows-Servern; `off` schaltet ihn ab | ja |
| `PATCHMAN_EPSS_URL` | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Tägliche EPSS-Datei; `off` schaltet sie ab | ja |
| `PATCHMAN_EOL_URL` | `https://endoflife.date/api` | End-of-Life-Kalender für Betriebssysteme und Software; `off` schaltet ab (eingebauter Kalender) | ja |
| `PATCHMAN_SMTP_HOST`, `PATCHMAN_SMTP_PORT` | —, `587` | E-Mail-Server | ja |
| `PATCHMAN_SMTP_USERNAME`, `PATCHMAN_SMTP_PASSWORD` | — | SMTP-Zugangsdaten | ja |
| `PATCHMAN_SMTP_FROM_NAME`, `PATCHMAN_SMTP_FROM_ADDRESS` | `netio.patchman`, — | Absendername und -adresse | ja |
| `PATCHMAN_LOG_LEVEL`, `PATCHMAN_LOG_FORMAT` | `info`, `json` | Protokollstufe und -format | Stufe: ja, Format: — |
| `PATCHMAN_VERSION` | Datei `VERSION` | Zu bauende Server- und Agentenversion | — |

Hat eine Umgebungsvariable einen ungültigen Wert, startet der Server nicht und listet die Fehler in der Standardsprache auf.

## REST-API und Prometheus

Erstellen Sie einen Schlüssel unter **Profil → API-Schlüssel**. Ein Schlüssel arbeitet mit Rolle und Serverzugriff des erstellenden Benutzers; schreibgeschützte Schlüssel können nichts ändern. Endpunkte, Felder und Beispiele: [docs/api.md](docs/api.md) (Türkisch).

```sh
curl -H "Authorization: Bearer npat_..." https://patchman.your-domain/api/v1/hosts
curl -H "Authorization: Bearer npat_..." "https://patchman.your-domain/api/v1/vulnerabilities?sort=epss&overdue=1"
curl -X POST -H "Authorization: Bearer npat_..." -H "Content-Type: application/json" \
  -d '{"type":"upgrade_security"}' https://patchman.your-domain/api/v1/hosts/12/jobs
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: netio-patchman
    scheme: https
    authorization: { credentials: npat_... }
    static_configs: [{ targets: ["patchman.your-domain"] }]
```

## Fehlerbehebung

| Symptom | Prüfung |
|---|---|
| Nach einer Aktualisierung startet der Server nicht, im Log steht, dass die SQLite-Datenbank nicht nach PostgreSQL übertragen werden konnte | Details stehen im selben Log-Eintrag; die SQLite-Datei ist unverändert. Mit `docker compose ps` prüfen, ob `postgres` "healthy" ist und genug Speicherplatz frei ist, dann `docker compose up -d`. Vorübergehend zurück zu SQLite: `PATCHMAN_DATABASE_URL=sqlite` in `.env`. |
| Das Dashboard öffnet sich nicht | `docker compose ps` sollte in der Spalte PORTS `0.0.0.0:<port>->8080/tcp` zeigen. Fehler mit `docker compose logs server` ansehen. Ist der Port `PATCHMAN_PUBLISH_PORT` in der Firewall offen? |
| Der Installationsbefehl zeigt `localhost` | Ändern Sie auf der Seite **Serverkonfiguration** die Serveradresse auf eine für die Agenten erreichbare Adresse. |
| Der Agent registriert sich nicht | Funktioniert `curl -I https://patchman.your-domain/healthz` vom Server des Agenten aus? `journalctl -u netio-patchman-agent -n 50` |
| Der Windows-Agent registriert sich nicht oder zeigt keine Updates | `Get-Content C:\ProgramData\netio-patchman\agent.log -Tail 50`. Ist der Windows-Update-Dienst (`wuauserv`) deaktiviert? Nutzt der Server WSUS: Sind die Updates dort genehmigt? |
| Keine CVEs auf einem Windows-Server | Erreicht der zentrale Server `api.msrc.microsoft.com`? Ist der Microsoft Security Update Guide in der **Serverkonfiguration** eingeschaltet? |
| Der Schwachstellenscan findet nichts | Erreicht der zentrale Server `api.osv.dev`? Suchen Sie in den Protokollen nach OSV-Fehlern. |
| Es kommen keine E-Mails an | Senden Sie auf der Seite **Serverkonfiguration** eine Test-E-Mail; der Fehler wird im Dashboard angezeigt. |

Weitere Informationen (Türkisch): [docs/kurulum.md](docs/kurulum.md) (Installation und Betrieb), [docs/kullanim.md](docs/kullanim.md) (Bedienung des Dashboards).

## Sprache und Lokalisierung

- Die Standardsprache ist Türkisch (`tr-TR`). Die Oberfläche ist außerdem auf Englisch (`en-US`), Deutsch (`de-DE`) und Russisch (`ru-RU`) verfügbar: über die Links auf der Anmeldeseite oder **Mein Profil → Sprache der Oberfläche**. Die Auswahl wird für den Benutzer gespeichert und gilt auch auf anderen Geräten.
- E-Mails, Chat-Nachrichten und Systemprotokolle verwenden die Standardsprache des Servers (`PATCHMAN_LOCALE`). Die Sprache der Agentenmeldungen wird bei der Installation mit `--locale` festgelegt; das Dashboard fügt diese Option dem Installationsbefehl selbst hinzu.
- Datumsangaben erscheinen auf Deutsch, Russisch und Türkisch als `21.11.2026`, auf Englisch als `2026-11-21`. CSV-Dateien werden auf Englisch mit `,`, sonst mit `;` getrennt.
- **Schwachstellendaten werden nie übersetzt.** CVE-IDs, offizielle Titel, Beschreibungen, CVSS-Werte, Paketnamen und Herstellerhinweise werden genau so angezeigt, wie die Quelle sie veröffentlicht.
- Zeiten werden in UTC gespeichert und in der gewählten Zeitzone angezeigt (Standard `Europe/Istanbul`).
- Die Oberflächentexte liegen in `internal/i18n/locales/`. Eine neue Sprache wird als neue Datei mit denselben Schlüsseln hinzugefügt; ein Test prüft, dass jeder Katalog alle Schlüssel und Platzhalter enthält.
- Die Dokumentation in `docs/` ist türkisch.

## Sicherheit

- Passwörter werden mit PBKDF2-SHA256 (600.000 Iterationen) gespeichert. Sitzungen, Registrierungsschlüssel und Agentenzugangsdaten werden in der Datenbank nur als SHA-256-Hashes abgelegt.
- Alle Formularaktionen sind gegen CSRF geschützt. Fehlgeschlagene Anmeldungen werden pro IP und Konto begrenzt. Zwei-Faktor-Authentifizierung (TOTP) ist verfügbar und kann vorgeschrieben werden.
- Der Agent öffnet keine Ports und nimmt keine eingehenden Verbindungen an. Er führt nur vordefinierte Paketmanager-Befehle ohne Shell aus; Paketnamen werden auf beiden Seiten geprüft. Unter Windows wird Windows Update über ein im Agenten eingebettetes, festes PowerShell-Skript (Windows Update Agent API) verwendet; auch KB-Namen werden geprüft.
- Um Remote-Updates auf einem Server vollständig abzuschalten, setzen Sie `PATCHMAN_REMOTE_UPDATES=false` in dessen `/etc/netio-patchman/agent.env`. Unter Windows steht dieselbe Einstellung in `C:\ProgramData\netio-patchman\agent.env`.
- Das Dashboard wird mit einer strengen Content-Security-Policy ausgeliefert und nutzt keine externen Ressourcen (CDNs, Schriftarten); es funktioniert auch in Netzen ohne Internetzugang.

## Entwicklung

Voraussetzung: Go 1.26 oder neuer.

```sh
go test ./...                                   # Unit- und End-to-End-Tests (SQLite)
# Dieselben Tests mit PostgreSQL (jeder Test in einem eigenen Schema):
PATCHMAN_TEST_DATABASE_URL=postgres://patchman:passwort@127.0.0.1:5432/patchman go test ./...
go vet ./...
PATCHMAN_DATA_DIR=./data go run ./cmd/netio-patchman-server

# Agentendateien im Verteilungsformat des Servers nach dist/agent/ bauen
scripts/build-agent.sh                                    # Linux / macOS
powershell -File scripts\build-agent.ps1                  # Windows

# Live-Scantest gegen OSV.dev und den Microsoft Security Update Guide (Internetzugang erforderlich)
go test -tags live -run Live -v ./internal/scanner/

# Echte Windows-Update-Suche unter Windows (sucht nur, installiert nichts)
go test -tags live -run LiveWindows -v ./internal/agent/
```

Die Produktanforderungen liegen im Verzeichnis [docs/spec/](docs/spec/).

## Haftungsausschluss

netio.patchman wird „WIE BESEHEN“ (AS IS) bereitgestellt. Es wird keinerlei ausdrückliche oder stillschweigende Gewährleistung übernommen, einschließlich Marktgängigkeit, Eignung für einen bestimmten Zweck, fehlerfreiem oder unterbrechungsfreiem Betrieb und vollständiger Erkennung von Schwachstellen.

**Alle Risiken und Folgen der Installation und Nutzung der Software trägt die Person oder Organisation, die sie installiert und nutzt.** Soweit gesetzlich zulässig, haftet der Entwickler nicht für direkte oder indirekte Schäden, insbesondere:

- Dienstausfälle, Inkompatibilitäten und Datenverlust während oder nach Paketupdates, Dienstneustarts oder Serverneustarts.
- Fehlgeschlagene, unvollständige oder unerwartete Update-Aufträge und geplante Updates.
- Nicht erkannte, falsch erkannte oder mit falschem Schweregrad angezeigte Schwachstellen. Sicherheitsdaten stammen aus Drittquellen (OSV.dev, CISA KEV, Microsoft Security Update Guide, Hinweise der Distributionen); ihre Richtigkeit hängt von diesen Quellen ab.
- Fehlkonfiguration der Software, der Agenten oder des zentralen Servers, ungeschützter Zugang oder Missbrauch.

Vor der Nutzung:

- Testen Sie die Software zuerst in einer Nicht-Produktivumgebung.
- Sichern Sie vor Updates Ihre Server und die netio.patchman-Datenbank.
- Spielen Sie Updates auf kritischen Servern kontrolliert in Wartungsfenstern ein.
- Stellen Sie den zentralen Server nur per HTTPS und nur für vertrauenswürdige Netze bereit.

Mit der Installation und Nutzung dieser Software akzeptieren Sie diese Bedingungen.

## Lizenz

Entwickler: **Alptekin Sünnetci**. Copyright © 2026 Alptekin Sünnetci.

netio.patchman steht unter der [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) mit der Bedingung **Commons Clause**. Volltext: [LICENSE](LICENSE).

- **Erlaubt:** Die Software kostenlos nutzen (auf eigener Infrastruktur, auch innerhalb Ihrer Organisation), untersuchen, ändern und kostenlos weitergeben.
- **Nicht erlaubt:** Die Software oder ein Produkt bzw. eine Dienstleistung, deren Wert ganz oder wesentlich aus ihr stammt, gegen Entgelt an Dritte anzubieten. Dazu gehören Verkauf, kostenpflichtiges Hosting und kostenpflichtige Beratung oder Support.
- Weitergegebene Kopien müssen die Datei LICENSE und den Urheberrechtshinweis enthalten.

Für eine kommerzielle Nutzung wenden Sie sich an den Entwickler.

Verbindlich ist der Lizenztext in der Datei [LICENSE](LICENSE); dieser Abschnitt ist nur eine Zusammenfassung.

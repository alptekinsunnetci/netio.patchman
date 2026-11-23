# netio.patchman

**Central Linux and Windows Vulnerability and Update Management**

[Türkçe](README.md) · **English** · [Deutsch](README.de.md) · [Русский](README.ru.md)

netio.patchman is a self-hosted platform for monitoring and managing the vulnerabilities and package updates of hundreds of Linux and Windows servers from a single dashboard.

- The central server runs with Docker Compose: the application container and a PostgreSQL database. The SQLite database of earlier versions is moved into PostgreSQL automatically on the first start. No queue or cache service is needed.
- A small agent is installed on each managed server. The agent opens no ports; it connects to the central server itself.
- The web interface is available in Turkish, English, German and Russian, and each user picks their own language. CVE data is shown exactly as published by its source, never translated.

> [!WARNING]
> **You use this software entirely at your own risk.** netio.patchman updates packages and restarts services and servers on your machines. It is provided "as is", without any warranty. The person or organization that installs and uses the software is responsible for any damage resulting from its use, including data loss, service outages, failed updates and security vulnerabilities. Details: [Disclaimer](#disclaimer).

![Dashboard](docs/images/dashboard.png)

## Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [How it works](#how-it-works)
- [Installation (Docker)](#installation-docker)
- [Installing the agent on servers](#installing-the-agent-on-servers)
- [Updating, backup and removal](#updating-backup-and-removal)
- [Configuration](#configuration)
- [REST API and Prometheus](#rest-api-and-prometheus)
- [Troubleshooting](#troubleshooting)
- [Language and localization](#language-and-localization)
- [Security](#security)
- [Development](#development)
- [Disclaimer](#disclaimer)
- [License](#license)

## Features

- **Server inventory:** Operating system, kernel, IP addresses, installed packages, pending updates, reboot status and services still running old code.
- **Vulnerability scanning:** Installed package versions are matched against the distributions' official security data through [OSV.dev](https://osv.dev). CVSS score, severity, fixed version and vendor advisories are shown.
- **Known exploited vulnerabilities:** Vulnerabilities in the CISA Known Exploited Vulnerabilities (KEV) catalog are flagged and prioritized.
- **Windows servers:** Windows Server 2016, 2019, 2022, 2025 and Windows 10 and 11 are managed from the same dashboard. The agent runs as a Windows service and reports installed programs and the updates pending in Windows Update (KB number, title, Microsoft severity, classification). The CVEs each pending KB fixes come from the Microsoft Security Update Guide (MSRC). When a server is several months behind, the CVEs of the older cumulative updates it supersedes are added too, compared against the server's Windows build. Security updates, all updates or selected KBs are installed from the dashboard and verified; the server can be restarted from the dashboard.
- **Central updates:** Install security updates, all updates or selected packages on one server, on selected servers or on all of them from the dashboard. **Apply fix** on a CVE updates the related packages on every affected server. After each job the agent verifies that the packages were really updated; packages that were not updated are listed and can be retried with one click.
- **Service and server restarts:** Services still using old versions of updated libraries are detected and can be restarted from the dashboard; servers can be rebooted from the dashboard.
- **Scheduled updates:** Maintenance windows such as "apply security updates to Ubuntu servers every Sunday at 03:00". Schedules never reboot servers by themselves.
- **Preview and approval:** An update started on a server page first runs in the package manager's simulation mode (APT, DNF, YUM, Zypper). Packages to upgrade, install, remove or downgrade, the download size and whether a reboot will be needed are shown; the update starts after approval.
- **Health checks and continuous monitoring:** HTTP/HTTPS, TCP, service, CPU/memory/disk and local script (health.d) checks before and after an update. A failing check before skips the update; a check that breaks after it fails the job. Agents also run the checks on their own at an interval (5 minutes by default) and report CPU load, memory, swap and disk usage. Disk 90% and memory 95% limits warn without any setup; two failed rounds in a row are notified, and so is the recovery.
- **Rolling updates:** Canary hosts, stages, a parallel job limit, a wait between stages and a failure-rate policy. The rollout stops on its own when the rate is exceeded; pause, resume and cancel are manual and audited.
- **Rollback without snapshots:** Package versions before and after every job are kept. Whether the old versions are still in the repositories is checked first; after approval the package manager goes back and the result is verified, and packages that did not go back are never shown as a success.
- **Software and service inventory:** 88 server products are recognized: web servers (Nginx, Apache, LiteSpeed, Tomcat, IIS…), databases (MySQL, MariaDB, PostgreSQL, SQL Server, MongoDB…), runtimes such as Python, Java, .NET, PHP and Node.js, mail, DNS, FTP, VPN, monitoring, CI/CD, message queues, OpenSSL and hosting panels such as cPanel, Plesk and DirectAdmin. Linux distribution packages and Windows programs are matched; the agent detects products installed outside the package manager. Installed and running services are told apart, two servers can be compared, and installs, removals and version changes are kept as history.
- **End-of-life (EOL) tracking:** endoflife.date calendars for operating systems and software (with a built-in calendar offline). Packages the distribution still maintains are marked; approaching and past dates are notified.
- **Security score:** A 0-100 score per server, group and fleet with daily history, adjustable weights and a threshold notification. A CVE matching several criteria is deducted only once.
- **Server standards and drift:** Rules such as "PHP only 8.2 or 8.3", "telnetd must not be installed", "nginx must be running". Version rules compare distribution version numbers (backports cause no false drift), new deviations are notified and a fitting update is suggested.
- **Automatic agent updates:** When the central server moves to a new version, agents download it, verify its SHA-256 digest and update themselves.
- **New version notice:** The dashboard tells administrators when a new netio.patchman version is released on GitHub and shows the update commands. It can be turned off for installations without internet access. With the optional updater container, the upgrade runs from the dashboard with one click (git pull, backup, build, restart).
- **Finding management:** Open, In Progress, Risk Accepted and False Positive statuses. When a package is updated, its finding becomes "Resolved" automatically. Risks are accepted for a limited term (30, 90, 180 or 365 days; the maximum is set in Settings). When the term ends, the finding reopens and a notification and email are sent.
- **Server groups:** Divide servers into groups such as "Production", "Test" or "Database". A server can belong to several groups. Lists can be filtered by group, scheduled updates can target a group and reports can be created for a group.
- **Platform information:** The agent reports whether the server is a VMware, Hyper-V, KVM, Xen or VirtualBox virtual machine, a Docker/LXC container or a physical server. The server list can be filtered by platform.
- **Reboot tracking:** If a new kernel is installed but the server has not been rebooted, this is shown together with how long it has been pending. The dashboard has a separate card and filter for it. It is also detected on Debian (no `/var/run/reboot-required` file) and Alpine by comparing kernels.
- **Trend charts:** The server records the fleet status every day. The dashboard shows the last 30 days of critical and high vulnerabilities, actively exploited vulnerabilities, open findings and pending security updates as charts and a table.
- **Compliance report:** A printable report (save it as PDF from the browser) for a chosen period and group: summary figures, findings detected and resolved in the period, mean time to remediate, KEV vulnerabilities past their CISA due date, server status, accepted risks (with who accepted them and when they expire) and update jobs. Useful as evidence in ISO 27001 and similar audits.
- **Two-factor authentication:** TOTP codes from apps such as Google Authenticator or Microsoft Authenticator, plus single-use recovery codes. Administrators can require two-factor authentication for all users and reset it for a user who lost their phone.
- **Notifications:** Notification center and email notifications for new vulnerabilities, disconnected agents and failed or partially completed update jobs.
- **Notification channels and integrations:** Slack, Microsoft Teams, Telegram, HMAC-SHA256 signed (timestamped) JSON webhooks, Jira, ServiceNow and GLPI tickets and Zabbix trapper items. Each channel subscribes by level or by event (critical CVE, KEV, EOL, update started/succeeded/failed, rollback, reboot, health check, SLA, score, offline server, drift…). Failed deliveries are retried; a delivery history is kept and a failed delivery can be sent again.
- **Automatic backups:** The database is backed up every day at a set time and the newest N backups are kept. Backups can be downloaded from the dashboard; failed backups are reported.
- **Multilingual interface:** Turkish, English, German and Russian. Each user picks the interface language; dates, decimal separators and CSV format follow the language.
- **Users and roles:** Administrator, Operator and Viewer roles; audit log.
- **Configuration from the dashboard:** SMTP, server address, time zone, data sources and all operational settings are changed in the dashboard. Changes apply without a restart.
- **Export:** Server and vulnerability lists can be downloaded as Excel-compatible CSV files.
- **Live kernel patching:** KernelCare (CloudLinux, AlmaLinux, Rocky, RHEL) and Canonical Livepatch (Ubuntu) are detected. The kernel version KernelCare patched up to is used for kernel findings, CVEs fixed by Livepatch do not count as open, and a kernel update covered by KernelCare does not mark the server as needing a restart.
- **Packages not to update:** Patterns such as `kernel*`, `mysql-*` or `KB5034439` for all servers, a group or one server. Every update job from the dashboard, schedules or the API skips these packages.
- **EPSS prioritization:** The FIRST EPSS score (probability of exploitation in the next 30 days) is shown for each vulnerability; the list can be sorted by KEV and EPSS.
- **Remediation targets (SLA):** Days per severity (default critical 15, high 30, medium 90, low 180). Overdue findings are marked, appear on the dashboard and in the report, and trigger a notification and email.
- **Group-based access:** Operators and viewers can be limited to the servers of some groups (separate teams or customers).
- **Optional restart in schedules:** Servers that need a restart after the update can be restarted while the maintenance window is open (per rule, off by default).
- **Third-party Windows programs:** On servers with winget, updates of programs such as Chrome, 7-Zip or Git are listed and installed.
- **REST API and Prometheus:** API keys read servers, vulnerabilities, updates and jobs and start update jobs; `/metrics` serves metrics for Grafana/Prometheus. See [docs/api.md](docs/api.md).

### Supported systems

| System | Inventory and updates | Vulnerability scanning |
|---|---|---|
| Debian, Ubuntu | apt | ✓ |
| AlmaLinux, Rocky Linux, Red Hat Enterprise Linux | dnf / yum | ✓ |
| CloudLinux 8, 9 | dnf | ✓ (with AlmaLinux security data) |
| CentOS 7, CloudLinux 7, Oracle Linux 7 | yum | ✓ (with Red Hat 7 and TuxCare ELS data) |
| Oracle Linux 8, 9; CentOS Linux 8 | dnf | ✓ (with AlmaLinux data) |
| Mageia, openEuler | dnf | ✓ |
| Linux Mint, Pop!_OS, Zorin OS, elementary OS, LMDE, Raspberry Pi OS | apt | ✓ (with the data of their Ubuntu/Debian release) |
| SUSE Linux Enterprise, openSUSE Leap | zypper | ✓ |
| Alpine Linux | apk | ✓ |
| CentOS Stream, Amazon Linux, Fedora and other distributions (using dnf, yum, zypper, apt or apk) | ✓ | — |
| Windows Server 2016, 2019, 2022, 2025; Windows 10, 11 (x64) | Windows Update | ✓ (pending Microsoft updates) |

The agent runs on amd64 and arm64. It requires systemd or OpenRC (Alpine) as the service manager. Physical, virtual (VMware, Hyper-V, KVM/Proxmox) and cloud servers are all supported.

On Windows the agent runs as a Windows service on x64 systems and uses the Windows Update Agent; servers attached to WSUS see the updates approved in WSUS. Vulnerability scanning on Windows is limited to Microsoft updates: third-party programs (browsers, 7-Zip and so on) are listed in the inventory but not scanned. Updates for which Microsoft publishes no CVE mapping (some .NET rollups, for example) are shown as security updates with the severity Windows Update reports.

CloudLinux 8 and 9 are built from AlmaLinux sources and are scanned with AlmaLinux security data. CloudLinux-specific packages (LVE tools, alt-php and so on) are not in the AlmaLinux data and are not scanned; the LVE kernel is compared with the same AlmaLinux kernel version. There is no vulnerability data for CloudLinux 7.

## Screenshots

The screenshots show the Turkish interface; the other languages have the same layout. They were taken with six test servers running Ubuntu, Debian, Rocky Linux, AlmaLinux and Alpine. The vulnerabilities are real data from OSV.dev.

**Server inventory:** All servers with their vulnerabilities by severity, pending updates and agent status. Bulk updates can be started on selected servers.

![Server inventory](docs/images/servers.png)

**Server details:** The server's vulnerabilities with CVSS score, affected package, installed and fixed version. Security updates, all updates and reboots are started with one click.

![Server details](docs/images/server.png)

**Vulnerabilities:** All vulnerabilities found across the fleet, filterable by severity, exploitation and fix availability.

![Vulnerabilities](docs/images/vulnerabilities.png)

**Vulnerability details:** The original (untranslated) description, CVSS vector, affected servers and status.

![Vulnerability details](docs/images/vulnerability.png)

**Update job:** The agent sends the command output and verifies after the job that the packages were really updated.

![Update job](docs/images/job.png)

**Scheduled updates:** Maintenance window with days, time, duration and target servers (all, an operating system, a group or selected servers).

![Scheduled update](docs/images/schedule.png)

**Agent installation:** Pick the distribution and the install command is built for it (curl or wget, root or sudo).

![Agents](docs/images/agents.png)

**Dark theme:** The dashboard follows the operating system's light or dark theme setting.

![Dashboard, dark theme](docs/images/dashboard-dark.png)

## How it works

```
 Managed servers                         Central server (Docker)                 External sources
┌──────────────────────┐   HTTPS   ┌──────────────────────────────┐   HTTPS   ┌──────────────┐
│ netio-patchman-agent │ ────────▶ │ netio.patchman               │ ────────▶ │ api.osv.dev  │
│  inventory, jobs     │ (outbound)│  dashboard + API + PostgreSQL│           │ CISA KEV     │
│  (Linux, Windows)    │           │                              │           │ MSRC         │
└──────────────────────┘           └──────────────────────────────┘           └──────────────┘
                                                 ▲
                                     Browser ────┘  (dashboard)
```

1. The agent connects to the central server at regular intervals. It reports installed packages and pending updates, and picks up a job if one is queued.
2. The central server matches package versions against the distributions' security data on OSV.dev and shows the findings in the dashboard. For Windows servers, the CVEs fixed by the pending KBs come from the Microsoft Security Update Guide.
3. Update jobs from the dashboard are handed to the agent on its next connection. The agent runs them with fixed package manager commands and reports the result.

No inbound ports need to be opened on managed servers.

## Installation (Docker)

### Requirements

- A Linux server with Docker Engine 24 or later and Docker Compose v2.24 or later.
- `git`.
- **Internet access:** The first build downloads Docker images and Go modules. Vulnerability data also requires HTTPS access to `api.osv.dev` and `www.cisa.gov`. For environments without internet access, see [docs/kurulum.md](docs/kurulum.md#8-internet-erişimi-olmayan-ortamlar) (Turkish).
- **Recommended resources:** up to 100 servers: 1 CPU core, 1 GB RAM and 5 GB disk.

If Docker is not installed, you can install it with Docker's official script:

```sh
curl -fsSL https://get.docker.com | sudo sh
```

### 1. Download the repository

```sh
git clone https://github.com/alptekinsunnetci/netio.patchman.git
cd netio.patchman
```

### 2. (Optional) Set the server address and language

You can write the address that agents and users will use to reach the central server in the `.env` file. To make English the default language (for new users, emails, chat messages and logs), also set `PATCHMAN_LOCALE`:

```sh
cp .env.example .env
nano .env        # PATCHMAN_BASE_URL=https://patchman.your-domain
                 # PATCHMAN_LOCALE=en-US
```

If you skip this step, the address starts as `http://localhost:8080`. You can change it after installation under **Settings → Server configuration**. Make sure the address is correct before installing agents, because the install command uses it.

### 3. Start

```sh
docker compose up -d --build
```

The first build takes a few minutes depending on your connection. Check the status:

```sh
docker compose ps                 # the STATUS column should show "healthy"
docker compose logs -f server     # logs (Ctrl+C to exit)
```

### 4. Create the first administrator account

Open `http://<server-address>:8080` in a browser. Because the database is empty, the **Initial Setup** page opens. Use the **English** link at the bottom of the page to switch the language, then create the administrator account. This page is only available while there are no users.

### 5. Basic settings

In the dashboard, under **Settings → Server configuration**:

- **Server address:** The external address agents will use, for example `https://patchman.your-domain`.
- **Email server (SMTP):** For email notifications. You can send a test email from the same page.

Installation is complete. The next step is installing the agent on your servers.

### HTTPS

Agents and browsers should connect to the server over HTTPS. The recommended way is to put the server behind a reverse proxy such as nginx, Caddy or HAProxy. In that case, turn on **Trust the X-Forwarded-For and X-Forwarded-Proto headers of a reverse proxy** in the dashboard. For example configurations and for letting the server terminate TLS itself, see [docs/kurulum.md](docs/kurulum.md#3-tls-ve-ters-vekil) (Turkish).

**Changing the port:** Set `PATCHMAN_PUBLISH_PORT=8899` in `.env` and run `docker compose up -d` again. If the reverse proxy runs on the same machine, use `PATCHMAN_PUBLISH_PORT=127.0.0.1:8899` so that the dashboard is not exposed over plain HTTP. Do not change the port with `PATCHMAN_HTTP_ADDR`; that setting is for installations without Docker and is ignored by Docker Compose.

**Plesk:** Add the following to the domain's **Apache & nginx Settings → Additional nginx directives**. The regular expression form avoids a conflict with Plesk's own `location /` block:

```nginx
location ~ ^/ {
    proxy_pass http://127.0.0.1:8899;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 64m;
}
```

Then turn on the reverse proxy option in the dashboard (or set `PATCHMAN_TRUST_PROXY=true` in `.env`).

## Installing the agent on servers

1. Create an **enrollment token** on the **Agents** page. The token is shown only once. You can set a validity period and a use limit.
2. Select the server's distribution on the page. The command is built for it: `wget` on Debian and Alpine, `curl` on the others. If you connect as root, leave **Run with sudo** unchecked (sudo is often not installed on CentOS, Debian and Alpine). When the dashboard is in English, the command includes `--locale en-US` so the agent's messages are in English too. Run the command on the server to be managed. Example (as root, RHEL/CentOS):

   ```sh
   curl -fsSL https://patchman.your-domain/downloads/install-agent.sh | \
     sh -s -- --server-url https://patchman.your-domain --token <ENROLLMENT-TOKEN> --locale en-US
   ```

3. The server appears on the **Server Inventory** page within seconds and the first vulnerability scan starts automatically.

The install script:

- installs the agent as `/usr/local/bin/netio-patchman-agent`,
- writes the configuration to `/etc/netio-patchman/agent.env`,
- starts the service: `netio-patchman-agent.service` with systemd, `/etc/init.d/netio-patchman-agent` with OpenRC (Alpine).

The output of the install script is in Turkish.

To see the agent's status and logs:

```sh
systemctl status netio-patchman-agent
journalctl -u netio-patchman-agent -f
```

For bulk deployment (Ansible etc.), offline installation, agent options and removal, see [docs/kurulum.md](docs/kurulum.md#4-ajan-kurulumu) (Turkish).

### Windows servers

On the Agents page choose **Windows / Windows Server (PowerShell)** and run the generated command on the server in PowerShell or a command prompt opened **as administrator**:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm 'https://patchman.your-domain/downloads/install-agent.ps1').TrimStart([char]65279))) -ServerUrl 'https://patchman.your-domain' -Token '<ENROLLMENT-TOKEN>'"
```

The install script puts the agent in `C:\Program Files\netio-patchman\netio-patchman-agent.exe`, writes the configuration to `C:\ProgramData\netio-patchman\agent.env` (readable only by SYSTEM and Administrators), and creates and starts the `netio-patchman-agent` Windows service (automatic start, restart on failure). The log is `C:\ProgramData\netio-patchman\agent.log`:

```powershell
Get-Service netio-patchman-agent
Get-Content C:\ProgramData\netio-patchman\agent.log -Tail 50 -Wait
```

For servers without internet access, copy `install-agent.ps1` and `netio-patchman-agent-windows-amd64.exe` to one folder and use the `-Binary` option. To remove the agent: `.\install-agent.ps1 -Uninstall`. The agent asks the Windows Update service online at most every 6 hours; in between it reads the result of Windows' own last scan.

## Updating, backup and removal

### Moving to a new version

```sh
cd netio.patchman
git pull
docker compose up -d --build
```

- The database schema is updated automatically at startup; still, take a backup first.
- The version is read from the `VERSION` file in the repository.
- If **Settings → Agents → Update agents automatically** is on (the default), agents switch to the new version by themselves.

### 0.8.0: moving to PostgreSQL

Version 0.8.0 moves the database from SQLite to PostgreSQL. The Compose file now runs a PostgreSQL 17 container next to the application (`postgres`, volume `netio-patchman-db`). Nothing extra is needed for the move; the usual `git pull && docker compose up -d --build` (or **Update now** in the dashboard) is enough:

1. The PostgreSQL container starts for the first time. Its password is generated randomly and kept in the database volume; no port is published.
2. If PostgreSQL is empty and `/data/netio-patchman.db` exists, the server copies all tables into PostgreSQL in one transaction and compares the row count of every table with the source. The dashboard opens only after the copy. A database with 1.3 million rows is moved in about 15 seconds.
3. Afterwards the old file is renamed to `netio-patchman.db.imported-<time>` (not deleted), an information notice appears in the notification center and the move is written to the audit log.

If any step fails, PostgreSQL is left empty, the SQLite file is not changed and the server does not start. The error is shown by `docker compose logs server`. After fixing the cause, `docker compose up -d` starts the move again.

- **Staying on SQLite:** add `PATCHMAN_DATABASE_URL=sqlite` to `.env`. The PostgreSQL container still runs but is not used.
- **External PostgreSQL:** add `PATCHMAN_DATABASE_URL=postgres://user:password@host:5432/database?sslmode=require` to `.env`. If that database is empty, the SQLite data is moved there.
- **Going back:** start with `PATCHMAN_DATABASE_URL=sqlite` and restore a current backup with the `restore` command; the steps are in [docs/kurulum.md](docs/kurulum.md#22-veritabanı) (Turkish).

### Updating from the dashboard (optional)

The upgrade can also be started with **Settings → Server configuration → Product version → Update now**. Turn on the `updater` container from the Compose file once:

```sh
cd netio.patchman
echo "COMPOSE_PROFILES=updater" >> .env
docker compose up -d --build
```

The updater then runs `git pull --ff-only`, a database backup (`/data/before-update-<version>-<time>.db`), the image build, the restart and a health check. Progress and command output appear in the dashboard; the page reloads when it is over and the result goes to the notification center. The dashboard is unavailable for a few seconds; agents are not affected. If a step fails, the server keeps running the current version.

> [!WARNING]
> The updater has access to the Docker socket (`/var/run/docker.sock`), which equals root access on the server. It opens no port, only waits for the request file the dashboard writes into the data volume and runs fixed steps; it takes no parameters from the request. Still, turn it on only if you need it and protect administrator accounts with two-factor authentication. If the repository has local changes, `git pull --ff-only` stops and nothing is updated.

### Backup and restore

**Automatic backups** are on by default: the database is backed up every day at 02:30 to `/data/backups/` and the newest 7 backups are kept. The time, the number of backups to keep and the on/off switch are under **Settings → Automatic backup**. The same place has a **Back up now** button and download links. By default the backups live in the same Docker volume as the database; copy them elsewhere regularly or write them to a separate disk with `PATCHMAN_BACKUP_DIR` (see [docs/kurulum.md](docs/kurulum.md), section 5.1, Turkish).

You can also take a consistent backup manually:

```sh
docker compose exec server netio-patchman-server backup -out /data/backup.db
docker compose cp server:/data/backup.db ./backup-$(date +%Y%m%d).db
```

Restoring from a backup (backups are SQLite files whichever database is in use):

```sh
docker compose stop server
docker compose run --rm --no-deps server restore -in /data/backups/netio-patchman-20261120-023000.db
docker compose start server
```

Copy a backup from outside into the volume first: `docker compose cp ./backup-20261120.db server:/data/backup.db`, then restore it with `-in /data/backup.db`. The restore runs in one transaction: if it fails, the database is not changed.

The data is kept in the PostgreSQL volume `netio-patchman-db`, backups in the volume `netio-patchman-data` (`/data/backups`). Backups also contain the SMTP password; protect them accordingly.

### Resetting an administrator password

```sh
docker compose exec server netio-patchman-server reset-password -email admin@your-domain
```

The command generates a new password and prints it.

The two-factor authentication of a user who lost their phone can be removed in the dashboard (**Users → user → Reset two-factor authentication**) or on the command line:

```sh
docker compose exec server netio-patchman-server reset-mfa -email admin@your-domain
```

### Removal or starting over

```sh
docker compose down        # stops the container, data is kept
docker compose down -v     # deletes the container and the database (cannot be undone)
```

After `down -v`, `docker compose up -d` starts with an empty database at the **Initial Setup** step.

## Configuration

All configuration can be done in the dashboard:

- **Settings:** Notification thresholds and recipients, agent connection intervals, automatic agent updates, scanning, retention, security (two-factor authentication, risk acceptance term) and automatic backups.
- **Settings → Notification channels:** Slack, Microsoft Teams, Telegram, webhook, Jira, ServiceNow, GLPI and Zabbix channels, event filters and delivery history.
- **Settings → Health checks, Security score:** Checks before and after updates, score weights and threshold.
- **Settings → Server configuration:** Server address, reverse proxy, time zone, log level, SMTP and data sources (OSV, CISA KEV, Microsoft Security Update Guide).

The `PATCHMAN_`-prefixed variables in `.env` only provide the initial values; a value saved in the dashboard replaces them. Values marked "—" in the "Dashboard" column are needed when the server starts, so they can only be changed in `.env` and require a restart. All options are described in [.env.example](.env.example) (comments in Turkish).

| Variable | Default | Description | Dashboard |
|---|---|---|---|
| `PATCHMAN_BASE_URL` | `http://localhost:8080` | External address used by the dashboard and agents | yes |
| `PATCHMAN_PUBLISH_PORT` | `8080` | Port Docker publishes on the host; the `127.0.0.1:8899` form publishes on the local interface only | — |
| `PATCHMAN_HTTP_ADDR` | `:8080` | Listen address for installations without Docker only; fixed at `:8080` in Docker Compose | — |
| `PATCHMAN_TRUST_PROXY` | `false` | Take the client IP from the `X-Forwarded-For` header behind a reverse proxy | yes |
| `PATCHMAN_TLS_CERT_FILE`, `PATCHMAN_TLS_KEY_FILE` | — | Certificate and key for letting the server terminate TLS itself | — |
| `PATCHMAN_TIMEZONE` | `Europe/Istanbul` | Time zone in which dates and times are shown | yes |
| `PATCHMAN_LOCALE` | `tr-TR` | Default language (`tr-TR`, `en-US`, `de-DE` or `ru-RU`): interface of new users, emails and logs. Each user can choose their own interface language | — |
| `PATCHMAN_DATABASE_URL` | PostgreSQL from Compose | PostgreSQL address (`postgres://user@host:5432/database`); `sqlite` uses the SQLite file `/data/netio-patchman.db` | — |
| `PATCHMAN_DATABASE_PASSWORD_FILE` | password file from Compose | File the password is read from when the address has none | — |
| `PATCHMAN_BACKUP_DIR` | `/data/backups` | Directory for automatic backups | — |
| `PATCHMAN_OSV_URL` | `https://api.osv.dev` | OSV API address (an internal mirror can be used) | yes |
| `PATCHMAN_KEV_URL` | CISA KEV address | KEV catalog address; `off` turns it off | yes |
| `PATCHMAN_MSRC_URL` | `https://api.msrc.microsoft.com/sug/v2.0/en-US` | Microsoft Security Update Guide address for the CVE mapping of Windows servers; `off` turns it off | yes |
| `PATCHMAN_EPSS_URL` | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Daily EPSS score file; `off` turns it off | yes |
| `PATCHMAN_EOL_URL` | `https://endoflife.date/api` | End-of-life calendars of operating systems and software; `off` turns it off (the built-in calendar is used) | yes |
| `PATCHMAN_SMTP_HOST`, `PATCHMAN_SMTP_PORT` | —, `587` | Email server | yes |
| `PATCHMAN_SMTP_USERNAME`, `PATCHMAN_SMTP_PASSWORD` | — | SMTP credentials | yes |
| `PATCHMAN_SMTP_FROM_NAME`, `PATCHMAN_SMTP_FROM_ADDRESS` | `netio.patchman`, — | Sender name and address | yes |
| `PATCHMAN_LOG_LEVEL`, `PATCHMAN_LOG_FORMAT` | `info`, `json` | Log level and format | level: yes, format: — |
| `PATCHMAN_VERSION` | `VERSION` file | Server and agent version to build | — |

If an environment variable has an invalid value, the server does not start and lists the errors in the default language.

## REST API and Prometheus

Create a key under **Profile → API keys**. A key works with the role and server access of the user who created it; read-only keys cannot change anything. Endpoints, fields and examples: [docs/api.md](docs/api.md) (Turkish).

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

## Troubleshooting

| Symptom | Check |
|---|---|
| After an update the server does not start and the log says the SQLite database could not be copied to PostgreSQL | The details are in the same log entry; the SQLite file is unchanged. Check with `docker compose ps` that `postgres` is "healthy" and that there is free disk space, then run `docker compose up -d`. To go back to SQLite for now, add `PATCHMAN_DATABASE_URL=sqlite` to `.env`. |
| The dashboard does not open | `docker compose ps` should show `0.0.0.0:<port>->8080/tcp` in the PORTS column. See errors with `docker compose logs server`. Is the `PATCHMAN_PUBLISH_PORT` port open in the firewall? |
| The install command shows `localhost` | Change the server address on the **Server configuration** page to an address the agents can reach. |
| The agent does not enroll | Does `curl -I https://patchman.your-domain/healthz` work from the agent's server? `journalctl -u netio-patchman-agent -n 50` |
| The Windows agent does not enroll or shows no updates | `Get-Content C:\ProgramData\netio-patchman\agent.log -Tail 50`. Is the Windows Update service (`wuauserv`) disabled? If the server uses WSUS, are the updates approved there? |
| No CVEs on a Windows server | Can the central server reach `api.msrc.microsoft.com`? Is the Microsoft Security Update Guide turned on in **Server configuration**? |
| Vulnerability scanning finds nothing | Can the central server reach `api.osv.dev`? Look for OSV errors in the logs. |
| No emails arrive | Send a test email from the **Server configuration** page; the error is shown in the dashboard. |

More information (in Turkish): [docs/kurulum.md](docs/kurulum.md) (installation and operation), [docs/kullanim.md](docs/kullanim.md) (using the dashboard).

## Language and localization

- The default language is Turkish (`tr-TR`). The interface is also available in English (`en-US`), German (`de-DE`) and Russian (`ru-RU`): the language links on the sign-in page or **My Profile → Interface language**. The choice is saved for the user and applies on other devices too.
- Emails, chat channel messages and system logs use the server's default language (`PATCHMAN_LOCALE`). The language of agent messages is set with `--locale` when installing the agent (e.g. `--locale en-US`); the dashboard adds this option to the install command when it is not in Turkish.
- Dates are shown as `21.11.2026` in Turkish, German and Russian and as `2026-11-21` in English. CSV files are separated by `,` in English and `;` in the other languages.
- **Vulnerability data is never translated.** CVE IDs, official titles, descriptions, CVSS values, package names and vendor advisories are shown exactly as published by their source.
- Times are stored in UTC and shown in the chosen time zone (default `Europe/Istanbul`).
- Interface texts are in `internal/i18n/locales/`. A new language is added as a new file with the same keys; a test checks that every catalog has all keys and placeholders.
- The documentation in `docs/` is in Turkish.

## Security

- Passwords are stored with PBKDF2-SHA256 (600,000 iterations). Sessions, enrollment tokens and agent credentials are stored in the database only as SHA-256 hashes.
- All form actions are protected against CSRF. Failed sign-ins are rate-limited per IP and per account. Two-factor authentication (TOTP) is available and can be made mandatory.
- The agent opens no ports and accepts no inbound connections. It only runs predefined package manager commands, without a shell; package names are validated on both sides. On Windows, Windows Update is used through a fixed PowerShell script embedded in the agent (Windows Update Agent API); KB names are validated too.
- To turn off remote updates completely on a server, set `PATCHMAN_REMOTE_UPDATES=false` in that server's `/etc/netio-patchman/agent.env`. On Windows the same setting is in `C:\ProgramData\netio-patchman\agent.env`.
- The dashboard is served with a strict Content-Security-Policy and uses no external resources (CDNs, fonts); it also works in networks without internet access.

## Development

Requirement: Go 1.26 or later.

```sh
go test ./...                                   # unit and end-to-end tests (SQLite)
# The same tests on PostgreSQL (each test uses its own schema):
PATCHMAN_TEST_DATABASE_URL=postgres://patchman:password@127.0.0.1:5432/patchman go test ./...
go vet ./...
PATCHMAN_DATA_DIR=./data go run ./cmd/netio-patchman-server

# Build the agent binaries into dist/agent/ in the server's distribution layout
scripts/build-agent.sh                                    # Linux / macOS
powershell -File scripts\build-agent.ps1                  # Windows

# Live scan test against OSV.dev and the Microsoft Security Update Guide (requires internet access)
go test -tags live -run Live -v ./internal/scanner/

# Real Windows Update search on Windows (searches only, installs nothing)
go test -tags live -run LiveWindows -v ./internal/agent/
```

Product requirements are in the [docs/spec/](docs/spec/) directory.

## Disclaimer

netio.patchman is provided "AS IS". No warranty of any kind is given, express or implied, including merchantability, fitness for a particular purpose, error-free or uninterrupted operation, and complete detection of vulnerabilities.

**All risks and consequences of installing and using the software lie with the person or organization that installs and uses it.** To the fullest extent permitted by applicable law, the developer cannot be held liable for any direct or indirect damage, including:

- Service outages, incompatibilities and data loss during or after package updates, service restarts or server reboots.
- Failed, incomplete or unexpected update jobs and scheduled updates.
- Vulnerabilities that are not detected, detected incorrectly or shown with a wrong severity. Security data comes from third-party sources (OSV.dev, CISA KEV, Microsoft Security Update Guide, distribution advisories); its accuracy depends on those sources.
- Misconfiguration of the software, the agents or the central server, leaving them open to unauthorized access, or misuse.

Before using it:

- Try the software in a non-production environment first.
- Back up your servers and the netio.patchman database before updates.
- Apply updates to critical servers in maintenance windows and in a controlled way.
- Publish the central server only over HTTPS and only to trusted networks.

By installing and using this software you accept these terms.

## License

Developer: **Alptekin Sünnetci**. Copyright © 2026 Alptekin Sünnetci.

netio.patchman is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) with the **Commons Clause** condition. Full text: [LICENSE](LICENSE).

- **Allowed:** Using the software free of charge (on your own infrastructure, including inside your organization), studying it, modifying it and distributing it free of charge.
- **Not allowed:** Selling the software, or a product or service whose value derives entirely or substantially from it, to third parties. This includes sale, paid hosting and paid consulting/support services.
- Copies you distribute must keep the LICENSE file and the copyright notice.

Contact the developer for commercial use.

The binding text of the license is the [LICENSE](LICENSE) file; this section is only a summary.

# netio.patchman Installation and Operations Guide

🇬🇧 **English** · 🇹🇷 [Türkçe](kurulum.md) · ⏱️ Reading time: about 20 minutes

This document describes how to install the netio.patchman server for production, roll out agents, back up and upgrade.
Back to the [README](../README.md) · [User guide](usage.md) · [REST API](api.en.md)

## 1. System requirements

**Server**

| Managed hosts | CPU | Memory | Disk |
|---|---|---|---|
| up to 100 | 1 core | 1 GB | 5 GB |
| 100–500 | 2 cores | 2 GB | 20 GB |
| more than 500 | 4 cores | 4 GB | 40 GB |

- Docker Engine 24+ and Docker Compose v2.24+, or any Linux distribution to run the binary directly. The values above include the PostgreSQL container.
- A domain name the agents can reach and a TLS certificate (recommended).
- HTTPS (443) access to `api.osv.dev` and `www.cisa.gov` for vulnerability data, and to `api.msrc.microsoft.com` if you manage Windows hosts. Without internet access see [section 8](#8-networks-without-internet-access).

**Managed hosts (agent)**

- A Linux distribution with systemd or OpenRC (Alpine), amd64 or arm64.
- or Windows Server 2016, 2019, 2022, 2025, or Windows 10, 11 (x64). See [section 4.5](#45-windows-hosts).
- HTTPS access to the server address. The agent always starts the connection itself; no inbound port has to be opened on managed hosts.

## 2. Installing with Docker Compose

```sh
git clone https://github.com/alptekinsunnetci/netio.patchman.git netio-patchman && cd netio-patchman
cp .env.example .env
```

In `.env` you only need to set the external address of the server:

```sh
PATCHMAN_BASE_URL=https://patchman.your-domain
```

The server address, reverse proxy setting, SMTP, time zone, log level and data sources can be changed in the panel after installation, on **Settings → Server configuration** (see section 2.1).

Start it:

```sh
docker compose up -d --build
docker compose ps                  # the state should be "healthy"
docker compose logs -f server
```

The Compose project is called `netio-patchman`, the image `netio-patchman-server`. Two containers run: `server` (the application) and `postgres` (PostgreSQL 17). Data lives in the `netio-patchman-db` volume (PostgreSQL); backups and temporary files in the `netio-patchman-data` volume (`/data`). See [section 2.2](#22-database).

On the first start, create the first administrator at `PATCHMAN_BASE_URL/setup`. This page only opens while no user exists.

### 2.2 Database

By default the database is the PostgreSQL 17 container of the same Compose project:

- User and database name `patchman`. The password is generated randomly on the first start and written to the `patchman-password` file in the `netio-patchman-db` volume. The server mounts this file read-only (`PATCHMAN_DATABASE_PASSWORD_FILE`).
- PostgreSQL publishes no port; only the server on the Compose network connects. For manual queries: `docker compose exec postgres psql -U patchman patchman`.
- The database is created with `--locale=C`: text sorts by byte order and case-insensitive comparisons (e-mail, group name, search) only fold ASCII letters. This matches the earlier SQLite behavior.

To use an **external PostgreSQL** (13 or later), put its address in `.env`:

```sh
PATCHMAN_DATABASE_URL=postgres://patchman:password@db.your-domain:5432/patchman?sslmode=verify-full
```

The user needs permission to create tables in the database (the schema is created and upgraded on start). Instead of writing the password into the address you can read it from a file: `PATCHMAN_DATABASE_PASSWORD_FILE=/run/secrets/db-password`. The `postgres` container of the Compose file then keeps running but is not used.

To run on **SQLite** (small installations, running outside Docker) set `PATCHMAN_DATABASE_URL=sqlite` or leave the variable unset (the default outside Docker). The database is the file `PATCHMAN_DATA_DIR/netio-patchman.db`.

**Moving from earlier versions (0.8.0).** If PostgreSQL is empty on the first start and `/data/netio-patchman.db` exists, the server imports the SQLite data by itself:

1. The SQLite file is checked for integrity (`PRAGMA quick_check`) and a consistent working copy is taken (including an unfinished write-ahead log). The original file is not touched.
2. All tables are copied in a single PostgreSQL transaction. The row count of each table is compared with the source, id counters are set to continue where they left off and foreign keys are validated at the end.
3. PostgreSQL does not accept invalid UTF-8 bytes or NUL characters in text. Such values are repaired during the import; their number appears in the log as `sanitized`. Rows still pointing to deleted records are removed or unlinked according to the foreign key rule (`orphans`).
4. When the transaction commits, the old file is renamed to `netio-patchman.db.imported-<UTC time>`, an informational notification is created and an audit log entry is written.

If a step fails, the transaction is rolled back, PostgreSQL stays empty and the server does not start. This is deliberate: it prevents the server from starting with an empty database and someone running a new **Initial Setup**. After fixing the problem, `docker compose up -d` repeats the import from the start. If PostgreSQL already contains data, nothing is imported and a warning is logged.

To go back to SQLite after the move, take a fresh backup and restore it in SQLite mode:

```sh
docker compose exec server netio-patchman-server backup -out /data/backups/back.db
echo "PATCHMAN_DATABASE_URL=sqlite" >> .env
docker compose stop server
docker compose run --rm --no-deps server restore -in /data/backups/back.db
docker compose up -d
```

To return to the state before the move, pass the imported old file (`/data/netio-patchman.db.imported-…`) with `-in`.

### 2.1 Configuration in the panel

The **Settings → Server configuration** page (administrators only) contains these settings; saved values take effect immediately, without a restart:

| Setting | Environment variable (initial value) |
|---|---|
| Server address | `PATCHMAN_BASE_URL` |
| Trust reverse proxy headers | `PATCHMAN_TRUST_PROXY` |
| Time zone | `PATCHMAN_TIMEZONE` |
| Log level | `PATCHMAN_LOG_LEVEL` |
| SMTP server, port, user name, password, sender name and address | `PATCHMAN_SMTP_*` |
| OSV API address, CISA KEV catalog (on/off and address) | `PATCHMAN_OSV_URL`, `PATCHMAN_KEV_URL` |
| New version check (on/off and address) | `PATCHMAN_UPDATE_CHECK_URL` (`off` turns it off) |
| End-of-life calendars, endoflife.date (on/off and address) | `PATCHMAN_EOL_URL` (`off` turns it off; the built-in calendar is used) |

- Environment variables are only initial values: once a value is saved in the panel it replaces the environment variable. **Revert to environment variables** deletes the values saved in the panel.
- The SMTP password is stored in the database, never shown on the page and never written to the audit log. Protect database backups accordingly.
- When the server address changes, new install commands and e-mail links use the new address. Installed agents keep connecting to the address in `/etc/netio-patchman/agent.env`; if the server really moved, update `PATCHMAN_SERVER_URL` in that file and restart the agent.
- When the time zone changes, the next run of scheduled updates is recalculated in the new zone.
- The panel keeps working when reached through another address (e.g. `http://localhost:8080`) even if the server address is HTTPS, so a wrong address does not lock administrators out.

These values are needed before the database opens, so they can only be changed with environment variables and need a restart: `PATCHMAN_HTTP_ADDR`, `PATCHMAN_DATA_DIR`, `PATCHMAN_TLS_CERT_FILE`/`PATCHMAN_TLS_KEY_FILE`, `PATCHMAN_AGENT_DIST_DIR`, `PATCHMAN_LOG_FORMAT`, `PATCHMAN_LOCALE`. The **Startup configuration** section of the page shows their current values.

## 3. TLS and reverse proxy

Agents and browsers should connect to the server over HTTPS. There are two options.

### 3.1 Reverse proxy (recommended)

Publish the server only on the local interface (`PATCHMAN_PUBLISH_PORT=127.0.0.1:8080` in `.env`) and terminate TLS with nginx or Caddy. Turn on "Trust the X-Forwarded-For and X-Forwarded-Proto headers of a reverse proxy" on the **Server configuration** page (or set `PATCHMAN_TRUST_PROXY=true`).

**nginx example**

```nginx
server {
    listen 443 ssl http2;
    server_name patchman.your-domain;

    ssl_certificate     /etc/ssl/patchman/fullchain.pem;
    ssl_certificate_key /etc/ssl/patchman/privkey.pem;

    client_max_body_size 32m;   # for large inventory reports

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
```

**Caddy example**

```
patchman.your-domain {
    reverse_proxy 127.0.0.1:8080
}
```

### 3.2 TLS terminated by the server

```sh
PATCHMAN_TLS_CERT_FILE=/certs/tls.crt
PATCHMAN_TLS_KEY_FILE=/certs/tls.key
```

Mount the certificate files into the container as a read-only volume.

### 3.3 Internal certificate authority

If your certificate is signed by an internal CA, pass the CA file when installing the agent:

```sh
sh install-agent.sh --server-url https://patchman.your-domain --token <TOKEN> --ca-file /path/company-ca.pem
```

## 4. Installing agents

### 4.1 Downloading from the server

Create a token in the panel with **Agents → New enrollment token**. Pick the host's distribution above the command field; the command is built for that distribution:

| Distribution | Download tool | Default privilege |
|---|---|---|
| Ubuntu, Fedora | `curl` | `sudo` |
| RHEL, CentOS, AlmaLinux, Rocky, Oracle Linux | `curl` | root |
| SUSE, openSUSE | `curl` | root |
| Debian | `wget` | root |
| Alpine | `wget` | root |

The defaults follow standard installations. Change them with the **Run with sudo** box: a root session does not need sudo; leave the box empty if sudo is not installed. Example (as root, CentOS):

```sh
curl -fsSL https://patchman.your-domain/downloads/install-agent.sh | \
  sh -s -- --server-url https://patchman.your-domain --token <ENROLLMENT-TOKEN>
```

The script:

1. Downloads the agent for the architecture and verifies its SHA-256 hash.
2. Installs the agent to `/usr/local/bin/netio-patchman-agent`.
3. Writes the configuration to `/etc/netio-patchman/agent.env` (readable by root only).
4. Detects the service manager, enables and starts the service:
   - systemd: `netio-patchman-agent.service`, logs with `journalctl -u netio-patchman-agent -f`.
   - OpenRC (Alpine): `/etc/init.d/netio-patchman-agent` (supervised by supervise-daemon), logs in `/var/log/netio-patchman-agent.log`.

If neither is present the script stops with an error.

On its first run the agent registers with the server using the enrollment token. It keeps its permanent identity in `/var/lib/netio-patchman/credentials.json`; the enrollment token is not needed after registration.

### 4.2 Mass rollout

Create the enrollment token with an expiry and a use limit and run the same command with Ansible, Puppet or a similar tool. Example Ansible task:

```yaml
- name: Install the netio.patchman agent
  ansible.builtin.shell: >
    curl -fsSL https://patchman.your-domain/downloads/install-agent.sh |
    sh -s -- --server-url https://patchman.your-domain --token {{ patchman_token }}
  args:
    creates: /usr/local/bin/netio-patchman-agent
  become: true
```

### 4.3 Agent configuration

`/etc/netio-patchman/agent.env`:

| Variable | Default | Description |
|---|---|---|
| `PATCHMAN_SERVER_URL` | — | Server address (required) |
| `PATCHMAN_ENROLLMENT_TOKEN` | — | Token for the first registration |
| `PATCHMAN_REMOTE_UPDATES` | `true` | With `false`, package update jobs started in the panel do not run on this host |
| `PATCHMAN_AUTO_UPDATE` | `true` | With `false`, the agent does not update itself (version pinning) |
| `PATCHMAN_WINGET` | `true` | Windows: lists and installs updates of third-party programs with winget (`-DisableWinget` at installation) |
| `PATCHMAN_REFRESH_PACKAGE_LISTS` | `true` | Refreshes package lists at most every 6 hours (`apt-get update`, `zypper refresh`, `apk update`) |
| `PATCHMAN_UPDATE_KEYS` | — | Public keys agent updates must be signed with (comma separated). When set, the agent only installs newer versions signed with one of them (see [Signed agent updates](#signed-agent-updates)) |
| `PATCHMAN_CA_FILE` | — | Additional CA certificate |
| `PATCHMAN_LOCALE` | `tr-TR` | Language of the agent's logs and of the job messages shown in the panel (`tr-TR`, `en-US`, `de-DE` or `ru-RU`). Set at installation with `--locale` (e.g. `--locale en-US`) |

After a change: `systemctl restart netio-patchman-agent.service` (Alpine: `rc-service netio-patchman-agent restart`)

### 4.4 Removing the agent

As root (or prefix the commands with `sudo`):

```sh
systemctl disable --now netio-patchman-agent.service
rm -f /etc/systemd/system/netio-patchman-agent.service /usr/local/bin/netio-patchman-agent \
  /usr/local/bin/netio-patchman-agent.previous
rm -rf /etc/netio-patchman /var/lib/netio-patchman
systemctl daemon-reload
```

Alpine (OpenRC):

```sh
rc-service netio-patchman-agent stop
rc-update del netio-patchman-agent default
rm -f /etc/init.d/netio-patchman-agent /usr/local/bin/netio-patchman-agent \
  /usr/local/bin/netio-patchman-agent.previous /var/log/netio-patchman-agent.log
rm -rf /etc/netio-patchman /var/lib/netio-patchman
```

Then remove the host in the panel from its **System Information** tab.

### 4.5 Windows hosts

Supported versions: Windows Server 2016, 2019, 2022, 2025 and Windows 10, 11 (x64). The agent runs as a Windows service and uses the Windows Update Agent. The Windows Update service (`wuauserv`) must not be disabled. If the host uses WSUS, the agent sees and installs the updates approved in WSUS.

**Installation.** On the **Agents** page pick **Windows / Windows Server (PowerShell)** and run the command in PowerShell or a command prompt opened **as administrator** on the host:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm 'https://patchman.your-domain/downloads/install-agent.ps1').TrimStart([char]65279))) -ServerUrl 'https://patchman.your-domain' -Token '<ENROLLMENT-TOKEN>'"
```

The command first enables TLS 1.2 (so it also works on Windows Server 2016), then downloads and runs `install-agent.ps1`. The script:

1. Downloads the agent from `https://patchman.your-domain/downloads/agent/netio-patchman-agent-windows-amd64.exe` and verifies its SHA-256 hash.
2. Installs it to `C:\Program Files\netio-patchman\netio-patchman-agent.exe`.
3. Writes the configuration to `C:\ProgramData\netio-patchman\agent.env`. This folder (including credentials and the log) is readable by SYSTEM and Administrators only.
4. Creates the `netio-patchman-agent` service with automatic start. Windows restarts the service after failures and after a self-update (`sc failure` and `sc failureflag`).

Script options: `-ServerUrl`, `-Token`, `-Binary <file>` (offline installation), `-CaFile <file>` (an additional CA for the agent to verify the server certificate; the script's own download uses the Windows certificate store, so add the internal CA to Windows or use `-Binary`), `-DisableRemoteUpdates`, `-DisableAutoUpdate`, `-Locale <language>`, `-Uninstall`, `-Help`.

**Offline installation.** Copy `install-agent.ps1` and `netio-patchman-agent-windows-amd64.exe` into the same folder:

```powershell
.\install-agent.ps1 -ServerUrl https://patchman.your-domain -Token <ENROLLMENT-TOKEN> -Binary .\netio-patchman-agent-windows-amd64.exe
```

**Mass rollout.** The install command can run as a Group Policy startup script, through SCCM/Intune or with Ansible (`ansible.windows.win_shell`). The same token can be used on several hosts.

**Status and log:**

```powershell
Get-Service netio-patchman-agent
Get-Content C:\ProgramData\netio-patchman\agent.log -Tail 50 -Wait
Restart-Service netio-patchman-agent        # after changing agent.env
```

When the log exceeds 10 MB it is kept as `agent.log.1`.

**How it works.**

- *Inventory:* installed programs (the "Programs and Features" list) and updates pending in Windows Update (KB number, title, Microsoft severity, classification). Definition updates (Defender) and feature updates are not listed. The agent queries the Windows Update service online at most every 6 hours; in between it reads the result of Windows' own last scan (with `PATCHMAN_REFRESH_PACKAGE_LISTS=false` it always uses that result).
- *Vulnerabilities:* for every pending KB the central server asks the [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide) API which CVEs it fixes, with CVSS scores and titles. For cumulative updates, older KBs they supersede are added as long as the Windows build containing the fix is newer than the host's build. A finding is tied to the KB; once the KB is installed the finding becomes "Resolved". KEV flags work as on Linux. Updates for which Microsoft publishes no CVE mapping (such as some .NET cumulative updates) are listed as security updates but create no CVE findings. Third-party programs are not scanned.
- *Update jobs:* security updates, all updates, selected KBs and **Apply fix** are downloaded and installed through Windows Update; afterwards the agent reads the pending list again to verify the installation. If an installation needs a reboot, the job output says so and the host is marked **Reboot required**. Scheduled updates do not reboot Windows hosts either.
- *Reboot:* the **Reboot** job runs `shutdown.exe /r /t 60`; the result reaches the panel first.

**Removal.** In an administrator PowerShell:

```powershell
.\install-agent.ps1 -Uninstall
```

Without the script:

```powershell
Stop-Service netio-patchman-agent; sc.exe delete netio-patchman-agent
Remove-Item -Recurse -Force 'C:\Program Files\netio-patchman', 'C:\ProgramData\netio-patchman'
```

Then remove the host in the panel from its **System Information** tab.

### 4.6 Health check scripts (health.d)

HTTP, TCP, service and resource checks are defined in the panel and run inside the agent. If a host needs a specific check (e.g. the state of database replication), write a local script, then create a check of type **Local command (health.d)** in the panel and give the script's file name. The panel only sends the file name to the agent; it cannot send a command line or parameters, so the host's administrator always decides which scripts can run.

Linux:

```sh
sudo install -d -o root -g root -m 0755 /etc/netio-patchman/health.d
sudo install -o root -g root -m 0755 replication-check /etc/netio-patchman/health.d/replication-check
```

- The folder and the file must be owned by root and must not be writable by group or others. Otherwise the agent does not run the script and the check counts as failed.
- The file name starts with a letter or digit and consists of letters, digits, dots, dashes and underscores (at most 64 characters). Subfolders and symbolic links are not accepted.
- The check passes when the script exits with 0. The last five lines of output are shown as the result. If the check's timeout (default 10 seconds, at most 2 minutes) passes, the script is stopped.

On Windows the folder is `C:\ProgramData\netio-patchman\health.d\`. `.ps1`, `.cmd`, `.bat` and `.exe` files are accepted; PowerShell scripts run with `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File`. Make sure only administrators can write to the folder.

Health checks, the service list, preview and rollback work with agents 1.0.0 and later. Agents move to the new version by automatic update (see section 6).

## 5. Backup and restore

### 5.1 Automatic backups

Every day at the configured time (default 02:30 in `PATCHMAN_TIMEZONE`) the server writes a consistent copy of the database and keeps the newest N copies (default 7). The settings are in **Settings → Automatic backup**. If the server is down at backup time, the backup is taken in the first minute after it starts.

- File name: `netio-patchman-YYYYMMDD-HHMMSS.db`. Every file is a SQLite database you can open directly; with PostgreSQL the backups are written in the same format from a single consistent snapshot, so a backup can be restored into either database.
- The default folder is `/data/backups` (inside the Docker volume). Against losing the volume or disk, write backups to a separate disk:

  ```yaml
  # docker-compose.override.yml
  services:
    server:
      environment:
        PATCHMAN_BACKUP_DIR: /backups
      volumes:
        - /mnt/backup/netio-patchman:/backups
  ```

  The container runs as user 65532; the folder must be writable for that user: `chown 65532:65532 /mnt/backup/netio-patchman`.
- **Back up now** in the panel takes a backup immediately, and the **Download** link in the list downloads one. Backups contain password hashes and the SMTP password, so only administrators can download them; every download is written to the audit log.
- If a backup fails (disk full, no permission) a critical notification is created and, if e-mail notifications are on, an e-mail is sent.

### 5.2 Manual backup

A consistent database backup can be taken while the server runs:

```sh
docker compose exec server netio-patchman-server backup -out /data/backup-$(date +%Y%m%d).db
docker compose cp server:/data/backup-$(date +%Y%m%d).db ./
```

### 5.3 Restore

The `restore` command replaces all data in the database with the backup. It runs in a single transaction; if the backup cannot be read or belongs to another version's schema, the database does not change. Stop the server first:

```sh
docker compose stop server
docker compose run --rm --no-deps server restore -in /data/backups/netio-patchman-20261119-023000.db
docker compose start server
```

Copy a backup from outside into the volume first: `docker compose cp ./backup-20261119.db server:/data/backup-20261119.db`, then `-in /data/backup-20261119.db`. To take automatic backups out: `docker compose cp server:/data/backups/netio-patchman-20261119-023000.db ./`. Keep copies of backups outside the server too.

Backups of earlier versions (SQLite) can also be restored; the schema is upgraded to this version first. A backup of a newer version is not restored.

## 6. Upgrading

```sh
git pull
docker compose up -d --build
```

The database schema is upgraded automatically on start. Take a backup before upgrading. When moving from 0.7.x to 0.8.0 the SQLite data is imported into PostgreSQL, see [section 2.2](#22-database).

The version of the server and the agents comes from the `VERSION` file in the repository. To give your own build a different version, set `PATCHMAN_VERSION` in `.env`. Agents only update when the version changes.

### New release notices

The server reads the `VERSION` file of the repository one minute after start and then every 12 hours. When a newer version exists:

- Administrators see a notice at the top of every page and a **New version** badge in the sidebar.
- A notification is created once for every new version.
- If e-mail notifications are on, administrators (or the configured recipients) get one e-mail per new version. It can be turned off under **Settings → Email notifications**.
- **Settings → Server configuration → Product version** shows the installed version, the latest published version, the time of the last check and the upgrade commands. **Check now** runs the check immediately.

The request only sends the header `User-Agent: netio-patchman-server/<version>`; nothing about hosts, users or findings is sent. The address can be changed: a plain-text `VERSION` file or the GitHub release API (`https://api.github.com/repos/<owner>/<repo>/releases/latest`) can be used. The check can be turned off in the same section.

The notice only appears from the version that introduced this feature. A server running an older version has to be upgraded once by hand.

### Updating from the panel

When the optional `updater` container is enabled, upgrades are started from **Settings → Server configuration → Product version → Update now**:

```sh
cd netio.patchman
echo "COMPOSE_PROFILES=updater" >> .env
docker compose up -d --build
```

How it works:

1. The panel writes `update-request.json` into the data volume (it does not touch Docker).
2. The updater (polling every 5 seconds) picks the file up and runs, in this order: `git pull --ff-only` (as the repository owner, so files do not become root's), a backup with `netio-patchman-server backup` (`/data/before-update-<version>-<time>.db`), `docker compose build server`, `docker compose up -d server`, a health check (up to 10 minutes).
3. The state is written to `/data/update/status.json` and the output to `/data/update/update.log`; the panel shows them and creates a notification when done.

While the update runs, the **Product version** section shows the steps (request, git pull, backup, build, restart, health check), what the current step does, the elapsed time and the live output. On every other page administrators see a notice with the current step, and the "new release" notice is hidden meanwhile. While the server restarts the panel is out of reach for a short time: the page says so, carries on once the connection is back and reloads when the work is done. The result ("Updated from … to …" or the failed step) stays on every page for 15 minutes. If no updater picks up the request (its container is not running), the panel says that too.

The updater runs the script from the repository (`deploy/updater/updater.sh`), so `git pull` updates it as well. If the updater image itself changes (`deploy/updater/Dockerfile`), run `docker compose up -d --build` once.

**Security:** the updater mounts `/var/run/docker.sock`, which is equivalent to root on the server. It opens no port and takes no parameters from the request file; an administrator in the panel can only start an upgrade to the newest version in the repository. To turn the feature off, remove the `COMPOSE_PROFILES=updater` line from `.env` and run `docker compose --profile updater rm -sf updater`.

**Troubleshooting:** if the repository has local changes, `git pull --ff-only` stops (visible in the output); revert the changes or put them aside with `git stash`. If the updater does not run: `docker compose logs updater`.

### Automatic agent updates

The Docker image contains the amd64 and arm64 Linux agents and the amd64 Windows agent of the same version as the server. While **Settings → Agents → Update agents automatically** is on (the default):

1. When an agent running a different version connects, the server creates an "Agent update" job.
2. The agent downloads the new binary from the server, compares the SHA-256 hash and checks that it runs with `-version`. Agents with a signing key first verify the version's signature (see below).
3. It keeps the current binary as `netio-patchman-agent.previous`, puts the new one in place and exits; systemd restarts the agent with the new version. On Windows the running file is set aside as `netio-patchman-agent.exe.previous` and the service restarts with the new version within a few seconds thanks to the recovery settings.

At most 25 agents update at the same time. A failed update is retried after 6 hours and shows up in Notifications. With automatic updates off, agents can be updated with **Agents → Update outdated agents** or the **Update agent** button on the host page.

To pin the agent version on a host, put `PATCHMAN_AUTO_UPDATE=false` into `/etc/netio-patchman/agent.env` (or install with `--disable-auto-update`).

To undo an update:

```sh
sudo mv /usr/local/bin/netio-patchman-agent.previous /usr/local/bin/netio-patchman-agent
sudo systemctl restart netio-patchman-agent.service
```

For installations without the image, put the agent binaries into the `PATCHMAN_AGENT_DIST_DIR` folder as `netio-patchman-agent-linux-<arch>` and `netio-patchman-agent-windows-amd64.exe`, and write the version into a `version` file in the same folder. `scripts/build-agent.sh <version> <folder>` produces this folder ready to use (Linux amd64 and arm64, Windows amd64, SHA-256 hashes and the `version` file).

### Signed agent updates

When an agent update is checked by SHA-256 only, the server provides the hash. Whoever takes over the server could therefore hand every host an agent binary of their own; agents run as root, so that means running commands on every host. With signed updates the agent requires the version to be signed with an Ed25519 key that is not on the server:

- The signature covers the version, the platform and the SHA-256 of the file. The agent verifies it before the download, and the downloaded file must match the signed hash.
- An agent with a signing key refuses unsigned updates and downgrades.
- The keys an agent trusts are kept on the managed host and cannot be changed from the central server.
- It is optional and does not affect existing installations: until a key is set, all agents keep updating by SHA-256. Agents older than 1.1.2 do not know signatures, keep working with the new server and move to the new version through automatic updates.

**1. Create the key pair** on a machine you trust, away from the server (it may be offline):

```sh
netio-patchman-server agent-key -out agent-signing.key
```

The command writes the private key to a file only its owner can read and prints the public key (e.g. `Z0OUQxnMvSfCy+bgVZSs/wKuAflQXnAHoeof0yjj1e4=`) and its id (e.g. `471ae649095c738e`). The private key never goes onto the server; if you lose it, create a new pair and replace the key on the agents. Without a `netio-patchman-server` binary on that machine, run the command from the repository: `go run ./cmd/netio-patchman-server agent-key -out agent-signing.key`.

**2. Build and sign the agent files** on the same machine, from the tag of the version the server runs:

```sh
git checkout v1.1.2
PATCHMAN_SIGNING_KEY=/path/agent-signing.key scripts/build-agent.sh "" agent
```

The script builds the files and writes a `<file>.sig` signature next to each one (on Windows `scripts\build-agent.ps1` reads the same variable). To sign an existing folder: `netio-patchman-server agent-sign -key agent-signing.key -dir agent`. The command computes the hashes itself and does not sign when a `.sha256` file disagrees.

**3. Give the signed files to the server.** When the `agent` folder in the data directory contains a `version` file, the server distributes it instead of the agent files in the image. With Docker Compose:

```sh
docker compose cp agent/. server:/data/agent/
docker compose restart server
```

For installations without the image, put the files into `<data directory>/agent` or the `PATCHMAN_AGENT_DIST_DIR` folder and restart the server. **Agents → Agent updates** shows the distributed version, and the **Signature** row the key that signed it.

**4. Give the key to the agents.** There are two ways:

- Enter the public key under **Settings → Agents → Update signing keys**. Agents without a key yet (1.1.2 and later) save it in their state directory at their next connection (`/var/lib/netio-patchman/update-keys`, on Windows `C:\ProgramData\netio-patchman\update-keys`) and from then on only install updates signed with it. This first save trusts the server: if the server is compromised at that moment, the attacker's key could be saved.
- For a stricter setup, write the key into the agent configuration yourself: add `PATCHMAN_UPDATE_KEYS=<public key>` to `/etc/netio-patchman/agent.env` (Windows: `C:\ProgramData\netio-patchman\agent.env`) and restart the agent. Keys in the configuration take precedence over saved keys. For a mass rollout, add the line with your configuration management tool.

Once signing is in use (a key on the server, a signed release or an agent with a key), the **Signed agent updates** notice under **Agents → Agent updates** lists by name the agents that do not trust a matching key yet: those trusting another key (the key can only be changed on the host), those without a key, older agents that cannot take a key (they must move to 1.1.2 or later first; automatic updates do that on their own) and those that save the key at their next connection. With keys on the server, the notice shows the `PATCHMAN_UPDATE_KEYS=…` line for assigning the key by hand, ready to copy. The notice disappears once every agent trusts a matching key.

In the agent list, agents that require signed updates carry the **Signed only** label. If the distributed version is not signed with an agent's key or is not newer than the agent, the server sends that agent no update job; it shows **Waiting for a signature**.

**On every upgrade**, repeat steps 2 and 3 for the new version. The files in the data directory take precedence over those in the image, so a version you did not sign is never distributed.

**Changing the key:** create a new pair. During the transition give the agents both keys (`PATCHMAN_UPDATE_KEYS=<old>,<new>`, at most 8 keys), then sign releases with the new key. Keys saved from the server only change on the managed host: edit or delete the `update-keys` file and restart the agent. Once the file is deleted, the agent saves the server's keys again at its next connection.

### Reinstalling an agent by hand

If you run the install command again **without** the `--token` option, the agent keeps its identity:

```sh
curl -fsSL https://patchman.your-domain/downloads/install-agent.sh | \
  sh -s -- --server-url https://patchman.your-domain
```

With `--token` the agent registers again. Because the server matches the record by machine id, the history is not lost.

## 7. Resetting an administrator password

If every administrator forgot their password:

```sh
docker compose exec server netio-patchman-server reset-password -email admin@your-domain
```

The command generates a new password, prints it and enables the account.

If an administrator with two-step verification lost the authenticator app and the recovery codes:

```sh
docker compose exec server netio-patchman-server reset-mfa -email admin@your-domain
```

The command removes the user's authenticator and recovery codes and ends their sessions. The user signs in with the password only and sets up verification again. If it is required, the first sign-in leads to the My Profile page.

## 8. Networks without internet access

- **Agents:** take the agent binary, the `netio-patchman-agent.service` file and the `install-agent.sh` script from the download addresses on the panel's **Agents** page, copy them to the host and install with the `--binary` option. On Windows use `install-agent.ps1` and `netio-patchman-agent-windows-amd64.exe` with `-Binary`.
- **Vulnerability data:** on the **Server configuration** page point the OSV API address to a mirror in your network. Point the KEV catalog address to an internal copy or turn the catalog off. For Windows hosts, point the Microsoft Security Update Guide address to a proxy or turn it off; when off, only the CVEs Windows Update reports itself are used. (Environment variables: `PATCHMAN_OSV_URL`, `PATCHMAN_KEV_URL`, `PATCHMAN_MSRC_URL`.)
- **New version check:** turn it off under **Server configuration → Version check** or point it to an internal `VERSION` file (`PATCHMAN_UPDATE_CHECK_URL=off`).
- **End-of-life calendars:** turn off endoflife.date access on the **Server configuration** page (`PATCHMAN_EOL_URL=off`). The built-in calendar shipped with the release is used; it is updated with every netio.patchman release. If you have an internal mirror, give its address (it must answer in the `/api/<product>.json` format).
- **Docker images:** building the server image needs `golang:1.26-alpine` and `gcr.io/distroless/static-debian12`, the database needs `postgres:17-alpine`. Pull them with `docker pull` and `docker save` on a machine with internet access and load them on the target with `docker load`.
- The panel uses no external resources (CDNs, fonts).

## 9. REST API and monitoring

For the REST API and Prometheus metrics see [api.en.md](api.en.md). Keys are created under **My Profile → API keys**; `/metrics` is protected with the same keys.

## 10. Troubleshooting

| Symptom | What to check |
|---|---|
| The server does not start | `docker compose logs server`: configuration errors are listed in the log. |
| "Cannot connect to the database, retrying" in the log | Is `docker compose ps postgres` "healthy"? `docker compose logs postgres`. For an external PostgreSQL check the address, password and `sslmode`. The server keeps retrying for two minutes. |
| "The SQLite database could not be copied to PostgreSQL" in the log | The error details are in the same entry. The SQLite file is unchanged and PostgreSQL left empty. Check disk space and the `postgres` container, then retry with `docker compose up -d`. |
| "The SQLite file was not copied because the PostgreSQL database already holds data" in the log | The import ran before but the old file could not be renamed. Check that the data shows up in the panel, then move `/data/netio-patchman.db` aside. |
| An agent does not appear | On the host: `journalctl -u netio-patchman-agent.service -n 50`. The enrollment token may have expired or reached its use limit. |
| A Windows agent does not appear or lists no updates | `Get-Content C:\ProgramData\netio-patchman\agent.log -Tail 50`. Is the `wuauserv` service disabled? With WSUS, are the updates approved? |
| No CVEs on a Windows host | Check that the central server can reach `api.msrc.microsoft.com` and the Microsoft Security Update Guide setting on the **Server configuration** page. |
| Agent "Offline" | Check the agent service, HTTPS access to the server and time synchronization. |
| No vulnerabilities are found | Check the last error in **Settings → Scan status**. Make sure the distribution is supported. |
| No e-mails arrive | Check the SMTP settings on **Settings → Server configuration** and send a **Test email**. |
| An update job "Timed out" | The agent did not report a result within 3 hours. Look at `journalctl -u netio-patchman-agent.service` on the host. |

Server logs are JSON and every entry has the field `app=netio.patchman`. Log messages use the server's default language (`PATCHMAN_LOCALE`).

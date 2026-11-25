# netio.patchman User Guide

🇬🇧 **English** · 🇹🇷 [Türkçe](kullanim.md) · ⏱️ Reading time: about 40 minutes

This document describes the daily use of the web panel. The names of pages, buttons and settings are those of the
English interface (choose it under **My Profile → Interface language**).
Back to the [README](../README.md) · [Installation guide](installation.md) · [REST API](api.en.md) ·
[Live demo](https://alptekinsunnetci.github.io/netio.patchman/demo/en/dashboard.html)

## Roles

| Role | Permissions |
|---|---|
| **Administrator** | Everything: user management, settings, enrollment tokens, scheduled updates, removing servers |
| **Operator** | Viewing, starting update jobs, refreshing inventory, changing the status of findings |
| **Viewer** | Viewing and CSV export only |

### Group-based access

An operator or viewer can be limited to the servers of certain groups (e.g. the web team only sees the "Web" group, a customer only its own group). Choose **Users → user → Server access → Only the servers of the selected groups** and tick the groups.

A limited user:

- only sees the servers of these groups, their findings, updates and jobs, and the notifications about these servers; starting jobs, changing statuses and **Apply fix** also only work on these servers,
- does not see schedules, agent management and the fleet-wide trend charts,
- API keys of the user work with the same limit.

A server removed from the group becomes invisible to these users. A limited user without any group sees no servers. Administrators always see all servers.

## Dashboard

Shows the overall state of the infrastructure:

- **Critical Vulnerabilities:** the number of critical vulnerabilities waiting for a fix.
- **Exploited Vulnerabilities:** vulnerabilities in the CISA KEV catalog, i.e. known to be actively exploited. These always come first.
- **Pending Security Updates:** updates from the distribution's security repository that are not installed yet.
- **Offline Agents:** agents that did not connect within the configured time.
- **Waiting for Reboot:** servers with a new kernel or microcode installed but not rebooted yet, and how long the oldest one has been waiting.

Click a card to open the matching filtered list.

The **My watched packages** section shows the state of packages you want to keep an eye on, such as nginx or mariadb, across all servers: on how many servers it is installed, how many different versions run, on how many servers an update is pending, and the number of open vulnerabilities with the highest severity. To watch a package, click the star next to its name on the server's **Installed Packages** tab, on the **Packages** page or on the package page. Clicking the star again removes it. The list is personal: every user has their own, and viewers can keep a list too. A user can watch at most 100 packages. Users limited to groups only see the state on their own servers.

The **Daily trend** section shows the last 30 days in four small charts: critical and high vulnerabilities (CVEs), actively exploited vulnerabilities (KEV), open findings and pending security updates. Hover over a chart (or use the arrow keys while it is selected) to see the value of a day. **Show daily values as a table** opens the same data as a table. The server writes the state of the fleet into the day's record every 15 minutes; days when the central server was down leave a gap. The chart appears from the second day on.

## Server Inventory

Lists every server with its operating system, last connection, open vulnerabilities (by severity) and pending updates. Click a server name to open its detail page:

- **Vulnerabilities:** the findings on this server. The search box filters by CVE number, title or package name. On Debian/Ubuntu findings are recorded under the source package name, but you can also search by binary package name: `mariadb-server` finds the findings of the `mariadb` source package.
- **Pending Updates:** upgradable packages. The search box filters by package name, KB number on Windows, title or CVE. Select packages and use **Update selected packages** to install only those.
- **Installed Packages:** all packages and their versions. The star next to a package name adds it to your watch list.
- **Watched:** the watched packages installed on this server, each with its installed version, a newer version if any and open vulnerabilities. To add a package type its name and press **Watch**. Packages with an update can be selected and updated here too.
- **Job History:** the jobs run on this server.
- **System Information:** hardware, agent details and notes.

Buttons at the top of the page:

- **Refresh inventory:** asks the agent to send its package list again right away.
- **Apply security updates:** installs security updates only.
- **Apply all updates:** installs all pending updates.

### Bulk actions on several servers

Tick servers in the Server Inventory list (the box in the header selects all servers on the page). Then pick the action in the **On selected servers:** bar at the top and press **Apply**:

- Security updates
- All updates
- Refresh inventory
- Agent update

Combined with filters, an action like "apply security updates on all Ubuntu servers with pending updates" takes a few clicks. Servers with remote updates turned off are skipped and listed in the result message.

The "Reboot required" label means the server must be rebooted for installed updates (e.g. a kernel) to take effect. Its tooltip and the server's **System Information** tab show since when it has been waiting. Detection depends on the distribution: `/var/run/reboot-required` on Ubuntu, comparing the kernels under `/boot` with the running kernel on Debian, `needs-restarting -r` on the RHEL family, `zypper needs-rebooting` on SUSE, comparing the installed `linux-*` package with the running kernel on Alpine. If `needrestart` is installed, new microcode is considered too. netio.patchman never reboots servers on its own.

### Platform

The agent reports the platform the server runs on: virtual machines such as VMware, Hyper-V, KVM/QEMU, Xen, VirtualBox, Amazon EC2, Google Compute Engine, Docker/Podman/LXC containers, or physical hardware. It is detected with `systemd-detect-virt`, without it (e.g. on Alpine) from DMI data and container markers, on Windows from the BIOS data. The **platform** filter of Server Inventory lists, for example, only physical servers or only VMware virtual machines. Agents older than 0.3.0 show the platform as "Unknown" until they are updated.

### Windows servers

Windows servers appear in the same lists as Linux servers; their operating system id is `windows` (this name is used in filters and schedule scopes). Differences:

- The **Pending Updates** tab lists Windows Update updates instead of packages: KB number, title, Microsoft severity, classification (Security Updates, Update Rollups, etc.) and release date. If Windows Update reported the CVEs of an update, their number is shown next to the title. Select updates and use **Update selected packages** to install only those KBs.
- The **Installed Packages** tab shows the programs of the "Programs and Features" list. These programs are not scanned for vulnerabilities.
- On servers with **winget** (App Installer), updates of third-party programs (Chrome, 7-Zip, Git, etc.) are also listed under Pending Updates with the classification **winget** and are installed by **All updates** or as selected packages (a security update job does not install them). As the agent runs as SYSTEM, only programs installed for all users are visible. Windows Server 2016/2019/2022 usually do not have App Installer; without winget the feature is off automatically. `PATCHMAN_WINGET=false` turns it off.
- **Vulnerabilities:** the CVEs fixed by every pending KB come from the Microsoft Security Update Guide. In a finding the **Affected Package** is the KB number, the **Installed Version** the server's Windows build (e.g. `10.0.20348.2700`) and the **Fixed Version** the build containing the fix. If a server is several months behind, the CVEs of earlier months superseded by the pending cumulative update are shown under the same KB; installing that one KB closes all of them. **Apply fix** installs the KB. Updates for which Microsoft publishes no CVE mapping (such as some .NET cumulative updates) are listed as security updates but create no CVE findings.
- **Update jobs** download and install through Windows Update; the job output shows the result for every KB (installed, or not installed with the result code and HRESULT). Verification works as on Linux. If an installation needs a reboot, the output says so and the server is marked "Reboot required". The need for a reboot is read from Windows Update and the Windows component servicing (CBS) records.
- The **Reboot** button runs `shutdown.exe /r /t 60` on Windows. Signed-in users see the warning.
- **Services that need a restart** are not detected on Windows; updates request a reboot when needed anyway.
- The platform is detected from the BIOS (SMBIOS) manufacturer and product name (Hyper-V, VMware, KVM, etc.).

### Packages not to update

If some packages must never change in any update job (a database server, the kernel, a KB known to cause trouble), define a pattern list:

- **Settings → Updates:** for all servers,
- **Server Groups → group:** for the servers of the group,
- **Server → System Information → Packages not to update:** for one server.

Patterns are separated by commas, spaces or new lines; `*` and `?` can be used (`kernel*`, `mysql-*`, `KB5034439`, `7zip.7zip`). The three lists are merged. The central server passes the list to the agent with the job; the agent skips matching packages and says so in the job output. This applies to every job from the panel, schedules, **Apply fix** and the API. On the Pending Updates tab these packages carry the **Excluded** label; their vulnerabilities are still shown.

Note: on SUSE, security patches (`zypper patch`) cannot be filtered by package name; with a list defined the SUSE security job does not run, use **All updates** or selected packages instead.

### Live kernel patching (KernelCare, Livepatch)

If KernelCare (`kcarectl`) or Canonical Livepatch (`canonical-livepatch`) is installed, the agent reports it; it is shown in the server header and under **System Information**.

- **KernelCare (RPM distributions: CloudLinux, AlmaLinux, Rocky, RHEL):** kernel findings are assessed against the kernel version KernelCare patched up to (`kcarectl --uname`). When a new kernel package is installed that KernelCare already covers, the server is not marked "Reboot required"; updated core libraries such as glibc or systemd still require a reboot.
- **Canonical Livepatch (Ubuntu):** CVEs closed by Livepatch do not count as open for kernel packages. The reboot notice for activating a new kernel package stays.
- On Debian/Ubuntu the KernelCare version cannot be mapped to a package version, so kernel findings follow the package version.

## Server Groups

Sort servers into groups such as "Production", "Test" or "Database". A server can belong to several groups.

- **Creating, renaming, deleting groups:** on the **Server Groups** page (administrators only). Deleting a group does not delete its servers.
- **Adding and removing servers (operators and administrators):** tick servers in Server Inventory, pick the group in the **Selected servers to group:** bar and press **Add to group** or **Remove from group**. The groups of a single server can also be changed under **System Information → Groups** on its detail page.
- **Use:** Server Inventory can be filtered by group; scheduled updates can target a group; compliance reports can be created for a group. The group page shows the group's critical and KEV counts.

A schedule targeting a group applies to the group's members at the moment it runs; servers added to the group later are covered as well. If the group is deleted, these schedules are disabled and their targets emptied; they never switch to all servers on their own.

### Restarting services and the server

When an update replaces a library a running service uses (e.g. `libssl3`, `libc6`), the service keeps running the old version in memory until it is restarted. The agent detects these services with every inventory:

- Debian/Ubuntu: with the `needrestart` package. If it is not installed, install it with `apt install needrestart`. When it is installed, apt upgrades already restart services on their own.
- RHEL family: with `needs-restarting -s` (`dnf-utils` / `yum-utils`).
- SUSE: with `zypper ps`.

The detected services are listed in the **Services that need a restart** section of the server page. Operators select services and restart them with **Restart selected services**. Services whose restart could end sessions or drop the network (dbus, systemd-logind, NetworkManager, getty, etc.) and the agent itself are skipped; for these the server has to be rebooted. After the job the agent checks that the services were really renewed.

The **Reboot** button on the server page reboots the server after one minute. The delay lets the result reach the panel and warns signed-in users. When the server is up again the agent sends a new inventory and the "Reboot required" label disappears. Both actions need remote updates to be on and are written to the audit log.

## Vulnerabilities

Detected vulnerabilities are listed starting with the most critical. Actively exploited vulnerabilities carry the **KEV** label.

On the detail page of a vulnerability:

- **Original Description:** the official description from the CVE record, in its source language (usually English) and unchanged.
- **Recommendation:** which package to update to which version.
- **Vendor Advisory:** advisories published by the distribution (DSA, USN, ALSA, RHSA, etc.); on Windows the KB that fixes the vulnerability with a link to the Microsoft support page.
- **Affected Servers:** with their installed and fixed versions.

If several kernels are installed on a server, only the **running kernel** (`uname -r`) is scanned. Old kernel packages cannot be updated, only removed; scanning them would keep vulnerabilities open even after a new kernel is installed and running. If a new kernel is installed but the server has not been rebooted yet, the vulnerabilities of the running old kernel stay open until the reboot. If the running kernel was not installed by the package manager (WSL, containers, custom kernels), all packages are scanned.

On Ubuntu, kernel vulnerabilities are shown under the `linux` source package and can number in the thousands; this comes from the structure of Ubuntu's security data. The first scan can therefore take a few minutes; later scans use the cache.

The **Apply fix** button updates the packages on every affected server where the fixed version is available in the repositories. On Debian, Ubuntu and Alpine vulnerabilities are shown under the source package name (e.g. `openssl`); netio.patchman determines the binary packages built from that source (`libssl3`, `openssl`) automatically.

### Resolution statuses

| Status | Meaning |
|---|---|
| Open | Newly detected, waiting for action |
| In Progress | Being worked on |
| Risk Accepted | Assessed, will not be fixed for now (a note is required) |
| False Positive | Verified not to affect the server (a note is required) |
| Resolved | The package was updated; netio.patchman detects this automatically |

Findings that are Risk Accepted or False Positive are left out of counts and notifications. A resolved vulnerability that is detected again is reopened automatically.

**Risk acceptance has a term.** When setting a finding to "Risk Accepted", choose **Accepted for**: 30, 90, 180 or 365 days. Administrators set the upper limit with **Settings → Security → Longest risk acceptance (days)** (default 365; 0 allows acceptance without an end). The term ends at the end of the chosen day (23:59). At that moment the findings become **Open** again, a notification is created for every CVE, a summary e-mail is sent if e-mail notifications are on and the audit log records it. Finding lists and reports show the end date and the user who accepted the risk.

### Remediation times (SLA) and EPSS

Under **Settings → Remediation times** set the number of days for every severity (default: critical 15, high 30, medium 90, low 180; 0 = no target). The due date counts from the first detection of a finding.

- Finding lists show a **Due** column and an **Overdue** label on overdue findings; the **Overdue** filter lists only these.
- The dashboard has an **Overdue findings** card; compliance reports have a **Security update SLA** section.
- When findings become overdue, a single summary notification is created and, if enabled, an e-mail is sent. Every finding is reported once.

**EPSS** (FIRST Exploit Prediction Scoring System) is the probability that a vulnerability is exploited in the next 30 days; it is updated daily. The vulnerability list has an EPSS column; the **By exploitation likelihood (KEV, EPSS)** sort shows actively exploited vulnerabilities first, then those with a high EPSS. It is a better guide than CVSS for deciding what to fix first.

## Compliance & Audit

The reports organizations need for audits come from one place: the **Compliance & Audit** group in the sidebar. There are no separate menus or report systems per framework; there is one reporting engine, one shared evidence repository and a separate control assessment for every framework.

| Section | Contents |
|---|---|
| **Overview** | Recent reports and their control outcomes, size of the evidence repository, the date evidence collection began |
| **Compliance Reports** | Creating reports, versions, reviews, finalizing, PDF / CSV / JSON export |
| **Audit Evidence** | The shared evidence repository: search, details, hashes, the controls an item supports; adding manual evidence |
| **Audit History** | Report versions, the user audit log (administrators), the integrity check of the evidence chain |
| **Compliance Policies** | Enabled frameworks, thresholds of the automated checks, control applicability, server standards |

> Reports are based on technical evidence that is collected automatically. They are not a certification or a statement of conformity. Using the same evidence in several frameworks does not mean all their requirements are met; the assessment and the decision belong to the auditor. This note appears in every report and every export.

### Assessment frameworks

When creating a report, choose one or more of the following. Control ids and descriptions are netio.patchman's own; no standard's text is copied. The catalogs are versioned (e.g. `isms@1`); a report keeps the catalog version it was created with.

| Framework | Scope | Controls |
|---|---|---|
| Information security management audits (`isms`) | Asset inventory, vulnerability management, configuration, change, logging, monitoring, backup, access, lifecycle, risk treatment, policies | 12 |
| IT baseline protection audits (`baseline`) | Patch and change management; separate controls for Linux servers, Windows servers and Windows clients; logging, backup, identity management | 12 |
| IT service management assessments (`itsm`) | Change enablement, release and deployment, configuration and asset management, monitoring, service levels | 8 |
| General security & patch compliance (`general`) | Basic security and update controls with measurable targets | 12 |

When several frameworks are chosen, evidence and checks are computed once, every framework is assessed separately with its own controls and the result is a single report.

### The evidence repository

Evidence is collected every minute from existing records while the server runs; nothing is collected specifically for a framework:

| Evidence kind | Source |
|---|---|
| Update job | Finished package updates and rollbacks (Linux packages and Windows KBs): result, remaining packages, who started it (user, schedule, rolling update, automatic), preview approval |
| Change job | Reboots, service restarts, agent updates, previews, health checks |
| Resolved vulnerability | CVE, package, severity, detection and resolution time, within the SLA or not, KEV or not |
| Audit log entry | User and system actions |
| Standard deviation | Deviations from server standards when first detected |
| Backup | Successful and failed backups |
| Daily inventory | At the end of every UTC day, the hash of that day's server states |
| Manual evidence | A document record added by a user (title, date, location, mapped controls) |

In addition the daily state of every server is stored: platform, operating system, agent version, last connection, pending updates, open findings by severity, KEV and SLA state, reboot, support state of the operating system and monitoring. So a 12-month audit period can be reported even after jobs and resolved findings were removed by the retention period (default 90 days).

- Items never change. The SHA-256 hash of every item covers its content and the hash of the item before it (a hash chain); if an item is changed or removed, **Audit History → Evidence integrity** shows it.
- Evidence retention is independent of operational data (default 1095 days, at least 400). Evidence used by final report versions is never removed.
- On the first run, older records that still exist are taken over too; they are marked **Retroactive**. If evidence collection began after the start of the period, the report says so in a warning.
- **Manual evidence** is for evidence that cannot be collected automatically, such as policy or process documents. Not the document itself is stored, but its title, date, location (document management number, address) and mapped controls.
- The platform is determined for every server: Linux, Windows Server, Windows 10, Windows 11.

### Creating a report and its structure

**Compliance Reports → New report**: choose a title, frameworks, the audit period (last 30/90 days, last quarter, last 12 months, last calendar year or a custom range of up to 731 days), the scope (all servers or a group) and optionally platforms. The sections of the report:

1. Executive summary (control outcomes per framework, warnings)
2. Scope and assessment period
3. Managed asset inventory
4. Linux and Windows update status (per platform)
5. Vulnerability management (open findings at the start and end of the period, resolved findings, mean time to resolve, open KEVs)
6. Patch compliance
7. Security update SLA
8. End-of-life systems
9. Change management (by type and origin, preview approvals)
10. Audit logs and the state of the evidence chain
11. Control assessments by framework and the shared checks
12. Collected technical evidence (id, kind, hash, mapped controls)
13. Missing evidence and recommendations

The **automated outcome** of a control is computed from its primary checks only; supporting checks add evidence but never improve the outcome:

| Outcome | Meaning |
|---|---|
| Evidence sufficient | The evidence of the period supports the control |
| Partial | Evidence exists, with values below the thresholds or missing aspects |
| Deviation | The evidence shows a deviation (e.g. overdue vulnerabilities, an end-of-life system, an administrator without MFA) |
| Evidence missing | No evidence for the period |
| Manual evidence required / present | Only a document can support the control; even when one is attached it needs a review |
| Not applicable | Excluded (with a reason) or no server of that platform in the scope |

Example: a successfully applied Windows security update is one evidence item and appears in the same report under vulnerability management (`ISMS-02`), patch and change management (`BASE-01`), change enablement (`ITSM-01`) and update job success (`GEN-04`), each time with its own relevance (primary or supporting).

### Versions, reviews and exports

- Every generation opens a new **version**; earlier versions are kept unchanged. **Generate new version** re-assesses with the current evidence. For a large fleet or a long period this can take a while: if the version is not ready within about 20 seconds, it is finished in the background and the report list shows it as **Generating…** until it appears (refresh the page). Only one generation per report runs at a time; if one fails, the list shows **Generation failed** with **Try again**, and the details are in the server log.
- Administrators record a **manual review** for every control (reviewed, accepted / reviewed, gap found, plus a note). The review is stored next to the automated outcome and does not change it. Reviews of controls whose automated outcome did not change carry over to the new version.
- **Finalize version** freezes the version and its reviews; a final version cannot change and a report with a final version cannot be deleted. A final version carries a separate SHA-256 covering its content and reviews.
- Exports are built from the stored version, never recomputed: the same version always gives the same content.
  - **PDF**: generated on the server (embedded font, Latin, Turkish and Cyrillic letters); the version hash is in the page footer.
  - **CSV**: a ZIP with the files `summary`, `controls`, `checks`, `gaps`, `assets`, `evidence`.
  - **JSON**: the content, the reviews and all evidence with hashes (`netio.patchman/compliance-export/v1`).
- Exports are written to the audit log. Only administrators see audit log details; in exports by other roles the person and detail fields of these items are hidden.

### Compliance Policies

- **Frameworks and thresholds**: the frameworks offered when creating a report; agent reach and monitoring coverage, update failure rate, share of up-to-date servers, share of findings resolved within the SLA, longest pending reboot and the evidence retention. Thresholds apply to newly generated versions.
- SLA times, the risk acceptance term, MFA enforcement, preview approval, backup and monitoring settings are kept in one place on their own pages; they are shown here with links.
- **Control applicability**: exclude a control that does not apply to your organization, with a reason; the reason appears next to the control in reports.
- **Server Standards** are in this section too (see the next chapter).

### Permissions

All roles see and export reports and evidence. Creating reports and new versions and adding manual evidence is open to operators and administrators; reviews, finalizing, deleting and policy changes to administrators. Users with group-based access only create and see reports for one of their groups and only see the evidence of their own servers.

API: `/api/v1/compliance/reports`, `/api/v1/compliance/reports/{id}/versions/{n}`, `/api/v1/compliance/evidence` (see [api.en.md](api.en.md)).

## Security score

Every server gets a security score from 0 to 100 (higher is better). It is recalculated every 15 minutes and its daily history is kept. These deductions are subtracted from 100:

| Criterion | Default |
|---|---|
| Open CVE: critical / high / medium / low / unknown | 10 / 5 / 2 / 0.5 / 1 |
| CVE in the KEV catalog | 25 |
| EPSS probability | 20 × EPSS (e.g. EPSS 0.5 → 10) |
| Past the remediation time (SLA) | 12 |
| Upper limit for vulnerabilities | 70 |
| Operating system out of support / support ending soon | 25 / 5 |
| Software out of support (except software the distribution maintains) | 5 per product, at most 15 |
| Security update not tied to a vulnerability | 1 per update, at most 10 |

- **A CVE counts only once.** Even if a CVE is critical, in the KEV catalog and overdue at the same time, only the deduction of the highest criterion applies. The same CVE found in several packages is subtracted once. Accepted risks and false positives do not count.
- Security updates are only subtracted when they do not match a vulnerability finding, so the same issue is not punished twice.
- Click the score in the server list to see which criterion took how many points and the score history of the last 90 days. The list can be sorted by score and filtered, e.g. "score below 60". The dashboard shows the fleet's average and lowest score, the Server Groups page the average of every group.
- The weights are changed on **Settings → Security score weights** (administrators only). If a threshold is set on the same page, one notification is sent for servers whose score drops below it. If the score rises above the threshold and drops again, it is reported again.
- API: `/api/v1/hosts/{id}/score`; Prometheus: `netio_patchman_security_score`.

## Server standards and deviations

On **Compliance & Audit → Compliance Policies → Server Standards** rules are defined for all servers or a group (only administrators define rules; all roles see the deviation report). Example: "On web servers PHP must be 8.2 or 8.3, telnetd must not be installed, nginx must be running."

| Rule | Meaning |
|---|---|
| Must be installed | The software or package must be installed |
| Must not be installed | The software or package must not be installed |
| Allowed release series | The software's release series must be one of the list (e.g. `8.2, 8.3`) |
| Minimum version | The package version must be at least this |
| Must be running | The software's service must be running |

- The subject of a rule is a **software** (a product of the Software Inventory, e.g. `nginx`) or an exact **package name**.
- **Minimum version** is compared with the distribution's own version number (e.g. `1.22.1-9+deb12u1`), so backported security fixes do not produce false deviations. Upstream version numbers are not compared.
- Deviations are re-evaluated on every save and every 15 minutes. A notification is sent when a new deviation is first seen. Resolved deviations disappear from the list on their own.
- The **Deviations** tab shows the server, the rule, what was found and when it was first seen for every deviation. If a pending update can fix the deviation it is shown as a suggestion (e.g. "update php8.1-common"). The Software tab of a server page lists that server's deviations.
- Deviations are compliance findings, not vulnerabilities; they do not affect the security score. API: `/api/v1/drift`.

## Packages

- **Pending Updates:** updates on all servers grouped by package. **Update on all servers** updates a package everywhere; **Apply all security updates** starts security updates on every server.
- **Package details:** click a package name to list the servers waiting for its update. Tick servers and use **Update on selected servers** to update the package only there (for example on test servers first).
- **Find Installed Package:** find on which server a package is installed in which version.

## Software Inventory

The **Software Inventory** page shows the recognized software on the servers; currently 399 products are recognized. Package names are mapped to product names (e.g. `nginx-core` → Nginx, `php8.2-fpm` → PHP-FPM 8.2, `ea-php82` → PHP 8.2, `openjdk-17-jre-headless` → Java 17). Debian/Ubuntu, Red Hat family, SUSE and Alpine package names and the names of programs installed on Windows are recognized. cPanel EasyApache (`ea-php*`, `ea-apache24`, `ea-nginx`) and CloudLinux PHP Selector (`alt-php*`) packages are linked to their products as well.

| Category | Example products |
|---|---|
| Runtime | Python, PyPy, Java (OpenJDK, Temurin, Corretto, Zulu, Oracle), GraalVM, Node.js, Deno, Bun, PHP, PHP-FPM, Ruby, JRuby, Go, .NET, .NET SDK, Mono, Perl, Rust, Erlang, Elixir, Lua, R, Swift |
| Web server / proxy | Apache, Nginx, NGINX Unit, OpenResty, Caddy, Traefik, HAProxy, Envoy, Varnish, Squid, lighttpd, LiteSpeed, OpenLiteSpeed, Cherokee, H2O, Apache Traffic Server, Tengine, IIS, Tinyproxy, 3proxy, Privoxy |
| Application server | Tomcat, TomEE, WildFly, JBoss EAP, Jetty, GlassFish, Gunicorn, uWSGI, Uvicorn, Daphne, Puma, Unicorn, Passenger, FrankenPHP |
| Database and cache | MySQL, MariaDB, Percona Server, PostgreSQL, TimescaleDB, SQLite, SQL Server, Oracle Database, Firebird, CockroachDB, MongoDB, CouchDB, Couchbase, RethinkDB, RavenDB, ArangoDB, FerretDB, ScyllaDB, Cassandra, HBase, ClickHouse, InfluxDB, VictoriaMetrics, OpenTSDB, FoundationDB, Aerospike, Tarantool, Redis, Valkey, KeyDB, Dragonfly, Memcached, Hazelcast |
| Message queue | RabbitMQ, Kafka, ActiveMQ, NATS, EMQX, VerneMQ, Mosquitto, Redpanda, Celery, Gearman, Beanstalkd, NSQ |
| Search, logging and monitoring | Elasticsearch, OpenSearch, Solr, Sphinx, Meilisearch, Typesense, Graylog, Loki, Fluentd, Fluent Bit, Logstash, Vector, Filebeat, Metricbeat, OpenTelemetry Collector, Jaeger, Kibana, Zabbix, Prometheus and its exporters, Alertmanager, Grafana, Alloy, Tempo, Mimir, Icinga 2, Checkmk Agent, Centreon, Nagios, Netdata, Sensu, Telegraf, collectd, Munin, Monit, Thanos |
| Mail | Postfix, Exim, Sendmail, OpenSMTPD, Dovecot, Courier, Cyrus IMAP, Rspamd, SpamAssassin, Amavis, ClamAV, OpenDKIM, OpenDMARC, Mailman, Roundcube, SOGo, MailScanner, Exchange |
| DNS and network | BIND, Unbound, PowerDNS, Knot DNS, Knot Resolver, NSD, CoreDNS, dnsmasq, Kea, ISC DHCP, FRR, BIRD, OpenBGPD, Quagga, Open vSwitch, Keepalived, Corosync, Pacemaker, IPVS |
| VPN and remote access | OpenVPN, WireGuard, strongSwan, Tailscale, Headscale, ZeroTier, Nebula, SoftEther, OpenSSH, Dropbear |
| Identity | OpenLDAP, 389 Directory Server, FreeIPA, MIT and Heimdal Kerberos, Keycloak, Authelia, Kanidm, SSSD, FreeRADIUS |
| Security | Fail2ban, CrowdSec, ClamAV, maldet, OSSEC, Wazuh, AIDE, Tripwire, Lynis, RKHunter, chkrootkit, Suricata, Snort, Zeek, ModSecurity, OWASP CRS, SELinux, AppArmor, nftables, iptables, firewalld, UFW, Shorewall, CSF, Imunify360, ImunifyAV, OpenSCAP, auditd, YARA, Falco, KernelCare, Certbot, OpenSSL, GnuPG |
| Containers and virtualization | Docker, Docker Compose, containerd, CRI-O, Podman, Buildah, Skopeo, runc, crun, LXC, LXD, Incus, Kubernetes, minikube, Helm, QEMU/KVM, libvirt, Proxmox VE, OpenNebula, oVirt, Xen, VirtualBox, Nomad |
| Storage and backup | Ceph, GlusterFS, MooseFS, MinIO, DRBD, OpenZFS, Btrfs, LVM2, mdadm, multipath, Samba, NFS, iSCSI, Bacula, Bareos, BorgBackup, Restic, Duplicity, Duplicati, UrBackup, Amanda, Kopia, rsnapshot, rsync, Rclone, Veeam, Proxmox Backup Server, ReaR, pgBackRest, XtraBackup, Mariabackup, Barman, JetBackup |
| CI/CD and automation | Jenkins, GitLab, GitLab Runner, Gitea, Forgejo, Woodpecker, Buildbot, Ansible, Puppet, Chef, Salt, CFEngine, Terraform, OpenTofu, Packer, Vagrant, Rundeck, Semaphore, Artifactory |
| Hosting panel | cPanel & WHM, Plesk, DirectAdmin, Webmin, Virtualmin, ISPConfig, HestiaCP, CloudPanel, Froxlor, VestaCP, Cockpit, CageFS, LVE Manager, MySQL Governor |
| Web and business applications (installed as packages) | WordPress, MediaWiki, phpMyAdmin, Adminer, phpBB, Redmine, Matomo, Odoo, Zammad, GLPI, Mattermost, Matrix Synapse, ONLYOFFICE, Collabora Online, OpenProject |
| System tools | systemd, D-Bus, Polkit, chrony, NTPsec, rsyslog, syslog-ng, logrotate, TuneD, smartmontools, sysstat, iproute2, tcpdump, TShark, nmap, sudo, coreutils and similar |

The system tools category also shows base packages installed on every server and can make the list long; filter it out with the category filter.

Products installed outside the package manager are detected by the agent itself and shown as **Detected by the agent**:
- **Linux:** cPanel (`/usr/local/cpanel/version`), Plesk (`/usr/local/psa/version`), LiteSpeed/OpenLiteSpeed (`/usr/local/lsws/VERSION`), DirectAdmin (the version output of its program), CSF (`/etc/csf/version.txt`), maldet and ISPConfig.
- **Windows:** the patch level of IIS and SQL Server instances is read from the registry.

This detection needs agent 1.0.2 or later.

Software installed from a tarball, in containers or with a language package manager does not appear in the package inventory. For example, WordPress, Joomla, Drupal, Magento, Nextcloud, Laravel or Django applications installed per site, or components inside Kubernetes such as Argo CD or Longhorn, are not recognized. An application-level detection scanning web directories may be added later.

- **Software:** on which servers every product is installed and in which release series. The product page shows the package, version and service state per server.
- **Installed and running:** the agent also sends its service list (systemd, OpenRC, Windows services). Software that is installed but whose service is not running is marked separately. Service data only comes from agents 1.0.0 and later.
- **Vulnerabilities and EOL:** product rows show the open findings in the software's packages and its support state.
- **Compare servers:** the software and release series of two servers side by side. Rows present on only one of them or with different versions are marked.
- **Change history:** installed, removed and changed software with date, server, old and new version. Notifications for these changes can be turned on and off under **Settings → Software inventory**.

### End of life (EOL)

The **End of life (EOL)** tab of Software Inventory shows the support calendar of operating systems and recognized software: supported, ending soon, end of life and unknown.

- The calendars are updated once a day from [endoflife.date](https://endoflife.date). The built-in calendar shipped with the product is used in installations without internet access (`PATCHMAN_EOL_URL=off`).
- Distributions such as Ubuntu, Debian and the RHEL family keep maintaining the software they package (e.g. the distribution's PHP or Python) with security updates after upstream support ended. Such installations are marked **Maintained by the distribution** and are left out of EOL notifications and the security score.
- The warning period (default 90 days) is changed with **Settings → Advance warning (days)** in the inventory section. One notification is sent for every release whose support is ending or has ended.
- The page can be filtered by status, kind and group. API: `/api/v1/eol`.

## Scheduled Updates

To apply updates automatically on certain days and times within a maintenance window, create a rule on the **Scheduled Updates** page (administrators only). Example: "Every Sunday at 03:00 apply security updates on Ubuntu servers, maintenance window 2 hours."

| Field | Description |
|---|---|
| Action | Security updates or all updates |
| Days, start time | The days and time the rule runs (`PATCHMAN_TIMEZONE`, default Europe/Istanbul) |
| Maintenance window | How long an agent may pick up the job (15 minutes – 24 hours) |
| Scope | All servers, one operating system (e.g. `ubuntu` or `windows`), a group or selected servers |

How it works:

- At the start time a job is created for every server in scope that has pending updates of the matching kind. Up-to-date servers get no job.
- Servers with remote updates turned off and servers with a pending job of the same kind are skipped.
- If an agent does not connect within the maintenance window, the job is not run and is marked **Expired**. So a server that was switched off does not get updated during working hours when it comes back. A job that started within the window finishes even if the window closes.
- If the central server is down during the whole maintenance window, that run is skipped and a warning notification is created.
- Every run creates a single summary notification. Successful jobs create no further notifications; failed jobs are reported and e-mailed as usual.
- **Run now** runs the rule immediately (the maintenance window starts then); the normal schedule does not change.
- When a schedule is deleted, its jobs not yet sent to agents are cancelled; the history of finished jobs is kept.

Scheduled updates do not reboot servers unless **Restart the server within the maintenance window if the update requires it** is ticked. With the option on, if the update job finished successfully (or partially), the server reports that it needs a reboot and the maintenance window is still open, the server reboots one minute later; at most once per update job. With the option off, plan reboots after kernel updates with the **Reboot** button on the server page or your own method; servers that need one carry the "Reboot required" label. The schedules that cover a server are listed on its **System Information** tab.

## Update Jobs

Every action started from the panel or by a schedule is a job. Jobs run when the agent next connects (by default within a minute). The job page shows the command output, the exit code and the times. Jobs not yet sent to an agent can be cancelled. If the agent does not report a result within 3 hours, the job is marked "Timed out". For jobs created by a schedule, the "Started By" column shows the schedule's name.

Agents open no ports on servers. They connect to the central server over HTTPS at regular intervals, pick up pending jobs and report results. So managed servers need no inbound access; the agent only has to reach the central server.

When a job finishes, the agent sends its inventory right away and the security scan is updated.

### Verifying the result

A package manager finishing without an error does not mean the packages were updated. For example, apt skips packages that are not installed or held, prints a warning and still succeeds. So in every update job the agent:

1. Refreshes the package lists and takes the pending updates as targets. Selected packages without a pending update are skipped and the output says so.
2. Runs the update command.
3. Checks again which targets are still pending.

The job status follows this check:

| Status | Meaning |
| --- | --- |
| Succeeded | All targeted packages were updated (the output says "Verified"). |
| Partially succeeded | Some packages were updated, some are still pending. |
| Failed | The command failed or none of the packages was updated. |

Packages that could not be updated are listed on the job page. **Retry remaining** creates a new job for these packages only. Other failed jobs can be repeated with **Retry**. Partially succeeded and failed jobs create notifications and, if enabled, e-mails. The agent does not retry an update on its own: the cause of a failure (dependency conflicts, held packages, repository errors) usually needs a manual fix. Scheduled updates run again in the next maintenance window.

New dependencies that are not installed yet (such as a new kernel version or split firmware packages) are not shown in the update list. When the package requiring them is updated, the package manager installs them itself.

### Preview and approval (dry-run)

An update started from a server page first runs as a **preview**. The agent uses the simulation mode of the package manager: `apt-get -s`, `--assumeno` for `dnf`/`yum`, `zypper --dry-run`. Nothing changes during the preview. The job page lists the packages to be updated, newly installed, removed and downgraded, the download size and whether a reboot will be needed. If anything would be removed or downgraded, the page also shows a warning. The update only starts after **Approve and start the update** is pressed. The approval is written to the audit log.

- The preview requirement can be turned off with **Settings → Updates → For updates started on a server page, show a preview first and update after approval** (on by default).
- Scheduled updates, rolling updates and jobs started through the API do not wait for a preview.
- Previews are only made by agents that announce the feature (1.0.0 and later) and for APT, DNF, YUM, Zypper and apk. Windows Update has no simulation mode, so on Windows servers and with older agents the update starts directly.
- A preview waiting for approval changes nothing. Even if the package list changed after the preview, the agent determines the targets again during the update and verifies the result.

### Health checks

On **Settings → Health checks** (administrators only) define extra checks that run before and after updates and at the monitoring interval. Every check applies to all servers, a group or a single server.

| Type | Check |
|---|---|
| HTTP/HTTPS | Does the address answer with the expected status code (optionally the expected text)? |
| TCP port | Is the connection accepted? |
| Service | Is the service running (systemd, OpenRC, Windows services)? |
| CPU, memory and disk | Are load, memory and disk use below the given limits? |
| Local command (health.d) | Does the script in the server's `health.d` folder exit with 0? |

- For security, local commands are only called by name; the panel cannot send a command line to the agent. The server's administrator puts the script into `/etc/netio-patchman/health.d/`. On Windows the folder is `C:\ProgramData\netio-patchman\health.d\` and `.ps1`, `.cmd`, `.bat` and `.exe` files are accepted. The file and the folder must be owned by root and must not be writable by group or others. Details in [installation.md](installation.md), section 4.6.
- In an update job the checks run first. If one fails, by default the update is not run and the job counts as failed. With **If a check fails before an update → Update anyway** the update runs regardless.
- After the update the checks run again once the configured delay (default 15 seconds) has passed. A check that passed before and fails afterwards is marked as **regressed**; the job counts as failed and a notification is sent.
- The results appear on the job page and on the **Health** tab of the server page. **Check now** on the server page runs the checks without updating.

#### Resource monitoring

Agents report CPU, memory, swap and the usage of all local disks on their own at a regular interval (default 5 minutes). No check has to be defined for this. CPU use is the average between two samples; on Linux the load average is shown too.

- **Server page:** the **Resource usage** section at the top of the **Health** tab shows:
  - Current values for CPU, memory, swap and every disk, with bars.
  - **Last 24 hours / Last 7 days / Last 30 days** charts: CPU, memory and the fullest disk.
  - The state of the built-in limits.
- **Server list:** the **Resources** column shows every server's current CPU, RAM and fullest disk. Values close to a limit are orange, values above it red. Samples older than 15 minutes (or three monitoring intervals) are not shown.
- **Built-in limits:** servers whose disk reaches 90 %, memory 95 % or CPU 90 % raise a warning on their own. Limits and the interval are changed under **Settings → Resource monitoring**; 0 turns a limit or the monitoring off.
- **Notifications:** a limit or check exceeded in two samples in a row is reported once; single-sample spikes do not create notifications. Recovery is reported too. In notification channels these belong to the **Health checks and resource warnings** event.
- **Extra checks:** website, port, service or script checks are optional. When defined they run at the same interval and their results appear in the **Extra checks (optional)** section. Every check has the option **Also run in the agents' monitoring rounds** (on by default).
- **History:** samples are kept for 30 days. The check history only records the moments a check changed from passing to failing (or back).
- Network file systems (NFS, CIFS) are not measured, because an unreachable share could block the measurement indefinitely. Use a local command check for them.
- **Agent version:** resource monitoring needs agent 1.0.2 or later. 1.0.1 agents did not send samples; with automatic agent updates on, agents upgrade on their own.

### Rollback

netio.patchman does not take disk or virtual machine snapshots. A rollback is done by the package manager installing the previous version:

1. In every update job the agent reports the package versions before and after the job. For older agents the inventory at the start of the job is stored. The **Package changes** section of the job page shows the difference.
2. Select the packages to roll back and press **Check whether the selected can be rolled back**. The check changes nothing: it looks whether the previous versions are available in the repositories and shows the package manager's simulation.
3. On the check page, **Approve and roll back** starts the rollback. If you want, the rolled-back packages are excluded from updates on this server, so the next update does not upgrade them again.
4. After the rollback the agent reads the versions again. Every package shows **Rolled back** or **Failed**. If some packages did not go back, the job becomes "Partially succeeded"; it is never shown as a success. Health checks, if defined, run after the rollback as well.

Limits: packages whose old version was removed from the repository cannot be rolled back. This usually happens with Ubuntu security repositories and repositories keeping a single version. Newly installed and removed packages are not part of a rollback. Alpine (apk) and Windows Update are not supported. A kernel rollback needs a reboot. Checks and rollbacks are written to the audit log.

## Rolling Updates

On the **Rolling Updates** page (operators and administrators) an update is applied to many servers in stages:

| Field | Description |
|---|---|
| Servers | Selected servers, a group or all servers. Order by server name or group order. |
| Canary servers | Servers updated in the first stage. 0 means no canary stage. |
| Servers per stage | Size of the following stages |
| Maximum parallel updates | Jobs running at the same time within a stage |
| Wait between stages (minutes) | Time to wait after a stage before the next one starts |
| Maximum failure rate (%) | The rollout stops on its own above this rate |
| Pause after the canary stage and wait for my approval | The rollout pauses after the canary and waits to be continued by hand |
| Count broken health checks as failures | Servers whose health checks regressed count toward the failure rate |

The rollout progresses in the background, in the server's maintenance loop (every minute), and continues if the page is closed. **Pause**, **Resume** and **Cancel** are written to the audit log. Cancelling a rollout cancels its jobs not yet sent to agents; started jobs finish. Notifications are sent when the failure rate is exceeded, while waiting after the canary and when the rollout ends. If a rollout stopped by the failure rate is resumed, the failures so far count as accepted and the rate is calculated anew for the remaining servers. Partially succeeded jobs and jobs that expired or timed out because the agent did not connect count as failures.

## Agents

- **Enrollment tokens:** used by new servers to register. A token is shown only when it is created. Giving it an expiry and a use limit is recommended. Revoking a token does not affect registered agents.
- **Agents:** agent versions, automatic and remote update settings, last connection. Agents on an old version carry the "Outdated" label.
- **Agent updates:** the agent version the server distributes and the number of outdated agents. With automatic updates on, agents update on their own; otherwise **Update outdated agents** starts an update for all of them.

## Notifications and e-mail

Notifications shows these events: new vulnerabilities, agents disconnecting and coming back, new server registrations, job results, scan and e-mail errors and new netio.patchman releases.

**New version:** when a newer netio.patchman release is published on GitHub, administrators see a notice at the top of every page. The **Update steps** link opens **Settings → Server configuration → Product version**, which shows the installed and published version, a link to the changes and the upgrade commands. Operators and viewers do not see this notice. If e-mail notifications are on, the new version is also announced by e-mail; the link in the e-mail opens the release notes. The check is turned off in the **Version check** section of the same page, the e-mail under **Settings → Email notifications**.

E-mail notifications are configured on the **Settings** page:

- **Minimum severity:** no e-mail is sent for vulnerabilities below this severity.
- **Exploited vulnerabilities:** an e-mail is sent for vulnerabilities in the KEV catalog regardless of severity.
- **Digest threshold:** if a scan finds many new vulnerabilities (e.g. on a newly added server), one summary is sent instead of an e-mail per vulnerability.
- **Recipients:** if empty, all active administrators receive the e-mails.

The SMTP server used to send e-mail is defined on **Settings → Server configuration**. That page also holds the server address, time zone, log level, the reverse proxy setting and the vulnerability data sources (OSV, CISA KEV). Changes apply without a restart. After saving you can send a test e-mail from the same page.

E-mails are written in the server's default language (`PATCHMAN_LOCALE`). Example subject in English:

```
[CRITICAL] CVE-2026-12345 - vulnerability detected on 12 servers
```

### Notification channels and integrations

On **Settings → Notification channels** (administrators only) the notifications can be sent to chat channels, your own systems, ticketing systems and Zabbix. Every channel has two filters:

- **Minimum level:** **Info** sends everything, **Warning** only warnings and critical ones, **Critical** only critical ones (critical vulnerabilities, KEV vulnerabilities, failed backups).
- **Events:** when one or more events are chosen, only these are sent and the level is ignored. This way, for example, the info-level "Update started" event can be subscribed for a channel. With none chosen, only the level applies.

| Event | When |
|---|---|
| Critical CVE | A critical vulnerability is newly detected |
| Actively exploited vulnerability (KEV) | A vulnerability from the KEV catalog is detected |
| Other new vulnerabilities | New vulnerabilities that are not critical and not in KEV |
| Software near or past end of life | Support is about to end or has ended |
| Update started / succeeded / failed or partial | An agent picked up an update job, and its result |
| Rollback done | A rollback finished |
| Reboot required | A server reports for the first time that it needs a reboot |
| Health checks and resource warnings | A check failed before or after an update, or a resource limit was exceeded |
| SLA exceeded | There are findings past their remediation time |
| Security score below threshold | A server's score dropped below the threshold |
| Server offline | An agent cannot be reached |
| Standard deviation | A new deviation from a server standard was found |
| Rolling update status | A rollout stopped, waits for approval or finished |
| Software inventory changed | Software was installed, removed or changed version |
| Other notifications | Backup errors, new versions, expired risk acceptances and others |

"Update started" and "Reboot required" happen often, so they are not stored in Notifications; they are only sent to channels subscribed to them.

| Type | What you need |
|---|---|
| Slack | An **Incoming Webhook** address for the channel (`https://hooks.slack.com/services/…`) |
| Microsoft Teams | The address created in the channel with **Workflows → "Post to a channel when a webhook request is received"**. Messages arrive as an Adaptive Card with an "Open in panel" button. |
| Telegram | The token of a bot created with @BotFather and the chat id (`-100…` for groups, `@channel_name` for channels). The bot must be a member of the group. |
| Webhook (JSON) | The address of your system. Body and signature format below. |
| Jira | Jira address, user (the e-mail address on Jira Cloud), API token (a personal access token on Jira Server), project key and issue type (default `Task`). Every notification opens an issue through REST API v2, labeled `netio.patchman` and with the event name. |
| ServiceNow | Instance address (`https://<instance>.service-now.com`), user, password and table (default `incident`). Records are created with the Table API; critical notifications get urgency 1, warnings 2, others 3. |
| GLPI | REST API root (`…/apirest.php`), the user's API token (user_token) and the API client's App-Token. For every notification a session is opened, a Ticket created and the session closed. |
| Zabbix (trapper) | Zabbix server or proxy (`address:port`, default port 10051), the host name in Zabbix and the item key (default `netio.patchman.event`). The notification is sent with the Zabbix sender protocol as a JSON value to a text item of type "Zabbix trapper". If Zabbix does not confirm it processed the value, the delivery counts as failed. |

**Webhook body:** every notification is POSTed as JSON with the fields `product`, `version`, `event_id`, `event` (the event id above, e.g. `update_failed`), `kind`, `level`, `title`, `text`, `link`, `url`, `params`, `created_at`. The headers carry `X-Netio-Patchman-Event` (notification kind) and `X-Netio-Patchman-Timestamp` (Unix seconds). If a signing secret is given:

- `X-Netio-Patchman-Signature: sha256=<hex>`: HMAC-SHA256 of the body (compatible with earlier versions)
- `X-Netio-Patchman-Signature-V2: t=<time>,sha256=<hex>`: HMAC-SHA256 of the text `<time>.<body>`. The receiver can verify the time as well (e.g. reject requests older than 5 minutes) to tell replayed old requests apart.

After adding a channel, check it with **Send test message**. A failed delivery is retried at most three times, after 5 seconds, 30 seconds and 2 minutes. One channel waiting for a retry does not delay the others. The error is shown in the channel list with the state "Error" and its message (no extra notification is created).

Click a channel name to open its page. There you change the event filter and see the **Delivery history**: the time, event, result, number of attempts, duration and error message of every delivery. An undelivered notification can be sent again with **Send again**. The delivery history is kept as long as notifications are.

Addresses, passwords, API tokens and bot tokens are secrets. After saving they are never shown in full and are removed from error messages. To change one, delete the channel and add it again. Channels can be stopped temporarily with **Disable**.

**Grafana, Prometheus and Netdata:** these systems pull data from netio.patchman. Prometheus reads `/metrics` (servers, vulnerabilities, updates, security score, EOL, deviations, rolling updates and channel state). Grafana builds dashboards from this Prometheus data. Netdata's Prometheus collector (`go.d/prometheus`) can read the same address. Details and example configurations in [api.en.md](api.en.md).

## Automatic backup

Under **Settings → Automatic backup** set the daily backup time and the number of backups to keep (default every day at 02:30, 7 backups). The **Backups** list at the bottom of the same page shows the backups taken, their size and **Download** links; **Back up now** takes a backup immediately. A failed backup appears in Notifications as a critical warning and is e-mailed. To keep backups outside the server and to restore them, see [installation.md](installation.md), section 5.

## Interface language

The interface is available in Turkish, English, German and Russian. Pick the language with the **Türkçe · Deutsch · English · Русский** links under the sign-in form or with **My Profile → Interface language**. A language saved in the profile also applies when signing in from another device. The language only affects your panel: e-mails, chat channel messages and system logs use the server's default language. Notifications are shown in the language you chose. In the English interface dates are written `2026-11-21` and CSV files use `,`; German and Russian use `21.11.2026` and `;` as Turkish does.

## Audit log

The **Compliance & Audit → Audit History → Audit Log** tab (administrators) lists sign-ins, failed sign-in attempts, user and settings changes, started jobs, enrollment token actions and server removals, with user and IP address. Group changes, enabling and disabling two-step verification, wrong verification codes and expired risk acceptances are recorded as well.

## Two-step verification

Every user can turn on two-step verification on the **My Profile** page:

1. Press **Set up an authenticator app**.
2. In the authenticator app on your phone (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP, 1Password, etc.) add a new account and enter the setup key shown. If the panel is open on the phone, the **open in app** link passes the key to the app directly.
3. Enter the 6-digit code the app shows and your password, then press **Verify and turn on**.

When it is on, **10 recovery codes** are shown once. Each can be used once to sign in when the phone is not available; keep them in a safe place. Recovery codes can be renewed on the same page; this needs the password and a valid code and invalidates the old codes.

After the password, the sign-in asks for the code. The code changes every 30 seconds; a phone clock drift of ±30 seconds is tolerated. A used code is not accepted a second time. After five wrong codes the sign-in has to start over.

**Enforcing it:** an administrator can turn on **Settings → Security → Require two-factor authentication for all users**. Users without an authenticator can then only open their My Profile page until they set one up. While it is required, users cannot turn verification off.

**Lost phone:** an administrator removes the user's authenticator with **Users → user → Reset two-factor authentication**; the user's open sessions end. If the administrator is locked out, use the command `netio-patchman-server reset-mfa -email <address>` on the server (see [installation.md](installation.md)).

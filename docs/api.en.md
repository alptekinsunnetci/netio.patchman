# netio.patchman REST API and Prometheus

🇬🇧 **English** · 🇹🇷 [Türkçe](api.md) · ⏱️ Reading time: about 9 minutes

Use the API to read host, vulnerability, update and job data from scripts, Ansible or monitoring systems, and to start
update jobs. Back to the [README](../README.md).

## Authentication

1. In the panel, create a key under **My Profile → API keys**. The key is shown only once and starts with `npat_`.
2. Send it with every request:

   ```
   Authorization: Bearer npat_...
   ```

- A key works with the **role** and the **host access** of the user who created it. The key of a user limited to some
  groups only sees the hosts of those groups.
- **Read-only** keys (the default) cannot change anything. To start update jobs, tick **Allow starting update jobs (write)**
  when you create the key; only operators and administrators have this option.
- The validity is given in days (0 = no expiry). Revoke a key on the My Profile page; when a user is deleted or disabled,
  their keys stop working too.
- Only the SHA-256 hash of the key is stored. Requests that start jobs are written to the audit log with the key's name
  (`api_token=<name>`).
- The API does not accept cookies; a browser session is not valid for the API.
- Failed keys are rate-limited per IP address (`429` after repeated failures).

## Response format

- JSON, UTF-8. Field names are English and stay stable across versions.
- Times are UTC, RFC 3339 (`2026-11-21T10:15:00Z`); unknown times are `null`.
- CVE titles, package names and versions are returned exactly as their source publishes them.
- Lists are paginated (50 records per page): `?page=2`. Responses contain `pagination: {page, page_size, total}`.
- Errors: `{"code": "...", "message": "..."}`. Codes: `unauthorized` (401), `forbidden` (403), `not_found` (404),
  `bad_request` (400), `rate_limited` (429), `job_rejected` (409), `internal` (500). `message` is in the server's
  default language.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/hosts` | Hosts. Filters: `q` (name, IP, operating system), `status` (`online`, `offline`, `reboot`, `vulnerable`, `updates`), `os` (e.g. `ubuntu`, `windows`), `group` (group id), `platform` (`virtual`, `physical`, `vmware`…) |
| GET | `/api/v1/hosts/{id}` | One host |
| GET | `/api/v1/hosts/{id}/findings` | The host's vulnerability findings. Filters: `status` (empty = open and in progress, `all`, `resolved`, `accepted_risk`…), `severity`, `kev=1`, `overdue=1` |
| GET | `/api/v1/hosts/{id}/updates` | Pending updates; every record has `excluded` (on the never-update list) and the response contains the effective `exclude` list |
| POST | `/api/v1/hosts/{id}/jobs` | Starts an update job (key with write permission). Body: `{"type": "...", "packages": [...]}` |
| GET | `/api/v1/vulnerabilities` | Vulnerabilities in the fleet (one per CVE). Filters: `q`, `severity`, `status`, `kev=1`, `fix=1`, `overdue=1`, `sort=epss` (KEV first, then EPSS) |
| GET | `/api/v1/vulnerabilities/{cve}` | Vulnerability details (official title, description, CVSS, EPSS, KEV, advisories) and affected hosts |
| GET | `/api/v1/groups` | Server groups |
| GET | `/api/v1/jobs` | Jobs, newest first. Filters: `host` (host id), `status` |
| GET | `/api/v1/jobs/{id}` | Job details and command output |
| GET | `/api/v1/hosts/{id}/software` | Recognized software on the host (product, release series, version, package, service state) and the service list (`services_known` false: the agent does not report services) |
| GET | `/api/v1/software` | Software in the fleet. Filters: `software` (product id, e.g. `nginx`, `php`), `cycle` (e.g. `8.2`) |
| GET | `/api/v1/eol` | Support status of operating systems and software (`status`: `supported`, `soon`, `eol`, `unknown`; `distro_supported`: the distribution still maintains it) |
| GET | `/api/v1/hosts/{id}/score` | Security score (`score`, `band`), total deduction and details per criterion (`categories`). `score: null` before the first computation |
| GET | `/api/v1/hosts/{id}/health` | Resource monitoring: current state of the checks and built-in limits (`checks`: `key`, `name`, `type`, `builtin`, `ok`, `value`, `since`, `checked_at`), number failing (`failing`) and the latest resource sample (`resources`: `cpus`, `cpu_percent` (average over the sampling interval, agent 1.0.2+), `load`, `memory_total`, `memory_available`, `swap_total`, `swap_free`, `disks[]` in bytes; `resources_at`) |
| GET | `/api/v1/drift` | Deviations from server standards. Filters: `standard`, `host`, `group`. Every record has the rule (`kind`, `subject_type`, `subject`, `expected`), what was found (`found`), `first_seen` and, if any, a suggested update (`suggested_update`) |
| GET | `/api/v1/rollouts` | Rolling updates, newest first: status, stage, host counts (`hosts.total`, `succeeded`, `failed`…). Closed to group-limited keys (`403`) |
| GET | `/api/v1/compliance/reports` | Compliance reports: title, frameworks (`profiles`, e.g. `isms@1`), period (`period_from`, `period_to` exclusive), scope (`group_id`, `platforms`), number of versions, latest version and its status (`draft`, `final`). Group-limited keys only see reports of their groups |
| GET | `/api/v1/compliance/reports/{id}/versions/{n}` | JSON export of a report version (`netio.patchman/compliance-export/v1`): version data and hashes, the stored report content (`report`), the automated outcome and manual review per control (`assessments`), every piece of evidence used with its hash and mapped controls (`evidence`). `n` = 0 is the latest version |
| GET | `/api/v1/compliance/evidence` | Evidence repository, newest first. Filters: `kind` (`update_job`, `change_job`, `vuln_resolved`, `audit_event`, `drift_detected`, `backup_result`, `inventory_snapshot`, `manual`), `platform` (`linux`, `windows_server`, `windows_10`, `windows_11`, `windows_other`), `q`, `from`, `to` (`YYYY-MM-DD`), `version` (report version id) and `control` (`profile:CONTROL`). Every record carries `sha256` and the previous item's `prev_sha256`. Audit log items (`audit_event`) are only shown to administrator keys |
| GET | `/metrics` | Prometheus metrics |

Host records also contain `security_score` (`null` before the first computation) and the capabilities the agent reported
(`capabilities`: `services`, `health`, `preview`, `rollback`).

### Job types

| `type` | Meaning |
|---|---|
| `refresh` | Refresh the inventory now |
| `upgrade_security` | Install security updates |
| `upgrade_all` | Install all updates |
| `upgrade_packages` | Update the packages in `packages` (KB numbers or winget ids on Windows) |
| `restart_services` | Restart the services in `packages` |
| `reboot` | Reboot the host after one minute |
| `agent_update` | Update the agent to the version the server distributes |
| `health_check` | Run the health checks that apply to the host without updating (works even with remote updates off; needs the agent's `health` capability and at least one check) |

Updates started through the API do not wait for a preview (dry-run) approval. When health checks are defined they run
before and after update jobs; the results are on the job page.

Jobs are created with the same rules as in the panel: package jobs are rejected on hosts with remote updates turned off,
excluded packages are skipped, and no new reboot is queued while one of the same kind is pending. A rejected job answers
`409` with `{"code": "job_rejected", "message": "..."}`. Success answers `201` with the job itself; follow its status with
`/api/v1/jobs/{id}` (`queued` → `dispatched` → `succeeded` / `partial` / `failed`).

### Examples

```sh
KEY=npat_...
BASE=https://patchman.your-domain

# Hosts with open findings
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/hosts?status=vulnerable"

# Overdue vulnerabilities, most likely to be exploited first
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/vulnerabilities?overdue=1&sort=epss"

# Start security updates on a host
curl -s -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"type":"upgrade_security"}' "$BASE/api/v1/hosts/12/jobs"

# Download the latest version of a compliance report as JSON
curl -s -H "Authorization: Bearer $KEY" "$BASE/api/v1/compliance/reports/3/versions/0" -o report.json

# Update specific packages
curl -s -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"type":"upgrade_packages","packages":["openssl","libssl3"]}' "$BASE/api/v1/hosts/12/jobs"
```

Example host record:

```json
{
  "id": 12,
  "hostname": "web-01",
  "os_id": "ubuntu",
  "os_name": "Ubuntu 24.04.1 LTS",
  "kernel": "6.8.0-45-generic",
  "online": true,
  "reboot_required": false,
  "kernel_patch": "livepatch",
  "groups": ["Production"],
  "updates": 14,
  "security_updates": 3,
  "vulnerabilities": {"critical": 1, "high": 4, "medium": 9, "low": 2, "other": 0}
}
```

## Prometheus

`/metrics` uses the Prometheus text format and is protected by the same API keys. The key of a group-limited user only
returns metrics of that user's hosts.

```yaml
scrape_configs:
  - job_name: netio-patchman
    scheme: https
    scrape_interval: 60s
    authorization:
      credentials: npat_...
    static_configs:
      - targets: ["patchman.your-domain"]
```

| Metric | Labels | Description |
|---|---|---|
| `netio_patchman_info` | `version`, `codename` | Server version and the release name of its major version (value 1) |
| `netio_patchman_hosts` | `state` (`online`, `offline`, `never_seen`) | Number of hosts |
| `netio_patchman_hosts_reboot_required` | — | Hosts waiting for a reboot |
| `netio_patchman_vulnerabilities` | `severity` | Distinct CVEs with open findings |
| `netio_patchman_vulnerabilities_known_exploited` | — | Open CVEs listed in CISA KEV |
| `netio_patchman_findings_overdue` | — | Findings past their remediation target (SLA) |
| `netio_patchman_updates_pending` | `kind` (`all`, `security`) | Pending updates |
| `netio_patchman_jobs_last_24h` | `status` | Jobs created in the last 24 hours |
| `netio_patchman_scan_last_run_timestamp_seconds` | — | Time of the last scan |
| `netio_patchman_host_up` | `host`, `os` | 1 if the agent connected within the offline threshold |
| `netio_patchman_host_vulnerabilities` | `host`, `os`, `severity` | Open CVEs on the host |
| `netio_patchman_host_updates_pending` | `host`, `os`, `kind` | Pending updates on the host |
| `netio_patchman_host_reboot_required` | `host`, `os` | 1 if the host waits for a reboot |
| `netio_patchman_host_health_failing` | `host`, `os` | Monitored checks and built-in limits currently failing on the host |
| `netio_patchman_host_cpu_used_percent` | `host`, `os` | CPU use (average over the sampling interval) |
| `netio_patchman_host_memory_used_percent` | `host`, `os` | Memory use (total minus available) |
| `netio_patchman_host_load_per_cpu_percent` | `host`, `os` | 1-minute load average divided by the number of cores (Linux) |
| `netio_patchman_host_disk_used_percent` | `host`, `os`, `path` | File system usage (as `df` shows it). Resource metrics are only written for fresh samples (last 3 monitoring intervals, at least 15 minutes), so stale values of a disconnected host do not raise alerts. |
| `netio_patchman_security_score` | `stat` (`avg`, `min`) | Average and lowest security score of the fleet (not written while no host has a score) |
| `netio_patchman_eol` | `kind` (`os`, `software`), `status` (`eol`, `soon`, `eol_distro_maintained`) | Operating systems (hosts) and software installations out of or near the end of support |
| `netio_patchman_drift_deviations` | — | Open deviations from server standards |
| `netio_patchman_rollouts` | `status` (`running`, `paused`, `failed`) | Rolling updates (unlimited keys only) |
| `netio_patchman_channel_failing` | `channel`, `type` | 1 if the last delivery to an enabled notification channel failed (unlimited keys only) |

Example alerting rules:

```yaml
groups:
  - name: netio-patchman
    rules:
      - alert: CriticalVulnerability
        expr: netio_patchman_host_vulnerabilities{severity="critical"} > 0
        for: 1h
      - alert: AgentNotConnected
        expr: netio_patchman_host_up == 0
        for: 30m
      - alert: RemediationOverdue
        expr: netio_patchman_findings_overdue > 0
      - alert: DiskFilling
        expr: netio_patchman_host_disk_used_percent > 90
        for: 15m
      - alert: LowSecurityScore
        expr: netio_patchman_security_score{stat="min"} < 50
        for: 1h
      - alert: RollingUpdateStopped
        expr: netio_patchman_rollouts{status="failed"} > 0
      - alert: NotificationChannelFailing
        expr: netio_patchman_channel_failing == 1
        for: 15m
```

## Grafana, Netdata and Zabbix

- **Grafana:** add the Prometheus data above as a data source. Useful panels: `netio_patchman_security_score`,
  `sum by (severity) (netio_patchman_host_vulnerabilities)`, `netio_patchman_updates_pending`, `netio_patchman_eol`.
  For a per-host table, show `netio_patchman_host_vulnerabilities{severity="critical"}` by the `host` label.
- **Netdata:** the `go.d` Prometheus collector can read `/metrics` (`/etc/netdata/go.d/prometheus.conf`):

  ```yaml
  jobs:
    - name: netio_patchman
      url: https://patchman.your-domain/metrics
      update_every: 60
      headers:
        Authorization: Bearer npat_...
  ```

- **Zabbix:** there are two ways. For events, add a **Zabbix (trapper)** channel on **Settings → Notification channels**.
  In Zabbix, create a host with the host name given in the channel and a text item of type "Zabbix trapper" with the same
  key. The value is JSON (`event`, `kind`, `level`, `title`, `text`, `url`, `params`, `time`); triggers can use it, e.g.
  `find(/patchman/netio.patchman.event,,"like","\"event\":\"update_failed\"")=1`. For state metrics, the HTTP agent item
  of Zabbix 6.0 and later can read `/metrics` with the `Authorization: Bearer npat_...` header, then pick the metric
  with the "Prometheus pattern" preprocessing step.

## Webhooks and ticketing systems

Notification channels forward events to other systems (webhook, Jira, ServiceNow, GLPI, Zabbix, Slack, Teams, Telegram);
for the fields, the event list and signature verification see [usage.md](usage.md), "Notification channels and
integrations". Verifying the webhook signature (Python):

```python
import hashlib, hmac, time

def verify(secret: bytes, body: bytes, header: str, max_age=300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    ts = parts["t"]
    if abs(time.time() - int(ts)) > max_age:
        return False
    expected = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts["sha256"])

# header: the value of the X-Netio-Patchman-Signature-V2 header
```

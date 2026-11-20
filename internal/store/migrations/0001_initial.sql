-- netio.patchman initial schema. All timestamps are UTC unix seconds.

CREATE TABLE users (
    id                  INTEGER PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name                TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    disabled            INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    last_login_at       INTEGER NOT NULL DEFAULT 0,
    password_changed_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE enrollment_tokens (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL DEFAULT 0,
    max_uses     INTEGER NOT NULL DEFAULT 0,
    uses         INTEGER NOT NULL DEFAULT 0,
    revoked_at   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE hosts (
    id                INTEGER PRIMARY KEY,
    machine_id        TEXT NOT NULL DEFAULT '',
    hostname          TEXT NOT NULL,
    fqdn              TEXT NOT NULL DEFAULT '',
    os_id             TEXT NOT NULL DEFAULT '',
    os_version_id     TEXT NOT NULL DEFAULT '',
    os_name           TEXT NOT NULL DEFAULT '',
    os_version        TEXT NOT NULL DEFAULT '',
    kernel            TEXT NOT NULL DEFAULT '',
    arch              TEXT NOT NULL DEFAULT '',
    ip_addresses      TEXT NOT NULL DEFAULT '[]',
    package_manager   TEXT NOT NULL DEFAULT '',
    ecosystem         TEXT NOT NULL DEFAULT '',
    agent_version     TEXT NOT NULL DEFAULT '',
    remote_updates    INTEGER NOT NULL DEFAULT 0,
    reboot_required   INTEGER NOT NULL DEFAULT 0,
    uptime_seconds    INTEGER NOT NULL DEFAULT 0,
    agent_secret_hash TEXT NOT NULL UNIQUE,
    enrolled_at       INTEGER NOT NULL,
    enrollment_token  INTEGER REFERENCES enrollment_tokens(id) ON DELETE SET NULL,
    last_seen_at      INTEGER NOT NULL DEFAULT 0,
    last_report_at    INTEGER NOT NULL DEFAULT 0,
    last_scan_at      INTEGER NOT NULL DEFAULT 0,
    needs_scan        INTEGER NOT NULL DEFAULT 0,
    report_errors     TEXT NOT NULL DEFAULT '[]',
    offline_notified  INTEGER NOT NULL DEFAULT 0,
    notes             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX hosts_machine ON hosts(machine_id);
CREATE INDEX hosts_needs_scan ON hosts(needs_scan);

CREATE TABLE host_packages (
    host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    arch           TEXT NOT NULL DEFAULT '',
    version        TEXT NOT NULL,
    source_name    TEXT NOT NULL DEFAULT '',
    source_version TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (host_id, name, arch)
) WITHOUT ROWID;
CREATE INDEX host_packages_name ON host_packages(name);

CREATE TABLE host_updates (
    host_id           INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    current_version   TEXT NOT NULL DEFAULT '',
    available_version TEXT NOT NULL,
    repository        TEXT NOT NULL DEFAULT '',
    security          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, name)
) WITHOUT ROWID;
CREATE INDEX host_updates_name ON host_updates(name);

-- Cached OSV query results per (ecosystem, package, version).
CREATE TABLE osv_queries (
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    record_ids TEXT NOT NULL,
    checked_at INTEGER NOT NULL,
    PRIMARY KEY (ecosystem, name, version)
) WITHOUT ROWID;

-- Cached raw OSV records, verbatim JSON.
CREATE TABLE osv_records (
    id         TEXT PRIMARY KEY,
    modified   TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    data       TEXT NOT NULL
);

-- Vulnerability text fields are stored verbatim from the source.
CREATE TABLE vulnerabilities (
    cve_id           TEXT PRIMARY KEY,
    title            TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    description_lang TEXT NOT NULL DEFAULT 'en',
    cvss_score       REAL,
    cvss_vector      TEXT NOT NULL DEFAULT '',
    cvss_version     TEXT NOT NULL DEFAULT '',
    severity         TEXT NOT NULL DEFAULT 'unknown',
    published_at     INTEGER NOT NULL DEFAULT 0,
    modified_at      INTEGER NOT NULL DEFAULT 0,
    fetched_at       INTEGER NOT NULL DEFAULT 0,
    source           TEXT NOT NULL DEFAULT '',
    refs             TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX vulnerabilities_severity ON vulnerabilities(severity);

-- CISA Known Exploited Vulnerabilities catalog, values verbatim.
CREATE TABLE kev (
    cve_id     TEXT PRIMARY KEY,
    date_added TEXT NOT NULL DEFAULT '',
    due_date   TEXT NOT NULL DEFAULT '',
    ransomware TEXT NOT NULL DEFAULT ''
);

CREATE TABLE advisories (
    id     TEXT PRIMARY KEY,
    title  TEXT NOT NULL DEFAULT '',
    url    TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT ''
);

CREATE TABLE vulnerability_advisories (
    cve_id      TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, advisory_id)
) WITHOUT ROWID;

CREATE TABLE findings (
    id                INTEGER PRIMARY KEY,
    host_id           INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cve_id            TEXT NOT NULL,
    package_name      TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version     TEXT NOT NULL DEFAULT '',
    record_id         TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'open',
    status_note       TEXT NOT NULL DEFAULT '',
    status_changed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    first_detected_at INTEGER NOT NULL,
    last_checked_at   INTEGER NOT NULL,
    resolved_at       INTEGER NOT NULL DEFAULT 0,
    notified          INTEGER NOT NULL DEFAULT 0,
    UNIQUE (host_id, cve_id, package_name)
);
CREATE INDEX findings_cve ON findings(cve_id);
CREATE INDEX findings_status ON findings(status);

CREATE TABLE jobs (
    id            INTEGER PRIMARY KEY,
    host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    type          TEXT NOT NULL,
    packages      TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'queued',
    created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at    INTEGER NOT NULL,
    dispatched_at INTEGER NOT NULL DEFAULT 0,
    finished_at   INTEGER NOT NULL DEFAULT 0,
    exit_code     INTEGER NOT NULL DEFAULT 0,
    output        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX jobs_host_status ON jobs(host_id, status);

-- In-app notifications. Text is rendered from (kind, params) at display time
-- so that notifications follow the UI language.
CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY,
    created_at INTEGER NOT NULL,
    level      TEXT NOT NULL,
    kind       TEXT NOT NULL,
    params     TEXT NOT NULL DEFAULT '{}',
    link       TEXT NOT NULL DEFAULT '',
    read_at    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX notifications_read ON notifications(read_at);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL,
    user_id    INTEGER,
    user_email TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    details    TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at ON audit_log(at);

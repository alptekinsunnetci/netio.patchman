-- Release a derivative distribution is built on ("ubuntu:jammy").
ALTER TABLE hosts ADD COLUMN upstream TEXT NOT NULL DEFAULT '';

-- Live kernel patching reported by the agent (KernelCare, Canonical Livepatch).
ALTER TABLE hosts ADD COLUMN kernel_patch TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN kernel_effective TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN livepatch_cves TEXT NOT NULL DEFAULT '[]';

-- Package name patterns no job updates (comma separated), per host and group.
-- The fleet-wide list is the setting updates.exclude.
ALTER TABLE hosts ADD COLUMN exclude_packages TEXT NOT NULL DEFAULT '';
ALTER TABLE host_groups ADD COLUMN exclude_packages TEXT NOT NULL DEFAULT '';

-- Remediation targets (SLA): when the overdue notice of a finding was sent.
ALTER TABLE findings ADD COLUMN sla_notified_at INTEGER NOT NULL DEFAULT 0;

-- EPSS (FIRST.org): probability of exploitation in the next 30 days.
CREATE TABLE epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL NOT NULL
) WITHOUT ROWID;

-- Schedules may reboot hosts that need it after their update job (opt-in),
-- within the maintenance window. reboot_job_id links the update job to the
-- reboot job queued after it.
ALTER TABLE schedules ADD COLUMN reboot INTEGER NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN reboot_job_id INTEGER NOT NULL DEFAULT 0;

-- Operators and viewers limited to the hosts of some groups. group_scoped
-- marks a limited user; with no groups left such a user sees no hosts.
ALTER TABLE users ADD COLUMN group_scoped INTEGER NOT NULL DEFAULT 0;
CREATE TABLE user_groups (
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES host_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
) WITHOUT ROWID;

-- The host a notification concerns (0 = none), so limited users only see
-- notifications about their hosts.
ALTER TABLE notifications ADD COLUMN host_id INTEGER NOT NULL DEFAULT 0;

-- API tokens act as their user. Only the SHA-256 hash is stored.
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    read_only    INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER NOT NULL DEFAULT 0,
    revoked_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX api_tokens_user ON api_tokens(user_id);

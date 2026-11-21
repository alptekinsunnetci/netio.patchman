-- Host groups, two-factor authentication, time-limited risk acceptance,
-- daily trend snapshots, virtualization platform and reboot-pending time.

CREATE TABLE host_groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);

CREATE TABLE host_group_members (
    group_id INTEGER NOT NULL REFERENCES host_groups(id) ON DELETE CASCADE,
    host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, host_id)
) WITHOUT ROWID;
CREATE INDEX host_group_members_host ON host_group_members(host_id);

-- A schedule with group_id targets the members of that group (target 'all').
ALTER TABLE schedules ADD COLUMN group_id INTEGER REFERENCES host_groups(id) ON DELETE SET NULL;

-- TOTP (RFC 6238). totp_secret is the base32 key, totp_last_step the last
-- accepted time step (replay protection). Recovery codes are stored hashed.
ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
CREATE TABLE user_recovery_codes (
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
) WITHOUT ROWID;

-- Accepted risks may expire; the finding then becomes open again.
ALTER TABLE findings ADD COLUMN status_expires_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX findings_status_expires ON findings(status, status_expires_at);

-- One row per UTC day with the fleet state at the last snapshot of that day.
CREATE TABLE daily_snapshots (
    day              INTEGER PRIMARY KEY,
    hosts            INTEGER NOT NULL,
    critical         INTEGER NOT NULL,
    high             INTEGER NOT NULL,
    medium           INTEGER NOT NULL,
    low              INTEGER NOT NULL,
    other            INTEGER NOT NULL,
    kev              INTEGER NOT NULL,
    open_findings    INTEGER NOT NULL,
    security_updates INTEGER NOT NULL,
    reboot_required  INTEGER NOT NULL,
    taken_at         INTEGER NOT NULL
);

-- systemd-detect-virt style platform id reported by the agent ('' unknown).
ALTER TABLE hosts ADD COLUMN virtualization TEXT NOT NULL DEFAULT '';
-- Since when the host has been waiting for a reboot (0 = not pending).
ALTER TABLE hosts ADD COLUMN reboot_required_since INTEGER NOT NULL DEFAULT 0;
UPDATE hosts SET reboot_required_since = last_report_at WHERE reboot_required = 1;

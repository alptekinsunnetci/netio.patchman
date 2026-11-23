-- Continuous monitoring: agents run the checks on an interval and report
-- resource usage. monitor: the check also runs in these rounds.
ALTER TABLE health_checks ADD COLUMN monitor INTEGER NOT NULL DEFAULT 1;

-- Latest resource snapshot of a host (protocol.Resources as JSON).
ALTER TABLE hosts ADD COLUMN resources TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN resources_at INTEGER NOT NULL DEFAULT 0;

-- Current state of each monitored check on a host. check_key: 'c<id>' for a
-- defined check, 'disk:<path>', 'memory' or 'cpu' for the built-in limits.
-- fails counts consecutive failures; notified: a failure was notified and
-- the recovery will be.
CREATE TABLE host_health_state (
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    check_key  TEXT NOT NULL,
    check_id   INTEGER NOT NULL DEFAULT 0,
    check_name TEXT NOT NULL DEFAULT '',
    check_type TEXT NOT NULL,
    ok         INTEGER NOT NULL,
    value      TEXT NOT NULL DEFAULT '',
    message    TEXT NOT NULL DEFAULT '',
    fails      INTEGER NOT NULL DEFAULT 0,
    notified   INTEGER NOT NULL DEFAULT 0,
    since      INTEGER NOT NULL,
    checked_at INTEGER NOT NULL,
    PRIMARY KEY (host_id, check_key)
);

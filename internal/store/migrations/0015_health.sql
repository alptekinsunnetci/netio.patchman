-- Health check definitions. scope: 'all' hosts, one 'group' or one 'host'.
-- with_updates: run before and after update jobs (always available for a
-- manual check).
CREATE TABLE health_checks (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    target          TEXT NOT NULL DEFAULT '',
    expect          INTEGER NOT NULL DEFAULT 0,
    contains        TEXT NOT NULL DEFAULT '',
    insecure        INTEGER NOT NULL DEFAULT 0,
    cpu             INTEGER NOT NULL DEFAULT 0,
    memory          INTEGER NOT NULL DEFAULT 0,
    disk            INTEGER NOT NULL DEFAULT 0,
    paths           TEXT NOT NULL DEFAULT '[]',
    timeout_seconds INTEGER NOT NULL DEFAULT 10,
    scope           TEXT NOT NULL DEFAULT 'all',
    group_id        INTEGER REFERENCES host_groups(id) ON DELETE CASCADE,
    host_id         INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    with_updates    INTEGER NOT NULL DEFAULT 1,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL
);

-- Health check results per host: phase 'before'/'after' an update job,
-- 'check' for a manual or standalone run.
CREATE TABLE health_results (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    job_id      INTEGER NOT NULL DEFAULT 0,
    check_id    INTEGER NOT NULL DEFAULT 0,
    check_name  TEXT NOT NULL,
    check_type  TEXT NOT NULL,
    phase       TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    value       TEXT NOT NULL DEFAULT '',
    message     TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
CREATE INDEX health_results_host ON health_results(host_id, created_at);
CREATE INDEX health_results_job ON health_results(job_id);

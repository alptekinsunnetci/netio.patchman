-- Scheduled update rules (maintenance windows). days is a weekday bitmask
-- (bit 0 = Sunday ... bit 6 = Saturday); minute is minutes after midnight in
-- the server's display time zone. Jobs created by a schedule expire if the
-- agent does not pick them up before the window ends.
CREATE TABLE schedules (
    id             INTEGER PRIMARY KEY,
    name           TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    job_type       TEXT NOT NULL,
    days           INTEGER NOT NULL,
    minute         INTEGER NOT NULL,
    window_minutes INTEGER NOT NULL,
    target         TEXT NOT NULL CHECK (target IN ('all', 'os', 'hosts')),
    os_id          TEXT NOT NULL DEFAULT '',
    next_run_at    INTEGER NOT NULL DEFAULT 0,
    last_run_at    INTEGER NOT NULL DEFAULT 0,
    last_queued    INTEGER NOT NULL DEFAULT 0,
    last_skipped   INTEGER NOT NULL DEFAULT 0,
    created_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
);
CREATE INDEX schedules_due ON schedules(enabled, next_run_at);

CREATE TABLE schedule_hosts (
    schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (schedule_id, host_id)
);

ALTER TABLE jobs ADD COLUMN schedule_id INTEGER REFERENCES schedules(id) ON DELETE SET NULL;
ALTER TABLE jobs ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX jobs_status_expires ON jobs(status, expires_at);

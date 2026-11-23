-- Rolling updates: one package job type over many hosts in stages (an
-- optional canary first, then batches or groups), stopped automatically
-- when too many fail. status: running, paused, completed, failed, cancelled.
CREATE TABLE rollouts (
    id                    INTEGER PRIMARY KEY,
    name                  TEXT NOT NULL,
    job_type              TEXT NOT NULL,
    packages              TEXT NOT NULL DEFAULT '[]',
    status                TEXT NOT NULL,
    stages                INTEGER NOT NULL,
    current_stage         INTEGER NOT NULL DEFAULT 0,
    canary                INTEGER NOT NULL DEFAULT 0,
    max_parallel          INTEGER NOT NULL,
    wait_minutes          INTEGER NOT NULL DEFAULT 0,
    max_failure_pct       INTEGER NOT NULL DEFAULT 0,
    require_health        INTEGER NOT NULL DEFAULT 1,
    pause_after_canary    INTEGER NOT NULL DEFAULT 0,
    job_timeout_minutes   INTEGER NOT NULL DEFAULT 120,
    stage_finished_at     INTEGER NOT NULL DEFAULT 0,
    -- failures (and finished hosts) already accepted by resuming after a stop
    accepted_failures     INTEGER NOT NULL DEFAULT 0,
    accepted_processed    INTEGER NOT NULL DEFAULT 0,
    reason                TEXT NOT NULL DEFAULT '',
    created_by            INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at            INTEGER NOT NULL,
    finished_at           INTEGER NOT NULL DEFAULT 0
);

-- Hosts of a rollout with their stage and order; status: pending, queued,
-- succeeded, failed, skipped.
CREATE TABLE rollout_hosts (
    rollout_id INTEGER NOT NULL REFERENCES rollouts(id) ON DELETE CASCADE,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    stage      INTEGER NOT NULL,
    position   INTEGER NOT NULL,
    job_id     INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'pending',
    note       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (rollout_id, host_id)
) WITHOUT ROWID;
CREATE INDEX rollout_hosts_stage ON rollout_hosts(rollout_id, stage, position);

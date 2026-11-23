-- The host's package inventory when a package job was dispatched (gzip,
-- base64 JSON): what a rollback returns to when the agent reported no
-- changes itself. Deleted with the job.
CREATE TABLE job_inventory (
    job_id     BIGINT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE DEFERRABLE,
    host_id    BIGINT NOT NULL,
    data       TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

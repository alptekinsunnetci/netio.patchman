-- Optional agent features (protocol.Cap*), JSON array; empty for agents
-- before 0.10.0, which only get the job types they know.
ALTER TABLE hosts ADD COLUMN capabilities TEXT NOT NULL DEFAULT '[]';

-- Structured job results (health checks, dry-run plan, package changes,
-- rollback outcome) as JSON, next to the plain output.
ALTER TABLE jobs ADD COLUMN result TEXT NOT NULL DEFAULT '';

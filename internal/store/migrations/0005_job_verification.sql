-- Job verification and service restarts.
-- jobs.remaining: packages (or services) a job targeted that were still pending after it ran.
-- hosts.restart_services: services still running code replaced by an update.
ALTER TABLE jobs ADD COLUMN remaining TEXT NOT NULL DEFAULT '[]';
ALTER TABLE hosts ADD COLUMN restart_services TEXT NOT NULL DEFAULT '[]';

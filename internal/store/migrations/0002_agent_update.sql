-- Agent self-update: job parameters and the agent's self-update capability.
ALTER TABLE jobs ADD COLUMN params TEXT NOT NULL DEFAULT '{}';
ALTER TABLE hosts ADD COLUMN self_update INTEGER NOT NULL DEFAULT 0;
CREATE INDEX jobs_type_status ON jobs(type, status);

-- Security score per host (0-100, -1 = not computed yet), its explanation
-- (JSON, see package score) and whether the below-threshold notice was sent.
ALTER TABLE hosts ADD COLUMN security_score INTEGER NOT NULL DEFAULT -1;
ALTER TABLE hosts ADD COLUMN score_detail TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN score_alerted INTEGER NOT NULL DEFAULT 0;

-- Daily score per host (the latest computation of the UTC day).
CREATE TABLE host_scores (
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    day     INTEGER NOT NULL,
    score   INTEGER NOT NULL,
    PRIMARY KEY (host_id, day)
) WITHOUT ROWID;

-- Fleet average score of the day in the trend snapshot (-1 = none).
ALTER TABLE daily_snapshots ADD COLUMN security_score INTEGER NOT NULL DEFAULT -1;

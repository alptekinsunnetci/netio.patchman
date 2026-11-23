-- Resource history of a host: one row per monitoring round. Percentages are
-- stored in tenths (853 = 85.3%), -1 when unknown. disk is the fullest file
-- system. Kept for 30 days.
CREATE TABLE host_metrics (
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    at      INTEGER NOT NULL,
    cpu     INTEGER NOT NULL DEFAULT -1,
    load    INTEGER NOT NULL DEFAULT -1,
    memory  INTEGER NOT NULL DEFAULT -1,
    swap    INTEGER NOT NULL DEFAULT -1,
    disk    INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (host_id, at)
);
CREATE INDEX host_metrics_at ON host_metrics(at);
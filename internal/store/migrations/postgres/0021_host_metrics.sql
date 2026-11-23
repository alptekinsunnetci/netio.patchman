-- Resource history of a host: one row per monitoring round. Percentages are
-- stored in tenths (853 = 85.3%), -1 when unknown. disk is the fullest file
-- system. Kept for 30 days.
CREATE TABLE host_metrics (
    host_id BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE DEFERRABLE,
    at      BIGINT NOT NULL,
    cpu     BIGINT NOT NULL DEFAULT -1,
    load    BIGINT NOT NULL DEFAULT -1,
    memory  BIGINT NOT NULL DEFAULT -1,
    swap    BIGINT NOT NULL DEFAULT -1,
    disk    BIGINT NOT NULL DEFAULT -1,
    PRIMARY KEY (host_id, at)
);
CREATE INDEX host_metrics_at ON host_metrics(at);
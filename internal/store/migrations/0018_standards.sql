-- Server standards: rules for a group (or all hosts when group_id is NULL).
CREATE TABLE standards (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    group_id    INTEGER REFERENCES host_groups(id) ON DELETE CASCADE,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);

-- kind: required, forbidden, allowed_cycles, min_version, running.
-- subject_type: software (catalog id) or package (exact package name).
CREATE TABLE standard_rules (
    id           INTEGER PRIMARY KEY,
    standard_id  INTEGER NOT NULL REFERENCES standards(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject      TEXT NOT NULL,
    value        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX standard_rules_standard ON standard_rules(standard_id);

-- Current deviations from the standards, one row per host and rule.
CREATE TABLE drift_findings (
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    rule_id     INTEGER NOT NULL REFERENCES standard_rules(id) ON DELETE CASCADE,
    detail      TEXT NOT NULL DEFAULT '',
    first_seen  INTEGER NOT NULL,
    PRIMARY KEY (host_id, rule_id)
) WITHOUT ROWID;

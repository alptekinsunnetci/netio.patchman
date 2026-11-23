-- Services reported by the agent (protocol.CapServices).
CREATE TABLE host_services (
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    state   TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, name)
) WITHOUT ROWID;

-- Recognized products (package software) per host and release cycle.
-- running: 1 yes, 0 no, -1 unknown.
CREATE TABLE host_software (
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    software        TEXT NOT NULL,
    cycle           TEXT NOT NULL,
    version         TEXT NOT NULL,
    package         TEXT NOT NULL,
    package_version TEXT NOT NULL,
    running         INTEGER NOT NULL DEFAULT -1,
    service         TEXT NOT NULL DEFAULT '',
    first_seen_at   INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (host_id, software, cycle)
) WITHOUT ROWID;
CREATE INDEX host_software_software ON host_software(software, cycle);

-- Software installed, removed or changed version, per host.
CREATE TABLE software_events (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    software    TEXT NOT NULL,
    cycle       TEXT NOT NULL,
    event       TEXT NOT NULL,
    old_version TEXT NOT NULL DEFAULT '',
    new_version TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);
CREATE INDEX software_events_host ON software_events(host_id, created_at);
CREATE INDEX software_events_created ON software_events(created_at);

-- services_known: the last report carried a service list.
-- software_synced_at: first software inventory done (no events before it).
ALTER TABLE hosts ADD COLUMN services_known INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN software_synced_at INTEGER NOT NULL DEFAULT 0;

-- Findings of a product are matched through all binaries of its source package.
CREATE INDEX host_packages_source ON host_packages(host_id, source_name);

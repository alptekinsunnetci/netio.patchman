-- Ticket systems and Zabbix are new channel types: the type CHECK of 0007
-- goes away (store.ValidChannelType checks it), so the table is rebuilt.
-- New columns: the event filter (JSON array of event ids, empty = every
-- event at or above min_level) and type-specific settings (JSON: Jira
-- project, ServiceNow table, GLPI app token, Zabbix host and key).
CREATE TABLE notify_channels_new (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL,
    url          TEXT NOT NULL,
    secret       TEXT NOT NULL DEFAULT '',
    chat_id      TEXT NOT NULL DEFAULT '',
    min_level    TEXT NOT NULL DEFAULT 'warning' CHECK (min_level IN ('info', 'warning', 'critical')),
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    last_sent_at INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT '',
    last_error_at INTEGER NOT NULL DEFAULT 0,
    events       TEXT NOT NULL DEFAULT '[]',
    config       TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO notify_channels_new (id, name, type, url, secret, chat_id, min_level, enabled, created_at, last_sent_at, last_error, last_error_at)
    SELECT id, name, type, url, secret, chat_id, min_level, enabled, created_at, last_sent_at, last_error, last_error_at FROM notify_channels;
DROP TABLE notify_channels;
ALTER TABLE notify_channels_new RENAME TO notify_channels;

-- Delivery history: one row per notification and channel, with the
-- notification itself so a failed delivery can be sent again.
CREATE TABLE channel_deliveries (
    id          INTEGER PRIMARY KEY,
    channel_id  INTEGER NOT NULL REFERENCES notify_channels(id) ON DELETE CASCADE,
    event       TEXT NOT NULL,
    kind        TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    attempts    INTEGER NOT NULL,
    error       TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    payload     TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX channel_deliveries_channel ON channel_deliveries(channel_id, created_at);

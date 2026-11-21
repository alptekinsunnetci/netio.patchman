-- Interface language per user and outgoing notification channels.

-- '' follows the server default (PATCHMAN_LOCALE).
ALTER TABLE users ADD COLUMN locale TEXT NOT NULL DEFAULT '';

-- Slack, Microsoft Teams, Telegram or a generic JSON webhook. url holds the
-- webhook address (Telegram: the bot token), secret the HMAC key of a generic
-- webhook, chat_id the Telegram chat. min_level filters by notification level.
CREATE TABLE notify_channels (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL CHECK (type IN ('slack', 'teams', 'telegram', 'webhook')),
    url          TEXT NOT NULL,
    secret       TEXT NOT NULL DEFAULT '',
    chat_id      TEXT NOT NULL DEFAULT '',
    min_level    TEXT NOT NULL DEFAULT 'warning' CHECK (min_level IN ('info', 'warning', 'critical')),
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    last_sent_at INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT '',
    last_error_at INTEGER NOT NULL DEFAULT 0
);

-- Support calendars (endoflife.date product files, verbatim JSON) fetched
-- by the daily refresh; the built-in snapshot covers products not stored.
CREATE TABLE eol_data (
    product    TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);

-- End-of-life notifications already sent, once per release and kind
-- ("soon", "eol").
CREATE TABLE eol_notices (
    product     TEXT NOT NULL,
    cycle       TEXT NOT NULL,
    kind        TEXT NOT NULL,
    notified_at INTEGER NOT NULL,
    PRIMARY KEY (product, cycle, kind)
) WITHOUT ROWID;

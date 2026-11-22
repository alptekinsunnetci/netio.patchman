-- Packages a user watches (exact names), shown on the dashboard and the
-- host page. Per user, so viewers can keep their own list.
CREATE TABLE watched_packages (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, name)
) WITHOUT ROWID;

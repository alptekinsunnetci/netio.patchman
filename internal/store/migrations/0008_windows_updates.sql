-- Windows Update details per pending update: the update title and Microsoft
-- severity verbatim, and the CVE IDs the update fixes (JSON array).
ALTER TABLE host_updates ADD COLUMN title TEXT NOT NULL DEFAULT '';
ALTER TABLE host_updates ADD COLUMN severity TEXT NOT NULL DEFAULT '';
ALTER TABLE host_updates ADD COLUMN cves TEXT NOT NULL DEFAULT '[]';

-- Microsoft Security Update Guide lookups by KB number: the CVEs a KB fixes
-- and the KBs it supersedes (JSON, see scanner.MSRCKB). Shared by all hosts.
CREATE TABLE msrc_kb_cache (
    kb TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);

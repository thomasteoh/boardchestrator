-- 0030: Org wiki configuration (WU-501)
--
-- One row per org: the connected wiki repository. repo (URL) is set by the
-- org owner; ref (branch/tag) + path (subdirectory within the repo) are set by
-- a team admin — distinct permissions (wiki.config.repo vs wiki.config.ref).

CREATE TABLE IF NOT EXISTS wiki_configs (
    org_id     TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    repo       TEXT NOT NULL DEFAULT '',
    ref        TEXT NOT NULL DEFAULT 'main',
    path       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

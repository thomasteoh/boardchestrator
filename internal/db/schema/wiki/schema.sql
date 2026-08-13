CREATE TABLE IF NOT EXISTS orgs (id TEXT PRIMARY KEY);

CREATE TABLE IF NOT EXISTS wiki_configs (
    org_id     TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    repo       TEXT NOT NULL DEFAULT '',
    ref        TEXT NOT NULL DEFAULT 'main',
    path       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

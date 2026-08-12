-- 0028: GitHub links + inbound webhooks (WU-405)
--
-- project_github: per-project GitHub integration config. repo is "owner/name";
-- transitions is a JSON map of PR-state → task status (e.g. {"opened":"todo",
-- "merged":"done"}); webhook_secret signs inbound /hooks/github payloads.
--
-- github_links: one row per extracted KEY-n reference from a branch/commit/PR
-- body. kind: branch | commit | pr. state reflects the linked PR/commit state
-- (e.g. pr.opened, pr.merged, commit pushed). task_id is the matched task
-- (null when the key does not resolve to a task yet).

CREATE TABLE IF NOT EXISTS project_github (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    repo           TEXT NOT NULL,
    transitions    TEXT NOT NULL DEFAULT '{}',
    webhook_secret TEXT NOT NULL DEFAULT '',
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_project_github_repo ON project_github(repo);
CREATE INDEX IF NOT EXISTS idx_project_github_project ON project_github(project_id);

CREATE TABLE IF NOT EXISTS github_links (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,               -- branch | commit | pr
    key        TEXT NOT NULL,               -- project key (from KEY-n)
    key_num    INTEGER NOT NULL,            -- numeric suffix n
    ref        TEXT NOT NULL,               -- branch name / commit sha / PR number
    state      TEXT NOT NULL DEFAULT '',    -- e.g. pr.opened, pr.merged, commit.pushed
    task_id    TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    url        TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_github_links_project ON github_links(project_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_github_links_ref ON github_links(project_id, kind, key, key_num, ref);
CREATE INDEX IF NOT EXISTS idx_github_links_task ON github_links(task_id);

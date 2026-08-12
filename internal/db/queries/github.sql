-- name: UpsertProjectGithub :one
-- Config row is keyed by repo (unique); create-or-update keeps a single row.
INSERT INTO project_github (id, project_id, repo, transitions, webhook_secret, enabled, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(repo) DO UPDATE SET
    project_id = excluded.project_id,
    transitions = excluded.transitions,
    webhook_secret = excluded.webhook_secret,
    enabled = excluded.enabled,
    updated_at = excluded.updated_at
RETURNING id, project_id, repo, transitions, webhook_secret, enabled, created_at, updated_at;

-- name: FindProjectGithubByRepo :one
SELECT id, project_id, repo, transitions, webhook_secret, enabled, created_at, updated_at
FROM project_github
WHERE repo = ?;

-- name: FindProjectGithubByProject :one
SELECT id, project_id, repo, transitions, webhook_secret, enabled, created_at, updated_at
FROM project_github
WHERE project_id = ?;

-- name: ListProjectGithubByOrg :many
SELECT pg.id, pg.project_id, pg.repo, pg.transitions, pg.webhook_secret, pg.enabled, pg.created_at, pg.updated_at
FROM project_github pg
JOIN projects p ON p.id = pg.project_id
WHERE p.org_id = ?
ORDER BY pg.repo ASC;

-- name: DeleteProjectGithub :exec
DELETE FROM project_github
WHERE repo = ?;

-- name: CreateGithubLink :one
INSERT INTO github_links (id, project_id, kind, key, key_num, ref, state, task_id, url)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, project_id, kind, key, key_num, ref, state, task_id, url, created_at, updated_at;

-- name: UpsertGithubLink :one
-- One row per (kind, key, key_num, ref); update state/task/url on re-delivery.
INSERT INTO github_links (id, project_id, kind, key, key_num, ref, state, task_id, url)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(project_id, kind, key, key_num, ref) DO UPDATE SET
    state = excluded.state,
    task_id = excluded.task_id,
    url = excluded.url,
    updated_at = excluded.updated_at
RETURNING id, project_id, kind, key, key_num, ref, state, task_id, url, created_at, updated_at;

-- name: ListGithubLinksByProject :many
SELECT id, project_id, kind, key, key_num, ref, state, task_id, url, created_at, updated_at
FROM github_links
WHERE project_id = ?
ORDER BY created_at DESC;

-- name: ListGithubLinksByTask :many
SELECT id, project_id, kind, key, key_num, ref, state, task_id, url, created_at, updated_at
FROM github_links
WHERE task_id = ?
ORDER BY created_at DESC;

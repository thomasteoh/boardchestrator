-- name: FindWikiConfig :one
SELECT org_id, repo, ref, path, created_at, updated_at
FROM wiki_configs WHERE org_id = ?;

-- name: UpsertWikiConfig :exec
INSERT INTO wiki_configs (org_id, repo, ref, path, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(org_id) DO UPDATE SET repo = excluded.repo, ref = excluded.ref, path = excluded.path, updated_at = excluded.updated_at;

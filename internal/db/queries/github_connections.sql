-- name: UpsertGithubConnection :one
-- One row per user (user_id PK); create-or-update the token source.
INSERT INTO github_connections (user_id, provider, token_enc, login, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(user_id) DO UPDATE SET
    provider = excluded.provider,
    token_enc = excluded.token_enc,
    login = excluded.login,
    updated_at = excluded.updated_at
RETURNING user_id, provider, token_enc, login, created_at, updated_at;

-- name: FindGithubConnection :one
SELECT user_id, provider, token_enc, login, created_at, updated_at
FROM github_connections
WHERE user_id = ?;

-- name: DeleteGithubConnection :exec
DELETE FROM github_connections
WHERE user_id = ?;

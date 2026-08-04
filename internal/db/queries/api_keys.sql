-- name: CreateAPIKey :one
INSERT INTO api_keys (id, user_id, org_id, name, prefix, hash, scope_json)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at;

-- name: FindAPIKeyByPrefix :one
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at
FROM api_keys
WHERE prefix = ? AND revoked_at IS NULL;

-- name: FindAPIKeyByID :one
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at
FROM api_keys
WHERE id = ? AND revoked_at IS NULL;

-- name: ListAPIKeysByUser :many
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at
FROM api_keys
WHERE user_id = ? AND revoked_at IS NULL
ORDER BY created_at;

-- name: ListAPIKeysByOrg :many
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at
FROM api_keys
WHERE org_id = ? AND revoked_at IS NULL
ORDER BY created_at;

-- name: RevokeAPIKey :exec
UPDATE api_keys SET revoked_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ? AND user_id = ?;

-- name: TouchAPIKey :exec
UPDATE api_keys SET last_used_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ?;

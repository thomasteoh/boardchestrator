-- name: CreateAPIKey :one
INSERT INTO api_keys (id, user_id, org_id, name, prefix, hash, scope_json, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at, expires_at;

-- name: FindAPIKeyByPrefix :one
-- SPEC s7.10: revoked and expired keys never authenticate.
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at, expires_at
FROM api_keys
WHERE prefix = ? AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- name: FindAPIKeyByID :one
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at, expires_at
FROM api_keys
WHERE id = ? AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- name: ListAPIKeysByUser :many
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at, expires_at
FROM api_keys
WHERE user_id = ? AND revoked_at IS NULL
ORDER BY created_at;

-- name: ListUserOrgAPIKeys :many
-- A user's own unrevoked keys bound to one org (apikey.list).
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at, expires_at
FROM api_keys
WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL
ORDER BY created_at, id;

-- name: ListAPIKeysByOrg :many
SELECT id, user_id, org_id, name, prefix, hash, scope_json, last_used_at, created_at, revoked_at, expires_at
FROM api_keys
WHERE org_id = ? AND revoked_at IS NULL
ORDER BY created_at;

-- name: ListOrgAPIKeysWithOwner :many
-- apikey.org_list: every unrevoked key bound to the org with its owner.
SELECT k.id, k.user_id, k.name, k.prefix, k.last_used_at, k.created_at, k.expires_at,
       COALESCE(u.name, '') AS owner_name, COALESCE(u.email, '') AS owner_email
FROM api_keys k
LEFT JOIN users u ON u.id = k.user_id
WHERE k.org_id = ? AND k.revoked_at IS NULL
ORDER BY k.created_at, k.id;

-- name: RevokeAPIKey :execrows
-- apikey.revoke: the caller's own key in the org.
UPDATE api_keys SET revoked_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ? AND user_id = ? AND org_id = ? AND revoked_at IS NULL;

-- name: RevokeOrgAPIKey :execrows
-- apikey.org_revoke: any key bound to the org.
UPDATE api_keys SET revoked_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ? AND org_id = ? AND revoked_at IS NULL;

-- name: TouchAPIKey :exec
UPDATE api_keys SET last_used_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ?;

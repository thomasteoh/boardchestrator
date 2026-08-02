-- name: CreateOrgSecret :one
INSERT INTO org_secrets (id, org_id, "key", ciphertext)
VALUES (?, ?, ?, ?)
RETURNING id, org_id, "key", ciphertext, created_at;

-- name: FindOrgSecretByKey :one
SELECT id, org_id, "key", ciphertext, created_at
FROM org_secrets
WHERE org_id = ? AND "key" = ?;

-- name: DeleteOrgSecret :exec
DELETE FROM org_secrets
WHERE org_id = ? AND "key" = ?;

-- name: ListOrgSecrets :many
SELECT id, org_id, "key", ciphertext, created_at
FROM org_secrets
WHERE org_id = ?;

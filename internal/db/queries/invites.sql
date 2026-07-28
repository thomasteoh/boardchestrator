-- name: CreateInvite :one
INSERT INTO invites (id, org_id, inviter_id, email, token_hash, role_id, resource_type, resource_id, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, inviter_id, email, token_hash, role_id, resource_type, resource_id, expires_at, accepted_at, created_at;

-- name: FindInviteByID :one
SELECT id, org_id, inviter_id, email, token_hash, role_id, resource_type, resource_id, expires_at, accepted_at, created_at
FROM invites
WHERE id = ?;

-- name: FindInviteByTokenHash :one
SELECT id, org_id, inviter_id, email, token_hash, role_id, resource_type, resource_id, expires_at, accepted_at, created_at
FROM invites
WHERE token_hash = ?;

-- name: FindPendingInvitesByOrg :many
SELECT id, org_id, inviter_id, email, token_hash, role_id, resource_type, resource_id, expires_at, accepted_at, created_at
FROM invites
WHERE org_id = ? AND accepted_at IS NULL AND expires_at > ?
ORDER BY created_at;

-- name: AcceptInvite :one
UPDATE invites SET accepted_at = ?
WHERE id = ? AND accepted_at IS NULL
RETURNING id, org_id, inviter_id, email, token_hash, role_id, resource_type, resource_id, expires_at, accepted_at, created_at;

-- name: DeleteInvite :exec
DELETE FROM invites
WHERE id = ? AND org_id = ?;

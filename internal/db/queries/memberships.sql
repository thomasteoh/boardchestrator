-- name: CreateMembership :one
INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at;

-- name: FindMembership :one
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at
FROM memberships
WHERE org_id = ? AND actor_id = ? AND actor_type = ? AND resource_type = ? AND resource_id = ?;

-- name: FindMembershipsByOrg :many
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at
FROM memberships
WHERE org_id = ?
ORDER BY resource_type, resource_id, actor_id;

-- name: FindMembershipsByResource :many
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at
FROM memberships
WHERE org_id = ? AND resource_type = ? AND resource_id = ?;

-- name: DeleteMembership :exec
DELETE FROM memberships
WHERE org_id = ? AND actor_id = ? AND actor_type = ? AND resource_type = ? AND resource_id = ?;

-- name: FindOrgsByActor :many
SELECT o.id, o.name
FROM memberships m
JOIN orgs o ON o.id = m.org_id
WHERE m.actor_id = ? AND m.actor_type = 'user' AND m.resource_type = 'org'
ORDER BY o.name ASC;

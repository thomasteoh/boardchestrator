-- name: CreateMembership :one
INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at, source;

-- name: FindMembership :one
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at, source
FROM memberships
WHERE org_id = ? AND actor_id = ? AND actor_type = ? AND resource_type = ? AND resource_id = ?;

-- name: FindMembershipsByOrg :many
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at, source
FROM memberships
WHERE org_id = ?
ORDER BY resource_type, resource_id, actor_id;

-- name: FindMembershipsByResource :many
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at, source
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

-- name: ListOrgOwnerCandidates :many
-- Last-owner guard (WU-613): the org-level memberships of live users with
-- their role's grants; the caller keeps the owner-equivalent ones.
SELECT m.id, m.actor_id, COALESCE(m.role_id, '') AS role_id, COALESCE(r.grants_json, '[]') AS grants_json
FROM memberships m
JOIN roles r ON r.id = m.role_id
JOIN users u ON u.id = m.actor_id
WHERE m.org_id = ? AND m.actor_type = 'user' AND m.resource_type = 'org'
  AND m.resource_id = m.org_id AND u.deleted_at IS NULL
ORDER BY m.id;

-- name: DeleteUserOrgMembershipsExcept :execrows
-- SCIM deprovisioning of an org's last owner: every membership of the user
-- in the org except the preserved owner membership.
DELETE FROM memberships
WHERE org_id = ? AND actor_type = 'user' AND actor_id = ? AND id <> ?;

-- name: CountUserMembershipOrgsExcept :one
-- How many orgs other than one the user still belongs to.
SELECT count(DISTINCT org_id) FROM memberships
WHERE actor_type = 'user' AND actor_id = ? AND org_id <> ?;

-- name: CreateRole :one
INSERT INTO roles (id, org_id, name, is_system, grants_json)
VALUES (?, ?, ?, ?, ?)
RETURNING id, org_id, name, is_system, grants_json, created_at;

-- name: UpdateRole :one
UPDATE roles SET name = ?, grants_json = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, name, is_system, grants_json, created_at;

-- name: FindRoleByID :one
SELECT id, org_id, name, is_system, grants_json, created_at
FROM roles
WHERE id = ? AND org_id = ?;

-- name: FindRoleByOrgAndName :one
SELECT id, org_id, name, is_system, grants_json, created_at
FROM roles
WHERE org_id = ? AND name = ?;

-- name: ListRolesByOrg :many
SELECT id, org_id, name, is_system, grants_json, created_at
FROM roles
WHERE org_id = ?
ORDER BY name;

-- name: DeleteRole :exec
DELETE FROM roles
WHERE id = ? AND org_id = ?;

-- name: CreateOrg :one
INSERT INTO orgs (id, name, slug, context, visibility, monthly_cap_usd, cap_alert_pct)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, name, slug, context, visibility, monthly_cap_usd, cap_alert_pct, created_at;

-- name: UpdateOrg :one
UPDATE orgs SET name = ?, context = ?, visibility = ?
WHERE id = ?
RETURNING id, name, slug, context, visibility, monthly_cap_usd, cap_alert_pct, created_at;

-- name: UpdateOrgCap :one
UPDATE orgs SET monthly_cap_usd = ?, cap_alert_pct = ?
WHERE id = ?
RETURNING id, name, slug, context, visibility, monthly_cap_usd, cap_alert_pct, created_at;

-- name: FindOrgByID :one
SELECT id, name, slug, context, visibility, monthly_cap_usd, cap_alert_pct, created_at
FROM orgs
WHERE id = ?;

-- name: FindOrgBySlug :one
SELECT id, name, slug, context, visibility, monthly_cap_usd, cap_alert_pct, created_at
FROM orgs
WHERE slug = ?;

-- name: CreateTeam :one
INSERT INTO teams (id, org_id, name, slug, context, visibility)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, org_id, name, slug, context, visibility, created_at;

-- name: UpdateTeam :one
UPDATE teams SET name = ?, context = ?, visibility = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, name, slug, context, visibility, created_at;

-- name: FindTeamByID :one
SELECT id, org_id, name, slug, context, visibility, created_at
FROM teams
WHERE id = ? AND org_id = ?;

-- name: ListTeamsByOrg :many
SELECT id, org_id, name, slug, context, visibility, created_at
FROM teams
WHERE org_id = ?
ORDER BY name ASC;

-- name: ListProjectsByOrg :many
SELECT id, org_id, team_id, name, key, context, visibility, archived, next_task_num, created_at
FROM projects
WHERE org_id = ?
ORDER BY name ASC;

-- name: CreateProject :one
INSERT INTO projects (id, org_id, team_id, name, key, context, visibility)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, team_id, name, key, context, visibility, archived, next_task_num, created_at;

-- name: UpdateProject :one
UPDATE projects SET name = ?, context = ?, visibility = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, team_id, name, key, context, visibility, archived, next_task_num, created_at;

-- name: ArchiveProject :exec
UPDATE projects SET archived = 1
WHERE id = ? AND org_id = ?;

-- name: UnarchiveProject :exec
UPDATE projects SET archived = 0
WHERE id = ? AND org_id = ?;

-- name: FindProjectByID :one
SELECT id, org_id, team_id, name, key, context, visibility, archived, next_task_num, created_at
FROM projects
WHERE id = ? AND org_id = ?;

-- name: FindProjectByKey :one
SELECT id, org_id, team_id, name, key, context, visibility, archived, next_task_num, created_at
FROM projects
WHERE org_id = ? AND key = ?;

-- name: GetProjectOrg :one
SELECT org_id
FROM projects
WHERE id = ?;

-- name: FindRoleByID2 :one
SELECT id, org_id, name, is_system, grants_json, created_at
FROM roles
WHERE id = ?;

-- name: FindRoleByName2 :one
SELECT id, org_id, name, is_system, grants_json, created_at
FROM roles
WHERE org_id = ? AND name = ?;

-- name: ListRolesByOrg2 :many
SELECT id, org_id, name, is_system, grants_json, created_at
FROM roles
WHERE org_id = ? OR org_id = '00000000000000000000000000000000'
ORDER BY is_system DESC, name ASC;

-- name: CreateRole2 :one
INSERT INTO roles (id, org_id, name, is_system, grants_json)
VALUES (?, ?, ?, ?, ?)
RETURNING id, org_id, name, is_system, grants_json, created_at;

-- name: UpdateRoleGrants :one
UPDATE roles SET grants_json = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, name, is_system, grants_json, created_at;

-- name: FindMemberships :many
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at
FROM memberships
WHERE org_id = ? AND actor_type = ? AND actor_id = ?
  AND resource_type = ? AND resource_id = ?;

-- name: FindMembershipsForActor :many
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at
FROM memberships
WHERE org_id = ? AND actor_type = ? AND actor_id = ?;

-- name: FindOrgIDsForActor :many
SELECT org_id
FROM memberships
WHERE actor_id = ? AND actor_type = 'user' AND resource_type = 'org'
ORDER BY org_id;

-- name: CreateMembershipFromOrgQuery :one
INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at;

-- name: DeleteMembershipByID :exec
DELETE FROM memberships
WHERE id = ? AND org_id = ?;

-- name: ListOrgs :many
SELECT id, name, slug, context, visibility, monthly_cap_usd, cap_alert_pct, created_at
FROM orgs
ORDER BY name ASC;
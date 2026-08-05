-- name: ListUserIdentities :many
SELECT id, user_id, provider, subject, email
FROM identities
WHERE user_id = ?;

-- name: ListUserSessions :many
SELECT token_hash, user_id, ip, ua, created_at, last_seen_at, expires_at
FROM sessions
WHERE user_id = ?;

-- name: ListUserMemberships :many
SELECT m.id, m.org_id, m.actor_id, m.actor_type, m.resource_type, m.resource_id, m.role_id, m.created_at, o.name as org_name
FROM memberships m
JOIN orgs o ON o.id = m.org_id
WHERE m.actor_id = ? AND m.actor_type = 'user';

-- name: ListUserApiKeys :many
SELECT id, user_id, org_id, name, prefix, scope_json, last_used_at, created_at, revoked_at
FROM api_keys
WHERE user_id = ?;

-- name: ListUserComments :many
SELECT id, task_id, project_id, author_id, body, created_at, updated_at
FROM comments
WHERE author_id = ?;

-- name: ListUserTaskActivity :many
SELECT id, task_id, project_id, actor_id, actor_type, action, detail_json, created_at
FROM task_activity
WHERE actor_id = ? AND actor_type = 'user';

-- name: ListUserTaskAssignments :many
SELECT task_id, project_id, user_id
FROM task_assignees
WHERE user_id = ?;

-- name: ListUserWatchers :many
SELECT task_id, project_id, user_id
FROM task_watchers
WHERE user_id = ?;

-- name: ListUserSavedFilters :many
SELECT id, project_id, name, query_json, pinned, created_by, created_at, updated_at
FROM saved_filters
WHERE created_by = ?;

-- name: ListUserNotifications :many
SELECT id, org_id, user_id, event_name, subject_id, title, body, grouping_key, created_at, read_at
FROM notifications
WHERE user_id = ?;

-- name: DeleteUserIdentities :exec
DELETE FROM identities WHERE user_id = ?;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = ?;

-- name: DeleteUserMemberships :exec
DELETE FROM memberships WHERE actor_id = ? AND actor_type = 'user';

-- name: DeleteUserApiKeys :exec
DELETE FROM api_keys WHERE user_id = ?;

-- name: DeleteUserNotifications :exec
DELETE FROM notifications WHERE user_id = ?;

-- name: ReattributeComments :exec
UPDATE comments SET author_id = 'ffffffffffffffffffffffffffffffff', deleted_by = ?
WHERE author_id = ?;

-- name: ReattributeTaskActivity :exec
UPDATE task_activity SET actor_id = 'ffffffffffffffffffffffffffffffff', deleted_by = ?
WHERE actor_id = ? AND actor_type = 'user';

-- name: ReattributeTaskAssignees :exec
DELETE FROM task_assignees WHERE user_id = ?;

-- name: ReattributeTaskWatchers :exec
DELETE FROM task_watchers WHERE user_id = ?;

-- name: DeleteUserSavedFilters :exec
DELETE FROM saved_filters WHERE created_by = ?;

-- name: DeleteUser :exec
UPDATE users SET email = '', name = 'Former member', avatar_url = '', deleted_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ?;

-- name: ListOrgProjects :many
SELECT id, org_id, team_id, name, key, context, visibility, archived, next_task_num, created_at
FROM projects
WHERE org_id = ?;

-- name: ListOrgTeams :many
SELECT id, org_id, name, slug, context, visibility, created_at
FROM teams
WHERE org_id = ?;

-- name: ListOrgRoles :many
SELECT id, org_id, name, is_system, grants_json, created_at
FROM roles
WHERE org_id = ?;

-- name: ListOrgMemberships :many
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at
FROM memberships
WHERE org_id = ?;

-- name: ListOrgSecrets2 :many
SELECT id, org_id, key, ciphertext, created_at
FROM org_secrets
WHERE org_id = ?;

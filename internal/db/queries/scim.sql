-- SCIM 2.0 provisioning (WU-611, SPEC s7.8). Every query binds org_id except
-- FindSCIMTokenByPrefix, the bearer-token lookup: it maps a token prefix to
-- its row, and the row's org_id is the org every later query is scoped to.

-- name: CreateSCIMToken :exec
INSERT INTO scim_tokens (id, org_id, name, prefix, token_hash, created_by, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: FindSCIMTokenByPrefix :one
SELECT id, org_id, name, prefix, token_hash, expires_at, revoked_at
FROM scim_tokens
WHERE prefix = ?;

-- name: ListSCIMTokens :many
SELECT id, org_id, name, prefix, created_by, expires_at, last_used_at, revoked_at, created_at
FROM scim_tokens
WHERE org_id = ?
ORDER BY created_at DESC, id;

-- name: CountActiveSCIMTokens :one
SELECT count(*) FROM scim_tokens
WHERE org_id = sqlc.arg(org_id) AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > sqlc.arg(now));

-- name: RevokeSCIMToken :execrows
UPDATE scim_tokens SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) AND revoked_at IS NULL;

-- name: TouchSCIMToken :exec
-- Throttled: last_used_at moves at most once a minute.
UPDATE scim_tokens SET last_used_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id)
  AND (last_used_at IS NULL OR last_used_at < sqlc.arg(before));

-- name: CreateSCIMUser :exec
INSERT INTO scim_users (id, org_id, user_id, external_id, user_name, email, given_name, family_name,
                        display_name, active, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSCIMUser :one
SELECT * FROM scim_users
WHERE id = ? AND org_id = ?;

-- name: GetSCIMUserByUser :one
SELECT * FROM scim_users
WHERE org_id = ? AND user_id = ?;

-- name: FindSCIMUserByUserName :one
SELECT * FROM scim_users
WHERE org_id = ? AND lower(user_name) = lower(sqlc.arg(user_name));

-- name: ListSCIMUsers :many
SELECT * FROM scim_users
WHERE org_id = ?
ORDER BY created_at, id;

-- name: UpdateSCIMUser :exec
UPDATE scim_users SET external_id = ?, user_name = ?, email = ?, given_name = ?, family_name = ?,
    display_name = ?, active = ?, updated_at = ?
WHERE id = ? AND org_id = ?;

-- name: DeleteSCIMUser :execrows
DELETE FROM scim_users
WHERE id = ? AND org_id = ?;

-- name: CreateSCIMGroup :exec
INSERT INTO scim_groups (id, org_id, external_id, display_name, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetSCIMGroup :one
SELECT * FROM scim_groups
WHERE id = ? AND org_id = ?;

-- name: ListSCIMGroups :many
SELECT * FROM scim_groups
WHERE org_id = ?
ORDER BY created_at, id;

-- name: UpdateSCIMGroup :exec
UPDATE scim_groups SET external_id = ?, display_name = ?, updated_at = ?
WHERE id = ? AND org_id = ?;

-- name: DeleteSCIMGroup :execrows
DELETE FROM scim_groups
WHERE id = ? AND org_id = ?;

-- name: ListSCIMGroupMembers :many
-- Members of every group in the org, as SCIM user ids.
SELECT m.group_id, m.user_id, u.id AS scim_user_id, u.user_name
FROM scim_group_members m
JOIN scim_users u ON u.org_id = m.org_id AND u.user_id = m.user_id
WHERE m.org_id = ?
ORDER BY m.group_id, u.created_at, u.id;

-- name: ListSCIMGroupMemberUsers :many
SELECT user_id FROM scim_group_members
WHERE group_id = ? AND org_id = ?;

-- name: AddSCIMGroupMember :exec
INSERT INTO scim_group_members (group_id, user_id, org_id)
VALUES (?, ?, ?)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveSCIMGroupMember :execrows
DELETE FROM scim_group_members
WHERE group_id = ? AND user_id = ? AND org_id = ?;

-- name: ClearSCIMGroupMembers :exec
DELETE FROM scim_group_members
WHERE group_id = ? AND org_id = ?;

-- name: RemoveSCIMUserFromGroups :exec
DELETE FROM scim_group_members
WHERE org_id = ? AND user_id = ?;

-- name: ListSCIMUserGroupNames :many
-- The display names of the SCIM groups user_id is in: the group values for
-- reconciliation.
SELECT g.display_name
FROM scim_group_members m
JOIN scim_groups g ON g.id = m.group_id AND g.org_id = m.org_id
WHERE m.org_id = ? AND m.user_id = ?
ORDER BY g.display_name;

-- name: FindUserByEmailFold :one
-- Case-insensitive email lookup (SCIM provisioning and SCIM-linked sign-in).
SELECT id, email, name, deleted_at
FROM users
WHERE lower(email) = lower(sqlc.arg(email))
ORDER BY id
LIMIT 1;

-- name: DeleteUserOrgMemberships :execrows
-- SCIM deprovisioning: every membership of the user in one org, any source.
DELETE FROM memberships
WHERE org_id = ? AND actor_type = 'user' AND actor_id = ?;

-- name: RevokeUserOrgAPIKeys :execrows
UPDATE api_keys SET revoked_at = sqlc.arg(now)
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- name: CountUserMembershipOrgs :one
-- How many orgs (any, including the platform org) the user still belongs to.
SELECT count(DISTINCT org_id) FROM memberships
WHERE actor_type = 'user' AND actor_id = ?;

-- name: FindOrgMembershipForUser :one
SELECT id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, created_at, source
FROM memberships
WHERE org_id = sqlc.arg(org_id) AND actor_type = 'user' AND actor_id = sqlc.arg(actor_id)
  AND resource_type = 'org' AND resource_id = sqlc.arg(org_id);

-- name: GetOrgSSOSettingsForSCIM :one
SELECT org_id, jit_default_role_id FROM org_sso_settings
WHERE org_id = ?;

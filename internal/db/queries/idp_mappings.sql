-- IdP group -> role mappings and JIT settings (WU-608, SPEC s7.5). Every
-- query binds org_id.

-- name: CreateIdPGroupMapping :exec
INSERT INTO idp_group_mappings (id, org_id, provider_id, group_value, role_id, resource_type, resource_id)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListIdPGroupMappings :many
SELECT * FROM idp_group_mappings
WHERE org_id = ?
ORDER BY group_value, created_at, id;

-- name: ListIdPGroupMappingsForProvider :many
-- Mappings that apply to sign-ins through provider_id: its own plus the
-- org-wide ones (provider_id NULL). Oldest first: when two mappings target
-- the same resource with different roles, the oldest wins.
SELECT * FROM idp_group_mappings
WHERE org_id = sqlc.arg(org_id)
  AND (provider_id IS NULL OR provider_id = sqlc.arg(provider_id))
ORDER BY created_at, id;

-- name: DeleteIdPGroupMapping :execrows
DELETE FROM idp_group_mappings
WHERE id = ? AND org_id = ?;

-- name: FindRoleForOrg :one
-- A role usable in org_id: one the org owns, or a seeded system role (held
-- by the platform org and shared by every org).
SELECT id, org_id, name, is_system, grants_json, created_at
FROM roles
WHERE id = sqlc.arg(id)
  AND (org_id = sqlc.arg(org_id) OR (org_id = '00000000000000000000000000000000' AND is_system = 1));

-- name: CreateSourcedMembership :exec
INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, source)
VALUES (?, ?, ?, 'user', ?, ?, ?, ?);

-- name: UpdateIdPMembershipRole :execrows
UPDATE memberships SET role_id = ?
WHERE id = ? AND org_id = ? AND source = 'idp';

-- name: DeleteIdPMembership :execrows
DELETE FROM memberships
WHERE id = ? AND org_id = ? AND source = 'idp';

-- name: SetOrgSSOProvisioning :exec
INSERT INTO org_sso_settings (org_id, jit_enabled, jit_default_role_id, group_claim, group_sync, updated_at)
VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT (org_id) DO UPDATE SET
    jit_enabled         = excluded.jit_enabled,
    jit_default_role_id = excluded.jit_default_role_id,
    group_claim         = excluded.group_claim,
    group_sync          = excluded.group_sync,
    updated_at          = excluded.updated_at;

-- Organisation SSO (WU-607, SPEC s7.4): org-owned sign-in providers and the
-- per-org SSO settings. Every query binds org_id. auth_providers itself is not
-- in check-scope's tenant list (nullable org_id), so these queries pin
-- org_id = ? by hand; managed_by is always 'ui' for org rows.

-- name: ListOrgAuthProviders :many
-- Omits client_secret_enc: callers only learn whether a secret is set.
SELECT p.id, p.kind, p.preset, p.display_name, p.enabled, p.managed_by, p.issuer,
       p.client_id, CAST(p.client_secret_enc <> '' AS INTEGER) AS has_secret,
       p.scopes, p.claim_map_json, p.trust_email, p.allow_signup,
       p.allowed_tenants_json, p.position, p.created_at, p.updated_at,
       CAST((SELECT COUNT(*) FROM identities i WHERE i.provider = p.id) AS INTEGER) AS identity_count
FROM auth_providers p
WHERE p.org_id = ?
ORDER BY p.position, p.id;

-- name: GetOrgAuthProvider :one
SELECT * FROM auth_providers
WHERE id = ? AND org_id = ?;

-- name: ListEnabledOrgAuthProviderIDs :many
SELECT id FROM auth_providers
WHERE org_id = ? AND enabled = 1
ORDER BY position, id;

-- name: NextOrgAuthProviderPosition :one
SELECT CAST(COALESCE(MAX(position), 0) + 10 AS INTEGER) FROM auth_providers
WHERE org_id = ?;

-- name: CreateOrgAuthProvider :exec
INSERT INTO auth_providers (id, org_id, kind, preset, display_name, enabled, managed_by, issuer,
                            client_id, client_secret_enc, scopes, claim_map_json,
                            trust_email, allow_signup, allowed_tenants_json, position)
VALUES (?, ?, ?, ?, ?, ?, 'ui', ?, ?, ?, ?, ?, ?, 0, ?, ?);

-- name: UpdateOrgAuthProvider :execrows
-- allow_signup is always 0 for org-owned providers.
UPDATE auth_providers
SET preset               = ?,
    display_name         = ?,
    issuer               = ?,
    client_id            = ?,
    client_secret_enc    = ?,
    scopes               = ?,
    claim_map_json       = ?,
    trust_email          = ?,
    allow_signup         = 0,
    allowed_tenants_json = ?,
    position             = ?,
    updated_at           = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND org_id = ? AND managed_by = 'ui';

-- name: SetOrgAuthProviderEnabled :execrows
UPDATE auth_providers
SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND org_id = ? AND managed_by = 'ui';

-- name: DeleteOrgAuthProvider :execrows
DELETE FROM auth_providers
WHERE id = ? AND org_id = ? AND managed_by = 'ui';

-- name: GetOrgSSOSettings :one
SELECT * FROM org_sso_settings
WHERE org_id = ?;

-- name: SetOrgSSOEnforce :exec
INSERT INTO org_sso_settings (org_id, enforce_sso, updated_at)
VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT (org_id) DO UPDATE SET
    enforce_sso = excluded.enforce_sso,
    updated_at  = excluded.updated_at;

-- name: FindProjectOrg :one
-- Maps a project id to its org for the SSO gate on /app/project/{id}
-- routes, which carry no org id.
SELECT org_id FROM projects
WHERE id = ?;

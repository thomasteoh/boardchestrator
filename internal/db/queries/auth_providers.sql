-- Sign-in provider registry (SPEC s7.1). auth_providers.org_id is nullable
-- (NULL = platform provider) and the registry serves every enabled row by id,
-- so these queries are deliberately not org-scoped; see check-scope.sh.

-- name: ListEnabledAuthProviders :many
SELECT * FROM auth_providers
WHERE enabled = 1
ORDER BY position, id;

-- name: ListAuthProviders :many
SELECT * FROM auth_providers
ORDER BY position, id;

-- name: GetAuthProvider :one
SELECT * FROM auth_providers
WHERE id = ?;

-- name: UpsertEnvAuthProvider :exec
-- Seeds an env-managed row. Never overwrites a UI-managed row with the same
-- id (the WHERE on the conflict update), so callers check managed_by first.
INSERT INTO auth_providers (id, kind, preset, display_name, enabled, managed_by, issuer,
                            client_id, client_secret_enc, scopes, claim_map_json,
                            trust_email, allow_signup, position, updated_at)
VALUES (?, ?, ?, ?, 1, 'env', ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT (id) DO UPDATE SET
    kind              = excluded.kind,
    preset            = excluded.preset,
    display_name      = excluded.display_name,
    enabled           = 1,
    issuer            = excluded.issuer,
    client_id         = excluded.client_id,
    client_secret_enc = excluded.client_secret_enc,
    scopes            = excluded.scopes,
    claim_map_json    = excluded.claim_map_json,
    trust_email       = excluded.trust_email,
    allow_signup      = excluded.allow_signup,
    position          = excluded.position,
    updated_at        = excluded.updated_at
WHERE auth_providers.managed_by = 'env';

-- name: DisableEnvAuthProvider :exec
UPDATE auth_providers
SET enabled = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND managed_by = 'env' AND enabled = 1;

-- Platform provider management (idp.* actions, WU-603). These touch only
-- platform rows (org_id IS NULL) managed in the UI (managed_by = 'ui');
-- org-owned providers are WU-607.

-- name: ListPlatformAuthProviders :many
-- Every platform provider with its identity count. Deliberately omits
-- client_secret_enc: callers only learn whether a secret is set.
SELECT p.id, p.kind, p.preset, p.display_name, p.enabled, p.managed_by, p.issuer,
       p.client_id, CAST(p.client_secret_enc <> '' AS INTEGER) AS has_secret,
       p.scopes, p.claim_map_json, p.trust_email, p.allow_signup,
       p.allowed_tenants_json, p.position, p.created_at, p.updated_at, p.idp_logout,
       CAST((SELECT COUNT(*) FROM identities i WHERE i.provider = p.id) AS INTEGER) AS identity_count
FROM auth_providers p
WHERE p.org_id IS NULL
ORDER BY p.position, p.id;

-- name: CountIdentitiesByProvider :one
SELECT COUNT(*) FROM identities
WHERE provider = ?;

-- name: NextAuthProviderPosition :one
SELECT CAST(COALESCE(MAX(position), 0) + 10 AS INTEGER) FROM auth_providers
WHERE org_id IS NULL;

-- name: CreateAuthProvider :exec
INSERT INTO auth_providers (id, org_id, kind, preset, display_name, enabled, managed_by, issuer,
                            client_id, client_secret_enc, scopes, claim_map_json,
                            trust_email, allow_signup, allowed_tenants_json, position, idp_logout)
VALUES (?, NULL, ?, ?, ?, ?, 'ui', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateAuthProvider :execrows
-- client_secret_enc is passed through unchanged by callers that keep the
-- stored secret.
UPDATE auth_providers
SET preset               = ?,
    display_name         = ?,
    issuer               = ?,
    client_id            = ?,
    client_secret_enc    = ?,
    scopes               = ?,
    claim_map_json       = ?,
    trust_email          = ?,
    allow_signup         = ?,
    allowed_tenants_json = ?,
    position             = ?,
    idp_logout           = ?,
    updated_at           = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND org_id IS NULL AND managed_by = 'ui';

-- name: SetAuthProviderEnabled :execrows
UPDATE auth_providers
SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND org_id IS NULL AND managed_by = 'ui';

-- name: DeleteAuthProvider :execrows
DELETE FROM auth_providers
WHERE id = ? AND org_id IS NULL AND managed_by = 'ui';

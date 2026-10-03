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

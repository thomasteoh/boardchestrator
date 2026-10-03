-- name: FindUserByEmail :one
SELECT id, email, name, avatar_url, theme, timezone, created_at, deleted_at
FROM users
WHERE email = ?
  AND deleted_at IS NULL;

-- name: CreateUser :exec
INSERT INTO users (id, email, name, avatar_url)
VALUES (?, ?, ?, ?);

-- name: FindUserByEmailAnyState :one
-- Login resolution (SPEC s7.3 step 3): includes deleted users so a deleted
-- account's email is refused rather than tripping the UNIQUE constraint.
-- email_verified = 0 (a passkey bootstrap claim, WU-612) is never linked to.
SELECT id, deleted_at, email_verified
FROM users
WHERE email = ?;

-- name: LinkIdentity :exec
INSERT INTO identities (id, user_id, provider, subject, email, last_login_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: FindIdentityForLogin :one
-- Login resolution (SPEC s7.3 step 1): (provider, subject) first, with the
-- owning user's deletion state so a deleted user is refused.
SELECT i.id, i.user_id, u.deleted_at
FROM identities i
JOIN users u ON u.id = i.user_id
WHERE i.provider = ?
  AND i.subject = ?;

-- name: TouchIdentityLogin :exec
UPDATE identities
SET email = ?, last_login_at = ?
WHERE id = ?;

-- name: SetIdentityTokenByID :exec
UPDATE identities
SET token_enc = ?
WHERE id = ?;

-- name: FindIdentityByProviderSubject :one
SELECT id, user_id, provider, subject, email
FROM identities
WHERE provider = ?
  AND subject = ?;

-- name: FindIdentityByUserAndProvider :one
SELECT id, user_id, provider, subject, email, token_enc
FROM identities
WHERE user_id = ?
  AND provider = ?;

-- name: SetIdentityToken :exec
UPDATE identities
SET token_enc = ?
WHERE user_id = ?
  AND provider = ?;

-- name: GetUser :one
SELECT id, email, name, avatar_url, theme, timezone, created_at, deleted_at
FROM users
WHERE id = ?;

-- name: UpdateUserTheme :exec
UPDATE users SET theme = ? WHERE id = ?;

-- name: UpdateUserTimezone :exec
UPDATE users SET timezone = ? WHERE id = ?;

-- name: GetPlatformSettings :one
SELECT id, context, bootstrap_done, settings_json
FROM platform_settings
WHERE id = 1;

-- name: SetBootstrapDone :exec
-- Claiming the platform also forgets any generated bootstrap token hash.
UPDATE platform_settings
SET bootstrap_done = 1,
    settings_json = json_remove(settings_json, '$.bootstrap_token_hash')
WHERE id = 1;

-- name: SetBootstrapTokenHash :execrows
-- Stores the SHA-256 of a generated bootstrap token (WU-605) while the
-- platform is unclaimed. The token itself is never stored.
UPDATE platform_settings
SET settings_json = json_set(settings_json, '$.bootstrap_token_hash', CAST(sqlc.arg(token_hash) AS TEXT))
WHERE id = 1 AND bootstrap_done = 0;

-- name: ListSignInIdentities :many
-- Settings -> Sign-in methods (WU-604): the caller's identities with the
-- provider's display name. Never selects token_enc.
SELECT i.id, i.provider, COALESCE(p.display_name, '') AS display_name, i.email,
       i.last_login_at, i.created_at
FROM identities i
LEFT JOIN auth_providers p ON p.id = i.provider
WHERE i.user_id = ?
ORDER BY COALESCE(i.created_at, ''), i.id;

-- name: FindUserIdentity :one
SELECT id, provider, email
FROM identities
WHERE id = ?
  AND user_id = ?;

-- name: CountUserIdentities :one
SELECT COUNT(*) FROM identities WHERE user_id = ?;

-- name: DeleteUserIdentity :execrows
-- identity.unlink: a user can only unlink their own identities.
DELETE FROM identities
WHERE id = ?
  AND user_id = ?;

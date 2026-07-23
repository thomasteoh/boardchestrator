-- name: FindUserByEmail :one
SELECT id, email, name, avatar_url, theme, timezone, created_at, deleted_at
FROM users
WHERE email = ?
  AND deleted_at IS NULL;

-- name: CreateUser :exec
INSERT INTO users (id, email, name, avatar_url)
VALUES (?, ?, ?, ?);

-- name: LinkIdentity :exec
INSERT INTO identities (id, user_id, provider, subject, email)
VALUES (?, ?, ?, ?, ?);

-- name: FindIdentityByProviderSubject :one
SELECT id, user_id, provider, subject, email
FROM identities
WHERE provider = ?
  AND subject = ?;

-- name: GetUser :one
SELECT id, email, name, avatar_url, theme, timezone, created_at, deleted_at
FROM users
WHERE id = ?;

-- name: GetPlatformSettings :one
SELECT id, context, bootstrap_done, settings_json
FROM platform_settings
WHERE id = 1;

-- name: SetBootstrapDone :exec
UPDATE platform_settings
SET bootstrap_done = 1
WHERE id = 1;

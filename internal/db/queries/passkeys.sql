-- Passkeys (WU-612, SPEC s7.9). webauthn_credentials and users are
-- platform-scoped (no org_id): every query here is pinned to a user id or
-- looks a credential up by its globally unique credential id.

-- name: GetUserWebAuthnHandle :one
SELECT id, email, name, webauthn_handle, deleted_at
FROM users
WHERE id = ?;

-- name: SetUserWebAuthnHandle :execrows
-- Lazily assigns the user handle; never replaces one.
UPDATE users
SET webauthn_handle = sqlc.arg(handle)
WHERE id = sqlc.arg(id)
  AND webauthn_handle IS NULL;

-- name: CreateUserWithPasskey :exec
-- First-method sign-up with a passkey: the user and its handle together.
INSERT INTO users (id, email, name, webauthn_handle, email_verified)
VALUES (?, ?, ?, ?, ?);

-- name: CreateWebAuthnCredential :exec
INSERT INTO webauthn_credentials (
    id, user_id, credential_id, public_key, sign_count, aaguid, transports_json,
    attestation_type, attestation_format, user_verified, backup_eligible, backup_state,
    name, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: FindWebAuthnCredentialForLogin :one
-- Usernameless sign-in: the credential the authenticator chose, with its
-- owner's handle and deletion state.
SELECT c.id, c.user_id, c.credential_id, c.public_key, c.sign_count, c.aaguid,
       c.transports_json, c.attestation_type, c.attestation_format,
       c.user_verified, c.backup_eligible, c.backup_state,
       u.webauthn_handle, u.email, u.name, u.deleted_at
FROM webauthn_credentials c
JOIN users u ON u.id = c.user_id
WHERE c.credential_id = ?;

-- name: GetWebAuthnCredentialCount :one
-- The stored sign count, read again inside the sign-in transaction.
SELECT sign_count, user_id
FROM webauthn_credentials
WHERE id = ?;

-- name: UpdateWebAuthnCredentialLogin :execrows
UPDATE webauthn_credentials
SET sign_count = sqlc.arg(sign_count),
    user_verified = sqlc.arg(user_verified),
    backup_state = sqlc.arg(backup_state),
    last_used_at = sqlc.arg(last_used_at)
WHERE id = sqlc.arg(id)
  AND user_id = sqlc.arg(user_id);

-- name: ListUserWebAuthnCredentialIDs :many
-- Registration excludes the authenticators the user already has.
SELECT credential_id, transports_json
FROM webauthn_credentials
WHERE user_id = ?
ORDER BY created_at, id;

-- name: ListUserPasskeys :many
-- passkey.list and Settings -> Sign-in methods. Never selects key material.
SELECT id, name, aaguid, backup_eligible, backup_state, created_at, last_used_at
FROM webauthn_credentials
WHERE user_id = ?
ORDER BY created_at, id;

-- name: CountUserWebAuthnCredentials :one
SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?;

-- name: RenameUserPasskey :execrows
UPDATE webauthn_credentials
SET name = sqlc.arg(name)
WHERE id = sqlc.arg(id)
  AND user_id = sqlc.arg(user_id);

-- name: FindUserPasskey :one
SELECT id, name
FROM webauthn_credentials
WHERE id = ?
  AND user_id = ?;

-- name: DeleteUserPasskey :execrows
DELETE FROM webauthn_credentials
WHERE id = ?
  AND user_id = ?;

-- name: DeleteUserWebAuthnCredentials :exec
-- user.delete erases every passkey of the departing user.
DELETE FROM webauthn_credentials WHERE user_id = ?;

-- name: SetPlatformPasskeysEnabled :exec
-- Platform setting passkeys_enabled (absent = on), stored as 0/1.
UPDATE platform_settings
SET settings_json = json_set(settings_json, '$.passkeys_enabled', CAST(sqlc.arg(enabled) AS INTEGER))
WHERE id = 1;

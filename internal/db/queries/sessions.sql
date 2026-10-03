-- name: CreateSession :exec
INSERT INTO sessions (token_hash, user_id, ip, ua, created_at, last_seen_at, expires_at,
                      provider_id, auth_method, idp_sid, idp_subject, id_token_enc)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
-- SPEC s7.10: a session whose user is deleted does not resolve.
SELECT s.token_hash, s.user_id, s.ip, s.ua, s.created_at, s.last_seen_at, s.expires_at,
       s.provider_id, s.auth_method
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = ?
  AND u.deleted_at IS NULL;

-- name: ListSessionsByUser :many
SELECT token_hash, user_id, ip, ua, created_at, last_seen_at, expires_at
FROM sessions
WHERE user_id = ?
ORDER BY created_at DESC;

-- name: TouchSession :exec
UPDATE sessions
SET last_seen_at = ?, expires_at = ?
WHERE token_hash = ?;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE token_hash = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions
WHERE expires_at <= ?;

-- name: DeleteUserSession :execrows
-- session.revoke: a user can only revoke their own sessions.
DELETE FROM sessions
WHERE token_hash = ? AND user_id = ?;

-- name: GetSessionLogoutInfo :one
-- RP-initiated logout (SPEC s7.6): the provider a session signed in through
-- and its sealed ID token (the id_token_hint).
SELECT provider_id, id_token_enc
FROM sessions
WHERE token_hash = ?;

-- name: DeleteSessionsByIdPSID :execrows
-- Back-channel logout by IdP session id (SPEC s7.6). Callers never pass an
-- empty sid.
DELETE FROM sessions
WHERE provider_id = ? AND idp_sid = ?;

-- name: DeleteSessionsByIdPSIDSubject :execrows
-- Back-channel logout naming both sid and sub: the sessions must match both.
DELETE FROM sessions
WHERE provider_id = ? AND idp_sid = ? AND idp_subject = ?;

-- name: DeleteSessionsByIdPSubject :execrows
-- Back-channel logout by subject: every session of that IdP user. Callers
-- never pass an empty subject.
DELETE FROM sessions
WHERE provider_id = ? AND idp_subject = ?;

-- name: DeleteSessionsBySubjectSIDs :execrows
-- SAML IdP-initiated logout naming a NameID and one or more SessionIndex
-- values (sqlc.slice): sessions must match the subject and one of them.
DELETE FROM sessions
WHERE provider_id = ? AND idp_subject = ? AND idp_sid IN (sqlc.slice('sids'));

-- name: CreateSession :exec
INSERT INTO sessions (token_hash, user_id, ip, ua, created_at, last_seen_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT token_hash, user_id, ip, ua, created_at, last_seen_at, expires_at
FROM sessions
WHERE token_hash = ?;

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

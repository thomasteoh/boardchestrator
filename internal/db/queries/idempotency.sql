-- name: GetIdempotencyKey :one
SELECT key, actor, action, result_json, created_at
FROM idempotency_keys
WHERE key = ?;

-- name: CreateIdempotencyKey :exec
INSERT INTO idempotency_keys (key, actor, action, result_json, created_at)
VALUES (?, ?, ?, ?, ?);

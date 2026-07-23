-- name: EnqueueJob :exec
INSERT INTO jobs (id, kind, payload_json, run_at, max_attempts)
VALUES (:id, :kind, :payload_json, :run_at, :max_attempts);

-- name: ListQueuedJobs :many
SELECT * FROM jobs
WHERE status = 'queued' AND run_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
ORDER BY run_at ASC
LIMIT 25;

-- name: ClaimJob :one
UPDATE jobs
SET status = 'running', locked_by = :locked_by, locked_at = :locked_at
WHERE id = :id
  AND status = 'queued'
  AND run_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
RETURNING *;

-- name: MarkJobComplete :exec
UPDATE jobs
SET status = 'succeeded', locked_by = NULL, locked_at = NULL
WHERE id = :id;

-- name: MarkJobFailed :exec
UPDATE jobs
SET status = :status, attempts = :attempts, run_at = :run_at, locked_by = NULL, locked_at = NULL
WHERE id = :id;

-- name: MarkJobDead :exec
UPDATE jobs
SET status = 'dead', locked_by = NULL, locked_at = NULL
WHERE id = :id;

-- name: RequeueJob :exec
UPDATE jobs
SET status = 'queued', attempts = 0, run_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), locked_by = NULL, locked_at = NULL
WHERE id = :id;

-- name: ListDeadJobs :many
SELECT * FROM jobs
WHERE status = 'dead'
ORDER BY created_at DESC;

-- name: GetQueueDepth :many
SELECT status, count(*) FROM jobs
WHERE status IN ('queued', 'running', 'dead')
GROUP BY status;

-- name: GetQueueOldestAge :one
SELECT jobs.run_at
FROM jobs
WHERE status = 'queued'
ORDER BY run_at ASC
LIMIT 1;

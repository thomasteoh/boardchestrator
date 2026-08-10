-- name: CreateApproval :one
INSERT INTO approvals (id, org_id, run_id, action_name, input_json, status)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, org_id, run_id, action_name, input_json, status, requested_at, decided_by, decided_at;

-- name: FindApprovalByID :one
SELECT id, org_id, run_id, action_name, input_json, status, requested_at, decided_by, decided_at
FROM approvals
WHERE id = ? AND org_id = ?;

-- name: FindApprovalForRun :one
SELECT id, org_id, run_id, action_name, input_json, status, requested_at, decided_by, decided_at
FROM approvals
WHERE run_id = ? AND org_id = ? AND action_name = ? AND input_json = ?
ORDER BY requested_at DESC
LIMIT 1;

-- name: FindPendingApprovalForRun :one
SELECT id, org_id, run_id, action_name, input_json, status, requested_at, decided_by, decided_at
FROM approvals
WHERE run_id = ? AND org_id = ? AND action_name = ? AND input_json = ? AND status = 'pending';

-- name: DecideApproval :one
UPDATE approvals
SET status = ?, decided_by = ?, decided_at = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, run_id, action_name, input_json, status, requested_at, decided_by, decided_at;

-- name: ListApprovalsByRun :many
SELECT id, org_id, run_id, action_name, input_json, status, requested_at, decided_by, decided_at
FROM approvals
WHERE run_id = ? AND org_id = ?
ORDER BY requested_at ASC;

-- name: ListPendingApprovalsByOrg :many
SELECT id, org_id, run_id, action_name, input_json, status, requested_at, decided_by, decided_at
FROM approvals
WHERE org_id = ? AND status = 'pending'
ORDER BY requested_at ASC
LIMIT ?;

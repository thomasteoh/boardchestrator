-- Compliant fixture for the check-scope self-test: the query below binds
-- org_id, so the gate must not flag it.

-- name: ListTasksScoped :many
SELECT id, title
FROM tasks
WHERE org_id = ? AND state = ?;

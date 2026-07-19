-- Deliberately violating fixture for the check-scope self-test.
-- Lives outside internal/db/queries so sqlc never reads it and the repo
-- scan never flags it. Do not "fix" this query.

-- name: ListTasksUnscoped :many
SELECT id, title
FROM tasks
WHERE state = ?;

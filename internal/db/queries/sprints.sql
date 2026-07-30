-- name: ListSprints :many
SELECT id, org_id, project_id, name, starts_on, ends_on, state, created_at
FROM sprints
WHERE project_id = ?
ORDER BY starts_on DESC;

-- name: FindSprint :one
SELECT id, org_id, project_id, name, starts_on, ends_on, state, created_at
FROM sprints
WHERE id = ? AND project_id = ?;

-- name: FindActiveSprint :one
SELECT id, org_id, project_id, name, starts_on, ends_on, state, created_at
FROM sprints
WHERE project_id = ? AND state = 'active'
ORDER BY starts_on DESC
LIMIT 1;

-- name: CreateSprint :one
INSERT INTO sprints (id, org_id, project_id, name, starts_on, ends_on, state)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, project_id, name, starts_on, ends_on, state, created_at;

-- name: UpdateSprint :one
UPDATE sprints SET name = ?, starts_on = ?, ends_on = ?, state = ?
WHERE id = ? AND project_id = ?
RETURNING id, org_id, project_id, name, starts_on, ends_on, state, created_at;

-- name: CloseSprint :one
UPDATE sprints SET state = 'closed'
WHERE id = ? AND project_id = ?
RETURNING id, org_id, project_id, name, starts_on, ends_on, state, created_at;

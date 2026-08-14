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

-- WU-504: sprint snapshots (burndown/burnup).
-- name: UpsertSprintSnapshot :one
INSERT INTO sprint_snapshots (id, sprint_id, project_id, org_id, taken_on, total_points, done_points, open_count, done_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (sprint_id, taken_on) DO UPDATE SET
  total_points = excluded.total_points,
  done_points = excluded.done_points,
  open_count = excluded.open_count,
  done_count = excluded.done_count
RETURNING id, sprint_id, project_id, org_id, taken_on, total_points, done_points, open_count, done_count, created_at;

-- name: ListSprintSnapshots :many
SELECT id, sprint_id, project_id, org_id, taken_on, total_points, done_points, open_count, done_count, created_at
FROM sprint_snapshots
WHERE sprint_id = ?
ORDER BY taken_on ASC;

-- name: SprintTaskTotals :one
SELECT
  COUNT(*) AS total_count,
  COALESCE(SUM(points), 0) AS total_points,
  COALESCE(SUM(CASE WHEN status = 'done' THEN points ELSE 0 END), 0) AS done_points,
  COALESCE(SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END), 0) AS done_count
FROM tasks
WHERE sprint_id = ? AND project_id = ?;

-- name: FindSprintByID :one
SELECT id, org_id, project_id, name, starts_on, ends_on, state, created_at
FROM sprints
WHERE id = ?;

-- Active sprints across all projects/orgs for the daily snapshot job.
-- name: ListActiveSprints :many
SELECT s.id, s.org_id, s.project_id, s.name, s.starts_on, s.ends_on, s.state
FROM sprints s
WHERE s.state = 'active'
ORDER BY s.starts_on ASC;

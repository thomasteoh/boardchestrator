-- WU-504: flow metrics + project distributions for reports.

-- Cycle/lead time source: task_activity rows. A task's lead time is from
-- task.create to the first move into a done status; cycle time is from the
-- first move into an in-progress status to that same done transition.
-- name: ListProjectTaskActivity :many
SELECT id, task_id, project_id, actor_id, actor_type, action, detail_json, created_at
FROM task_activity
WHERE project_id = ?
  AND action IN ('task.create', 'task.move', 'task.update')
ORDER BY task_id, created_at ASC;

-- Project distributions: task counts + points per project in an org.
-- name: ProjectDistributions :many
SELECT p.id AS project_id, p.name,
       COUNT(t.id) AS task_count,
       COALESCE(SUM(t.points), 0) AS total_points,
       COALESCE(SUM(CASE WHEN t.status = 'done' THEN 1 ELSE 0 END), 0) AS done_count
FROM projects p
LEFT JOIN tasks t ON t.project_id = p.id
WHERE p.org_id = ?
GROUP BY p.id, p.name
ORDER BY task_count DESC;

-- Filtered task list for CSV export (report.csv / report.tasks).
-- name: ListTasksByProjectStatus :many
SELECT id, project_id, key, title, description, points, priority, status, due_at, created_at, updated_at
FROM tasks
WHERE project_id = ? AND (? = '' OR status = ?)
ORDER BY key;

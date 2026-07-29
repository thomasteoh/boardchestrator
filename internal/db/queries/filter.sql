-- name: CreateSavedFilter :one
INSERT INTO saved_filters (id, project_id, name, query_json, pinned, created_by)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, project_id, name, query_json, pinned, created_by, created_at, updated_at;

-- name: UpdateSavedFilter :one
UPDATE saved_filters SET name = ?, query_json = ?, pinned = ?, updated_at = ?
WHERE id = ? AND project_id = ?
RETURNING id, project_id, name, query_json, pinned, created_by, created_at, updated_at;

-- name: DeleteSavedFilter :exec
DELETE FROM saved_filters WHERE id = ? AND project_id = ?;

-- name: ListSavedFiltersByProject :many
SELECT id, project_id, name, query_json, pinned, created_by, created_at, updated_at
FROM saved_filters
WHERE project_id = ?
ORDER BY pinned DESC, name ASC;

-- name: FilterTasksByProject :many
SELECT t.id, t.project_id, t.title, t.description, t.key, t.points, t.priority, t.status, t.due_at, t.sort_order, t.created_at, t.updated_at
FROM tasks t
WHERE t.project_id = ?
  AND (? = '' OR t.status IN (SELECT value FROM json_each(?)))
  AND (? = '' OR t.id IN (SELECT task_id FROM task_assignees WHERE user_id IN (SELECT value FROM json_each(?))))
  AND (? = '' OR t.id IN (SELECT task_id FROM task_labels WHERE label_id IN (SELECT value FROM json_each(?))))
  AND (? = '' OR t.title LIKE '%' || ? || '%')
ORDER BY t.sort_order ASC, t.created_at ASC;

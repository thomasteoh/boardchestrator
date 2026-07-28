-- name: CreateTask :one
INSERT INTO tasks (id, project_id, title, description, key, key_num, points, priority, status, due_at, sort_order)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, project_id, title, description, key, key_num, points, priority, status, due_at, sort_order, created_at, updated_at;

-- name: UpdateTask :one
UPDATE tasks SET title = ?, description = ?, points = ?, priority = ?, due_at = ?, sort_order = ?, status = ?, updated_at = ?
WHERE id = ? AND project_id = ?
RETURNING id, project_id, title, description, key, points, priority, status, due_at, sort_order, created_at, updated_at;

-- name: FindTaskByID :one
SELECT id, project_id, title, description, key, points, priority, status, due_at, sort_order, created_at, updated_at
FROM tasks
WHERE id = ? AND project_id = ?;

-- name: ListTasksByProject :many
SELECT id, project_id, title, description, key, points, priority, status, due_at, sort_order, created_at, updated_at
FROM tasks
WHERE project_id = ?
ORDER BY sort_order ASC, created_at ASC;

-- name: ArchiveTask :exec
UPDATE tasks SET archived = 1, updated_at = ?
WHERE id = ? AND project_id = ?;

-- name: UnarchiveTask :exec
UPDATE tasks SET archived = 0, updated_at = ?
WHERE id = ? AND project_id = ?;

-- name: NextTaskNum :one
SELECT COALESCE(MAX(key_num), 0) + 1
FROM tasks
WHERE project_id = ?;

-- name: CreateLabel :one
INSERT INTO labels (id, org_id, name, color, description)
VALUES (?, ?, ?, ?, ?)
RETURNING id, org_id, name, color, description, created_at;

-- name: UpdateLabel :one
UPDATE labels SET name = ?, color = ?, description = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, name, color, description, created_at;

-- name: FindLabelByID :one
SELECT id, org_id, name, color, description, created_at
FROM labels
WHERE id = ? AND org_id = ?;

-- name: ListLabelsByOrg :many
SELECT id, org_id, name, color, description, created_at
FROM labels
WHERE org_id = ?
ORDER BY name ASC;

-- name: ClearTaskLabels :exec
DELETE FROM task_labels WHERE task_id = ? AND project_id = ?;

-- name: AddTaskLabel :exec
INSERT INTO task_labels (task_id, project_id, label_id)
VALUES (?, ?, ?);

-- name: GetTaskLabels :many
SELECT tl.task_id, tl.project_id, tl.label_id, l.name, l.color
FROM task_labels tl
JOIN labels l ON l.id = tl.label_id AND l.org_id = ?
WHERE tl.task_id = ? AND tl.project_id = ?;

-- name: CreateTaskRelation :one
INSERT INTO task_relations (id, task_id, related_task_id, relation_type, project_id)
VALUES (?, ?, ?, ?, ?)
RETURNING id, task_id, related_task_id, relation_type, project_id, created_at;

-- name: ListTaskRelations :many
SELECT id, task_id, related_task_id, relation_type, project_id, created_at
FROM task_relations
WHERE (task_id = ? OR related_task_id = ?) AND project_id = ?;

-- name: DeleteTaskRelation :exec
DELETE FROM task_relations
WHERE id = ? AND project_id = ?;

-- name: ClearTaskAssignees :exec
DELETE FROM task_assignees WHERE task_id = ? AND project_id = ?;

-- name: AddTaskAssignee :exec
INSERT INTO task_assignees (task_id, project_id, user_id)
VALUES (?, ?, ?);

-- name: GetTaskAssignees :many
SELECT ta.task_id, ta.project_id, ta.user_id, u.name, u.email
FROM task_assignees ta
JOIN users u ON u.id = ta.user_id
WHERE ta.task_id = ? AND ta.project_id = ?;

-- name: ClearTaskWatchers :exec
DELETE FROM task_watchers WHERE task_id = ? AND project_id = ?;

-- name: AddTaskWatcher :exec
INSERT INTO task_watchers (task_id, project_id, user_id)
VALUES (?, ?, ?);

-- name: GetTaskWatchers :many
SELECT tw.task_id, tw.project_id, tw.user_id, u.name, u.email
FROM task_watchers tw
JOIN users u ON u.id = tw.user_id
WHERE tw.task_id = ? AND tw.project_id = ?;

-- name: CreateComment :one
INSERT INTO comments (id, task_id, project_id, author_id, body)
VALUES (?, ?, ?, ?, ?)
RETURNING id, task_id, project_id, author_id, body, created_at, updated_at;

-- name: UpdateComment :one
UPDATE comments SET body = ?, updated_at = ?
WHERE id = ? AND task_id = ? AND project_id = ?
RETURNING id, task_id, project_id, author_id, body, created_at, updated_at;

-- name: DeleteComment :exec
DELETE FROM comments
WHERE id = ? AND task_id = ? AND project_id = ?;

-- name: ListCommentsByTask :many
SELECT id, task_id, project_id, author_id, body, created_at, updated_at
FROM comments
WHERE task_id = ? AND project_id = ?
ORDER BY created_at ASC;

-- name: CreateTaskActivity :one
INSERT INTO task_activity (id, task_id, project_id, actor_id, actor_type, action, detail_json)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, task_id, project_id, actor_id, actor_type, action, detail_json, created_at;

-- name: ListTaskActivity :many
SELECT id, task_id, project_id, actor_id, actor_type, action, detail_json, created_at
FROM task_activity
WHERE task_id = ? AND project_id = ?
ORDER BY created_at DESC;

-- name: CreateCustomFieldDef :one
INSERT INTO custom_field_defs (id, org_id, name, kind, config_json)
VALUES (?, ?, ?, ?, ?)
RETURNING id, org_id, name, kind, config_json, created_at;

-- name: ListCustomFieldDefsByOrg :many
SELECT id, org_id, name, kind, config_json, created_at
FROM custom_field_defs
WHERE org_id = ?
ORDER BY name ASC;

-- name: ClearTaskCustomFields :exec
DELETE FROM task_custom_field_values WHERE task_id = ? AND project_id = ?;

-- name: AddTaskCustomField :exec
INSERT INTO task_custom_field_values (task_id, project_id, field_def_id, value)
VALUES (?, ?, ?, ?);

-- name: GetTaskCustomFields :many
SELECT tcfv.task_id, tcfv.project_id, tcfv.field_def_id, tcfv.value, cfd.name, cfd.kind
FROM task_custom_field_values tcfv
JOIN custom_field_defs cfd ON cfd.id = tcfv.field_def_id AND cfd.org_id = ?
WHERE tcfv.task_id = ? AND tcfv.project_id = ?;

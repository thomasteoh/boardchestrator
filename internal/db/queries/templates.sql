-- name: ListTemplates :many
SELECT id, org_id, project_id, name, title_template, description_template, points, priority, status, labels_json, created_at, updated_at
FROM task_templates
WHERE org_id = ? AND project_id = ?
ORDER BY name;

-- name: FindTemplate :one
SELECT id, org_id, project_id, name, title_template, description_template, points, priority, status, labels_json, created_at, updated_at
FROM task_templates
WHERE id = ? AND org_id = ?;

-- name: CreateTemplate :one
INSERT INTO task_templates (id, org_id, project_id, name, title_template, description_template, points, priority, status, labels_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, project_id, name, title_template, description_template, points, priority, status, labels_json, created_at, updated_at;

-- name: UpdateTemplate :one
UPDATE task_templates SET name = ?, title_template = ?, description_template = ?, points = ?, priority = ?, status = ?, labels_json = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, project_id, name, title_template, description_template, points, priority, status, labels_json, created_at, updated_at;

-- name: DeleteTemplate :exec
DELETE FROM task_templates
WHERE id = ? AND org_id = ?;

-- name: ListRecurringRules :many
SELECT id, org_id, project_id, template_id, cron_expr, next_at, enabled, created_at, updated_at
FROM recurring_rules
WHERE org_id = ? AND project_id = ?
ORDER BY created_at;

-- name: FindRecurringRule :one
SELECT id, org_id, project_id, template_id, cron_expr, next_at, enabled, created_at, updated_at
FROM recurring_rules
WHERE id = ? AND org_id = ?;

-- name: CreateRecurringRule :one
INSERT INTO recurring_rules (id, org_id, project_id, template_id, cron_expr, next_at, enabled)
VALUES (?, ?, ?, ?, ?, '', 1)
RETURNING id, org_id, project_id, template_id, cron_expr, next_at, enabled, created_at, updated_at;

-- name: UpdateRecurringRule :one
UPDATE recurring_rules SET cron_expr = ?, next_at = ?, enabled = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, project_id, template_id, cron_expr, next_at, enabled, created_at, updated_at;

-- name: DeleteRecurringRule :exec
DELETE FROM recurring_rules
WHERE id = ? AND org_id = ?;

-- name: ListDueRecurringRules :many
SELECT id, org_id, project_id, template_id, cron_expr, next_at, enabled, created_at, updated_at
FROM recurring_rules
WHERE enabled = 1 AND next_at != '' AND next_at <= ?
ORDER BY next_at
LIMIT ?;

-- name: UpdateRecurringNextAt :exec
UPDATE recurring_rules SET next_at = ?
WHERE id = ?;

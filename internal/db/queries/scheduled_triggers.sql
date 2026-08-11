-- name: CreateScheduledTrigger :one
INSERT INTO scheduled_triggers (id, org_id, project_id, agent_id, cron_expr, prompt, next_at, enabled)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, project_id, agent_id, cron_expr, prompt, next_at, enabled, created_at, updated_at;

-- name: FindScheduledTriggerByID :one
SELECT id, org_id, project_id, agent_id, cron_expr, prompt, next_at, enabled, created_at, updated_at
FROM scheduled_triggers
WHERE id = ? AND org_id = ?;

-- name: ListScheduledTriggersByProject :many
SELECT id, org_id, project_id, agent_id, cron_expr, prompt, next_at, enabled, created_at, updated_at
FROM scheduled_triggers
WHERE org_id = ? AND project_id = ?
ORDER BY created_at ASC;

-- name: ListDueScheduledTriggers :many
-- Fired by the scheduler (WU-309): enabled triggers whose next_at is at or
-- before the given reference time. The JOIN to projects keeps the project's
-- org in scope and lets the scheduler skip paused projects via the caller.
SELECT st.id, st.org_id, st.project_id, st.agent_id, st.cron_expr, st.prompt, st.next_at, st.enabled, st.created_at, st.updated_at
FROM scheduled_triggers st
JOIN projects p ON p.id = st.project_id AND p.org_id = st.org_id
WHERE st.enabled = 1 AND st.next_at != '' AND st.next_at <= ?
ORDER BY st.next_at ASC;

-- name: UpdateScheduledTrigger :exec
UPDATE scheduled_triggers
SET cron_expr = ?, prompt = ?, agent_id = ?, enabled = ?, next_at = ?, updated_at = ?
WHERE id = ? AND org_id = ?;

-- name: DeleteScheduledTrigger :exec
DELETE FROM scheduled_triggers
WHERE id = ? AND org_id = ?;

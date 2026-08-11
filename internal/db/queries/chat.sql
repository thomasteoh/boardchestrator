-- name: CreateChatSession :one
INSERT INTO chat_sessions (id, org_id, project_id, team_id, agent_id, name, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, project_id, team_id, agent_id, name, created_by, created_at, updated_at;

-- name: FindChatSessionByID :one
SELECT id, org_id, project_id, team_id, agent_id, name, created_by, created_at, updated_at
FROM chat_sessions
WHERE id = ? AND org_id = ?;

-- name: ListChatSessionsByOrg :many
SELECT id, org_id, project_id, team_id, agent_id, name, created_by, created_at, updated_at
FROM chat_sessions
WHERE org_id = ?
ORDER BY updated_at DESC
LIMIT ?;

-- name: ListChatSessionsByProject :many
SELECT id, org_id, project_id, team_id, agent_id, name, created_by, created_at, updated_at
FROM chat_sessions
WHERE org_id = ? AND project_id = ?
ORDER BY updated_at DESC
LIMIT ?;

-- name: TouchChatSession :exec
UPDATE chat_sessions
SET updated_at = ?
WHERE id = ? AND org_id = ?;

-- name: CreateChatMessage :exec
INSERT INTO chat_messages (id, chat_id, role, content, run_id, action_name, action_input)
SELECT ?, ?, ?, ?, ?, ?, ?
WHERE EXISTS (SELECT 1 FROM chat_sessions WHERE chat_sessions.id = ? AND chat_sessions.org_id = ?);

-- name: ListChatMessages :many
SELECT cm.id, cm.chat_id, cm.role, cm.content, cm.run_id, cm.action_name, cm.action_input, cm.created_at
FROM chat_messages cm
JOIN chat_sessions cs ON cs.id = cm.chat_id
WHERE cm.chat_id = ? AND cs.org_id = ?
ORDER BY cm.created_at ASC;

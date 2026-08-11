-- name: CreateRun :one
INSERT INTO runs (id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at;

-- name: FindRunByID :one
SELECT id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at
FROM runs
WHERE id = ? AND org_id = ?;

-- name: FindRunByTaskAndOrg :many
SELECT id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at
FROM runs
WHERE task_id = ? AND org_id = ?
ORDER BY created_at DESC;

-- name: CountActiveRunsByTask :one
SELECT COUNT(*) FROM runs
WHERE task_id = ? AND org_id = ? AND status IN ('queued', 'running', 'awaiting_approval');

-- name: CountActiveRunsByProject :one
-- WU-309 overlap guard: skip firing a schedule when the project already has
-- an active run (queued/running/awaiting_approval) so schedules don't pile up.
SELECT COUNT(*) FROM runs
WHERE project_id = ? AND org_id = ? AND status IN ('queued', 'running', 'awaiting_approval');

-- name: ListRunsByOrg :many
SELECT id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at
FROM runs
WHERE org_id = ?
ORDER BY created_at DESC
LIMIT ?;

-- name: StartRun :one
UPDATE runs
SET status = 'running', started_at = ?, error = ''
WHERE id = ? AND org_id = ? AND status = 'queued'
RETURNING id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at;

-- name: FinishRun :one
UPDATE runs
SET status = ?, finished_at = ?, error = ?, prompt_tokens = ?, completion_tokens = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at;

-- name: SetRunAwaitingApproval :one
UPDATE runs
SET status = 'awaiting_approval'
WHERE id = ? AND org_id = ?
RETURNING id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at;

-- name: RequeueRun :one
UPDATE runs
SET status = 'queued', error = ''
WHERE id = ? AND org_id = ? AND status = 'awaiting_approval'
RETURNING id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at;

-- name: CancelRun :one
UPDATE runs
SET status = 'cancelled', finished_at = ?, error = ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at;

-- name: AddRunTokens :one
UPDATE runs
SET prompt_tokens = prompt_tokens + ?, completion_tokens = completion_tokens + ?
WHERE id = ? AND org_id = ?
RETURNING id, org_id, agent_id, trigger, task_id, chat_session_id, project_id, initiated_by, status, error, prompt_tokens, completion_tokens, created_at, started_at, finished_at;

-- name: CountRunningRunsForAgent :one
SELECT COUNT(*) FROM runs
WHERE agent_id = ? AND org_id = ? AND status IN ('queued', 'running', 'awaiting_approval');

-- name: CountRunsByAgentSince :one
SELECT COUNT(*) FROM runs
WHERE agent_id = ? AND org_id = ? AND created_at >= ?;

-- name: CreateRunStep :exec
INSERT INTO run_steps (id, run_id, seq, kind, request_json, response_json, tokens)
SELECT ?, ?, ?, ?, ?, ?, ?
WHERE EXISTS (SELECT 1 FROM runs WHERE runs.id = ? AND runs.org_id = ?);

-- name: ListRunSteps :many
SELECT rs.id, rs.run_id, rs.seq, rs.kind, rs.request_json, rs.response_json, rs.tokens, rs.created_at
FROM run_steps rs
JOIN runs r ON r.id = rs.run_id
WHERE rs.run_id = ? AND r.org_id = ?
ORDER BY rs.seq ASC;

-- name: ListAgentSkillsWithActions :many
SELECT s.id, s.org_id, s.name, s.version, s.description, s.instructions, s.allowed_actions_json, s.param_schema_json, s.mcp_endpoints_enc
FROM agent_skills asg
JOIN skills s ON s.id = asg.skill_id
JOIN agents a ON a.id = asg.agent_id
WHERE asg.agent_id = ? AND a.org_id = ?
ORDER BY asg.created_at;

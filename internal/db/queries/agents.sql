-- name: CreateAgent :one
INSERT INTO agents (id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at;

-- name: UpdateAgent :one
UPDATE agents SET
  name = ?, provider_id = ?, model = ?, context = ?, role_id = ?, retry_max = ?, backoff_secs = ?, runs_per_hour = ?, token_budget = ?, approval_policy_json = ?, active = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ? AND org_id = ?
RETURNING id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at;

-- name: FindAgentByID :one
SELECT id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at
FROM agents
WHERE id = ?;

-- name: FindAgentByOrgAndName :one
SELECT id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at
FROM agents
WHERE org_id = ? AND name = ?;

-- name: FindActiveAgentByOrgAndName :one
SELECT id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at
FROM agents
WHERE org_id = ? AND name = ? AND active = 1;

-- name: ListAgentsByOrg :many
SELECT id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at
FROM agents
WHERE org_id = ?
ORDER BY name ASC;

-- name: ListAgents :many
SELECT id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at
FROM agents
ORDER BY name ASC;

-- name: DeleteAgent :exec
DELETE FROM agents WHERE id = ? AND org_id = ?;

-- name: DeactivateAllAgentsByOrg :exec
-- Kill-switch (WU-311): set every agent in an org to inactive instantly.
UPDATE agents SET active = 0 WHERE org_id = ?;

-- name: CreateAgentSkill :exec
INSERT INTO agent_skills (agent_id, skill_id)
SELECT ?, ?
WHERE EXISTS (SELECT 1 FROM agents WHERE id = ? AND org_id = ?);

-- name: DeleteAgentSkill :exec
DELETE FROM agent_skills
WHERE agent_id = ? AND skill_id = ?
  AND EXISTS (SELECT 1 FROM agents WHERE id = ? AND org_id = ?);

-- name: ListAgentSkills :many
SELECT agent_skills.skill_id
FROM agent_skills
JOIN agents ON agents.id = agent_skills.agent_id
WHERE agent_skills.agent_id = ? AND agents.org_id = ?
ORDER BY agent_skills.created_at;

-- name: ListAgentSkillActions :many
SELECT DISTINCT s.allowed_actions_json
FROM agent_skills AS a
JOIN skills AS s ON s.id = a.skill_id
JOIN agents AS g ON g.id = a.agent_id
WHERE a.agent_id = ? AND g.org_id = ?;

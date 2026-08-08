-- name: CreateAgent :one
INSERT INTO agents (id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at;

-- name: UpdateAgent :one
UPDATE agents SET
  name = ?, provider_id = ?, model = ?, context = ?, role_id = ?, retry_max = ?, backoff_secs = ?, runs_per_hour = ?, token_budget = ?, approval_policy_json = ?, active = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ?
RETURNING id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at;

-- name: FindAgentByID :one
SELECT id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at
FROM agents
WHERE id = ?;

-- name: FindAgentByOrgAndName :one
SELECT id, org_id, template_id, name, provider_id, model, context, role_id, retry_max, backoff_secs, runs_per_hour, token_budget, approval_policy_json, active, created_at, updated_at
FROM agents
WHERE org_id = ? AND name = ?;

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
DELETE FROM agents WHERE id = ?;

-- name: CreateAgentSkill :exec
INSERT INTO agent_skills (agent_id, skill_id)
VALUES (?, ?);

-- name: DeleteAgentSkill :exec
DELETE FROM agent_skills
WHERE agent_id = ? AND skill_id = ?;

-- name: ListAgentSkills :many
SELECT skill_id
FROM agent_skills
WHERE agent_id = ?
ORDER BY created_at;

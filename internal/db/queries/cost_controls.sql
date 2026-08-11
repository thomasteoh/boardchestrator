-- name: UpsertModelPricing :one
INSERT INTO model_pricing (id, provider_id, model, input_per_mtok, output_per_mtok)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(provider_id, model) DO UPDATE SET
    input_per_mtok = excluded.input_per_mtok,
    output_per_mtok = excluded.output_per_mtok,
    updated_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
RETURNING id, provider_id, model, input_per_mtok, output_per_mtok, created_at, updated_at;

-- name: FindModelPricing :one
SELECT id, provider_id, model, input_per_mtok, output_per_mtok, created_at, updated_at
FROM model_pricing
WHERE provider_id = ? AND model = ?;

-- name: ListModelPricing :many
SELECT id, provider_id, model, input_per_mtok, output_per_mtok, created_at, updated_at
FROM model_pricing
ORDER BY provider_id, model;

-- name: DeleteModelPricing :exec
DELETE FROM model_pricing
WHERE provider_id = ? AND model = ?;

-- name: GetRunPricing :one
-- Price for a run's provider+model. Returns zero rows if unpriced (caller
-- treats missing pricing as $0). Join provider+model through the agent's
-- provider/model to the pricing table.
SELECT COALESCE(p.input_per_mtok, 0) AS input_per_mtok,
       COALESCE(p.output_per_mtok, 0) AS output_per_mtok
FROM agents a
LEFT JOIN model_pricing p ON p.provider_id = a.provider_id AND p.model = a.model
WHERE a.id = ?;

-- name: SumRunStepsTokens :one
SELECT COALESCE(SUM(tokens), 0) FROM run_steps
WHERE run_id = ?;

-- name: OrgMonthlySpend :one
-- Cost of all finished runs in an org for the current UTC month, in USD.
-- Cost = sum over runs of (prompt_tokens/1M * input_per_mtok +
--                     completion_tokens/1M * output_per_mtok).
-- Runs without a pricing row count as $0.
SELECT CAST(COALESCE(SUM(
    (r.prompt_tokens / 1000000.0) * COALESCE(p.input_per_mtok, 0) +
    (r.completion_tokens / 1000000.0) * COALESCE(p.output_per_mtok, 0)
), 0) AS REAL) AS total_usd
FROM runs r
JOIN agents a ON a.id = r.agent_id
LEFT JOIN model_pricing p ON p.provider_id = a.provider_id AND p.model = a.model
WHERE r.org_id = ?
  AND r.status IN ('finished', 'cancelled')
  AND r.finished_at >= ?;

-- name: OrgMonthlyTokens :one
SELECT CAST(COALESCE(SUM(r.prompt_tokens + r.completion_tokens), 0) AS INTEGER)
FROM runs r
WHERE r.org_id = ?
  AND r.status IN ('finished', 'cancelled')
  AND r.finished_at >= ?;

-- name: AgentUsageByMonth :many
-- Per-agent cost + run count for the current month (dashboard "by agent").
SELECT a.id AS agent_id,
       a.name AS agent_name,
       COUNT(r.id) AS runs,
       CAST(COALESCE(SUM(r.prompt_tokens + r.completion_tokens), 0) AS INTEGER) AS tokens,
       CAST(COALESCE(SUM(
           (r.prompt_tokens / 1000000.0) * COALESCE(p.input_per_mtok, 0) +
           (r.completion_tokens / 1000000.0) * COALESCE(p.output_per_mtok, 0)
       ), 0) AS REAL) AS total_usd
FROM runs r
JOIN agents a ON a.id = r.agent_id
LEFT JOIN model_pricing p ON p.provider_id = a.provider_id AND p.model = a.model
WHERE r.org_id = ?
  AND r.status IN ('finished', 'cancelled')
  AND r.finished_at >= ?
GROUP BY a.id, a.name
ORDER BY total_usd DESC;

-- name: ProjectUsageByMonth :many
-- Per-project cost + run count for the current month (dashboard "by project").
SELECT r.project_id AS project_id,
       COUNT(r.id) AS runs,
       CAST(COALESCE(SUM(r.prompt_tokens + r.completion_tokens), 0) AS INTEGER) AS tokens,
       CAST(COALESCE(SUM(
           (r.prompt_tokens / 1000000.0) * COALESCE(p.input_per_mtok, 0) +
           (r.completion_tokens / 1000000.0) * COALESCE(p.output_per_mtok, 0)
       ), 0) AS REAL) AS total_usd
FROM runs r
JOIN agents a ON a.id = r.agent_id
LEFT JOIN model_pricing p ON p.provider_id = a.provider_id AND p.model = a.model
WHERE r.org_id = ?
  AND r.status IN ('finished', 'cancelled')
  AND r.finished_at >= ?
GROUP BY r.project_id
ORDER BY total_usd DESC;

-- name: CountRunsByAgentInWindow :one
-- Runs started by an agent in the last hour (WU-310 runs/hour cap).
SELECT COUNT(*) FROM runs
WHERE agent_id = ? AND org_id = ?
  AND status IN ('queued', 'running', 'awaiting_approval', 'finished', 'cancelled')
  AND created_at >= ?;

-- name: SumAgentTokensInWindow :one
-- Tokens consumed by an agent in the current UTC month (WU-310 token budget).
SELECT CAST(COALESCE(SUM(prompt_tokens + completion_tokens), 0) AS INTEGER)
FROM runs
WHERE agent_id = ? AND org_id = ?
  AND created_at >= ?;

-- name: CreateOrgCapAlert :one
INSERT INTO org_cap_alerts (id, org_id, spend_usd, cap_usd)
VALUES (?, ?, ?, ?)
RETURNING id, org_id, spend_usd, cap_usd, created_at;

-- name: ListOrgCapAlerts :many
SELECT id, org_id, spend_usd, cap_usd, created_at
FROM org_cap_alerts
WHERE org_id = ?
ORDER BY created_at DESC;

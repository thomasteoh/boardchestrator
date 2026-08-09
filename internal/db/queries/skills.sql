-- name: CreateSkill :one
INSERT INTO skills (id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc)
VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
RETURNING id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at;

-- name: CreateSkillAtVersion :one
INSERT INTO skills (id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at;

-- name: ListSkills :many
SELECT id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at
FROM skills
WHERE org_id = ?
ORDER BY name ASC, version ASC;

-- name: ListPlatformSkills :many
SELECT id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at
FROM skills
WHERE org_id IS NULL
ORDER BY name ASC, version ASC;

-- name: FindSkillByID :one
SELECT id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at
FROM skills
WHERE id = ?;

-- name: FindSkillByIDAndOrg :one
SELECT id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at
FROM skills
WHERE id = ? AND org_id = ?;

-- name: FindLatestSkillByName :one
SELECT id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at
FROM skills
WHERE org_id = ? AND name = ?
ORDER BY version DESC
LIMIT 1;

-- name: FindMaxSkillVersion :one
SELECT CAST(COALESCE(MAX(version), 0) AS INTEGER)
FROM skills
WHERE org_id = ? AND name = ?;

-- name: DeleteSkill :exec
DELETE FROM skills WHERE id = ? AND org_id = ?;

-- name: ListSkillVersions :many
SELECT id, org_id, name, version, description, instructions, allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at
FROM skills
WHERE org_id = ? AND name = ?
ORDER BY version ASC;

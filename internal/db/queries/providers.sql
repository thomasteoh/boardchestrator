-- name: CreateProvider :one
INSERT INTO providers (id, kind, name, base_url, key_enc, models_json)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, kind, name, base_url, key_enc, models_json, created_at, updated_at;

-- name: UpdateProvider :one
UPDATE providers SET
  kind = ?, name = ?, base_url = ?, key_enc = ?, models_json = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')
WHERE id = ?
RETURNING id, kind, name, base_url, key_enc, models_json, created_at, updated_at;

-- name: DeleteProvider :exec
DELETE FROM providers WHERE id = ?;

-- name: FindProviderByID :one
SELECT id, kind, name, base_url, key_enc, models_json, created_at, updated_at
FROM providers
WHERE id = ?;

-- name: ListProviders :many
SELECT id, kind, name, base_url, key_enc, models_json, created_at, updated_at
FROM providers
ORDER BY name ASC;

-- name: CreateProviderOrg :one
INSERT INTO provider_orgs (id, provider_id, org_id)
VALUES (?, ?, ?)
RETURNING id, provider_id, org_id, created_at;

-- name: DeleteProviderOrg :exec
DELETE FROM provider_orgs
WHERE provider_id = ? AND org_id = ?;

-- name: FindProviderOrg :one
SELECT id, provider_id, org_id, created_at
FROM provider_orgs
WHERE provider_id = ? AND org_id = ?;

-- name: ListProviderOrgsByProvider :many
SELECT id, provider_id, org_id, created_at
FROM provider_orgs
WHERE provider_id = ?
ORDER BY created_at;

-- name: ListProviderOrgsByOrg :many
SELECT p.id, p.kind, p.name, p.base_url, p.key_enc, p.models_json, p.created_at, p.updated_at
FROM providers p
JOIN provider_orgs po ON po.provider_id = p.id
WHERE po.org_id = ?
ORDER BY p.name ASC;

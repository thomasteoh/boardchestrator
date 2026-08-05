-- name: CreateAuditLog :exec
INSERT INTO audit_log (id, org_id, actor_type, actor_id, action, subject, detail_json, ip, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAuditLogsByOrg :many
SELECT id, org_id, actor_type, actor_id, action, subject, detail_json, ip, created_at
FROM audit_log
WHERE org_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListAuditLogsByOrgFiltered :many
SELECT id, org_id, actor_type, actor_id, action, subject, detail_json, ip, created_at
FROM audit_log
WHERE org_id = ?
  AND (? = '' OR actor_id = ?)
  AND (? = '' OR action = ?)
  AND (? = '' OR created_at >= ?)
  AND (? = '' OR created_at <= ?)
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListAuditLogsPlatform :many
SELECT id, org_id, actor_type, actor_id, action, subject, detail_json, ip, created_at
FROM audit_log
WHERE org_id IS NULL
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: CountAuditLogsByOrg :one
SELECT COUNT(*) FROM audit_log WHERE org_id = ?;

-- name: CountAuditLogsByOrgFiltered :one
SELECT COUNT(*) FROM audit_log
WHERE org_id = ?
  AND (? = '' OR actor_id = ?)
  AND (? = '' OR action = ?)
  AND (? = '' OR created_at >= ?)
  AND (? = '' OR created_at <= ?);

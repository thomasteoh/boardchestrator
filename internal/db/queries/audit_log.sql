-- name: CreateAuditLog :exec
INSERT INTO audit_log (id, org_id, actor_type, actor_id, action, subject, detail_json, ip, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

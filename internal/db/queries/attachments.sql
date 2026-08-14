-- name: CreateAttachment :one
INSERT INTO attachments (id, org_id, task_id, uploader_id, filename, mime, size, storage_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, task_id, uploader_id, filename, mime, size, storage_key, created_at;

-- name: GetAttachment :one
SELECT id, org_id, task_id, uploader_id, filename, mime, size, storage_key, created_at
FROM attachments
WHERE id = ?;

-- name: GetAttachmentByKey :one
SELECT id, org_id, task_id, uploader_id, filename, mime, size, storage_key, created_at
FROM attachments
WHERE storage_key = ?;

-- name: DeleteAttachment :exec
DELETE FROM attachments WHERE id = ? AND org_id = ?;

-- name: ListAttachmentsByTask :many
SELECT id, org_id, task_id, uploader_id, filename, mime, size, storage_key, created_at
FROM attachments
WHERE task_id = ?
ORDER BY created_at;

-- name: ListAttachmentsByOrg :many
SELECT id, org_id, task_id, uploader_id, filename, mime, size, storage_key, created_at
FROM attachments
WHERE org_id = ?
ORDER BY created_at;

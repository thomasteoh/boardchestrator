-- name: CreateWebhook :one
INSERT INTO webhooks (id, org_id, team_id, name, url, secret, event_filter, enabled)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, team_id, name, url, secret, event_filter, enabled, created_at, updated_at;

-- name: FindWebhookByID :one
SELECT id, org_id, team_id, name, url, secret, event_filter, enabled, created_at, updated_at
FROM webhooks
WHERE id = ? AND org_id = ?;

-- name: ListWebhooksByOrg :many
SELECT id, org_id, team_id, name, url, secret, event_filter, enabled, created_at, updated_at
FROM webhooks
WHERE org_id = ?
ORDER BY created_at ASC;

-- name: ListWebhooksByTeam :many
SELECT id, org_id, team_id, name, url, secret, event_filter, enabled, created_at, updated_at
FROM webhooks
WHERE org_id = ? AND team_id = ?
ORDER BY created_at ASC;

-- name: ListEnabledWebhooksByOrg :many
-- Fetched by the delivery worker (WU-404): enabled webhooks in an org, used to
-- match events against their event_filter.
SELECT id, org_id, team_id, name, url, secret, event_filter, enabled, created_at, updated_at
FROM webhooks
WHERE org_id = ? AND enabled = 1;

-- name: UpdateWebhook :exec
UPDATE webhooks
SET name = ?, url = ?, secret = ?, event_filter = ?, enabled = ?, updated_at = ?
WHERE id = ? AND org_id = ?;

-- name: DeleteWebhook :exec
DELETE FROM webhooks
WHERE id = ? AND org_id = ?;

-- name: CreateWebhookDelivery :one
INSERT INTO webhook_deliveries (id, webhook_id, event_name, event_json, status, max_attempts)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, webhook_id, event_name, event_json, status, attempts, max_attempts, response_code, error, created_at, updated_at;

-- name: ListQueuedWebhookDeliveries :many
-- Polled by the delivery worker: queued deliveries due now.
SELECT id, webhook_id, event_name, event_json, status, attempts, max_attempts, response_code, error, created_at, updated_at
FROM webhook_deliveries
WHERE status = 'queued' AND created_at <= ?
ORDER BY created_at ASC;

-- name: UpdateWebhookDeliveryAttempt :exec
UPDATE webhook_deliveries
SET status = ?, attempts = ?, response_code = ?, error = ?, updated_at = ?
WHERE id = ?;

-- name: FindWebhookDeliveryByID :one
SELECT id, webhook_id, event_name, event_json, status, attempts, max_attempts, response_code, error, created_at, updated_at
FROM webhook_deliveries
WHERE id = ?;

-- name: ListWebhookDeliveries :many
-- Delivery log for a webhook (delivery log UI).
SELECT id, webhook_id, event_name, event_json, status, attempts, max_attempts, response_code, error, created_at, updated_at
FROM webhook_deliveries
WHERE webhook_id = ?
ORDER BY created_at DESC
LIMIT 100;

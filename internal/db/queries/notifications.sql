-- name: ListNotifications :many
SELECT id, org_id, user_id, event_name, subject_id, title, body, grouping_key, created_at, read_at
FROM notifications
WHERE user_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListUnreadNotifications :many
SELECT id, org_id, user_id, event_name, subject_id, title, body, grouping_key, created_at, read_at
FROM notifications
WHERE user_id = ? AND read_at = ''
ORDER BY created_at DESC
LIMIT ?;

-- name: UnreadNotificationCount :one
SELECT COUNT(*) FROM notifications
WHERE user_id = ? AND read_at = '';

-- name: CreateNotification :one
INSERT INTO notifications (id, org_id, user_id, event_name, subject_id, title, body, grouping_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, org_id, user_id, event_name, subject_id, title, body, grouping_key, created_at, read_at;

-- name: MarkNotificationRead :exec
UPDATE notifications SET read_at = ?
WHERE id = ? AND user_id = ?;

-- name: MarkAllNotificationsRead :exec
UPDATE notifications SET read_at = ?
WHERE user_id = ? AND read_at = '';

-- name: FindGroupedNotification :one
SELECT id, org_id, user_id, event_name, subject_id, title, body, grouping_key, created_at, read_at
FROM notifications
WHERE grouping_key = ? AND read_at = ''
ORDER BY created_at DESC
LIMIT 1;

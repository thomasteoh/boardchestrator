-- name: ListBoardColumns :many
SELECT id, project_id, name, color, position, wip_limit, status, created_at
FROM board_columns
WHERE project_id = ?
ORDER BY position ASC;

-- name: FindBoardColumn :one
SELECT id, project_id, name, color, position, wip_limit, status, created_at
FROM board_columns
WHERE id = ? AND project_id = ?;

-- name: CreateBoardColumn :one
INSERT INTO board_columns (id, project_id, name, color, position, wip_limit, status)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, project_id, name, color, position, wip_limit, status, created_at;

-- name: UpdateBoardColumn :one
UPDATE board_columns SET name = ?, color = ?, position = ?, wip_limit = ?, status = ?
WHERE id = ? AND project_id = ?
RETURNING id, project_id, name, color, position, wip_limit, status, created_at;

-- name: DeleteBoardColumn :exec
DELETE FROM board_columns
WHERE id = ? AND project_id = ?;

-- name: MaxBoardColumnPosition :one
SELECT COALESCE(MAX(position), 0) + 1
FROM board_columns
WHERE project_id = ?;

-- name: ReorderBoardColumns :exec
UPDATE board_columns SET position = ?
WHERE id = ? AND project_id = ?;

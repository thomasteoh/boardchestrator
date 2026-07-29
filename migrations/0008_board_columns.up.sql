-- 0008: board columns

CREATE TABLE IF NOT EXISTS board_columns (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '#6366f1',
    position REAL NOT NULL DEFAULT 0,
    wip_limit INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'backlog',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_board_cols_project ON board_columns(project_id, position);

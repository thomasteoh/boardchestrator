-- 0013: FTS5 search indexes for tasks and comments
-- FTS5 content-sync virtual tables. The indexer in internal/search
-- subscribes to the event bus and maintains these indexes in real time.
-- No triggers here — the event-driven approach avoids double-indexing.

CREATE VIRTUAL TABLE IF NOT EXISTS tasks_fts USING fts5(
    id UNINDEXED,
    title,
    description,
    key UNINDEXED,
    project_id UNINDEXED,
    tokenize='porter unicode61',
    content='tasks',
    content_rowid='rowid',
);

CREATE VIRTUAL TABLE IF NOT EXISTS comments_fts USING fts5(
    id UNINDEXED,
    body,
    task_id UNINDEXED,
    project_id UNINDEXED,
    tokenize='porter unicode61',
    content='comments',
    content_rowid='rowid',
);

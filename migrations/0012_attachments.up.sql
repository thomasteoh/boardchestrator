CREATE TABLE attachments (
    id          TEXT NOT NULL PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id),
    task_id     TEXT NOT NULL REFERENCES tasks(id),
    uploader_id TEXT NOT NULL REFERENCES users(id),
    filename    TEXT NOT NULL,
    mime        TEXT NOT NULL,
    size        INTEGER NOT NULL DEFAULT 0,
    storage_key TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_attachments_task ON attachments(task_id);
CREATE INDEX idx_attachments_org  ON attachments(org_id);

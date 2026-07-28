-- 0007: tasks and related tables

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    key TEXT NOT NULL,
    key_num INTEGER NOT NULL DEFAULT 0,
    points INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'backlog',
    due_at TEXT NOT NULL DEFAULT '',
    sort_order REAL NOT NULL DEFAULT 0,
    archived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_project_key ON tasks(project_id, key);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(project_id, status, sort_order);

CREATE TABLE IF NOT EXISTS task_assignees (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, project_id, user_id)
);

CREATE TABLE IF NOT EXISTS task_watchers (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, project_id, user_id)
);

CREATE TABLE IF NOT EXISTS labels (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '#6366f1',
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_org_name ON labels(org_id, name);

CREATE TABLE IF NOT EXISTS task_labels (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    label_id TEXT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, project_id, label_id)
);

CREATE TABLE IF NOT EXISTS task_relations (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    related_task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL DEFAULT 'relates_to',
    project_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_task_relations_task ON task_relations(task_id, project_id);

CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_comments_task ON comments(task_id, project_id, created_at);

CREATE TABLE IF NOT EXISTS task_activity (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_task_activity_task ON task_activity(task_id, project_id, created_at);

CREATE TABLE IF NOT EXISTS custom_field_defs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'text',
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_cfd_org ON custom_field_defs(org_id, name);

CREATE TABLE IF NOT EXISTS task_custom_field_values (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    field_def_id TEXT NOT NULL REFERENCES custom_field_defs(id) ON DELETE CASCADE,
    value TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (task_id, project_id, field_def_id)
);

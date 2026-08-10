-- 0001: identity & access foundation (SPEC §5 — users, identities,
-- sessions, platform_settings). These tables are platform-scoped, not
-- tenant data, so they carry no org_id.

CREATE TABLE users (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    theme      TEXT NOT NULL DEFAULT 'system',
    timezone   TEXT NOT NULL DEFAULT 'UTC',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at TEXT
);

CREATE TABLE identities (
    id        TEXT PRIMARY KEY,
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider  TEXT NOT NULL,
    subject   TEXT NOT NULL,
    email     TEXT NOT NULL DEFAULT '',
    token_enc BLOB,
    UNIQUE (provider, subject)
);

CREATE INDEX idx_identities_user_id ON identities (user_id);

CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    ip           TEXT NOT NULL DEFAULT '',
    ua           TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT NOT NULL
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE platform_settings (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    context        TEXT NOT NULL DEFAULT '',
    bootstrap_done INTEGER NOT NULL DEFAULT 0,
    settings_json  TEXT NOT NULL DEFAULT '{}'
);

INSERT INTO platform_settings (id) VALUES (1);
-- 0002: action-dispatch infrastructure (SPEC §5 — idempotency_keys,
-- audit_log). These are deliberately NOT tenant-scoped in the usual way:
-- idempotency_keys carries no org_id (keyed globally by the idempotency
-- key), and audit_log.org_id is nullable (platform-level actions and some
-- pre-org events have no org). check-scope.sh is updated to reflect this.

CREATE TABLE idempotency_keys (
    key         TEXT PRIMARY KEY,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE audit_log (
    id          TEXT PRIMARY KEY,
    org_id      TEXT,
    actor_type  TEXT NOT NULL,
    actor_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}',
    ip          TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_audit_log_org_id ON audit_log (org_id);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
-- 0003: job queue table (SPEC §5, §10).
-- Used by the agent runtime (internal/agentrt) to enqueue and process
-- asynchronous jobs (agent runs, recurring tasks, scheduler triggers).

CREATE TABLE jobs (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,                          -- job type: "run", "recurring", "scheduler", etc.
    payload_json TEXT NOT NULL DEFAULT '{}',             -- JSON payload (run id, prompt, config)
    run_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    attempts     INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    status       TEXT NOT NULL DEFAULT 'queued',         -- queued | running | succeeded | failed | dead
    locked_by    TEXT,                                    -- worker id that claimed the job
    locked_at    TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_jobs_status_run_at ON jobs (status, run_at);
CREATE INDEX idx_jobs_locked_by ON jobs (locked_by);
CREATE TABLE orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    context TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'private',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE TABLE org_secrets (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    key TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, key)
);

CREATE TABLE teams (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    context TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'private',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, slug)
);

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    team_id TEXT REFERENCES teams(id),
    name TEXT NOT NULL,
    key TEXT NOT NULL,
    context TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'private',
    archived INTEGER NOT NULL DEFAULT 0,
    next_task_num INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, key)
);

CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    name TEXT NOT NULL,
    is_system INTEGER NOT NULL DEFAULT 0,
    grants_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, name)
);

CREATE TABLE memberships (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL DEFAULT 'user',
    resource_type TEXT NOT NULL DEFAULT 'org',
    resource_id TEXT NOT NULL DEFAULT '',
    role_id TEXT REFERENCES roles(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, actor_id, actor_type, resource_type, resource_id)
);
-- Seed system roles (SPEC §6, copy-on-edit).
-- Create the platform sentinel org first so FK constraints on roles are satisfied.
INSERT INTO orgs (id, name, slug, context, visibility)
VALUES ('00000000000000000000000000000000', 'Platform', '_platform', '', 'internal')
ON CONFLICT DO NOTHING;

INSERT INTO roles (id, org_id, name, is_system, grants_json) VALUES
    ('00000000000000000000000000000000', '00000000000000000000000000000000', 'Org Owner', 1, '["*"]'),
    ('11111111111111111111111111111111', '00000000000000000000000000000000', 'Team Admin', 1, '["org.read","team.*","project.*","board.*","sprint.*","task.*","comment.*","wiki.*","report.view"]'),
    ('22222222222222222222222222222222', '00000000000000000000000000000000', 'Member', 1, '["org.read","project.read","task.*","comment.*","sprint.read","board.read","wiki.read"]'),
    ('33333333333333333333333333333333', '00000000000000000000000000000000', 'Viewer', 1, '["org.read","project.read","task.read","comment.read","sprint.read","board.read","wiki.read"]'),
    ('44444444444444444444444444444444', '00000000000000000000000000000000', 'Guest', 1, '["project.read","task.read","comment.read"]')
ON CONFLICT DO NOTHING;
CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    inviter_id TEXT NOT NULL REFERENCES users(id),
    email TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL,
    role_id TEXT REFERENCES roles(id),
    resource_type TEXT NOT NULL DEFAULT 'org',
    resource_id TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    accepted_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, email, resource_type, resource_id)
);
-- 0007: tasks and related tables

CREATE TABLE tasks (
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

CREATE TABLE task_assignees (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, project_id, user_id)
);

CREATE TABLE task_watchers (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, project_id, user_id)
);

CREATE TABLE labels (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '#6366f1',
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_org_name ON labels(org_id, name);

CREATE TABLE task_labels (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    label_id TEXT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, project_id, label_id)
);

CREATE TABLE task_relations (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    related_task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL DEFAULT 'relates_to',
    project_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_task_relations_task ON task_relations(task_id, project_id);

CREATE TABLE comments (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S')),
    deleted_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_comments_task ON comments(task_id, project_id, created_at);

CREATE TABLE task_activity (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S')),
    deleted_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_task_activity_task ON task_activity(task_id, project_id, created_at);

CREATE TABLE custom_field_defs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'text',
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_cfd_org ON custom_field_defs(org_id, name);

CREATE TABLE task_custom_field_values (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    field_def_id TEXT NOT NULL REFERENCES custom_field_defs(id) ON DELETE CASCADE,
    value TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (task_id, project_id, field_def_id)
);
-- 0008: board columns

CREATE TABLE board_columns (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '#6366f1',
    position REAL NOT NULL DEFAULT 0,
    wip_limit INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'backlog',
    trigger_agent_id TEXT REFERENCES agents(id),
    trigger_prompt TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_board_cols_project ON board_columns(project_id, position);
CREATE TABLE saved_filters (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    query_json  TEXT NOT NULL DEFAULT '{}',
    pinned      INTEGER NOT NULL DEFAULT 0,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_saved_filters_project ON saved_filters(project_id);
CREATE TABLE sprints (
    id         TEXT NOT NULL PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    project_id TEXT NOT NULL REFERENCES projects(id),
    name       TEXT NOT NULL,
    starts_on  TEXT NOT NULL,  -- ISO-8601 UTC date
    ends_on    TEXT NOT NULL,  -- ISO-8601 UTC date
    state      TEXT NOT NULL DEFAULT 'active',  -- active|closed
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_sprints_project ON sprints(project_id);
-- 0011: add sprint_id column to tasks table for sprint membership

ALTER TABLE tasks ADD COLUMN sprint_id TEXT REFERENCES sprints(id);
CREATE INDEX IF NOT EXISTS idx_tasks_sprint ON tasks(project_id, sprint_id, sort_order);
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

-- FTS5 virtual tables (sqlc-compatible stubs for query generation)
-- At runtime these are created by migration 0013_search.up.sql as FTS5
-- content-sync virtual tables. These stubs let sqlc understand the schema.
CREATE TABLE tasks_fts (
    id TEXT,
    title TEXT,
    description TEXT,
    key TEXT,
    project_id TEXT
);

CREATE TABLE comments_fts (
    id TEXT,
    body TEXT,
    task_id TEXT,
    project_id TEXT
);

-- 0014: task templates + recurring rules

CREATE TABLE IF NOT EXISTS task_templates (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    title_template TEXT NOT NULL DEFAULT '',
    description_template TEXT NOT NULL DEFAULT '',
    points INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'backlog',
    labels_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_templates_org_project_name ON task_templates(org_id, project_id, name);

CREATE TABLE IF NOT EXISTS recurring_rules (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    template_id TEXT NOT NULL REFERENCES task_templates(id) ON DELETE CASCADE,
    cron_expr TEXT NOT NULL,
    next_at TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S'))
);

CREATE INDEX IF NOT EXISTS idx_recurring_next ON recurring_rules(enabled, next_at);

-- 0015: notifications

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_name TEXT NOT NULL,
    subject_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    grouping_key TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S')),
    read_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_notif_user_unread ON notifications(user_id, read_at, created_at);
CREATE INDEX IF NOT EXISTS idx_notif_grouping ON notifications(grouping_key, created_at);

-- 0017: data export & deletion support
-- Sentinel "Former member" user for re-attribution.
INSERT INTO users (id, email, name, avatar_url)
VALUES ('ffffffffffffffffffffffffffffffff', 'former-member@local', 'Former member', '')
ON CONFLICT DO NOTHING;

-- 0016: API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    org_id TEXT NOT NULL REFERENCES orgs(id),
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    hash TEXT NOT NULL,
    scope_json TEXT NOT NULL DEFAULT '[]',
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    revoked_at TEXT,
    UNIQUE(org_id, name)
);
-- 0018: providers + provider_orgs (SPEC §10 — LLM provider management)
--
-- providers: platform-level config (base URL, auth, models)
-- provider_orgs: per-org allocation (which providers an org can use)

CREATE TABLE IF NOT EXISTS providers (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT 'openai-compatible',
    name        TEXT NOT NULL,
    base_url    TEXT NOT NULL DEFAULT '',
    key_enc     BLOB,
    models_json TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE TABLE IF NOT EXISTS provider_orgs (
    id          TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES providers(id),
    org_id      TEXT NOT NULL REFERENCES orgs(id),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(provider_id, org_id)
);

CREATE INDEX idx_provider_orgs_org ON provider_orgs (org_id);
-- 0019: agents + agent_skills (SPEC §10 — AI agent management)
--
-- agents: platform templates (org_id NULL) and org-customised agents
-- agent_skills: which skills an agent has attached

CREATE TABLE IF NOT EXISTS agents (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT REFERENCES orgs(id),
    template_id         TEXT REFERENCES agents(id),
    name                TEXT NOT NULL,
    provider_id         TEXT NOT NULL REFERENCES providers(id),
    model               TEXT NOT NULL DEFAULT '',
    context             TEXT NOT NULL DEFAULT '',
    role_id             TEXT REFERENCES roles(id),
    retry_max           INTEGER NOT NULL DEFAULT 3,
    backoff_secs        INTEGER NOT NULL DEFAULT 30,
    runs_per_hour       INTEGER NOT NULL DEFAULT 20,
    token_budget        INTEGER NOT NULL DEFAULT 50000,
    approval_policy_json TEXT NOT NULL DEFAULT '{"low":"auto","read":"auto","high":"require"}',
    active              INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, name)
);

CREATE TABLE IF NOT EXISTS skills (
    id                   TEXT PRIMARY KEY,
    org_id               TEXT REFERENCES orgs(id),
    name                 TEXT NOT NULL,
    version              INTEGER NOT NULL DEFAULT 1,
    description          TEXT NOT NULL DEFAULT '',
    instructions         TEXT NOT NULL DEFAULT '',
    allowed_actions_json TEXT NOT NULL DEFAULT '[]',
    param_schema_json    TEXT NOT NULL DEFAULT '{}',
    mcp_endpoints_enc    TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, name, version)
);

CREATE TABLE IF NOT EXISTS agent_skills (
    agent_id TEXT NOT NULL REFERENCES agents(id),
    skill_id TEXT NOT NULL REFERENCES skills(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    PRIMARY KEY (agent_id, skill_id)
);

-- 0020: runs + run_steps (SPEC §10 — agent run engine)
CREATE TABLE IF NOT EXISTS runs (
    id                 TEXT PRIMARY KEY,
    org_id             TEXT NOT NULL REFERENCES orgs(id),
    agent_id           TEXT NOT NULL REFERENCES agents(id),
    trigger            TEXT NOT NULL,
    task_id            TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    chat_session_id    TEXT,
    initiated_by       TEXT,
    status             TEXT NOT NULL DEFAULT 'queued',
    error              TEXT NOT NULL DEFAULT '',
    prompt_tokens      INTEGER NOT NULL DEFAULT 0,
    completion_tokens  INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    started_at         TEXT,
    finished_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_org ON runs(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_runs_task ON runs(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_runs_agent ON runs(agent_id, created_at);

CREATE TABLE IF NOT EXISTS run_steps (
    id             TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq            INTEGER NOT NULL,
    kind           TEXT NOT NULL,
    request_json   TEXT NOT NULL DEFAULT '',
    response_json  TEXT NOT NULL DEFAULT '',
    tokens         INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_run_steps_run ON run_steps(run_id, seq);


CREATE TABLE IF NOT EXISTS approvals (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    run_id        TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    action_name   TEXT NOT NULL,
    input_json    TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending',
    requested_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    decided_by    TEXT,
    decided_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_org ON approvals(org_id, status, requested_at);
CREATE INDEX IF NOT EXISTS idx_approvals_run ON approvals(run_id, status);

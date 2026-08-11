-- 0023: chat sessions + messages (WU-308)
--
-- chat_sessions: one row per chat conversation. Org-scoped (tenant table);
-- scope is project by default, or team/org for permitted users. A session is
-- tied to a single agent (the agent picker / @agent in chat).
-- chat_messages: the transcript. Child of chat_sessions (no own org_id; scope
-- through the parent). role is user|assistant. An assistant message that
-- performed tool actions carries run_id + the action name/input so the UI can
-- render an action card ("Created BC-142") linked to the run.

CREATE TABLE IF NOT EXISTS chat_sessions (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    team_id    TEXT REFERENCES teams(id) ON DELETE CASCADE,
    agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name       TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_org ON chat_sessions(org_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_project ON chat_sessions(project_id, updated_at);

CREATE TABLE IF NOT EXISTS chat_messages (
    id            TEXT PRIMARY KEY,
    chat_id       TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    role          TEXT NOT NULL,
    content       TEXT NOT NULL DEFAULT '',
    run_id        TEXT REFERENCES runs(id) ON DELETE SET NULL,
    action_name   TEXT NOT NULL DEFAULT '',
    action_input  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_chat ON chat_messages(chat_id, created_at);

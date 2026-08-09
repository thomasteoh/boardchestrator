-- 0020: runs + run_steps (SPEC §10 — agent run engine)
--
-- runs: one row per agent run. Trigger is one of mention|column|chat|schedule|
--       manual. status lifecycle per SPEC §10:
--       queued → running → (succeeded|failed|cancelled), or awaiting_approval
--       when a gated tool call is parked (WU-306 resumes it).
-- run_steps: one row per tool-loop iteration (each model call + tool execution),
--            recording the request/response for the transcript and token usage.

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

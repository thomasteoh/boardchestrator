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

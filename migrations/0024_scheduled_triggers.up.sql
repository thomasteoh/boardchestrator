-- 0024: scheduled agent triggers per project (WU-309)
--
-- scheduled_triggers: a cron expression + agent + prompt that periodically
-- enqueues an agent run for a project. Org-scoped (tenant table); the
-- scheduler fires due rows (next_at <= now, enabled=1), enqueues a run with
-- trigger='schedule' and the prompt as the instruction, then advances next_at
-- via the cron expression. Overlap guard: a project with an active (non-
-- terminal) run is skipped so schedules don't pile up.
--
-- timezone: cron is evaluated in the project owner org's configured tz
-- (default UTC, documented). The scheduler computes next_at with that tz.

CREATE TABLE IF NOT EXISTS scheduled_triggers (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    cron_expr   TEXT NOT NULL,
    prompt      TEXT NOT NULL DEFAULT '',
    next_at     TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_sched_triggers_org ON scheduled_triggers(org_id);
CREATE INDEX IF NOT EXISTS idx_sched_triggers_project ON scheduled_triggers(project_id);
CREATE INDEX IF NOT EXISTS idx_sched_triggers_due ON scheduled_triggers(enabled, next_at);

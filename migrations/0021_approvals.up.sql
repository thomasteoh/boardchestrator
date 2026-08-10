-- 0021: approvals (SPEC §4/§10 — agent approval gates)
--
-- One row per gated agent action awaiting or decided a human approval.
-- status: pending|approved|rejected. The stored input_json + action_name let
-- approval.decide re-dispatch the original call as the agent actor with the
-- gate satisfied (approved) or surface a rejection to the model (rejected).

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

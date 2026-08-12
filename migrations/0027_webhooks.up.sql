-- 0027: outbound webhooks (WU-404)
--
-- webhooks: org/team-scoped outbound delivery config. event_filter is a JSON
-- list of event names (e.g. ["task.create","task.update"]) — empty/[] matches
-- all events. secret is used to HMAC-SHA256 sign delivery bodies.
--
-- webhook_deliveries: one row per attempted delivery. status: queued | running
-- | delivered | failed | dead. attempts/max_attempts drive backoff retries via
-- the shared jobs queue; dead = max attempts exhausted (DLQ).

CREATE TABLE IF NOT EXISTS webhooks (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    team_id      TEXT REFERENCES teams(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    url          TEXT NOT NULL,
    secret       TEXT NOT NULL DEFAULT '',
    event_filter TEXT NOT NULL DEFAULT '[]',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(org_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_team ON webhooks(team_id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id           TEXT PRIMARY KEY,
    webhook_id   TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_name   TEXT NOT NULL,
    event_json   TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'queued',
    attempts     INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    response_code INT,
    error        TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status, created_at);

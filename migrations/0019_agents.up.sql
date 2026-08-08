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

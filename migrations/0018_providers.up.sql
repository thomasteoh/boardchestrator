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

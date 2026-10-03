-- 0034: sign-in provider registry (WU-602, SPEC s5, s7.1).
--
-- One row per sign-in provider. org_id NULL = platform provider; set = owned
-- by that org (WU-607). kind selects the connector (oidc covers every OIDC
-- preset; github is OAuth; saml is WU-610). managed_by 'env' rows are seeded
-- from BC_* variables at startup and are read-only in the UI; 'ui' rows are
-- managed by idp.* actions (WU-603). The ids 'google' and 'github' match the
-- existing identities.provider values, so identities need no migration.
-- client_secret_enc / sp_key_enc are AES-GCM sealed with BC_SECRET_KEY.
-- Env-managed rows removed from the environment are disabled, never deleted,
-- because identities and sessions keep referring to the id.

CREATE TABLE auth_providers (
    id                   TEXT PRIMARY KEY,
    org_id               TEXT REFERENCES orgs (id) ON DELETE CASCADE,
    kind                 TEXT NOT NULL CHECK (kind IN ('oidc', 'github', 'saml')),
    preset               TEXT NOT NULL DEFAULT 'generic',
    display_name         TEXT NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 1,
    managed_by           TEXT NOT NULL DEFAULT 'ui' CHECK (managed_by IN ('ui', 'env')),
    issuer               TEXT NOT NULL DEFAULT '',
    client_id            TEXT NOT NULL DEFAULT '',
    client_secret_enc    TEXT NOT NULL DEFAULT '',
    scopes               TEXT NOT NULL DEFAULT '',
    claim_map_json       TEXT NOT NULL DEFAULT '{}',
    trust_email          INTEGER NOT NULL DEFAULT 0,
    allow_signup         INTEGER NOT NULL DEFAULT 0,
    allowed_tenants_json TEXT NOT NULL DEFAULT '[]',
    saml_metadata_url    TEXT NOT NULL DEFAULT '',
    saml_metadata_xml    TEXT NOT NULL DEFAULT '',
    sp_key_enc           TEXT NOT NULL DEFAULT '',
    sp_cert              TEXT NOT NULL DEFAULT '',
    position             INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_auth_providers_org ON auth_providers (org_id);

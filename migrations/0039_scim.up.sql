-- 0039: SCIM 2.0 provisioning (WU-611, SPEC s5, s7.8).
--
-- scim_tokens: bearer tokens an organisation's IdP uses to call /scim/v2.
-- The token is bcscim_<prefix>_<secret>; prefix is stored plain for lookup
-- and the SHA-256 of the whole token is compared in constant time.
CREATE TABLE scim_tokens (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL,
    created_by   TEXT NOT NULL DEFAULT '',
    expires_at   TEXT,
    last_used_at TEXT,
    revoked_at   TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_scim_tokens_org ON scim_tokens (org_id);

-- scim_users: a SCIM User resource, linked to one platform user. email is
-- the address the IdP last sent; users.email is set only when SCIM creates
-- the user and is never changed by SCIM afterwards.
CREATE TABLE scim_users (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    external_id  TEXT NOT NULL DEFAULT '',
    user_name    TEXT NOT NULL,
    email        TEXT NOT NULL DEFAULT '',
    given_name   TEXT NOT NULL DEFAULT '',
    family_name  TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX idx_scim_users_user_name ON scim_users (org_id, lower(user_name));
CREATE UNIQUE INDEX idx_scim_users_user ON scim_users (org_id, user_id);

-- scim_groups: a SCIM Group; display_name feeds group -> role mapping
-- (SPEC s7.5) as the group value.
CREATE TABLE scim_groups (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    external_id  TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_scim_groups_org ON scim_groups (org_id);

CREATE TABLE scim_group_members (
    group_id TEXT NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    org_id   TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_scim_group_members_user ON scim_group_members (org_id, user_id);

-- 0001: identity & access foundation (SPEC §5 — users, identities,
-- sessions, platform_settings). These tables are platform-scoped, not
-- tenant data, so they carry no org_id.

CREATE TABLE users (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    theme      TEXT NOT NULL DEFAULT 'system',
    timezone   TEXT NOT NULL DEFAULT 'UTC',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at TEXT
);

CREATE TABLE identities (
    id        TEXT PRIMARY KEY,
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider  TEXT NOT NULL,
    subject   TEXT NOT NULL,
    email     TEXT NOT NULL DEFAULT '',
    token_enc BLOB,
    UNIQUE (provider, subject)
);

CREATE INDEX idx_identities_user_id ON identities (user_id);

CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    ip           TEXT NOT NULL DEFAULT '',
    ua           TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT NOT NULL
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE platform_settings (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    context        TEXT NOT NULL DEFAULT '',
    bootstrap_done INTEGER NOT NULL DEFAULT 0,
    settings_json  TEXT NOT NULL DEFAULT '{}'
);

INSERT INTO platform_settings (id) VALUES (1);

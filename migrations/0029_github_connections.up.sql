-- 0029: User GitHub connections (WU-406)
--
-- One row per user: the effective GitHub token used for wiki edits (Phase 5)
-- and the "connected" state. provider is the source: "oauth" (token captured
-- at GitHub SSO login) or "pat" (user-entered personal access token). token_enc
-- is AES-GCM ciphertext (base64) of the token, keyed by the app secret key.
-- login is the GitHub login/username for display.

CREATE TABLE IF NOT EXISTS github_connections (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL DEFAULT 'oauth',
    token_enc  TEXT NOT NULL DEFAULT '',
    login      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

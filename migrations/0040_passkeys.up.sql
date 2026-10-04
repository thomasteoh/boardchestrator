-- 0040: passkeys (WU-612, SPEC s5, s7.9).
--
-- users.webauthn_handle is the WebAuthn user handle: 32 random bytes, never
-- the email or the user id, generated the first time the user registers a
-- passkey. Unique where set.
-- users.email_verified is 0 only for an account whose address nobody has
-- confirmed: a passkey bootstrap claim, where the claimant types it. Such an
-- account is never linked to by email (SPEC s7.3 step 3).
ALTER TABLE users ADD COLUMN webauthn_handle BLOB;
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1;

CREATE UNIQUE INDEX idx_users_webauthn_handle ON users (webauthn_handle)
    WHERE webauthn_handle IS NOT NULL;

-- webauthn_credentials: one row per registered passkey. credential_id and
-- public_key (COSE) are what the authenticator returned; sign_count, the
-- flags and last_used_at are updated at every sign-in.
CREATE TABLE webauthn_credentials (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id      BLOB NOT NULL UNIQUE,
    public_key         BLOB NOT NULL,
    sign_count         INTEGER NOT NULL DEFAULT 0,
    aaguid             BLOB NOT NULL DEFAULT x'',
    transports_json    TEXT NOT NULL DEFAULT '[]',
    attestation_type   TEXT NOT NULL DEFAULT '',
    attestation_format TEXT NOT NULL DEFAULT '',
    user_verified      INTEGER NOT NULL DEFAULT 0,
    backup_eligible    INTEGER NOT NULL DEFAULT 0,
    backup_state       INTEGER NOT NULL DEFAULT 0,
    name               TEXT NOT NULL,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at       TEXT
);

CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials (user_id);

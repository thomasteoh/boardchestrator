CREATE TABLE IF NOT EXISTS invites (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    inviter_id TEXT NOT NULL REFERENCES users(id),
    email TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL,
    role_id TEXT REFERENCES roles(id),
    resource_type TEXT NOT NULL DEFAULT 'org',
    resource_id TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    accepted_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, email, resource_type, resource_id)
);

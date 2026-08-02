CREATE TABLE IF NOT EXISTS orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    context TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'private',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE TABLE IF NOT EXISTS org_secrets (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    key TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, key)
);

CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    context TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'private',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, slug)
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    team_id TEXT REFERENCES teams(id),
    name TEXT NOT NULL,
    key TEXT NOT NULL,
    context TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'private',
    archived INTEGER NOT NULL DEFAULT 0,
    next_task_num INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, key)
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    name TEXT NOT NULL,
    is_system INTEGER NOT NULL DEFAULT 0,
    grants_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, name)
);

CREATE TABLE IF NOT EXISTS memberships (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    actor_type TEXT NOT NULL DEFAULT 'user',
    resource_type TEXT NOT NULL DEFAULT 'org',
    resource_id TEXT NOT NULL DEFAULT '',
    role_id TEXT REFERENCES roles(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(org_id, user_id, actor_type, resource_type, resource_id)
);

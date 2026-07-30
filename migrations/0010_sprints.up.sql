CREATE TABLE sprints (
    id         TEXT NOT NULL PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    project_id TEXT NOT NULL REFERENCES projects(id),
    name       TEXT NOT NULL,
    starts_on  TEXT NOT NULL,  -- ISO-8601 UTC date
    ends_on    TEXT NOT NULL,  -- ISO-8601 UTC date
    state      TEXT NOT NULL DEFAULT 'active',  -- active|closed
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_sprints_project ON sprints(project_id);

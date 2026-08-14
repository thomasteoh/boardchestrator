-- 0032: sprint snapshots for burndown/burnup reports (WU-504).
-- A daily snapshot records the sprint's open/done task counts and points so
-- burndown/burnup can be charted without replaying activity history.

CREATE TABLE sprint_snapshots (
    id          TEXT NOT NULL PRIMARY KEY,
    sprint_id   TEXT NOT NULL REFERENCES sprints(id) ON DELETE CASCADE,
    project_id  TEXT NOT NULL,
    org_id      TEXT NOT NULL REFERENCES orgs(id),
    taken_on    TEXT NOT NULL,            -- ISO-8601 UTC date (YYYY-MM-DD)
    total_points INTEGER NOT NULL DEFAULT 0,
    done_points INTEGER NOT NULL DEFAULT 0,
    open_count  INTEGER NOT NULL DEFAULT 0,
    done_count  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX idx_sprint_snapshots_sprint_date ON sprint_snapshots(sprint_id, taken_on);
CREATE INDEX idx_sprint_snapshots_project ON sprint_snapshots(project_id, taken_on);

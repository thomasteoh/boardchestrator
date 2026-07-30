-- 0011: add sprint_id column to tasks table for sprint membership

ALTER TABLE tasks ADD COLUMN sprint_id TEXT REFERENCES sprints(id);
CREATE INDEX IF NOT EXISTS idx_tasks_sprint ON tasks(project_id, sprint_id, sort_order);

DROP INDEX IF EXISTS idx_tasks_sprint;
-- ALTER TABLE DROP COLUMN is not supported in SQLite — we can't undo a column
-- add. This down migration is a no-op for safety; full restore requires
-- recreating the table.

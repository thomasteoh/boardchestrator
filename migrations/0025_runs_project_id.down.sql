-- 0025 down: add project_id to runs for per-project overlap guard (WU-309)
DROP INDEX IF EXISTS idx_runs_project;
-- SQLite cannot drop a column; the ALTER is effectively irreversible. Keep the
-- column (nullable, unused by legacy runs) and drop only the index.

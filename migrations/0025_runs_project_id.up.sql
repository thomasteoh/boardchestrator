-- 0025: add project_id to runs for per-project overlap guard (WU-309)
--
-- Scheduled triggers (WU-309) enqueue runs with trigger='schedule' and no
-- task_id; the overlap guard needs to skip firing when the *project* already
-- has an active run (queued/running/awaiting_approval) so schedules don't
-- pile up. Existing runs keep their project_id NULL (project-scoped runs are
-- identified via task_id).

ALTER TABLE runs ADD COLUMN project_id TEXT;
CREATE INDEX IF NOT EXISTS idx_runs_project ON runs(project_id, status, created_at);

-- 0017 down: revert data export changes
-- No-op for sentinel user; cannot delete because of FK refs.
ALTER TABLE task_activity DROP COLUMN deleted_by;
ALTER TABLE comments DROP COLUMN deleted_by;

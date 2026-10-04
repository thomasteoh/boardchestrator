-- 0035 down: drop identities.created_at.

ALTER TABLE identities DROP COLUMN created_at;

-- 0035: identities.created_at (WU-604). Settings -> Sign-in methods shows when
-- each sign-in method was linked. SQLite cannot add a column with a
-- non-constant default, so the column is nullable and written by the
-- LinkIdentity query; identities linked before this migration show no date.

ALTER TABLE identities ADD COLUMN created_at TEXT;
